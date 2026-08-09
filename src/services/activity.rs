//! Consistent VM activity and IP-abuse audit records.
//!
//! Vexa-VM already stores append-only audit events at the database layer. This
//! service gives every caller the same actor/request fields, bounds untrusted
//! details, and removes credentials before they reach that immutable store.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    db::Database,
    error::{AppError, AppResult},
    models::{AuditEvent, NewAuditEvent, Timestamp},
};

const MAX_AUDIT_DETAILS_BYTES: usize = 16 * 1024;
const MAX_DETAIL_DEPTH: usize = 12;
const MAX_COLLECTION_ITEMS: usize = 100;
const MAX_DETAIL_NODES: usize = 2048;
const MAX_DETAIL_STRING_BYTES: usize = 2048;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivityActor {
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl ActivityActor {
    pub fn system(component: &str) -> Self {
        Self {
            actor_type: "system".into(),
            actor_id: Some(component.into()),
            ..Self::default()
        }
    }

    fn validate(&self) -> AppResult<()> {
        validate_identifier("activity actor type", &self.actor_type, 64)?;
        validate_optional_text("activity actor ID", self.actor_id.as_deref(), 256)?;
        validate_optional_text("activity request ID", self.request_id.as_deref(), 256)?;
        validate_optional_text("activity user agent", self.user_agent.as_deref(), 4096)?;
        if let Some(source_ip) = self.source_ip.as_deref() {
            source_ip
                .parse::<IpAddr>()
                .map_err(|_| AppError::Validation("activity source IP is invalid".into()))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ActivityLogger {
    database: Database,
}

impl ActivityLogger {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn record_vm_action(
        &self,
        actor: &ActivityActor,
        action: &str,
        vm_id: &str,
        success: bool,
        details: Value,
    ) -> AppResult<AuditEvent> {
        self.record_resource_action(actor, action, "vm", Some(vm_id), success, details)
    }

    pub fn record_resource_action(
        &self,
        actor: &ActivityActor,
        action: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        success: bool,
        details: Value,
    ) -> AppResult<AuditEvent> {
        actor.validate()?;
        validate_identifier("activity action", action, 128)?;
        validate_identifier("activity resource type", resource_type, 64)?;
        validate_optional_text("activity resource ID", resource_id, 256)?;
        self.database.append_audit(&NewAuditEvent {
            actor_type: actor.actor_type.clone(),
            actor_id: actor.actor_id.clone(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.map(str::to_owned),
            request_id: actor.request_id.clone(),
            source_ip: canonical_optional_ip(actor.source_ip.as_deref())?,
            user_agent: actor
                .user_agent
                .as_deref()
                .map(|value| truncate_string(value, 512)),
            success,
            details: sanitize_audit_details(details),
        })
    }

    /// Store an immutable abuse observation in the existing append-only audit
    /// stream. `resource_type=ip_abuse` is queryable through the audit API and
    /// `resource_id` is the canonical IPv4/IPv6 address.
    pub fn record_ip_abuse(
        &self,
        actor: &ActivityActor,
        observation: &IpAbuseObservation,
    ) -> AppResult<AuditEvent> {
        observation.validate()?;
        let address = canonical_abuse_ip(&observation.address)?;
        let details = json!({
            "record_id": observation.id,
            "vm_id": observation.vm_id,
            "category": observation.category,
            "severity": observation.severity,
            "observed_at": observation.observed_at,
            "provider_case_id": observation.provider_case_id,
            "status": AbuseStatus::Open,
        });
        self.record_resource_action(
            actor,
            "ip.abuse.reported",
            "ip_abuse",
            Some(&address),
            true,
            details,
        )
    }

    /// Record status changes as new events so the original report is never
    /// mutated. Consumers derive the current status from the newest event for
    /// a record ID.
    pub fn record_ip_abuse_status(
        &self,
        actor: &ActivityActor,
        change: &IpAbuseStatusChange,
    ) -> AppResult<AuditEvent> {
        validate_identifier("IP abuse record ID", &change.record_id, 128)?;
        validate_optional_text("IP abuse status note", change.note.as_deref(), 2048)?;
        let address = canonical_abuse_ip(&change.address)?;
        self.record_resource_action(
            actor,
            "ip.abuse.status_changed",
            "ip_abuse",
            Some(&address),
            true,
            json!({
                "record_id": change.record_id,
                "status": change.status,
                "note_present": change.note.is_some(),
            }),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseCategory {
    BruteForce,
    CommandAndControl,
    Copyright,
    Ddos,
    Fraud,
    Malware,
    Phishing,
    PortScan,
    Spam,
    Spoofing,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseDirection {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseStatus {
    Open,
    Acknowledged,
    Resolved,
    FalsePositive,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpAbuseObservation {
    pub id: String,
    pub address: String,
    pub vm_id: Option<String>,
    pub category: AbuseCategory,
    pub direction: AbuseDirection,
    pub severity: AbuseSeverity,
    pub observed_at: Timestamp,
    pub reported_by: String,
    pub provider_case_id: Option<String>,
    pub protocol: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub packet_count: Option<u64>,
    pub byte_count: Option<u64>,
    #[serde(default)]
    pub evidence: Value,
}

impl IpAbuseObservation {
    pub fn new(
        address: impl Into<String>,
        category: AbuseCategory,
        severity: AbuseSeverity,
        observed_at: Timestamp,
        reported_by: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            address: address.into(),
            vm_id: None,
            category,
            direction: AbuseDirection::Unknown,
            severity,
            observed_at,
            reported_by: reported_by.into(),
            provider_case_id: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            packet_count: None,
            byte_count: None,
            evidence: json!({}),
        }
    }

    fn validate(&self) -> AppResult<()> {
        validate_identifier("IP abuse record ID", &self.id, 128)?;
        canonical_abuse_ip(&self.address)?;
        validate_optional_text("IP abuse VM ID", self.vm_id.as_deref(), 256)?;
        validate_optional_text("IP abuse provider case ID", self.provider_case_id.as_deref(), 256)?;
        validate_optional_identifier("IP abuse protocol", self.protocol.as_deref(), 32)?;
        validate_optional_text("IP abuse reporter", Some(self.reported_by.as_str()), 256)?;
        if self.observed_at <= 0 {
            return Err(AppError::Validation(
                "IP abuse observation time is invalid".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpAbuseStatusChange {
    pub record_id: String,
    pub address: String,
    pub status: AbuseStatus,
    pub note: Option<String>,
}

pub fn sanitize_audit_details(details: Value) -> Value {
    let mut remaining = MAX_DETAIL_NODES;
    let sanitized = sanitize_value(details, 0, &mut remaining);
    let size = serde_json::to_vec(&sanitized).map_or(0, |bytes| bytes.len());
    if size <= MAX_AUDIT_DETAILS_BYTES {
        sanitized
    } else {
        json!({
            "truncated": true,
            "reason": "audit details exceeded 16 KiB after credential redaction",
            "sanitized_size_bytes": size,
        })
    }
}

fn sanitize_value(value: Value, depth: usize, remaining: &mut usize) -> Value {
    if *remaining == 0 {
        return Value::String("[item limit]".into());
    }
    *remaining -= 1;
    if depth >= MAX_DETAIL_DEPTH {
        return Value::String("[depth limit]".into());
    }
    match value {
        Value::String(value) => Value::String(truncate_string(&value, MAX_DETAIL_STRING_BYTES)),
        Value::Array(values) => {
            let mut sanitized = Vec::new();
            for value in values.into_iter().take(MAX_COLLECTION_ITEMS) {
                if *remaining == 0 {
                    sanitized.push(Value::String("[item limit]".into()));
                    break;
                }
                sanitized.push(sanitize_value(value, depth + 1, remaining));
            }
            Value::Array(sanitized)
        }
        Value::Object(values) => {
            let mut sanitized = Map::new();
            for (key, value) in values.into_iter().take(MAX_COLLECTION_ITEMS) {
                if *remaining == 0 {
                    sanitized.insert("_truncated".into(), Value::String("[item limit]".into()));
                    break;
                }
                let sensitive = is_sensitive_key(&key);
                let key = truncate_string(&key, 256);
                if sensitive {
                    *remaining -= 1;
                    sanitized.insert(key, Value::String("[redacted]".into()));
                } else {
                    sanitized.insert(key, sanitize_value(value, depth + 1, remaining));
                }
            }
            Value::Object(sanitized)
        }
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "authorization"
            | "access_key"
            | "api_key"
            | "cookie"
            | "credential"
            | "credentials"
            | "credential_hash"
            | "master_key"
            | "passphrase"
            | "password"
            | "password_hash"
            | "private_key"
            | "secret"
            | "secret_key"
            | "session"
            | "session_cookie"
            | "set_cookie"
            | "token"
    ) || key.ends_with("_password")
        || key.ends_with("_passphrase")
        || key.ends_with("_private_key")
        || key.ends_with("_secret")
        || (key.ends_with("_token") && !key.ends_with("_token_id"))
}

fn canonical_optional_ip(value: Option<&str>) -> AppResult<Option<String>> {
    value
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map(|address| address.to_string())
                .map_err(|_| AppError::Validation("activity source IP is invalid".into()))
        })
        .transpose()
}

fn canonical_abuse_ip(value: &str) -> AppResult<String> {
    let address: IpAddr = value
        .parse()
        .map_err(|_| AppError::Validation("IP abuse address is invalid".into()))?;
    let unusable = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.octets() == [255, 255, 255, 255]
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_loopback() || address.is_multicast(),
    };
    if unusable {
        return Err(AppError::Validation(
            "IP abuse address must identify a unicast guest or remote host".into(),
        ));
    }
    Ok(address.to_string())
}

fn validate_identifier(label: &str, value: &str, maximum: usize) -> AppResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
    {
        return Err(AppError::Validation(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_optional_identifier(label: &str, value: Option<&str>, maximum: usize) -> AppResult<()> {
    match value {
        Some(value) => validate_identifier(label, value, maximum),
        None => Ok(()),
    }
}

fn validate_optional_text(label: &str, value: Option<&str>, maximum: usize) -> AppResult<()> {
    if value.is_some_and(|value| value.is_empty() || value.len() > maximum || value.contains('\0')) {
        return Err(AppError::Validation(format!("{label} is invalid")));
    }
    Ok(())
}

fn truncate_string(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ActivityActor {
        ActivityActor {
            actor_type: "admin".into(),
            actor_id: Some("admin-1".into()),
            request_id: Some("request-1".into()),
            source_ip: Some("2001:0db8::1".into()),
            user_agent: Some("test-agent".into()),
        }
    }

    #[test]
    fn vm_activity_is_append_only_and_credentials_are_redacted() {
        let database = Database::open_in_memory().unwrap();
        let logger = ActivityLogger::new(database.clone());
        let event = logger
            .record_vm_action(
                &actor(),
                "vm.password.update",
                "vm-1",
                true,
                json!({
                    "password": "do-not-store",
                    "nested": {
                        "api_key": "do-not-store",
                        "api_token": "do-not-store",
                        "password_hash": "do-not-store",
                        "token_id": "safe-id"
                    },
                    "job_id": "job-1",
                }),
            )
            .unwrap();
        assert_eq!(event.source_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(event.details["password"], "[redacted]");
        assert_eq!(event.details["nested"]["api_key"], "[redacted]");
        assert_eq!(event.details["nested"]["api_token"], "[redacted]");
        assert_eq!(event.details["nested"]["password_hash"], "[redacted]");
        assert_eq!(event.details["nested"]["token_id"], "safe-id");
        assert_eq!(event.details["job_id"], "job-1");

        let events = database
            .list_audit(None, Some("vm"), Some("vm-1"), 10)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(database
            .with_connection(|connection| {
                connection.execute("DELETE FROM audit_log", [])?;
                Ok(())
            })
            .is_err());
    }

    #[test]
    fn ip_abuse_records_are_canonical_and_queryable() {
        let database = Database::open_in_memory().unwrap();
        let logger = ActivityLogger::new(database.clone());
        let mut observation = IpAbuseObservation::new(
            "2001:0db8:0000::20",
            AbuseCategory::PortScan,
            AbuseSeverity::High,
            1_786_000_000,
            "datacenter-noc",
        );
        observation.vm_id = Some("vm-1".into());
        observation.provider_case_id = Some("ABUSE-42".into());
        observation.evidence = json!({ "authorization": "must-not-survive", "flow_count": 12 });
        let event = logger.record_ip_abuse(&actor(), &observation).unwrap();
        assert_eq!(event.resource_type, "ip_abuse");
        assert_eq!(event.resource_id.as_deref(), Some("2001:db8::20"));
        assert!(event.details.get("evidence").is_none());

        let events = database
            .list_audit(None, Some("ip_abuse"), Some("2001:db8::20"), 10)
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn rejects_non_unicast_abuse_addresses_and_invalid_actions() {
        for address in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "ff02::1"] {
            assert!(canonical_abuse_ip(address).is_err(), "accepted {address}");
        }
        let database = Database::open_in_memory().unwrap();
        let logger = ActivityLogger::new(database);
        assert!(logger
            .record_vm_action(&actor(), "bad action", "vm-1", false, json!({}))
            .is_err());
    }

    #[test]
    fn oversized_details_are_replaced_with_a_bounded_marker() {
        let details = json!({ "output": "x".repeat(MAX_AUDIT_DETAILS_BYTES * 2) });
        let sanitized = sanitize_audit_details(details);
        // Individual strings are shortened before the whole-record size check.
        assert!(serde_json::to_vec(&sanitized).unwrap().len() <= MAX_AUDIT_DETAILS_BYTES);
    }
}
