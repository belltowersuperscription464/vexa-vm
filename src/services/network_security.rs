//! Validation and compilation for VM network-security policy.
//!
//! This module is intentionally side-effect free.  Persisting a policy cannot
//! change host networking, and disabled policies compile to no active rules.
//! A reconciler can consume the compiled representation when nftables/libvirt
//! enforcement is wired in.

use std::{net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, AppResult},
    models::{
        FirewallAction, FirewallProtocol, NewVmFirewallRule, PortRange, VmFirewallRule,
        VmNetworkSecurity,
    },
};

const MAX_PORT_RANGES_PER_SIDE: usize = 64;
const MAX_RULE_DESCRIPTION_BYTES: usize = 512;
pub const MAX_FIREWALL_RULES_PER_VM: i64 = 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompiledDdosProtection {
    pub syn_rate_limit_pps: Option<u32>,
    pub udp_rate_limit_pps: Option<u32>,
    pub icmp_rate_limit_pps: Option<u32>,
    pub new_connection_limit_pps: Option<u32>,
    pub concurrent_connection_limit: Option<u32>,
    pub port_scan_protection: bool,
    pub drop_invalid_packets: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompiledVmNetworkPolicy {
    pub vm_id: String,
    pub revision: u64,
    pub firewall_enabled: bool,
    pub default_ingress_action: FirewallAction,
    pub default_egress_action: FirewallAction,
    pub rules: Vec<VmFirewallRule>,
    pub ddos: Option<CompiledDdosProtection>,
}

/// Normalize a single address or network. Bare addresses become host routes,
/// making blacklist matching deterministic for both address families.
pub fn canonical_ip_network(value: &str) -> AppResult<IpNet> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Validation("IP address or CIDR cannot be empty".into()));
    }
    if let Ok(network) = IpNet::from_str(value) {
        return Ok(network.trunc());
    }
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| AppError::Validation(format!("invalid IP address or CIDR: {value}")))?;
    let prefix = if address.is_ipv4() { 32 } else { 128 };
    IpNet::new(address, prefix)
        .map_err(|_| AppError::Validation(format!("invalid IP address or CIDR: {value}")))
}

pub fn normalize_firewall_rule(spec: &NewVmFirewallRule) -> AppResult<NewVmFirewallRule> {
    if spec.description.len() > MAX_RULE_DESCRIPTION_BYTES {
        return Err(AppError::Validation(format!(
            "firewall rule description cannot exceed {MAX_RULE_DESCRIPTION_BYTES} bytes"
        )));
    }
    validate_port_ranges("source", spec.protocol, &spec.source_ports)?;
    validate_port_ranges("destination", spec.protocol, &spec.destination_ports)?;

    let source_cidr = normalize_optional_network(spec.source_cidr.as_deref())?;
    let destination_cidr = normalize_optional_network(spec.destination_cidr.as_deref())?;
    validate_protocol_families(spec.protocol, source_cidr.as_deref(), destination_cidr.as_deref())?;

    let mut normalized = spec.clone();
    normalized.source_cidr = source_cidr;
    normalized.destination_cidr = destination_cidr;
    normalized.description = spec.description.trim().to_owned();
    normalized.source_ports = normalize_port_ranges(&spec.source_ports);
    normalized.destination_ports = normalize_port_ranges(&spec.destination_ports);
    Ok(normalized)
}

pub fn validate_vm_network_security(profile: &VmNetworkSecurity) -> AppResult<()> {
    for (label, limit) in [
        ("syn_rate_limit_pps", profile.syn_rate_limit_pps),
        ("udp_rate_limit_pps", profile.udp_rate_limit_pps),
        ("icmp_rate_limit_pps", profile.icmp_rate_limit_pps),
        ("new_connection_limit_pps", profile.new_connection_limit_pps),
        (
            "concurrent_connection_limit",
            profile.concurrent_connection_limit,
        ),
    ] {
        if limit == Some(0) {
            return Err(AppError::Validation(format!("{label} must be greater than zero")));
        }
    }
    // nftables' connection-count expression is scoped through dynamic sets;
    // treating this field as a simple per-VM aggregate would either enforce a
    // different policy (for example, per source address) or grow unbounded
    // state. Reject it until that data-plane contract is implemented instead
    // of persisting a setting that has no effect.
    if profile.concurrent_connection_limit.is_some() {
        return Err(AppError::Validation(
            "concurrent_connection_limit is not supported by this firewall backend".into(),
        ));
    }
    if profile.ddos_enabled
        && profile.syn_rate_limit_pps.is_none()
        && profile.udp_rate_limit_pps.is_none()
        && profile.icmp_rate_limit_pps.is_none()
        && profile.new_connection_limit_pps.is_none()
        && !profile.port_scan_protection
        && !profile.drop_invalid_packets
    {
        return Err(AppError::Validation(
            "DDoS protection requires at least one configured limit or packet check".into(),
        ));
    }
    Ok(())
}

/// Produce the exact desired policy. Disabled firewall/DDoS features compile
/// to no active rules, guaranteeing that merely creating configuration rows
/// cannot affect guest traffic.
pub fn compile_vm_network_policy(
    profile: &VmNetworkSecurity,
    rules: &[VmFirewallRule],
) -> AppResult<CompiledVmNetworkPolicy> {
    validate_vm_network_security(profile)?;
    let mut active_rules = Vec::new();
    for rule in rules {
        if rule.vm_id != profile.vm_id {
            return Err(AppError::Validation(
                "firewall rule belongs to a different VM".into(),
            ));
        }
        normalize_firewall_rule(&NewVmFirewallRule {
            priority: rule.priority,
            direction: rule.direction,
            action: rule.action,
            protocol: rule.protocol,
            source_cidr: rule.source_cidr.clone(),
            destination_cidr: rule.destination_cidr.clone(),
            source_ports: rule.source_ports.clone(),
            destination_ports: rule.destination_ports.clone(),
            log: rule.log,
            enabled: rule.enabled,
            description: rule.description.clone(),
        })?;
        if profile.firewall_enabled && rule.enabled {
            active_rules.push(rule.clone());
        }
    }
    active_rules.sort_by_key(|rule| (rule.direction.as_str(), rule.priority, rule.created_at));

    let ddos = profile.ddos_enabled.then(|| CompiledDdosProtection {
        syn_rate_limit_pps: profile.syn_rate_limit_pps,
        udp_rate_limit_pps: profile.udp_rate_limit_pps,
        icmp_rate_limit_pps: profile.icmp_rate_limit_pps,
        new_connection_limit_pps: profile.new_connection_limit_pps,
        concurrent_connection_limit: profile.concurrent_connection_limit,
        port_scan_protection: profile.port_scan_protection,
        drop_invalid_packets: profile.drop_invalid_packets,
    });

    Ok(CompiledVmNetworkPolicy {
        vm_id: profile.vm_id.clone(),
        revision: profile.revision,
        firewall_enabled: profile.firewall_enabled,
        default_ingress_action: profile.default_ingress_action,
        default_egress_action: profile.default_egress_action,
        rules: active_rules,
        ddos,
    })
}

fn normalize_optional_network(value: Option<&str>) -> AppResult<Option<String>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(canonical_ip_network)
        .transpose()
        .map(|network| network.map(|network| network.to_string()))
}

fn validate_port_ranges(
    label: &str,
    protocol: FirewallProtocol,
    ranges: &[PortRange],
) -> AppResult<()> {
    if ranges.len() > MAX_PORT_RANGES_PER_SIDE {
        return Err(AppError::Validation(format!(
            "at most {MAX_PORT_RANGES_PER_SIDE} {label} port ranges are allowed"
        )));
    }
    if !ranges.is_empty() && !matches!(protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp) {
        return Err(AppError::Validation(
            "port ranges are only valid for TCP and UDP rules".into(),
        ));
    }
    for range in ranges {
        if range.start == 0 || range.end == 0 || range.start > range.end {
            return Err(AppError::Validation(format!(
                "invalid {label} port range {}-{}",
                range.start, range.end
            )));
        }
    }
    Ok(())
}

fn normalize_port_ranges(ranges: &[PortRange]) -> Vec<PortRange> {
    let mut ranges = ranges.to_vec();
    ranges.sort_by_key(|range| (range.start, range.end));
    ranges.dedup();
    ranges
}

fn validate_protocol_families(
    protocol: FirewallProtocol,
    source: Option<&str>,
    destination: Option<&str>,
) -> AppResult<()> {
    let source = source
        .map(|value| value.parse::<IpNet>())
        .transpose()
        .map_err(|_| AppError::Validation("normalized source CIDR is invalid".into()))?;
    let destination = destination
        .map(|value| value.parse::<IpNet>())
        .transpose()
        .map_err(|_| AppError::Validation("normalized destination CIDR is invalid".into()))?;
    if source
        .as_ref()
        .zip(destination.as_ref())
        .is_some_and(|(left, right)| left.addr().is_ipv4() != right.addr().is_ipv4())
    {
        return Err(AppError::Validation(
            "source and destination CIDRs must use the same address family".into(),
        ));
    }
    let has_ipv6 = source
        .as_ref()
        .or(destination.as_ref())
        .is_some_and(|network| network.addr().is_ipv6());
    let has_ipv4 = source
        .as_ref()
        .or(destination.as_ref())
        .is_some_and(|network| network.addr().is_ipv4());
    if protocol == FirewallProtocol::Icmp && has_ipv6 {
        return Err(AppError::Validation("ICMP rules require IPv4 CIDRs".into()));
    }
    if protocol == FirewallProtocol::Icmpv6 && has_ipv4 {
        return Err(AppError::Validation("ICMPv6 rules require IPv6 CIDRs".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FirewallAction, FirewallDirection};

    fn disabled_profile() -> VmNetworkSecurity {
        VmNetworkSecurity {
            vm_id: "vm-1".into(),
            firewall_enabled: false,
            ddos_enabled: false,
            default_ingress_action: FirewallAction::Accept,
            default_egress_action: FirewallAction::Accept,
            syn_rate_limit_pps: Some(5_000),
            udp_rate_limit_pps: Some(25_000),
            icmp_rate_limit_pps: Some(1_000),
            new_connection_limit_pps: Some(10_000),
            concurrent_connection_limit: None,
            port_scan_protection: false,
            drop_invalid_packets: false,
            revision: 0,
            applied_revision: None,
            last_applied_at: None,
            last_error: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn enabled_rule(vm_id: &str) -> VmFirewallRule {
        VmFirewallRule {
            id: "rule-1".into(),
            vm_id: vm_id.into(),
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: None,
            destination_cidr: None,
            source_ports: vec![],
            destination_ports: vec![PortRange::single(22)],
            log: false,
            enabled: true,
            description: "Block SSH".into(),
            owner_type: "customer_token".into(),
            owner_id: Some("status-token".into()),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn bare_blacklist_addresses_become_host_networks() {
        assert_eq!(canonical_ip_network("192.0.2.7").unwrap().to_string(), "192.0.2.7/32");
        assert_eq!(canonical_ip_network("2001:db8::7").unwrap().to_string(), "2001:db8::7/128");
        assert_eq!(canonical_ip_network("192.0.2.9/24").unwrap().to_string(), "192.0.2.0/24");
    }

    #[test]
    fn omitted_firewall_rule_switch_deserializes_disabled() {
        let rule: NewVmFirewallRule = serde_json::from_value(serde_json::json!({
            "direction": "ingress",
            "action": "drop",
            "protocol": "tcp",
            "destination_ports": [{ "start": 22, "end": 22 }]
        }))
        .unwrap();
        assert!(!rule.enabled);
        assert!(!rule.log);
        assert_eq!(rule.priority, 1000);
    }

    #[test]
    fn ports_require_tcp_or_udp() {
        let rule = NewVmFirewallRule {
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Any,
            source_cidr: None,
            destination_cidr: None,
            source_ports: vec![],
            destination_ports: vec![PortRange::single(22)],
            log: false,
            enabled: false,
            description: String::new(),
        };
        assert!(normalize_firewall_rule(&rule).is_err());
    }

    #[test]
    fn unsupported_connection_limit_is_rejected_instead_of_ignored() {
        let profile = VmNetworkSecurity {
            vm_id: "vm-1".into(),
            firewall_enabled: false,
            ddos_enabled: true,
            default_ingress_action: FirewallAction::Accept,
            default_egress_action: FirewallAction::Accept,
            syn_rate_limit_pps: None,
            udp_rate_limit_pps: None,
            icmp_rate_limit_pps: None,
            new_connection_limit_pps: None,
            concurrent_connection_limit: Some(100),
            port_scan_protection: false,
            drop_invalid_packets: false,
            revision: 0,
            applied_revision: None,
            last_applied_at: None,
            last_error: None,
            created_at: 0,
            updated_at: 0,
        };
        let error = validate_vm_network_security(&profile).unwrap_err();
        assert!(error.to_string().contains("not supported"));
    }

    #[test]
    fn enabled_empty_ddos_profile_is_rejected_instead_of_reported_active() {
        let profile = VmNetworkSecurity {
            vm_id: "vm-1".into(),
            firewall_enabled: false,
            ddos_enabled: true,
            default_ingress_action: FirewallAction::Accept,
            default_egress_action: FirewallAction::Accept,
            syn_rate_limit_pps: None,
            udp_rate_limit_pps: None,
            icmp_rate_limit_pps: None,
            new_connection_limit_pps: None,
            concurrent_connection_limit: None,
            port_scan_protection: false,
            drop_invalid_packets: false,
            revision: 0,
            applied_revision: None,
            last_applied_at: None,
            last_error: None,
            created_at: 0,
            updated_at: 0,
        };
        let error = validate_vm_network_security(&profile).unwrap_err();
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn configured_rules_and_thresholds_compile_to_nothing_by_default() {
        let compiled = compile_vm_network_policy(
            &disabled_profile(),
            &[enabled_rule("vm-1")],
        )
        .unwrap();
        assert!(!compiled.firewall_enabled);
        assert!(compiled.rules.is_empty());
        assert!(compiled.ddos.is_none());
    }

    #[test]
    fn compiler_rejects_cross_vm_or_malformed_stored_rules_even_when_disabled() {
        let profile = disabled_profile();
        let error = compile_vm_network_policy(&profile, &[enabled_rule("vm-2")]).unwrap_err();
        assert!(error.to_string().contains("different VM"));

        let mut malformed = enabled_rule("vm-1");
        malformed.destination_ports = vec![PortRange { start: 443, end: 22 }];
        let error = compile_vm_network_policy(&profile, &[malformed]).unwrap_err();
        assert!(error.to_string().contains("invalid destination port range"));
    }

    #[test]
    fn normalization_rejects_mixed_address_families() {
        let rule = NewVmFirewallRule {
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: Some("192.0.2.10/24".into()),
            destination_cidr: Some("2001:db8::10/64".into()),
            source_ports: vec![],
            destination_ports: vec![PortRange::single(443)],
            log: false,
            enabled: true,
            description: String::new(),
        };
        assert!(normalize_firewall_rule(&rule).is_err());
    }
}
