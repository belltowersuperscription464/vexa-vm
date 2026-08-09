//! Persistent domain models shared by the web panel, API, and background workers.
//!
//! Timestamps are Unix seconds in UTC.  IP addresses and networks are stored in
//! canonical text form by the database layer so SQLite remains equally useful
//! on IPv4-only, IPv6-only, and dual-stack nodes.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub type Timestamp = i64;
pub const STAGED_PASSWORD_ENVELOPE_FIELD: &str = "_staged_password_envelope";
/// Non-secret reinstall-job payload field used to identify a staged Vexa Guest
/// Tools rotation during completion, cancellation, and recovery.
pub const STAGED_GUEST_TOOLS_GENERATION_FIELD: &str = "_guest_tools_rotation_generation";

/// Preserve the distinction required by PATCH documents: an omitted field
/// means "leave it unchanged", while an explicit JSON `null` means "clear
/// the stored value". Serde's default `Option<Option<T>>` handling collapses
/// both cases into `None`, so nullable PATCH fields use this decoder together
/// with `#[serde(default)]`.
pub(crate) fn deserialize_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    other => Err(format!("invalid {} value: {other}", stringify!($name))),
                }
            }
        }
    };
}

string_enum!(AdminRole {
    SuperAdmin => "super_admin",
    Admin => "admin",
    ReadOnly => "read_only",
});

string_enum!(VmState {
    Creating => "creating",
    Running => "running",
    Stopped => "stopped",
    Paused => "paused",
    Reinstalling => "reinstalling",
    Migrating => "migrating",
    Error => "error",
    Unknown => "unknown",
});

string_enum!(IpScope {
    Public => "public",
    Private => "private",
});

string_enum!(IpStatus {
    Free => "free",
    Reserved => "reserved",
    Used => "used",
    Main => "main",
});

string_enum!(InstallMode {
    CloudInit => "cloud_init",
    Automatic => "automatic",
    Manual => "manual",
});

string_enum!(JobStatus {
    Queued => "queued",
    Running => "running",
    Succeeded => "succeeded",
    Failed => "failed",
    Cancelled => "cancelled",
});

string_enum!(SnapshotState {
    Creating => "creating",
    Ready => "ready",
    Reverting => "reverting",
    Deleting => "deleting",
    Error => "error",
});

string_enum!(GuestToolsPlatform {
    Linux => "linux",
    Windows => "windows",
});

string_enum!(GuestToolsProvisioner {
    CloudInit => "cloud_init",
    CloudbaseNoCloud => "cloudbase_nocloud",
});

string_enum!(GuestToolsStatus {
    Pending => "pending",
    Ready => "ready",
    Unavailable => "unavailable",
    Error => "error",
});

string_enum!(FirewallDirection {
    Ingress => "ingress",
    Egress => "egress",
});

string_enum!(FirewallAction {
    Accept => "accept",
    Drop => "drop",
    Reject => "reject",
});

string_enum!(FirewallProtocol {
    Any => "any",
    Tcp => "tcp",
    Udp => "udp",
    Icmp => "icmp",
    Icmpv6 => "icmpv6",
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }

    pub fn from_i64(value: impl Into<i64>) -> Result<Self, String> {
        let value = value.into();
        match value {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            other => Err(format!("invalid address family: {other}")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Admin {
    pub id: String,
    pub username: String,
    pub role: AdminRole,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_login_at: Option<Timestamp>,
}

/// Internal authentication view. The PHC hash must never be serialized.
#[derive(Clone, Debug)]
pub struct AdminAuth {
    pub admin: Admin,
    pub password_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminSession {
    pub admin: Admin,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub permissions: Vec<String>,
    pub ip_allowlist: Vec<String>,
    pub created_by: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct ApiKeyAuth {
    pub key: ApiKey,
    pub token_hash: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewVm {
    pub name: String,
    pub hostname: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub os_family: String,
    pub iso_id: Option<String>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    #[serde(default = "default_disk_format")]
    pub disk_format: String,
    #[serde(default = "default_firmware")]
    pub firmware: String,
    pub machine_type: Option<String>,
    pub bridge: Option<String>,
    pub tap_name: Option<String>,
    pub mac_address: Option<String>,
    pub network_limit_mbps: Option<u64>,
    pub traffic_limit_bytes: Option<u64>,
    #[serde(default = "default_root_user")]
    pub root_username: String,
    #[serde(default)]
    pub guest_agent: bool,
    #[serde(default)]
    pub autostart: bool,
    pub timezone: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

fn default_disk_format() -> String {
    "qcow2".into()
}

fn default_firmware() -> String {
    "auto".into()
}

fn default_root_user() -> String {
    "root".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Vm {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub description: String,
    pub os_family: String,
    pub iso_id: Option<String>,
    pub state: VmState,
    pub desired_state: VmState,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub disk_format: String,
    pub firmware: String,
    pub machine_type: Option<String>,
    pub bridge: Option<String>,
    pub tap_name: Option<String>,
    pub mac_address: Option<String>,
    pub network_limit_mbps: Option<u64>,
    pub traffic_limit_bytes: Option<u64>,
    pub traffic_used_bytes: u64,
    pub root_username: String,
    pub guest_agent: bool,
    pub autostart: bool,
    pub timezone: Option<String>,
    pub libvirt_uuid: Option<String>,
    pub vnc_display: Option<i64>,
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VmGuestTools {
    pub vm_id: String,
    pub enabled: bool,
    pub platform: GuestToolsPlatform,
    pub provisioner: GuestToolsProvisioner,
    pub desired_version: String,
    pub installed_version: Option<String>,
    pub status: GuestToolsStatus,
    pub last_seen_at: Option<Timestamp>,
    pub last_error: Option<String>,
    /// A fresh channel key has been staged for a reinstall. The generation and
    /// encrypted key are intentionally never part of this serialized model.
    pub pending_rotation: bool,
    /// The pending key has been armed for reinstall. Clients must use it until
    /// an authenticated bootstrap promotes it; reverting is unsafe once guest
    /// disk mutation may have started.
    pub pending_installed: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Internal-only seed material injected into a reinstall image. This type is
/// deliberately not serializable and its Debug implementation redacts the key.
#[derive(Clone)]
pub struct PendingVmGuestToolsSeed {
    pub generation: String,
    pub platform: GuestToolsPlatform,
    pub provisioner: GuestToolsProvisioner,
    pub desired_version: String,
    pub secret: String,
    /// Whether this generation has been armed and may already be on guest disk.
    pub installed: bool,
}

impl fmt::Debug for PendingVmGuestToolsSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingVmGuestToolsSeed")
            .field("generation", &self.generation)
            .field("platform", &self.platform)
            .field("provisioner", &self.provisioner)
            .field("desired_version", &self.desired_version)
            .field("secret", &"[REDACTED]")
            .field("installed", &self.installed)
            .finish()
    }
}

/// Internal channel-key selection for host-to-guest requests. Once a pending
/// reinstall is armed, `pending_generation` identifies the key that must
/// complete bootstrap before it can be promoted.
#[derive(Clone)]
pub struct VmGuestToolsClientSecret {
    pub secret: String,
    pub desired_version: String,
    pub pending_generation: Option<String>,
}

/// Non-secret description of an armed Guest Tools rotation that may be
/// reused only to retry the exact failed reinstall which originally armed it.
/// This is intentionally not serializable: rotation generations are internal
/// coordination tokens, not API credentials or public VM state.
#[derive(Clone, Debug)]
pub struct ReusableVmGuestToolsRotation {
    pub generation: String,
    pub platform: GuestToolsPlatform,
    pub provisioner: GuestToolsProvisioner,
    pub desired_version: String,
    pub origin_job_id: String,
}

impl fmt::Debug for VmGuestToolsClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VmGuestToolsClientSecret")
            .field("secret", &"[REDACTED]")
            .field("desired_version", &self.desired_version)
            .field("pending_generation", &self.pending_generation)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VmPatch {
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub iso_id: Option<Option<String>>,
    pub os_family: Option<String>,
    pub root_username: Option<String>,
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub state: Option<VmState>,
    pub desired_state: Option<VmState>,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub disk_gib: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub tap_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub network_limit_mbps: Option<Option<u64>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub traffic_limit_bytes: Option<Option<u64>>,
    pub traffic_used_bytes: Option<u64>,
    pub guest_agent: Option<bool>,
    pub autostart: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub timezone: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub libvirt_uuid: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub vnc_display: Option<Option<i64>>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewIpPool {
    pub name: String,
    pub cidr: String,
    pub scope: IpScope,
    pub gateway: Option<String>,
    pub bridge: Option<String>,
    pub vlan_id: Option<u16>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IpPoolPatch {
    pub name: Option<String>,
    pub scope: Option<IpScope>,
    pub gateway: Option<String>,
    pub bridge: Option<String>,
    pub vlan_id: Option<u16>,
    pub mtu: Option<u32>,
    pub enabled: Option<bool>,
}

fn default_mtu() -> u32 {
    1500
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpPool {
    pub id: String,
    pub name: String,
    pub cidr: String,
    pub family: AddressFamily,
    pub scope: IpScope,
    pub gateway: Option<String>,
    pub bridge: Option<String>,
    pub vlan_id: Option<u16>,
    pub mtu: u32,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewIpAddress {
    #[serde(alias = "range_id")]
    pub pool_id: Option<String>,
    pub address: String,
    pub prefix_length: u8,
    pub scope: IpScope,
    #[serde(default = "default_ip_status")]
    pub status: IpStatus,
    pub gateway: Option<String>,
    pub reverse_dns: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

fn default_ip_status() -> IpStatus {
    IpStatus::Free
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpAddressRecord {
    pub id: String,
    pub pool_id: Option<String>,
    pub address: String,
    pub family: AddressFamily,
    pub prefix_length: u8,
    pub scope: IpScope,
    pub status: IpStatus,
    pub gateway: Option<String>,
    pub assigned_vm_id: Option<String>,
    pub primary_for_vm: bool,
    pub reverse_dns: Option<String>,
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsServer {
    pub id: i64,
    pub address: String,
    pub family: AddressFamily,
    pub priority: i64,
    pub pool_id: Option<String>,
    pub vm_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IsoImage {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub version: Option<String>,
    pub os_family: String,
    pub architecture: String,
    pub install_mode: InstallMode,
    pub source_url: Option<String>,
    pub local_path: Option<String>,
    pub checksum_sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub supports_guest_agent: bool,
    pub supports_cloud_init: bool,
    pub uefi: bool,
    pub enabled: bool,
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostInventory {
    pub hostname: String,
    pub architecture: String,
    pub kernel: String,
    pub cpu_model: Option<String>,
    pub cpu_cores: u32,
    pub memory_total_bytes: u64,
    pub root_disk_total_bytes: u64,
    pub listen_port: u16,
    pub public_interface: Option<String>,
    pub detected_addresses: Vec<String>,
    pub metadata: Value,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMetric {
    pub sampled_at: Timestamp,
    pub cpu_percent: f64,
    pub load_one: f64,
    pub load_five: f64,
    pub load_fifteen: f64,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_bps: f64,
    pub network_tx_bps: f64,
    pub uptime_seconds: u64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VmMetric {
    pub vm_id: String,
    pub sampled_at: Timestamp,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_bps: f64,
    pub network_tx_bps: f64,
    pub traffic_used_bytes: u64,
    pub traffic_limit_bytes: Option<u64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VmTrafficEnforcement {
    pub vm_id: String,
    pub blocked: bool,
    pub blocked_at: Option<Timestamp>,
    pub last_error: Option<String>,
    pub updated_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn single(port: u16) -> Self {
        Self { start: port, end: port }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VmNetworkSecurity {
    pub vm_id: String,
    pub firewall_enabled: bool,
    pub ddos_enabled: bool,
    pub default_ingress_action: FirewallAction,
    pub default_egress_action: FirewallAction,
    pub syn_rate_limit_pps: Option<u32>,
    pub udp_rate_limit_pps: Option<u32>,
    pub icmp_rate_limit_pps: Option<u32>,
    pub new_connection_limit_pps: Option<u32>,
    pub concurrent_connection_limit: Option<u32>,
    pub port_scan_protection: bool,
    pub drop_invalid_packets: bool,
    pub revision: u64,
    pub applied_revision: Option<u64>,
    pub last_applied_at: Option<Timestamp>,
    pub last_error: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VmNetworkSecurityPatch {
    pub firewall_enabled: Option<bool>,
    pub ddos_enabled: Option<bool>,
    pub default_ingress_action: Option<FirewallAction>,
    pub default_egress_action: Option<FirewallAction>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub syn_rate_limit_pps: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub udp_rate_limit_pps: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub icmp_rate_limit_pps: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub new_connection_limit_pps: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub concurrent_connection_limit: Option<Option<u32>>,
    pub port_scan_protection: Option<bool>,
    pub drop_invalid_packets: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewVmFirewallRule {
    #[serde(default = "default_firewall_priority")]
    pub priority: u16,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    #[serde(default = "default_firewall_protocol")]
    pub protocol: FirewallProtocol,
    pub source_cidr: Option<String>,
    pub destination_cidr: Option<String>,
    #[serde(default)]
    pub source_ports: Vec<PortRange>,
    #[serde(default)]
    pub destination_ports: Vec<PortRange>,
    #[serde(default)]
    pub log: bool,
    /// Rules are inert until explicitly enabled and the VM firewall is enabled.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

fn default_firewall_priority() -> u16 {
    1000
}

fn default_firewall_protocol() -> FirewallProtocol {
    FirewallProtocol::Any
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VmFirewallRulePatch {
    pub priority: Option<u16>,
    pub direction: Option<FirewallDirection>,
    pub action: Option<FirewallAction>,
    pub protocol: Option<FirewallProtocol>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub source_cidr: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub destination_cidr: Option<Option<String>>,
    pub source_ports: Option<Vec<PortRange>>,
    pub destination_ports: Option<Vec<PortRange>>,
    pub log: Option<bool>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VmFirewallRule {
    pub id: String,
    pub vm_id: String,
    pub priority: u16,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: FirewallProtocol,
    pub source_cidr: Option<String>,
    pub destination_cidr: Option<String>,
    pub source_ports: Vec<PortRange>,
    pub destination_ports: Vec<PortRange>,
    pub log: bool,
    pub enabled: bool,
    pub description: String,
    /// `admin` rules cannot be changed through a customer status session.
    pub owner_type: String,
    pub owner_id: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HypervisorNetworkSecurity {
    pub bcp38_enabled: bool,
    pub revision: u64,
    pub applied_revision: Option<u64>,
    pub last_applied_at: Option<Timestamp>,
    pub last_error: Option<String>,
    pub updated_by: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HypervisorNetworkSecurityPatch {
    pub bcp38_enabled: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewIpBlacklistEntry {
    /// A single address or CIDR. Single addresses are stored as /32 or /128.
    pub cidr: String,
    pub reason: String,
    #[serde(default = "default_blacklist_source")]
    pub source: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub expires_at: Option<Timestamp>,
    pub created_by: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

fn default_blacklist_source() -> String {
    "manual".into()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IpBlacklistPatch {
    pub reason: Option<String>,
    pub source: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    pub expires_at: Option<Option<Timestamp>>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpBlacklistEntry {
    pub id: String,
    pub cidr: String,
    pub family: AddressFamily,
    pub reason: String,
    pub source: String,
    pub enabled: bool,
    pub expires_at: Option<Timestamp>,
    pub created_by: Option<String>,
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewIpAbuseRecord {
    pub address: String,
    pub vm_id: Option<String>,
    pub category: String,
    #[serde(default = "default_abuse_severity")]
    pub severity: u8,
    pub summary: String,
    pub reporter: Option<String>,
    pub provider_reference: Option<String>,
    pub observed_at: Option<Timestamp>,
    #[serde(default)]
    pub metadata: Value,
}

fn default_abuse_severity() -> u8 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpAbuseRecord {
    pub id: String,
    pub address: String,
    pub family: AddressFamily,
    pub vm_id: Option<String>,
    pub category: String,
    pub severity: u8,
    pub summary: String,
    pub reporter: Option<String>,
    pub provider_reference: Option<String>,
    pub observed_at: Timestamp,
    pub reported_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub resolved_by: Option<String>,
    pub resolution: Option<String>,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettingRecord {
    pub key: String,
    pub value: Value,
    pub encrypted: bool,
    pub updated_by: Option<String>,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewJob {
    pub kind: String,
    pub vm_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
    pub idempotency_key: Option<String>,
    pub run_after: Option<Timestamp>,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    pub actor_type: Option<String>,
    pub actor_id: Option<String>,
}

fn default_max_attempts() -> u32 {
    3
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub vm_id: Option<String>,
    pub status: JobStatus,
    #[serde(skip_serializing)]
    pub payload: Value,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub progress_percent: f64,
    pub idempotency_key: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub run_after: Timestamp,
    pub locked_by: Option<String>,
    pub locked_at: Option<Timestamp>,
    pub actor_type: Option<String>,
    pub actor_id: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub finished_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub id: String,
    pub vm_id: String,
    pub name: String,
    pub description: String,
    pub state: SnapshotState,
    pub disk_path: Option<String>,
    pub size_bytes: Option<u64>,
    pub memory_included: bool,
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub completed_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewAuditEvent {
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    #[serde(default)]
    pub details: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub occurred_at: Timestamp,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub request_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub details: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustomerTokenRecord {
    pub id: String,
    pub vm_id: String,
    pub scopes: Vec<String>,
    pub bound_ip: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    pub session_expires_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VncTokenRecord {
    pub id: String,
    pub vm_id: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    pub session_expires_at: Option<Timestamp>,
    pub bound_ip: Option<String>,
    pub revoked_at: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use super::{IpBlacklistPatch, VmFirewallRulePatch, VmNetworkSecurityPatch, VmPatch};

    #[test]
    fn nullable_patch_fields_distinguish_omission_clear_and_value() {
        let omitted: VmNetworkSecurityPatch = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.syn_rate_limit_pps, None);

        let cleared: VmNetworkSecurityPatch =
            serde_json::from_str(r#"{"syn_rate_limit_pps":null}"#).unwrap();
        assert_eq!(cleared.syn_rate_limit_pps, Some(None));

        let set: VmNetworkSecurityPatch =
            serde_json::from_str(r#"{"syn_rate_limit_pps":1250}"#).unwrap();
        assert_eq!(set.syn_rate_limit_pps, Some(Some(1250)));
    }

    #[test]
    fn nullable_string_and_timestamp_fields_can_be_explicitly_cleared() {
        let vm: VmPatch = serde_json::from_str(
            r#"{"tap_name":null,"network_limit_mbps":null,"timezone":null}"#,
        )
        .unwrap();
        assert_eq!(vm.tap_name, Some(None));
        assert_eq!(vm.network_limit_mbps, Some(None));
        assert_eq!(vm.timezone, Some(None));

        let rule: VmFirewallRulePatch =
            serde_json::from_str(r#"{"source_cidr":null,"destination_cidr":null}"#).unwrap();
        assert_eq!(rule.source_cidr, Some(None));
        assert_eq!(rule.destination_cidr, Some(None));

        let blacklist: IpBlacklistPatch =
            serde_json::from_str(r#"{"expires_at":null}"#).unwrap();
        assert_eq!(blacklist.expires_at, Some(None));
    }
}
