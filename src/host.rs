//! Linux host discovery and live node metrics.
//!
//! Discovery is intentionally read-only. It reads fixed `/proc` and `/sys`
//! locations and, when available, invokes an absolute `ip`/`df` executable
//! with a fixed argument vector. A missing optional source produces partial
//! data and a warning rather than preventing the panel from starting.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{process::Command, time::sleep};

use crate::error::{AppError, AppResult};

const SAMPLE_WINDOW: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub operating_system: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub primary_interface: Option<String>,
    pub default_gateway_v4: Option<IpAddr>,
    pub default_gateway_v6: Option<IpAddr>,
    pub interfaces: Vec<NetworkInterfaceInfo>,
    pub filesystems: Vec<FilesystemInfo>,
    pub listening_tcp_ports: Vec<u16>,
    pub detected_at: DateTime<Utc>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub logical_cores: u32,
    pub physical_cores: u32,
    pub current_frequency_mhz: Option<u64>,
    pub virtualization_supported: bool,
    pub kvm_device_available: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub scope: String,
    pub is_primary: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac_address: Option<String>,
    pub state: String,
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub is_loopback: bool,
    pub addresses: Vec<HostAddress>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub source: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostMetrics {
    pub sampled_at: DateTime<Utc>,
    pub window_ms: u64,
    pub cpu_usage_pct: f64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub uptime_seconds: u64,
    pub memory: MemoryInfo,
    pub memory_used_bytes: u64,
    pub interfaces: Vec<InterfaceMetric>,
    pub block_devices: Vec<BlockDeviceMetric>,
    pub filesystems: Vec<FilesystemInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceMetric {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_second: f64,
    pub tx_bytes_per_second: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockDeviceMetric {
    pub name: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_bytes_per_second: f64,
    pub write_bytes_per_second: f64,
}

#[derive(Clone, Debug, Default)]
struct CpuTicks {
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug, Default)]
struct IoCounters {
    read: u64,
    written: u64,
}

#[derive(Clone, Debug, Default)]
struct DefaultRoute {
    interface: Option<String>,
    gateway: Option<IpAddr>,
    preferred_source: Option<IpAddr>,
}

#[derive(Clone, Debug, Default)]
pub struct HostDetector {
    preferred_interface: Option<String>,
}

impl HostDetector {
    pub fn new(preferred_interface: Option<String>) -> AppResult<Self> {
        if preferred_interface
            .as_deref()
            .is_some_and(|name| !valid_interface_name(name))
        {
            return Err(AppError::Validation(
                "preferred public interface is not a valid Linux interface name".into(),
            ));
        }
        Ok(Self { preferred_interface })
    }

    pub async fn detect(&self) -> AppResult<HostInfo> {
        detect_host(self.preferred_interface.as_deref()).await
    }

    pub async fn sample(&self) -> AppResult<HostMetrics> {
        sample_host_metrics().await
    }
}

/// Detect static host capabilities, IP addresses and link properties.
pub async fn detect_host(preferred_interface: Option<&str>) -> AppResult<HostInfo> {
    let mut warnings = Vec::new();
    let cpuinfo = read_optional("/proc/cpuinfo").await.unwrap_or_default();
    let memory = read_memory_info().await?;
    let cpu = parse_cpu_info(&cpuinfo).await;
    let route_v4 = read_default_route(false).await.unwrap_or_default();
    let route_v6 = read_default_route(true).await.unwrap_or_default();

    let primary_interface = preferred_interface
        .filter(|name| valid_interface_name(name))
        .map(ToOwned::to_owned)
        .or(route_v4.interface.clone())
        .or(route_v6.interface.clone());

    let address_map = match read_ip_addresses().await {
        Ok(addresses) => addresses,
        Err(message) => {
            warnings.push(message);
            HashMap::new()
        }
    };
    let mut interfaces = read_interfaces(address_map).await?;
    mark_primary_address(
        &mut interfaces,
        primary_interface.as_deref(),
        route_v4.preferred_source.or(route_v6.preferred_source),
    );

    if interfaces.is_empty() {
        warnings.push("no Linux network interfaces were detected in /sys/class/net".into());
    }

    let filesystems = match read_filesystems().await {
        Ok(items) => items,
        Err(message) => {
            warnings.push(message);
            Vec::new()
        }
    };

    Ok(HostInfo {
        hostname: read_optional("/proc/sys/kernel/hostname")
            .await
            .unwrap_or_else(|| "unknown".into()),
        operating_system: read_os_name().await,
        kernel_version: read_optional("/proc/sys/kernel/osrelease").await,
        architecture: std::env::consts::ARCH.into(),
        cpu,
        memory,
        primary_interface,
        default_gateway_v4: route_v4.gateway,
        default_gateway_v6: route_v6.gateway,
        interfaces,
        filesystems,
        listening_tcp_ports: read_listening_tcp_ports().await,
        detected_at: Utc::now(),
        warnings,
    })
}

/// Take a short, non-blocking delta sample. Totals come from kernel counters;
/// rates are derived over a 250 ms Tokio timer and therefore do not block an
/// executor thread.
pub async fn sample_host_metrics() -> AppResult<HostMetrics> {
    let first_cpu = read_cpu_ticks().await?;
    let first_network = read_network_counters().await?;
    let first_block = read_block_counters().await?;

    sleep(SAMPLE_WINDOW).await;

    let second_cpu = read_cpu_ticks().await?;
    let second_network = read_network_counters().await?;
    let second_block = read_block_counters().await?;
    let elapsed = SAMPLE_WINDOW.as_secs_f64();

    let cpu_delta = second_cpu.total.saturating_sub(first_cpu.total);
    let idle_delta = second_cpu.idle.saturating_sub(first_cpu.idle);
    let cpu_usage_pct = if cpu_delta == 0 {
        0.0
    } else {
        (cpu_delta.saturating_sub(idle_delta) as f64 * 100.0 / cpu_delta as f64).clamp(0.0, 100.0)
    };

    let mut interfaces: Vec<_> = second_network
        .iter()
        .map(|(name, current)| {
            let previous = first_network.get(name).cloned().unwrap_or_default();
            InterfaceMetric {
                name: name.clone(),
                rx_bytes: current.read,
                tx_bytes: current.written,
                rx_bytes_per_second: current.read.saturating_sub(previous.read) as f64 / elapsed,
                tx_bytes_per_second: current.written.saturating_sub(previous.written) as f64 / elapsed,
            }
        })
        .collect();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));

    let mut block_devices: Vec<_> = second_block
        .iter()
        .map(|(name, current)| {
            let previous = first_block.get(name).cloned().unwrap_or_default();
            BlockDeviceMetric {
                name: name.clone(),
                read_bytes: current.read,
                write_bytes: current.written,
                read_bytes_per_second: current.read.saturating_sub(previous.read) as f64 / elapsed,
                write_bytes_per_second: current.written.saturating_sub(previous.written) as f64 / elapsed,
            }
        })
        .collect();
    block_devices.sort_by(|left, right| left.name.cmp(&right.name));

    let memory = read_memory_info().await?;
    let (load_1m, load_5m, load_15m) = read_load_average().await;
    Ok(HostMetrics {
        sampled_at: Utc::now(),
        window_ms: SAMPLE_WINDOW.as_millis() as u64,
        cpu_usage_pct: round_two(cpu_usage_pct),
        load_1m,
        load_5m,
        load_15m,
        uptime_seconds: read_uptime().await,
        memory_used_bytes: memory.total_bytes.saturating_sub(memory.available_bytes),
        memory,
        interfaces,
        block_devices,
        filesystems: read_filesystems().await.unwrap_or_default(),
    })
}

async fn parse_cpu_info(cpuinfo: &str) -> CpuInfo {
    let logical_cores = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor") && line.contains(':'))
        .count()
        .max(1) as u32;
    let model = cpuinfo.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        matches!(key.trim(), "model name" | "Processor")
            .then(|| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    });

    let mut physical_pairs = HashSet::new();
    let mut fallback_cores = None;
    for block in cpuinfo.split("\n\n") {
        let mut physical_id = None;
        let mut core_id = None;
        for line in block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "physical id" => physical_id = value.trim().parse::<u32>().ok(),
                "core id" => core_id = value.trim().parse::<u32>().ok(),
                "cpu cores" if fallback_cores.is_none() => fallback_cores = value.trim().parse::<u32>().ok(),
                _ => {}
            }
        }
        if let (Some(socket), Some(core)) = (physical_id, core_id) {
            physical_pairs.insert((socket, core));
        }
    }

    let current_frequency_mhz = read_optional("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        .await
        .and_then(|value| value.parse::<u64>().ok())
        .map(|khz| khz / 1000);
    let virtualization_supported = cpuinfo.split_ascii_whitespace().any(|flag| {
        matches!(
            flag.trim_matches(|character: char| !character.is_alphanumeric()),
            "vmx" | "svm"
        )
    });

    CpuInfo {
        model,
        logical_cores,
        physical_cores: u32::try_from(physical_pairs.len())
            .ok()
            .filter(|count| *count > 0)
            .or(fallback_cores)
            .unwrap_or(logical_cores),
        current_frequency_mhz,
        virtualization_supported,
        kvm_device_available: Path::new("/dev/kvm").exists(),
    }
}

async fn read_memory_info() -> AppResult<MemoryInfo> {
    let raw = tokio::fs::read_to_string("/proc/meminfo").await?;
    let values: HashMap<_, _> = raw
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key, kib.saturating_mul(1024)))
        })
        .collect();
    Ok(MemoryInfo {
        total_bytes: values.get("MemTotal").copied().unwrap_or(0),
        available_bytes: values
            .get("MemAvailable")
            .or_else(|| values.get("MemFree"))
            .copied()
            .unwrap_or(0),
        swap_total_bytes: values.get("SwapTotal").copied().unwrap_or(0),
        swap_free_bytes: values.get("SwapFree").copied().unwrap_or(0),
    })
}

async fn read_os_name() -> Option<String> {
    let raw = read_optional("/etc/os-release").await?;
    let entries: HashMap<_, _> = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim(), value.trim().trim_matches('"')))
        })
        .collect();
    entries
        .get("PRETTY_NAME")
        .or_else(|| entries.get("NAME"))
        .map(|value| (*value).to_owned())
}

async fn read_ip_addresses() -> Result<HashMap<String, Vec<HostAddress>>, String> {
    let ip = find_binary("ip").ok_or_else(|| "the `ip` command was not found".to_owned())?;
    let output = Command::new(ip)
        .args(["-j", "address", "show"])
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|error| format!("could not inspect host addresses: {error}"))?;
    if !output.status.success() {
        return Err("the `ip address` command failed".into());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "the `ip address` response was not valid JSON".to_owned())?;
    let mut result = HashMap::<String, Vec<HostAddress>>::new();
    for interface in payload.as_array().into_iter().flatten() {
        let Some(name) = interface.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        if !valid_interface_name(name) {
            continue;
        }
        for item in interface
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(address) = item
                .get("local")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let max_prefix = if address.is_ipv4() { 32 } else { 128 };
            let prefix_len = item
                .get("prefixlen")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value <= max_prefix)
                .unwrap_or(max_prefix);
            result.entry(name.to_owned()).or_default().push(HostAddress {
                address,
                prefix_len,
                scope: item
                    .get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                is_primary: false,
            });
        }
    }
    Ok(result)
}

async fn read_default_route(ipv6: bool) -> Option<DefaultRoute> {
    let ip = find_binary("ip")?;
    let family = if ipv6 { "-6" } else { "-4" };
    let output = Command::new(ip)
        .args(["-j", family, "route", "show", "default"])
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let payload: Value = serde_json::from_slice(&output.stdout).ok()?;
    let route = payload.as_array()?.first()?;
    Some(DefaultRoute {
        interface: route
            .get("dev")
            .and_then(Value::as_str)
            .filter(|name| valid_interface_name(name))
            .map(ToOwned::to_owned),
        gateway: route
            .get("gateway")
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok()),
        preferred_source: route
            .get("prefsrc")
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok()),
    })
}

async fn read_interfaces(
    mut addresses: HashMap<String, Vec<HostAddress>>,
) -> AppResult<Vec<NetworkInterfaceInfo>> {
    let mut entries = tokio::fs::read_dir("/sys/class/net").await?;
    let mut interfaces = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_interface_name(&name) {
            continue;
        }
        let root = PathBuf::from("/sys/class/net").join(&name);
        interfaces.push(NetworkInterfaceInfo {
            mac_address: read_path_optional(root.join("address")).await,
            state: read_path_optional(root.join("operstate"))
                .await
                .unwrap_or_else(|| "unknown".into()),
            mtu: read_path_optional(root.join("mtu"))
                .await
                .and_then(|value| value.parse().ok()),
            speed_mbps: read_path_optional(root.join("speed"))
                .await
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|value| u64::try_from(value).ok())
                .filter(|value| *value > 0),
            duplex: read_path_optional(root.join("duplex"))
                .await
                .filter(|value| !value.is_empty()),
            is_loopback: name == "lo",
            addresses: addresses.remove(&name).unwrap_or_default(),
            rx_bytes: read_path_u64(root.join("statistics/rx_bytes")).await,
            tx_bytes: read_path_u64(root.join("statistics/tx_bytes")).await,
            name,
        });
    }
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(interfaces)
}

fn mark_primary_address(
    interfaces: &mut [NetworkInterfaceInfo],
    primary_interface: Option<&str>,
    preferred_source: Option<IpAddr>,
) {
    let mut marked = false;
    if let Some(source) = preferred_source {
        for interface in interfaces.iter_mut() {
            for address in &mut interface.addresses {
                if address.address == source {
                    address.is_primary = true;
                    marked = true;
                }
            }
        }
    }
    if marked {
        return;
    }
    let Some(primary_interface) = primary_interface else {
        return;
    };
    if let Some(interface) = interfaces
        .iter_mut()
        .find(|interface| interface.name == primary_interface)
    {
        let primary_index = interface
            .addresses
            .iter()
            .position(|address| address.scope == "global" && address.address.is_ipv4())
            .or_else(|| {
                interface
                    .addresses
                    .iter()
                    .position(|address| address.scope == "global")
            });
        if let Some(index) = primary_index {
            interface.addresses[index].is_primary = true;
        }
    }
}

async fn read_filesystems() -> Result<Vec<FilesystemInfo>, String> {
    let df = find_binary("df").ok_or_else(|| "the `df` command was not found".to_owned())?;
    let output = Command::new(df)
        .args(["-B1", "-P"])
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|error| format!("could not inspect filesystems: {error}"))?;
    if !output.status.success() {
        return Err("the `df` command failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut filesystems = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let Some(total_bytes) = fields[1].parse().ok() else {
            continue;
        };
        let Some(used_bytes) = fields[2].parse().ok() else {
            continue;
        };
        let Some(available_bytes) = fields[3].parse().ok() else {
            continue;
        };
        filesystems.push(FilesystemInfo {
            source: fields[0].to_owned(),
            mount_point: fields[5..].join(" "),
            total_bytes,
            used_bytes,
            available_bytes,
        });
    }
    filesystems.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    Ok(filesystems)
}

/// Return current free bytes for the filesystem containing `path`.
///
/// This is used immediately before a large image transfer instead of relying
/// on the periodically sampled host inventory, which may already be stale.
pub(crate) async fn filesystem_available_bytes(path: &Path) -> AppResult<u64> {
    let df =
        find_binary("df").ok_or_else(|| AppError::Configuration("the `df` command was not found".into()))?;
    let output = Command::new(df)
        .args(["-B1", "-P", "--"])
        .arg(path)
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|error| AppError::Internal(format!("could not inspect image storage: {error}")))?;
    if !output.status.success() {
        return Err(AppError::Configuration(
            "the filesystem containing image storage could not be inspected".into(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(3))
        .filter_map(|value| value.parse::<u64>().ok())
        .next()
        .ok_or_else(|| AppError::Internal("image storage free space was unavailable".into()))
}

async fn read_cpu_ticks() -> AppResult<CpuTicks> {
    let raw = tokio::fs::read_to_string("/proc/stat").await?;
    let line = raw
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| AppError::Internal("/proc/stat did not contain aggregate CPU data".into()))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse().ok())
        .collect();
    if values.len() < 4 {
        return Err(AppError::Internal(
            "/proc/stat aggregate CPU data was incomplete".into(),
        ));
    }
    Ok(CpuTicks {
        total: values.iter().take(8).copied().sum(),
        idle: values[3].saturating_add(values.get(4).copied().unwrap_or(0)),
    })
}

async fn read_network_counters() -> AppResult<HashMap<String, IoCounters>> {
    let interfaces = read_interfaces(HashMap::new()).await?;
    Ok(interfaces
        .into_iter()
        .map(|interface| {
            (
                interface.name,
                IoCounters {
                    read: interface.rx_bytes,
                    written: interface.tx_bytes,
                },
            )
        })
        .collect())
}

async fn read_block_counters() -> AppResult<HashMap<String, IoCounters>> {
    let raw = tokio::fs::read_to_string("/proc/diskstats").await?;
    let mut result = HashMap::new();
    for line in raw.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let name = fields[2];
        if !valid_block_name(name)
            || !PathBuf::from("/sys/block").join(name).exists()
            || name.starts_with("loop")
            || name.starts_with("ram")
        {
            continue;
        }
        let Some(read_sectors) = fields[5].parse::<u64>().ok() else {
            continue;
        };
        let Some(written_sectors) = fields[9].parse::<u64>().ok() else {
            continue;
        };
        result.insert(
            name.to_owned(),
            IoCounters {
                read: read_sectors.saturating_mul(512),
                written: written_sectors.saturating_mul(512),
            },
        );
    }
    Ok(result)
}

async fn read_load_average() -> (f64, f64, f64) {
    let Some(raw) = read_optional("/proc/loadavg").await else {
        return (0.0, 0.0, 0.0);
    };
    let mut values = raw
        .split_whitespace()
        .take(3)
        .map(|value| value.parse::<f64>().unwrap_or(0.0));
    (
        values.next().unwrap_or(0.0),
        values.next().unwrap_or(0.0),
        values.next().unwrap_or(0.0),
    )
}

async fn read_uptime() -> u64 {
    read_optional("/proc/uptime")
        .await
        .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
        .map(|seconds| seconds.max(0.0) as u64)
        .unwrap_or(0)
}

async fn read_listening_tcp_ports() -> Vec<u16> {
    let mut ports = BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Some(raw) = read_optional(path).await else {
            continue;
        };
        for line in raw.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[3] != "0A" {
                continue;
            }
            let Some((_, port_hex)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                ports.insert(port);
            }
        }
    }
    ports.into_iter().collect()
}

async fn read_optional(path: impl AsRef<Path>) -> Option<String> {
    read_path_optional(path.as_ref().to_path_buf()).await
}

async fn read_path_optional(path: PathBuf) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|value| value.trim().to_owned())
}

async fn read_path_u64(path: PathBuf) -> u64 {
    read_path_optional(path)
        .await
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_block_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn find_binary(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| PathBuf::from(directory).join(name))
        .find(|path| path.is_file())
}

fn round_two(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_cannot_escape_sysfs() {
        assert!(valid_interface_name("enp1s0.20"));
        assert!(!valid_interface_name("../../etc/passwd"));
        assert!(!valid_interface_name("name with spaces"));
    }

    #[tokio::test]
    async fn samples_linux_metrics() {
        let sample = sample_host_metrics().await.unwrap();
        assert!((0.0..=100.0).contains(&sample.cpu_usage_pct));
        assert!(sample.memory.total_bytes > 0);
    }
}
