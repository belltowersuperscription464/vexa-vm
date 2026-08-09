use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub public_url: String,
    pub database_path: PathBuf,
    pub template_dir: PathBuf,
    pub static_dir: PathBuf,
    pub master_key: [u8; 32],
    pub bootstrap_admin: String,
    pub bootstrap_password: Option<String>,
    pub secure_cookies: bool,
    pub hypervisor_mode: HypervisorMode,
    pub libvirt_uri: String,
    pub vm_storage: PathBuf,
    pub iso_storage: PathBuf,
    pub cloud_init_storage: PathBuf,
    pub guest_tools_socket_dir: PathBuf,
    pub guest_tools_linux_x86_64_artifact: Option<PathBuf>,
    pub guest_tools_windows_x86_64_artifact: Option<PathBuf>,
    pub guest_tools_version: String,
    pub network_bridge: String,
    pub public_interface: Option<String>,
    pub vnc_ttl: Duration,
    pub metrics_interval: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypervisorMode {
    Auto,
    Libvirt,
    Mock,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        let bind = parse_env("VEXA_BIND", "127.0.0.1:8080")?;
        let public_url = env_or("VEXA_PUBLIC_URL", &format!("http://{bind}"));
        let secure_cookies = parse_bool_env("VEXA_SECURE_COOKIES", public_url.starts_with("https://"))?;
        let master_key = load_master_key()?;
        let hypervisor_mode = match env_or("VEXA_HYPERVISOR", "mock").to_ascii_lowercase().as_str() {
            "auto" => HypervisorMode::Auto,
            "libvirt" | "kvm" => HypervisorMode::Libvirt,
            "mock" => HypervisorMode::Mock,
            value => {
                return Err(AppError::Configuration(format!(
                    "VEXA_HYPERVISOR must be auto, libvirt, or mock; got {value}"
                )))
            }
        };
        let guest_tools_linux_x86_64_artifact =
            non_empty_env("VEXA_GUEST_TOOLS_LINUX_X86_64_ARTIFACT").map(PathBuf::from);
        let guest_tools_windows_x86_64_artifact =
            non_empty_env("VEXA_GUEST_TOOLS_WINDOWS_X86_64_ARTIFACT").map(PathBuf::from);
        let guest_tools_version = configured_guest_tools_version(
            guest_tools_linux_x86_64_artifact.as_deref(),
            guest_tools_windows_x86_64_artifact.as_deref(),
            non_empty_env("VEXA_GUEST_TOOLS_VERSION"),
        );

        Self {
            bind,
            public_url: public_url.trim_end_matches('/').to_owned(),
            database_path: env_or("VEXA_DATABASE", "data/vexa.db").into(),
            template_dir: env_or("VEXA_TEMPLATE_DIR", "templates").into(),
            static_dir: env_or("VEXA_STATIC_DIR", "static").into(),
            master_key,
            bootstrap_admin: env_or("VEXA_BOOTSTRAP_ADMIN", "admin"),
            bootstrap_password: non_empty_env("VEXA_BOOTSTRAP_PASSWORD"),
            secure_cookies,
            hypervisor_mode,
            libvirt_uri: env_or("VEXA_LIBVIRT_URI", "qemu:///system"),
            vm_storage: env_or("VEXA_VM_STORAGE", "data/vms").into(),
            iso_storage: env_or("VEXA_ISO_STORAGE", "data/isos").into(),
            cloud_init_storage: env_or("VEXA_CLOUD_INIT_STORAGE", "data/cloud-init").into(),
            guest_tools_socket_dir: env_or(
                "VEXA_GUEST_TOOLS_SOCKET_DIR",
                "/var/lib/vexa-vm/guest-tools",
            )
            .into(),
            guest_tools_linux_x86_64_artifact,
            guest_tools_windows_x86_64_artifact,
            guest_tools_version,
            network_bridge: env_or("VEXA_NETWORK_BRIDGE", "virbr0"),
            public_interface: non_empty_env("VEXA_PUBLIC_INTERFACE"),
            vnc_ttl: Duration::from_secs(parse_env("VEXA_VNC_TTL_SECONDS", "600")?),
            metrics_interval: Duration::from_secs(parse_env("VEXA_METRICS_INTERVAL_SECONDS", "15")?),
        }
        .validate()
    }

    pub fn validate(self) -> AppResult<Self> {
        if self.vnc_ttl != Duration::from_secs(600) {
            return Err(AppError::Configuration(
                "VEXA_VNC_TTL_SECONDS must be exactly 600 seconds".into(),
            ));
        }
        if self.metrics_interval < Duration::from_secs(5) {
            return Err(AppError::Configuration(
                "VEXA_METRICS_INTERVAL_SECONDS cannot be lower than 5".into(),
            ));
        }
        if !matches!(self.public_url.split_once("://"), Some(("http" | "https", _))) {
            return Err(AppError::Configuration(
                "VEXA_PUBLIC_URL must start with http:// or https://".into(),
            ));
        }
        if !self.guest_tools_socket_dir.is_absolute() {
            return Err(AppError::Configuration(
                "VEXA_GUEST_TOOLS_SOCKET_DIR must be an absolute path".into(),
            ));
        }
        if self.guest_tools_version.len() > 64
            || self.guest_tools_version.is_empty()
            || self.guest_tools_version.chars().any(char::is_control)
        {
            return Err(AppError::Configuration(
                "VEXA_GUEST_TOOLS_VERSION must contain 1-64 printable characters".into(),
            ));
        }
        Ok(self)
    }
}

fn configured_guest_tools_version(
    linux_artifact: Option<&Path>,
    windows_artifact: Option<&Path>,
    explicit_version: Option<String>,
) -> String {
    const BUNDLED_LINUX: &str =
        "/opt/vexa-vm/current/guest-tools/vexa-guest-tools-linux-x86_64";
    const BUNDLED_WINDOWS: &str =
        "/opt/vexa-vm/current/guest-tools/vexa-guest-tools-windows-x86_64.exe";
    let bundled = linux_artifact == Some(Path::new(BUNDLED_LINUX))
        && windows_artifact == Some(Path::new(BUNDLED_WINDOWS));
    if bundled {
        // Both artifacts move atomically with `current`; an old environment
        // override must not pin their expected version across self-updates.
        env!("CARGO_PKG_VERSION").to_owned()
    } else {
        explicit_version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned())
    }
}

fn load_master_key() -> AppResult<[u8; 32]> {
    let raw = non_empty_env("VEXA_MASTER_KEY").ok_or_else(|| {
        AppError::Configuration(
            "VEXA_MASTER_KEY is required; generate it with `openssl rand -base64 32`".into(),
        )
    })?;
    let decoded = STANDARD.decode(raw.trim()).map_err(|_| {
        AppError::Configuration("VEXA_MASTER_KEY must be valid base64 for exactly 32 bytes".into())
    })?;
    decoded
        .try_into()
        .map_err(|_| AppError::Configuration("VEXA_MASTER_KEY must decode to exactly 32 bytes".into()))
}

fn env_or(name: &str, default: &str) -> String {
    non_empty_env(name).unwrap_or_else(|| default.to_owned())
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_env<T>(name: &str, default: &str) -> AppResult<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    env_or(name, default)
        .parse()
        .map_err(|error| AppError::Configuration(format!("invalid {name}: {error}")))
}

fn parse_bool_env(name: &str, default: bool) -> AppResult<bool> {
    match non_empty_env(name)
        .unwrap_or_else(|| default.to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AppError::Configuration(format!("{name} must be true or false"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ten_minute_vnc_ttl() {
        let config = Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            public_url: "http://127.0.0.1:8080".into(),
            database_path: "x.db".into(),
            template_dir: "templates".into(),
            static_dir: "static".into(),
            master_key: [7; 32],
            bootstrap_admin: "admin".into(),
            bootstrap_password: None,
            secure_cookies: false,
            hypervisor_mode: HypervisorMode::Mock,
            libvirt_uri: "qemu:///system".into(),
            vm_storage: "vms".into(),
            iso_storage: "isos".into(),
            cloud_init_storage: "seed".into(),
            guest_tools_socket_dir: "/var/lib/vexa-vm/guest-tools".into(),
            guest_tools_linux_x86_64_artifact: None,
            guest_tools_windows_x86_64_artifact: None,
            guest_tools_version: "0.1.0".into(),
            network_bridge: "virbr0".into(),
            public_interface: None,
            vnc_ttl: Duration::from_secs(599),
            metrics_interval: Duration::from_secs(15),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn bundled_guest_tools_follow_the_running_release_version() {
        let linux = Path::new(
            "/opt/vexa-vm/current/guest-tools/vexa-guest-tools-linux-x86_64",
        );
        let windows = Path::new(
            "/opt/vexa-vm/current/guest-tools/vexa-guest-tools-windows-x86_64.exe",
        );
        assert_eq!(
            configured_guest_tools_version(
                Some(linux),
                Some(windows),
                Some("stale-version".into()),
            ),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            configured_guest_tools_version(
                Some(Path::new("/srv/custom/guest-tools")),
                Some(windows),
                Some("vendor-7".into()),
            ),
            "vendor-7"
        );
    }
}
