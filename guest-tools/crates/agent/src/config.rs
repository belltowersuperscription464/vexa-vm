use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use serde::Deserialize;
use vexa_guest_protocol::{DEFAULT_MAX_CLOCK_SKEW_SECONDS, MIN_SECRET_BYTES};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub channel_path: PathBuf,
    pub secret_file: PathBuf,
    pub max_clock_skew_seconds: u64,
    pub replay_cache_capacity: usize,
    pub reconnect_delay_seconds: u64,
    pub policy: Policy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub password: bool,
    pub hostname: bool,
    pub dns: bool,
    pub ssh_keys: bool,
    pub power: bool,
    pub allowed_users: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            // A hand-written configuration that omits policy must not expose
            // privileged mutations. Vexa provisioning writes every intended
            // capability explicitly, so normal opted-in installs are
            // unaffected by these deny-by-default serde values.
            password: false,
            hostname: false,
            dns: false,
            ssh_keys: false,
            power: false,
            allowed_users: Vec::new(),
        }
    }
}

impl Policy {
    pub fn permits_user(&self, username: &str) -> bool {
        self.allowed_users.is_empty() || self.allowed_users.iter().any(|item| item == username)
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            channel_path: default_channel_path(),
            secret_file: default_secret_file(),
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
            replay_cache_capacity: 4096,
            reconnect_delay_seconds: 2,
            policy: Policy::default(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read configuration {}", path.display()))?;
        let config: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.channel_path.as_os_str().is_empty() || self.secret_file.as_os_str().is_empty() {
            bail!("channel_path and secret_file are required");
        }
        if !(30..=600).contains(&self.max_clock_skew_seconds) {
            bail!("max_clock_skew_seconds must be between 30 and 600");
        }
        if !(128..=65_536).contains(&self.replay_cache_capacity) {
            bail!("replay_cache_capacity must be between 128 and 65536");
        }
        if !(1..=60).contains(&self.reconnect_delay_seconds) {
            bail!("reconnect_delay_seconds must be between 1 and 60");
        }
        for user in &self.policy.allowed_users {
            if user.is_empty()
                || user.len() > 64
                || user.starts_with('-')
                || !user
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                bail!("policy.allowed_users contains an invalid username");
            }
        }
        Ok(())
    }

    pub fn load_secret(&self) -> Result<Secret> {
        let metadata = fs::symlink_metadata(&self.secret_file)
            .with_context(|| format!("failed to inspect secret {}", self.secret_file.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("guest-tools secret must be a regular file, not a symbolic link");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                bail!("guest-tools secret must be owned by root and inaccessible to group/other users");
            }
        }
        let mut raw = fs::read(&self.secret_file)
            .with_context(|| format!("failed to read secret {}", self.secret_file.display()))?;
        let encoded = trim_ascii_whitespace(&raw);
        let encoded = encoded.strip_prefix(b"base64:").unwrap_or(encoded);
        let decoded = STANDARD_NO_PAD
            .decode(encoded)
            .or_else(|_| STANDARD.decode(encoded));
        raw.fill(0);
        let bytes = decoded.context("guest-tools secret is not valid base64")?;
        if bytes.len() < MIN_SECRET_BYTES {
            bail!("guest-tools secret must decode to at least 32 bytes");
        }
        Ok(Secret(bytes))
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub struct Secret(Vec<u8>);

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(target_os = "linux")]
pub fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/vexa-guest-tools/config.json")
}

#[cfg(windows)]
pub fn default_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(r"Vexa\GuestTools\config.json")
}

#[cfg(target_os = "linux")]
fn default_channel_path() -> PathBuf {
    PathBuf::from("/dev/virtio-ports/com.vexa.guest_tools.0")
}

#[cfg(windows)]
fn default_channel_path() -> PathBuf {
    PathBuf::from(r"\\.\Global\com.vexa.guest_tools.0")
}

#[cfg(target_os = "linux")]
fn default_secret_file() -> PathBuf {
    PathBuf::from("/etc/vexa-guest-tools/secret")
}

#[cfg(windows)]
fn default_secret_file() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(r"Vexa\GuestTools\secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        AgentConfig::default().validate().expect("valid defaults");
    }

    #[test]
    fn rejects_dangerous_time_windows() {
        let mut config = AgentConfig::default();
        config.max_clock_skew_seconds = 86_400;
        assert!(config.validate().is_err());
    }

    #[test]
    fn omitted_policy_is_deny_by_default() {
        let config: AgentConfig = serde_json::from_str(
            r#"{"channel_path":"channel","secret_file":"secret"}"#,
        )
        .expect("parse minimal config");
        assert!(!config.policy.password);
        assert!(!config.policy.hostname);
        assert!(!config.policy.dns);
        assert!(!config.policy.ssh_keys);
        assert!(!config.policy.power);
    }
}
