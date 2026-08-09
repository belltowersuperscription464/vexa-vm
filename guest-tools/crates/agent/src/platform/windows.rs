use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use vexa_guest_protocol::{Command, ResponseData};

use super::{require_user, run_command, ActionOutcome, DeferredAction, Platform};
use crate::config::Policy;

pub struct NativePlatform;

impl NativePlatform {
    pub fn new() -> Self {
        Self
    }

    fn health(&self, policy: &Policy) -> ResponseData {
        let powershell_available = windows_utility(r"WindowsPowerShell\v1.0\powershell.exe");
        let mut capabilities = Vec::new();
        if policy.password && powershell_available {
            capabilities.push("password".into());
        }
        if policy.hostname && powershell_available {
            capabilities.push("hostname".into());
        }
        if policy.dns && powershell_available {
            capabilities.push("dns".into());
        }
        if policy.ssh_keys
            && windows_utility("icacls.exe")
            && vexa_authorized_keys_configured()
        {
            capabilities.push("ssh_keys".into());
        }
        if policy.power && windows_utility("shutdown.exe") {
            capabilities.push("shutdown".into());
            capabilities.push("reboot".into());
        }

        ResponseData::Health {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            operating_system: format!("Windows {}", std::env::consts::ARCH),
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()),
            uptime_seconds: operating_system_uptime_seconds(),
            capabilities,
        }
    }

    fn set_password(&self, username: &str, password: &str) -> Result<()> {
        const SCRIPT: &str = "$s=ConvertTo-SecureString $vexaInput -AsPlainText -Force;Set-LocalUser -Name $args[0] -Password $s -ErrorAction Stop";
        run_powershell(SCRIPT, &[username], Some(password.as_bytes()))
    }

    fn set_hostname(&self, hostname: &str) -> Result<()> {
        const SCRIPT: &str = "Rename-Computer -NewName $args[0] -Force -ErrorAction Stop";
        run_powershell(SCRIPT, &[hostname], None)
    }

    fn set_dns(&self, interface: Option<&str>, servers: &[std::net::IpAddr]) -> Result<()> {
        #[derive(Serialize)]
        struct DnsPayload<'a> {
            interface: Option<&'a str>,
            servers: Vec<String>,
        }
        let payload = serde_json::to_vec(&DnsPayload {
            interface,
            servers: servers.iter().map(ToString::to_string).collect(),
        })?;
        const SCRIPT: &str = "$p=$vexaInput|ConvertFrom-Json;if($null-ne$p.interface){Set-DnsClientServerAddress -InterfaceAlias $p.interface -ServerAddresses $p.servers -ErrorAction Stop}else{Get-NetAdapter|Where-Object Status -eq 'Up'|Set-DnsClientServerAddress -ServerAddresses $p.servers -ErrorAction Stop}";
        run_powershell(SCRIPT, &[], Some(&payload))
    }

    fn set_ssh_keys(&self, username: &str, keys: &[String]) -> Result<()> {
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let sshd_configuration = program_data.join(r"ssh\sshd_config");
        let sshd_text = fs::read_to_string(&sshd_configuration)
            .context("Windows OpenSSH is not configured for Vexa-managed keys")?;
        if !sshd_text.contains("Vexa/GuestTools/authorized_keys/%u") {
            bail!("Windows OpenSSH is not configured for Vexa-managed keys");
        }
        let data_directory = program_data.join(r"Vexa\GuestTools\authorized_keys");
        fs::create_dir_all(&data_directory)
            .context("failed to create the protected OpenSSH directory")?;
        let key_file = data_directory.join(username);
        let existing = match fs::read_to_string(&key_file) {
            Ok(existing) => existing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(error).context("failed to read the existing authorized_keys file")
            }
        };
        let content = replace_managed_key_block(&existing, keys)?;
        fs::write(&key_file, content).context("failed to update authorized_keys")?;
        let path = key_file.to_str().context("OpenSSH path is not valid Unicode")?;
        run_command(
            "icacls.exe",
            &[
                path,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(F)",
                "/grant:r",
                "*S-1-5-32-544:(F)",
            ],
            None,
        )
    }
}

impl Platform for NativePlatform {
    fn execute(&self, command: &Command, policy: &Policy) -> Result<ActionOutcome> {
        match command {
            Command::Ping => Ok(ActionOutcome::immediate(ResponseData::Pong {
                agent_version: env!("CARGO_PKG_VERSION").into(),
            })),
            Command::Health => Ok(ActionOutcome::immediate(self.health(policy))),
            Command::SetPassword { username, password } => {
                require_enabled(policy.password, "password changes")?;
                require_user(policy, username)?;
                self.set_password(username, password)?;
                Ok(changed("password changed", false))
            }
            Command::SetHostname { hostname } => {
                require_enabled(policy.hostname, "hostname changes")?;
                self.set_hostname(hostname)?;
                Ok(changed("hostname changed", true))
            }
            Command::SetDns { interface, servers } => {
                require_enabled(policy.dns, "DNS changes")?;
                self.set_dns(interface.as_deref(), servers)?;
                Ok(changed("DNS servers changed", false))
            }
            Command::SetSshKeys {
                username,
                authorized_keys,
            } => {
                require_enabled(policy.ssh_keys, "SSH key changes")?;
                require_user(policy, username)?;
                self.set_ssh_keys(username, authorized_keys)?;
                Ok(changed("managed SSH keys changed", false))
            }
            Command::Shutdown => {
                require_enabled(policy.power, "power actions")?;
                Ok(deferred("shutdown accepted", DeferredAction::Shutdown))
            }
            Command::Reboot => {
                require_enabled(policy.power, "power actions")?;
                Ok(deferred("reboot accepted", DeferredAction::Reboot))
            }
        }
    }

    fn execute_deferred(&self, action: DeferredAction) -> Result<()> {
        match action {
            DeferredAction::Shutdown => run_command("shutdown.exe", &["/s", "/t", "0"], None),
            DeferredAction::Reboot => run_command("shutdown.exe", &["/r", "/t", "0"], None),
        }
    }
}

fn require_enabled(enabled: bool, operation: &str) -> Result<()> {
    if !enabled {
        bail!("{operation} are disabled by guest policy");
    }
    Ok(())
}

fn run_powershell(script: &str, arguments: &[&str], stdin: Option<&[u8]>) -> Result<()> {
    let wrapped_script = stdin.map(|_| {
        // Windows PowerShell decodes redirected console input using the active legacy code page.
        // Carry UTF-8 as ASCII base64 so passwords and interface aliases survive every locale.
        format!(
            "$vexaInput=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()));{script}"
        )
    });
    let mut encoded_input = stdin.map(|input| STANDARD.encode(input).into_bytes());
    let command_script = wrapped_script.as_deref().unwrap_or(script);
    let mut command_arguments = vec![
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command_script,
    ];
    command_arguments.extend_from_slice(arguments);
    let result = run_command(
        "powershell.exe",
        &command_arguments,
        encoded_input.as_deref(),
    );
    if let Some(input) = encoded_input.as_mut() {
        input.fill(0);
    }
    result
}

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

fn windows_utility(relative_to_system32: &str) -> bool {
    std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(relative_to_system32)
        .is_file()
}

fn vexa_authorized_keys_configured() -> bool {
    fs::read_to_string(program_data().join(r"ssh\sshd_config"))
        .map(|contents| contents.contains("Vexa/GuestTools/authorized_keys/%u"))
        .unwrap_or(false)
}

#[link(name = "kernel32")]
extern "system" {
    fn GetTickCount64() -> u64;
}

fn operating_system_uptime_seconds() -> u64 {
    // SAFETY: GetTickCount64 has no parameters, is available on every supported Windows release,
    // and returns a monotonic millisecond counter without caller-owned memory.
    unsafe { GetTickCount64() / 1000 }
}

fn changed(message: &str, reboot_required: bool) -> ActionOutcome {
    ActionOutcome::immediate(ResponseData::Action {
        changed: true,
        reboot_required,
        message: message.into(),
    })
}

fn deferred(message: &str, action: DeferredAction) -> ActionOutcome {
    ActionOutcome {
        data: ResponseData::Action {
            changed: true,
            reboot_required: false,
            message: message.into(),
        },
        deferred: Some(action),
    }
}

fn replace_managed_key_block(existing: &str, keys: &[String]) -> Result<String> {
    const BEGIN: &str = "# BEGIN VEXA GUEST TOOLS";
    const END: &str = "# END VEXA GUEST TOOLS";
    let mut preserved = match (existing.find(BEGIN), existing.find(END)) {
        (Some(start), Some(end)) if start <= end => {
            format!("{}{}", &existing[..start], &existing[end + END.len()..])
        }
        (None, None) => existing.to_owned(),
        _ => bail!("authorized_keys contains an incomplete Vexa managed block"),
    };
    while preserved.ends_with('\r') || preserved.ends_with('\n') {
        preserved.pop();
    }
    if !preserved.is_empty() {
        preserved.push_str("\r\n");
    }
    preserved.push_str(BEGIN);
    preserved.push_str("\r\n");
    for key in keys {
        preserved.push_str(key.trim());
        preserved.push_str("\r\n");
    }
    preserved.push_str(END);
    preserved.push_str("\r\n");
    Ok(preserved)
}
