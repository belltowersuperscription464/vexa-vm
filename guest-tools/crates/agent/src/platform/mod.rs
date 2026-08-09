use std::{
    io::Write,
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use vexa_guest_protocol::{Command, ResponseData};

use crate::config::Policy;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::NativePlatform;
#[cfg(windows)]
pub use windows::NativePlatform;

#[derive(Clone, Copy, Debug)]
pub enum DeferredAction {
    Shutdown,
    Reboot,
}

pub struct ActionOutcome {
    pub data: ResponseData,
    pub deferred: Option<DeferredAction>,
}

impl ActionOutcome {
    pub fn immediate(data: ResponseData) -> Self {
        Self {
            data,
            deferred: None,
        }
    }
}

pub trait Platform {
    fn execute(&self, command: &Command, policy: &Policy) -> Result<ActionOutcome>;
    fn execute_deferred(&self, action: DeferredAction) -> Result<()>;
}

pub(super) fn require_user(policy: &Policy, username: &str) -> Result<()> {
    if !policy.permits_user(username) {
        bail!("the requested user is not allowed by guest policy");
    }
    Ok(())
}

pub(super) fn run_command(
    program: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> Result<()> {
    let mut command = ProcessCommand::new(program);
    command
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start required operating-system utility {program}"))?;
    if let Some(input) = stdin {
        let pipe = child.stdin.as_mut().context("failed to open command input")?;
        pipe.write_all(input).context("failed to send command input")?;
    }
    drop(child.stdin.take());

    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to wait for utility")? {
            if status.success() {
                return Ok(());
            }
            bail!("operating-system utility returned a failure status");
        }
        if started.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("operating-system utility timed out");
        }
        thread::sleep(Duration::from_millis(50));
    }
}
