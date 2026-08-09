mod config;
mod platform;
#[cfg(windows)]
mod windows_service;

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("Vexa Guest Tools supports Linux and Windows targets only");

use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use config::{default_config_path, AgentConfig};
use platform::{NativePlatform, Platform};
use tracing::{error, info, warn};
use vexa_guest_protocol::{read_frame, write_frame, ReplayCache, Request, Response};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vexa_guest_tools=info".into()),
        )
        .init();

    let (config_path, service_mode) = arguments()?;
    #[cfg(windows)]
    if service_mode {
        return windows_service::dispatch(config_path);
    }
    #[cfg(not(windows))]
    if service_mode {
        anyhow::bail!("--service is supported only on Windows");
    }

    run_agent_with_path(Arc::new(AtomicBool::new(false)), config_path)
}

fn arguments() -> Result<(PathBuf, bool)> {
    let mut path = std::env::var_os("VEXA_GUEST_TOOLS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);
    let mut service = false;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--service" {
            service = true;
        } else if argument == "--config" {
            path = arguments
                .next()
                .map(PathBuf::from)
                .context("--config requires a path")?;
        } else {
            anyhow::bail!("unknown argument: {}", argument.to_string_lossy());
        }
    }
    Ok((path, service))
}

#[cfg(windows)]
pub(crate) fn run_agent(stopping: Arc<AtomicBool>) -> Result<()> {
    let path = std::env::var_os("VEXA_GUEST_TOOLS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);
    run_agent_with_path(stopping, path)
}

fn run_agent_with_path(stopping: Arc<AtomicBool>, config_path: PathBuf) -> Result<()> {
    let config = AgentConfig::load(&config_path)?;
    let secret = config.load_secret()?;
    let platform = NativePlatform::new();
    let mut replay_cache = ReplayCache::new(config.replay_cache_capacity);
    info!(
        channel = %config.channel_path.display(),
        "Vexa Guest Tools started"
    );

    while !stopping.load(Ordering::Acquire) {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.channel_path)
        {
            Ok(mut channel) => {
                info!("connected to Vexa host channel");
                if let Err(error) = serve_channel(
                    &mut channel,
                    &config,
                    secret.as_ref(),
                    &platform,
                    &mut replay_cache,
                    &stopping,
                ) {
                    warn!(error = %error, "host channel disconnected");
                }
            }
            Err(error) => {
                warn!(error = %error, "guest channel is not available; retrying");
            }
        }
        for _ in 0..config.reconnect_delay_seconds * 10 {
            if stopping.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    info!("Vexa Guest Tools stopped");
    Ok(())
}

fn serve_channel<P: Platform>(
    channel: &mut std::fs::File,
    config: &AgentConfig,
    secret: &[u8],
    platform: &P,
    replay_cache: &mut ReplayCache,
    stopping: &AtomicBool,
) -> Result<()> {
    while !stopping.load(Ordering::Acquire) {
        let request: Request = read_frame(channel).context("failed to read host request")?;
        let now = unix_timestamp();
        let command = match request.verify_and_decrypt(
            secret,
            now,
            config.max_clock_skew_seconds,
            replay_cache,
        ) {
            Ok(command) => command,
            Err(error) => {
                warn!(error = %error, "rejected unauthenticated guest-tools request");
                anyhow::bail!("host request authentication failed");
            }
        };

        let action = command.kind();
        let (response, deferred) = match platform.execute(&command, &config.policy) {
            Ok(outcome) => (
                Response::success(&request, unix_timestamp(), outcome.data, secret)?,
                outcome.deferred,
            ),
            Err(error) => {
                warn!(request_id = %request.request_id, action, error = %error, "guest action failed");
                (
                    Response::failure(
                        &request,
                        unix_timestamp(),
                        "action_failed",
                        error.to_string(),
                        secret,
                    )?,
                    None,
                )
            }
        };
        write_frame(channel, &response).context("failed to write host response")?;
        info!(
            request_id = %request.request_id,
            action,
            succeeded = response.ok,
            "processed guest action"
        );

        if let Some(deferred) = deferred {
            if let Err(error) = platform.execute_deferred(deferred) {
                error!(request_id = %request.request_id, action, error = %error, "deferred action failed");
            }
        }
    }
    Ok(())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
