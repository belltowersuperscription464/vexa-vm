#![cfg(windows)]

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "VexaGuestTools";

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(config_path: PathBuf) -> Result<()> {
    std::env::set_var("VEXA_GUEST_TOOLS_CONFIG", config_path);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to connect to Windows Service Control Manager")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(error = %error, "Windows service stopped with an error");
    }
}

fn run_service() -> windows_service::Result<()> {
    let stopping = Arc::new(AtomicBool::new(false));
    let handler_stopping = Arc::clone(&stopping);
    let event_handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stopping.store(true, Ordering::Release);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status.set_service_status(service_status(
        ServiceState::StartPending,
        0,
        1,
        Duration::from_secs(5),
    ))?;

    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let worker_stopping = Arc::clone(&stopping);
    std::thread::spawn(move || {
        let result = crate::run_agent(worker_stopping);
        let _ = finished_tx.send(result);
    });

    // Catch configuration/secret failures before claiming that the service is healthy. Channel
    // absence is intentionally retried by the worker and therefore does not block service start.
    let mut exit_code = 0;
    match finished_rx.recv_timeout(Duration::from_millis(300)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::error!(error = %error, "guest-tools worker failed during startup");
            exit_code = 1;
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            status.set_service_status(service_status(
                ServiceState::Running,
                0,
                0,
                Duration::default(),
            ))?;
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => exit_code = 1,
    }

    while !stopping.load(Ordering::Acquire) {
        if exit_code != 0 {
            break;
        }
        match finished_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(())) => break,
            Ok(Err(error)) => {
                tracing::error!(error = %error, "guest-tools worker failed");
                exit_code = 1;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                exit_code = 1;
                break;
            }
        }
    }

    stopping.store(true, Ordering::Release);
    status.set_service_status(service_status(
        ServiceState::StopPending,
        0,
        1,
        Duration::from_secs(5),
    ))?;

    // The virtio channel read can be blocked in the kernel. Give the worker a bounded graceful-stop
    // window, updating SCM checkpoints, then return so the process can close the channel.
    let mut worker_finished = exit_code != 0;
    for checkpoint in 2..=11 {
        if worker_finished {
            break;
        }
        match finished_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(())) => worker_finished = true,
            Ok(Err(error)) => {
                tracing::error!(error = %error, "guest-tools worker failed while stopping");
                exit_code = 1;
                worker_finished = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                status.set_service_status(service_status(
                    ServiceState::StopPending,
                    0,
                    checkpoint,
                    Duration::from_secs(5),
                ))?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                exit_code = 1;
                worker_finished = true;
            }
        }
    }
    if !worker_finished {
        tracing::warn!("guest-tools worker did not stop before the service deadline");
    }
    status.set_service_status(service_status(
        ServiceState::Stopped,
        exit_code,
        0,
        Duration::default(),
    ))?;
    Ok(())
}

fn service_status(
    state: ServiceState,
    exit_code: u32,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}
