use std::time::Duration;

use anyhow::Context;
use tokio::signal;
use tracing::info;
use tracing_subscriber::EnvFilter;

use vexa_vm::{config::Config, services, AppResultExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Config::from_env().context_app("could not load configuration")?;
    let bind = config.bind;
    let (router, state) = vexa_vm::build(config)
        .await
        .context_app("could not initialize Vexa-VM")?;
    services::background::spawn(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("could not bind {bind}"))?;
    info!(%bind, version = env!("CARGO_PKG_VERSION"), "Vexa-VM is listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server stopped unexpectedly")?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("VEXA_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("could not install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("could not install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown requested");
    tokio::time::sleep(Duration::from_millis(100)).await;
}
