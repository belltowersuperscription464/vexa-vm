pub mod config;
pub mod db;
pub mod error;
pub mod host;
pub mod hypervisor;
pub mod models;
pub mod rate_limit;
pub mod routes;
pub mod security;
pub mod services;
pub mod state;

use std::sync::Arc;

use axum::Router;

use crate::{config::Config, error::AppResult, state::AppState};

pub async fn build(config: Config) -> AppResult<(Router, Arc<AppState>)> {
    let state = AppState::initialize(config).await?;
    let router = routes::router(state.clone());
    Ok((router, state))
}

pub trait AppResultExt<T> {
    fn context_app(self, context: &str) -> anyhow::Result<T>;
}

impl<T> AppResultExt<T> for AppResult<T> {
    fn context_app(self, context: &str) -> anyhow::Result<T> {
        self.map_err(|error| anyhow::anyhow!("{context}: {error}"))
    }
}
