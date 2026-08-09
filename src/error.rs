use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("{0} was not found")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("request limit exceeded")]
    RateLimited,
    #[error("database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("hypervisor operation failed: {0}")]
    Hypervisor(String),
    #[error("template rendering failed: {0}")]
    Template(#[from] tera::Error),
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorEnvelope {
    success: bool,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    request_id: String,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Hypervisor(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Configuration(_)
            | Self::Database(_)
            | Self::Template(_)
            | Self::Io(_)
            | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Configuration(_) => "configuration_error",
            Self::Validation(_) => "validation_error",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Database(_) => "database_error",
            Self::Hypervisor(_) => "hypervisor_error",
            Self::Template(_) => "template_error",
            Self::Io(_) => "io_error",
            Self::Internal(_) => "internal_error",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Database(_) | Self::Template(_) | Self::Io(_) | Self::Internal(_) => {
                "The server could not complete the request".into()
            }
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let request_id = Uuid::new_v4().to_string();
        let status = self.status_code();
        if status.is_server_error() {
            error!(%request_id, error = %self, "request failed");
        }
        let mut response = (
            status,
            Json(ErrorEnvelope {
                success: false,
                error: ErrorBody {
                    code: self.code(),
                    message: self.public_message(),
                    request_id,
                },
            }),
        )
            .into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("60"),
            );
        }
        response
    }
}
