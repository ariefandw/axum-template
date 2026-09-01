use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use utoipa::ToSchema;

/// Standardized Success Envelope
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data,
            meta: None,
        }
    }

    pub fn with_meta(data: T, meta: serde_json::Value) -> Self {
        Self {
            success: true,
            data,
            meta: Some(meta),
        }
    }
}

/// Standardized Error Envelope
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorResponse {
    pub success: bool,
    pub error: ApiErrorPayload,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow_error::AnyhowOrGeneric),
}

pub mod anyhow_error {
    #[derive(Debug)]
    pub struct AnyhowOrGeneric(pub String);

    impl std::fmt::Display for AnyhowOrGeneric {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for AnyhowOrGeneric {}

    impl From<String> for AnyhowOrGeneric {
        fn from(s: String) -> Self {
            Self(s)
        }
    }

    impl From<&str> for AnyhowOrGeneric {
        fn from(s: &str) -> Self {
            Self(s.to_string())
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match &self {
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone(), None)
            }
            AppError::ValidationError(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                msg.clone(),
                None,
            ),
            AppError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone(), None)
            }
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone(), None),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone(), None),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone(), None),
            AppError::PayloadTooLarge(msg) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                msg.clone(),
                None,
            ),
            AppError::TooManyRequests(msg) => (
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_REQUESTS",
                msg.clone(),
                None,
            ),
            AppError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                msg.clone(),
                None,
            ),
            AppError::DatabaseError(err) => {
                // A unique violation is a caller-visible conflict, not a server
                // fault: it is how concurrent sign-ups for one address resolve.
                if let sqlx::Error::Database(db_err) = err {
                    if db_err.is_unique_violation() {
                        tracing::debug!(target: "app::database", constraint = ?db_err.constraint(), "Unique violation");
                        (
                            StatusCode::CONFLICT,
                            "CONFLICT",
                            "That resource already exists".to_string(),
                            None,
                        )
                    } else {
                        tracing::error!(target: "app::database", error = ?db_err, "Database query failed");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DATABASE_ERROR",
                            "A database error occurred".to_string(),
                            None,
                        )
                    }
                } else {
                    tracing::error!(target: "app::database", error = ?err, "Database query failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "DATABASE_ERROR",
                        "A database error occurred".to_string(),
                        None,
                    )
                }
            }
            AppError::Internal(err) => {
                tracing::error!(target: "app::internal", error = ?err, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR",
                    "Internal server error".to_string(),
                    None,
                )
            }
        };

        let body = Json(ApiErrorResponse {
            success: false,
            error: ApiErrorPayload {
                code: code.to_string(),
                message,
                details,
            },
        });

        (status, body).into_response()
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(errs: validator::ValidationErrors) -> Self {
        AppError::ValidationError(errs.to_string())
    }
}
