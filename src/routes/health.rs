use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{crypto, error::AppError, state::AppState};

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Liveness: is the process running? Deliberately does not touch the database.
///
/// A single endpoint that checks dependencies makes an orchestrator restart pods
/// during a database blip, which removes capacity exactly when the database is
/// already struggling. Liveness and readiness must answer different questions.
#[utoipa::path(
    get, path = "/health/live",
    responses((status = 200, description = "Process is alive", body = HealthResponse)),
    tag = "Observability"
)]
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        database: "not_checked".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        timestamp: chrono::Utc::now(),
    })
}

/// Readiness: can this instance serve traffic? Fails the instance out of the
/// load balancer without restarting it.
#[utoipa::path(
    get, path = "/health/ready",
    responses(
        (status = 200, description = "Ready to serve", body = HealthResponse),
        (status = 503, description = "Dependencies unavailable", body = HealthResponse)
    ),
    tag = "Observability"
)]
pub async fn readiness(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<HealthResponse>)> {
    let healthy = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .inspect_err(
            |e| tracing::error!(target: "health::ready", error = ?e, "Database ping failed"),
        )
        .is_ok();

    let resp = HealthResponse {
        status: if healthy { "ok" } else { "degraded" }.into(),
        database: if healthy { "healthy" } else { "unhealthy" }.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        timestamp: chrono::Utc::now(),
    };

    if healthy {
        Ok(Json(resp))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(resp)))
    }
}

/// Retained as an alias for readiness, so existing probes keep working.
#[utoipa::path(
    get, path = "/health",
    responses(
        (status = 200, description = "System health", body = HealthResponse),
        (status = 503, description = "Service unavailable", body = HealthResponse)
    ),
    tag = "Observability"
)]
pub async fn health_check(
    state: State<Arc<AppState>>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<HealthResponse>)> {
    readiness(state).await
}

/// Prometheus scrape endpoint.
///
/// Requires `METRICS_TOKEN` when one is configured, which production always is.
/// Route inventory, traffic volume and error rates are internal information and
/// were previously served to anyone.
#[utoipa::path(
    get, path = "/metrics",
    responses(
        (status = 200, description = "Prometheus exposition format", content_type = "text/plain"),
        (status = 401, description = "Missing or invalid metrics token")
    ),
    security(("bearer_auth" = [])), tag = "Observability"
)]
pub async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    if let Some(expected) = state.config.metrics_token.as_ref() {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();

        if !crypto::constant_time_eq(presented, expected.expose()) {
            return Err(AppError::Unauthorized("Invalid metrics token".to_string()));
        }
    }

    Ok((
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.prometheus_handle.render(),
    )
        .into_response())
}
