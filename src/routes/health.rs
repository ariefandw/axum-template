use std::sync::Arc;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "System health check", body = HealthResponse),
        (status = 503, description = "Service unavailable", body = HealthResponse)
    ),
    tag = "Observability"
)]
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<HealthResponse>)> {
    let db_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "healthy".to_string(),
        Err(e) => {
            tracing::error!(target: "health::check", error = ?e, "Database ping failed");
            "unhealthy".to_string()
        }
    };

    let is_ok = db_status == "healthy";
    let resp = HealthResponse {
        status: if is_ok { "ok".to_string() } else { "degraded".to_string() },
        database: db_status,
        timestamp: chrono::Utc::now(),
    };

    if is_ok {
        Ok(Json(resp))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(resp)))
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus metrics dump", content_type = "text/plain")
    ),
    tag = "Observability"
)]
pub async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    state.prometheus_handle.render()
}
