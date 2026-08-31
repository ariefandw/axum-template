use std::sync::Arc;
use utoipa_axum::{router::OpenApiRouter, routes};
use crate::state::AppState;

pub mod health;
pub mod v1;

pub fn app_router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(health::health_check))
        .routes(routes!(health::prometheus_metrics))
        .nest("/api/v1", v1::router())
}
