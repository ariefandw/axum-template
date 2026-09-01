use std::sync::Arc;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{config::AppConfig, state::AppState};

pub mod health;
pub mod v1;

pub fn app_router(config: &AppConfig) -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(health::health_check))
        .routes(routes!(health::liveness))
        .routes(routes!(health::readiness))
        .routes(routes!(health::prometheus_metrics))
        .nest("/api/v1", v1::router(config))
}
