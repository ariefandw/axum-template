use std::sync::Arc;
use utoipa_axum::router::OpenApiRouter;
use crate::state::AppState;

pub mod auth;
pub mod files;

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .nest("/auth", auth::router())
        .nest("/files", files::router())
}
