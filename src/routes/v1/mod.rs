use std::sync::Arc;
use utoipa_axum::router::OpenApiRouter;
use crate::state::AppState;

pub mod audit;
pub mod auth;
pub mod files;
pub mod notifications;
pub mod realtime;
pub mod users;

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .nest("/auth", auth::router())
        .nest("/users", users::router())
        .nest("/files", files::router())
        .nest("/notifications", notifications::router())
        .nest("/realtime", realtime::router())
        .nest("/audit-logs", audit::router())
}
