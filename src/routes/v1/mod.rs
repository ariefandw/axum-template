use crate::{config::AppConfig, middleware::rate_limit, state::AppState};
use std::sync::Arc;
use utoipa_axum::router::OpenApiRouter;

pub mod api_key;
pub mod apps;
pub mod audit;
pub mod auth;
pub mod files;
pub mod notifications;
pub mod realtime;
pub mod users;
pub mod webhooks;

pub fn router(config: &AppConfig) -> OpenApiRouter<Arc<AppState>> {
    // Credential endpoints carry their own, much tighter bucket. Combined with
    // the per-account lockout in AuthService, this covers both an attacker
    // hammering one account and one spraying many.
    let auth_limiter =
        rate_limit::auth_limiter(config).expect("Invalid auth rate limit configuration");

    OpenApiRouter::new()
        .nest("/api-keys", api_key::router())
        .nest("/auth/api-key", api_key::router())
        .nest("/apps", apps::router())
        .nest("/auth", auth::router().layer(auth_limiter))
        .nest("/users", users::router())
        .nest("/files", files::router())
        .nest("/notifications", notifications::router())
        .nest("/realtime", realtime::router())
        .nest("/audit-logs", audit::router())
        .nest("/webhooks", webhooks::router())
}
