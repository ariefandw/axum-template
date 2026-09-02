use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, StatusCode, header},
    middleware as axum_middleware,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_scalar::{Scalar, Servable};

pub mod config;
pub mod crypto;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;
pub mod state;

use crate::{
    config::AppConfig,
    error::{ApiErrorPayload, ApiErrorResponse, ApiResponse},
    models::api_key::{ApiKeyRecord, CreateApiKeyRequest, CreateApiKeyResponse},
    models::events::{AuditLog, Notification, RealtimeEvent},
    models::org::{
        AddOrgMemberRequest, App, CreateAppRequest, CreateOrgRequest, OrgMember, Organization,
    },
    models::pagination::{CursorMeta, CursorParams, PageMeta, PageParams},
    models::upload::{
        FileRecord, PresignedUploadRequest, PresignedUploadResponse, SignedUrlResponse,
        UploadResponse,
    },
    models::user::{
        AuthResponse, ChangePasswordRequest, ForgetPasswordRequest, RefreshTokenRequest,
        ResetPasswordRequest, SignInEmailRequest, SignUpEmailRequest, UpdateUserRequest,
        UserResponse, VerifyEmailRequest,
    },
    routes::health::HealthResponse,
    routes::v1::auth::{OAuthCallbackQuery, OAuthUrlResponse},
    state::AppState,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Axum Production API",
        version = "1.0.0",
        description = "Production-ready Axum API scaffold: session-backed auth, M2M API keys, RBAC, \
                       apps, organizations, owned storage with signed URLs, rate limiting, idempotency, metrics, \
                       cross-replica realtime, notifications, and an append-only audit log"
    ),
    components(schemas(
        HealthResponse, ApiErrorResponse, ApiErrorPayload,
        ApiResponse<App>, ApiResponse<Vec<App>>,
        ApiResponse<Organization>, ApiResponse<Vec<Organization>>,
        ApiResponse<OrgMember>,
        ApiResponse<CreateApiKeyResponse>, ApiResponse<Vec<ApiKeyRecord>>,
        ApiResponse<AuthResponse>, ApiResponse<UserResponse>, ApiResponse<Vec<UserResponse>>,
        ApiResponse<Vec<Notification>>, ApiResponse<Vec<AuditLog>>, ApiResponse<OAuthUrlResponse>,
        ApiResponse<UploadResponse>, ApiResponse<PresignedUploadResponse>,
        ApiResponse<SignedUrlResponse>, ApiResponse<String>,
        CreateAppRequest, CreateOrgRequest, AddOrgMemberRequest,
        CreateApiKeyRequest, CreateApiKeyResponse, ApiKeyRecord,
        App, Organization, OrgMember,
        SignUpEmailRequest, SignInEmailRequest, RefreshTokenRequest, VerifyEmailRequest,
        ForgetPasswordRequest, ResetPasswordRequest, UpdateUserRequest, ChangePasswordRequest,
        PresignedUploadRequest, PresignedUploadResponse, SignedUrlResponse, UploadResponse,
        FileRecord, PageParams, PageMeta, CursorParams, CursorMeta,
        AuthResponse, UserResponse, Notification, AuditLog, RealtimeEvent,
        OAuthCallbackQuery, OAuthUrlResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Observability", description = "Liveness, readiness and Prometheus metrics"),
        (name = "Authentication", description = "Registration, sign-in, sessions and recovery"),
        (name = "API Keys", description = "Machine-to-Machine (M2M) API keys management"),
        (name = "Applications", description = "Multi-app platform registry"),
        (name = "Organizations", description = "B2B tenant management and org memberships"),
        (name = "Users", description = "Profile management and admin user queries"),
        (name = "Notifications", description = "In-app notifications feed"),
        (name = "Realtime", description = "Server-Sent Events stream"),
        (name = "Audit", description = "Append-only compliance audit log"),
        (name = "Storage", description = "Owned file storage with signed URLs"),
        (name = "Webhooks", description = "Transactional outbox event webhooks")
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

fn build_cors(config: &AppConfig) -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-request-id"),
            header::HeaderName::from_static("idempotency-key"),
        ])
        .expose_headers([
            header::HeaderName::from_static("x-request-id"),
            header::HeaderName::from_static("x-idempotent-replayed"),
        ])
        .max_age(Duration::from_secs(3600));

    if config.cors_allowed_origins.is_empty() {
        // Configuration rejects this combination in production.
        tracing::warn!("CORS is open to any origin; set CORS_ALLOWED_ORIGINS before deploying");
        cors.allow_origin(AllowOrigin::any())
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        // Credentials are only meaningful against an explicit allowlist.
        cors.allow_origin(AllowOrigin::list(origins))
            .allow_credentials(true)
    }
}

pub fn create_app(state: Arc<AppState>) -> Router {
    let config = state.config.clone();

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(routes::app_router(&config))
        .with_state(state.clone())
        .split_for_parts();

    let global_limiter =
        middleware::rate_limit::global_limiter(&config).expect("Invalid rate limit configuration");

    let idempotency_state = state.clone();
    let headers_state = state.clone();

    router
        .merge(Scalar::with_url("/docs", api))
        // Inside routing, so `MatchedPath` is available and metric labels stay
        // bounded by the route template rather than the raw URI.
        .route_layer(axum_middleware::from_fn(middleware::metrics::track_metrics))
        .layer(axum_middleware::from_fn(move |req, next| {
            middleware::idempotency::idempotency_guard(idempotency_state.clone(), req, next)
        }))
        .layer(axum_middleware::from_fn(move |req, next| {
            middleware::security_headers::security_headers(headers_state.clone(), req, next)
        }))
        .layer(global_limiter)
        .layer(build_cors(&config))
        .layer(DefaultBodyLimit::max(config.body_limit_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.request_timeout_seconds),
        ))
        // Outermost counter: catches what never reaches a route, such as
        // rate-limit rejections and timeouts.
        .layer(axum_middleware::from_fn(
            middleware::metrics::track_outcomes,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new())
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}
