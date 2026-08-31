use std::sync::Arc;
use std::time::Duration;
use axum::{
    extract::DefaultBodyLimit,
    http::{header, Method, StatusCode},
    middleware as axum_middleware,
    Router,
};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_scalar::{Scalar, Servable};

pub mod config;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;
pub mod state;

use crate::{
    error::{ApiErrorPayload, ApiErrorResponse, ApiResponse},
    models::upload::UploadResponse,
    models::user::{
        AuthResponse, ForgetPasswordRequest, ResetPasswordRequest, SignInEmailRequest,
        SignUpEmailRequest, UserResponse, VerifyEmailRequest,
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
        description = "Production-ready Axum API scaffold with Auth, Rate Limiting, Idempotency, Metrics, and OpenAPI Docs"
    ),
    components(
        schemas(
            HealthResponse,
            ApiErrorResponse,
            ApiErrorPayload,
            ApiResponse<AuthResponse>,
            ApiResponse<UserResponse>,
            ApiResponse<OAuthUrlResponse>,
            ApiResponse<UploadResponse>,
            ApiResponse<String>,
            SignUpEmailRequest,
            SignInEmailRequest,
            VerifyEmailRequest,
            ForgetPasswordRequest,
            ResetPasswordRequest,
            AuthResponse,
            UserResponse,
            UploadResponse,
            OAuthCallbackQuery,
            OAuthUrlResponse
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Observability", description = "Health and Prometheus metrics"),
        (name = "Authentication", description = "User registration, login, verification, and sessions"),
        (name = "Social Login", description = "OAuth2 endpoints (Google, GitHub)"),
        (name = "Storage", description = "Streaming multipart file uploads & static downloads")
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

pub fn create_app(state: Arc<AppState>) -> Router {
    // 1. Setup CORS
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
        .allow_origin(tower_http::cors::Any);

    // 2. Setup OpenAPI Routes with utoipa-axum
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(routes::health::health_check))
        .routes(routes!(routes::health::prometheus_metrics))
        .routes(routes!(routes::v1::auth::sign_up_email))
        .routes(routes!(routes::v1::auth::sign_in_email))
        .routes(routes!(routes::v1::auth::verify_email))
        .routes(routes!(routes::v1::auth::forget_password))
        .routes(routes!(routes::v1::auth::reset_password))
        .routes(routes!(routes::v1::auth::get_session))
        .routes(routes!(routes::v1::auth::google_auth))
        .routes(routes!(routes::v1::auth::google_callback))
        .routes(routes!(routes::v1::auth::github_auth))
        .routes(routes!(routes::v1::auth::github_callback))
        .routes(routes!(routes::v1::files::upload_file))
        .routes(routes!(routes::v1::files::get_file))
        .with_state(state.clone())
        .split_for_parts();

    // 3. Rate limiter
    let rate_limiter = middleware::rate_limit::create_rate_limiter();

    // 4. Merge Scalar Doc and middleware stack
    let app_state_clone = state.clone();

    router
        .merge(Scalar::with_url("/docs", api))
        .layer(axum_middleware::from_fn(middleware::metrics::track_metrics))
        .layer(axum_middleware::from_fn(move |req, next| {
            middleware::idempotency::idempotency_guard(app_state_clone.clone(), req, next)
        }))
        .layer(axum_middleware::from_fn(middleware::security_headers::security_headers))
        .layer(rate_limiter)
        .layer(cors)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB Max Request Body
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}
