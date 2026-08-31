use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::user::{
        AuthResponse, ForgetPasswordRequest, ResetPasswordRequest, SignInEmailRequest,
        SignUpEmailRequest, User, UserResponse, VerifyEmailRequest,
    },
    services::{auth::AuthService, oauth::OAuthService},
    state::AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthUrlResponse {
    pub url: String,
    pub csrf_token: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/sign-up/email",
    request_body = SignUpEmailRequest,
    responses(
        (status = 201, description = "User registered successfully", body = ApiResponse<AuthResponse>),
        (status = 400, description = "Bad request / validation error", body = ApiErrorResponse),
        (status = 409, description = "User already exists", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn sign_up_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignUpEmailRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthResponse>>), AppError> {
    payload.validate()?;
    let res = AuthService::sign_up_email(&state, payload).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(res))))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/sign-in/email",
    request_body = SignInEmailRequest,
    responses(
        (status = 200, description = "Login successful", body = ApiResponse<AuthResponse>),
        (status = 401, description = "Invalid credentials", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn sign_in_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignInEmailRequest>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    payload.validate()?;
    let res = AuthService::sign_in_email(&state, payload).await?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified", body = ApiResponse<String>),
        (status = 400, description = "Invalid or expired token", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::verify_email(&state, payload).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/forget-password",
    request_body = ForgetPasswordRequest,
    responses(
        (status = 200, description = "Password reset initiated", body = ApiResponse<String>),
        (status = 400, description = "Validation error", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn forget_password(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ForgetPasswordRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    payload.validate()?;
    let msg = AuthService::forget_password(&state, payload).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/reset-password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset completed", body = ApiResponse<String>),
        (status = 400, description = "Invalid or expired token", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    payload.validate()?;
    let msg = AuthService::reset_password(&state, payload).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/get-session",
    responses(
        (status = 200, description = "Current authenticated user profile", body = ApiResponse<UserResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Authentication"
)]
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, name, email, email_verified, image, role, banned, created_at, updated_at FROM users WHERE id = $1",
    )
    .bind(auth_user.id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(ApiResponse::success(user.into())))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/sign-in/social/google",
    responses(
        (status = 200, description = "Google OAuth authorization URL", body = ApiResponse<OAuthUrlResponse>),
        (status = 400, description = "Google OAuth not configured", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn google_auth(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<OAuthUrlResponse>>, AppError> {
    let (url, csrf_token) = OAuthService::get_google_auth_url(&state)?;
    Ok(Json(ApiResponse::success(OAuthUrlResponse { url, csrf_token })))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/callback/google",
    params(
        ("code" = String, Query, description = "OAuth authorization code"),
        ("state" = Option<String>, Query, description = "CSRF state token")
    ),
    responses(
        (status = 200, description = "Google login successful", body = ApiResponse<AuthResponse>),
        (status = 401, description = "OAuth authentication failed", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn google_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    let res = OAuthService::handle_google_callback(&state, query.code).await?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/sign-in/social/github",
    responses(
        (status = 200, description = "GitHub OAuth authorization URL", body = ApiResponse<OAuthUrlResponse>),
        (status = 400, description = "GitHub OAuth not configured", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn github_auth(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<OAuthUrlResponse>>, AppError> {
    let (url, csrf_token) = OAuthService::get_github_auth_url(&state)?;
    Ok(Json(ApiResponse::success(OAuthUrlResponse { url, csrf_token })))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/callback/github",
    params(
        ("code" = String, Query, description = "OAuth authorization code"),
        ("state" = Option<String>, Query, description = "CSRF state token")
    ),
    responses(
        (status = 200, description = "GitHub login successful", body = ApiResponse<AuthResponse>),
        (status = 401, description = "OAuth authentication failed", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    let res = OAuthService::handle_github_callback(&state, query.code).await?;
    Ok(Json(ApiResponse::success(res)))
}
