use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::{AuthUser, SessionUser},
    models::user::{
        AuthResponse, ChangePasswordRequest, ForgetPasswordRequest, RefreshTokenRequest,
        ResetPasswordRequest, SignInEmailRequest, SignUpEmailRequest, UpdateUserRequest,
        UserResponse, VerifyEmailRequest,
    },
    services::{
        auth::{AuthService, RequestContext},
        oauth::OAuthService,
    },
    state::AppState,
};

/// The `state` parameter is required: it is checked against the pending
/// authorization request this server issued.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthUrlResponse {
    pub url: String,
    /// Echo of the CSRF state, for clients that want to correlate the redirect.
    pub state: String,
}

#[utoipa::path(
    post, path = "/sign-up/email", request_body = SignUpEmailRequest,
    responses(
        (status = 201, description = "User registered", body = ApiResponse<AuthResponse>),
        (status = 409, description = "User already exists", body = ApiErrorResponse),
        (status = 422, description = "Validation error", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn sign_up_email(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Json(payload): Json<SignUpEmailRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthResponse>>), AppError> {
    payload.validate()?;
    let res = AuthService::sign_up_email(&state, payload, &ctx).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(res))))
}

#[utoipa::path(
    post, path = "/sign-in/email", request_body = SignInEmailRequest,
    responses(
        (status = 200, description = "Signed in", body = ApiResponse<AuthResponse>),
        (status = 401, description = "Invalid credentials", body = ApiErrorResponse),
        (status = 429, description = "Account temporarily locked", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn sign_in_email(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Json(payload): Json<SignInEmailRequest>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    payload.validate()?;
    let res = AuthService::sign_in_email(&state, payload, &ctx).await?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    post, path = "/refresh", request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "New access and refresh token pair", body = ApiResponse<AuthResponse>),
        (status = 401, description = "Invalid, expired, or replayed refresh token", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    let res = AuthService::refresh_session(&state, &payload.refresh_token, &ctx).await?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    post, path = "/sign-out",
    responses((status = 200, description = "Current session revoked", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn sign_out(
    State(state): State<Arc<AppState>>,
    session_user: SessionUser,
    ctx: RequestContext,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::sign_out(&state, session_user.id, session_user.session_id, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post, path = "/sign-out-all",
    responses((status = 200, description = "All sessions revoked", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn sign_out_all(
    State(state): State<Arc<AppState>>,
    session_user: SessionUser,
    ctx: RequestContext,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::sign_out_all(&state, session_user.id, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post, path = "/verify-email", request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified", body = ApiResponse<String>),
        (status = 400, description = "Invalid or expired token", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::verify_email(&state, payload, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post, path = "/forget-password", request_body = ForgetPasswordRequest,
    responses((status = 200, description = "Reset initiated if the address is registered", body = ApiResponse<String>)),
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
    post, path = "/reset-password", request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset; all sessions revoked", body = ApiResponse<String>),
        (status = 400, description = "Invalid or expired token", body = ApiErrorResponse)
    ),
    tag = "Authentication"
)]
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    payload.validate()?;
    let msg = AuthService::reset_password(&state, payload, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    get, path = "/get-session",
    responses(
        (status = 200, description = "Current authenticated user", body = ApiResponse<UserResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn get_session(
    auth_user: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    crate::routes::v1::users::load_user(&state, auth_user.id)
        .await
        .map(|u| Json(ApiResponse::success(u)))
}

// ---------------------------------------------------------------------------
// Better Auth RPC-style aliases. These delegate to the same service methods as
// their REST equivalents; no business logic is duplicated.
//   POST /update-user     <-> PATCH  /api/v1/users/me
//   POST /change-password <-> PATCH  /api/v1/users/me/password
//   POST /delete-user     <-> DELETE /api/v1/users/me
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/update-user", request_body = UpdateUserRequest,
    responses((status = 200, description = "Profile updated", body = ApiResponse<UserResponse>)),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    payload.validate()?;
    let updated = AuthService::update_profile(&state, auth_user.id, payload).await?;
    Ok(Json(ApiResponse::success(updated)))
}

#[utoipa::path(
    post, path = "/change-password", request_body = ChangePasswordRequest,
    responses((status = 200, description = "Password changed", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    session_user: SessionUser,
    ctx: RequestContext,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    payload.validate()?;
    let msg = AuthService::change_password(
        &state,
        session_user.id,
        session_user.session_id,
        payload,
        &ctx,
    )
    .await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    post, path = "/delete-user",
    responses((status = 200, description = "Account deleted", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Authentication"
)]
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    session_user: SessionUser,
    ctx: RequestContext,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::delete_account(&state, session_user.id, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

// --- Social OAuth2 ---------------------------------------------------------

#[utoipa::path(
    get, path = "/sign-in/social/google",
    responses((status = 200, description = "Google authorization URL", body = ApiResponse<OAuthUrlResponse>)),
    tag = "Social Login"
)]
pub async fn google_auth(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<OAuthUrlResponse>>, AppError> {
    Ok(Json(ApiResponse::success(
        OAuthService::get_google_auth_url(&state).await?,
    )))
}

#[utoipa::path(
    get, path = "/callback/google",
    params(
        ("code" = String, Query, description = "Authorization code"),
        ("state" = String, Query, description = "CSRF state issued by /sign-in/social/google")
    ),
    responses(
        (status = 200, description = "Signed in with Google", body = ApiResponse<AuthResponse>),
        (status = 401, description = "Invalid state or failed exchange", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn google_callback(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    let res = OAuthService::handle_google_callback(&state, query.code, query.state, &ctx).await?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    get, path = "/sign-in/social/github",
    responses((status = 200, description = "GitHub authorization URL", body = ApiResponse<OAuthUrlResponse>)),
    tag = "Social Login"
)]
pub async fn github_auth(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<OAuthUrlResponse>>, AppError> {
    Ok(Json(ApiResponse::success(
        OAuthService::get_github_auth_url(&state).await?,
    )))
}

#[utoipa::path(
    get, path = "/callback/github",
    params(
        ("code" = String, Query, description = "Authorization code"),
        ("state" = String, Query, description = "CSRF state issued by /sign-in/social/github")
    ),
    responses(
        (status = 200, description = "Signed in with GitHub", body = ApiResponse<AuthResponse>),
        (status = 401, description = "Invalid state or failed exchange", body = ApiErrorResponse)
    ),
    tag = "Social Login"
)]
pub async fn github_callback(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<ApiResponse<AuthResponse>>, AppError> {
    let res = OAuthService::handle_github_callback(&state, query.code, query.state, &ctx).await?;
    Ok(Json(ApiResponse::success(res)))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(sign_up_email))
        .routes(routes!(sign_in_email))
        .routes(routes!(refresh))
        .routes(routes!(sign_out))
        .routes(routes!(sign_out_all))
        .routes(routes!(verify_email))
        .routes(routes!(forget_password))
        .routes(routes!(reset_password))
        .routes(routes!(get_session))
        .routes(routes!(update_user))
        .routes(routes!(change_password))
        .routes(routes!(delete_user))
        .routes(routes!(google_auth))
        .routes(routes!(google_callback))
        .routes(routes!(github_auth))
        .routes(routes!(github_callback))
}
