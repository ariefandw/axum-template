use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::{AdminUser, AuthUser},
    models::{
        pagination::{PageMeta, PageParams},
        user::{ChangePasswordRequest, USER_COLUMNS, UpdateUserRequest, User, UserResponse},
    },
    services::auth::{AuthService, RequestContext},
    state::AppState,
};

/// Shared read path, so every caller filters soft-deleted rows identically.
pub async fn load_user(state: &Arc<AppState>, user_id: Uuid) -> Result<UserResponse, AppError> {
    sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLUMNS} FROM users WHERE id = $1 AND deleted_at IS NULL"
    ))
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .map(Into::into)
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

#[utoipa::path(
    get, path = "/me",
    responses(
        (status = 200, description = "Current authenticated user", body = ApiResponse<UserResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Users"
)]
pub async fn get_me(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    Ok(Json(ApiResponse::success(
        load_user(&state, auth_user.id).await?,
    )))
}

#[utoipa::path(
    patch, path = "/me", request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "Profile updated", body = ApiResponse<UserResponse>),
        (status = 422, description = "Validation error", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Users"
)]
pub async fn update_me(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    payload.validate()?;
    let updated = AuthService::update_profile(&state, auth_user.id, payload).await?;
    Ok(Json(ApiResponse::success(updated)))
}

#[utoipa::path(
    patch, path = "/me/password", request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed; other sessions revoked", body = ApiResponse<String>),
        (status = 401, description = "Incorrect current password", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Users"
)]
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    ctx: RequestContext,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    payload.validate()?;
    let msg =
        AuthService::change_password(&state, auth_user.id, auth_user.session_id, payload, &ctx)
            .await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    delete, path = "/me",
    responses((status = 200, description = "Account deleted", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Users"
)]
pub async fn delete_me(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    ctx: RequestContext,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = AuthService::delete_account(&state, auth_user.id, &ctx).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    get, path = "", params(PageParams),
    responses(
        (status = 200, description = "Paginated users (admin only)", body = ApiResponse<Vec<UserResponse>>),
        (status = 403, description = "Admin privileges required", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Users"
)]
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _admin_user: AdminUser,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<UserResponse>>>, AppError> {
    let users = sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    ))
    .bind(params.limit() as i64)
    .bind(params.offset() as i64)
    .fetch_all(&state.db)
    .await?;

    let total_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
            .fetch_one(&state.db)
            .await? as u64;

    let meta = PageMeta::new(params.page(), params.page_size(), total_count);
    let user_responses: Vec<UserResponse> = users.into_iter().map(Into::into).collect();

    Ok(Json(ApiResponse::with_meta(
        user_responses,
        serde_json::to_value(meta).unwrap_or_default(),
    )))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(get_me))
        .routes(routes!(update_me))
        .routes(routes!(change_password))
        .routes(routes!(delete_me))
        .routes(routes!(list_users))
}
