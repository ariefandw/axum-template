use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::{
        events::Notification,
        pagination::{PageMeta, PageParams},
    },
    services::notification::NotificationService,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "",
    params(PageParams),
    responses(
        (status = 200, description = "Paginated list of notifications for current user", body = ApiResponse<Vec<Notification>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Notifications"
)]
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<Notification>>>, AppError> {
    let limit = params.limit() as i64;
    let offset = params.offset() as i64;

    let notifs = sqlx::query_as::<_, Notification>(
        "SELECT id, user_id, title, body, read, data, created_at FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth_user.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1",
    )
    .bind(auth_user.id)
    .fetch_one(&state.db)
    .await? as u64;

    let meta = PageMeta::new(params.page(), params.page_size(), total_count);

    Ok(Json(ApiResponse::with_meta(
        notifs,
        serde_json::to_value(meta).unwrap(),
    )))
}

#[utoipa::path(
    patch,
    path = "/{id}/read",
    params(
        ("id" = Uuid, Path, description = "Notification ID")
    ),
    responses(
        (status = 200, description = "Notification marked as read", body = ApiResponse<String>),
        (status = 404, description = "Notification not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Notifications"
)]
pub async fn mark_notification_read(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = NotificationService::mark_as_read(&state, auth_user.id, id).await?;
    Ok(Json(ApiResponse::success(msg)))
}

#[utoipa::path(
    patch,
    path = "/read-all",
    responses(
        (status = 200, description = "All notifications marked as read", body = ApiResponse<String>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Notifications"
)]
pub async fn mark_all_notifications_read(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = NotificationService::mark_all_as_read(&state, auth_user.id).await?;
    Ok(Json(ApiResponse::success(msg)))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(list_notifications))
        .routes(routes!(mark_notification_read))
        .routes(routes!(mark_all_notifications_read))
}
