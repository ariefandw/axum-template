use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::{
        events::Notification,
        pagination::{Cursor, CursorMeta, CursorParams},
    },
    services::notification::NotificationService,
    state::AppState,
};

/// Keyset-paginated, and scoped to the calling user by the query itself.
#[utoipa::path(
    get, path = "", params(CursorParams),
    responses(
        (status = 200, description = "Notification page for the current user", body = ApiResponse<Vec<Notification>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Notifications"
)]
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Query(params): Query<CursorParams>,
) -> Result<Json<ApiResponse<Vec<Notification>>>, AppError> {
    let limit = params.limit();
    let cursor = match params.cursor.as_deref() {
        Some(raw) => Some(
            Cursor::decode(raw).ok_or_else(|| AppError::BadRequest("Malformed cursor".into()))?,
        ),
        None => None,
    };

    let mut notifs = sqlx::query_as::<_, Notification>(
        r#"
        SELECT id, user_id, title, body, read, data, created_at FROM notifications
        WHERE user_id = $1
          AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3))
        ORDER BY created_at DESC, id DESC
        LIMIT $4
        "#,
    )
    .bind(auth_user.id)
    .bind(cursor.map(|c| c.created_at))
    .bind(cursor.map(|c| c.id))
    .bind(limit as i64 + 1)
    .fetch_all(&state.db)
    .await?;

    let has_next = notifs.len() as u64 > limit;
    notifs.truncate(limit as usize);
    let last = notifs.last().map(|n| Cursor {
        created_at: n.created_at,
        id: n.id,
    });

    let unread = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read = false",
    )
    .bind(auth_user.id)
    .fetch_one(&state.db)
    .await?;

    let mut meta =
        serde_json::to_value(CursorMeta::from_page(limit, has_next, last)).unwrap_or_default();
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("unread_count".into(), unread.into());
    }

    Ok(Json(ApiResponse::with_meta(notifs, meta)))
}

#[utoipa::path(
    patch, path = "/{id}/read",
    params(("id" = Uuid, Path, description = "Notification ID")),
    responses(
        (status = 200, description = "Marked as read", body = ApiResponse<String>),
        (status = 404, description = "Not found", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Notifications"
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
    patch, path = "/read-all",
    responses((status = 200, description = "All marked as read", body = ApiResponse<String>)),
    security(("bearer_auth" = [])), tag = "Notifications"
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
