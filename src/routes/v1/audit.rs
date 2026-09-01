use std::sync::Arc;
use axum::{
    extract::{Query, State},
    Json,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AdminUser,
    models::{
        events::AuditLog,
        pagination::{PageMeta, PageParams},
    },
    state::AppState,
};

#[utoipa::path(
    get,
    path = "",
    params(PageParams),
    responses(
        (status = 200, description = "Paginated list of system audit logs (Admin only)", body = ApiResponse<Vec<AuditLog>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden: Admin privileges required", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Audit"
)]
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    _admin_user: AdminUser,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<AuditLog>>>, AppError> {
    let limit = params.limit() as i64;
    let offset = params.offset() as i64;

    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT id, user_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&state.db)
        .await? as u64;

    let meta = PageMeta::new(params.page(), params.page_size(), total_count);

    Ok(Json(ApiResponse::with_meta(
        logs,
        serde_json::to_value(meta).unwrap(),
    )))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(list_audit_logs))
}
