use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AdminUser,
    models::{
        events::AuditLog,
        pagination::{Cursor, CursorMeta, CursorParams},
    },
    state::AppState,
};

const AUDIT_COLUMNS: &str = "id, user_id, action, resource, resource_id, ip_address, \
                             user_agent, metadata, created_at";

#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditFilter {
    /// Restrict to one actor.
    pub user_id: Option<Uuid>,
    /// Restrict to one action, e.g. `user.signed_in`.
    pub action: Option<String>,
}

/// Audit logs are keyset-paginated: the table is append-only and grows without
/// bound, so `OFFSET` plus `COUNT(*)` would get slower with every entry.
#[utoipa::path(
    get, path = "", params(CursorParams, AuditFilter),
    responses(
        (status = 200, description = "Audit log page (admin only)", body = ApiResponse<Vec<AuditLog>>),
        (status = 403, description = "Admin privileges required", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Audit"
)]
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    _admin_user: AdminUser,
    Query(params): Query<CursorParams>,
    Query(filter): Query<AuditFilter>,
) -> Result<Json<ApiResponse<Vec<AuditLog>>>, AppError> {
    let limit = params.limit();
    let cursor = match params.cursor.as_deref() {
        Some(raw) => Some(
            Cursor::decode(raw).ok_or_else(|| AppError::BadRequest("Malformed cursor".into()))?,
        ),
        None => None,
    };

    // One extra row tells us whether a further page exists.
    let mut logs = sqlx::query_as::<_, AuditLog>(&format!(
        r#"
        SELECT {AUDIT_COLUMNS} FROM audit_logs
        WHERE ($1::uuid IS NULL OR user_id = $1)
          AND ($2::text IS NULL OR action = $2)
          AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4))
        ORDER BY created_at DESC, id DESC
        LIMIT $5
        "#
    ))
    .bind(filter.user_id)
    .bind(filter.action.as_deref())
    .bind(cursor.map(|c| c.created_at))
    .bind(cursor.map(|c| c.id))
    .bind(limit as i64 + 1)
    .fetch_all(&state.db)
    .await?;

    let has_next = logs.len() as u64 > limit;
    logs.truncate(limit as usize);
    let last = logs.last().map(|l| Cursor {
        created_at: l.created_at,
        id: l.id,
    });

    let meta = CursorMeta::from_page(limit, has_next, last);
    Ok(Json(ApiResponse::with_meta(
        logs,
        serde_json::to_value(meta).unwrap_or_default(),
    )))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(list_audit_logs))
}
