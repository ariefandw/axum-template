use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use crate::{error::AppError, models::events::AuditLog, state::AppState};

pub struct AuditService;

impl AuditService {
    pub async fn record(
        state: &Arc<AppState>,
        user_id: Option<Uuid>,
        action: &str,
        resource: &str,
        resource_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<AuditLog, AppError> {
        let log_id = Uuid::now_v7();
        let now = Utc::now();

        let log = sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs (id, user_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, user_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at
            "#,
        )
        .bind(log_id)
        .bind(user_id)
        .bind(action)
        .bind(resource)
        .bind(resource_id)
        .bind(ip_address)
        .bind(user_agent)
        .bind(metadata)
        .bind(now)
        .fetch_one(&state.db)
        .await?;

        tracing::info!(
            action = %action,
            resource = %resource,
            actor = ?user_id,
            "Audit event recorded"
        );

        Ok(log)
    }
}
