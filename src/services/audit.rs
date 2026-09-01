//! Append-only audit trail.
//!
//! Previously this service had no callers at all, so the audit endpoint returned
//! an empty list forever. It is now invoked from every security-relevant
//! mutation, and the table itself is protected by a database trigger that
//! rejects `UPDATE` and `DELETE`.

use std::sync::Arc;

use uuid::Uuid;

use crate::{
    error::AppError, models::events::AuditLog, services::auth::RequestContext, state::AppState,
};

pub struct AuditService;

impl AuditService {
    #[allow(clippy::too_many_arguments)]
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
        let log = sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs
                (id, user_id, action, resource, resource_id, ip_address, user_agent, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, user_id, action, resource, resource_id, ip_address, user_agent,
                      metadata, created_at
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(action)
        .bind(resource)
        .bind(resource_id)
        .bind(ip_address)
        .bind(user_agent)
        .bind(metadata)
        .fetch_one(&state.db)
        .await?;

        Ok(log)
    }

    /// Record an event without letting an audit failure fail the operation being
    /// audited. The failure is logged loudly, because a silently missing audit
    /// trail is worse than a noisy one.
    pub async fn record_best_effort(
        state: &Arc<AppState>,
        user_id: Option<Uuid>,
        action: &str,
        resource: &str,
        resource_id: Option<&str>,
        ctx: &RequestContext,
        metadata: Option<serde_json::Value>,
    ) {
        if let Err(e) = Self::record(
            state,
            user_id,
            action,
            resource,
            resource_id,
            ctx.ip_address.as_deref(),
            ctx.user_agent.as_deref(),
            metadata,
        )
        .await
        {
            tracing::error!(action, resource, error = %e, "Failed to write audit log entry");
        }
    }
}
