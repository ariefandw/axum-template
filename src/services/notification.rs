//! In-app notifications, with realtime delivery.
//!
//! `create` previously had no callers, so both this feed and the SSE stream that
//! depends on it were permanently empty. It is now called from the auth and
//! storage paths, and publishes through Postgres so every replica's connected
//! clients receive the event.

use std::sync::Arc;

use uuid::Uuid;

use crate::{
    error::AppError,
    models::events::{Notification, RealtimeEvent},
    services::realtime::RealtimeService,
    state::AppState,
};

pub struct NotificationService;

impl NotificationService {
    pub async fn create(
        state: &Arc<AppState>,
        user_id: Uuid,
        title: &str,
        body: &str,
        data: Option<serde_json::Value>,
    ) -> Result<Notification, AppError> {
        Self::create_scoped(state, user_id, None, title, body, data).await
    }

    /// Create a notification, optionally attributed to an organization so the
    /// recipient can separate tenant activity from personal activity.
    pub async fn create_scoped(
        state: &Arc<AppState>,
        user_id: Uuid,
        org_id: Option<Uuid>,
        title: &str,
        body: &str,
        data: Option<serde_json::Value>,
    ) -> Result<Notification, AppError> {
        let notif = sqlx::query_as::<_, Notification>(
            r#"
            INSERT INTO notifications (id, user_id, org_id, title, body, read, data)
            VALUES ($1, $2, $3, $4, $5, false, $6)
            RETURNING id, user_id, org_id, title, body, read, data, created_at
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(org_id)
        .bind(title)
        .bind(body)
        .bind(&data)
        .fetch_one(&state.db)
        .await?;

        RealtimeService::publish_best_effort(
            state,
            &RealtimeEvent {
                id: Uuid::now_v7(),
                event_type: "notification.created".to_string(),
                target_user_id: Some(user_id),
                payload: serde_json::to_value(&notif).unwrap_or_default(),
                timestamp: notif.created_at,
            },
        )
        .await;

        Ok(notif)
    }

    /// Notify without failing the operation that triggered it.
    pub async fn notify_best_effort(
        state: &Arc<AppState>,
        user_id: Uuid,
        title: &str,
        body: &str,
        data: Option<serde_json::Value>,
    ) {
        if let Err(e) = Self::create(state, user_id, title, body, data).await {
            tracing::warn!(%user_id, title, error = %e, "Failed to create notification");
        }
    }

    pub async fn mark_as_read(
        state: &Arc<AppState>,
        user_id: Uuid,
        notification_id: Uuid,
    ) -> Result<String, AppError> {
        let rows =
            sqlx::query("UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2")
                .bind(notification_id)
                .bind(user_id)
                .execute(&state.db)
                .await?
                .rows_affected();

        if rows == 0 {
            return Err(AppError::NotFound("Notification not found".to_string()));
        }
        Ok("Notification marked as read".to_string())
    }

    pub async fn mark_all_as_read(
        state: &Arc<AppState>,
        user_id: Uuid,
    ) -> Result<String, AppError> {
        let rows =
            sqlx::query("UPDATE notifications SET read = true WHERE user_id = $1 AND read = false")
                .bind(user_id)
                .execute(&state.db)
                .await?
                .rows_affected();

        Ok(format!("Marked {rows} notification(s) as read"))
    }
}
