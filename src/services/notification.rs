use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::events::{Notification, RealtimeEvent},
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
        let notif_id = Uuid::now_v7();
        let now = Utc::now();

        // 1. Insert in-app notification record
        let notif = sqlx::query_as::<_, Notification>(
            r#"
            INSERT INTO notifications (id, user_id, title, body, read, data, created_at)
            VALUES ($1, $2, $3, $4, false, $5, $6)
            RETURNING id, user_id, title, body, read, data, created_at
            "#,
        )
        .bind(notif_id)
        .bind(user_id)
        .bind(title)
        .bind(body)
        .bind(&data)
        .bind(now)
        .fetch_one(&state.db)
        .await?;

        // 2. Broadcast realtime SSE event to user's active connection
        let event = RealtimeEvent {
            id: Uuid::now_v7(),
            event_type: "notification.created".to_string(),
            target_user_id: Some(user_id),
            payload: serde_json::to_value(&notif).unwrap_or_default(),
            timestamp: now,
        };

        let _ = state.realtime_tx.send(event);

        tracing::info!(user_id = %user_id, title = %title, "Notification dispatched and broadcasted");

        Ok(notif)
    }

    pub async fn mark_as_read(
        state: &Arc<AppState>,
        user_id: Uuid,
        notification_id: Uuid,
    ) -> Result<String, AppError> {
        let rows = sqlx::query(
            "UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2",
        )
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
        sqlx::query(
            "UPDATE notifications SET read = true WHERE user_id = $1 AND read = false",
        )
        .bind(user_id)
        .execute(&state.db)
        .await?;

        Ok("All notifications marked as read".to_string())
    }
}
