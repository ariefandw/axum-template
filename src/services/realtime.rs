//! Cross-replica realtime fan-out over Postgres `LISTEN`/`NOTIFY`.
//!
//! Publishing into a process-local broadcast channel only reaches clients that
//! happen to be connected to the publishing replica. Events are therefore sent
//! through Postgres, and every replica re-publishes what it hears onto its own
//! local channel. This keeps the deployment to one dependency: no Redis, no
//! message broker.

use std::sync::Arc;

use sqlx::postgres::PgListener;
use tokio::sync::broadcast;

use crate::{
    error::AppError,
    models::events::RealtimeEvent,
    state::{AppState, REALTIME_CHANNEL},
};

/// `pg_notify` payloads are capped at 8000 bytes.
const MAX_NOTIFY_PAYLOAD: usize = 7_500;

pub struct RealtimeService;

impl RealtimeService {
    /// Publish an event to every replica.
    pub async fn publish(state: &Arc<AppState>, event: &RealtimeEvent) -> Result<(), AppError> {
        let payload = serde_json::to_string(event).map_err(|e| {
            AppError::Internal(format!("Failed to encode realtime event: {e}").into())
        })?;

        if payload.len() > MAX_NOTIFY_PAYLOAD {
            // Rather than truncate into invalid JSON, send a pointer and let the
            // client re-fetch the resource.
            tracing::warn!(
                event_type = %event.event_type,
                bytes = payload.len(),
                "Realtime payload exceeds the NOTIFY limit; publishing a reference only"
            );
            let slim = RealtimeEvent {
                payload: serde_json::json!({ "truncated": true }),
                ..event.clone()
            };
            let slim_payload = serde_json::to_string(&slim).map_err(|e| {
                AppError::Internal(format!("Failed to encode realtime event: {e}").into())
            })?;
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(REALTIME_CHANNEL)
                .bind(slim_payload)
                .execute(&state.db)
                .await?;
            return Ok(());
        }

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(REALTIME_CHANNEL)
            .bind(payload)
            .execute(&state.db)
            .await?;
        Ok(())
    }

    /// Best-effort publish for paths where a realtime hiccup must not fail the
    /// underlying write.
    pub async fn publish_best_effort(state: &Arc<AppState>, event: &RealtimeEvent) {
        if let Err(e) = Self::publish(state, event).await {
            tracing::warn!(error = %e, event_type = %event.event_type, "Realtime publish failed");
        }
    }

    /// Long-running task: bridge Postgres notifications onto the local channel.
    /// Reconnects with backoff, because losing this task silently would leave
    /// every SSE client on the replica permanently idle.
    pub async fn run_listener(database_url: String, tx: broadcast::Sender<RealtimeEvent>) {
        let mut backoff_secs = 1u64;

        loop {
            match PgListener::connect(&database_url).await {
                Ok(mut listener) => {
                    if let Err(e) = listener.listen(REALTIME_CHANNEL).await {
                        tracing::error!(error = %e, "Failed to LISTEN on the realtime channel");
                    } else {
                        tracing::info!(channel = REALTIME_CHANNEL, "Realtime listener connected");
                        backoff_secs = 1;

                        loop {
                            match listener.recv().await {
                                Ok(notification) => {
                                    match serde_json::from_str::<RealtimeEvent>(
                                        notification.payload(),
                                    ) {
                                        // A send error only means nobody is
                                        // currently subscribed on this replica.
                                        Ok(event) => {
                                            let _ = tx.send(event);
                                        }
                                        Err(e) => tracing::warn!(
                                            error = %e,
                                            "Discarding malformed realtime notification"
                                        ),
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "Realtime listener dropped; reconnecting");
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "Could not connect the realtime listener"),
            }

            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(30);
        }
    }
}
