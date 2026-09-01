use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::Stream;
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{middleware::auth::AuthUser, state::AppState};

/// Server-sent event stream, scoped to the calling user.
///
/// Events reach this replica through the Postgres listener, so a client here
/// receives events published by any replica. Dropped events are surfaced as an
/// explicit `lagged` event rather than silently discarded, which lets a client
/// know it must re-fetch instead of assuming it is up to date.
#[utoipa::path(
    get, path = "/stream",
    responses((status = 200, description = "SSE stream for the current user", content_type = "text/event-stream")),
    security(("bearer_auth" = [])), tag = "Realtime"
)]
pub async fn sse_stream(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.realtime_tx.subscribe();
    let current_user_id = auth_user.id;

    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(event) => {
            // Deliver broadcast events and this user's own; never another user's.
            let for_me = event.target_user_id.is_none()
                || event.target_user_id == Some(current_user_id);
            if !for_me {
                return None;
            }
            match serde_json::to_string(&event) {
                Ok(json) => Some(Ok(Event::default()
                    .id(event.id.to_string())
                    .event(event.event_type)
                    .data(json))),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to serialize realtime event");
                    None
                }
            }
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(skipped)) => {
            // Tell the client it has a gap instead of leaving it silently stale.
            tracing::warn!(%current_user_id, skipped, "SSE consumer lagged behind the broadcast channel");
            Some(Ok(Event::default()
                .event("lagged")
                .data(format!(r#"{{"skipped":{skipped},"action":"resync"}}"#))))
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(sse_stream))
}
