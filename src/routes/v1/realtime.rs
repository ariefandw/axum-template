use std::{convert::Infallible, sync::Arc, time::Duration};
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::Stream;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{middleware::auth::AuthUser, state::AppState};

#[utoipa::path(
    get,
    path = "/stream",
    responses(
        (status = 200, description = "Realtime SSE event stream for authenticated user", content_type = "text/event-stream")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Realtime"
)]
pub async fn sse_stream(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.realtime_tx.subscribe();
    let current_user_id = auth_user.id;

    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        match item {
            Ok(event) => {
                // Filter events intended for this user or global events
                if event.target_user_id.is_none() || event.target_user_id == Some(current_user_id) {
                    let json = serde_json::to_string(&event).unwrap_or_default();
                    Some(Ok(Event::default().event(event.event_type).data(json)))
                } else {
                    None
                }
            }
            Err(_) => None, // Lagged or missed event
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
