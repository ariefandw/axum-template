use std::sync::Arc;
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub async fn idempotency_guard(
    state: Arc<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method();

    // Idempotency applies to state-mutating requests (POST, PATCH)
    if method != axum::http::Method::POST && method != axum::http::Method::PATCH {
        return next.run(req).await;
    }

    let key_opt = req
        .headers()
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string());

    let idempotency_key = match key_opt {
        Some(k) if !k.is_empty() => k,
        _ => return next.run(req).await,
    };

    // Check if key exists in idempotency store
    let cached = {
        let store = state.idempotency_store.read().await;
        store.get(&idempotency_key).cloned()
    };

    if let Some((status_code, body_bytes)) = cached {
        tracing::info!(key = %idempotency_key, "Returning cached idempotent response");
        let resp = Response::builder()
            .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-idempotent-replayed", "true")
            .body(Body::from(body_bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        return resp;
    }

    // Execute request
    let response = next.run(req).await;

    // Only cache successful or client error responses (2xx / 4xx)
    let status = response.status();
    if status.is_success() || status.is_client_error() {
        let (parts, body) = response.into_parts();
        let bytes = match to_bytes(body, 5 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to buffer response").into_response(),
        };

        {
            let mut store = state.idempotency_store.write().await;
            store.insert(idempotency_key, (status.as_u16(), bytes.clone()));
        }

        Response::from_parts(parts, Body::from(bytes))
    } else {
        response
    }
}
