//! Idempotent replay of mutating requests.
//!
//! The previous implementation keyed its cache on the `Idempotency-Key` header
//! alone, so two unrelated callers who happened to send the same key collided and
//! the second received the first's response body verbatim — including, for the
//! auth routes, their access token. The key is now bound to the caller, the
//! route, and the request body, and the store lives in Postgres so it is bounded
//! by a TTL and shared correctly across replicas.

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{crypto, error::AppError, middleware::auth::bearer_identity, state::AppState};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const MAX_CACHED_BODY: usize = 1024 * 1024;

pub async fn idempotency_guard(state: Arc<AppState>, req: Request, next: Next) -> Response {
    if !matches!(
        *req.method(),
        Method::POST | Method::PATCH | Method::PUT | Method::DELETE
    ) {
        return next.run(req).await;
    }

    let Some(client_key) = req
        .headers()
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return next.run(req).await;
    };

    if client_key.len() > 255 {
        return AppError::BadRequest("Idempotency-Key must be at most 255 characters".to_string())
            .into_response();
    }

    // The identity is derived from the presented bearer token, not from a
    // handler-set extension, because this layer runs before routing.
    let identity = bearer_identity(req.headers(), &state.config.jwt_secret)
        .map(|(user_id, session_id)| format!("{user_id}:{session_id}"))
        .unwrap_or_else(|| "anonymous".to_string());

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Buffer the body so it can be hashed into the key and still forwarded.
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, state.config.body_limit_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return AppError::PayloadTooLarge(
                "Request body exceeds the configured limit".to_string(),
            )
            .into_response();
        }
    };

    // Every component matters: a replay is only a replay if the same caller
    // repeats the same request.
    let scope_hash = crypto::sha256_hex(&format!(
        "{identity}\n{method}\n{path}\n{}\n{client_key}",
        crypto::sha256_hex(&String::from_utf8_lossy(&body_bytes))
    ));

    let req = Request::from_parts(parts, Body::from(body_bytes));

    match claim_key(&state, &scope_hash).await {
        Ok(Claim::Fresh) => {}
        Ok(Claim::Replay {
            status,
            content_type,
            body,
        }) => {
            tracing::debug!("Replaying stored idempotent response");
            return build_replay(status, content_type, body);
        }
        Ok(Claim::InFlight) => {
            return AppError::Conflict(
                "A request with this Idempotency-Key is still in progress".to_string(),
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Idempotency store unavailable; processing without replay protection");
            return next.run(req).await;
        }
    }

    let response = next.run(req).await;
    let status = response.status();

    // Only settled outcomes are worth replaying. A 5xx is released so the caller
    // can retry the same key against a transient failure.
    if !(status.is_success() || status.is_client_error()) {
        release_key(&state, &scope_hash).await;
        return response;
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, MAX_CACHED_BODY).await {
        Ok(b) => b,
        Err(_) => {
            // Too large to store: release the key and stream the response on.
            release_key(&state, &scope_hash).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to buffer response",
            )
                .into_response();
        }
    };

    if let Err(e) = complete_key(
        &state,
        &scope_hash,
        status.as_u16(),
        content_type.as_deref(),
        &bytes,
    )
    .await
    {
        tracing::error!(error = %e, "Failed to persist idempotent response");
    }

    Response::from_parts(parts, Body::from(bytes))
}

enum Claim {
    Fresh,
    InFlight,
    Replay {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
}

/// Atomically reserve the key, or report what is already stored against it.
///
/// The insert doubles as the in-flight lock: a concurrent duplicate loses the
/// race on the primary key and is told the original is still running, rather
/// than both executing as they did before.
async fn claim_key(state: &Arc<AppState>, scope_hash: &str) -> Result<Claim, AppError> {
    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM idempotency_keys WHERE scope_hash = $1 AND expires_at <= now()")
        .bind(scope_hash)
        .execute(&mut *tx)
        .await?;

    let inserted = sqlx::query(
        r#"
        INSERT INTO idempotency_keys (scope_hash, expires_at)
        VALUES ($1, now() + make_interval(secs => $2))
        ON CONFLICT (scope_hash) DO NOTHING
        "#,
    )
    .bind(scope_hash)
    .bind(state.config.idempotency_ttl_seconds as f64)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 1 {
        tx.commit().await?;
        return Ok(Claim::Fresh);
    }

    let existing = sqlx::query_as::<_, (Option<i32>, Option<String>, Option<Vec<u8>>)>(
        "SELECT status_code, content_type, response_body FROM idempotency_keys WHERE scope_hash = $1",
    )
    .bind(scope_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;

    match existing {
        Some((Some(status), content_type, Some(body))) => Ok(Claim::Replay {
            status: status as u16,
            content_type,
            body,
        }),
        Some(_) => Ok(Claim::InFlight),
        None => Ok(Claim::Fresh),
    }
}

async fn complete_key(
    state: &Arc<AppState>,
    scope_hash: &str,
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE idempotency_keys
        SET status_code = $2, content_type = $3, response_body = $4, completed_at = now()
        WHERE scope_hash = $1
        "#,
    )
    .bind(scope_hash)
    .bind(status as i32)
    .bind(content_type)
    .bind(body)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn release_key(state: &Arc<AppState>, scope_hash: &str) {
    if let Err(e) = sqlx::query("DELETE FROM idempotency_keys WHERE scope_hash = $1")
        .bind(scope_hash)
        .execute(&state.db)
        .await
    {
        tracing::warn!(error = %e, "Failed to release idempotency key");
    }
}

fn build_replay(status: u16, content_type: Option<String>, body: Vec<u8>) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header("x-idempotent-replayed", "true");

    if let Some(ct) = content_type
        .as_deref()
        .and_then(|v| HeaderValue::from_str(v).ok())
    {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }

    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
