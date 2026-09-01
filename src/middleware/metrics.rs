//! Prometheus instrumentation.
//!
//! Labels come from the matched route template, not the raw URI. Using the raw
//! path minted a new time series per file ID and per 404 probe, an unbounded
//! memory leak in the registry that any anonymous caller could drive.

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use metrics::{counter, histogram};
use std::time::Instant;

/// Applied with `route_layer`, so routing has already run and `MatchedPath` is
/// present.
pub async fn track_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        // Bounded fallback: never the caller-supplied path.
        .unwrap_or_else(|| "unmatched".to_owned());
    let method = req.method().to_string();

    let response = next.run(req).await;

    let labels = [
        ("method", method),
        ("path", path),
        ("status", response.status().as_u16().to_string()),
    ];

    counter!("http_requests_total", &labels).increment(1);
    histogram!("http_requests_duration_seconds", &labels).record(start.elapsed().as_secs_f64());

    response
}

/// Outermost counter, catching what never reaches a route: rate-limit
/// rejections, timeouts, and body-limit failures. Labelled by method and status
/// only, so its cardinality stays fixed.
pub async fn track_outcomes(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let response = next.run(req).await;
    let status = response.status();

    if status.is_client_error() || status.is_server_error() {
        counter!(
            "http_rejected_total",
            &[("method", method), ("status", status.as_u16().to_string())]
        )
        .increment(1);
    }

    response
}
