//! Response security headers.
//!
//! Adds the Content-Security-Policy and Permissions-Policy that the previous
//! header set advertised but never sent, and stops asserting HSTS over plaintext
//! development traffic, where it would pin a browser to an https origin that does
//! not exist.

use std::sync::Arc;

use axum::{
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

/// The API returns JSON and streams files; it never needs script, style, or
/// frame privileges of its own. The Scalar documentation page is the one
/// exception and is allowed its CDN explicitly.
const API_CSP: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const DOCS_CSP: &str = "default-src 'self'; \
                        script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; \
                        style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; \
                        font-src 'self' data: https://fonts.gstatic.com; \
                        img-src 'self' data: https:; \
                        connect-src 'self'; \
                        frame-ancestors 'none'; base-uri 'none'";

pub async fn security_headers(state: Arc<AppState>, req: Request, next: Next) -> Response {
    let is_docs = req.uri().path().starts_with("/docs");
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if is_docs { DOCS_CSP } else { API_CSP }),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("x-download-options"),
        HeaderValue::from_static("noopen"),
    );

    // HSTS is meaningful only where the origin is actually served over TLS.
    // Asserting it in development pins localhost to https for a year.
    if state.config.environment.is_production() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    response
}
