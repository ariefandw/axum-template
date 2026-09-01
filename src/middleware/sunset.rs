//! RFC 8594 Sunset and Deprecation Response Headers.
//!
//! Provides a strictly-typed middleware to mark deprecated endpoints or entire
//! API route subtrees with standard `Deprecation`, `Sunset`, and `Link` headers.
//!
//! Spec: https://datatracker.ietf.org/doc/html/rfc8594

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, header},
    middleware::Next,
    response::Response,
};

static HEADER_DEPRECATION: HeaderName = HeaderName::from_static("deprecation");
static HEADER_SUNSET: HeaderName = HeaderName::from_static("sunset");

/// Configuration for deprecating an endpoint or route group.
#[derive(Debug, Clone)]
pub struct SunsetConfig {
    /// Date when the endpoint will become permanently unavailable (HTTP date format, e.g. "Wed, 11 Nov 2026 00:00:00 GMT").
    pub sunset_date: Option<&'static str>,
    /// Link to migration guide or documentation explaining the deprecation.
    pub migration_doc_url: Option<&'static str>,
}

impl SunsetConfig {
    /// Create a deprecation notice without a hard sunset date.
    pub const fn deprecated() -> Self {
        Self {
            sunset_date: None,
            migration_doc_url: None,
        }
    }

    /// Set a hard sunset date in RFC 8594 HTTP-date format.
    pub const fn with_sunset(mut self, sunset_date: &'static str) -> Self {
        self.sunset_date = Some(sunset_date);
        self
    }

    /// Attach a migration guide URL via `Link: <url>; rel="sunset"`.
    pub const fn with_doc(mut self, url: &'static str) -> Self {
        self.migration_doc_url = Some(url);
        self
    }
}

/// Middleware layer injecting RFC 8594 deprecation and sunset headers into responses.
pub async fn sunset_layer(config: SunsetConfig, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Mark as deprecated: @true per RFC 8594 (or simply "true")
    headers.insert(HEADER_DEPRECATION.clone(), HeaderValue::from_static("true"));

    // Add Sunset date if specified
    if let Some(sunset) = config.sunset_date {
        if let Ok(val) = HeaderValue::from_str(sunset) {
            headers.insert(HEADER_SUNSET.clone(), val);
        }
    }

    // Add Link header pointing to migration docs if specified
    if let Some(doc_url) = config.migration_doc_url {
        let link_val = format!(r#"<{}>; rel="sunset""#, doc_url);
        if let Ok(val) = HeaderValue::from_str(&link_val) {
            headers.append(header::LINK, val);
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn,
        routing::get,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn sunset_headers_are_injected() {
        let config = SunsetConfig::deprecated()
            .with_sunset("Wed, 11 Nov 2026 00:00:00 GMT")
            .with_doc("https://api.example.com/docs/v2-migration");

        let app = Router::new()
            .route("/deprecated-endpoint", get(|| async { StatusCode::OK }))
            .layer(from_fn(move |req, next| {
                let conf = config.clone();
                sunset_layer(conf, req, next)
            }));

        let req = Request::builder()
            .uri("/deprecated-endpoint")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("deprecation").unwrap().to_str().unwrap(),
            "true"
        );
        assert_eq!(
            res.headers().get("sunset").unwrap().to_str().unwrap(),
            "Wed, 11 Nov 2026 00:00:00 GMT"
        );
        assert_eq!(
            res.headers().get("link").unwrap().to_str().unwrap(),
            r#"<https://api.example.com/docs/v2-migration>; rel="sunset""#
        );
    }
}
