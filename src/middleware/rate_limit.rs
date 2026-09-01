//! Rate limiting.
//!
//! Two changes: the limits are read from configuration (they were hardcoded, so
//! the documented `RATE_LIMIT_*` variables did nothing), and forwarded headers
//! are honoured only when explicitly trusted. `SmartIpKeyExtractor` reads
//! `X-Forwarded-For` unconditionally, which let any caller pick their own bucket
//! and bypass the limiter with a single header.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::Request;
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};

use crate::config::AppConfig;

/// Keys on the peer address by default; consults `X-Forwarded-For` and
/// `X-Real-IP` only when the deployment declares it sits behind a trusted proxy.
#[derive(Clone, Copy, Debug)]
pub struct ConfiguredIpExtractor {
    trust_proxy_headers: bool,
}

impl KeyExtractor for ConfiguredIpExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if self.trust_proxy_headers {
            let forwarded = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .and_then(|v| v.parse::<IpAddr>().ok())
                .or_else(|| {
                    req.headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<IpAddr>().ok())
                });

            if let Some(ip) = forwarded {
                return Ok(ip);
            }
        }

        req.extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

pub type ConfiguredGovernor =
    GovernorLayer<ConfiguredIpExtractor, governor::middleware::NoOpMiddleware>;

fn build(
    per_second: u64,
    burst_size: u32,
    trust_proxy_headers: bool,
) -> Result<ConfiguredGovernor, String> {
    let conf = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size)
        .key_extractor(ConfiguredIpExtractor {
            trust_proxy_headers,
        })
        .finish()
        .ok_or_else(|| "Invalid rate limit configuration".to_string())?;

    Ok(GovernorLayer {
        config: Arc::new(conf),
    })
}

/// Baseline limit for the whole API.
pub fn global_limiter(config: &AppConfig) -> Result<ConfiguredGovernor, String> {
    build(
        config.rate_limit_per_second,
        config.rate_limit_burst_size,
        config.trust_proxy_headers,
    )
}

/// Much tighter limit for credential endpoints. Combined with the per-account
/// lockout in `AuthService`, this covers both an attacker hammering one account
/// and one spraying many.
pub fn auth_limiter(config: &AppConfig) -> Result<ConfiguredGovernor, String> {
    build(
        config.auth_rate_limit_per_second,
        config.auth_rate_limit_burst_size,
        config.trust_proxy_headers,
    )
}
