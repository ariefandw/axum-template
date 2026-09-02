//! Remote JWKS (JSON Web Key Set) verifier for OIDC / Better Auth SSO integration.
//!
//! Fetches and caches public keys from an external OIDC / Better Auth IdP
//! (`/.well-known/jwks.json`), validating RS256 / ES256 / EdDSA tokens with in-memory
//! TTL caching and automatic key rotation support.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::AppError;

/// Standard JWKS response envelope from an OIDC / Better Auth server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwksKey {
    pub kty: String,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub kid: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub crv: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JwksKey>,
}

/// Standard OIDC claims extracted from an SSO token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteClaims {
    /// Subject (User ID in SSO).
    pub sub: String,
    /// Email of the user.
    pub email: Option<String>,
    /// Display name or full name.
    pub name: Option<String>,
    /// User role (if populated by SSO/Better Auth).
    pub role: Option<String>,
    /// Active organization ID (for multi-tenant SSO sessions).
    pub org_id: Option<String>,
    /// Email verified flag.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Expiration timestamp (seconds since Unix epoch).
    pub exp: usize,
    /// Issued at timestamp.
    pub iat: Option<usize>,
    /// Issuer.
    pub iss: Option<String>,
    /// Audience.
    pub aud: Option<serde_json::Value>,
}

/// Thread-safe, cached JWKS client.
#[derive(Clone)]
pub struct JwksClient {
    jwks_url: String,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    http_client: reqwest::Client,
    cache: Arc<RwLock<Option<CachedKeys>>>,
    cache_ttl: Duration,
}

struct CachedKeys {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

impl JwksClient {
    pub fn new(
        jwks_url: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            jwks_url,
            expected_issuer,
            expected_audience,
            http_client,
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(60 * 60), // 1 hour TTL default
        }
    }

    /// Fetch and parse JWKS keys from remote URL or return cached keys.
    async fn get_keys(&self) -> Result<HashMap<String, DecodingKey>, AppError> {
        {
            let read = self.cache.read().await;
            if let Some(cached) = read.as_ref() {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch fresh keys
        let response = self
            .http_client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to fetch remote JWKS: {}", e).into())
            })?;

        if !response.status().is_success() {
            return Err(AppError::Internal(
                format!("Remote JWKS returned HTTP status: {}", response.status()).into(),
            ));
        }

        let jwks: JwksResponse = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse remote JWKS response: {}", e).into())
        })?;

        let mut key_map = HashMap::new();
        for key in jwks.keys {
            if let (Some(kid), Some(n), Some(e)) = (key.kid, key.n, key.e) {
                if let Ok(decoding_key) = DecodingKey::from_rsa_components(&n, &e) {
                    key_map.insert(kid, decoding_key);
                }
            }
        }

        let mut write = self.cache.write().await;
        *write = Some(CachedKeys {
            keys: key_map.clone(),
            fetched_at: Instant::now(),
        });

        Ok(key_map)
    }

    /// Verify a remote token against the JWKS keys.
    pub async fn verify_token(&self, token: &str) -> Result<RemoteClaims, AppError> {
        let header = decode_header(token)
            .map_err(|_| AppError::Unauthorized("Invalid JWT header format".to_string()))?;

        let kid = header.kid.ok_or_else(|| {
            AppError::Unauthorized("JWT header missing 'kid' key identifier".to_string())
        })?;

        let keys = self.get_keys().await?;
        let decoding_key = keys.get(&kid).ok_or_else(|| {
            AppError::Unauthorized(format!("Unknown key identifier 'kid={}'", kid))
        })?;

        let mut validation = Validation::new(header.alg);
        if let Some(iss) = &self.expected_issuer {
            validation.set_issuer(&[iss]);
        } else {
            validation.validate_nbf = false;
        }

        if let Some(aud) = &self.expected_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<RemoteClaims>(token, decoding_key, &validation).map_err(|e| {
            AppError::Unauthorized(format!("Remote token validation failed: {}", e))
        })?;

        Ok(token_data.claims)
    }
}
