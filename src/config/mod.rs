//! Strongly-typed, strictly-validated application configuration.
//!
//! Two rules govern this module:
//!
//! 1. Secrets are wrapped in [`Secret`] so they cannot reach a log line, and the
//!    struct's `Debug` output is safe to print in full.
//! 2. Development defaults never silently become production defaults. Anything
//!    that is merely convenient locally (an open CORS policy, an unauthenticated
//!    metrics endpoint, a mailer that logs instead of sending) is a hard startup
//!    error when `APP_ENV=production`.

use std::env;

use crate::crypto::{self, Secret};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }
}

#[derive(Clone, Debug)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// When false the transport is plaintext, which is only permitted outside
    /// production (Mailpit and friends).
    pub use_tls: bool,
}

/// Which object-storage backend serves file bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageBackendKind {
    /// Local disk. Fine for development and single-node deployments; a file
    /// written by one replica is invisible to the others.
    Local,
    /// Any S3-compatible service. Required for horizontal scale.
    S3,
}

#[derive(Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    /// Set for non-AWS providers (R2, MinIO, regional clouds). `None` uses the
    /// AWS endpoint derived from the region.
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: Secret,
    /// Non-AWS providers almost always need path-style addressing, since
    /// virtual-hosted style requires per-bucket DNS they do not publish.
    pub force_path_style: bool,
    /// Key namespace, so one bucket can host several environments safely.
    pub prefix: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &self.secret_access_key)
            .field("force_path_style", &self.force_path_style)
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: Secret,
    pub redirect_url: String,
}

#[derive(Clone, Debug)]
pub struct OidcProviderConfig {
    pub jwks_url: String,
    pub expected_issuer: Option<String>,
    pub expected_audience: Option<String>,
}

/// `Debug` is derived, and is safe: every secret-bearing field is a [`Secret`],
/// and `encryption_key` is stored as raw bytes that are explicitly redacted.
#[derive(Clone)]
pub struct AppConfig {
    pub environment: Environment,
    pub server_host: String,
    pub server_port: u16,
    pub public_base_url: String,

    pub database_url: Secret,
    pub database_max_connections: u32,

    pub jwt_secret: Secret,
    /// Short-lived, because revocation now lives in the sessions table.
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
    pub argon2: Argon2Params,

    /// Keys third-party credentials at rest and signs storage URLs.
    pub encryption_key: [u8; 32],
    pub url_signing_key: [u8; 32],

    pub email_verify_ttl_hours: i64,
    pub password_reset_ttl_minutes: i64,
    pub lockout_threshold: i32,
    pub lockout_minutes: i64,

    pub rate_limit_per_second: u64,
    pub rate_limit_burst_size: u32,
    pub auth_rate_limit_per_second: u64,
    pub auth_rate_limit_burst_size: u32,
    /// Only enable behind a proxy you control: it lets callers pick their own
    /// rate-limit bucket via `X-Forwarded-For`.
    pub trust_proxy_headers: bool,

    /// Empty means "allow any origin", which is rejected in production.
    pub cors_allowed_origins: Vec<String>,
    pub metrics_token: Option<Secret>,
    pub idempotency_ttl_seconds: i64,
    pub request_timeout_seconds: u64,
    pub body_limit_bytes: usize,

    pub storage_backend: StorageBackendKind,
    pub s3: Option<S3Config>,
    pub upload_dir: String,
    pub max_upload_bytes: u64,
    pub allowed_upload_mime: Vec<String>,
    pub signed_url_ttl_seconds: i64,

    pub smtp: Option<SmtpConfig>,
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
    pub oidc: Option<OidcProviderConfig>,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("environment", &self.environment)
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("public_base_url", &self.public_base_url)
            .field("database_url", &"Secret(<redacted>)")
            .field("database_max_connections", &self.database_max_connections)
            .field("jwt_secret", &self.jwt_secret)
            .field("access_token_ttl_minutes", &self.access_token_ttl_minutes)
            .field("refresh_token_ttl_days", &self.refresh_token_ttl_days)
            .field("argon2", &self.argon2)
            .field("encryption_key", &"[redacted; 32 bytes]")
            .field("url_signing_key", &"[redacted; 32 bytes]")
            .field("rate_limit_per_second", &self.rate_limit_per_second)
            .field("rate_limit_burst_size", &self.rate_limit_burst_size)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("metrics_token", &self.metrics_token)
            .field("storage_backend", &self.storage_backend)
            .field("s3", &self.s3)
            .field("upload_dir", &self.upload_dir)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("smtp", &self.smtp)
            .field("google_configured", &self.google.is_some())
            .field("github_configured", &self.github.is_some())
            .finish()
    }
}

impl AppConfig {
    pub fn load_from_env() -> Result<Self, String> {
        let environment = match env::var("APP_ENV")
            .unwrap_or_else(|_| "development".into())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "production" | "prod" => Environment::Production,
            "development" | "dev" | "test" | "" => Environment::Development,
            other => {
                return Err(format!(
                    "Invalid APP_ENV '{other}' (expected development|production)"
                ));
            }
        };
        let is_prod = environment.is_production();

        let server_host = opt_string("SERVER_HOST").unwrap_or_else(|| "127.0.0.1".into());
        let server_port = parse_env("SERVER_PORT", 3000u16)?;
        let public_base_url = opt_string("PUBLIC_BASE_URL")
            .unwrap_or_else(|| format!("http://{server_host}:{server_port}"));

        let database_url = require("DATABASE_URL")?;
        let database_max_connections = parse_env("DATABASE_MAX_CONNECTIONS", 20u32)?;

        let jwt_secret = require("JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters long".into());
        }

        let access_token_ttl_minutes = parse_env("ACCESS_TOKEN_TTL_MINUTES", 15i64)?;
        if access_token_ttl_minutes <= 0 {
            return Err("ACCESS_TOKEN_TTL_MINUTES must be positive".into());
        }
        let refresh_token_ttl_days = parse_env("REFRESH_TOKEN_TTL_DAYS", 30i64)?;

        // OWASP minimum for Argon2id is 19 MiB / t=2 / p=1.
        let argon2 = Argon2Params {
            memory_kib: parse_env("ARGON2_MEMORY_KIB", 19_456u32)?,
            iterations: parse_env("ARGON2_ITERATIONS", 2u32)?,
            parallelism: parse_env("ARGON2_PARALLELISM", 1u32)?,
        };
        if argon2.memory_kib < 19_456 || argon2.iterations < 2 {
            return Err(
                "Argon2 parameters are below the OWASP minimum (19456 KiB, 2 iterations)".into(),
            );
        }

        let encryption_key = match opt_string("ENCRYPTION_KEY") {
            Some(raw) => crypto::parse_encryption_key(&raw)?,
            None if is_prod => {
                return Err(
                    "ENCRYPTION_KEY is required in production. Generate one with: \
                     openssl rand -base64 32"
                        .into(),
                );
            }
            None => {
                tracing::warn!(
                    "ENCRYPTION_KEY is unset; deriving a development key from JWT_SECRET. \
                     Set ENCRYPTION_KEY before deploying or stored credentials become unreadable."
                );
                crypto::derive_key_from_secret(&jwt_secret, "encryption-at-rest")
            }
        };
        let url_signing_key = crypto::derive_key_from_secret(&jwt_secret, "url-signing");

        let rate_limit_per_second = parse_env("RATE_LIMIT_PER_SECOND", 20u64)?;
        let rate_limit_burst_size = parse_env("RATE_LIMIT_BURST_SIZE", 40u32)?;
        let auth_rate_limit_per_second = parse_env("AUTH_RATE_LIMIT_PER_SECOND", 1u64)?;
        let auth_rate_limit_burst_size = parse_env("AUTH_RATE_LIMIT_BURST_SIZE", 10u32)?;
        if rate_limit_burst_size == 0 || auth_rate_limit_burst_size == 0 {
            return Err("Rate limit burst sizes must be greater than zero".into());
        }
        let trust_proxy_headers = parse_env("TRUST_PROXY_HEADERS", false)?;

        let cors_allowed_origins: Vec<String> = opt_string("CORS_ALLOWED_ORIGINS")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && s != "*")
                    .collect()
            })
            .unwrap_or_default();
        if is_prod && cors_allowed_origins.is_empty() {
            return Err(
                "CORS_ALLOWED_ORIGINS must list explicit origins in production \
                 (a wildcard policy is refused)"
                    .into(),
            );
        }

        let metrics_token = match opt_string("METRICS_TOKEN") {
            Some(token) => Some(Secret::new(token)),
            None if is_prod => {
                return Err("METRICS_TOKEN is required in production to protect /metrics".into());
            }
            None => None,
        };

        let smtp = match opt_string("SMTP_HOST") {
            Some(host) => {
                let use_tls = parse_env("SMTP_TLS", is_prod)?;
                let username = opt_string("SMTP_USERNAME");
                let password = opt_string("SMTP_PASSWORD").map(Secret::new);
                if is_prod && !use_tls {
                    return Err("SMTP_TLS cannot be disabled in production".into());
                }
                if username.is_some() != password.is_some() {
                    return Err("SMTP_USERNAME and SMTP_PASSWORD must be set together".into());
                }
                Some(SmtpConfig {
                    host,
                    port: parse_env("SMTP_PORT", if use_tls { 587u16 } else { 1025 })?,
                    from: opt_string("SMTP_FROM")
                        .unwrap_or_else(|| "noreply@localhost.local".into()),
                    username,
                    password,
                    use_tls,
                })
            }
            None if is_prod => {
                return Err(
                    "SMTP_HOST is required in production; without it account recovery mail \
                     is silently dropped"
                        .into(),
                );
            }
            None => None,
        };

        // Storage backend. `s3` requires the full credential set; a partial
        // configuration is refused rather than silently falling back to local
        // disk, which would look like it worked until the second replica
        // started.
        let storage_backend = match opt_string("STORAGE_BACKEND")
            .unwrap_or_else(|| "local".into())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "local" => StorageBackendKind::Local,
            "s3" => StorageBackendKind::S3,
            other => {
                return Err(format!(
                    "Invalid STORAGE_BACKEND '{other}' (expected local|s3)"
                ));
            }
        };

        let s3 = if storage_backend == StorageBackendKind::S3 {
            let bucket = require("AWS_BUCKET")?;
            let access_key_id = require("AWS_ACCESS_KEY_ID")?;
            let secret_access_key = require("AWS_SECRET_ACCESS_KEY")?;
            let region = opt_string("AWS_REGION")
                .or_else(|| opt_string("AWS_DEFAULT_REGION"))
                .ok_or_else(|| "AWS_REGION is required when STORAGE_BACKEND=s3".to_string())?;

            Some(S3Config {
                bucket,
                region,
                endpoint: opt_string("AWS_ENDPOINT"),
                access_key_id,
                secret_access_key: Secret::new(secret_access_key),
                force_path_style: parse_env("AWS_USE_PATH_STYLE_ENDPOINT", true)?,
                prefix: opt_string("AWS_KEY_PREFIX").unwrap_or_default(),
            })
        } else {
            if is_prod {
                tracing::warn!(
                    "STORAGE_BACKEND=local in production: uploaded files live on this \
                     container's disk, are invisible to other replicas, and are lost on restart"
                );
            }
            None
        };

        let google = oauth_provider("GOOGLE")?;
        let github = oauth_provider("GITHUB")?;

        let oidc = opt_string("OIDC_JWKS_URL").map(|jwks_url| OidcProviderConfig {
            jwks_url,
            expected_issuer: opt_string("OIDC_ISSUER"),
            expected_audience: opt_string("OIDC_AUDIENCE"),
        });

        let allowed_upload_mime = opt_string("ALLOWED_UPLOAD_MIME")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| {
                [
                    "image/jpeg",
                    "image/png",
                    "image/gif",
                    "image/webp",
                    "application/pdf",
                    "text/plain",
                    "application/json",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect()
            });

        Ok(Self {
            environment,
            server_host,
            server_port,
            public_base_url,
            database_url: Secret::new(database_url),
            database_max_connections,
            jwt_secret: Secret::new(jwt_secret),
            access_token_ttl_minutes,
            refresh_token_ttl_days,
            argon2,
            encryption_key,
            url_signing_key,
            email_verify_ttl_hours: parse_env("EMAIL_VERIFY_TTL_HOURS", 24i64)?,
            password_reset_ttl_minutes: parse_env("PASSWORD_RESET_TTL_MINUTES", 30i64)?,
            lockout_threshold: parse_env("LOCKOUT_THRESHOLD", 10i32)?,
            lockout_minutes: parse_env("LOCKOUT_MINUTES", 15i64)?,
            rate_limit_per_second,
            rate_limit_burst_size,
            auth_rate_limit_per_second,
            auth_rate_limit_burst_size,
            trust_proxy_headers,
            cors_allowed_origins,
            metrics_token,
            idempotency_ttl_seconds: parse_env("IDEMPOTENCY_TTL_SECONDS", 86_400i64)?,
            request_timeout_seconds: parse_env("REQUEST_TIMEOUT_SECONDS", 30u64)?,
            body_limit_bytes: parse_env("BODY_LIMIT_BYTES", 10 * 1024 * 1024usize)?,
            storage_backend,
            s3,
            upload_dir: opt_string("UPLOAD_DIR").unwrap_or_else(|| "uploads".into()),
            max_upload_bytes: parse_env("MAX_UPLOAD_BYTES", 10 * 1024 * 1024u64)?,
            allowed_upload_mime,
            signed_url_ttl_seconds: parse_env("SIGNED_URL_TTL_SECONDS", 900i64)?,
            smtp,
            google,
            github,
            oidc,
        })
    }

    /// A fully-populated development configuration, for tests and for the
    /// OpenAPI exporter (which must build the router without a live
    /// environment). Never reachable from `load_from_env`, so production
    /// configuration still has to come from the environment.
    pub fn for_testing(database_url: impl Into<String>) -> Self {
        let jwt_secret = "test-jwt-secret-key-that-is-at-least-32-chars-long".to_string();
        Self {
            environment: Environment::Development,
            server_host: "127.0.0.1".into(),
            server_port: 3000,
            public_base_url: "http://127.0.0.1:3000".into(),
            database_url: Secret::new(database_url.into()),
            database_max_connections: 5,
            encryption_key: crypto::derive_key_from_secret(&jwt_secret, "encryption-at-rest"),
            url_signing_key: crypto::derive_key_from_secret(&jwt_secret, "url-signing"),
            jwt_secret: Secret::new(jwt_secret),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 30,
            // Deliberately at the OWASP floor: tests hash passwords repeatedly
            // and production tuning would make the suite crawl.
            argon2: Argon2Params {
                memory_kib: 19_456,
                iterations: 2,
                parallelism: 1,
            },
            email_verify_ttl_hours: 24,
            password_reset_ttl_minutes: 30,
            lockout_threshold: 10,
            lockout_minutes: 15,
            rate_limit_per_second: 1000,
            rate_limit_burst_size: 5000,
            auth_rate_limit_per_second: 1000,
            auth_rate_limit_burst_size: 5000,
            trust_proxy_headers: false,
            cors_allowed_origins: Vec::new(),
            metrics_token: None,
            idempotency_ttl_seconds: 86_400,
            request_timeout_seconds: 30,
            body_limit_bytes: 10 * 1024 * 1024,
            storage_backend: StorageBackendKind::Local,
            s3: None,
            upload_dir: "target/test_uploads".into(),
            max_upload_bytes: 10 * 1024 * 1024,
            allowed_upload_mime: [
                "image/jpeg",
                "image/png",
                "image/gif",
                "image/webp",
                "application/pdf",
                "text/plain",
                "application/json",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            signed_url_ttl_seconds: 900,
            smtp: None,
            google: None,
            github: None,
            oidc: None,
        }
    }

    /// Emitted at startup so operators can see which optional subsystems are
    /// live without reading the environment back out of the process.
    pub fn log_summary(&self) {
        tracing::info!(
            environment = ?self.environment,
            cors = if self.cors_allowed_origins.is_empty() { "any (development)" } else { "allowlist" },
            metrics_protected = self.metrics_token.is_some(),
            proxy_headers_trusted = self.trust_proxy_headers,
            mailer = if self.smtp.is_some() { "smtp" } else { "log-only (development)" },
            storage = ?self.storage_backend,
            google_oauth = self.google.is_some(),
            github_oauth = self.github.is_some(),
            access_token_ttl_minutes = self.access_token_ttl_minutes,
            "Configuration loaded"
        );
    }
}

fn opt_string(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn require(key: &str) -> Result<String, String> {
    opt_string(key).ok_or_else(|| format!("{key} environment variable is strictly required"))
}

fn parse_env<T>(key: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match opt_string(key) {
        Some(raw) => raw.parse::<T>().map_err(|e| format!("Invalid {key}: {e}")),
        None => Ok(default),
    }
}

fn oauth_provider(prefix: &str) -> Result<Option<OAuthProviderConfig>, String> {
    let client_id = opt_string(&format!("{prefix}_CLIENT_ID"));
    let client_secret = opt_string(&format!("{prefix}_CLIENT_SECRET"));
    let redirect_url = opt_string(&format!("{prefix}_REDIRECT_URL"));

    match (client_id, client_secret, redirect_url) {
        (Some(id), Some(secret), Some(redirect)) => Ok(Some(OAuthProviderConfig {
            client_id: id,
            client_secret: Secret::new(secret),
            redirect_url: redirect,
        })),
        (None, None, None) => Ok(None),
        _ => Err(format!(
            "{prefix} OAuth is partially configured: set {prefix}_CLIENT_ID, \
             {prefix}_CLIENT_SECRET and {prefix}_REDIRECT_URL together, or none of them"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env access is process-global, so these run under one lock and restore
    /// what they touch.
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => unsafe { env::set_var(k, v) },
                None => unsafe { env::remove_var(k) },
            }
        }
        let out = f();
        for (k, v) in saved {
            match v {
                Some(v) => unsafe { env::set_var(&k, v) },
                None => unsafe { env::remove_var(&k) },
            }
        }
        out
    }

    const BASE: &[(&str, Option<&str>)] = &[
        ("DATABASE_URL", Some("postgres://localhost/test")),
        (
            "JWT_SECRET",
            Some("a-sufficiently-long-jwt-secret-value-here"),
        ),
        ("APP_ENV", Some("development")),
        ("ENCRYPTION_KEY", None),
        ("CORS_ALLOWED_ORIGINS", None),
        ("METRICS_TOKEN", None),
        ("SMTP_HOST", None),
        ("SMTP_TLS", None),
        ("GOOGLE_CLIENT_ID", None),
        ("GOOGLE_CLIENT_SECRET", None),
        ("GOOGLE_REDIRECT_URL", None),
    ];

    fn env_with(overrides: &[(&str, Option<&str>)]) -> Vec<(&'static str, Option<&'static str>)> {
        let mut vars: Vec<_> = BASE.to_vec();
        for (k, v) in overrides {
            let key: &'static str = Box::leak(k.to_string().into_boxed_str());
            let val: Option<&'static str> = v.map(|s| &*Box::leak(s.to_string().into_boxed_str()));
            if let Some(slot) = vars.iter_mut().find(|(ek, _)| ek == k) {
                slot.1 = val;
            } else {
                vars.push((key, val));
            }
        }
        vars
    }

    #[test]
    fn development_boots_with_convenient_defaults() {
        let config = with_env(BASE, AppConfig::load_from_env).expect("development should load");
        assert!(!config.environment.is_production());
        assert!(config.cors_allowed_origins.is_empty());
        assert!(config.metrics_token.is_none());
    }

    /// Production must not silently inherit the permissive development
    /// defaults. Each of these was a real exposure in the original template.
    #[test]
    fn production_refuses_unsafe_defaults() {
        let prod = env_with(&[("APP_ENV", Some("production"))]);

        let err = with_env(&prod, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("ENCRYPTION_KEY"), "got: {err}");

        let with_key = env_with(&[
            ("APP_ENV", Some("production")),
            (
                "ENCRYPTION_KEY",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ),
        ]);
        let err = with_env(&with_key, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("CORS_ALLOWED_ORIGINS"), "got: {err}");

        let with_cors = env_with(&[
            ("APP_ENV", Some("production")),
            (
                "ENCRYPTION_KEY",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ),
            ("CORS_ALLOWED_ORIGINS", Some("https://app.example.com")),
        ]);
        let err = with_env(&with_cors, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("METRICS_TOKEN"), "got: {err}");

        let with_metrics = env_with(&[
            ("APP_ENV", Some("production")),
            (
                "ENCRYPTION_KEY",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ),
            ("CORS_ALLOWED_ORIGINS", Some("https://app.example.com")),
            ("METRICS_TOKEN", Some("a-metrics-token")),
        ]);
        let err = with_env(&with_metrics, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("SMTP_HOST"), "got: {err}");

        // With everything supplied it loads, and plaintext SMTP is still refused.
        let complete = env_with(&[
            ("APP_ENV", Some("production")),
            (
                "ENCRYPTION_KEY",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ),
            ("CORS_ALLOWED_ORIGINS", Some("https://app.example.com")),
            ("METRICS_TOKEN", Some("a-metrics-token")),
            ("SMTP_HOST", Some("smtp.example.com")),
        ]);
        let config = with_env(&complete, AppConfig::load_from_env).expect("should load");
        assert!(config.environment.is_production());
        assert_eq!(config.cors_allowed_origins, vec!["https://app.example.com"]);

        let plaintext = env_with(&[
            ("APP_ENV", Some("production")),
            (
                "ENCRYPTION_KEY",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            ),
            ("CORS_ALLOWED_ORIGINS", Some("https://app.example.com")),
            ("METRICS_TOKEN", Some("a-metrics-token")),
            ("SMTP_HOST", Some("smtp.example.com")),
            ("SMTP_TLS", Some("false")),
        ]);
        let err = with_env(&plaintext, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("SMTP_TLS"), "got: {err}");
    }

    #[test]
    fn short_jwt_secrets_and_weak_argon2_are_rejected() {
        let short = env_with(&[("JWT_SECRET", Some("too-short"))]);
        assert!(
            with_env(&short, AppConfig::load_from_env)
                .unwrap_err()
                .contains("JWT_SECRET")
        );

        let weak = env_with(&[("ARGON2_MEMORY_KIB", Some("1024"))]);
        assert!(
            with_env(&weak, AppConfig::load_from_env)
                .unwrap_err()
                .contains("OWASP")
        );
    }

    #[test]
    fn partial_oauth_configuration_is_rejected_rather_than_half_enabled() {
        let partial = env_with(&[("GOOGLE_CLIENT_ID", Some("id-only"))]);
        let err = with_env(&partial, AppConfig::load_from_env).unwrap_err();
        assert!(err.contains("partially configured"), "got: {err}");
    }

    /// The whole struct must be safe to log.
    #[test]
    fn debug_output_contains_no_secrets() {
        let secrets = env_with(&[
            (
                "JWT_SECRET",
                Some("super-secret-jwt-value-of-sufficient-length"),
            ),
            ("DATABASE_URL", Some("postgres://user:hunter2@db/app")),
        ]);
        let config = with_env(&secrets, AppConfig::load_from_env).unwrap();
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("super-secret-jwt-value"),
            "JWT secret leaked: {rendered}"
        );
        assert!(
            !rendered.contains("hunter2"),
            "database password leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }
}
