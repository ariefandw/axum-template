//! Authentication and authorization extractors.
//!
//! The access token names a session, and every request resolves that session
//! against the database. That round trip is what makes a ban, a sign-out, or a
//! role change take effect immediately instead of waiting out the token's
//! lifetime.

use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, header, request::Parts},
};
use uuid::Uuid;

use crate::{
    crypto::Secret,
    error::AppError,
    services::auth::{AuthService, RequestContext},
    state::AppState,
};

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub session_id: Uuid,
    pub email: String,
    pub role: String,
    pub email_verified: bool,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// Requires the `admin` role, re-read from the database rather than trusted from
/// the token, so a demoted administrator loses access at once.
#[derive(Debug, Clone)]
pub struct AdminUser {
    pub id: Uuid,
    pub session_id: Uuid,
    pub email: String,
}

/// Resolves to `Some` when a valid session is presented and `None` otherwise,
/// for endpoints that serve both anonymous and authenticated callers.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<AuthUser>);

/// Extract `(user_id, session_id)` from a bearer token without touching the
/// database. Used only by layers that run before routing, where a rejection is
/// not appropriate and the value is a cache-scoping hint rather than an
/// authorization decision.
pub fn bearer_identity(headers: &HeaderMap, jwt_secret: &Secret) -> Option<(Uuid, Uuid)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))?;
    let claims = AuthService::verify_access_token(token, jwt_secret.expose()).ok()?;
    Some((
        Uuid::parse_str(&claims.sub).ok()?,
        Uuid::parse_str(&claims.sid).ok()?,
    ))
}

fn bearer_token(parts: &Parts) -> Result<&str, AppError> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header scheme".to_string()))
}

async fn authenticate<S>(parts: &mut Parts, state_ref: &S) -> Result<AuthUser, AppError>
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    let state: Arc<AppState> = FromRef::from_ref(state_ref);

    // 1. Check for x-api-key header (Better Auth M2M convention)
    if let Some(api_key) = parts.headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
        let (user, _key_record) =
            crate::services::api_key::ApiKeyService::resolve_key(&state, api_key).await?;

        return Ok(AuthUser {
            id: user.id,
            session_id: Uuid::nil(), // M2M API Keys use nil session
            email: user.email,
            role: user.role,
            email_verified: user.email_verified,
        });
    }

    // 2. Fall back to Bearer JWT access token
    let token = bearer_token(parts)?;
    let claims = AuthService::verify_access_token(token, state.config.jwt_secret.expose())?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Malformed user ID in token".to_string()))?;
    let session_id = Uuid::parse_str(&claims.sid)
        .map_err(|_| AppError::Unauthorized("Malformed session ID in token".to_string()))?;

    // Authoritative check: the session must still be live and the user must
    // still be permitted. Role and ban state come from here, never the token.
    let user = AuthService::resolve_session(&state.db, user_id, session_id).await?;

    Ok(AuthUser {
        id: user.id,
        session_id,
        email: user.email,
        role: user.role,
        email_verified: user.email_verified,
    })
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        authenticate(parts, state).await
    }
}

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalAuthUser(authenticate(parts, state).await.ok()))
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = authenticate(parts, state).await?;
        if !auth_user.is_admin() {
            return Err(AppError::Forbidden(
                "Access forbidden: admin privileges required".to_string(),
            ));
        }
        Ok(AdminUser {
            id: auth_user.id,
            session_id: auth_user.session_id,
            email: auth_user.email,
        })
    }
}

/// Client IP and user agent, for session records and the audit trail.
///
/// Forwarded headers are honoured only when `TRUST_PROXY_HEADERS` is set,
/// because a caller who can pick their own apparent IP can also pick their own
/// rate-limit bucket and forge audit entries.
impl<S> FromRequestParts<S> for RequestContext
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state_ref: &S) -> Result<Self, Self::Rejection> {
        let state: Arc<AppState> = FromRef::from_ref(state_ref);

        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(512).collect::<String>());

        let ip_address = if state.config.trust_proxy_headers {
            parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_string())
                .or_else(|| {
                    parts
                        .headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                })
        } else {
            None
        }
        .or_else(|| {
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
        });

        Ok(RequestContext {
            ip_address,
            user_agent,
        })
    }
}
