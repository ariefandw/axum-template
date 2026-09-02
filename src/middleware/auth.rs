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
    models::api_key::{ApiScope, ScopeSet},
    services::auth::{AuthService, RequestContext},
    state::AppState,
};

/// How the caller proved who they are.
///
/// This distinction is load-bearing. An interactive session belongs to a human
/// who just authenticated; an API key is a long-lived machine credential that
/// may sit in a CI environment or a config file. They must not carry the same
/// authority.
#[derive(Clone, Debug)]
pub enum Credential {
    Session { session_id: Uuid },
    ApiKey { key_id: Uuid, scopes: ScopeSet },
    SsoRemote { issuer: Option<String> },
}

impl Credential {
    /// Authorize one capability. A session or external SSO token carries full authority;
    /// an API key carries only what it declared at creation.
    pub fn require_scope(&self, scope: ApiScope) -> Result<(), AppError> {
        match self {
            Credential::Session { .. } | Credential::SsoRemote { .. } => Ok(()),
            Credential::ApiKey { scopes, .. } => {
                if scopes.contains(scope) {
                    Ok(())
                } else {
                    Err(AppError::Forbidden(format!(
                        "This API key does not carry the '{}' scope",
                        scope.as_str()
                    )))
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub email_verified: bool,
    pub credential: Credential,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    /// The session this caller is on, if they are on one. `None` for API keys,
    /// which deliberately have no session: the previous implementation used
    /// `Uuid::nil()`, which silently matched no row and made session-scoped
    /// operations look like they succeeded.
    pub fn session_id(&self) -> Option<Uuid> {
        match self.credential {
            Credential::Session { session_id } => Some(session_id),
            Credential::ApiKey { .. } | Credential::SsoRemote { .. } => None,
        }
    }

    pub fn require_scope(&self, scope: ApiScope) -> Result<(), AppError> {
        self.credential.require_scope(scope)
    }
}

/// Requires the `admin` role, re-read from the database rather than trusted from
/// the token, so a demoted administrator loses access at once.
///
/// An API key additionally has to carry the `admin` scope. Holding an
/// administrator's key is not the same as an administrator sitting at a console.
#[derive(Debug, Clone)]
pub struct AdminUser {
    pub id: Uuid,
    pub email: String,
    pub credential: Credential,
}

/// Requires an interactive session, refusing API keys regardless of scope.
///
/// Used by the account-lifecycle routes, which need a real `session_id` and must
/// never be reachable with a machine credential.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub id: Uuid,
    pub session_id: Uuid,
    pub email: String,
    pub role: String,
}

impl AdminUser {
    pub fn require_scope(&self, scope: ApiScope) -> Result<(), AppError> {
        self.credential.require_scope(scope)
    }
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

    // 1. x-api-key (Better Auth M2M convention). The key's declared scopes ride
    //    along on the credential so every handler can enforce them.
    if let Some(api_key) = parts.headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
        let (user, key_record) =
            crate::services::api_key::ApiKeyService::resolve_key(&state, api_key).await?;

        return Ok(AuthUser {
            id: user.id,
            email: user.email,
            role: user.role,
            email_verified: user.email_verified,
            credential: Credential::ApiKey {
                key_id: key_record.id,
                scopes: ScopeSet::from_stored(key_record.scopes.as_ref()),
            },
        });
    }

    // 2. Bearer JWT: check local session token first, then fallback to remote JWKS SSO
    let token = bearer_token(parts)?;

    match AuthService::verify_access_token(token, state.config.jwt_secret.expose()) {
        Ok(claims) => {
            let user_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| AppError::Unauthorized("Malformed user ID in token".to_string()))?;
            let session_id = Uuid::parse_str(&claims.sid)
                .map_err(|_| AppError::Unauthorized("Malformed session ID in token".to_string()))?;

            // Authoritative check: the session must still be live and the user must
            // still be permitted. Role and ban state come from here, never the token.
            let user = AuthService::resolve_session(&state.db, user_id, session_id).await?;

            Ok(AuthUser {
                id: user.id,
                email: user.email,
                role: user.role,
                email_verified: user.email_verified,
                credential: Credential::Session { session_id },
            })
        }
        Err(local_err) => {
            // If remote JWKS is configured, attempt validating token against external IdP (Better Auth / OIDC)
            if let Some(jwks_client) = &state.jwks_client {
                let remote_claims = jwks_client.verify_token(token).await?;

                let user_id =
                    Uuid::parse_str(&remote_claims.sub).unwrap_or_else(|_| Uuid::now_v7());

                let email = remote_claims
                    .email
                    .unwrap_or_else(|| format!("{}@sso.local", user_id));
                let role = remote_claims.role.unwrap_or_else(|| "member".to_string());
                let email_verified = remote_claims.email_verified.unwrap_or(true);

                Ok(AuthUser {
                    id: user_id,
                    email,
                    role,
                    email_verified,
                    credential: Credential::SsoRemote {
                        issuer: remote_claims.iss,
                    },
                })
            } else {
                Err(local_err)
            }
        }
    }
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
        // Both conditions must hold for a key: the account is an administrator
        // AND the key was explicitly issued for administration.
        auth_user.require_scope(ApiScope::Admin)?;

        Ok(AdminUser {
            id: auth_user.id,
            email: auth_user.email,
            credential: auth_user.credential,
        })
    }
}

impl<S> FromRequestParts<S> for SessionUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = authenticate(parts, state).await?;
        let session_id = auth_user.session_id().ok_or_else(|| {
            AppError::Forbidden(
                "This operation requires an interactive session; API keys cannot perform it"
                    .to_string(),
            )
        })?;

        Ok(SessionUser {
            id: auth_user.id,
            session_id,
            email: auth_user.email,
            role: auth_user.role,
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
