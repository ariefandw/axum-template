use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse,
    TokenResponse, TokenUrl,
    basic::{BasicClient, BasicErrorResponseType, BasicRevocationErrorResponse, BasicTokenType},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    crypto,
    error::AppError,
    models::user::{AuthResponse, USER_COLUMNS, User},
    routes::v1::auth::OAuthUrlResponse,
    services::{
        audit::AuditService,
        auth::{AuthService, RequestContext},
    },
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    /// Google only asserts ownership when this is true. Linking on an unverified
    /// address lets anyone who can create a provider account claim a local one.
    #[serde(default)]
    pub verified_email: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GithubUserInfo {
    pub id: i64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct GithubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

type ConfiguredOAuthClient = oauth2::Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

fn pkce() -> (PkceCodeVerifier, PkceCodeChallenge) {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    (verifier, challenge)
}

pub struct OAuthService;

impl OAuthService {
    pub fn get_google_client(state: &AppState) -> Result<ConfiguredOAuthClient, AppError> {
        let provider =
            state.config.google.as_ref().ok_or_else(|| {
                AppError::BadRequest("Google OAuth is not configured".to_string())
            })?;
        let (client_id, client_secret, redirect_url) = (
            &provider.client_id,
            provider.client_secret.expose(),
            &provider.redirect_url,
        );

        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid Google auth URL: {e}").into()))?;
        let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid Google token URL: {e}").into()))?;

        Ok(BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(RedirectUrl::new(redirect_url.clone()).map_err(|e| {
                AppError::Internal(format!("Invalid Google redirect URL: {e}").into())
            })?))
    }

    pub async fn get_google_auth_url(state: &Arc<AppState>) -> Result<OAuthUrlResponse, AppError> {
        let client = Self::get_google_client(state)?;
        let (verifier, challenge) = pkce();
        let (auth_url, csrf) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .set_pkce_challenge(challenge)
            .url();

        Self::store_auth_request(state, "google", csrf.secret(), verifier.secret()).await?;
        Ok(OAuthUrlResponse {
            url: auth_url.to_string(),
            state: csrf.secret().clone(),
        })
    }

    pub fn get_github_client(state: &AppState) -> Result<ConfiguredOAuthClient, AppError> {
        let provider =
            state.config.github.as_ref().ok_or_else(|| {
                AppError::BadRequest("GitHub OAuth is not configured".to_string())
            })?;
        let (client_id, client_secret, redirect_url) = (
            &provider.client_id,
            provider.client_secret.expose(),
            &provider.redirect_url,
        );

        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid GitHub auth URL: {e}").into()))?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid GitHub token URL: {e}").into()))?;

        Ok(BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(RedirectUrl::new(redirect_url.clone()).map_err(|e| {
                AppError::Internal(format!("Invalid GitHub redirect URL: {e}").into())
            })?))
    }

    pub async fn get_github_auth_url(state: &Arc<AppState>) -> Result<OAuthUrlResponse, AppError> {
        let client = Self::get_github_client(state)?;
        let (verifier, challenge) = pkce();
        let (auth_url, csrf) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("read:user".to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .set_pkce_challenge(challenge)
            .url();

        Self::store_auth_request(state, "github", csrf.secret(), verifier.secret()).await?;
        Ok(OAuthUrlResponse {
            url: auth_url.to_string(),
            state: csrf.secret().clone(),
        })
    }

    /// Persist the CSRF state and PKCE verifier so the callback can prove the
    /// response belongs to a flow this server started. The state was previously
    /// generated, handed to the client, and then never checked.
    async fn store_auth_request(
        state: &Arc<AppState>,
        provider: &str,
        csrf_state: &str,
        pkce_verifier: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_auth_requests (state_hash, provider, pkce_verifier, expires_at)
            VALUES ($1, $2, $3, now() + interval '10 minutes')
            "#,
        )
        .bind(crypto::sha256_hex(csrf_state))
        .bind(provider)
        .bind(pkce_verifier)
        .execute(&state.db)
        .await?;
        Ok(())
    }

    /// Consume a pending authorization request, enforcing single use, expiry and
    /// provider match in one atomic statement.
    async fn consume_auth_request(
        state: &Arc<AppState>,
        provider: &str,
        csrf_state: &str,
    ) -> Result<PkceCodeVerifier, AppError> {
        let verifier: Option<String> = sqlx::query_scalar(
            r#"
            UPDATE oauth_auth_requests
            SET consumed_at = now()
            WHERE state_hash = $1
              AND provider = $2
              AND consumed_at IS NULL
              AND expires_at > now()
            RETURNING pkce_verifier
            "#,
        )
        .bind(crypto::sha256_hex(csrf_state))
        .bind(provider)
        .fetch_optional(&state.db)
        .await?;

        verifier.map(PkceCodeVerifier::new).ok_or_else(|| {
            AppError::Unauthorized(
                "OAuth state is invalid, expired, or already used. Restart the sign-in flow."
                    .to_string(),
            )
        })
    }

    pub async fn handle_google_callback(
        state: &Arc<AppState>,
        code: String,
        csrf_state: String,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        // Proves this callback belongs to a flow this server started.
        let verifier = Self::consume_auth_request(state, "google", &csrf_state).await?;
        let client = Self::get_google_client(state)?;

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .set_pkce_verifier(verifier)
            .request_async(&state.http_client)
            .await
            .map_err(|e| AppError::Unauthorized(format!("OAuth token exchange failed: {e}")))?;

        let access_token = token_result.access_token().secret();

        let user_info: GoogleUserInfo = state
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to fetch Google user info: {e}").into())
            })?
            .error_for_status()
            .map_err(|e| AppError::Unauthorized(format!("Google rejected the token: {e}")))?
            .json()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse Google user info: {e}").into())
            })?;

        // Linking on an unverified address would let anyone who can add an email
        // to a Google account claim the matching local account.
        if !user_info.verified_email {
            return Err(AppError::BadRequest(
                "Your Google email address is not verified. Verify it with Google, then try again."
                    .to_string(),
            ));
        }

        Self::upsert_oauth_user(
            state,
            &user_info.email,
            user_info.name.as_deref().unwrap_or("Google User"),
            user_info.picture.as_deref(),
            "google",
            &user_info.id,
            Some(access_token),
            ctx,
        )
        .await
    }

    pub async fn handle_github_callback(
        state: &Arc<AppState>,
        code: String,
        csrf_state: String,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        let verifier = Self::consume_auth_request(state, "github", &csrf_state).await?;
        let client = Self::get_github_client(state)?;

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .set_pkce_verifier(verifier)
            .request_async(&state.http_client)
            .await
            .map_err(|e| AppError::Unauthorized(format!("OAuth token exchange failed: {e}")))?;

        let access_token = token_result.access_token().secret();

        let user_info: GithubUserInfo = state
            .http_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to fetch GitHub user info: {e}").into())
            })?
            .error_for_status()
            .map_err(|e| AppError::Unauthorized(format!("GitHub rejected the token: {e}")))?
            .json()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse GitHub user info: {e}").into())
            })?;

        // Only ever link a primary address GitHub has itself verified. The
        // profile `email` field is a free-text display value and is not proof.
        let emails: Vec<GithubEmail> = state
            .http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch GitHub emails: {e}").into()))?
            .error_for_status()
            .map_err(|e| AppError::Unauthorized(format!("GitHub rejected the token: {e}")))?
            .json()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse GitHub emails: {e}").into())
            })?;

        let email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .map(|e| e.email)
            .ok_or_else(|| {
                AppError::BadRequest(
                    "No verified primary email found on your GitHub account".to_string(),
                )
            })?;

        let display_name = user_info.name.unwrap_or(user_info.login);

        Self::upsert_oauth_user(
            state,
            &email,
            &display_name,
            user_info.avatar_url.as_deref(),
            "github",
            &user_info.id.to_string(),
            Some(access_token),
            ctx,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn upsert_oauth_user(
        state: &Arc<AppState>,
        email: &str,
        name: &str,
        image: Option<&str>,
        provider_id: &str,
        account_id: &str,
        access_token: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        let email = email.trim().to_ascii_lowercase();
        let mut tx = state.db.begin().await?;

        let existing = sqlx::query_as::<_, User>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE email = $1 AND deleted_at IS NULL"
        ))
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await?;

        let user = match existing {
            Some(u) => {
                if u.banned {
                    return Err(AppError::Forbidden(
                        "This account has been suspended".to_string(),
                    ));
                }
                sqlx::query_as::<_, User>(&format!(
                    "UPDATE users SET email_verified = true, image = COALESCE(image, $2), \
                     updated_at = now() WHERE id = $1 RETURNING {USER_COLUMNS}"
                ))
                .bind(u.id)
                .bind(image)
                .fetch_one(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_as::<_, User>(&format!(
                    r#"
                    INSERT INTO users (id, name, email, email_verified, image, role, banned)
                    VALUES ($1, $2, $3, true, $4, 'user', false)
                    RETURNING {USER_COLUMNS}
                    "#
                ))
                .bind(Uuid::now_v7())
                .bind(name)
                .bind(&email)
                .bind(image)
                .fetch_one(&mut *tx)
                .await?
            }
        };

        // Provider credentials are sealed before they touch the table, so a SQL
        // read no longer yields live third-party tokens.
        let sealed_token = match access_token {
            Some(token) => Some(crypto::encrypt(&state.config.encryption_key, token)?),
            None => None,
        };

        sqlx::query(
            r#"
            INSERT INTO accounts (id, user_id, account_id, provider_id, access_token)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (provider_id, account_id)
            DO UPDATE SET access_token = $5, updated_at = now()
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user.id)
        .bind(account_id)
        .bind(provider_id)
        .bind(sealed_token.as_deref())
        .execute(&mut *tx)
        .await?;

        let (session_id, refresh_token) =
            AuthService::create_oauth_session(&mut tx, user.id, &state.config, ctx).await?;

        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user.id),
            "user.signed_in_social",
            "session",
            Some(&session_id.to_string()),
            ctx,
            Some(serde_json::json!({ "provider": provider_id })),
        )
        .await;

        let access_token = AuthService::generate_access_token(&user, session_id, &state.config)?;
        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.access_token_ttl_minutes * 60,
            session_id,
            user: user.into(),
        })
    }
}
