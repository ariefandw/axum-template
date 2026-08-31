use std::sync::Arc;
use chrono::Utc;
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicRevocationErrorResponse, BasicTokenType},
    AuthUrl, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointNotSet,
    EndpointSet, RedirectUrl, Scope, StandardErrorResponse, StandardRevocableToken,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::user::{AuthResponse, User},
    services::auth::AuthService,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
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

pub struct OAuthService;

impl OAuthService {
    pub fn get_google_client(state: &AppState) -> Result<ConfiguredOAuthClient, AppError> {
        let client_id = state
            .config
            .google_client_id
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Google OAuth is not configured".to_string()))?;
        let client_secret = state
            .config
            .google_client_secret
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Google OAuth is not configured".to_string()))?;
        let redirect_url = state
            .config
            .google_redirect_url
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Google OAuth is not configured".to_string()))?;

        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid Google auth URL: {e}").into()))?;
        let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid Google token URL: {e}").into()))?;

        Ok(BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(
                RedirectUrl::new(redirect_url.clone())
                    .map_err(|e| AppError::Internal(format!("Invalid Google redirect URL: {e}").into()))?,
            ))
    }

    pub fn get_google_auth_url(state: &AppState) -> Result<(String, String), AppError> {
        let client = Self::get_google_client(state)?;
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
            .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token.secret().clone()))
    }

    pub fn get_github_client(state: &AppState) -> Result<ConfiguredOAuthClient, AppError> {
        let client_id = state
            .config
            .github_client_id
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("GitHub OAuth is not configured".to_string()))?;
        let client_secret = state
            .config
            .github_client_secret
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("GitHub OAuth is not configured".to_string()))?;
        let redirect_url = state
            .config
            .github_redirect_url
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("GitHub OAuth is not configured".to_string()))?;

        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid GitHub auth URL: {e}").into()))?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .map_err(|e| AppError::Internal(format!("Invalid GitHub token URL: {e}").into()))?;

        Ok(BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(
                RedirectUrl::new(redirect_url.clone())
                    .map_err(|e| AppError::Internal(format!("Invalid GitHub redirect URL: {e}").into()))?,
            ))
    }

    pub fn get_github_auth_url(state: &AppState) -> Result<(String, String), AppError> {
        let client = Self::get_github_client(state)?;
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("read:user".to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok((auth_url.to_string(), csrf_token.secret().clone()))
    }

    pub async fn handle_google_callback(
        state: &Arc<AppState>,
        code: String,
    ) -> Result<AuthResponse, AppError> {
        let client = Self::get_google_client(state)?;
        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code))
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
            .map_err(|e| AppError::Internal(format!("Failed to fetch Google user info: {e}").into()))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Google user info: {e}").into()))?;

        Self::upsert_oauth_user(
            state,
            &user_info.email,
            user_info.name.as_deref().unwrap_or("Google User"),
            user_info.picture.as_deref(),
            "google",
            &user_info.id,
            Some(access_token),
        )
        .await
    }

    pub async fn handle_github_callback(
        state: &Arc<AppState>,
        code: String,
    ) -> Result<AuthResponse, AppError> {
        let client = Self::get_github_client(state)?;
        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async(&state.http_client)
            .await
            .map_err(|e| AppError::Unauthorized(format!("OAuth token exchange failed: {e}")))?;

        let access_token = token_result.access_token().secret();

        let user_info: GithubUserInfo = state
            .http_client
            .get("https://api.github.com/user")
            .header("User-Agent", "axum-template")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch GitHub user info: {e}").into()))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse GitHub user info: {e}").into()))?;

        let email = if let Some(e) = user_info.email {
            e
        } else {
            let emails: Vec<GithubEmail> = state
                .http_client
                .get("https://api.github.com/user/emails")
                .header("User-Agent", "axum-template")
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to fetch GitHub emails: {e}").into()))?
                .json()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to parse GitHub emails: {e}").into()))?;

            emails
                .into_iter()
                .find(|e| e.primary && e.verified)
                .map(|e| e.email)
                .ok_or_else(|| AppError::BadRequest("No verified primary email found on GitHub account".to_string()))?
        };

        let display_name = user_info.name.unwrap_or(user_info.login);

        Self::upsert_oauth_user(
            state,
            &email,
            &display_name,
            user_info.avatar_url.as_deref(),
            "github",
            &user_info.id.to_string(),
            Some(access_token),
        )
        .await
    }

    async fn upsert_oauth_user(
        state: &Arc<AppState>,
        email: &str,
        name: &str,
        image: Option<&str>,
        provider_id: &str,
        account_id: &str,
        access_token: Option<&str>,
    ) -> Result<AuthResponse, AppError> {
        let now = Utc::now();
        let mut tx = state.db.begin().await?;

        // 1. Check if user exists by email
        let existing_user = sqlx::query_as::<_, User>(
            "SELECT id, name, email, email_verified, image, role, banned, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?;

        let user = match existing_user {
            Some(u) => {
                // Update verified status and avatar if missing
                sqlx::query_as::<_, User>(
                    "UPDATE users SET email_verified = true, image = COALESCE(image, $2), updated_at = $3 WHERE id = $1 RETURNING id, name, email, email_verified, image, role, banned, created_at, updated_at",
                )
                .bind(u.id)
                .bind(image)
                .bind(now)
                .fetch_one(&mut *tx)
                .await?
            }
            None => {
                // Create user
                sqlx::query_as::<_, User>(
                    r#"
                    INSERT INTO users (id, name, email, email_verified, image, role, banned, created_at, updated_at)
                    VALUES ($1, $2, $3, true, $4, 'user', false, $5, $6)
                    RETURNING id, name, email, email_verified, image, role, banned, created_at, updated_at
                    "#,
                )
                .bind(Uuid::now_v7())
                .bind(name)
                .bind(email)
                .bind(image)
                .bind(now)
                .bind(now)
                .fetch_one(&mut *tx)
                .await?
            }
        };

        // 2. Link social account in accounts table
        sqlx::query(
            r#"
            INSERT INTO accounts (id, user_id, account_id, provider_id, access_token, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (provider_id, account_id)
            DO UPDATE SET access_token = $5, updated_at = $7
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user.id)
        .bind(account_id)
        .bind(provider_id)
        .bind(access_token)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let token = AuthService::generate_jwt(&user, &state.config)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.jwt_expiration_hours * 3600,
            user: user.into(),
        })
    }
}
