use std::sync::Arc;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::AppError,
    models::user::{
        Account, AuthResponse, ForgetPasswordRequest, ResetPasswordRequest, SignInEmailRequest,
        SignUpEmailRequest, User, Verification, VerifyEmailRequest,
    },
    state::AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID (UUID)
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct AuthService;

impl AuthService {
    pub fn hash_password(password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}").into()))
    }

    pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash format: {e}").into()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn generate_random_token(len: usize) -> String {
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub fn generate_jwt(user: &User, config: &AppConfig) -> Result<String, AppError> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(config.jwt_expiration_hours);

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role.clone(),
            iat: now.timestamp() as usize,
            exp: expires_at.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("JWT encoding failed: {e}").into()))
    }

    pub fn verify_jwt(token: &str, jwt_secret: &str) -> Result<Claims, AppError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized("Invalid or expired authentication token".to_string()))?;

        Ok(token_data.claims)
    }

    pub async fn sign_up_email(
        state: &Arc<AppState>,
        req: SignUpEmailRequest,
    ) -> Result<AuthResponse, AppError> {
        let mut tx = state.db.begin().await?;

        // 1. Check if user already exists
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
        )
        .bind(&req.email)
        .fetch_one(&mut *tx)
        .await?;

        if exists {
            return Err(AppError::Conflict("User with this email already exists".to_string()));
        }

        let user_id = Uuid::now_v7();
        let account_id = Uuid::now_v7();
        let now = Utc::now();
        let password_hash = Self::hash_password(&req.password)?;

        // 2. Insert into users table
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, name, email, email_verified, image, role, banned, created_at, updated_at)
            VALUES ($1, $2, $3, false, $4, 'user', false, $5, $6)
            RETURNING id, name, email, email_verified, image, role, banned, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(&req.name)
        .bind(&req.email)
        .bind(&req.image)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // 3. Insert credentials into accounts table
        sqlx::query(
            r#"
            INSERT INTO accounts (id, user_id, account_id, provider_id, password, created_at, updated_at)
            VALUES ($1, $2, $3, 'credential', $4, $5, $6)
            "#,
        )
        .bind(account_id)
        .bind(user_id)
        .bind(&req.email)
        .bind(&password_hash)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // 4. Generate verification token for email
        let verify_token = Self::generate_random_token(32);
        let expires_at = now + Duration::hours(24);

        sqlx::query(
            r#"
            INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(&req.email)
        .bind(&verify_token)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // 4. Send verification email via MailService (Mailpit / SMTP)
        let config = state.config.clone();
        let recipient = user.email.clone();
        let token_val = verify_token.clone();
        tokio::spawn(async move {
            let body = format!(
                "<h2>Welcome!</h2><p>Please verify your account using code: <b>{}</b></p>",
                token_val
            );
            let _ = crate::services::mail::MailService::send_email(
                &config,
                &recipient,
                "Verify your email",
                &body,
            )
            .await;
        });

        tx.commit().await?;

        tracing::info!(email = %req.email, verify_token = %verify_token, "Email verification token generated");

        let token = Self::generate_jwt(&user, &state.config)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.jwt_expiration_hours * 3600,
            user: user.into(),
        })
    }

    pub async fn sign_in_email(
        state: &Arc<AppState>,
        req: SignInEmailRequest,
    ) -> Result<AuthResponse, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, name, email, email_verified, image, role, banned, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(&req.email)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        if user.banned {
            return Err(AppError::Forbidden("This account has been suspended".to_string()));
        }

        let account = sqlx::query_as::<_, Account>(
            "SELECT id, user_id, account_id, provider_id, password, access_token, refresh_token, access_token_expires_at, created_at, updated_at FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user.id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Account uses social login".to_string()))?;

        let password_hash = account
            .password
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("Password not configured".to_string()))?;

        if !Self::verify_password(&req.password, password_hash)? {
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }

        let token = Self::generate_jwt(&user, &state.config)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.jwt_expiration_hours * 3600,
            user: user.into(),
        })
    }

    pub async fn verify_email(
        state: &Arc<AppState>,
        req: VerifyEmailRequest,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let verification = sqlx::query_as::<_, Verification>(
            "SELECT id, identifier, value, expires_at, created_at, updated_at FROM verifications WHERE value = $1 AND expires_at > $2",
        )
        .bind(&req.token)
        .bind(now)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired verification token".to_string()))?;

        let mut tx = state.db.begin().await?;

        sqlx::query(
            "UPDATE users SET email_verified = true, updated_at = $2 WHERE email = $1",
        )
        .bind(&verification.identifier)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM verifications WHERE id = $1")
            .bind(verification.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok("Email verified successfully".to_string())
    }

    pub async fn forget_password(
        state: &Arc<AppState>,
        req: ForgetPasswordRequest,
    ) -> Result<String, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
        )
        .bind(&req.email)
        .fetch_one(&state.db)
        .await?;

        // Always return success to prevent email enumeration attacks
        if !exists {
            return Ok("If the email exists, a password reset token has been generated".to_string());
        }

        let reset_token = Self::generate_random_token(32);
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        sqlx::query(
            r#"
            INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(&req.email)
        .bind(&reset_token)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&state.db)
        .await?;

        // Send reset password email via MailService (Mailpit / SMTP)
        let config = state.config.clone();
        let recipient = req.email.clone();
        let token_val = reset_token.clone();
        tokio::spawn(async move {
            let body = format!(
                "<h2>Password Reset Request</h2><p>Reset your password using token: <b>{}</b></p>",
                token_val
            );
            let _ = crate::services::mail::MailService::send_email(
                &config,
                &recipient,
                "Reset your password",
                &body,
            )
            .await;
        });

        tracing::info!(email = %req.email, reset_token = %reset_token, "Password reset token generated");
        Ok("If your email is registered, you will receive a password reset token".to_string())
    }

    pub async fn reset_password(
        state: &Arc<AppState>,
        req: ResetPasswordRequest,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let verification = sqlx::query_as::<_, Verification>(
            "SELECT id, identifier, value, expires_at, created_at, updated_at FROM verifications WHERE value = $1 AND expires_at > $2",
        )
        .bind(&req.token)
        .bind(now)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

        let user = sqlx::query_as::<_, User>(
            "SELECT id, name, email, email_verified, image, role, banned, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(&verification.identifier)
        .fetch_one(&state.db)
        .await?;

        let new_password_hash = Self::hash_password(&req.new_password)?;

        let mut tx = state.db.begin().await?;

        sqlx::query(
            "UPDATE accounts SET password = $2, updated_at = $3 WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user.id)
        .bind(&new_password_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM verifications WHERE id = $1")
            .bind(verification.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok("Password has been reset successfully".to_string())
    }

    pub async fn update_profile(
        state: &Arc<AppState>,
        user_id: Uuid,
        req: crate::models::user::UpdateUserRequest,
    ) -> Result<crate::models::user::UserResponse, AppError> {
        let now = Utc::now();
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET name = COALESCE($2, name),
                image = COALESCE($3, image),
                updated_at = $4
            WHERE id = $1
            RETURNING id, name, email, email_verified, image, role, banned, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(req.name)
        .bind(req.image)
        .bind(now)
        .fetch_one(&state.db)
        .await?;

        Ok(user.into())
    }

    pub async fn change_password(
        state: &Arc<AppState>,
        user_id: Uuid,
        req: crate::models::user::ChangePasswordRequest,
    ) -> Result<String, AppError> {
        let account = sqlx::query_as::<_, Account>(
            "SELECT id, user_id, account_id, provider_id, password, access_token, refresh_token, access_token_expires_at, created_at, updated_at FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::BadRequest("User has no password account configured (OAuth login)".to_string()))?;

        let password_hash = account
            .password
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Password not set".to_string()))?;

        if !Self::verify_password(&req.current_password, password_hash)? {
            return Err(AppError::Unauthorized("Incorrect current password".to_string()));
        }

        let new_hash = Self::hash_password(&req.new_password)?;
        let now = Utc::now();

        sqlx::query(
            "UPDATE accounts SET password = $2, updated_at = $3 WHERE id = $1",
        )
        .bind(account.id)
        .bind(new_hash)
        .bind(now)
        .execute(&state.db)
        .await?;

        Ok("Password changed successfully".to_string())
    }

    pub async fn delete_account(
        state: &Arc<AppState>,
        user_id: Uuid,
    ) -> Result<String, AppError> {
        let rows_affected = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok("Account deleted successfully".to_string())
    }
}
