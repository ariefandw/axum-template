//! Credential and session management.
//!
//! Two design changes drive this module:
//!
//! * **Sessions are the source of truth.** The access token is a short-lived
//!   bearer credential naming a session row; that row is what gets revoked when a
//!   user signs out, is banned, or changes their password. A stateless JWT alone
//!   cannot be withdrawn, so bans and role changes could not previously take
//!   effect until the token expired.
//! * **Recovery tokens are scoped and hashed.** Each carries an explicit purpose
//!   and is stored only as a SHA-256 digest, so an email-verification token can
//!   no longer be replayed against the password-reset endpoint and a database
//!   read does not yield usable tokens.

use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    crypto,
    error::AppError,
    models::user::{
        Account, AuthResponse, ChangePasswordRequest, CredentialRow, ForgetPasswordRequest,
        ResetPasswordRequest, Session, SessionUserRow, SignInEmailRequest, SignUpEmailRequest,
        TokenPurpose, USER_COLUMNS, UpdateUserRequest, User, UserResponse, VerifyEmailRequest,
    },
    services::{audit::AuditService, mail::MailService},
    state::AppState,
};

/// A dummy Argon2 hash of a random value, verified against when an account does
/// not exist so that sign-in costs the same either way. Without it, response
/// latency reveals which addresses are registered.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User ID (UUID).
    pub sub: String,
    /// Session ID. Looked up on every request so revocation takes effect at once.
    pub sid: String,
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

/// Request metadata recorded against sessions and audit entries.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct AuthService;

impl AuthService {
    // -- password hashing ---------------------------------------------------

    fn argon2(config: &AppConfig) -> Result<Argon2<'static>, AppError> {
        let params = Params::new(
            config.argon2.memory_kib,
            config.argon2.iterations,
            config.argon2.parallelism,
            None,
        )
        .map_err(|e| AppError::Internal(format!("Invalid Argon2 parameters: {e}").into()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    pub fn hash_password(password: &str, config: &AppConfig) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        Self::argon2(config)?
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}").into()))
    }

    pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash format: {e}").into()))?;
        // Verification reads its parameters from the stored hash, so records
        // written under older Argon2 settings keep working.
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Burn the same CPU as a real verification, to keep sign-in constant-time
    /// with respect to account existence.
    fn verify_dummy_password(password: &str) {
        if let Ok(parsed) = PasswordHash::new(DUMMY_HASH) {
            let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
        }
    }

    // -- access tokens ------------------------------------------------------

    pub fn generate_access_token(
        user: &User,
        session_id: Uuid,
        config: &AppConfig,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(config.access_token_ttl_minutes);

        let claims = Claims {
            sub: user.id.to_string(),
            sid: session_id.to_string(),
            email: user.email.clone(),
            role: user.role.clone(),
            iat: now.timestamp() as usize,
            exp: expires_at.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.expose().as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("JWT encoding failed: {e}").into()))
    }

    pub fn verify_access_token(token: &str, jwt_secret: &str) -> Result<Claims, AppError> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| AppError::Unauthorized("Invalid or expired authentication token".to_string()))
    }

    // -- sessions -----------------------------------------------------------

    /// Create a session and return `(session_id, plaintext refresh token)`.
    /// Only the digest is persisted.
    async fn create_session(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        config: &AppConfig,
        ctx: &RequestContext,
    ) -> Result<(Uuid, String), AppError> {
        let session_id = Uuid::now_v7();
        let refresh_token = crypto::random_token(48);
        let expires_at = Utc::now() + Duration::days(config.refresh_token_ttl_days);

        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(crypto::sha256_hex(&refresh_token))
        .bind(expires_at)
        .bind(ctx.ip_address.as_deref())
        .bind(ctx.user_agent.as_deref())
        .execute(&mut **tx)
        .await?;

        Ok((session_id, refresh_token))
    }

    /// Session creation for callers outside this module (the OAuth flow), which
    /// must enrol a session inside their own transaction.
    pub async fn create_oauth_session(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        config: &AppConfig,
        ctx: &RequestContext,
    ) -> Result<(Uuid, String), AppError> {
        Self::create_session(tx, user_id, config, ctx).await
    }

    /// Resolve the session named by an access token, rejecting it if the session
    /// was revoked or expired, or the user was banned or deleted since issuance.
    ///
    /// This is the per-request check that makes revocation real.
    pub async fn resolve_session(
        db: &PgPool,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<User, AppError> {
        let row = sqlx::query_as::<_, SessionUserRow>(
            r#"
            SELECT u.id, u.name, u.email, u.email_verified, u.image, u.role, u.banned,
                   u.created_at, u.updated_at,
                   s.revoked_at, s.expires_at AS session_expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.id = $1 AND s.user_id = $2 AND u.deleted_at IS NULL
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;

        let row =
            row.ok_or_else(|| AppError::Unauthorized("Session no longer exists".to_string()))?;

        if row.revoked_at.is_some() {
            return Err(AppError::Unauthorized(
                "Session has been revoked".to_string(),
            ));
        }
        if row.session_expires_at <= Utc::now() {
            return Err(AppError::Unauthorized("Session has expired".to_string()));
        }
        if row.banned {
            return Err(AppError::Forbidden(
                "This account has been suspended".to_string(),
            ));
        }

        let user: User = row.into();
        Ok(user)
    }

    /// Rotate a refresh token. The presented token is consumed as the new one is
    /// issued, inside a single transaction.
    pub async fn refresh_session(
        state: &Arc<AppState>,
        refresh_token: &str,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        let token_hash = crypto::sha256_hex(refresh_token);
        let mut tx = state.db.begin().await?;

        // Match the live token first, then the superseded one. A hit on the
        // latter means a token that was already rotated has been presented
        // again, which is the signature of a stolen token being replayed.
        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT id, user_id, expires_at, revoked_at
            FROM sessions
            WHERE refresh_token_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await?;

        let replayed = if session.is_none() {
            sqlx::query_as::<_, Session>(
                r#"
                SELECT id, user_id, expires_at, revoked_at
                FROM sessions
                WHERE previous_token_hash = $1
                FOR UPDATE
                "#,
            )
            .bind(&token_hash)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            None
        };

        if let Some(compromised) = replayed {
            // Revoke the whole family: we cannot tell whether the legitimate
            // client or the attacker holds the current token, so both must
            // re-authenticate.
            sqlx::query(
                "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(compromised.user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            tracing::warn!(
                user_id = %compromised.user_id,
                "Rotated refresh token replayed; all sessions for the user were revoked"
            );
            return Err(AppError::Unauthorized(
                "Refresh token has already been used. Please sign in again.".to_string(),
            ));
        }

        let session =
            session.ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

        if session.revoked_at.is_some() {
            return Err(AppError::Unauthorized(
                "Session has been revoked. Please sign in again.".to_string(),
            ));
        }

        if session.expires_at <= Utc::now() {
            return Err(AppError::Unauthorized(
                "Refresh token has expired".to_string(),
            ));
        }

        let user = sqlx::query_as::<_, User>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE id = $1 AND deleted_at IS NULL"
        ))
        .bind(session.user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Account no longer exists".to_string()))?;

        if user.banned {
            return Err(AppError::Forbidden(
                "This account has been suspended".to_string(),
            ));
        }

        let new_refresh = crypto::random_token(48);
        let new_expiry = Utc::now() + Duration::days(state.config.refresh_token_ttl_days);
        sqlx::query(
            r#"
            UPDATE sessions
            SET previous_token_hash = refresh_token_hash,
                refresh_token_hash = $2,
                expires_at = $3,
                rotated_at = now(),
                last_used_at = now(),
                ip_address = COALESCE($4, ip_address),
                user_agent = COALESCE($5, user_agent)
            WHERE id = $1
            "#,
        )
        .bind(session.id)
        .bind(crypto::sha256_hex(&new_refresh))
        .bind(new_expiry)
        .bind(ctx.ip_address.as_deref())
        .bind(ctx.user_agent.as_deref())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let access_token = Self::generate_access_token(&user, session.id, &state.config)?;
        Ok(AuthResponse {
            access_token,
            refresh_token: new_refresh,
            token_type: "Bearer".to_string(),
            expires_in: state.config.access_token_ttl_minutes * 60,
            session_id: session.id,
            user: user.into(),
        })
    }

    pub async fn sign_out(
        state: &Arc<AppState>,
        user_id: Uuid,
        session_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&state.db)
        .await?;

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "session.signed_out",
            "session",
            Some(&session_id.to_string()),
            ctx,
            None,
        )
        .await;

        Ok("Signed out successfully".to_string())
    }

    pub async fn sign_out_all(
        state: &Arc<AppState>,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&state.db)
        .await?
        .rows_affected();

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "session.signed_out_all",
            "session",
            None,
            ctx,
            Some(serde_json::json!({ "sessions_revoked": revoked })),
        )
        .await;

        Ok(format!("Revoked {revoked} session(s)"))
    }

    // -- recovery tokens ----------------------------------------------------

    /// Issue a purpose-scoped, single-use token. Returns the plaintext, which is
    /// the only point at which it exists in readable form.
    async fn issue_verification_token(
        tx: &mut Transaction<'_, Postgres>,
        identifier: &str,
        purpose: TokenPurpose,
        ttl: Duration,
    ) -> Result<String, AppError> {
        // Supersede any outstanding token of the same purpose, so a leaked older
        // token cannot be used after a fresh one is requested.
        sqlx::query(
            "UPDATE verifications SET consumed_at = now() \
             WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL",
        )
        .bind(identifier)
        .bind(purpose.as_str())
        .execute(&mut **tx)
        .await?;

        let token = crypto::random_token(48);
        sqlx::query(
            r#"
            INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(identifier)
        .bind(purpose.as_str())
        .bind(crypto::sha256_hex(&token))
        .bind(Utc::now() + ttl)
        .execute(&mut **tx)
        .await?;

        Ok(token)
    }

    /// Consume a token, enforcing purpose, expiry, and single use in one atomic
    /// statement so a token cannot be redeemed twice concurrently.
    async fn consume_verification_token(
        tx: &mut Transaction<'_, Postgres>,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<String, AppError> {
        let identifier: Option<String> = sqlx::query_scalar(
            r#"
            UPDATE verifications
            SET consumed_at = now()
            WHERE token_hash = $1
              AND purpose = $2
              AND consumed_at IS NULL
              AND expires_at > now()
            RETURNING identifier
            "#,
        )
        .bind(crypto::sha256_hex(token))
        .bind(purpose.as_str())
        .fetch_optional(&mut **tx)
        .await?;

        identifier.ok_or_else(|| {
            AppError::BadRequest("Invalid, expired, or already-used token".to_string())
        })
    }

    // -- registration and sign-in -------------------------------------------

    pub async fn sign_up_email(
        state: &Arc<AppState>,
        req: SignUpEmailRequest,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        let email = req.email.trim().to_ascii_lowercase();
        let mut tx = state.db.begin().await?;

        // The unique index on live emails is the real guard; this check only
        // turns the common case into a clean 409 instead of a constraint error.
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)",
        )
        .bind(&email)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            return Err(AppError::Conflict(
                "User with this email already exists".to_string(),
            ));
        }

        let user_id = Uuid::now_v7();
        let password_hash = Self::hash_password(&req.password, &state.config)?;

        let user = sqlx::query_as::<_, User>(&format!(
            r#"
            INSERT INTO users (id, name, email, email_verified, image, role, banned)
            VALUES ($1, $2, $3, false, $4, 'user', false)
            RETURNING {USER_COLUMNS}
            "#
        ))
        .bind(user_id)
        .bind(req.name.trim())
        .bind(&email)
        .bind(&req.image)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO accounts (id, user_id, account_id, provider_id, password)
            VALUES ($1, $2, $3, 'credential', $4)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(&email)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;

        let verify_token = Self::issue_verification_token(
            &mut tx,
            &email,
            TokenPurpose::EmailVerify,
            Duration::hours(state.config.email_verify_ttl_hours),
        )
        .await?;

        let (session_id, refresh_token) =
            Self::create_session(&mut tx, user_id, &state.config, ctx).await?;

        tx.commit().await?;

        // Only after the transaction commits, so a rolled-back registration
        // cannot produce a live verification email.
        MailService::send_verification_email(state, &email, &verify_token);

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "user.signed_up",
            "user",
            Some(&user_id.to_string()),
            ctx,
            None,
        )
        .await;

        let access_token = Self::generate_access_token(&user, session_id, &state.config)?;
        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.access_token_ttl_minutes * 60,
            session_id,
            user: user.into(),
        })
    }

    pub async fn sign_in_email(
        state: &Arc<AppState>,
        req: SignInEmailRequest,
        ctx: &RequestContext,
    ) -> Result<AuthResponse, AppError> {
        let email = req.email.trim().to_ascii_lowercase();

        let record = sqlx::query_as::<_, CredentialRow>(
            r#"
            SELECT u.id, u.name, u.email, u.email_verified, u.image, u.role, u.banned,
                   u.created_at, u.updated_at,
                   a.password, u.locked_until
            FROM users u
            LEFT JOIN accounts a ON a.user_id = u.id AND a.provider_id = 'credential'
            WHERE u.email = $1 AND u.deleted_at IS NULL
            "#,
        )
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;

        let Some(row) = record else {
            // Spend the same work as a real verification before failing, so
            // response time does not disclose whether the address is registered.
            Self::verify_dummy_password(&req.password);
            return Err(AppError::Unauthorized(
                "Invalid email or password".to_string(),
            ));
        };
        let (password_hash, locked_until) = (row.password.clone(), row.locked_until);
        let user: User = row.into();

        if user.banned {
            return Err(AppError::Forbidden(
                "This account has been suspended".to_string(),
            ));
        }

        if locked_until.is_some_and(|until| until > Utc::now()) {
            return Err(AppError::TooManyRequests(
                "Too many failed sign-in attempts. Try again later.".to_string(),
            ));
        }

        let Some(password_hash) = password_hash else {
            // Social-only account: same timing, same message.
            Self::verify_dummy_password(&req.password);
            return Err(AppError::Unauthorized(
                "Invalid email or password".to_string(),
            ));
        };

        if !Self::verify_password(&req.password, &password_hash)? {
            Self::register_failed_login(state, user.id, ctx).await?;
            return Err(AppError::Unauthorized(
                "Invalid email or password".to_string(),
            ));
        }

        let mut tx = state.db.begin().await?;
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
        )
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
        let (session_id, refresh_token) =
            Self::create_session(&mut tx, user.id, &state.config, ctx).await?;
        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user.id),
            "user.signed_in",
            "session",
            Some(&session_id.to_string()),
            ctx,
            None,
        )
        .await;

        let access_token = Self::generate_access_token(&user, session_id, &state.config)?;
        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.access_token_ttl_minutes * 60,
            session_id,
            user: user.into(),
        })
    }

    /// Per-account lockout, complementing the per-IP rate limit: an attacker
    /// spreading attempts across many addresses still cannot brute-force one
    /// account.
    async fn register_failed_login(
        state: &Arc<AppState>,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let locked: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN failed_login_attempts + 1 >= $2 THEN now() + make_interval(mins => $3)
                    ELSE locked_until
                END
            WHERE id = $1
            RETURNING locked_until
            "#,
        )
        .bind(user_id)
        .bind(state.config.lockout_threshold)
        .bind(state.config.lockout_minutes as i32)
        .fetch_one(&state.db)
        .await?;

        if locked.is_some_and(|until| until > Utc::now()) {
            AuditService::record_best_effort(
                state,
                Some(user_id),
                "user.locked_out",
                "user",
                Some(&user_id.to_string()),
                ctx,
                None,
            )
            .await;
        }
        Ok(())
    }

    // -- account recovery ---------------------------------------------------

    pub async fn verify_email(
        state: &Arc<AppState>,
        req: VerifyEmailRequest,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        let mut tx = state.db.begin().await?;
        let identifier =
            Self::consume_verification_token(&mut tx, &req.token, TokenPurpose::EmailVerify)
                .await?;

        sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE email = $1")
            .bind(&identifier)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            None,
            "user.email_verified",
            "user",
            None,
            ctx,
            None,
        )
        .await;
        Ok("Email verified successfully".to_string())
    }

    pub async fn forget_password(
        state: &Arc<AppState>,
        req: ForgetPasswordRequest,
    ) -> Result<String, AppError> {
        const NEUTRAL: &str = "If that email is registered, a password reset link has been sent";
        let email = req.email.trim().to_ascii_lowercase();

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)",
        )
        .bind(&email)
        .fetch_one(&state.db)
        .await?;

        if !exists {
            return Ok(NEUTRAL.to_string());
        }

        let mut tx = state.db.begin().await?;
        let reset_token = Self::issue_verification_token(
            &mut tx,
            &email,
            TokenPurpose::PasswordReset,
            Duration::minutes(state.config.password_reset_ttl_minutes),
        )
        .await?;
        tx.commit().await?;

        MailService::send_password_reset_email(state, &email, &reset_token);
        Ok(NEUTRAL.to_string())
    }

    pub async fn reset_password(
        state: &Arc<AppState>,
        req: ResetPasswordRequest,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        let new_password_hash = Self::hash_password(&req.new_password, &state.config)?;
        let mut tx = state.db.begin().await?;

        // Only a token minted for password reset is accepted here.
        let identifier =
            Self::consume_verification_token(&mut tx, &req.token, TokenPurpose::PasswordReset)
                .await?;

        let user = sqlx::query_as::<_, User>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE email = $1 AND deleted_at IS NULL"
        ))
        .bind(&identifier)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired token".to_string()))?;

        sqlx::query(
            "UPDATE accounts SET password = $2, updated_at = now() \
             WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user.id)
        .bind(&new_password_hash)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1",
        )
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

        // A password reset must not leave an attacker's session alive.
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user.id),
            "user.password_reset",
            "user",
            Some(&user.id.to_string()),
            ctx,
            None,
        )
        .await;
        Ok("Password has been reset successfully. All sessions were signed out.".to_string())
    }

    // -- profile ------------------------------------------------------------

    pub async fn update_profile(
        state: &Arc<AppState>,
        user_id: Uuid,
        req: UpdateUserRequest,
    ) -> Result<UserResponse, AppError> {
        let user = sqlx::query_as::<_, User>(&format!(
            r#"
            UPDATE users
            SET name = COALESCE($2, name), image = COALESCE($3, image), updated_at = now()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING {USER_COLUMNS}
            "#
        ))
        .bind(user_id)
        .bind(req.name.as_deref().map(str::trim))
        .bind(req.image.as_deref())
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user.into())
    }

    pub async fn change_password(
        state: &Arc<AppState>,
        user_id: Uuid,
        current_session: Uuid,
        req: ChangePasswordRequest,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        let account = sqlx::query_as::<_, Account>(
            "SELECT id, user_id, account_id, provider_id, password, access_token, refresh_token, \
             access_token_expires_at, created_at, updated_at \
             FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("This account signs in with a social provider".to_string())
        })?;

        let password_hash = account
            .password
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Password not set".to_string()))?;

        if !Self::verify_password(&req.current_password, password_hash)? {
            return Err(AppError::Unauthorized(
                "Incorrect current password".to_string(),
            ));
        }

        let new_hash = Self::hash_password(&req.new_password, &state.config)?;
        let mut tx = state.db.begin().await?;

        sqlx::query("UPDATE accounts SET password = $2, updated_at = now() WHERE id = $1")
            .bind(account.id)
            .bind(new_hash)
            .execute(&mut *tx)
            .await?;

        // Every other session is dropped; the caller keeps the one they are on.
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(current_session)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "user.password_changed",
            "user",
            Some(&user_id.to_string()),
            ctx,
            None,
        )
        .await;
        Ok("Password changed. Other sessions were signed out.".to_string())
    }

    /// Soft delete: the row is retained (audit trails reference it) but the
    /// account is deactivated, its sessions revoked, and its email released so
    /// the address can be registered again.
    pub async fn delete_account(
        state: &Arc<AppState>,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<String, AppError> {
        let mut tx = state.db.begin().await?;

        let affected = sqlx::query(
            r#"
            UPDATE users
            SET deleted_at = now(),
                email = 'deleted+' || id::text || '@invalid',
                name = 'Deleted user',
                image = NULL,
                updated_at = now()
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM accounts WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "user.deleted",
            "user",
            Some(&user_id.to_string()),
            ctx,
            None,
        )
        .await;
        Ok("Account deleted successfully".to_string())
    }
}
