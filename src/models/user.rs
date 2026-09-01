use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub role: String,
    pub banned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Columns selected for every `User` read. Kept in one place so a schema change
/// cannot leave one query behind.
pub const USER_COLUMNS: &str =
    "id, name, email, email_verified, image, role, banned, created_at, updated_at";

/// Flat projection for the session-resolution join. sqlx maps rows to a single
/// `FromRow` struct, so joined queries get a purpose-built row type rather than
/// a tuple of structs.
#[derive(Debug, Clone, FromRow)]
pub struct SessionUserRow {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub role: String,
    pub banned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub session_expires_at: DateTime<Utc>,
}

impl From<SessionUserRow> for User {
    fn from(r: SessionUserRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            email: r.email,
            email_verified: r.email_verified,
            image: r.image,
            role: r.role,
            banned: r.banned,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Flat projection for the sign-in join: the user plus their credential hash and
/// lockout state, fetched in one round trip.
#[derive(Debug, Clone, FromRow)]
pub struct CredentialRow {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub role: String,
    pub banned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password: Option<String>,
    pub locked_until: Option<DateTime<Utc>>,
}

impl From<CredentialRow> for User {
    fn from(r: CredentialRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            email: r.email,
            email_verified: r.email_verified,
            image: r.image,
            role: r.role,
            banned: r.banned,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// A persisted session. This is the revocation point: signing out, being banned,
/// or changing a password all resolve to marking rows here revoked.
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// What a recovery token is allowed to do. The absence of this distinction let an
/// email-verification token reset a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPurpose {
    EmailVerify,
    PasswordReset,
}

impl TokenPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenPurpose::EmailVerify => "email_verify",
            TokenPurpose::PasswordReset => "password_reset",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Account {
    pub id: Uuid,
    pub user_id: Uuid,
    pub account_id: String,
    pub provider_id: String,
    pub password: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Verification {
    pub id: Uuid,
    pub identifier: String,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SignUpEmailRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,
    #[validate(email(message = "Invalid email format"), length(max = 254))]
    pub email: String,
    #[validate(custom(function = "validate_password_strength"))]
    pub password: String,
    #[validate(url(message = "Image must be a valid URL"), length(max = 512))]
    pub image: Option<String>,
}

/// Length bounds plus a rejection list for the passwords that dominate every
/// credential-stuffing corpus. The upper bound matters too: Argon2 hashes
/// whatever it is handed, so an unbounded password is a CPU amplification vector.
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    const COMMON: &[&str] = &[
        "password",
        "password1",
        "password12",
        "password123",
        "passw0rd",
        "12345678",
        "123456789",
        "1234567890",
        "qwertyuiop",
        "qwerty123",
        "letmein1",
        "iloveyou",
        "welcome1",
        "admin123",
        "changeme",
        "football1",
        "sunshine1",
        "princess1",
        "baseball1",
        "trustno1",
        "superman1",
        "starwars1",
        "whatever1",
        "monkey12",
    ];

    if password.chars().count() < 10 {
        return Err(ValidationError::new("password_too_short")
            .with_message("Password must be at least 10 characters".into()));
    }
    if password.len() > 128 {
        return Err(ValidationError::new("password_too_long")
            .with_message("Password must be at most 128 bytes".into()));
    }
    let lowered = password.to_ascii_lowercase();
    if COMMON.contains(&lowered.as_str()) {
        return Err(ValidationError::new("password_too_common").with_message(
            "That password is among the most commonly breached; choose another".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SignInEmailRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ForgetPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(custom(function = "validate_password_strength"))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: Option<String>,
    #[validate(url(message = "Image must be a valid URL"), length(max = 512))]
    pub image: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(custom(function = "validate_password_strength"))]
    pub new_password: String,
}

/// Exchanges a refresh token for a new access token. The refresh token itself is
/// rotated on every use, so a stolen-and-replayed token is detectable.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    /// Opaque, rotated on every refresh, and revocable server-side.
    pub refresh_token: String,
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: i64,
    pub session_id: Uuid,
    pub user: UserResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            name: u.name,
            email: u.email,
            email_verified: u.email_verified,
            image: u.image,
            role: u.role,
            created_at: u.created_at,
        }
    }
}
