use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::error::AppError;

// =========================================================================
// Scopes
// =========================================================================

/// What an API key is permitted to do.
///
/// Scopes were previously stored and returned but never consulted, so a key
/// declaring `["read:profile"]` could still rename its owner, mint further keys,
/// change the account password, and delete the account. A machine credential
/// must be narrower than the human account it belongs to, or a leaked CI token
/// is a full account compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiScope {
    #[serde(rename = "files:read")]
    FilesRead,
    #[serde(rename = "files:write")]
    FilesWrite,
    #[serde(rename = "notifications:read")]
    NotificationsRead,
    #[serde(rename = "notifications:write")]
    NotificationsWrite,
    #[serde(rename = "apps:read")]
    AppsRead,
    #[serde(rename = "apps:write")]
    AppsWrite,
    #[serde(rename = "orgs:read")]
    OrgsRead,
    #[serde(rename = "orgs:write")]
    OrgsWrite,
    #[serde(rename = "users:read")]
    UsersRead,
    #[serde(rename = "users:write")]
    UsersWrite,
    #[serde(rename = "audit:read")]
    AuditRead,
    /// Required, in addition to the account's own `admin` role, before a key may
    /// reach an administrative route. Holding the role is not enough: the key
    /// must say it is for administration.
    #[serde(rename = "admin")]
    Admin,
}

impl ApiScope {
    pub fn as_str(self) -> &'static str {
        match self {
            ApiScope::FilesRead => "files:read",
            ApiScope::FilesWrite => "files:write",
            ApiScope::NotificationsRead => "notifications:read",
            ApiScope::NotificationsWrite => "notifications:write",
            ApiScope::AppsRead => "apps:read",
            ApiScope::AppsWrite => "apps:write",
            ApiScope::OrgsRead => "orgs:read",
            ApiScope::OrgsWrite => "orgs:write",
            ApiScope::UsersRead => "users:read",
            ApiScope::UsersWrite => "users:write",
            ApiScope::AuditRead => "audit:read",
            ApiScope::Admin => "admin",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let scope = match raw.trim() {
            "files:read" => ApiScope::FilesRead,
            "files:write" => ApiScope::FilesWrite,
            "notifications:read" => ApiScope::NotificationsRead,
            "notifications:write" => ApiScope::NotificationsWrite,
            "apps:read" => ApiScope::AppsRead,
            "apps:write" => ApiScope::AppsWrite,
            "orgs:read" => ApiScope::OrgsRead,
            "orgs:write" => ApiScope::OrgsWrite,
            "users:read" => ApiScope::UsersRead,
            "users:write" => ApiScope::UsersWrite,
            "audit:read" => ApiScope::AuditRead,
            "admin" => ApiScope::Admin,
            other => {
                return Err(AppError::ValidationError(format!(
                    "Unknown scope '{other}'. Valid scopes: {}",
                    Self::all()
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };
        Ok(scope)
    }

    pub fn all() -> &'static [ApiScope] {
        &[
            ApiScope::FilesRead,
            ApiScope::FilesWrite,
            ApiScope::NotificationsRead,
            ApiScope::NotificationsWrite,
            ApiScope::AppsRead,
            ApiScope::AppsWrite,
            ApiScope::OrgsRead,
            ApiScope::OrgsWrite,
            ApiScope::UsersRead,
            ApiScope::UsersWrite,
            ApiScope::AuditRead,
            ApiScope::Admin,
        ]
    }

    /// `*` deliberately does NOT include `admin`: a wildcard key is a
    /// convenience for ordinary automation, and reaching administrative routes
    /// should always be a decision someone made explicitly.
    pub fn wildcard_set() -> BTreeSet<ApiScope> {
        Self::all()
            .iter()
            .copied()
            .filter(|s| *s != ApiScope::Admin)
            .collect()
    }
}

/// The scope set carried by a key, parsed from its stored JSONB array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet(BTreeSet<ApiScope>);

impl ScopeSet {
    pub fn new(scopes: BTreeSet<ApiScope>) -> Self {
        Self(scopes)
    }

    pub fn wildcard() -> Self {
        Self(ApiScope::wildcard_set())
    }

    pub fn contains(&self, scope: ApiScope) -> bool {
        self.0.contains(&scope)
    }

    pub fn to_strings(&self) -> Vec<String> {
        self.0.iter().map(|s| s.as_str().to_string()).collect()
    }

    /// Parse the requested scope list, rejecting unknown entries rather than
    /// silently dropping them — a typo in a scope name must not quietly widen
    /// or narrow a key.
    pub fn parse_request(raw: Option<&[String]>) -> Result<Self, AppError> {
        let Some(raw) = raw else {
            return Ok(Self::wildcard());
        };
        if raw.is_empty() {
            return Ok(Self::wildcard());
        }
        if raw.iter().any(|s| s.trim() == "*") {
            return Ok(Self::wildcard());
        }
        let mut set = BTreeSet::new();
        for entry in raw {
            set.insert(ApiScope::parse(entry)?);
        }
        Ok(Self(set))
    }

    /// Parse a stored JSONB value back into a scope set. Unknown or malformed
    /// stored values resolve to an EMPTY set, never a wildcard: a key whose
    /// scopes cannot be understood must lose access, not gain it.
    pub fn from_stored(value: Option<&serde_json::Value>) -> Self {
        let Some(array) = value.and_then(|v| v.as_array()) else {
            return Self(BTreeSet::new());
        };
        if array.iter().any(|v| v.as_str() == Some("*")) {
            return Self::wildcard();
        }
        Self(
            array
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| ApiScope::parse(s).ok())
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub org_id: Option<Uuid>,
    pub name: String,
    pub key_start: String,
    pub scopes: Option<serde_json::Value>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateApiKeyRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,
    pub org_id: Option<Uuid>,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key: String, // Plaintext secret returned ONCE on creation
    pub key_start: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_excludes_admin() {
        let wildcard = ScopeSet::wildcard();
        assert!(wildcard.contains(ApiScope::FilesWrite));
        assert!(
            !wildcard.contains(ApiScope::Admin),
            "a '*' key must not silently reach administrative routes"
        );
    }

    #[test]
    fn unknown_scopes_are_rejected_at_creation() {
        let err = ScopeSet::parse_request(Some(&["files:raed".to_string()])).unwrap_err();
        assert!(matches!(err, AppError::ValidationError(_)));
        // A typo must not be silently dropped, which would produce a key with
        // quietly different authority than the caller asked for.
        assert!(ScopeSet::parse_request(Some(&["files:read".to_string()])).is_ok());
    }

    #[test]
    fn stored_scopes_fail_closed() {
        // Malformed or unreadable stored scopes yield no authority at all.
        assert_eq!(
            ScopeSet::from_stored(None),
            ScopeSet::new(Default::default())
        );
        assert_eq!(
            ScopeSet::from_stored(Some(&serde_json::json!("not-an-array"))),
            ScopeSet::new(Default::default())
        );
        assert_eq!(
            ScopeSet::from_stored(Some(&serde_json::json!(["files:read", "bogus"]))).to_strings(),
            vec!["files:read"]
        );
        assert!(
            ScopeSet::from_stored(Some(&serde_json::json!(["*"]))).contains(ApiScope::FilesRead)
        );
    }

    #[test]
    fn round_trips_through_storage() {
        let requested = ScopeSet::parse_request(Some(&[
            "files:read".to_string(),
            "notifications:write".to_string(),
        ]))
        .unwrap();
        let stored = serde_json::json!(requested.to_strings());
        assert_eq!(ScopeSet::from_stored(Some(&stored)), requested);
    }
}
