use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

// =========================================================================
// Org Roles & Enums
// =========================================================================

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Type, ToSchema,
)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Member = 1,
    Admin = 2,
    Owner = 3,
}

impl std::fmt::Display for OrgRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrgRole::Owner => write!(f, "owner"),
            OrgRole::Admin => write!(f, "admin"),
            OrgRole::Member => write!(f, "member"),
        }
    }
}

// =========================================================================
// App DTOs
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct App {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateAppRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,
    #[validate(
        length(min = 2, max = 50, message = "Slug must be between 2 and 50 characters"),
        regex(path = *crate::models::org::SLUG_REGEX, message = "Slug must be lowercase alphanumeric with hyphens (e.g. 'my-app-123')")
    )]
    pub slug: String,
    pub description: Option<String>,
}

// =========================================================================
// Organization DTOs
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Organization {
    pub id: Uuid,
    pub app_id: Uuid,
    pub name: String,
    pub slug: String,
    pub logo_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateOrgRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,
    #[validate(
        length(min = 2, max = 50, message = "Slug must be between 2 and 50 characters"),
        regex(path = *crate::models::org::SLUG_REGEX, message = "Slug must be lowercase alphanumeric with hyphens (e.g. 'my-org-123')")
    )]
    pub slug: String,
    pub logo_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct OrgMember {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AddOrgMemberRequest {
    pub user_id: Uuid,
    pub role: OrgRole,
}

use std::sync::LazyLock;
pub static SLUG_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());
