//! Data models for Webhook subscriptions and delivery records.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Webhook endpoint subscription row.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct WebhookRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub org_id: Option<Uuid>,
    pub target_url: String,
    #[serde(skip_serializing)]
    pub secret: String,
    pub events: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Webhook registration request DTO.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateWebhookRequest {
    #[validate(url(message = "target_url must be a valid HTTP/HTTPS URL"))]
    pub target_url: String,
    pub org_id: Option<Uuid>,
    #[validate(length(min = 1, message = "At least one event topic is required"))]
    pub events: Vec<String>,
}

/// Response returned when a webhook is created (includes secret ONCE).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateWebhookResponse {
    pub id: Uuid,
    pub target_url: String,
    pub org_id: Option<Uuid>,
    pub events: Vec<String>,
    /// Plaintext HMAC signing secret. Presented once upon creation.
    pub secret: String,
    pub created_at: DateTime<Utc>,
}

/// Webhook delivery log record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct WebhookDeliveryRecord {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
