//! Webhook registration, event dispatch, and delivery service.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::webhook::{
        CreateWebhookRequest, CreateWebhookResponse, WebhookDeliveryRecord, WebhookRecord,
    },
    services::job_queue::JobQueueService,
};

type HmacSha256 = Hmac<Sha256>;

pub struct WebhookService;

impl WebhookService {
    /// Register a new webhook endpoint. Generates a secure random 32-character secret for HMAC signing.
    pub async fn create_webhook(
        pool: &PgPool,
        owner_id: Uuid,
        req: CreateWebhookRequest,
    ) -> Result<CreateWebhookResponse, AppError> {
        let id = Uuid::now_v7();
        let secret = format!("whsec_{}", crate::crypto::random_token(32));

        let record = sqlx::query_as!(
            WebhookRecord,
            r#"
            INSERT INTO webhooks (id, owner_id, org_id, target_url, secret, events, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            RETURNING id, owner_id, org_id, target_url, secret, events, is_active, created_at, updated_at
            "#,
            id,
            owner_id,
            req.org_id,
            req.target_url,
            secret,
            &req.events
        )
        .fetch_one(pool)
        .await?;

        Ok(CreateWebhookResponse {
            id: record.id,
            target_url: record.target_url,
            org_id: record.org_id,
            events: record.events,
            secret,
            created_at: record.created_at,
        })
    }

    /// List active webhooks owned by a user or organization.
    pub async fn list_webhooks(
        pool: &PgPool,
        owner_id: Uuid,
        org_id: Option<Uuid>,
    ) -> Result<Vec<WebhookRecord>, AppError> {
        let webhooks = match org_id {
            Some(org) => {
                sqlx::query_as!(
                    WebhookRecord,
                    r#"
                    SELECT id, owner_id, org_id, target_url, secret, events, is_active, created_at, updated_at
                    FROM webhooks
                    WHERE org_id = $1 AND is_active = true
                    ORDER BY created_at DESC
                    "#,
                    org
                )
                .fetch_all(pool)
                .await?
            }
            None => {
                sqlx::query_as!(
                    WebhookRecord,
                    r#"
                    SELECT id, owner_id, org_id, target_url, secret, events, is_active, created_at, updated_at
                    FROM webhooks
                    WHERE owner_id = $1 AND is_active = true
                    ORDER BY created_at DESC
                    "#,
                    owner_id
                )
                .fetch_all(pool)
                .await?
            }
        };

        Ok(webhooks)
    }

    /// Delete a webhook endpoint.
    pub async fn delete_webhook(
        pool: &PgPool,
        webhook_id: Uuid,
        owner_id: Uuid,
    ) -> Result<(), AppError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM webhooks
            WHERE id = $1 AND owner_id = $2
            "#,
            webhook_id,
            owner_id
        )
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Webhook not found".to_string()));
        }

        Ok(())
    }

    /// List delivery history for a webhook.
    pub async fn list_deliveries(
        pool: &PgPool,
        webhook_id: Uuid,
        owner_id: Uuid,
    ) -> Result<Vec<WebhookDeliveryRecord>, AppError> {
        // Verify owner owns this webhook
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM webhooks WHERE id = $1 AND owner_id = $2)",
            webhook_id,
            owner_id
        )
        .fetch_one(pool)
        .await?
        .unwrap_or(false);

        if !exists {
            return Err(AppError::NotFound("Webhook not found".to_string()));
        }

        let deliveries = sqlx::query_as!(
            WebhookDeliveryRecord,
            r#"
            SELECT id, webhook_id, event_type, payload, status, status_code, response_body, attempts, created_at, updated_at
            FROM webhook_deliveries
            WHERE webhook_id = $1
            ORDER BY created_at DESC
            LIMIT 50
            "#,
            webhook_id
        )
        .fetch_all(pool)
        .await?;

        Ok(deliveries)
    }

    /// Sign payload with HMAC-SHA256: `t={timestamp},v1={hex_digest}`.
    pub fn compute_signature(secret: &str, timestamp: i64, payload_json: &str) -> String {
        let signed_payload = format!("{}.{}", timestamp, payload_json);
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(signed_payload.as_bytes());
        let digest = mac.finalize().into_bytes();

        let mut hex_digest = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex_digest, "{byte:02x}");
        }

        format!("t={},v1={}", timestamp, hex_digest)
    }

    /// Dispatch an event to all matching webhook subscriptions via background job queue.
    pub async fn dispatch_event<T: serde::Serialize>(
        pool: &PgPool,
        event_type: &str,
        payload: &T,
        org_id: Option<Uuid>,
    ) -> Result<usize, AppError> {
        let payload_json = serde_json::to_value(payload).map_err(|e| {
            AppError::Internal(format!("Failed to serialize webhook payload: {}", e).into())
        })?;

        // Find matching active webhooks
        let matching_webhooks = sqlx::query_as!(
            WebhookRecord,
            r#"
            SELECT id, owner_id, org_id, target_url, secret, events, is_active, created_at, updated_at
            FROM webhooks
            WHERE is_active = true
              AND ($1::uuid IS NULL OR org_id IS NULL OR org_id = $1)
              AND ('*' = ANY(events) OR $2 = ANY(events))
            "#,
            org_id,
            event_type
        )
        .fetch_all(pool)
        .await?;

        let count = matching_webhooks.len();

        for wh in matching_webhooks {
            let delivery_id = Uuid::now_v7();

            // 1. Insert delivery log record (outbox)
            sqlx::query!(
                r#"
                INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status)
                VALUES ($1, $2, $3, $4, 'pending')
                "#,
                delivery_id,
                wh.id,
                event_type,
                payload_json
            )
            .execute(pool)
            .await?;

            // 2. Enqueue background job to deliver asynchronously
            let job_payload = serde_json::json!({
                "delivery_id": delivery_id,
                "webhook_id": wh.id,
                "target_url": wh.target_url,
                "secret": wh.secret,
                "event_type": event_type,
                "payload": payload_json,
            });

            JobQueueService::enqueue(
                pool,
                "webhook.deliver",
                &job_payload,
                Some("webhooks"),
                None,
                Some(5),
            )
            .await?;
        }

        Ok(count)
    }

    /// Execute a single delivery attempt via HTTP POST with HMAC signature.
    pub async fn execute_delivery(
        pool: &PgPool,
        http_client: &reqwest::Client,
        delivery_id: Uuid,
        target_url: &str,
        secret: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, AppError> {
        let payload_str = serde_json::to_string(payload).map_err(|e| {
            AppError::Internal(format!("Failed to stringify payload: {}", e).into())
        })?;

        let timestamp = Utc::now().timestamp();
        let signature = Self::compute_signature(secret, timestamp, &payload_str);

        let response_result = http_client
            .post(target_url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Event", event_type)
            .header("X-Webhook-Delivery", delivery_id.to_string())
            .header("X-Webhook-Signature", signature)
            .body(payload_str)
            .send()
            .await;

        match response_result {
            Ok(resp) => {
                let status_code = resp.status().as_u16() as i32;
                let body_snippet = resp.text().await.unwrap_or_default();
                let is_success = (200..300).contains(&status_code);

                let delivery_status = if is_success { "delivered" } else { "failed" };

                sqlx::query!(
                    r#"
                    UPDATE webhook_deliveries
                    SET status = $1,
                        status_code = $2,
                        response_body = $3,
                        attempts = attempts + 1,
                        updated_at = NOW()
                    WHERE id = $4
                    "#,
                    delivery_status,
                    status_code,
                    body_snippet.chars().take(1000).collect::<String>(),
                    delivery_id
                )
                .execute(pool)
                .await?;

                Ok(is_success)
            }
            Err(err) => {
                let err_msg = err.to_string();
                sqlx::query!(
                    r#"
                    UPDATE webhook_deliveries
                    SET status = 'failed',
                        response_body = $1,
                        attempts = attempts + 1,
                        updated_at = NOW()
                    WHERE id = $2
                    "#,
                    err_msg.chars().take(1000).collect::<String>(),
                    delivery_id
                )
                .execute(pool)
                .await?;

                Ok(false)
            }
        }
    }
}
