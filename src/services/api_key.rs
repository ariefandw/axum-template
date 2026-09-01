use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    crypto::{random_token, sha256_hex},
    error::AppError,
    models::{
        api_key::{ApiKeyRecord, CreateApiKeyRequest, CreateApiKeyResponse, ScopeSet},
        pagination::PageParams,
        user::User,
    },
    services::{audit::AuditService, auth::RequestContext},
    state::AppState,
};

pub struct ApiKeyService;

impl ApiKeyService {
    /// Generate an M2M API Key following Better Auth conventions (`ak_live_<random_secret>`).
    pub async fn create_key(
        state: &Arc<AppState>,
        user_id: Uuid,
        req: CreateApiKeyRequest,
        ctx: &RequestContext,
    ) -> Result<CreateApiKeyResponse, AppError> {
        let key_id = Uuid::now_v7();
        let random_part = random_token(48);
        let plaintext_key = format!("ak_live_{random_part}");
        let key_start = format!("ak_live_{}...", &random_part[..6]);
        let key_hash = sha256_hex(&plaintext_key);

        // Rejects unknown scope names rather than dropping them, so a key never
        // ends up with quietly different authority than the caller requested.
        let scope_set = ScopeSet::parse_request(req.scopes.as_deref())?;
        let scopes = scope_set.to_strings();
        let scopes_json = serde_json::json!(&scopes);

        let expires_at = req
            .expires_in_days
            .map(|days| Utc::now() + Duration::days(days));

        let record = sqlx::query_as::<_, ApiKeyRecord>(
            r#"
            INSERT INTO api_keys (id, user_id, org_id, name, key_start, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, user_id, org_id, name, key_start, scopes, expires_at, last_used_at, created_at, updated_at
            "#,
        )
        .bind(key_id)
        .bind(user_id)
        .bind(req.org_id)
        .bind(&req.name)
        .bind(&key_start)
        .bind(&key_hash)
        .bind(scopes_json)
        .bind(expires_at)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("create_key database error: {e:?}");
            AppError::from(e)
        })?;

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "api_key.create",
            "api_keys",
            Some(&record.id.to_string()),
            ctx,
            Some(serde_json::json!({ "name": record.name, "key_start": record.key_start, "org_id": req.org_id })),
        ).await;

        Ok(CreateApiKeyResponse {
            id: record.id,
            name: record.name,
            key: plaintext_key,
            key_start: record.key_start,
            scopes,
            expires_at: record.expires_at,
            created_at: record.created_at,
        })
    }

    pub async fn list_keys(
        state: &Arc<AppState>,
        user_id: Uuid,
        params: PageParams,
    ) -> Result<(Vec<ApiKeyRecord>, u64), AppError> {
        let limit = params.limit() as i64;
        let offset = params.offset() as i64;

        let keys = sqlx::query_as::<_, ApiKeyRecord>(
            "SELECT id, user_id, org_id, name, key_start, scopes, expires_at, last_used_at, created_at, updated_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        let total_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&state.db)
                .await? as u64;

        Ok((keys, total_count))
    }

    pub async fn delete_key(
        state: &Arc<AppState>,
        key_id: Uuid,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let rows_affected = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND user_id = $2")
            .bind(key_id)
            .bind(user_id)
            .execute(&state.db)
            .await?
            .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound(format!("API Key '{key_id}' not found")));
        }

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "api_key.delete",
            "api_keys",
            Some(&key_id.to_string()),
            ctx,
            None,
        )
        .await;

        Ok(())
    }

    /// Resolve an API Key secret string against the database.
    /// Updates `last_used_at` asynchronously and returns the associated `User`.
    pub async fn resolve_key(
        state: &Arc<AppState>,
        raw_key: &str,
    ) -> Result<(User, ApiKeyRecord), AppError> {
        let key_hash = sha256_hex(raw_key);

        let key_record = sqlx::query_as::<_, ApiKeyRecord>(
            r#"
            SELECT id, user_id, org_id, name, key_start, scopes, expires_at, last_used_at, created_at, updated_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(&key_hash)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

        // Verify expiration
        if let Some(expires_at) = key_record.expires_at {
            if expires_at < Utc::now() {
                return Err(AppError::Unauthorized("API key has expired".to_string()));
            }
        }

        // Fetch User and verify not banned / deleted
        let user = sqlx::query_as::<_, User>(
            "SELECT id, name, email, email_verified, image, role, banned, created_at, updated_at FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(key_record.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User associated with this API key not found or deleted".to_string()))?;

        if user.banned {
            return Err(AppError::Forbidden("User account is banned".to_string()));
        }

        // Record last use, but at most once a minute per key. Writing on every
        // request turns a read-only API call into a write and makes this row a
        // contention point for any key under real traffic; minute granularity is
        // all a "last used" display needs.
        let needs_touch = key_record
            .last_used_at
            .is_none_or(|last| Utc::now() - last > Duration::minutes(1));

        if needs_touch {
            let db = state.db.clone();
            let kid = key_record.id;
            tokio::spawn(async move {
                let _ = sqlx::query(
                    "UPDATE api_keys SET last_used_at = now() \
                     WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
                )
                .bind(kid)
                .execute(&db)
                .await;
            });
        }

        Ok((user, key_record))
    }
}
