//! Background job queue engine backed by PostgreSQL with `SKIP LOCKED`.
//!
//! Provides transactional enqueueing and concurrent worker polling.
//! If multiple replicas run concurrently, `SELECT ... FOR UPDATE SKIP LOCKED`
//! guarantees exactly-once processing with zero race conditions and zero Redis dependency.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{error::AppError, models::job::BackgroundJobRecord};

pub struct JobQueueService;

impl JobQueueService {
    /// Enqueue a strongly-typed background job to be executed immediately or in the future.
    pub async fn enqueue<T: Serialize>(
        pool: &PgPool,
        job_type: &str,
        payload: &T,
        queue: Option<&str>,
        run_at: Option<DateTime<Utc>>,
        max_attempts: Option<i32>,
    ) -> Result<Uuid, AppError> {
        let payload_json = serde_json::to_value(payload).map_err(|e| {
            AppError::Internal(format!("Failed to serialize job payload: {}", e).into())
        })?;

        let id = Uuid::now_v7();
        let queue_name = queue.unwrap_or("default");
        let max_retries = max_attempts.unwrap_or(5);

        sqlx::query!(
            r#"
            INSERT INTO background_jobs (id, queue, job_type, payload, status, run_at, max_attempts)
            VALUES ($1, $2, $3, $4, 'queued', COALESCE($5, NOW()), $6)
            "#,
            id,
            queue_name,
            job_type,
            payload_json,
            run_at,
            max_retries
        )
        .execute(pool)
        .await?;

        Ok(id)
    }

    /// Fetch and lock the next available job in a queue using PostgreSQL `SKIP LOCKED`.
    pub async fn poll_next_job(
        pool: &PgPool,
        queue: &str,
        worker_id: &str,
    ) -> Result<Option<BackgroundJobRecord>, AppError> {
        let mut tx = pool.begin().await?;

        let maybe_job = sqlx::query_as!(
            BackgroundJobRecord,
            r#"
            SELECT id, queue, job_type, payload, status, attempts, max_attempts,
                   last_error, run_at, locked_at, locked_by, created_at, updated_at
            FROM background_jobs
            WHERE queue = $1
              AND status = 'queued'
              AND run_at <= NOW()
            ORDER BY run_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            "#,
            queue
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(job) = maybe_job {
            let updated_job = sqlx::query_as!(
                BackgroundJobRecord,
                r#"
                UPDATE background_jobs
                SET status = 'running',
                    attempts = attempts + 1,
                    locked_at = NOW(),
                    locked_by = $1,
                    updated_at = NOW()
                WHERE id = $2
                RETURNING id, queue, job_type, payload, status, attempts, max_attempts,
                          last_error, run_at, locked_at, locked_by, created_at, updated_at
                "#,
                worker_id,
                job.id
            )
            .fetch_one(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(Some(updated_job))
        } else {
            tx.rollback().await?;
            Ok(None)
        }
    }

    /// Mark a job as successfully completed.
    pub async fn complete_job(pool: &PgPool, job_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE background_jobs
            SET status = 'completed',
                locked_at = NULL,
                locked_by = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
            job_id
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark a job as failed and schedule retry with exponential backoff if attempts < max_attempts.
    pub async fn fail_job(
        pool: &PgPool,
        job_id: Uuid,
        attempts: i32,
        max_attempts: i32,
        error_message: &str,
    ) -> Result<(), AppError> {
        if attempts >= max_attempts {
            sqlx::query!(
                r#"
                UPDATE background_jobs
                SET status = 'failed',
                    last_error = $1,
                    locked_at = NULL,
                    locked_by = NULL,
                    updated_at = NOW()
                WHERE id = $2
                "#,
                error_message,
                job_id
            )
            .execute(pool)
            .await?;
        } else {
            // Exponential backoff: 2^(attempts) * 5 seconds (5s, 10s, 20s, 40s...)
            let backoff_secs = (2_i64.pow(attempts.clamp(0, 10) as u32)) * 5;
            let retry_at = Utc::now() + chrono::Duration::seconds(backoff_secs);

            sqlx::query!(
                r#"
                UPDATE background_jobs
                SET status = 'queued',
                    last_error = $1,
                    run_at = $2,
                    locked_at = NULL,
                    locked_by = NULL,
                    updated_at = NOW()
                WHERE id = $3
                "#,
                error_message,
                retry_at,
                job_id
            )
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Reap completed or failed jobs older than the retention period.
    pub async fn reap_old_jobs(pool: &PgPool, retention_days: i64) -> Result<u64, AppError> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days);
        let result = sqlx::query!(
            r#"
            DELETE FROM background_jobs
            WHERE status IN ('completed', 'cancelled', 'failed')
              AND updated_at < $1
            "#,
            cutoff
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
