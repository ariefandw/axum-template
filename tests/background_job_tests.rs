//! Integration tests for the PostgreSQL SKIP LOCKED background job queue.

mod common;

use axum_template::services::job_queue::JobQueueService;
use common::*;
use serde_json::json;

#[tokio::test]
async fn job_queue_enqueue_and_poll_with_skip_locked() {
    let app = TestApp::spawn().await;

    let payload = json!({
        "to": "user@example.com",
        "subject": "Welcome to the platform",
        "body": "Your account is ready."
    });

    let queue_name = format!("mailer-{}", uuid::Uuid::now_v7().simple());

    // 1. Enqueue job
    let job_id = JobQueueService::enqueue(
        &app.state.db,
        "email.send",
        &payload,
        Some(&queue_name),
        None,
        Some(3),
    )
    .await
    .expect("Failed to enqueue job");

    // 2. Poll and lock job by Worker A
    let worker_a = "worker-node-1";
    let polled = JobQueueService::poll_next_job(&app.state.db, &queue_name, worker_a)
        .await
        .expect("Polling failed")
        .expect("Job should be available");

    assert_eq!(polled.id, job_id);
    assert_eq!(polled.job_type, "email.send");
    assert_eq!(polled.attempts, 1);
    assert_eq!(polled.locked_by.as_deref(), Some(worker_a));

    // 3. Worker B tries to poll while Worker A has it locked -> returns None (SKIP LOCKED)
    let worker_b = "worker-node-2";
    let concurrent_poll = JobQueueService::poll_next_job(&app.state.db, &queue_name, worker_b)
        .await
        .expect("Concurrent polling failed");
    assert!(
        concurrent_poll.is_none(),
        "Concurrent worker must skip locked row"
    );

    // 4. Complete job
    JobQueueService::complete_job(&app.state.db, job_id)
        .await
        .expect("Failed to complete job");

    // 5. Subsequent poll returns None because job is completed
    let after_complete = JobQueueService::poll_next_job(&app.state.db, &queue_name, worker_a)
        .await
        .expect("Polling failed");
    assert!(after_complete.is_none());
}

#[tokio::test]
async fn job_queue_exponential_backoff_and_retry() {
    let app = TestApp::spawn().await;

    let payload = json!({ "event": "webhook.dispatch" });

    let queue_name = format!("webhooks-{}", uuid::Uuid::now_v7().simple());

    let job_id = JobQueueService::enqueue(
        &app.state.db,
        "webhook.retry",
        &payload,
        Some(&queue_name),
        None,
        Some(2),
    )
    .await
    .unwrap();

    // Poll attempt 1
    let job = JobQueueService::poll_next_job(&app.state.db, &queue_name, "w1")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(job.attempts, 1);

    // Fail attempt 1 (attempts = 1 < max_attempts = 2) -> sets status back to 'queued' with future run_at
    JobQueueService::fail_job(
        &app.state.db,
        job_id,
        1,
        2,
        "Remote 503 Service Unavailable",
    )
    .await
    .unwrap();

    // Re-check row state
    let row = sqlx::query!(
        "SELECT status, attempts, last_error FROM background_jobs WHERE id = $1",
        job_id
    )
    .fetch_one(&app.state.db)
    .await
    .unwrap();

    assert_eq!(row.status, "queued");
    assert_eq!(
        row.last_error.as_deref(),
        Some("Remote 503 Service Unavailable")
    );

    // Fail attempt 2 (attempts = 2 >= max_attempts = 2) -> permanently sets status to 'failed'
    JobQueueService::fail_job(&app.state.db, job_id, 2, 2, "Max retries reached")
        .await
        .unwrap();

    let dead_row = sqlx::query!(
        "SELECT status, last_error FROM background_jobs WHERE id = $1",
        job_id
    )
    .fetch_one(&app.state.db)
    .await
    .unwrap();

    assert_eq!(dead_row.status, "failed");
    assert_eq!(dead_row.last_error.as_deref(), Some("Max retries reached"));
}
