//! Integration tests for Webhook subscription registration, HMAC signing, and delivery dispatch.

mod common;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use axum_template::services::{job_queue::JobQueueService, webhook::WebhookService};
use common::*;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn webhook_lifecycle_hmac_signature_and_delivery() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("webhooker")).await;

    // 1. Start a local mock receiver HTTP server
    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = received_count.clone();

    let receiver_app = Router::new().route(
        "/mock-webhook",
        post(move |headers: HeaderMap, _body: Bytes| {
            let count = count_clone.clone();
            async move {
                let sig = headers
                    .get("X-Webhook-Signature")
                    .unwrap()
                    .to_str()
                    .unwrap();
                let event = headers.get("X-Webhook-Event").unwrap().to_str().unwrap();
                assert_eq!(event, "order.created");
                assert!(sig.starts_with("t="));
                assert!(sig.contains(",v1="));
                count.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, receiver_app).await.unwrap();
    });

    let target_url = format!("http://127.0.0.1:{}/mock-webhook", port);

    // 2. Register Webhook via API
    let create_payload = json!({
        "target_url": target_url,
        "events": ["order.created", "user.banned"]
    });

    let (status, resp) = app
        .post_as("/api/v1/webhooks", create_payload, &token)
        .await;

    assert_eq!(status, StatusCode::CREATED);
    let webhook_id = resp["data"]["id"].as_str().unwrap();
    let secret = resp["data"]["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("whsec_"));

    // 3. Dispatch an event
    let event_payload = json!({ "order_id": 12345, "total": 99.50 });
    let dispatched =
        WebhookService::dispatch_event(&app.state.db, "order.created", &event_payload, None)
            .await
            .expect("Dispatch failed");

    assert_eq!(dispatched, 1);

    // 4. Poll job from background queue & execute delivery
    let job = JobQueueService::poll_next_job(&app.state.db, "webhooks", "test-worker")
        .await
        .unwrap()
        .expect("Webhook delivery job must be queued");

    let delivery_id = uuid::Uuid::parse_str(job.payload["delivery_id"].as_str().unwrap()).unwrap();
    let http_client = reqwest::Client::new();

    let ok = WebhookService::execute_delivery(
        &app.state.db,
        &http_client,
        delivery_id,
        job.payload["target_url"].as_str().unwrap(),
        job.payload["secret"].as_str().unwrap(),
        job.payload["event_type"].as_str().unwrap(),
        &job.payload["payload"],
    )
    .await
    .unwrap();

    assert!(ok, "Delivery execution should succeed with 200 OK");
    assert_eq!(received_count.load(Ordering::SeqCst), 1);

    // 5. Inspect deliveries endpoint via API
    let (list_status, deliveries_resp) = app
        .get_as(
            &format!("/api/v1/webhooks/{}/deliveries", webhook_id),
            &token,
        )
        .await;

    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(deliveries_resp["data"][0]["status"], "delivered");
    assert_eq!(deliveries_resp["data"][0]["status_code"], 200);

    // 6. Delete webhook
    let delete_req = json_request(
        "DELETE",
        &format!("/api/v1/webhooks/{}", webhook_id),
        serde_json::Value::Null,
        Some(&token),
        None,
    );
    let (del_status, _) = app.request(delete_req).await;
    assert_eq!(del_status, StatusCode::OK);
}
