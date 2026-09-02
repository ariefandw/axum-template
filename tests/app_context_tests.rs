//! Integration tests for multi-app tenancy and X-Application-ID guard.

mod common;

use axum::http::StatusCode;
use common::*;

#[tokio::test]
async fn app_context_guard_enforces_membership_and_rejects_outsiders() {
    let app = TestApp::spawn().await;

    // 1. User A creates an application
    let (token_a, _, _) = app.register(&unique_email("appowner")).await;
    let (app_id, _) = app.create_app_and_org(&token_a).await;

    // 2. User B (unrelated outsider)
    let (token_b, _, _) = app.register(&unique_email("outsider")).await;

    // 3. User A queries with X-Application-ID header -> 200 OK
    let req_a = axum::http::Request::builder()
        .uri(format!("/api/v1/apps/{}", app_id))
        .method("GET")
        .header("Authorization", format!("Bearer {}", token_a))
        .header("X-Application-ID", &app_id)
        .body(axum::body::Body::empty())
        .unwrap();

    let (status_a, body_a) = app.request(req_a).await;
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(body_a["data"]["id"].as_str().unwrap(), app_id);

    // 4. User B queries with User A's app_id -> 403 Forbidden
    let req_b = axum::http::Request::builder()
        .uri(format!("/api/v1/apps/{}", app_id))
        .method("GET")
        .header("Authorization", format!("Bearer {}", token_b))
        .header("X-Application-ID", &app_id)
        .body(axum::body::Body::empty())
        .unwrap();

    let (status_b, _) = app.request(req_b).await;
    assert_eq!(status_b, StatusCode::FORBIDDEN);

    // 5. Query without X-Application-ID header -> 400 Bad Request
    let req_no_header = axum::http::Request::builder()
        .uri(format!("/api/v1/apps/{}", app_id))
        .method("GET")
        .header("Authorization", format!("Bearer {}", token_a))
        .body(axum::body::Body::empty())
        .unwrap();

    let (status_no_header, _) = app.request(req_no_header).await;
    assert_eq!(status_no_header, StatusCode::BAD_REQUEST);
}
