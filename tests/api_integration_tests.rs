use std::sync::Arc;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use http_body_util::BodyExt;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::Value;
use tower::ServiceExt;

use axum_template::{
    config::AppConfig,
    create_app,
    state::AppState,
};

// Helper to create test app state
async fn setup_test_app() -> (axum::Router, Arc<AppState>) {
    dotenvy::dotenv().ok();

    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .unwrap_or_else(|_| {
            PrometheusBuilder::new()
                .build_recorder()
                .handle()
        });

    let config = AppConfig {
        server_host: "127.0.0.1".to_string(),
        server_port: 3000,
        database_url: std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgrespassword@localhost:5432/axum_template_db".to_string()),
        database_max_connections: 5,
        jwt_secret: "super-secret-test-jwt-key-that-is-at-least-32-chars-long".to_string(),
        jwt_expiration_hours: 1,
        upload_dir: "target/test_uploads".to_string(),
        smtp_host: None,
        smtp_port: None,
        smtp_from: None,
        google_client_id: None,
        google_client_secret: None,
        google_redirect_url: None,
        github_client_id: None,
        github_client_secret: None,
        github_redirect_url: None,
    };

    let pool = sqlx::PgPool::connect_lazy(&config.database_url)
        .expect("Failed to build lazy connection pool");

    let app_state = Arc::new(AppState::new(pool, config, prometheus_handle));
    (create_app(app_state.clone()), app_state)
}

#[tokio::test]
async fn test_health_check_endpoint() {
    let (app, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .method("GET")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("status").is_some());
    assert!(json.get("database").is_some());
}

#[tokio::test]
async fn test_prometheus_metrics_endpoint() {
    let (app, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .method("GET")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_security_headers_injected() {
    let (app, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .method("GET")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let headers = response.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.get("strict-transport-security").is_some());
    assert!(headers.get("x-request-id").is_some());
}

#[tokio::test]
async fn test_validation_error_envelope() {
    let (app, _) = setup_test_app().await;

    let invalid_payload = serde_json::json!({
        "name": "A",
        "email": "invalid-email",
        "password": "short"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/sign-up/email")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::from(serde_json::to_vec(&invalid_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], false);
    assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
    assert!(json["error"]["message"].is_string());
}

#[tokio::test]
async fn test_file_path_traversal_protection() {
    let (app, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/files/..%2F..%2Fetc%2Fpasswd")
                .method("GET")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_presigned_url_generation() {
    let (app, state) = setup_test_app().await;

    let mock_user = axum_template::models::user::User {
        id: uuid::Uuid::now_v7(),
        name: "Test User".to_string(),
        email: "user@test.local".to_string(),
        email_verified: true,
        image: None,
        role: "user".to_string(),
        banned: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let token = axum_template::services::auth::AuthService::generate_jwt(
        &mock_user,
        &state.config,
    )
    .unwrap();

    let payload = serde_json::json!({
        "filename": "avatar.png",
        "content_type": "image/png",
        "size_bytes": 1024
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/files/presigned-url")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert!(json["data"]["upload_url"].is_string());
    assert!(json["data"]["file_url"].is_string());
}

#[tokio::test]
async fn test_rbac_admin_guard_rejection_for_normal_user() {
    let (app, state) = setup_test_app().await;

    let normal_user = axum_template::models::user::User {
        id: uuid::Uuid::now_v7(),
        name: "Normal User".to_string(),
        email: "normaluser@test.local".to_string(),
        email_verified: true,
        image: None,
        role: "user".to_string(),
        banned: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let user_token = axum_template::services::auth::AuthService::generate_jwt(
        &normal_user,
        &state.config,
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit-logs")
                .method("GET")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Normal user must be strictly 403 Forbidden on admin audit logs
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], false);
    assert_eq!(json["error"]["code"], "FORBIDDEN");
}

#[tokio::test]
async fn test_unauthorized_missing_jwt_rejection() {
    let (app, _) = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/users/me")
                .method("GET")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
