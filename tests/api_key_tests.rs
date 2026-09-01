mod common;

use axum::http::{Request, StatusCode, header};
use serde_json::json;

use common::TestApp;

#[tokio::test]
async fn api_key_lifecycle_and_m2m_authentication() {
    let app = TestApp::spawn().await;

    // 1. Register a user with a unique email
    let email = format!("apikey_{}@test.local", uuid::Uuid::now_v7());
    let (user_token, _, _) = app.register(&email).await;

    // 2. Create an API key
    let (status, create_json) = app
        .post_as(
            "/api/v1/auth/api-key/create",
            json!({
                "name": "Integration Worker Key",
                "expires_in_days": 30
            }),
            &user_token,
        )
        .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "create api key failed: {create_json}"
    );
    let api_key = create_json["data"]["key"].as_str().unwrap().to_string();
    let key_id = create_json["data"]["id"].as_str().unwrap().to_string();
    assert!(api_key.starts_with("ak_live_"));

    // 3. Use x-api-key header to access protected /api/v1/users/me (M2M Auth)
    let (me_status, me_json) = app
        .request(
            Request::builder()
                .uri("/api/v1/users/me")
                .method("GET")
                .header("x-api-key", &api_key)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(
        me_status,
        StatusCode::OK,
        "me call with x-api-key failed: {me_json}"
    );
    assert_eq!(me_json["data"]["email"], email);

    // 4. List API keys
    let (list_status, list_json) = app.get_as("/api/v1/auth/api-key/list", &user_token).await;

    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list_json["data"].as_array().unwrap().len(), 1);

    // 5. Revoke (Delete) API Key
    let (del_status, del_json) = app
        .request(
            Request::builder()
                .uri(format!("/api/v1/auth/api-key/{key_id}"))
                .method("DELETE")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(
        del_status,
        StatusCode::OK,
        "delete api key failed: {del_json}"
    );

    // 6. Verify revoked API key is rejected with 401 Unauthorized
    let (rejected_status, _) = app
        .request(
            Request::builder()
                .uri("/api/v1/users/me")
                .method("GET")
                .header("x-api-key", &api_key)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(rejected_status, StatusCode::UNAUTHORIZED);
}
