mod common;

use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use common::TestApp;

#[tokio::test]
async fn outsider_cannot_create_org_in_another_users_app() {
    let app = TestApp::spawn().await;

    // Register User 1 (App Owner) and User 2 (Outsider)
    let (user1_token, _, _) = app.register("owner@test.local").await;
    let (user2_token, _, _) = app.register("outsider@test.local").await;

    // User 1 creates App
    let create_app_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/apps")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user1_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({
                        "name": "User 1 App",
                        "slug": "user-1-app"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_app_res.status(), StatusCode::CREATED);
    let body = create_app_res
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let app_json: Value = serde_json::from_slice(&body).unwrap();
    let app_id = app_json["data"]["id"].as_str().unwrap();

    // User 2 attempts to create an Org in User 1's App -> Must be 404 Not Found (no leak)
    let hijack_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/{app_id}/orgs"))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user2_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({
                        "name": "Hijacked Org",
                        "slug": "hijacked-org"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(hijack_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn outsider_cannot_list_another_users_app_orgs() {
    let app = TestApp::spawn().await;

    let (user1_token, _, _) = app.register("appowner@test.local").await;
    let (user2_token, _, _) = app.register("snooper@test.local").await;

    // User 1 creates App
    let create_app_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/apps")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user1_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Private App", "slug": "private-app" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = create_app_res
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let app_json: Value = serde_json::from_slice(&body).unwrap();
    let app_id = app_json["data"]["id"].as_str().unwrap();

    // User 2 attempts to list User 1's orgs -> 404 Not Found
    let list_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/{app_id}/orgs"))
                .method("GET")
                .header(header::AUTHORIZATION, format!("Bearer {user2_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn outsider_cannot_add_members_to_an_org() {
    let app = TestApp::spawn().await;

    let (user1_token, _, _) = app.register("realowner@test.local").await;
    let (user2_token, _, _) = app.register("attacker@test.local").await;
    let (_, _, victim_id) = app.register("victim@test.local").await;

    // User 1 creates App & Org
    let app_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/apps")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user1_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Target App", "slug": "target-app" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = app_res.into_body().collect().await.unwrap().to_bytes();
    let app_id = serde_json::from_slice::<Value>(&body).unwrap()["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let org_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/{app_id}/orgs"))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user1_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Secure Org", "slug": "secure-org" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = org_res.into_body().collect().await.unwrap().to_bytes();
    let org_id = serde_json::from_slice::<Value>(&body).unwrap()["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // User 2 (not in org) attempts to add a member -> 404 Not Found
    let exploit_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/orgs/{org_id}/members"))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user2_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({
                        "user_id": victim_id,
                        "role": "owner"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(exploit_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_slug_and_role_are_rejected() {
    let app = TestApp::spawn().await;
    let (user_token, _, _) = app.register("slugtest@test.local").await;

    // Bad Slug (uppercase and spaces)
    let bad_slug_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/apps")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Bad App", "slug": "INVALID SLUG!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(bad_slug_res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Create valid app and org
    let app_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/apps")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Valid App", "slug": "valid-app" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = app_res.into_body().collect().await.unwrap().to_bytes();
    let app_id = serde_json::from_slice::<Value>(&body).unwrap()["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let org_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/{app_id}/orgs"))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({ "name": "Valid Org", "slug": "valid-org" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = org_res.into_body().collect().await.unwrap().to_bytes();
    let org_id = serde_json::from_slice::<Value>(&body).unwrap()["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Bad Role string ("supergod")
    let bad_role_res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/apps/orgs/{org_id}/members"))
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::from(
                    json!({
                        "user_id": uuid::Uuid::now_v7(),
                        "role": "supergod"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(bad_role_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
