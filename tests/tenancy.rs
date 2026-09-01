mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::TestApp;

#[tokio::test]
async fn outsider_cannot_create_org_in_another_users_app() {
    let app = TestApp::spawn().await;

    let email1 = format!("owner_{}@test.local", uuid::Uuid::now_v7());
    let email2 = format!("outsider_{}@test.local", uuid::Uuid::now_v7());

    let (user1_token, _, _) = app.register(&email1).await;
    let (user2_token, _, _) = app.register(&email2).await;

    // User 1 creates App
    let (create_status, app_json) = app
        .post_as(
            "/api/v1/apps",
            json!({
                "name": "User 1 App",
                "slug": format!("user-app-{}", uuid::Uuid::now_v7().simple())
            }),
            &user1_token,
        )
        .await;

    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "app creation failed: {app_json}"
    );
    let app_id = app_json["data"]["id"].as_str().unwrap();

    // User 2 attempts to create an Org in User 1's App -> Must be 404 Not Found (no leak)
    let (hijack_status, _) = app
        .post_as(
            &format!("/api/v1/apps/{app_id}/orgs"),
            json!({
                "name": "Hijacked Org",
                "slug": "hijacked-org"
            }),
            &user2_token,
        )
        .await;

    assert_eq!(hijack_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn outsider_cannot_list_another_users_app_orgs() {
    let app = TestApp::spawn().await;

    let email1 = format!("appowner_{}@test.local", uuid::Uuid::now_v7());
    let email2 = format!("snooper_{}@test.local", uuid::Uuid::now_v7());

    let (user1_token, _, _) = app.register(&email1).await;
    let (user2_token, _, _) = app.register(&email2).await;

    // User 1 creates App
    let (status, app_json) = app
        .post_as(
            "/api/v1/apps",
            json!({ "name": "Private App", "slug": format!("private-app-{}", uuid::Uuid::now_v7().simple()) }),
            &user1_token,
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);
    let app_id = app_json["data"]["id"].as_str().unwrap();

    // User 2 attempts to list User 1's orgs -> 404 Not Found
    let (list_status, _) = app
        .get_as(&format!("/api/v1/apps/{app_id}/orgs"), &user2_token)
        .await;

    assert_eq!(list_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn outsider_cannot_add_members_to_an_org() {
    let app = TestApp::spawn().await;

    let email1 = format!("realowner_{}@test.local", uuid::Uuid::now_v7());
    let email2 = format!("attacker_{}@test.local", uuid::Uuid::now_v7());
    let email3 = format!("victim_{}@test.local", uuid::Uuid::now_v7());

    let (user1_token, _, _) = app.register(&email1).await;
    let (user2_token, _, _) = app.register(&email2).await;
    let (_, _, victim_id) = app.register(&email3).await;

    // User 1 creates App & Org
    let (app_status, app_json) = app
        .post_as(
            "/api/v1/apps",
            json!({ "name": "Target App", "slug": format!("target-app-{}", uuid::Uuid::now_v7().simple()) }),
            &user1_token,
        )
        .await;
    assert_eq!(app_status, StatusCode::CREATED);
    let app_id = app_json["data"]["id"].as_str().unwrap();

    let (org_status, org_json) = app
        .post_as(
            &format!("/api/v1/apps/{app_id}/orgs"),
            json!({ "name": "Secure Org", "slug": "secure-org" }),
            &user1_token,
        )
        .await;
    assert_eq!(org_status, StatusCode::CREATED);
    let org_id = org_json["data"]["id"].as_str().unwrap();

    // User 2 (not in org) attempts to add a member -> 404 Not Found
    let (exploit_status, _) = app
        .post_as(
            &format!("/api/v1/apps/orgs/{org_id}/members"),
            json!({
                "user_id": victim_id,
                "role": "owner"
            }),
            &user2_token,
        )
        .await;

    assert_eq!(exploit_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_slug_and_role_are_rejected() {
    let app = TestApp::spawn().await;
    let email = format!("slugtest_{}@test.local", uuid::Uuid::now_v7());
    let (user_token, _, _) = app.register(&email).await;

    // Bad Slug (uppercase and spaces)
    let (bad_slug_status, _) = app
        .post_as(
            "/api/v1/apps",
            json!({ "name": "Bad App", "slug": "INVALID SLUG!" }),
            &user_token,
        )
        .await;

    assert_eq!(bad_slug_status, StatusCode::UNPROCESSABLE_ENTITY);

    // Create valid app and org
    let (app_status, app_json) = app
        .post_as(
            "/api/v1/apps",
            json!({ "name": "Valid App", "slug": format!("valid-app-{}", uuid::Uuid::now_v7().simple()) }),
            &user_token,
        )
        .await;
    assert_eq!(app_status, StatusCode::CREATED);
    let app_id = app_json["data"]["id"].as_str().unwrap();

    let (org_status, org_json) = app
        .post_as(
            &format!("/api/v1/apps/{app_id}/orgs"),
            json!({ "name": "Valid Org", "slug": "valid-org" }),
            &user_token,
        )
        .await;
    assert_eq!(org_status, StatusCode::CREATED);
    let org_id = org_json["data"]["id"].as_str().unwrap();

    // Bad Role string ("supergod")
    let (bad_role_status, _) = app
        .post_as(
            &format!("/api/v1/apps/orgs/{org_id}/members"),
            json!({
                "user_id": uuid::Uuid::now_v7(),
                "role": "supergod"
            }),
            &user_token,
        )
        .await;

    assert_eq!(bad_role_status, StatusCode::UNPROCESSABLE_ENTITY);
}
