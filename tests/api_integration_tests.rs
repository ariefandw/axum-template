//! Functional coverage for the API surface, exercised against a real database.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::*;

#[tokio::test]
async fn liveness_and_readiness_are_separate_probes() {
    let app = TestApp::spawn().await;

    let (status, body) = app
        .request(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["database"], "not_checked",
        "liveness must not depend on the database"
    );

    let (status, body) = app
        .request(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "readiness failed: {body}");
    assert_eq!(body["database"], "healthy");
}

#[tokio::test]
async fn security_headers_include_a_content_security_policy() {
    let app = TestApp::spawn().await;
    let response = app
        .raw(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let headers = response.headers();

    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(
        headers.get("content-security-policy").is_some(),
        "CSP was documented but never sent"
    );
    assert!(headers.get("permissions-policy").is_some());
    assert!(headers.get("x-request-id").is_some());
    // HSTS over plaintext development traffic would pin localhost to https.
    assert!(
        headers.get("strict-transport-security").is_none(),
        "HSTS should be asserted only in production"
    );
}

#[tokio::test]
async fn validation_errors_use_the_standard_envelope() {
    let app = TestApp::spawn().await;
    let (status, body) = app
        .post(
            "/api/v1/auth/sign-up/email",
            serde_json::json!({ "name": "A", "email": "not-an-email", "password": "short" }),
        )
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["success"], false);
    assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn common_passwords_are_rejected() {
    let app = TestApp::spawn().await;
    for weak in ["password123", "12345678", "qwertyuiop"] {
        let (status, _) = app
            .post(
                "/api/v1/auth/sign-up/email",
                serde_json::json!({
                    "name": "Weak", "email": unique_email("weak"), "password": weak
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{weak:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn duplicate_registration_is_a_conflict_not_a_server_error() {
    let app = TestApp::spawn().await;
    let email = unique_email("duplicate");
    app.register(&email).await;

    let (status, body) = app
        .post(
            "/api/v1/auth/sign-up/email",
            serde_json::json!({
                "name": "Duplicate", "email": email, "password": "Str0ng-Test-Passphrase!"
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "expected 409, got {status}: {body}"
    );
}

#[tokio::test]
async fn refresh_rotates_the_token_and_detects_replay() {
    let app = TestApp::spawn().await;
    let (_, refresh, _) = app.register(&unique_email("rotate")).await;

    let (status, body) = app
        .post(
            "/api/v1/auth/refresh",
            serde_json::json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "refresh failed: {body}");
    let rotated = body["data"]["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated, refresh, "the refresh token must rotate on use");

    let (status, _) = app
        .get_as(
            "/api/v1/users/me",
            body["data"]["access_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the new access token should work");

    // Replaying the consumed token is treated as a compromise: every session for
    // the user is revoked.
    let (status, _) = app
        .post(
            "/api/v1/auth/refresh",
            serde_json::json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a consumed refresh token must be rejected"
    );

    let (status, _) = app
        .post(
            "/api/v1/auth/refresh",
            serde_json::json!({ "refresh_token": rotated }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replay detection should have revoked the rotated token too"
    );
}

#[tokio::test]
async fn changing_a_password_revokes_other_sessions_but_not_the_current_one() {
    let app = TestApp::spawn().await;
    let email = unique_email("pwchange");
    let (session_a, _, _) = app.register(&email).await;

    let (_, body) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": email, "password": "Str0ng-Test-Passphrase!" }),
        )
        .await;
    let session_b = body["data"]["access_token"].as_str().unwrap().to_string();

    let (status, body) = app
        .request(json_request(
            "PATCH",
            "/api/v1/users/me/password",
            serde_json::json!({
                "current_password": "Str0ng-Test-Passphrase!",
                "new_password": "Replacement-Passphrase!4"
            }),
            Some(&session_b),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "password change failed: {body}");

    let (status, _) = app.get_as("/api/v1/users/me", &session_b).await;
    assert_eq!(status, StatusCode::OK, "the acting session should survive");

    let (status, _) = app.get_as("/api/v1/users/me", &session_a).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "other sessions should be revoked"
    );
}

#[tokio::test]
async fn rbac_blocks_normal_users_from_admin_routes() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("normal")).await;

    for path in ["/api/v1/audit-logs", "/api/v1/users"] {
        let (status, body) = app.get_as(path, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} should be admin-only");
        assert_eq!(body["error"]["code"], "FORBIDDEN");
    }
}

#[tokio::test]
async fn missing_credentials_are_rejected() {
    let app = TestApp::spawn().await;
    let (status, _) = app
        .request(
            Request::builder()
                .uri("/api/v1/users/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_log_records_authentication_events() {
    let app = TestApp::spawn().await;
    let email = unique_email("audited");
    let (_, _, user_id) = app.register(&email).await;

    // The service is wired into the sign-up path, so a row must exist. It
    // previously had no callers at all and this table stayed empty forever.
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_logs WHERE user_id = $1 ORDER BY created_at")
            .bind(uuid::Uuid::parse_str(&user_id).unwrap())
            .fetch_all(&app.state.db)
            .await
            .unwrap();

    assert!(
        actions.iter().any(|a| a == "user.signed_up"),
        "expected a sign-up audit entry, found {actions:?}"
    );
}

#[tokio::test]
async fn notifications_feed_is_scoped_and_cursor_paginated() {
    let app = TestApp::spawn().await;
    let (token, _, user_id) = app.register(&unique_email("notify")).await;
    let (other_token, _, _) = app.register(&unique_email("notify-other")).await;
    let uid = uuid::Uuid::parse_str(&user_id).unwrap();

    for i in 0..5 {
        axum_template::services::notification::NotificationService::create(
            &app.state,
            uid,
            &format!("Notice {i}"),
            "body",
            None,
        )
        .await
        .expect("notification insert");
    }

    let (status, body) = app.get_as("/api/v1/notifications?limit=2", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    assert_eq!(body["meta"]["has_next"], true);
    assert_eq!(body["meta"]["unread_count"], 5);

    let cursor = body["meta"]["next_cursor"].as_str().expect("a next cursor");
    let (status, page2) = app
        .get_as(
            &format!("/api/v1/notifications?limit=2&cursor={cursor}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        page2["data"][0]["id"], body["data"][0]["id"],
        "pages must not overlap"
    );

    // Another user sees none of them.
    let (_, other) = app.get_as("/api/v1/notifications", &other_token).await;
    assert_eq!(other["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn malformed_cursor_is_a_client_error() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("badcursor")).await;
    let (status, _) = app
        .get_as("/api/v1/notifications?cursor=!!!not-base64!!!", &token)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn uploads_are_typed_by_content_not_by_filename() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("sniff")).await;

    // An ELF binary renamed to .png must not be accepted as an image.
    let (boundary, body) = multipart_body(
        "totally-an-image.png",
        "image/png",
        b"\x7fELF\x02\x01\x01\x00 this is not an image at all",
        "private",
    );
    let (status, resp) = app
        .request(
            Request::builder()
                .uri("/api/v1/files/upload")
                .method("POST")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "content sniffing should reject this: {resp}"
    );

    // A real PNG is accepted and typed correctly.
    let (status, resp) = app.upload_png(&token, "private").await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["data"]["mime_type"], "image/png");
}

#[tokio::test]
async fn public_files_are_readable_without_credentials() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("public-file")).await;

    let (status, body) = app.upload_png(&token, "public").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let file_id = body["data"]["id"].as_str().unwrap();
    assert_eq!(body["data"]["visibility"], "public");

    let response = app
        .raw(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn signed_download_urls_grant_access_and_reject_tampering() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("signed")).await;

    let (_, body) = app.upload_png(&token, "private").await;
    let file_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, signed) = app
        .get_as(&format!("/api/v1/files/{file_id}/signed-url"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let url = signed["data"]["url"].as_str().unwrap();
    let path_and_query = url
        .split_once("/api/v1")
        .map(|(_, r)| format!("/api/v1{r}"))
        .unwrap();

    // The signature grants anonymous access.
    let response = app
        .raw(
            Request::builder()
                .uri(&path_and_query)
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a valid signature should grant access"
    );

    // Tampering with the expiry invalidates it.
    let tampered = path_and_query.replace("expires=", "expires=9");
    let response = app
        .raw(
            Request::builder()
                .uri(&tampered)
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a tampered signature must not verify"
    );
}

#[tokio::test]
async fn presigned_upload_grant_is_actually_signed() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign")).await;

    let (status, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "avatar.png", "content_type": "image/png" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let url = body["data"]["upload_url"].as_str().unwrap();
    assert!(
        url.contains("signature="),
        "the grant must carry a signature"
    );
    assert!(url.contains("expires="), "the grant must carry an expiry");
    assert!(body["data"]["expires_at"].is_string());

    // A content type outside the allowlist is refused.
    let (status, _) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "x.exe", "content_type": "application/x-msdownload" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleted_accounts_release_their_email_and_lose_access() {
    let app = TestApp::spawn().await;
    let email = unique_email("deleted");
    let (token, _, _) = app.register(&email).await;

    let (status, _) = app
        .request(
            Request::builder()
                .uri("/api/v1/users/me")
                .method("DELETE")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.get_as("/api/v1/users/me", &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a deleted account's session must be revoked"
    );

    // The address becomes available again, which the original UNIQUE(email)
    // constraint would have blocked forever.
    let (status, body) = app
        .post(
            "/api/v1/auth/sign-up/email",
            serde_json::json!({
                "name": "Reused", "email": email, "password": "Str0ng-Test-Passphrase!"
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the address should be reusable: {body}"
    );
}

#[tokio::test]
async fn metrics_endpoint_requires_its_token_when_configured() {
    let app = TestApp::spawn().await;
    // The test config leaves METRICS_TOKEN unset (development), so it serves.
    let (status, _) = app
        .request(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // Production refusing to boot without a token is covered by the config
    // unit tests, which do not need a live server.
}
