//! Regression tests for the presigned upload lifecycle.
//!
//! A presigned upload writes bytes straight to storage, so the API never sees
//! them. Before the `pending` -> `ready` lifecycle, that produced an orphan: the
//! response advertised a `storage_key` and a `file_url`, but no row existed, the
//! object was unowned and unreachable, and the `file_url` returned 404 forever.
//! On the local backend it was worse — the upload handler ignored the signed
//! `key`, `expires` and `signature` entirely.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::*;

/// The whole flow: reserve, upload against the signature, complete, then read.
#[tokio::test]
async fn presigned_upload_round_trips_and_becomes_readable() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign-flow")).await;

    let (status, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "photo.png", "content_type": "image/png" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "presign failed: {body}");

    let data = &body["data"];
    let file_id = data["file_id"]
        .as_str()
        .expect("a reserved file id")
        .to_string();
    let upload_url = data["upload_url"].as_str().unwrap().to_string();
    assert!(data["complete_url"].as_str().unwrap().contains(&file_id));

    // Until the upload is completed, the reservation must be invisible.
    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &token)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a pending reservation must not be readable"
    );

    // Upload the bytes against the signed URL. No bearer token: the signature
    // is the credential.
    let path = upload_url
        .split_once("/api/v1")
        .map(|(_, r)| format!("/api/v1{r}"))
        .unwrap();
    let (status, resp) = app
        .request(
            Request::builder()
                .uri(&path)
                .method("PUT")
                .body(Body::from(PNG_BYTES.to_vec()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "signed upload failed: {resp}");

    // Still not readable until completion confirms the object.
    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, done) = app
        .post_as(
            &format!("/api/v1/files/{file_id}/complete"),
            serde_json::json!({}),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "complete failed: {done}");
    assert_eq!(
        done["data"]["size_bytes"].as_u64(),
        Some(PNG_BYTES.len() as u64),
        "size must come from storage, not from the client"
    );

    // Now it is a real, readable, owned file.
    let response = app
        .raw(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("GET")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the completed file should be readable"
    );
}

/// The reservation is owned from the moment it is issued.
#[tokio::test]
async fn a_stranger_cannot_complete_someone_elses_reservation() {
    let app = TestApp::spawn().await;
    let (owner, _, _) = app.register(&unique_email("presign-owner")).await;
    let (attacker, _, _) = app.register(&unique_email("presign-attacker")).await;

    let (_, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "a.png", "content_type": "image/png" }),
            &owner,
        )
        .await;
    let file_id = body["data"]["file_id"].as_str().unwrap().to_string();
    let upload_url = body["data"]["upload_url"].as_str().unwrap().to_string();
    let path = upload_url
        .split_once("/api/v1")
        .map(|(_, r)| format!("/api/v1{r}"))
        .unwrap();

    app.request(
        Request::builder()
            .uri(&path)
            .method("PUT")
            .body(Body::from(PNG_BYTES.to_vec()))
            .unwrap(),
    )
    .await;

    let (status, _) = app
        .post_as(
            &format!("/api/v1/files/{file_id}/complete"),
            serde_json::json!({}),
            &attacker,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "only the owner may complete a reservation"
    );
}

/// An upload grant is a signature, and forging or expiring it must not work.
#[tokio::test]
async fn signed_upload_rejects_a_tampered_grant() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign-tamper")).await;

    let (_, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "b.png", "content_type": "image/png" }),
            &token,
        )
        .await;
    let upload_url = body["data"]["upload_url"].as_str().unwrap().to_string();
    let path = upload_url
        .split_once("/api/v1")
        .map(|(_, r)| format!("/api/v1{r}"))
        .unwrap();

    for (label, tampered) in [
        ("extended expiry", path.replace("expires=", "expires=9")),
        (
            "forged signature",
            path.replace("signature=", "signature=AAAA"),
        ),
    ] {
        let (status, _) = app
            .request(
                Request::builder()
                    .uri(&tampered)
                    .method("PUT")
                    .body(Body::from(PNG_BYTES.to_vec()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label} must be rejected");
    }
}

/// Completing before the bytes exist must not mark the file readable.
#[tokio::test]
async fn completing_without_uploading_is_refused() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign-empty")).await;

    let (_, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "c.png", "content_type": "image/png" }),
            &token,
        )
        .await;
    let file_id = body["data"]["file_id"].as_str().unwrap().to_string();

    let (status, resp) = app
        .post_as(
            &format!("/api/v1/files/{file_id}/complete"),
            serde_json::json!({}),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "completing with no uploaded object must fail: {resp}"
    );

    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &token)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "and the file must stay unreadable"
    );
}

/// Content types outside the allowlist are refused at reservation time, before
/// any URL is handed out.
#[tokio::test]
async fn presign_refuses_disallowed_content_types() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign-mime")).await;

    let (status, _) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "x.exe", "content_type": "application/x-msdownload" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Reserving into an organization requires membership.
#[tokio::test]
async fn presign_into_an_org_requires_membership() {
    let app = TestApp::spawn().await;
    let (owner, _, _) = app.register(&unique_email("presign-org-owner")).await;
    let (outsider, _, _) = app.register(&unique_email("presign-org-outsider")).await;
    let (_app_id, org_id) = app.create_app_and_org(&owner).await;

    let (status, _) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({
                "filename": "d.png", "content_type": "image/png", "org_id": org_id
            }),
            &outsider,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member must not reserve into an org"
    );

    let (status, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({
                "filename": "d.png", "content_type": "image/png", "org_id": org_id
            }),
            &owner,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner should be able to: {body}"
    );
}

/// An abandoned reservation must not linger forever. The reaper runs hourly in
/// the server; this drives the same query directly so the behaviour is covered.
#[tokio::test]
async fn abandoned_reservations_are_reapable() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("presign-abandon")).await;

    let (_, body) = app
        .post_as(
            "/api/v1/files/presigned-url",
            serde_json::json!({ "filename": "e.png", "content_type": "image/png" }),
            &token,
        )
        .await;
    let file_id = uuid::Uuid::parse_str(body["data"]["file_id"].as_str().unwrap()).unwrap();

    // Age the reservation past the grace period.
    sqlx::query("UPDATE files SET created_at = now() - interval '30 days' WHERE id = $1")
        .bind(file_id)
        .execute(&app.state.db)
        .await
        .unwrap();

    let grace = app.state.config.signed_url_ttl_seconds * 2;
    let stale: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, storage_key FROM files \
         WHERE status = 'pending' AND deleted_at IS NULL \
           AND created_at < now() - make_interval(secs => $1)",
    )
    .bind(grace as f64)
    .fetch_all(&app.state.db)
    .await
    .unwrap();

    assert!(
        stale.iter().any(|(id, _)| *id == file_id),
        "the abandoned reservation should be selected for reaping"
    );

    // A completed file of the same age must NOT be selected.
    let (_, done) = app.upload_png(&token, "private").await;
    let ready_id = uuid::Uuid::parse_str(done["data"]["id"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE files SET created_at = now() - interval '30 days' WHERE id = $1")
        .bind(ready_id)
        .execute(&app.state.db)
        .await
        .unwrap();

    let stale_again: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM files \
         WHERE status = 'pending' AND deleted_at IS NULL \
           AND created_at < now() - make_interval(secs => $1)",
    )
    .bind(grace as f64)
    .fetch_all(&app.state.db)
    .await
    .unwrap();
    assert!(
        !stale_again.contains(&ready_id),
        "a completed upload must never be reaped, however old"
    );
}
