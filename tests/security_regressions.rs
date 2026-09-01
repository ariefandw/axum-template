//! Regression tests for the vulnerabilities found in the security review.
//!
//! Each test here reproduces a specific confirmed exploit and asserts it no
//! longer works. Every one of them fails against the pre-hardening code.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::*;

/// F-01: the idempotency cache was keyed on the client-supplied header alone, so
/// an attacker reusing a victim's key received the victim's cached response —
/// including their access token.
#[tokio::test]
async fn idempotency_key_cannot_replay_another_users_response() {
    let app = TestApp::spawn().await;
    let victim_email = unique_email("victim");
    let shared_key = format!("shared-key-{}", uuid::Uuid::now_v7().simple());

    let (status, victim_body) = app
        .request(json_request(
            "POST",
            "/api/v1/auth/sign-up/email",
            serde_json::json!({
                "name": "Victim", "email": victim_email,
                "password": "Str0ng-Test-Passphrase!"
            }),
            None,
            Some(&shared_key),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "victim sign-up failed: {victim_body}"
    );
    let victim_token = victim_body["data"]["access_token"].as_str().unwrap();

    // The attacker sends an entirely different request under the same key.
    let (status, attacker_body) = app
        .request(json_request(
            "POST",
            "/api/v1/auth/sign-in/email",
            serde_json::json!({
                "email": unique_email("attacker"), "password": "Str0ng-Test-Passphrase!"
            }),
            None,
            Some(&shared_key),
        ))
        .await;

    assert_ne!(
        status,
        StatusCode::CREATED,
        "attacker received the victim's cached 201 response: {attacker_body}"
    );
    let leaked = attacker_body["data"]["access_token"]
        .as_str()
        .unwrap_or_default();
    assert!(
        leaked.is_empty() && leaked != victim_token,
        "attacker was handed a token belonging to another user"
    );
    assert_ne!(
        attacker_body["data"]["user"]["email"]
            .as_str()
            .unwrap_or_default(),
        victim_email,
        "attacker received the victim's identity"
    );
}

/// F-01 (positive case): a genuine retry — same caller, same request, same key —
/// must still replay rather than creating a second resource.
#[tokio::test]
async fn idempotency_key_replays_the_same_callers_identical_request() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("idem-owner")).await;
    let key = format!("retry-{}", uuid::Uuid::now_v7().simple());
    let payload = serde_json::json!({ "name": "Renamed Once" });

    let first = app
        .request(json_request(
            "POST",
            "/api/v1/auth/update-user",
            payload.clone(),
            Some(&token),
            Some(&key),
        ))
        .await;
    let second = app
        .request(json_request(
            "POST",
            "/api/v1/auth/update-user",
            payload,
            Some(&token),
            Some(&key),
        ))
        .await;

    assert_eq!(first.0, StatusCode::OK, "first call failed: {:?}", first.1);
    assert_eq!(
        second.0, first.0,
        "a genuine retry should replay the original status"
    );
    assert_eq!(
        second.1, first.1,
        "a genuine retry should replay the original body"
    );
}

/// F-02: `verifications` stored every token type in one untyped column, so an
/// email-verification token was accepted by the password-reset endpoint.
#[tokio::test]
async fn email_verification_token_cannot_reset_a_password() {
    let app = TestApp::spawn().await;
    let email = unique_email("purpose");
    app.register(&email).await;

    // Read the verification token's hash straight from the table. The plaintext
    // is no longer recoverable, which is itself part of the fix, so the test
    // proves purpose-scoping by minting a known token for this identifier.
    let verify_token = format!("verify-token-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at)
         VALUES ($1, $2, 'email_verify', $3, now() + interval '1 hour')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(&email)
    .bind(sha256_hex(&verify_token))
    .execute(&app.state.db)
    .await
    .unwrap();

    let (status, body) = app
        .post(
            "/api/v1/auth/reset-password",
            serde_json::json!({ "token": verify_token, "new_password": "Attacker-Chosen-Pass!1" }),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an email-verification token was accepted for password reset: {body}"
    );

    // And the original password must still work.
    let (status, _) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": email, "password": "Str0ng-Test-Passphrase!" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the original password should be unchanged"
    );
}

/// F-02 (positive case): a token minted for password reset still works.
#[tokio::test]
async fn password_reset_token_works_for_its_own_purpose() {
    let app = TestApp::spawn().await;
    let email = unique_email("reset-ok");
    app.register(&email).await;

    let token = format!("reset-token-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at)
         VALUES ($1, $2, 'password_reset', $3, now() + interval '1 hour')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(&email)
    .bind(sha256_hex(&token))
    .execute(&app.state.db)
    .await
    .unwrap();

    let (status, body) = app
        .post(
            "/api/v1/auth/reset-password",
            serde_json::json!({ "token": token, "new_password": "Brand-New-Passphrase!9" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "reset with a correct-purpose token failed: {body}"
    );

    let (status, _) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": email, "password": "Brand-New-Passphrase!9" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Single use: the same token must not work twice.
    let (status, _) = app
        .post(
            "/api/v1/auth/reset-password",
            serde_json::json!({ "token": token, "new_password": "Yet-Another-Passphrase!7" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a reset token must be single-use"
    );
}

/// F-03: uploads were untracked on disk, so any file was readable without
/// credentials and deletable by any authenticated user.
#[tokio::test]
async fn files_are_not_readable_or_deletable_by_strangers() {
    let app = TestApp::spawn().await;
    let (owner_token, _, _) = app.register(&unique_email("file-owner")).await;
    let (attacker_token, _, _) = app.register(&unique_email("file-attacker")).await;

    let (status, body) = app.upload_png(&owner_token, "private").await;
    assert_eq!(status, StatusCode::CREATED, "upload failed: {body}");
    let file_id = body["data"]["id"].as_str().unwrap();

    // 1. Anonymous read is refused.
    let (status, _) = app
        .request(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a private file was served to an anonymous caller"
    );

    // 2. Another user's read is refused.
    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &attacker_token)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a private file was served to a stranger"
    );

    // 3. Another user's delete is refused.
    let (status, _) = app
        .request(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("DELETE")
                .header(header::AUTHORIZATION, format!("Bearer {attacker_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a stranger deleted another user's file"
    );

    // 4. The owner can still read it.
    let response = app
        .raw(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("GET")
                .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the owner must still be able to read the file"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png",
        "the detected MIME type should be preserved, not flattened to octet-stream"
    );
}

/// F-06: `banned` was checked only at sign-in, so an existing token kept working
/// for the rest of its lifetime. There was no revocation path at all.
#[tokio::test]
async fn banning_a_user_invalidates_their_live_token() {
    let app = TestApp::spawn().await;
    let email = unique_email("banned");
    let (token, _, _) = app.register(&email).await;

    let (status, _) = app.get_as("/api/v1/users/me", &token).await;
    assert_eq!(status, StatusCode::OK, "token should work before the ban");

    sqlx::query("UPDATE users SET banned = true WHERE email = $1")
        .bind(&email)
        .execute(&app.state.db)
        .await
        .unwrap();

    let (status, body) = app.get_as("/api/v1/users/me", &token).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a banned user's token still worked: {body}"
    );
}

/// F-06: signing out must revoke the session immediately.
#[tokio::test]
async fn signing_out_revokes_the_access_token_immediately() {
    let app = TestApp::spawn().await;
    let (token, refresh, _) = app.register(&unique_email("signout")).await;

    let (status, _) = app
        .post_as("/api/v1/auth/sign-out", serde_json::json!({}), &token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.get_as("/api/v1/users/me", &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked session still authenticated"
    );

    let (status, _) = app
        .post(
            "/api/v1/auth/refresh",
            serde_json::json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked session's refresh token still worked"
    );
}

/// F-06: a demoted administrator must lose access at once, because the role is
/// re-read from the database rather than trusted from the token.
#[tokio::test]
async fn demoting_an_admin_takes_effect_without_waiting_for_expiry() {
    let app = TestApp::spawn().await;
    let email = unique_email("demoted-admin");
    app.register(&email).await;
    let admin_token = app.promote_to_admin(&email).await;

    let (status, _) = app.get_as("/api/v1/audit-logs", &admin_token).await;
    assert_eq!(status, StatusCode::OK, "admin should reach the audit log");

    sqlx::query("UPDATE users SET role = 'user' WHERE email = $1")
        .bind(&email)
        .execute(&app.state.db)
        .await
        .unwrap();

    let (status, _) = app.get_as("/api/v1/audit-logs", &admin_token).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a demoted admin kept admin access via their token"
    );
}

/// F-09: the raw URI was used as a Prometheus label, so each distinct file ID
/// minted a new permanent time series — an unbounded, anonymously-driven leak.
///
/// The invariant is that cardinality does not grow with the number of distinct
/// paths, so the test measures the series count, generates many more unique
/// paths, and asserts it did not move.
#[tokio::test]
async fn metric_labels_do_not_grow_with_distinct_paths() {
    let app = TestApp::spawn().await;

    let count_file_series = |dump: &str| -> usize {
        dump.lines()
            .filter(|l| l.starts_with("http_requests_total{") && l.contains("/api/v1/files/"))
            .count()
    };

    // Warm up, so any method/status combination this test produces already exists.
    for _ in 0..5 {
        let _ = app
            .raw(
                Request::builder()
                    .uri(format!("/api/v1/files/{}", uuid::Uuid::now_v7()))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
    }
    let baseline = count_file_series(&app.state.prometheus_handle.render());

    // 50 further requests, every one to a distinct path.
    for _ in 0..50 {
        let _ = app
            .raw(
                Request::builder()
                    .uri(format!("/api/v1/files/{}", uuid::Uuid::now_v7()))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
    }

    let dump = app.state.prometheus_handle.render();
    let after = count_file_series(&dump);

    // Other tests share this process-wide registry and may add a method/status
    // combination mid-run, so the assertion is that cardinality stays bounded --
    // not that it is frozen. Under the old raw-URI labelling this would be 50+.
    assert!(
        after < 10 && after <= baseline + 5,
        "cardinality grew from {baseline} to {after} across 50 distinct paths; \
         labels must come from the route template, not the URI"
    );
    assert!(
        dump.contains("/api/v1/files/{id}"),
        "expected the route template to appear as the label value"
    );
    // The crisp invariant: no request-specific identifier may reach a label.
    for line in dump
        .lines()
        .filter(|l| l.starts_with("http_requests_total{"))
    {
        assert!(
            !line.contains("/api/v1/files/0"),
            "a raw UUID leaked into a metric label: {line}"
        );
    }
}

/// F-16: an unknown address must not be distinguishable from a wrong password.
#[tokio::test]
async fn unknown_and_known_accounts_return_the_same_rejection() {
    let app = TestApp::spawn().await;
    let email = unique_email("enumeration");
    app.register(&email).await;

    let (unknown_status, unknown_body) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": unique_email("nobody"), "password": "Wrong-Passphrase!1" }),
        )
        .await;
    let (known_status, known_body) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": email, "password": "Wrong-Passphrase!1" }),
        )
        .await;

    assert_eq!(unknown_status, known_status);
    assert_eq!(unknown_body["error"]["code"], known_body["error"]["code"]);
    assert_eq!(
        unknown_body["error"]["message"],
        known_body["error"]["message"]
    );
}

/// F-30: the audit table was documented as immutable but nothing enforced it.
#[tokio::test]
async fn audit_log_rows_cannot_be_modified_or_deleted() {
    let app = TestApp::spawn().await;
    let (_, _, user_id) = app.register(&unique_email("audit-immutable")).await;

    let update = sqlx::query("UPDATE audit_logs SET action = 'tampered' WHERE user_id = $1")
        .bind(uuid::Uuid::parse_str(&user_id).unwrap())
        .execute(&app.state.db)
        .await;
    assert!(update.is_err(), "audit rows must not be updatable");

    let delete = sqlx::query("DELETE FROM audit_logs WHERE user_id = $1")
        .bind(uuid::Uuid::parse_str(&user_id).unwrap())
        .execute(&app.state.db)
        .await;
    assert!(delete.is_err(), "audit rows must not be deletable");
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(input.as_bytes()))
}
