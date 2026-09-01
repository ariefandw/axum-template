//! Regression tests for the M2M API key privilege boundary.
//!
//! A machine credential must be strictly narrower than the human account that
//! issued it. Before these tests, a key declaring `["read:profile"]` could
//! rename its owner, mint further keys, change the account password, delete the
//! account, and — if the owner was an administrator — reach every admin route.
//! Each test below fails against that behaviour.

mod common;

use axum::http::StatusCode;
use common::*;

/// Scopes were stored and returned but never consulted.
#[tokio::test]
async fn declared_scopes_actually_restrict_the_key() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("scoped")).await;

    let read_only = app.create_api_key(&token, Some(vec!["users:read"])).await;

    // Within scope.
    let (status, _) = app.get_with_key("/api/v1/users/me", &read_only).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "users:read should permit reading the profile"
    );

    // Outside scope: the key must not be able to write.
    let (status, body) = app
        .call_with_key(
            "PATCH",
            "/api/v1/users/me",
            &read_only,
            Some(serde_json::json!({ "name": "Renamed By Key" })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a users:read key must not be able to modify the profile: {body}"
    );

    // Outside scope: the key must not reach other resources.
    let (status, _) = app.get_with_key("/api/v1/notifications", &read_only).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "notifications need their own scope"
    );
}

/// A wildcard key is convenient, but must not be a silent superuser.
#[tokio::test]
async fn wildcard_keys_do_not_include_admin() {
    let app = TestApp::spawn().await;
    let email = unique_email("wildcard-admin");
    app.register(&email).await;
    let admin_token = app.promote_to_admin(&email).await;

    // Explicitly wildcard.
    let wildcard = app.create_api_key(&admin_token, Some(vec!["*"])).await;
    let (status, _) = app.get_with_key("/api/v1/users/me", &wildcard).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a wildcard key should still work normally"
    );

    let (status, body) = app.get_with_key("/api/v1/audit-logs", &wildcard).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an administrator's wildcard key must not reach admin routes without the admin scope: {body}"
    );

    // Opting in explicitly does grant it.
    let admin_key = app
        .create_api_key(&admin_token, Some(vec!["admin", "audit:read"]))
        .await;
    let (status, _) = app.get_with_key("/api/v1/audit-logs", &admin_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an explicit admin-scoped key should be admitted"
    );
}

/// The operations that turn a leaked key into permanent control.
#[tokio::test]
async fn api_keys_cannot_perform_account_lifecycle_operations() {
    let app = TestApp::spawn().await;
    let email = unique_email("lifecycle");
    let (token, _, _) = app.register(&email).await;
    // Deliberately the broadest key obtainable.
    let key = app.create_api_key(&token, Some(vec!["*"])).await;

    // 1. Cannot change the password — otherwise a leaked key becomes ownership.
    let (status, body) = app
        .call_with_key(
            "PATCH",
            "/api/v1/users/me/password",
            &key,
            Some(serde_json::json!({
                "current_password": "Str0ng-Test-Passphrase!",
                "new_password": "Key-Owned-Now!1234"
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not change the password: {body}"
    );

    // The original password must still work.
    let (status, _) = app
        .post(
            "/api/v1/auth/sign-in/email",
            serde_json::json!({ "email": email, "password": "Str0ng-Test-Passphrase!" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the password must be unchanged");

    // 2. Cannot mint further keys — otherwise revoking the leaked one is futile.
    let (status, _) = app
        .call_with_key(
            "POST",
            "/api/v1/auth/api-key/create",
            &key,
            Some(serde_json::json!({ "name": "child key" })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not be able to mint another key"
    );

    // 3. Cannot revoke sessions.
    let (status, _) = app
        .call_with_key("POST", "/api/v1/auth/sign-out-all", &key, None)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not revoke the human's sessions"
    );

    // 4. Cannot delete the account.
    let (status, _) = app
        .call_with_key("DELETE", "/api/v1/users/me", &key, None)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not delete the account"
    );

    // The account is still usable.
    let (status, _) = app.get_as("/api/v1/users/me", &token).await;
    assert_eq!(status, StatusCode::OK);
}

/// A typo in a scope name must not silently produce a key with different
/// authority than the caller asked for.
#[tokio::test]
async fn unknown_scopes_are_rejected_at_creation() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("badscope")).await;

    let (status, body) = app
        .post_as(
            "/api/v1/auth/api-key/create",
            serde_json::json!({ "name": "typo key", "scopes": ["files:raed"] }),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unknown scope must be rejected rather than dropped: {body}"
    );
}

/// Sessions keep the account's full authority; only keys are narrowed.
#[tokio::test]
async fn sessions_are_unaffected_by_scoping() {
    let app = TestApp::spawn().await;
    let (token, _, _) = app.register(&unique_email("session-full")).await;

    for (method, path, body) in [
        ("GET", "/api/v1/users/me", None),
        ("GET", "/api/v1/notifications", None),
        (
            "PATCH",
            "/api/v1/users/me",
            Some(serde_json::json!({ "name": "Renamed By Human" })),
        ),
    ] {
        let (status, resp) = match (method, body) {
            ("GET", _) => app.get_as(path, &token).await,
            (m, Some(b)) => {
                app.request(json_request(m, path, b, Some(&token), None))
                    .await
            }
            (m, None) => {
                app.request(json_request(
                    m,
                    path,
                    serde_json::json!({}),
                    Some(&token),
                    None,
                ))
                .await
            }
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "{method} {path} should work for a session: {resp}"
        );
    }
}
