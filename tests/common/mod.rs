//! Shared test harness.
//!
//! Every test runs against a real PostgreSQL database. The previous suite built
//! its pool with `connect_lazy` and never issued a query, so none of the auth,
//! storage, notification or audit logic had any coverage at all.

// Each test binary compiles this module independently, so a helper used by
// only one of them appears unused to the others.
#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::Value;
use tower::ServiceExt;

use axum_template::{config::AppConfig, create_app, state::AppState};

/// A single global recorder. `install_recorder` succeeds only once per process,
/// and the previous suite's fallback handle pointed at a different registry than
/// the `metrics!` macros wrote to, which made metric assertions order-dependent.
fn prometheus_handle() -> PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("metrics recorder installs exactly once per test process")
        })
        .clone()
}

pub fn database_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set for the integration suite. \
         Start one with: docker compose up -d postgres",
    )
}

pub struct TestApp {
    pub router: Router,
    pub state: Arc<AppState>,
}

impl TestApp {
    pub async fn spawn() -> Self {
        let _ = dotenvy::dotenv();
        let config = AppConfig::for_testing(database_url());

        let pool = sqlx::PgPool::connect(config.database_url.expose())
            .await
            .expect("failed to connect to the test database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations must apply cleanly");

        let state = Arc::new(AppState::new(pool, config, prometheus_handle()));
        Self {
            router: create_app(state.clone()),
            state,
        }
    }

    pub async fn request(&self, req: Request<Body>) -> (StatusCode, Value) {
        let response = self
            .router
            .clone()
            .oneshot(with_peer(req))
            .await
            .expect("router call failed");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    pub async fn raw(&self, req: Request<Body>) -> axum::response::Response {
        self.router
            .clone()
            .oneshot(with_peer(req))
            .await
            .expect("router call failed")
    }

    pub async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.request(json_request("POST", uri, body, None, None))
            .await
    }

    pub async fn post_as(&self, uri: &str, body: Value, token: &str) -> (StatusCode, Value) {
        self.request(json_request("POST", uri, body, Some(token), None))
            .await
    }

    pub async fn get_as(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.request(
            Request::builder()
                .uri(uri)
                .method("GET")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Register a user and return `(access_token, refresh_token, user_id)`.
    pub async fn register(&self, email: &str) -> (String, String, String) {
        let (status, body) = self
            .post(
                "/api/v1/auth/sign-up/email",
                serde_json::json!({
                    "name": "Test User",
                    "email": email,
                    "password": "Str0ng-Test-Passphrase!",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "sign-up failed: {body}");
        (
            body["data"]["access_token"].as_str().unwrap().to_string(),
            body["data"]["refresh_token"].as_str().unwrap().to_string(),
            body["data"]["user"]["id"].as_str().unwrap().to_string(),
        )
    }

    /// Promote a user to admin and mint a fresh token carrying the new role.
    pub async fn promote_to_admin(&self, email: &str) -> String {
        sqlx::query("UPDATE users SET role = 'admin' WHERE email = $1")
            .bind(email)
            .execute(&self.state.db)
            .await
            .unwrap();

        let (_, body) = self
            .post(
                "/api/v1/auth/sign-in/email",
                serde_json::json!({ "email": email, "password": "Str0ng-Test-Passphrase!" }),
            )
            .await;
        body["data"]["access_token"].as_str().unwrap().to_string()
    }

    /// Authenticate with an API key rather than a bearer token.
    pub async fn get_with_key(&self, uri: &str, key: &str) -> (StatusCode, Value) {
        self.request(
            Request::builder()
                .uri(uri)
                .method("GET")
                .header("x-api-key", key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    pub async fn call_with_key(
        &self,
        method: &str,
        uri: &str,
        key: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .uri(uri)
            .method(method)
            .header("x-api-key", key)
            .header(header::CONTENT_TYPE, "application/json");
        let _ = &mut builder;
        let payload = match body {
            Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
            None => Body::empty(),
        };
        self.request(builder.body(payload).unwrap()).await
    }

    /// Mint an API key with the given scopes, returning the plaintext secret.
    pub async fn create_api_key(&self, token: &str, scopes: Option<Vec<&str>>) -> String {
        let mut body = serde_json::json!({ "name": "test key" });
        if let Some(scopes) = scopes {
            body["scopes"] = serde_json::json!(scopes);
        }
        let (status, resp) = self
            .post_as("/api/v1/auth/api-key/create", body, token)
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "api key creation failed: {resp}"
        );
        resp["data"]["key"].as_str().unwrap().to_string()
    }

    /// Create an app and an organization owned by `token`, returning both IDs.
    pub async fn create_app_and_org(&self, token: &str) -> (String, String) {
        let n = uuid::Uuid::now_v7().simple().to_string();
        let (s, app) = self
            .post_as(
                "/api/v1/apps",
                serde_json::json!({ "name": "Test App", "slug": format!("app-{}", n) }),
                token,
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "app creation failed: {app}");
        let app_id = app["data"]["id"].as_str().unwrap().to_string();

        let (s, org) = self
            .post_as(
                &format!("/api/v1/apps/{app_id}/orgs"),
                serde_json::json!({ "name": "Test Org", "slug": format!("org-{}", n) }),
                token,
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "org creation failed: {org}");
        (app_id, org["data"]["id"].as_str().unwrap().to_string())
    }

    /// Upload a PNG, optionally attributing it to an organization.
    pub async fn upload_png_to_org(
        &self,
        token: &str,
        visibility: &str,
        org_id: Option<&str>,
    ) -> (StatusCode, Value) {
        let (boundary, body) =
            multipart_body_with_org("avatar.png", "image/png", PNG_BYTES, visibility, org_id);
        self.request(
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
        .await
    }

    pub async fn upload_png(&self, token: &str, visibility: &str) -> (StatusCode, Value) {
        let (boundary, body) = multipart_body("avatar.png", "image/png", PNG_BYTES, visibility);
        self.request(
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
        .await
    }
}

/// Attach a peer address, as `into_make_service_with_connect_info` does in the
/// real server. The rate limiter keys on the peer address and fails closed
/// without one, which is the correct production behaviour.
fn with_peer(mut req: Request<Body>) -> Request<Body> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            50000,
        )));
    req
}

pub fn json_request(
    method: &str,
    uri: &str,
    body: Value,
    token: Option<&str>,
    idempotency_key: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .uri(uri)
        .method(method)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(k) = idempotency_key {
        builder = builder.header("idempotency-key", k);
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Unique address per test, so the suite can run in any order against a shared
/// database without collisions.
pub fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@test.local", uuid::Uuid::now_v7().simple())
}

pub fn multipart_body_with_org(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
    visibility: &str,
    org_id: Option<&str>,
) -> (String, Vec<u8>) {
    let boundary = format!("----test{}", uuid::Uuid::now_v7().simple());
    let mut body = Vec::new();

    let mut text_field = |name: &str, value: &str| {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    };
    text_field("visibility", visibility);
    if let Some(org) = org_id {
        text_field("org_id", org);
    }

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (boundary, body)
}

pub fn multipart_body(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
    visibility: &str,
) -> (String, Vec<u8>) {
    let boundary = format!("----test{}", uuid::Uuid::now_v7().simple());
    let mut body = Vec::new();

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"visibility\"\r\n\r\n");
    body.extend_from_slice(visibility.as_bytes());
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (boundary, body)
}

pub const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR-test-image-content";
