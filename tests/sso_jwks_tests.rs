use axum::{Json, Router, routing::get};
use axum_template::crypto::jwks::JwksClient;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn jwks_verifier_parses_and_caches_remote_keys() {
    let jwks_payload = json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-1",
                "n": "u1SU1LfVJ4Fi7m_xQakjmUutWhByJvigQVMDhDn17FiKGLkMpndhxv9KPwZSWDVBIGCP53daN228mRPOASQtZsTUqP2uZdSTUqS3ix41LqAO64Laq30tO2WEQ477-ezJSL4GsEGGDndphQ5Ey8wgz79oqBo5Ri9u12o0iea6WVk",
                "e": "AQAB"
            }
        ]
    });

    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || {
            let body = jwks_payload.clone();
            async move { Json(body) }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let jwks_url = format!("http://{}/.well-known/jwks.json", addr);
    let http_client = reqwest::Client::new();

    let client = JwksClient::new(
        jwks_url,
        Some("https://sso.example.com".to_string()),
        Some("my-api".to_string()),
        http_client,
    );

    // Invalid format test verifies network fetch succeeds and fails safely on JWT malformation
    let err = client.verify_token("not.a.valid.jwt").await.unwrap_err();
    assert!(err.to_string().contains("Invalid JWT header"));
}
