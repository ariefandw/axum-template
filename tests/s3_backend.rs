//! S3 backend integration tests.
//!
//! These talk to a real S3-compatible service and are skipped unless one is
//! configured, so the default `cargo test` run needs nothing but PostgreSQL.
//!
//! To run them:
//!
//! ```bash
//! export STORAGE_BACKEND=s3 AWS_BUCKET=... AWS_REGION=... AWS_ENDPOINT=...
//! export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
//! export AWS_KEY_PREFIX="ci-$(date +%s)"   # keep test objects out of the way
//! cargo test --test s3_backend
//! ```
//!
//! `AWS_KEY_PREFIX` matters when the bucket is shared: every object these tests
//! write lands under it, and each test removes what it created.

mod common;

use std::path::PathBuf;

use axum_template::{
    config::{AppConfig, S3Config, StorageBackendKind},
    services::storage_backend::{S3Backend, StorageBackend},
};
use tokio::io::AsyncWriteExt;

/// Build an S3 backend from the environment, or return `None` so the test can
/// skip rather than fail on a machine with no bucket configured.
fn s3_from_env() -> Option<S3Config> {
    let _ = dotenvy::dotenv();
    if std::env::var("STORAGE_BACKEND").ok().as_deref() != Some("s3") {
        return None;
    }
    let mut cfg = AppConfig::for_testing("postgres://unused");
    cfg.storage_backend = StorageBackendKind::S3;
    // Reuse the real loader so the test exercises the same parsing production does.
    match AppConfig::load_from_env() {
        Ok(loaded) => loaded.s3,
        Err(_) => None,
    }
}

macro_rules! skip_without_s3 {
    () => {
        match s3_from_env() {
            Some(cfg) => cfg,
            None => {
                eprintln!("skipping: STORAGE_BACKEND=s3 and AWS_* not configured");
                return;
            }
        }
    };
}

async fn temp_file(contents: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join("axum-template-s3-tests");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join(uuid::Uuid::now_v7().to_string());
    let mut f = tokio::fs::File::create(&path).await.unwrap();
    f.write_all(contents).await.unwrap();
    f.flush().await.unwrap();
    path
}

#[tokio::test]
async fn s3_round_trips_an_object() {
    let cfg = skip_without_s3!();
    let backend = S3Backend::new(&cfg);
    backend
        .check_connectivity()
        .await
        .expect("bucket should be reachable with the configured credentials");

    let key = format!("{}.txt", uuid::Uuid::now_v7());
    let payload = b"axum-template s3 round trip";
    let path = temp_file(payload).await;

    backend
        .put_file(&key, &path, "text/plain")
        .await
        .expect("put");

    let object = backend.open(&key).await.expect("open");
    assert_eq!(
        object.len,
        payload.len() as u64,
        "content length should match"
    );

    use futures_util::StreamExt;
    let mut stream = object.stream;
    let mut got = Vec::new();
    while let Some(chunk) = stream.next().await {
        got.extend_from_slice(&chunk.expect("chunk"));
    }
    assert_eq!(got, payload, "bytes must round-trip unchanged");

    backend.delete(&key).await.expect("delete");
    assert!(
        backend.open(&key).await.is_err(),
        "a deleted object must no longer be readable"
    );
    let _ = tokio::fs::remove_file(&path).await;
}

/// Presigned URLs are the reason to use S3 at all: they let bytes bypass this
/// service entirely.
#[tokio::test]
async fn s3_presigned_urls_point_at_object_storage() {
    let cfg = skip_without_s3!();
    let backend = S3Backend::new(&cfg);

    let key = format!("{}.txt", uuid::Uuid::now_v7());
    let path = temp_file(b"presigned").await;
    backend
        .put_file(&key, &path, "text/plain")
        .await
        .expect("put");

    let get_url = backend
        .presign_get(&key, 300)
        .await
        .expect("presign_get")
        .expect("the S3 backend must be able to presign");
    assert!(
        get_url.contains("X-Amz-Signature"),
        "URL must carry a signature"
    );
    assert!(
        !get_url.contains("/api/v1/"),
        "a native presigned URL must not route through this service: {get_url}"
    );

    let put_url = backend
        .presign_put(&key, "text/plain", 300)
        .await
        .expect("presign_put")
        .expect("the S3 backend must be able to presign uploads");
    assert!(put_url.contains("X-Amz-Signature"));

    backend.delete(&key).await.expect("delete");
    let _ = tokio::fs::remove_file(&path).await;
}

/// Storage keys are generated, never caller-supplied. The same allowlist that
/// stops `../` on local disk stops key injection against a bucket.
#[tokio::test]
async fn s3_rejects_keys_that_are_not_generated() {
    let cfg = skip_without_s3!();
    let backend = S3Backend::new(&cfg);
    let path = temp_file(b"nope").await;

    for bad in ["../escape.txt", "nested/key.txt", "..", ".hidden", ""] {
        assert!(
            backend.put_file(bad, &path, "text/plain").await.is_err(),
            "expected {bad:?} to be rejected before reaching the bucket"
        );
        assert!(
            backend.open(bad).await.is_err(),
            "expected {bad:?} to be rejected on read"
        );
    }
    let _ = tokio::fs::remove_file(&path).await;
}
