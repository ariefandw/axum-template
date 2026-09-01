//! Pluggable object storage.
//!
//! The service layer owns validation — size caps, content sniffing, ownership
//! and org membership — and hands a finished object to a backend. That split
//! means switching from local disk to S3 changes where bytes live without
//! touching a single authorization check.
//!
//! Uploads are streamed to a temporary local file first, so the size cap and
//! MIME sniffing still run before anything leaves the process, and a 10 MB
//! upload never has to sit in memory.

use std::path::{Path, PathBuf};
use std::pin::Pin;

use bytes::Bytes;
use futures_util::Stream;

use crate::error::AppError;

pub mod local;
pub mod s3;

pub use local::LocalBackend;
pub use s3::S3Backend;

/// A stored object opened for reading.
pub struct StoredObject {
    pub stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    pub len: u64,
}

#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Human-readable name, for startup logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Persist a finished, already-validated file.
    async fn put_file(
        &self,
        key: &str,
        local_path: &Path,
        content_type: &str,
    ) -> Result<(), AppError>;

    async fn open(&self, key: &str) -> Result<StoredObject, AppError>;

    async fn delete(&self, key: &str) -> Result<(), AppError>;

    /// A backend-native presigned download URL, letting the client fetch bytes
    /// without transiting this service.
    ///
    /// `None` means the backend cannot presign, and the caller should fall back
    /// to the application's own HMAC-signed URLs, which are served by this
    /// process.
    async fn presign_get(&self, _key: &str, _ttl_seconds: i64) -> Result<Option<String>, AppError> {
        Ok(None)
    }

    /// A backend-native presigned upload URL, so large uploads never pass
    /// through this service at all.
    async fn presign_put(
        &self,
        _key: &str,
        _content_type: &str,
        _ttl_seconds: i64,
    ) -> Result<Option<String>, AppError> {
        Ok(None)
    }
}

/// Reject anything that is not a generated storage key before it reaches a
/// backend. Keys are minted by this service, never supplied by a caller, so a
/// strict allowlist makes traversal impossible by construction rather than by
/// blocklist — and it protects the S3 backend from key injection just as it
/// protects the local one from `../`.
pub fn validate_storage_key(key: &str) -> Result<(), AppError> {
    let valid = !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        && !key.contains("..")
        && !key.starts_with('.');

    if valid {
        Ok(())
    } else {
        Err(AppError::BadRequest("Invalid storage key".to_string()))
    }
}

/// Join a validated key onto a root directory.
pub fn local_path_for(root: &Path, key: &str) -> Result<PathBuf, AppError> {
    validate_storage_key(key)?;
    Ok(root.join(key))
}
