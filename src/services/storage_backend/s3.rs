//! S3-compatible object storage.
//!
//! Works against AWS S3 and against the many services that speak its API
//! (Cloudflare R2, MinIO, Wasabi, and regional providers), which is why the
//! endpoint and path-style addressing are configurable rather than derived from
//! a region.
//!
//! This is the backend that makes horizontal scaling possible: object bytes stop
//! living on one replica's disk, and presigned URLs let clients upload and
//! download without the bytes transiting this service at all.

use std::path::Path;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region},
    presigning::PresigningConfig,
    primitives::ByteStream,
};
use tokio_util::io::ReaderStream;

use crate::{config::S3Config, error::AppError};

use super::{StorageBackend, StoredObject, validate_storage_key};

pub struct S3Backend {
    client: Client,
    bucket: String,
    /// Prepended to every key, so one bucket can host several environments or
    /// applications without collision.
    prefix: String,
}

impl S3Backend {
    pub fn new(config: &S3Config) -> Self {
        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.expose().to_string(),
            None,
            None,
            "axum-template-config",
        );

        let mut builder = aws_sdk_s3::config::Builder::default()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            // Non-AWS providers are almost always path-style: the virtual-hosted
            // form would require per-bucket DNS they do not publish.
            .force_path_style(config.force_path_style);

        if let Some(endpoint) = config.endpoint.as_deref() {
            builder = builder.endpoint_url(endpoint);
        }

        Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            prefix: config.prefix.trim_matches('/').to_string(),
        }
    }

    /// Namespace a validated key under the configured prefix.
    fn object_key(&self, key: &str) -> Result<String, AppError> {
        validate_storage_key(key)?;
        Ok(if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.prefix, key)
        })
    }

    fn presigning(ttl_seconds: i64) -> Result<PresigningConfig, AppError> {
        // S3 caps presigned URL lifetime at one week.
        let secs = ttl_seconds.clamp(1, 604_800) as u64;
        PresigningConfig::expires_in(Duration::from_secs(secs))
            .map_err(|e| AppError::Internal(format!("Invalid presigning config: {e}").into()))
    }

    /// Verify the bucket is reachable and the credentials work, so a
    /// misconfiguration surfaces at startup rather than on a user's first upload.
    pub async fn check_connectivity(&self) -> Result<(), AppError> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| {
                AppError::ServiceUnavailable(format!(
                    "S3 bucket '{}' is not reachable: {}",
                    self.bucket,
                    // Only the service message, never the signed request.
                    e.into_service_error()
                        .meta()
                        .message()
                        .unwrap_or("unknown error")
                ))
            })?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageBackend for S3Backend {
    fn name(&self) -> &'static str {
        "s3"
    }

    async fn put_file(
        &self,
        key: &str,
        local_path: &Path,
        content_type: &str,
    ) -> Result<(), AppError> {
        let object_key = self.object_key(key)?;

        // Streamed from the temp file rather than buffered, so a large upload
        // never has to sit in memory.
        let body = ByteStream::from_path(local_path).await.map_err(|e| {
            AppError::Internal(format!("Failed to read upload for transfer: {e}").into())
        })?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .content_type(content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(key = %object_key, error = ?e, "S3 put_object failed");
                AppError::Internal("Failed to store object".into())
            })?;

        Ok(())
    }

    async fn open(&self, key: &str) -> Result<StoredObject, AppError> {
        let object_key = self.object_key(key)?;

        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|_| AppError::NotFound("File not found".to_string()))?;

        let len = output.content_length().unwrap_or(0).max(0) as u64;

        // ByteStream exposes an AsyncRead rather than a Stream, so the body is
        // bridged back to a chunk stream. Bytes are still streamed: nothing is
        // buffered in full here.
        let reader = output.body.into_async_read();

        Ok(StoredObject {
            stream: Box::pin(ReaderStream::new(reader)),
            len,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let object_key = self.object_key(key)?;

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(key = %object_key, error = ?e, "S3 delete_object failed");
                AppError::Internal("Failed to delete object".into())
            })?;

        Ok(())
    }

    async fn presign_get(&self, key: &str, ttl_seconds: i64) -> Result<Option<String>, AppError> {
        let object_key = self.object_key(key)?;
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .presigned(Self::presigning(ttl_seconds)?)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to presign download");
                AppError::Internal("Failed to presign download URL".into())
            })?;

        Ok(Some(request.uri().to_string()))
    }

    async fn presign_put(
        &self,
        key: &str,
        content_type: &str,
        ttl_seconds: i64,
    ) -> Result<Option<String>, AppError> {
        let object_key = self.object_key(key)?;
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .content_type(content_type)
            .presigned(Self::presigning(ttl_seconds)?)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to presign upload");
                AppError::Internal("Failed to presign upload URL".into())
            })?;

        Ok(Some(request.uri().to_string()))
    }
}
