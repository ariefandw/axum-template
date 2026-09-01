//! Local filesystem backend.
//!
//! The default, and the right choice for development and single-node
//! deployments. It cannot serve a horizontally scaled deployment: a file written
//! by one replica is invisible to the others, and container-local storage does
//! not survive a restart. Use the S3 backend for anything multi-replica.

use std::path::{Path, PathBuf};

use tokio::fs;
use tokio_util::io::ReaderStream;

use crate::error::AppError;

use super::{StorageBackend, StoredObject, local_path_for};

pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[async_trait::async_trait]
impl StorageBackend for LocalBackend {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn put_file(
        &self,
        key: &str,
        local_path: &Path,
        _content_type: &str,
    ) -> Result<(), AppError> {
        let dest = local_path_for(&self.root, key)?;
        fs::create_dir_all(&self.root)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create upload dir: {e}").into()))?;

        // Rename when possible (same filesystem, atomic); copy otherwise.
        match fs::rename(local_path, &dest).await {
            Ok(()) => Ok(()),
            Err(_) => {
                fs::copy(local_path, &dest)
                    .await
                    .map_err(|e| AppError::Internal(format!("Failed to store file: {e}").into()))?;
                let _ = fs::remove_file(local_path).await;
                Ok(())
            }
        }
    }

    async fn open(&self, key: &str) -> Result<StoredObject, AppError> {
        let path = local_path_for(&self.root, key)?;
        let file = fs::File::open(&path)
            .await
            .map_err(|_| AppError::NotFound("File not found".to_string()))?;
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);

        Ok(StoredObject {
            stream: Box::pin(ReaderStream::new(file)),
            len,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let path = local_path_for(&self.root, key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // Already gone is success: the caller's intent is satisfied.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::Internal(
                format!("Failed to delete stored object: {e}").into(),
            )),
        }
    }
}
