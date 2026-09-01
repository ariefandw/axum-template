use std::path::Path;
use std::sync::Arc;
use axum::extract::multipart::Field;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::upload::{PresignedUploadRequest, PresignedUploadResponse, UploadResponse},
    state::AppState,
};

pub struct StorageService;

impl StorageService {
    pub async fn save_upload_field(
        state: &Arc<AppState>,
        mut field: Field<'_>,
    ) -> Result<UploadResponse, AppError> {
        let original_name = field
            .file_name()
            .unwrap_or("unnamed_file")
            .to_string();

        let ext = Path::new(&original_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
            .to_lowercase();

        let file_id = Uuid::now_v7();
        let stored_filename = format!("{file_id}.{ext}");

        fs::create_dir_all(&state.config.upload_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create upload dir: {e}").into()))?;

        let dest_path = format!("{}/{}", state.config.upload_dir, stored_filename);
        let mut file = fs::File::create(&dest_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create file: {e}").into()))?;

        let mut total_bytes: u64 = 0;
        const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10MB Limit

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to read chunk: {e}")))?
        {
            total_bytes += chunk.len() as u64;
            if total_bytes > MAX_BYTES {
                drop(file);
                let _ = fs::remove_file(&dest_path).await;
                return Err(AppError::BadRequest("File exceeds 10MB limit".to_string()));
            }

            file.write_all(&chunk)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to write chunk: {e}").into()))?;
        }

        let mime_type = match ext.as_str() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "webp" => "image/webp",
            "gif" => "image/gif",
            "pdf" => "application/pdf",
            "txt" => "text/plain",
            "json" => "application/json",
            _ => "application/octet-stream",
        };

        Ok(UploadResponse {
            id: file_id.to_string(),
            filename: stored_filename.clone(),
            original_name,
            size_bytes: total_bytes,
            mime_type: mime_type.to_string(),
            url: format!("/api/v1/files/{stored_filename}"),
        })
    }

    pub async fn delete_file(
        state: &Arc<AppState>,
        filename: &str,
    ) -> Result<String, AppError> {
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            return Err(AppError::BadRequest("Invalid filename".to_string()));
        }

        let file_path = format!("{}/{}", state.config.upload_dir, filename);
        if !fs::try_exists(&file_path).await.unwrap_or(false) {
            return Err(AppError::NotFound(format!("File '{filename}' not found")));
        }

        fs::remove_file(&file_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete file: {e}").into()))?;

        Ok(format!("File '{filename}' deleted successfully"))
    }

    pub fn generate_presigned_url(
        _state: &Arc<AppState>,
        req: PresignedUploadRequest,
    ) -> Result<PresignedUploadResponse, AppError> {
        let file_id = Uuid::now_v7();
        let ext = Path::new(&req.filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
            .to_lowercase();

        let key = format!("{file_id}.{ext}");
        let upload_url = format!("/api/v1/files/upload"); // In S3/R2 mode, this would be an AWS SigV4 signed URL
        let file_url = format!("/api/v1/files/{key}");

        Ok(PresignedUploadResponse {
            key,
            upload_url,
            file_url,
            expires_in_seconds: 900, // 15 mins
        })
    }
}
