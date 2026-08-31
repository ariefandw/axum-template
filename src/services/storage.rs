use std::{path::Path, sync::Arc};
use axum::extract::multipart::Field;
use tokio::{fs, io::AsyncWriteExt};
use uuid::Uuid;

use crate::{error::AppError, models::upload::UploadResponse, state::AppState};

const MAX_FILE_SIZE_BYTES: usize = 10 * 1024 * 1024; // 10MB
const ALLOWED_MIME_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "application/pdf",
    "text/plain",
    "application/json",
];

pub struct StorageService;

impl StorageService {
    pub async fn save_upload_field(
        state: &Arc<AppState>,
        mut field: Field<'_>,
    ) -> Result<UploadResponse, AppError> {
        let original_filename = field
            .file_name()
            .unwrap_or("unknown_file")
            .to_string();

        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();

        // 1. MIME Validation
        if !ALLOWED_MIME_TYPES.contains(&content_type.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Unsupported file type '{content_type}'. Allowed types: jpeg, png, webp, gif, pdf, txt, json"
            )));
        }

        // 2. Extract safe extension
        let extension = Path::new(&original_filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("bin");

        let file_id = Uuid::now_v7();
        let stored_filename = format!("{file_id}.{extension}");
        let upload_dir = &state.config.upload_dir;

        // 3. Ensure target directory exists
        fs::create_dir_all(upload_dir).await.map_err(|e| {
            AppError::Internal(format!("Failed to create upload directory: {e}").into())
        })?;

        let destination_path = format!("{upload_dir}/{stored_filename}");
        let mut file = fs::File::create(&destination_path).await.map_err(|e| {
            AppError::Internal(format!("Failed to create destination file: {e}").into())
        })?;

        let mut total_bytes = 0;

        // 4. Stream chunks directly to disk with bounded memory
        while let Some(chunk) = field.chunk().await.map_err(|e| {
            AppError::BadRequest(format!("Failed to read multipart chunk: {e}"))
        })? {
            total_bytes += chunk.len();
            if total_bytes > MAX_FILE_SIZE_BYTES {
                // Delete partial file on limit violation
                let _ = fs::remove_file(&destination_path).await;
                return Err(AppError::BadRequest(format!(
                    "File exceeds maximum allowed size of {} MB",
                    MAX_FILE_SIZE_BYTES / (1024 * 1024)
                )));
            }

            file.write_all(&chunk).await.map_err(|e| {
                AppError::Internal(format!("Failed to write chunk to disk: {e}").into())
            })?;
        }

        file.flush().await.map_err(|e| {
            AppError::Internal(format!("Failed to flush file to disk: {e}").into())
        })?;

        let url = format!("/api/v1/files/{stored_filename}");

        tracing::info!(
            file_id = %file_id,
            filename = %original_filename,
            size = total_bytes,
            "File uploaded successfully"
        );

        Ok(UploadResponse {
            id: file_id,
            original_filename,
            stored_filename,
            content_type,
            size_bytes: total_bytes,
            url,
        })
    }
}
