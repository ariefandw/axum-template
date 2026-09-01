use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UploadResponse {
    pub id: String,
    pub filename: String,
    pub original_name: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PresignedUploadRequest {
    #[validate(length(min = 1, message = "Filename is required"))]
    pub filename: String,
    #[validate(length(min = 3, message = "MIME type is required"))]
    pub content_type: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PresignedUploadResponse {
    pub key: String,
    pub upload_url: String,
    pub file_url: String,
    pub expires_in_seconds: u64,
}
