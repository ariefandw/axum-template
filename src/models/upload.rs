use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UploadResponse {
    pub id: Uuid,
    pub original_filename: String,
    pub stored_filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub url: String,
}
