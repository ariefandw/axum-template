use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// A stored object. Uploads were previously untracked on disk, which left the
/// filename as the only access-control mechanism; ownership and visibility now
/// live in this row and every read and delete is authorized against it.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct FileRecord {
    pub id: Uuid,
    pub owner_id: Option<Uuid>,
    /// Owning organization, when the file belongs to a tenant rather than to an
    /// individual. This column existed from the tenancy migration but was never
    /// read or written, so org membership granted no access to anything.
    pub org_id: Option<Uuid>,
    pub bucket: String,
    pub storage_key: String,
    pub original_name: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub checksum_sha256: Option<String>,
    pub visibility: String,
    /// `pending` until a presigned upload is confirmed present in storage.
    /// Reads only ever return `ready` rows.
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub const FILE_COLUMNS: &str = "id, owner_id, org_id, bucket, storage_key, original_name, \
                                mime_type, size_bytes, checksum_sha256, visibility, status, \
                                created_at";

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub storage_key: String,
    pub original_name: String,
    pub size_bytes: i64,
    pub mime_type: String,
    pub visibility: String,
    /// Relative download path. For a private file this needs a bearer token or a
    /// signed URL obtained from `/files/{id}/signed-url`.
    pub url: String,
}

impl From<FileRecord> for UploadResponse {
    fn from(f: FileRecord) -> Self {
        Self {
            url: format!("/api/v1/files/{}", f.id),
            id: f.id,
            org_id: f.org_id,
            storage_key: f.storage_key,
            original_name: f.original_name,
            size_bytes: f.size_bytes,
            mime_type: f.mime_type,
            visibility: f.visibility,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PresignedUploadRequest {
    #[validate(length(min = 1, max = 255, message = "Filename is required"))]
    pub filename: String,
    #[validate(length(min = 3, max = 127, message = "MIME type is required"))]
    pub content_type: String,
    pub size_bytes: Option<u64>,
    /// `private` (default) or `public`.
    pub visibility: Option<String>,
    /// Attribute the upload to an organization. Membership is verified before
    /// the reservation is made.
    pub org_id: Option<Uuid>,
}

/// A genuinely signed upload grant. The previous implementation returned a static
/// path with no signature and an advertised expiry that nothing enforced.
#[derive(Debug, Serialize, ToSchema)]
pub struct PresignedUploadResponse {
    /// The reserved file. A row already exists in `pending` state; call
    /// `POST /files/{id}/complete` once the bytes are uploaded.
    pub file_id: Uuid,
    pub storage_key: String,
    /// Absolute URL carrying the signature and expiry as query parameters.
    pub upload_url: String,
    pub file_url: String,
    /// Call this after the upload finishes, or the reservation is reaped and the
    /// object becomes unreachable.
    pub complete_url: String,
    /// `PUT` for a direct-to-storage URL, `POST` for the multipart fallback.
    pub method: String,
    pub expires_at: DateTime<Utc>,
    pub expires_in_seconds: i64,
    pub max_bytes: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignedUrlResponse {
    pub url: String,
    pub expires_at: DateTime<Utc>,
    pub expires_in_seconds: i64,
}
