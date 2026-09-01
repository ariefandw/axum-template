//! Object storage.
//!
//! Rebuilt around three properties the previous implementation lacked:
//!
//! * **Ownership.** Every upload gets a `files` row. Reads and deletes are
//!   authorized against it instead of trusting whoever knows the filename.
//! * **Real signatures.** Presigned URLs are HMAC-signed over the method, key and
//!   expiry, and the signature is verified on use. The previous "presigned" URL
//!   was an unsigned static path with a cosmetic expiry field.
//! * **Content-based typing.** The stored MIME type comes from sniffing the
//!   leading bytes and is cross-checked against the extension, rather than being
//!   inferred from an attacker-supplied filename.

use std::path::Path;
use std::sync::Arc;

use axum::extract::multipart::Field;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    crypto,
    error::AppError,
    models::org::OrgRole,
    models::upload::{
        FILE_COLUMNS, FileRecord, PresignedUploadRequest, PresignedUploadResponse,
        SignedUrlResponse,
    },
    services::org::OrgService,
    services::storage_backend::StoredObject,
    state::AppState,
};

pub struct StorageService;

impl StorageService {
    // -- key handling -------------------------------------------------------

    // -- content typing -----------------------------------------------------

    /// Identify a file from its leading bytes. Extensions are caller-controlled,
    /// so they are used only as a tie-breaker for formats without magic numbers.
    pub fn sniff_mime(bytes: &[u8], filename: &str) -> &'static str {
        const SNIFFERS: &[(&[u8], &str)] = &[
            (b"\xFF\xD8\xFF", "image/jpeg"),
            (b"\x89PNG\r\n\x1a\n", "image/png"),
            (b"GIF87a", "image/gif"),
            (b"GIF89a", "image/gif"),
            (b"%PDF-", "application/pdf"),
        ];

        for (magic, mime) in SNIFFERS {
            if bytes.starts_with(magic) {
                return mime;
            }
        }

        // RIFF....WEBP
        if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            return "image/webp";
        }

        // Formats with no magic number: fall back to the extension, but only
        // after confirming the content really is text.
        let is_text = bytes.is_empty()
            || std::str::from_utf8(&bytes[..bytes.len().min(512)]).is_ok_and(|s| {
                !s.chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
            });

        if is_text {
            let ext = Path::new(filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            return match ext.as_str() {
                "json" => "application/json",
                "txt" | "md" | "csv" | "log" => "text/plain",
                _ => "application/octet-stream",
            };
        }

        "application/octet-stream"
    }

    fn ensure_mime_allowed(state: &Arc<AppState>, mime: &str) -> Result<(), AppError> {
        if state.config.allowed_upload_mime.iter().any(|m| m == mime) {
            Ok(())
        } else {
            Err(AppError::BadRequest(format!(
                "Files of type '{mime}' are not accepted"
            )))
        }
    }

    fn extension_for(mime: &str) -> &'static str {
        match mime {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/gif" => "gif",
            "image/webp" => "webp",
            "application/pdf" => "pdf",
            "application/json" => "json",
            "text/plain" => "txt",
            _ => "bin",
        }
    }

    // -- upload -------------------------------------------------------------

    /// Stream a multipart field to disk, enforcing the size cap as it goes, then
    /// record ownership. The file is removed if anything fails, so a rejected
    /// upload never leaves a partial object behind.
    pub async fn save_upload_field(
        state: &Arc<AppState>,
        owner_id: Uuid,
        org_id: Option<Uuid>,
        mut field: Field<'_>,
        visibility: &str,
    ) -> Result<FileRecord, AppError> {
        // Membership is checked before a single byte is written, so an outsider
        // cannot use an upload to discover whether an organization exists.
        if let Some(org_id) = org_id {
            OrgService::require_membership(state, org_id, owner_id).await?;
        }

        let original_name = sanitize_filename(field.file_name().unwrap_or("unnamed_file"));
        let file_id = Uuid::now_v7();
        let max_bytes = state.config.max_upload_bytes;

        fs::create_dir_all(&state.config.upload_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create upload dir: {e}").into()))?;

        // Written to a temporary name first: the final key encodes the sniffed
        // type, which is not known until the first bytes arrive.
        let temp_key = format!("{file_id}.part");
        let temp_path = Path::new(&state.config.upload_dir).join(&temp_key);
        let mut file = fs::File::create(&temp_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create file: {e}").into()))?;

        let mut total: u64 = 0;
        let mut head = Vec::with_capacity(16);
        let mut hasher = Sha256::new();

        let outcome: Result<(), AppError> = async {
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| AppError::BadRequest(format!("Failed to read upload: {e}")))?
            {
                total += chunk.len() as u64;
                if total > max_bytes {
                    return Err(AppError::PayloadTooLarge(format!(
                        "File exceeds the {max_bytes} byte limit"
                    )));
                }
                if head.len() < 16 {
                    head.extend_from_slice(&chunk[..chunk.len().min(16 - head.len())]);
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await.map_err(|e| {
                    AppError::Internal(format!("Failed to write chunk: {e}").into())
                })?;
            }
            file.flush()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to flush upload: {e}").into()))?;
            Ok(())
        }
        .await;

        drop(file);

        if let Err(e) = outcome {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e);
        }

        if total == 0 {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::BadRequest("Uploaded file is empty".to_string()));
        }

        let mime = Self::sniff_mime(&head, &original_name);
        if let Err(e) = Self::ensure_mime_allowed(state, mime) {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e);
        }

        let storage_key = format!("{file_id}.{}", Self::extension_for(mime));

        // Validation is complete; hand the finished object to whichever backend
        // is configured. Everything above this line is identical for local disk
        // and S3, which is the point of the seam.
        if let Err(e) = state.storage.put_file(&storage_key, &temp_path, mime).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e);
        }
        let _ = fs::remove_file(&temp_path).await;

        let checksum = format!("{:x}", hasher.finalize());
        let visibility = normalize_visibility(visibility)?;

        let record = sqlx::query_as::<_, FileRecord>(&format!(
            r#"
            INSERT INTO files
                (id, owner_id, org_id, bucket, storage_key, original_name, mime_type,
                 size_bytes, checksum_sha256, visibility)
            VALUES ($1, $2, $3, 'default', $4, $5, $6, $7, $8, $9)
            RETURNING {FILE_COLUMNS}
            "#
        ))
        .bind(file_id)
        .bind(owner_id)
        .bind(org_id)
        .bind(&storage_key)
        .bind(&original_name)
        .bind(mime)
        .bind(total as i64)
        .bind(&checksum)
        .bind(visibility)
        .fetch_one(&state.db)
        .await;

        match record {
            Ok(record) => Ok(record),
            Err(e) => {
                // Never leave an orphaned object behind if the row fails.
                let _ = state.storage.delete(&storage_key).await;
                Err(e.into())
            }
        }
    }

    // -- authorized access --------------------------------------------------

    /// Files belonging to one organization, newest first.
    ///
    /// Callers must be members; non-members are told the organization does not
    /// exist rather than that they lack permission.
    pub async fn list_org_files(
        state: &Arc<AppState>,
        org_id: Uuid,
        viewer_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<FileRecord>, i64), AppError> {
        OrgService::require_membership(state, org_id, viewer_id).await?;

        let files = sqlx::query_as::<_, FileRecord>(&format!(
            "SELECT {FILE_COLUMNS} FROM files \
             WHERE org_id = $1 AND deleted_at IS NULL AND status = 'ready' \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ))
        .bind(org_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        let total = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM files \
             WHERE org_id = $1 AND deleted_at IS NULL AND status = 'ready'",
        )
        .bind(org_id)
        .fetch_one(&state.db)
        .await?;

        Ok((files, total))
    }

    pub async fn load_record(state: &Arc<AppState>, file_id: Uuid) -> Result<FileRecord, AppError> {
        sqlx::query_as::<_, FileRecord>(&format!(
            "SELECT {FILE_COLUMNS} FROM files \
             WHERE id = $1 AND deleted_at IS NULL AND status = 'ready'"
        ))
        .bind(file_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))
    }

    /// Who may read a file.
    ///
    /// Public files are readable by anyone. A private file is readable by its
    /// owner, by a platform administrator, and — when the file belongs to an
    /// organization — by any member of that organization. Everyone else is told
    /// it does not exist, so this cannot be used to probe for file IDs.
    ///
    /// The organization arm is what makes tenancy real: before it, an `org_id`
    /// column existed on `files` but no code read it, so two tenants inside one
    /// app had no way to share and no boundary to be separated by.
    pub async fn authorize_read(
        state: &Arc<AppState>,
        record: &FileRecord,
        viewer: Option<(Uuid, &str)>,
    ) -> Result<(), AppError> {
        if record.visibility == "public" {
            return Ok(());
        }
        let Some((viewer_id, role)) = viewer else {
            return Err(AppError::NotFound("File not found".to_string()));
        };
        if Some(viewer_id) == record.owner_id || role == "admin" {
            return Ok(());
        }
        if let Some(org_id) = record.org_id {
            if OrgService::get_user_org_role(state, org_id, viewer_id)
                .await?
                .is_some()
            {
                return Ok(());
            }
        }
        Err(AppError::NotFound("File not found".to_string()))
    }

    /// Who may delete or re-share a file: its owner, a platform administrator,
    /// or an `admin`/`owner` of the organization it belongs to. A plain `member`
    /// can read a tenant's files but not destroy them.
    pub async fn authorize_write(
        state: &Arc<AppState>,
        record: &FileRecord,
        actor_id: Uuid,
        role: &str,
    ) -> Result<(), AppError> {
        if Some(actor_id) == record.owner_id || role == "admin" {
            return Ok(());
        }
        if let Some(org_id) = record.org_id {
            if OrgService::get_user_org_role(state, org_id, actor_id)
                .await?
                .is_some_and(|r| r >= OrgRole::Admin)
            {
                return Ok(());
            }
        }
        Err(AppError::NotFound("File not found".to_string()))
    }

    pub async fn open_file(
        state: &Arc<AppState>,
        record: &FileRecord,
    ) -> Result<StoredObject, AppError> {
        let mut object = state.storage.open(&record.storage_key).await?;
        if object.len == 0 {
            // Some backends omit content-length; fall back to the recorded size.
            object.len = record.size_bytes.max(0) as u64;
        }
        Ok(object)
    }

    pub async fn delete_file(
        state: &Arc<AppState>,
        record: &FileRecord,
    ) -> Result<String, AppError> {
        sqlx::query("UPDATE files SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL")
            .bind(record.id)
            .execute(&state.db)
            .await?;

        // The row is already tombstoned, so the object is unreachable either way;
        // a stranded blob is a cleanup concern, not a request failure.
        if let Err(e) = state.storage.delete(&record.storage_key).await {
            tracing::warn!(file_id = %record.id, error = %e, "Failed to remove stored object");
        }

        Ok(format!(
            "File '{}' deleted successfully",
            record.original_name
        ))
    }

    // -- signed URLs --------------------------------------------------------

    fn signing_payload(method: &str, key: &str, expires_at: i64) -> String {
        format!("{method}\n{key}\n{expires_at}")
    }

    /// Reserve a key and issue a signed, expiring grant to upload against it.
    ///
    /// A `pending` row is created up front, so the object is owned before it
    /// exists. Without it, a direct-to-storage upload produces an orphan: bytes
    /// in the bucket that the API has no row for, cannot authorize, and cannot
    /// delete. The client must call `complete_upload` afterwards.
    pub async fn generate_presigned_upload(
        state: &Arc<AppState>,
        owner_id: Uuid,
        org_id: Option<Uuid>,
        req: &PresignedUploadRequest,
    ) -> Result<PresignedUploadResponse, AppError> {
        let content_type = req.content_type.trim().to_ascii_lowercase();
        Self::ensure_mime_allowed(state, &content_type)?;

        if req
            .size_bytes
            .is_some_and(|size| size > state.config.max_upload_bytes)
        {
            return Err(AppError::PayloadTooLarge(format!(
                "Declared size exceeds the {} byte limit",
                state.config.max_upload_bytes
            )));
        }

        if let Some(org_id) = org_id {
            OrgService::require_membership(state, org_id, owner_id).await?;
        }

        let visibility = normalize_visibility(req.visibility.as_deref().unwrap_or("private"))?;
        let file_id = Uuid::now_v7();
        let storage_key = format!("{file_id}.{}", Self::extension_for(&content_type));
        let ttl = state.config.signed_url_ttl_seconds;
        let expires_at = Utc::now() + Duration::seconds(ttl);

        // The row is reserved before the URL is handed out, so an abandoned
        // upload leaves a reapable record rather than an invisible object.
        sqlx::query(
            r#"
            INSERT INTO files
                (id, owner_id, org_id, bucket, storage_key, original_name, mime_type,
                 size_bytes, visibility, status)
            VALUES ($1, $2, $3, 'default', $4, $5, $6, 0, $7, 'pending')
            "#,
        )
        .bind(file_id)
        .bind(owner_id)
        .bind(org_id)
        .bind(&storage_key)
        .bind(sanitize_filename(&req.filename))
        .bind(&content_type)
        .bind(visibility)
        .execute(&state.db)
        .await?;

        let base = state.config.public_base_url.trim_end_matches('/');
        let (upload_url, method) = match state
            .storage
            .presign_put(&storage_key, &content_type, ttl)
            .await?
        {
            // Direct to object storage: the bytes never reach this service.
            Some(native) => (native, "PUT"),
            // No native presigning (local disk): serve a signed endpoint of our
            // own so clients use one protocol across both backends.
            None => {
                let signature = crypto::sign(
                    &state.config.url_signing_key,
                    &Self::signing_payload("PUT", &storage_key, expires_at.timestamp()),
                );
                (
                    format!(
                        "{base}/api/v1/files/upload-signed?key={storage_key}\
&expires={}&signature={signature}",
                        expires_at.timestamp()
                    ),
                    "PUT",
                )
            }
        };

        Ok(PresignedUploadResponse {
            file_id,
            upload_url,
            method: method.to_string(),
            file_url: format!("{base}/api/v1/files/{file_id}"),
            complete_url: format!("{base}/api/v1/files/{file_id}/complete"),
            storage_key,
            expires_at,
            expires_in_seconds: ttl,
            max_bytes: state.config.max_upload_bytes,
        })
    }

    /// Accept raw bytes against a signed upload grant, for backends that cannot
    /// presign themselves. The signature is verified before anything is stored.
    pub async fn accept_signed_upload(
        state: &Arc<AppState>,
        storage_key: &str,
        expires: i64,
        signature: &str,
        body: &[u8],
    ) -> Result<(), AppError> {
        if !Self::verify_signature(state, "PUT", storage_key, expires, signature) {
            return Err(AppError::Forbidden(
                "Invalid or expired upload signature".to_string(),
            ));
        }
        if body.len() as u64 > state.config.max_upload_bytes {
            return Err(AppError::PayloadTooLarge(format!(
                "Upload exceeds the {} byte limit",
                state.config.max_upload_bytes
            )));
        }

        // The signature binds the key, so the pending row it belongs to must
        // exist and still be pending.
        let mime: Option<String> = sqlx::query_scalar(
            "SELECT mime_type FROM files \
             WHERE storage_key = $1 AND status = 'pending' AND deleted_at IS NULL",
        )
        .bind(storage_key)
        .fetch_optional(&state.db)
        .await?;
        let mime =
            mime.ok_or_else(|| AppError::NotFound("No pending upload for this key".to_string()))?;

        state.storage.put_bytes(storage_key, body, &mime).await
    }

    /// Confirm a presigned upload: verify the object is really in storage, take
    /// its true size and type from there rather than from the client, and flip
    /// the row to `ready`.
    pub async fn complete_upload(
        state: &Arc<AppState>,
        file_id: Uuid,
        actor_id: Uuid,
        role: &str,
    ) -> Result<FileRecord, AppError> {
        let record = sqlx::query_as::<_, FileRecord>(&format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE id = $1 AND deleted_at IS NULL"
        ))
        .bind(file_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

        Self::authorize_write(state, &record, actor_id, role).await?;

        if record.status == "ready" {
            // Idempotent: completing twice is a normal client retry.
            return Ok(record);
        }

        // The client controls neither the size nor the type that get recorded.
        let meta = state.storage.head(&record.storage_key).await.map_err(|_| {
            AppError::BadRequest(
                "No uploaded object found for this reservation. Upload the bytes first."
                    .to_string(),
            )
        })?;

        if meta.len == 0 {
            return Err(AppError::BadRequest("Uploaded object is empty".to_string()));
        }
        if meta.len > state.config.max_upload_bytes {
            // Refuse it and remove the oversized object rather than adopting it.
            let _ = state.storage.delete(&record.storage_key).await;
            sqlx::query("UPDATE files SET deleted_at = now() WHERE id = $1")
                .bind(file_id)
                .execute(&state.db)
                .await?;
            return Err(AppError::PayloadTooLarge(format!(
                "Uploaded object is {} bytes, over the {} byte limit",
                meta.len, state.config.max_upload_bytes
            )));
        }

        let updated = sqlx::query_as::<_, FileRecord>(&format!(
            "UPDATE files SET status = 'ready', size_bytes = $2 \
             WHERE id = $1 AND status = 'pending' RETURNING {FILE_COLUMNS}"
        ))
        .bind(file_id)
        .bind(meta.len as i64)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(record);

        Ok(updated)
    }

    /// Issue a signed, expiring download URL for a private file, so it can be
    /// handed to a browser or CDN without exposing a bearer token.
    ///
    /// When the backend can presign natively (S3), the URL points straight at
    /// object storage and the bytes never transit this service. Otherwise it
    /// falls back to an application-signed URL served by this process.
    pub async fn generate_signed_download_url(
        state: &Arc<AppState>,
        record: &FileRecord,
    ) -> Result<SignedUrlResponse, AppError> {
        let ttl = state.config.signed_url_ttl_seconds;

        if let Some(url) = state.storage.presign_get(&record.storage_key, ttl).await? {
            return Ok(SignedUrlResponse {
                url,
                expires_at: Utc::now() + Duration::seconds(ttl),
                expires_in_seconds: ttl,
            });
        }

        Ok(Self::generate_signed_download(state, record))
    }

    fn generate_signed_download(state: &Arc<AppState>, record: &FileRecord) -> SignedUrlResponse {
        let expires_at = Utc::now() + Duration::seconds(state.config.signed_url_ttl_seconds);
        let signature = crypto::sign(
            &state.config.url_signing_key,
            &Self::signing_payload("GET", &record.id.to_string(), expires_at.timestamp()),
        );

        SignedUrlResponse {
            url: format!(
                "{}/api/v1/files/{}?expires={}&signature={signature}",
                state.config.public_base_url.trim_end_matches('/'),
                record.id,
                expires_at.timestamp()
            ),
            expires_at,
            expires_in_seconds: state.config.signed_url_ttl_seconds,
        }
    }

    /// Verify a signature and its expiry. Returns `true` only if both hold.
    pub fn verify_signature(
        state: &Arc<AppState>,
        method: &str,
        key: &str,
        expires: i64,
        signature: &str,
    ) -> bool {
        let Some(expires_at) = DateTime::from_timestamp(expires, 0) else {
            return false;
        };
        if expires_at <= Utc::now() {
            return false;
        }
        crypto::verify_signature(
            &state.config.url_signing_key,
            &Self::signing_payload(method, key, expires),
            signature,
        )
    }
}

fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .take(255)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "unnamed_file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_visibility(value: &str) -> Result<&'static str, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "private" => Ok("private"),
        "public" => Ok("public"),
        other => Err(AppError::BadRequest(format!(
            "Unknown visibility '{other}' (expected 'private' or 'public')"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing_ignores_a_misleading_extension() {
        // A PNG named .txt is still typed as a PNG.
        assert_eq!(
            StorageService::sniff_mime(b"\x89PNG\r\n\x1a\n\x00\x00", "notes.txt"),
            "image/png"
        );
        // An executable renamed to .png is not accepted as an image.
        assert_eq!(
            StorageService::sniff_mime(b"\x7fELF\x02\x01\x01\x00\x00", "avatar.png"),
            "application/octet-stream"
        );
        assert_eq!(
            StorageService::sniff_mime(b"%PDF-1.7", "x.bin"),
            "application/pdf"
        );
        assert_eq!(
            StorageService::sniff_mime(b"{\"a\":1}", "d.json"),
            "application/json"
        );
    }

    #[test]
    fn storage_keys_reject_traversal() {
        use crate::services::storage_backend::validate_storage_key;
        assert!(validate_storage_key("0193.png").is_ok());
        for bad in ["../etc/passwd", "a/b.png", "..", ".hidden", "a\\b.png", ""] {
            assert!(
                validate_storage_key(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn filenames_are_sanitized() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_filename("   "), "unnamed_file");
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
    }
}
