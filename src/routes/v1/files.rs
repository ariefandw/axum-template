use std::sync::Arc;

use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use serde::Deserialize;
use tokio_util::io::ReaderStream;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::{AuthUser, OptionalAuthUser},
    models::api_key::ApiScope,
    models::pagination::{PageMeta, PageParams},
    models::upload::{
        PresignedUploadRequest, PresignedUploadResponse, SignedUrlResponse, UploadResponse,
    },
    services::{audit::AuditService, auth::RequestContext, storage::StorageService},
    state::AppState,
};

/// Signature parameters accepted in place of a bearer token, so a signed URL can
/// be handed to a browser or CDN.
#[derive(Debug, Deserialize, IntoParams)]
pub struct SignedAccessQuery {
    pub expires: Option<i64>,
    pub signature: Option<String>,
    /// Reserved key, present on presigned upload URLs.
    pub key: Option<String>,
}

#[utoipa::path(
    post, path = "/upload",
    responses(
        (status = 201, description = "File uploaded", body = ApiResponse<UploadResponse>),
        (status = 400, description = "Missing or unacceptable file", body = ApiErrorResponse),
        (status = 413, description = "File exceeds the size limit", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Storage"
)]
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    ctx: RequestContext,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<ApiResponse<UploadResponse>>), AppError> {
    auth_user.require_scope(ApiScope::FilesWrite)?;
    let mut visibility = String::from("private");
    let mut org_id: Option<Uuid> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to parse multipart: {e}")))?
    {
        match field.name() {
            Some("visibility") => {
                visibility = field.text().await.unwrap_or_else(|_| "private".into());
            }
            // Uploading into an organization requires membership, checked in the
            // service before any bytes are written.
            Some("org_id") => {
                let raw = field.text().await.unwrap_or_default();
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    org_id =
                        Some(Uuid::parse_str(trimmed).map_err(|_| {
                            AppError::BadRequest("org_id must be a UUID".to_string())
                        })?);
                }
            }
            Some("file") => {
                let record = StorageService::save_upload_field(
                    &state,
                    auth_user.id,
                    org_id,
                    field,
                    &visibility,
                )
                .await?;

                AuditService::record_best_effort(
                    &state,
                    Some(auth_user.id),
                    "file.uploaded",
                    "file",
                    Some(&record.id.to_string()),
                    &ctx,
                    Some(serde_json::json!({
                        "mime_type": record.mime_type,
                        "size_bytes": record.size_bytes,
                        "visibility": record.visibility,
                        "org_id": record.org_id,
                    })),
                )
                .await;

                return Ok((
                    StatusCode::CREATED,
                    Json(ApiResponse::success(record.into())),
                ));
            }
            _ => {}
        }
    }

    Err(AppError::BadRequest(
        "Missing 'file' multipart field".to_string(),
    ))
}

#[utoipa::path(
    post, path = "/presigned-url", request_body = PresignedUploadRequest,
    responses(
        (status = 200, description = "Signed, expiring upload grant", body = ApiResponse<PresignedUploadResponse>),
        (status = 400, description = "Unacceptable content type", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Storage"
)]
pub async fn create_presigned_url(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<PresignedUploadRequest>,
) -> Result<Json<ApiResponse<PresignedUploadResponse>>, AppError> {
    auth_user.require_scope(ApiScope::FilesWrite)?;
    payload.validate()?;
    let res = StorageService::generate_presigned_upload(&state, &payload)?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    get, path = "/{id}/signed-url",
    params(("id" = Uuid, Path, description = "File ID")),
    responses(
        (status = 200, description = "Signed, expiring download URL", body = ApiResponse<SignedUrlResponse>),
        (status = 404, description = "File not found", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Storage"
)]
pub async fn create_signed_download_url(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<SignedUrlResponse>>, AppError> {
    auth_user.require_scope(ApiScope::FilesRead)?;
    let record = StorageService::load_record(&state, id).await?;
    StorageService::authorize_write(&state, &record, auth_user.id, &auth_user.role).await?;
    Ok(Json(ApiResponse::success(
        StorageService::generate_signed_download(&state, &record),
    )))
}

/// Download a file.
///
/// Access requires one of: the file being public, a bearer token for its owner
/// or an administrator, or a valid unexpired signature. Callers who fail all
/// three get 404 rather than 403, so this cannot be used to probe for file IDs.
#[utoipa::path(
    get, path = "/{id}",
    params(("id" = Uuid, Path, description = "File ID"), SignedAccessQuery),
    responses(
        (status = 200, description = "File contents", content_type = "application/octet-stream"),
        (status = 404, description = "File not found", body = ApiErrorResponse)
    ),
    tag = "Storage"
)]
pub async fn get_file(
    State(state): State<Arc<AppState>>,
    OptionalAuthUser(viewer): OptionalAuthUser,
    Path(id): Path<Uuid>,
    Query(signed): Query<SignedAccessQuery>,
) -> Result<Response, AppError> {
    let record = StorageService::load_record(&state, id).await?;

    let signature_ok = match (signed.expires, signed.signature.as_deref()) {
        (Some(expires), Some(signature)) => {
            StorageService::verify_signature(&state, "GET", &id.to_string(), expires, signature)
        }
        _ => false,
    };

    if !signature_ok {
        // A key-authenticated reader also needs the files:read scope.
        if let Some(v) = viewer.as_ref() {
            v.require_scope(ApiScope::FilesRead)?;
        }
        StorageService::authorize_read(
            &state,
            &record,
            viewer.as_ref().map(|v| (v.id, v.role.as_str())),
        )
        .await?;
    }

    let (file, len) = StorageService::open_file(&state, &record).await?;
    let body = axum::body::Body::from_stream(ReaderStream::new(file));

    let mut response = Response::new(body);
    let headers = response.headers_mut();

    // The stored MIME type is served back, rather than flattening everything to
    // application/octet-stream and discarding what was detected at upload.
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&record.mime_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    // Never render user content inline in this origin's context.
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            record.original_name.replace('"', "")
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    if let Some(Ok(etag)) = record
        .checksum_sha256
        .as_deref()
        .map(|c| HeaderValue::from_str(&format!("\"{c}\"")))
    {
        headers.insert(header::ETAG, etag);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if record.visibility == "public" {
            "public, max-age=3600"
        } else {
            "private, no-store"
        }),
    );

    Ok(response)
}

/// List the files belonging to an organization the caller is a member of.
#[utoipa::path(
    get, path = "/org/{org_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        PageParams
    ),
    responses(
        (status = 200, description = "Files owned by the organization", body = ApiResponse<Vec<UploadResponse>>),
        (status = 404, description = "Organization not found or caller is not a member", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Storage"
)]
pub async fn list_org_files(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(org_id): Path<Uuid>,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<UploadResponse>>>, AppError> {
    auth_user.require_scope(ApiScope::FilesRead)?;

    let (files, total) = StorageService::list_org_files(
        &state,
        org_id,
        auth_user.id,
        params.limit() as i64,
        params.offset() as i64,
    )
    .await?;

    let meta = PageMeta::new(params.page(), params.page_size(), total as u64);
    Ok(Json(ApiResponse::with_meta(
        files.into_iter().map(Into::into).collect(),
        serde_json::to_value(meta).unwrap_or_default(),
    )))
}

#[utoipa::path(
    delete, path = "/{id}",
    params(("id" = Uuid, Path, description = "File ID")),
    responses(
        (status = 200, description = "File deleted", body = ApiResponse<String>),
        (status = 404, description = "File not found or not yours", body = ApiErrorResponse)
    ),
    security(("bearer_auth" = [])), tag = "Storage"
)]
pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    ctx: RequestContext,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    auth_user.require_scope(ApiScope::FilesWrite)?;
    let record = StorageService::load_record(&state, id).await?;
    // Ownership check: any authenticated caller could previously delete any file.
    StorageService::authorize_write(&state, &record, auth_user.id, &auth_user.role).await?;

    let msg = StorageService::delete_file(&state, &record).await?;

    AuditService::record_best_effort(
        &state,
        Some(auth_user.id),
        "file.deleted",
        "file",
        Some(&record.id.to_string()),
        &ctx,
        None,
    )
    .await;

    Ok(Json(ApiResponse::success(msg)))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(upload_file))
        .routes(routes!(create_presigned_url))
        .routes(routes!(create_signed_download_url))
        .routes(routes!(list_org_files))
        .routes(routes!(get_file))
        .routes(routes!(delete_file))
}
