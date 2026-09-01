use std::sync::Arc;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use tokio::fs;
use tokio_util::io::ReaderStream;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::upload::{PresignedUploadRequest, PresignedUploadResponse, UploadResponse},
    services::storage::StorageService,
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/upload",
    responses(
        (status = 201, description = "File uploaded successfully", body = ApiResponse<UploadResponse>),
        (status = 400, description = "Invalid file or exceeds limit", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Storage"
)]
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<ApiResponse<UploadResponse>>), AppError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to parse multipart: {e}")))?
    {
        if field.name() == Some("file") {
            let res = StorageService::save_upload_field(&state, field).await?;
            return Ok((StatusCode::CREATED, Json(ApiResponse::success(res))));
        }
    }

    Err(AppError::BadRequest("Missing 'file' multipart field".to_string()))
}

#[utoipa::path(
    post,
    path = "/presigned-url",
    request_body = PresignedUploadRequest,
    responses(
        (status = 200, description = "Presigned direct upload URL generated", body = ApiResponse<PresignedUploadResponse>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Storage"
)]
pub async fn create_presigned_url(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser,
    Json(payload): Json<PresignedUploadRequest>,
) -> Result<Json<ApiResponse<PresignedUploadResponse>>, AppError> {
    payload.validate()?;
    let res = StorageService::generate_presigned_url(&state, payload)?;
    Ok(Json(ApiResponse::success(res)))
}

#[utoipa::path(
    get,
    path = "/{filename}",
    params(
        ("filename" = String, Path, description = "Stored filename (e.g. uuid.png)")
    ),
    responses(
        (status = 200, description = "File contents stream", content_type = "application/octet-stream"),
        (status = 404, description = "File not found", body = ApiErrorResponse)
    ),
    tag = "Storage"
)]
pub async fn get_file(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<Response, AppError> {
    // 1. Path traversal security check
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::BadRequest("Invalid filename".to_string()));
    }

    let file_path = format!("{}/{}", state.config.upload_dir, filename);

    let file = fs::File::open(&file_path)
        .await
        .map_err(|_| AppError::NotFound(format!("File '{filename}' not found")))?;

    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );

    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/{filename}",
    params(
        ("filename" = String, Path, description = "Stored filename (e.g. uuid.png)")
    ),
    responses(
        (status = 200, description = "File deleted successfully", body = ApiResponse<String>),
        (status = 404, description = "File not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Storage"
)]
pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser,
    Path(filename): Path<String>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let msg = StorageService::delete_file(&state, &filename).await?;
    Ok(Json(ApiResponse::success(msg)))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(upload_file))
        .routes(routes!(create_presigned_url))
        .routes(routes!(get_file))
        .routes(routes!(delete_file))
}
