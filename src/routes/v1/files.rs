use std::sync::Arc;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use tokio::fs;
use tokio_util::io::ReaderStream;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::upload::UploadResponse,
    services::storage::StorageService,
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/api/v1/files/upload",
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
    get,
    path = "/api/v1/files/{filename}",
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
