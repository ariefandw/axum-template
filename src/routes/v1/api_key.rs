use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use std::sync::Arc;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::SessionUser,
    models::{
        api_key::{ApiKeyRecord, CreateApiKeyRequest, CreateApiKeyResponse},
        pagination::{PageMeta, PageParams},
    },
    services::{api_key::ApiKeyService, auth::RequestContext},
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/create",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created successfully", body = ApiResponse<CreateApiKeyResponse>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "API Keys"
)]
pub async fn create_api_key(
    session_user: SessionUser,
    ctx: RequestContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiResponse<CreateApiKeyResponse>>), AppError> {
    payload.validate()?;
    let key = ApiKeyService::create_key(&state, session_user.id, payload, &ctx).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(key))))
}

#[utoipa::path(
    get,
    path = "/list",
    params(PageParams),
    responses(
        (status = 200, description = "List of API keys for the current user", body = ApiResponse<Vec<ApiKeyRecord>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "API Keys"
)]
pub async fn list_api_keys(
    session_user: SessionUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<ApiKeyRecord>>>, AppError> {
    let (keys, total_count) =
        ApiKeyService::list_keys(&state, session_user.id, params.clone()).await?;
    let meta = PageMeta::new(params.page(), params.page_size(), total_count);
    Ok(Json(ApiResponse::with_meta(
        keys,
        serde_json::to_value(meta).unwrap(),
    )))
}

#[utoipa::path(
    delete,
    path = "/{id}",
    params(
        ("id" = Uuid, Path, description = "API Key ID to revoke")
    ),
    responses(
        (status = 200, description = "API key revoked successfully", body = ApiResponse<String>),
        (status = 404, description = "API key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "API Keys"
)]
pub async fn delete_api_key(
    Path(key_id): Path<Uuid>,
    session_user: SessionUser,
    ctx: RequestContext,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    ApiKeyService::delete_key(&state, key_id, session_user.id, &ctx).await?;
    Ok(Json(ApiResponse::success(
        "API key revoked successfully".to_string(),
    )))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(create_api_key))
        .routes(routes!(list_api_keys))
        .routes(routes!(delete_api_key))
}
