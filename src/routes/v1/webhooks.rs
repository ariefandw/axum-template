use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::webhook::{
        CreateWebhookRequest, CreateWebhookResponse, WebhookDeliveryRecord, WebhookRecord,
    },
    services::webhook::WebhookService,
    state::AppState,
};

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListWebhookQuery {
    pub org_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "",
    operation_id = "create_webhook",
    request_body = CreateWebhookRequest,
    responses(
        (status = 201, description = "Webhook registered successfully", body = ApiResponse<CreateWebhookResponse>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Webhooks"
)]
pub async fn create_webhook(
    auth_user: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<ApiResponse<CreateWebhookResponse>>), AppError> {
    payload.validate()?;
    let webhook = WebhookService::create_webhook(&state.db, auth_user.id, payload).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(webhook))))
}

#[utoipa::path(
    get,
    path = "",
    operation_id = "list_webhooks",
    params(ListWebhookQuery),
    responses(
        (status = 200, description = "List registered webhooks", body = ApiResponse<Vec<WebhookRecord>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Webhooks"
)]
pub async fn list_webhooks(
    auth_user: AuthUser,
    Query(query): Query<ListWebhookQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<Vec<WebhookRecord>>>, AppError> {
    let webhooks = WebhookService::list_webhooks(&state.db, auth_user.id, query.org_id).await?;
    Ok(Json(ApiResponse::success(webhooks)))
}

#[utoipa::path(
    delete,
    path = "/{id}",
    operation_id = "delete_webhook",
    params(
        ("id" = Uuid, Path, description = "Webhook ID to delete")
    ),
    responses(
        (status = 200, description = "Webhook deleted successfully", body = ApiResponse<String>),
        (status = 404, description = "Webhook not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Webhooks"
)]
pub async fn delete_webhook(
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    WebhookService::delete_webhook(&state.db, id, auth_user.id).await?;
    Ok(Json(ApiResponse::success(
        "Webhook deleted successfully".to_string(),
    )))
}

#[utoipa::path(
    get,
    path = "/{id}/deliveries",
    operation_id = "list_webhook_deliveries",
    params(
        ("id" = Uuid, Path, description = "Webhook ID to inspect deliveries")
    ),
    responses(
        (status = 200, description = "List webhook delivery attempts", body = ApiResponse<Vec<WebhookDeliveryRecord>>),
        (status = 404, description = "Webhook not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Webhooks"
)]
pub async fn list_deliveries(
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<Vec<WebhookDeliveryRecord>>>, AppError> {
    let deliveries = WebhookService::list_deliveries(&state.db, id, auth_user.id).await?;
    Ok(Json(ApiResponse::success(deliveries)))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(create_webhook))
        .routes(routes!(list_webhooks))
        .routes(routes!(delete_webhook))
        .routes(routes!(list_deliveries))
}
