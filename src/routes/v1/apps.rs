use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{ApiErrorResponse, ApiResponse, AppError},
    middleware::auth::AuthUser,
    models::org::{
        AddOrgMemberRequest, App, CreateAppRequest, CreateOrgRequest, OrgMember, Organization,
    },
    services::org::OrgService,
    state::AppState,
};

// =========================================================================
// App Endpoints
// =========================================================================

#[utoipa::path(
    post,
    path = "",
    request_body = CreateAppRequest,
    responses(
        (status = 201, description = "Application created successfully", body = ApiResponse<App>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 409, description = "App slug already exists", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Applications"
)]
pub async fn create_app(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<ApiResponse<App>>), AppError> {
    payload.validate()?;
    let app = OrgService::create_app(&state, auth_user.id, payload).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(app))))
}

#[utoipa::path(
    get,
    path = "",
    responses(
        (status = 200, description = "List of applications owned by current user", body = ApiResponse<Vec<App>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Applications"
)]
pub async fn list_apps(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<Vec<App>>>, AppError> {
    let apps = OrgService::list_user_apps(&state, auth_user.id).await?;
    Ok(Json(ApiResponse::success(apps)))
}

// =========================================================================
// Organization Endpoints
// =========================================================================

#[utoipa::path(
    post,
    path = "/{app_id}/orgs",
    params(
        ("app_id" = Uuid, Path, description = "Target Application ID")
    ),
    request_body = CreateOrgRequest,
    responses(
        (status = 201, description = "Organization created successfully", body = ApiResponse<Organization>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 409, description = "Org slug already exists in this app", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn create_org(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(app_id): Path<Uuid>,
    Json(payload): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Organization>>), AppError> {
    payload.validate()?;
    let org = OrgService::create_org(&state, app_id, auth_user.id, payload).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(org))))
}

#[utoipa::path(
    get,
    path = "/{app_id}/orgs",
    params(
        ("app_id" = Uuid, Path, description = "Target Application ID")
    ),
    responses(
        (status = 200, description = "List of organizations under this app", body = ApiResponse<Vec<Organization>>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn list_orgs(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser,
    Path(app_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<Organization>>>, AppError> {
    let orgs = OrgService::list_app_orgs(&state, app_id).await?;
    Ok(Json(ApiResponse::success(orgs)))
}

#[utoipa::path(
    post,
    path = "/orgs/{org_id}/members",
    params(
        ("org_id" = Uuid, Path, description = "Target Organization ID")
    ),
    request_body = AddOrgMemberRequest,
    responses(
        (status = 201, description = "Member added to organization", body = ApiResponse<OrgMember>),
        (status = 400, description = "Validation error", body = ApiErrorResponse),
        (status = 409, description = "User is already an org member", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn add_org_member(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<AddOrgMemberRequest>,
) -> Result<(StatusCode, Json<ApiResponse<OrgMember>>), AppError> {
    payload.validate()?;
    let member = OrgService::add_member(&state, org_id, payload).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(member))))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(create_app))
        .routes(routes!(list_apps))
        .routes(routes!(create_org))
        .routes(routes!(list_orgs))
        .routes(routes!(add_org_member))
}
