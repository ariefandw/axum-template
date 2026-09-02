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
    middleware::auth::AuthUser,
    models::{
        api_key::ApiScope,
        org::{
            AddOrgMemberRequest, App, CreateAppRequest, CreateOrgRequest, OrgMember, Organization,
        },
        pagination::{PageMeta, PageParams},
    },
    services::{auth::RequestContext, org::OrgService},
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
    auth_user: AuthUser,
    ctx: RequestContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<ApiResponse<App>>), AppError> {
    payload.validate()?;
    auth_user.require_scope(ApiScope::AppsWrite)?;
    let app = OrgService::create_app(&state, auth_user.id, payload, &ctx).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(app))))
}

#[utoipa::path(
    get,
    path = "",
    params(PageParams),
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
    auth_user: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<App>>>, AppError> {
    let (apps, total_count) =
        OrgService::list_user_apps(&state, auth_user.id, params.clone()).await?;
    let meta = PageMeta::new(params.page(), params.page_size(), total_count);
    Ok(Json(ApiResponse::with_meta(
        apps,
        serde_json::to_value(meta).unwrap(),
    )))
}

#[utoipa::path(
    get,
    path = "/{app_id}",
    operation_id = "get_app_details",
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Application details", body = ApiResponse<App>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden: Caller does not have access to this app", body = ApiErrorResponse),
        (status = 404, description = "Application not found", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Applications"
)]
pub async fn get_app_details(
    app_ctx: crate::middleware::app_context::AppContext,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<App>>, AppError> {
    let app = sqlx::query_as!(
        App,
        r#"
        SELECT id, owner_id, name, slug, description, created_at, updated_at
        FROM apps
        WHERE id = $1
        "#,
        app_ctx.app_id
    )
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ApiResponse::success(app)))
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
        (status = 404, description = "App not found or not owned by user", body = ApiErrorResponse),
        (status = 409, description = "Org slug already exists in this app", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn create_org(
    Path(app_id): Path<Uuid>,
    auth_user: AuthUser,
    ctx: RequestContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Organization>>), AppError> {
    payload.validate()?;
    auth_user.require_scope(ApiScope::OrgsWrite)?;
    let org = OrgService::create_org(&state, app_id, auth_user.id, payload, &ctx).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(org))))
}

#[utoipa::path(
    get,
    path = "/{app_id}/orgs",
    params(
        ("app_id" = Uuid, Path, description = "Target Application ID"),
        PageParams
    ),
    responses(
        (status = 200, description = "List of organizations under this app (Owner only)", body = ApiResponse<Vec<Organization>>),
        (status = 404, description = "App not found or not owned by user", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn list_orgs(
    Path(app_id): Path<Uuid>,
    auth_user: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageParams>,
) -> Result<Json<ApiResponse<Vec<Organization>>>, AppError> {
    let (orgs, total_count) =
        OrgService::list_app_orgs(&state, app_id, auth_user.id, params.clone()).await?;
    let meta = PageMeta::new(params.page(), params.page_size(), total_count);
    Ok(Json(ApiResponse::with_meta(
        orgs,
        serde_json::to_value(meta).unwrap(),
    )))
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
        (status = 403, description = "Forbidden: Caller must be Org Admin or Owner", body = ApiErrorResponse),
        (status = 404, description = "Organization not found or caller not a member", body = ApiErrorResponse),
        (status = 409, description = "User is already an org member", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Organizations"
)]
pub async fn add_org_member(
    Path(org_id): Path<Uuid>,
    auth_user: AuthUser,
    ctx: RequestContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddOrgMemberRequest>,
) -> Result<(StatusCode, Json<ApiResponse<OrgMember>>), AppError> {
    payload.validate()?;
    auth_user.require_scope(ApiScope::OrgsWrite)?;
    let member = OrgService::add_member(&state, org_id, auth_user.id, payload, &ctx).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::success(member))))
}

pub fn router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(create_app))
        .routes(routes!(list_apps))
        .routes(routes!(get_app_details))
        .routes(routes!(create_org))
        .routes(routes!(list_orgs))
        .routes(routes!(add_org_member))
}
