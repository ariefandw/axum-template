use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{
        org::{
            AddOrgMemberRequest, App, CreateAppRequest, CreateOrgRequest, OrgMember, OrgRole,
            Organization,
        },
        pagination::PageParams,
    },
    services::{audit::AuditService, auth::RequestContext},
    state::AppState,
};

pub struct OrgService;

impl OrgService {
    // =========================================================================
    // Apps Management
    // =========================================================================

    pub async fn create_app(
        state: &Arc<AppState>,
        owner_id: Uuid,
        req: CreateAppRequest,
        ctx: &RequestContext,
    ) -> Result<App, AppError> {
        let app_id = Uuid::now_v7();

        let app = sqlx::query_as::<_, App>(
            r#"
            INSERT INTO apps (id, owner_id, name, slug, description)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, owner_id, name, slug, description, created_at, updated_at
            "#,
        )
        .bind(app_id)
        .bind(owner_id)
        .bind(&req.name)
        .bind(&req.slug)
        .bind(&req.description)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return AppError::Conflict(
                        "An application with this slug already exists".to_string(),
                    );
                }
            }
            AppError::from(e)
        })?;

        AuditService::record_best_effort(
            state,
            Some(owner_id),
            "app.create",
            "apps",
            Some(&app.id.to_string()),
            ctx,
            Some(serde_json::json!({ "name": app.name, "slug": app.slug })),
        )
        .await;

        Ok(app)
    }

    pub async fn list_user_apps(
        state: &Arc<AppState>,
        user_id: Uuid,
        params: PageParams,
    ) -> Result<(Vec<App>, u64), AppError> {
        let limit = params.limit() as i64;
        let offset = params.offset() as i64;

        let apps = sqlx::query_as::<_, App>(
            "SELECT id, owner_id, name, slug, description, created_at, updated_at FROM apps WHERE owner_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        let total_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM apps WHERE owner_id = $1")
                .bind(user_id)
                .fetch_one(&state.db)
                .await? as u64;

        Ok((apps, total_count))
    }

    // =========================================================================
    // Organizations Management
    // =========================================================================

    pub async fn create_org(
        state: &Arc<AppState>,
        app_id: Uuid,
        user_id: Uuid,
        req: CreateOrgRequest,
        ctx: &RequestContext,
    ) -> Result<Organization, AppError> {
        // 1. Verify app exists and caller is owner of the App
        let app = sqlx::query_as::<_, App>("SELECT id, owner_id, name, slug, description, created_at, updated_at FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Application '{app_id}' not found")))?;

        if app.owner_id != user_id {
            return Err(AppError::NotFound(format!(
                "Application '{app_id}' not found"
            )));
        }

        let org_id = Uuid::now_v7();
        let member_id = Uuid::now_v7();

        let mut tx = state.db.begin().await?;

        let org = sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (id, app_id, name, slug, logo_url)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, app_id, name, slug, logo_url, created_at, updated_at
            "#,
        )
        .bind(org_id)
        .bind(app_id)
        .bind(&req.name)
        .bind(&req.slug)
        .bind(&req.logo_url)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return AppError::Conflict(
                        "An organization with this slug already exists in this app".to_string(),
                    );
                }
            }
            AppError::from(e)
        })?;

        // Add creator as Org Owner
        sqlx::query(
            r#"
            INSERT INTO org_members (id, org_id, user_id, role)
            VALUES ($1, $2, $3, 'owner')
            "#,
        )
        .bind(member_id)
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        AuditService::record_best_effort(
            state,
            Some(user_id),
            "org.create",
            "organizations",
            Some(&org.id.to_string()),
            ctx,
            Some(serde_json::json!({ "app_id": app_id, "name": org.name, "slug": org.slug })),
        )
        .await;

        Ok(org)
    }

    pub async fn list_app_orgs(
        state: &Arc<AppState>,
        app_id: Uuid,
        user_id: Uuid,
        params: PageParams,
    ) -> Result<(Vec<Organization>, u64), AppError> {
        // Verify app exists and caller is owner
        let app = sqlx::query_as::<_, App>("SELECT id, owner_id, name, slug, description, created_at, updated_at FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Application '{app_id}' not found")))?;

        if app.owner_id != user_id {
            return Err(AppError::NotFound(format!(
                "Application '{app_id}' not found"
            )));
        }

        let limit = params.limit() as i64;
        let offset = params.offset() as i64;

        let orgs = sqlx::query_as::<_, Organization>(
            "SELECT id, app_id, name, slug, logo_url, created_at, updated_at FROM organizations WHERE app_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(app_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        let total_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM organizations WHERE app_id = $1")
                .bind(app_id)
                .fetch_one(&state.db)
                .await? as u64;

        Ok((orgs, total_count))
    }

    pub async fn add_member(
        state: &Arc<AppState>,
        org_id: Uuid,
        caller_id: Uuid,
        req: AddOrgMemberRequest,
        ctx: &RequestContext,
    ) -> Result<OrgMember, AppError> {
        // Verify caller is at least Admin/Owner of the organization
        let caller_role = Self::get_user_org_role(state, org_id, caller_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Organization '{org_id}' not found")))?;

        if caller_role < OrgRole::Admin {
            return Err(AppError::Forbidden(
                "Only organization admins or owners can add members".to_string(),
            ));
        }

        // Only owners can add another owner
        if req.role == OrgRole::Owner && caller_role < OrgRole::Owner {
            return Err(AppError::Forbidden(
                "Only an owner can grant the owner role".to_string(),
            ));
        }

        let member_id = Uuid::now_v7();
        let role_str = req.role.to_string();

        let member = sqlx::query_as::<_, OrgMember>(
            r#"
            INSERT INTO org_members (id, org_id, user_id, role)
            VALUES ($1, $2, $3, $4)
            RETURNING id, org_id, user_id, role, created_at, updated_at
            "#,
        )
        .bind(member_id)
        .bind(org_id)
        .bind(req.user_id)
        .bind(&role_str)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return AppError::Conflict(
                        "User is already a member of this organization".to_string(),
                    );
                }
            }
            AppError::from(e)
        })?;

        AuditService::record_best_effort(
            state,
            Some(caller_id),
            "org.member_add",
            "org_members",
            Some(&member.id.to_string()),
            ctx,
            Some(serde_json::json!({ "org_id": org_id, "user_id": req.user_id, "role": role_str })),
        )
        .await;

        Ok(member)
    }

    pub async fn get_user_org_role(
        state: &Arc<AppState>,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>, AppError> {
        let role_str = sqlx::query_scalar::<_, String>(
            "SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;

        match role_str.as_deref() {
            Some("owner") => Ok(Some(OrgRole::Owner)),
            Some("admin") => Ok(Some(OrgRole::Admin)),
            Some("member") => Ok(Some(OrgRole::Member)),
            _ => Ok(None),
        }
    }
}
