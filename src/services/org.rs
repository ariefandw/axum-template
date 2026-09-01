use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::org::{
        AddOrgMemberRequest, App, CreateAppRequest, CreateOrgRequest, OrgMember, Organization,
    },
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
    ) -> Result<App, AppError> {
        let app_id = Uuid::now_v7();
        let now = Utc::now();

        let app = sqlx::query_as::<_, App>(
            r#"
            INSERT INTO apps (id, owner_id, name, slug, description, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, owner_id, name, slug, description, created_at, updated_at
            "#,
        )
        .bind(app_id)
        .bind(owner_id)
        .bind(req.name)
        .bind(req.slug)
        .bind(req.description)
        .bind(now)
        .bind(now)
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

        Ok(app)
    }

    pub async fn list_user_apps(
        state: &Arc<AppState>,
        user_id: Uuid,
    ) -> Result<Vec<App>, AppError> {
        let apps = sqlx::query_as::<_, App>(
            "SELECT id, owner_id, name, slug, description, created_at, updated_at FROM apps WHERE owner_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;

        Ok(apps)
    }

    // =========================================================================
    // Organizations Management
    // =========================================================================

    pub async fn create_org(
        state: &Arc<AppState>,
        app_id: Uuid,
        user_id: Uuid,
        req: CreateOrgRequest,
    ) -> Result<Organization, AppError> {
        let org_id = Uuid::now_v7();
        let member_id = Uuid::now_v7();
        let now = Utc::now();

        let mut tx = state.db.begin().await?;

        let org = sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (id, app_id, name, slug, logo_url, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, app_id, name, slug, logo_url, created_at, updated_at
            "#,
        )
        .bind(org_id)
        .bind(app_id)
        .bind(req.name)
        .bind(req.slug)
        .bind(req.logo_url)
        .bind(now)
        .bind(now)
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
            INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
            VALUES ($1, $2, $3, 'owner', $4, $5)
            "#,
        )
        .bind(member_id)
        .bind(org_id)
        .bind(user_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(org)
    }

    pub async fn list_app_orgs(
        state: &Arc<AppState>,
        app_id: Uuid,
    ) -> Result<Vec<Organization>, AppError> {
        let orgs = sqlx::query_as::<_, Organization>(
            "SELECT id, app_id, name, slug, logo_url, created_at, updated_at FROM organizations WHERE app_id = $1 ORDER BY created_at DESC",
        )
        .bind(app_id)
        .fetch_all(&state.db)
        .await?;

        Ok(orgs)
    }

    pub async fn add_member(
        state: &Arc<AppState>,
        org_id: Uuid,
        req: AddOrgMemberRequest,
    ) -> Result<OrgMember, AppError> {
        let member_id = Uuid::now_v7();
        let now = Utc::now();

        let member = sqlx::query_as::<_, OrgMember>(
            r#"
            INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, org_id, user_id, role, created_at, updated_at
            "#,
        )
        .bind(member_id)
        .bind(org_id)
        .bind(req.user_id)
        .bind(req.role)
        .bind(now)
        .bind(now)
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

        Ok(member)
    }
}
