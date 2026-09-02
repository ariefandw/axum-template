//! Multi-App Tenancy Extractor (`X-Application-ID` Guard).
//!
//! Enables axum-template to serve as a multi-tenant Backend-as-a-Service (BaaS)
//! hosting multiple distinct frontend applications.
//!
//! The `AppContext` extractor validates the `X-Application-ID` header, verifies
//! the application exists in the database, and ensures the authenticated caller
//! has legitimate ownership or membership access to that app.

use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use uuid::Uuid;

use crate::{error::AppError, middleware::auth::AuthUser, models::org::App, state::AppState};

/// Verified application context for the current request.
#[derive(Clone, Debug)]
pub struct AppContext {
    pub app_id: Uuid,
    pub name: String,
    pub slug: String,
    pub owner_id: Uuid,
    pub is_owner: bool,
}

impl<S> FromRequestParts<S> for AppContext
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state_ref: &S) -> Result<Self, Self::Rejection> {
        let state: Arc<AppState> = FromRef::from_ref(state_ref);

        // 1. First ensure caller is authenticated
        let auth_user = AuthUser::from_request_parts(parts, state_ref).await?;

        // 2. Extract `x-application-id` header
        let raw_app_id = parts
            .headers
            .get("x-application-id")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                AppError::BadRequest("Missing required 'X-Application-ID' header".to_string())
            })?;

        let app_id = Uuid::parse_str(raw_app_id)
            .map_err(|_| AppError::BadRequest("Malformed 'X-Application-ID' UUID".to_string()))?;

        // 3. Resolve app from database
        let app = sqlx::query_as!(
            App,
            r#"
            SELECT id, owner_id, name, slug, description, created_at, updated_at
            FROM apps
            WHERE id = $1
            "#,
            app_id
        )
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Application not found".to_string()))?;

        // 4. Verify access: caller must be either the owner or an admin or belong to an org in this app
        let is_owner = app.owner_id == auth_user.id || auth_user.is_admin();

        if !is_owner {
            // Check if caller is a member of any organization within this app
            let is_member = sqlx::query_scalar!(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM org_members om
                    JOIN organizations o ON o.id = om.org_id
                    WHERE o.app_id = $1 AND om.user_id = $2
                )
                "#,
                app_id,
                auth_user.id
            )
            .fetch_one(&state.db)
            .await?
            .unwrap_or(false);

            if !is_member {
                return Err(AppError::Forbidden(
                    "You do not have access to this application".to_string(),
                ));
            }
        }

        Ok(AppContext {
            app_id: app.id,
            name: app.name,
            slug: app.slug,
            owner_id: app.owner_id,
            is_owner,
        })
    }
}
