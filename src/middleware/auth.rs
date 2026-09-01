use std::sync::Arc;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::auth::AuthService,
    state::AppState,
};

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct AdminUser {
    pub id: Uuid,
    pub email: String,
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;
        if auth_user.role != "admin" {
            return Err(AppError::Forbidden(
                "Access forbidden: admin privileges required".to_string(),
            ));
        }
        Ok(AdminUser {
            id: auth_user.id,
            email: auth_user.email,
        })
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state_ref: &S) -> Result<Self, Self::Rejection> {
        let state: Arc<AppState> = FromRef::from_ref(state_ref);
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header scheme".to_string()))?;

        let claims = AuthService::verify_jwt(token, &state.config.jwt_secret)?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized("Malformed user ID in token".to_string()))?;

        Ok(AuthUser {
            id: user_id,
            email: claims.email,
            role: claims.role,
        })
    }
}

