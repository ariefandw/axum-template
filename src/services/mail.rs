//! Transactional mail.
//!
//! Two things changed here. Delivery no longer logs the rendered message body
//! (which contained the very recovery tokens the mail exists to deliver), and
//! the transport can be configured with TLS and credentials rather than being
//! hardwired to an unauthenticated plaintext relay.

use std::sync::Arc;

use lettre::{
    AsyncTransport, Message, Tokio1Executor,
    message::header::ContentType,
    transport::smtp::{AsyncSmtpTransport, authentication::Credentials},
};

use crate::{config::AppConfig, error::AppError, state::AppState};

pub struct MailService;

impl MailService {
    /// Queue a verification mail. Dispatch is detached so a slow relay cannot
    /// stall the request, but failures are logged rather than swallowed.
    pub fn send_verification_email(state: &Arc<AppState>, recipient: &str, token: &str) {
        let link = format!(
            "{}/api/v1/auth/verify-email?token={}",
            state.config.public_base_url.trim_end_matches('/'),
            token
        );
        let body = format!(
            "<h2>Confirm your email</h2>\
             <p>Use this link to verify your account. It expires in {} hours.</p>\
             <p><a href=\"{link}\">Verify my email</a></p>",
            state.config.email_verify_ttl_hours
        );
        Self::dispatch(state, recipient, "Verify your email", body, "email_verify");
    }

    /// Queue a password-reset mail.
    pub fn send_password_reset_email(state: &Arc<AppState>, recipient: &str, token: &str) {
        let link = format!(
            "{}/reset-password?token={}",
            state.config.public_base_url.trim_end_matches('/'),
            token
        );
        let body = format!(
            "<h2>Reset your password</h2>\
             <p>Use this link to choose a new password. It expires in {} minutes.</p>\
             <p><a href=\"{link}\">Reset my password</a></p>\
             <p>If you did not request this, no action is needed.</p>",
            state.config.password_reset_ttl_minutes
        );
        Self::dispatch(
            state,
            recipient,
            "Reset your password",
            body,
            "password_reset",
        );
    }

    fn dispatch(
        state: &Arc<AppState>,
        recipient: &str,
        subject: &str,
        body: String,
        kind: &'static str,
    ) {
        let config = state.config.clone();
        let recipient = recipient.to_string();
        let subject = subject.to_string();

        tokio::spawn(async move {
            match Self::send_email(&config, &recipient, &subject, &body).await {
                Ok(()) => tracing::info!(kind, "Transactional email dispatched"),
                // The recipient is logged; the body, which carries the token, is not.
                Err(e) => {
                    tracing::error!(kind, error = %e, "Failed to dispatch transactional email")
                }
            }
        });
    }

    pub async fn send_email(
        config: &Arc<AppConfig>,
        to_email: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), AppError> {
        let Some(smtp) = config.smtp.as_ref() else {
            // Development convenience only: configuration refuses to start in
            // production without SMTP, so this branch cannot silently drop mail
            // there. The body is deliberately not logged.
            tracing::warn!(
                to = %to_email,
                subject = %subject,
                "SMTP is not configured; email was not sent (development mode)"
            );
            return Ok(());
        };

        let email = Message::builder()
            .from(smtp.from.parse().map_err(|e| {
                AppError::Internal(format!("Invalid SMTP_FROM address: {e}").into())
            })?)
            .to(to_email
                .parse()
                .map_err(|e| AppError::BadRequest(format!("Invalid recipient email: {e}")))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to build email: {e}").into()))?;

        let mut builder = if smtp.use_tls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host).map_err(|e| {
                AppError::Internal(format!("Failed to build SMTP transport: {e}").into())
            })?
        } else {
            // Plaintext is reachable only outside production; config rejects
            // SMTP_TLS=false when APP_ENV=production.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
        }
        .port(smtp.port);

        if let (Some(user), Some(pass)) = (smtp.username.as_ref(), smtp.password.as_ref()) {
            builder =
                builder.credentials(Credentials::new(user.clone(), pass.expose().to_string()));
        }

        builder
            .build()
            .send(email)
            .await
            .map_err(|e| AppError::Internal(format!("SMTP delivery failed: {e}").into()))?;

        Ok(())
    }
}
