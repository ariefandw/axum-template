use std::sync::Arc;
use lettre::{
    message::header::ContentType,
    transport::smtp::AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};

use crate::{config::AppConfig, error::AppError};

pub struct MailService;

impl MailService {
    pub async fn send_email(
        config: &Arc<AppConfig>,
        to_email: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), AppError> {
        let smtp_host = match &config.smtp_host {
            Some(h) if !h.is_empty() => h,
            _ => {
                tracing::info!(
                    to = %to_email,
                    subject = %subject,
                    "SMTP not configured - simulated email dispatch: {}",
                    html_body
                );
                return Ok(());
            }
        };

        let smtp_port = config.smtp_port.unwrap_or(1025);
        let from_addr = config
            .smtp_from
            .as_deref()
            .unwrap_or("noreply@localhost.local");

        let email = Message::builder()
            .from(
                from_addr
                    .parse()
                    .map_err(|e| AppError::Internal(format!("Invalid from email: {e}").into()))?,
            )
            .to(
                to_email
                    .parse()
                    .map_err(|e| AppError::BadRequest(format!("Invalid recipient email: {e}")))?,
            )
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to build email: {e}").into()))?;

        let mailer: AsyncSmtpTransport<Tokio1Executor> =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host)
                .port(smtp_port)
                .build();

        mailer
            .send(email)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to send SMTP email: {e}").into()))?;

        tracing::info!(to = %to_email, subject = %subject, "SMTP email dispatched successfully");
        Ok(())
    }
}
