use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use thiserror::Error;

use crate::config::SmtpConfig;

#[derive(Debug, Error)]
pub enum MailerError {
    #[error("Ungültige E-Mail-Adresse: {0}")]
    InvalidAddress(String),
    #[error("E-Mail-Erstellung fehlgeschlagen: {0}")]
    Build(String),
    #[error("SMTP-Versand fehlgeschlagen: {0}")]
    Transport(String),
}

#[derive(Debug, Clone)]
pub struct Mailer {
    smtp: Option<SmtpConfig>,
}

impl Mailer {
    pub fn new(smtp: Option<SmtpConfig>) -> Self {
        Self { smtp }
    }

    pub fn is_enabled(&self) -> bool {
        self.smtp.is_some()
    }

    pub async fn send_text(
        &self,
        to_email: &str,
        subject: &str,
        body: &str,
    ) -> Result<bool, MailerError> {
        let Some(cfg) = &self.smtp else {
            tracing::debug!(
                to = %to_email,
                subject = %subject,
                "SMTP nicht konfiguriert – E-Mail-Versand übersprungen (No-Op)"
            );
            return Ok(false);
        };

        let from_mailbox: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| MailerError::InvalidAddress(format!("{}: {e}", cfg.from)))?;
        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| MailerError::InvalidAddress(format!("{to_email}: {e}")))?;

        let email = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| MailerError::Build(e.to_string()))?;

        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|e| MailerError::Transport(e.to_string()))?
            .port(cfg.port);

        if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }

        let transport = builder.build();
        transport
            .send(email)
            .await
            .map_err(|e| MailerError::Transport(e.to_string()))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mailer_without_smtp_config_is_clean_noop() {
        let mailer = Mailer::new(None);
        assert!(!mailer.is_enabled());
        let sent = mailer
            .send_text("iso@example.com", "Test", "Inhalt")
            .await
            .expect("No-Op darf keinen Fehler liefern");
        assert!(!sent);
    }
}
