use axum::{
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Ungültige Anfrage: {0}")]
    BadRequest(String),

    #[error("Authentifizierung erforderlich")]
    Unauthorized,

    #[error("Zugriff verweigert: {0}")]
    Forbidden(String),

    #[error("Ressource nicht gefunden: {0}")]
    NotFound(String),

    #[error("Konflikt: {0}")]
    Conflict(String),

    #[error("Nicht unterstützter Medientyp: {0}")]
    UnsupportedMediaType(String),

    #[error("Zu viele Anfragen: {0}")]
    TooManyRequests(String),

    #[error("Validierungsfehler")]
    Validation(Vec<String>),

    #[error("Datenbankfehler")]
    Database(#[from] sqlx::Error),

    #[error("Ein-/Ausgabefehler")]
    Io(#[from] std::io::Error),

    #[error("Speicherfehler: {0}")]
    Storage(String),

    #[error("Interner Fehler")]
    Internal(String),
}

impl AppError {
    pub fn to_html_partial(&self) -> String {
        let items = match self {
            Self::Validation(errors) if !errors.is_empty() => errors
                .iter()
                .map(|msg| format!("<li>{}</li>", escape_html(msg)))
                .collect::<Vec<_>>()
                .join(""),
            other => format!("<li>{}</li>", escape_html(&other.user_message())),
        };
        format!(r#"<div class="alert alert-error" role="alert"><ul>{items}</ul></div>"#)
    }

    fn user_message(&self) -> String {
        match self {
            Self::BadRequest(msg)
            | Self::Forbidden(msg)
            | Self::NotFound(msg)
            | Self::Conflict(msg)
            | Self::UnsupportedMediaType(msg)
            | Self::TooManyRequests(msg) => msg.clone(),
            Self::Unauthorized => "Bitte melden Sie sich erneut an.".to_string(),
            Self::Validation(errs) => errs.join("; "),
            // Interne Details niemals an den HTTP-Client durchreichen.
            Self::Database(_) | Self::Io(_) | Self::Storage(_) | Self::Internal(_) => {
                "Ein interner Systemfehler ist aufgetreten.".to_string()
            }
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Database(_) | Self::Io(_) | Self::Storage(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        if status.is_server_error() {
            tracing::error!(error = ?self, "Serverfehler bei Request-Verarbeitung");
        }

        let mut response = (status, Html(self.to_html_partial())).into_response();
        if matches!(self, Self::Validation(_))
            && let Ok(val) = HeaderValue::from_str(
                r#"{"showToast":{"level":"error","message":"Bitte Eingaben prüfen."}}"#,
            )
        {
            response.headers_mut().insert("HX-Trigger", val);
        }
        response
    }
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
