pub mod editor;
pub mod library;
pub mod view;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role, ensure_owner_scope},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocType {
    Policy,
    Guideline,
    Sop,
    Record,
    Template,
    Runbook,
}

impl DocType {
    pub const ALL: [Self; 6] = [
        Self::Policy,
        Self::Guideline,
        Self::Sop,
        Self::Record,
        Self::Template,
        Self::Runbook,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Guideline => "guideline",
            Self::Sop => "sop",
            Self::Record => "record",
            Self::Template => "template",
            Self::Runbook => "runbook",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Policy => "Richtlinie (Policy)",
            Self::Guideline => "Leitlinie",
            Self::Sop => "Verfahrensanweisung (SOP)",
            Self::Record => "Nachweis / Protokoll",
            Self::Template => "Vorlage",
            Self::Runbook => "Runbook",
        }
    }
}

impl fmt::Display for DocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DocType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "policy" => Ok(Self::Policy),
            "guideline" => Ok(Self::Guideline),
            "sop" => Ok(Self::Sop),
            "record" => Ok(Self::Record),
            "template" => Ok(Self::Template),
            "runbook" => Ok(Self::Runbook),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Dokumenttyp: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    MarkdownEditor,
    UploadedFile,
    ExternalLink,
}

impl SourceType {
    pub const ALL: [Self; 3] = [Self::MarkdownEditor, Self::UploadedFile, Self::ExternalLink];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarkdownEditor => "markdown_editor",
            Self::UploadedFile => "uploaded_file",
            Self::ExternalLink => "external_link",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MarkdownEditor => "Markdown-Editor",
            Self::UploadedFile => "Hochgeladene Datei",
            Self::ExternalLink => "Externer Link",
        }
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SourceType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "markdown_editor" => Ok(Self::MarkdownEditor),
            "uploaded_file" => Ok(Self::UploadedFile),
            "external_link" => Ok(Self::ExternalLink),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Quelltyp: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    Draft,
    InReview,
    Approved,
    Archived,
}

impl VersionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::InReview => "in_review",
            Self::Approved => "approved",
            Self::Archived => "archived",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Draft => "Entwurf",
            Self::InReview => "In Prüfung",
            Self::Approved => "Freigegeben",
            Self::Archived => "Archiviert",
        }
    }

    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Draft => "badge-draft",
            Self::InReview => "badge-in-review",
            Self::Approved => "badge-approved",
            Self::Archived => "badge-neutral",
        }
    }
}

impl fmt::Display for VersionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for VersionStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "draft" => Ok(Self::Draft),
            "in_review" => Ok(Self::InReview),
            "approved" => Ok(Self::Approved),
            "archived" => Ok(Self::Archived),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Versionsstatus: {other}"
            )])),
        }
    }
}

pub fn validate_external_url(raw: &str, is_production: bool) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(vec![
            "Externe URL darf nicht leer sein.".to_string(),
        ]));
    }

    let parsed = url::Url::parse(trimmed).map_err(|_| {
        AppError::Validation(vec![
            "Ungültige externe URL (muss mit https:// beginnen).".to_string(),
        ])
    })?;

    let scheme_ok = match parsed.scheme() {
        "https" => true,
        "http" => !is_production,
        _ => false,
    };

    if !scheme_ok {
        return Err(AppError::Validation(vec![
            "Unzulässiges URL-Schema: Es sind ausschließlich https://-Links zulässig.".to_string(),
        ]));
    }

    if parsed.host_str().is_none() {
        return Err(AppError::Validation(vec![
            "Externe URL muss einen gültigen Hostnamen enthalten.".to_string(),
        ]));
    }

    Ok(parsed.to_string())
}

pub fn next_version_number(current: &str) -> String {
    let trimmed = current.trim();
    if let Some((major, minor)) = trimmed.rsplit_once('.')
        && let Ok(minor_num) = minor.parse::<u32>()
    {
        return format!("{major}.{}", minor_num + 1);
    }
    if trimmed.is_empty() {
        "0.1".to_string()
    } else {
        format!("{trimmed}.1")
    }
}

pub fn can_view_version(role: Role, status: VersionStatus) -> bool {
    match role {
        Role::Admin | Role::Iso | Role::Owner => true,
        Role::Auditor => matches!(status, VersionStatus::Approved | VersionStatus::Archived),
        Role::Employee => matches!(status, VersionStatus::Approved),
    }
}

pub fn can_edit_document(
    user: &CurrentUser,
    owner_unit_id: Option<Uuid>,
    owner_user_id: Option<Uuid>,
) -> bool {
    ensure_owner_scope(user, owner_unit_id, owner_user_id).is_ok()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/documents",
            get(library::list_documents_handler).post(library::create_document_handler),
        )
        .route("/documents/new", get(library::new_document_form_handler))
        .route("/documents/preview", post(editor::preview_markdown_handler))
        .route("/documents/{id}", get(view::view_document_handler))
        .route(
            "/documents/{id}/drawer",
            get(library::document_drawer_handler),
        )
        .route(
            "/documents/{id}/acknowledge",
            post(view::acknowledge_document_handler),
        )
        .route(
            "/documents/{id}/versions",
            post(view::derive_version_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}",
            post(editor::update_version_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}/edit",
            get(editor::edit_version_page_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}/submit-review",
            post(editor::submit_review_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}/approve",
            post(editor::approve_version_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}/download",
            get(editor::download_version_file_handler),
        )
        .route(
            "/documents/{id}/versions/{vid}/export.pdf",
            get(editor::export_version_pdf_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_external_url_schemes_strictly() {
        assert!(validate_external_url("https://wiki.example.com/runbook", true).is_ok());
        assert!(validate_external_url("http://wiki.local/runbook", false).is_ok());
        assert!(validate_external_url("http://wiki.local/runbook", true).is_err());
        assert!(validate_external_url("javascript:alert(1)", false).is_err());
        assert!(validate_external_url("data:text/html,<script>", false).is_err());
        assert!(validate_external_url("file:///etc/passwd", false).is_err());
    }

    #[test]
    fn increments_version_numbers() {
        assert_eq!(next_version_number("0.1"), "0.2");
        assert_eq!(next_version_number("1.0"), "1.1");
        assert_eq!(next_version_number("2.9"), "2.10");
    }

    #[test]
    fn enforces_role_version_visibility() {
        assert!(!can_view_version(Role::Auditor, VersionStatus::Draft));
        assert!(!can_view_version(Role::Auditor, VersionStatus::InReview));
        assert!(can_view_version(Role::Auditor, VersionStatus::Approved));
        assert!(can_view_version(Role::Auditor, VersionStatus::Archived));

        assert!(!can_view_version(Role::Employee, VersionStatus::Draft));
        assert!(!can_view_version(Role::Employee, VersionStatus::InReview));
        assert!(can_view_version(Role::Employee, VersionStatus::Approved));
        assert!(!can_view_version(Role::Employee, VersionStatus::Archived));
    }
}
