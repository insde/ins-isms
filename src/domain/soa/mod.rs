pub mod actions;
pub mod export;
pub mod matrix;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    auth::rbac::{CurrentUser, Role},
    domain::documents::validate_external_url,
    error::AppError,
    markdown::is_valid_anchor_id,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    NotStarted,
    InProgress,
    Implemented,
    Verified,
}

impl ImplementationStatus {
    pub const ALL: [Self; 4] = [
        Self::NotStarted,
        Self::InProgress,
        Self::Implemented,
        Self::Verified,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::InProgress => "in_progress",
            Self::Implemented => "implemented",
            Self::Verified => "verified",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "Nicht begonnen",
            Self::InProgress => "In Umsetzung",
            Self::Implemented => "Umgesetzt",
            Self::Verified => "Verifiziert",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::NotStarted => "badge-draft",
            Self::InProgress => "badge-warning",
            Self::Implemented => "badge-info",
            Self::Verified => "badge-approved",
        }
    }

    /// Nächster Status beim Keyboard-Triage (`s`), abhängig von der Benutzerrolle.
    /// `owner` darf nicht auf `verified` schalten.
    pub fn next_for_role(self, role: Role) -> Self {
        match self {
            Self::NotStarted => Self::InProgress,
            Self::InProgress => Self::Implemented,
            Self::Implemented => {
                if role.is_iso_or_admin() {
                    Self::Verified
                } else {
                    Self::NotStarted
                }
            }
            Self::Verified => Self::NotStarted,
        }
    }
}

impl fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImplementationStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "not_started" => Ok(Self::NotStarted),
            "in_progress" => Ok(Self::InProgress),
            "implemented" => Ok(Self::Implemented),
            "verified" => Ok(Self::Verified),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Umsetzungsstatus: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    File,
    PolicyLink,
    ExternalUrl,
    Note,
}

impl EvidenceType {
    pub const ALL: [Self; 4] = [Self::File, Self::PolicyLink, Self::ExternalUrl, Self::Note];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::PolicyLink => "policy_link",
            Self::ExternalUrl => "external_url",
            Self::Note => "note",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::File => "Datei-Nachweis",
            Self::PolicyLink => "Richtlinien-Verweis",
            Self::ExternalUrl => "Externe URL",
            Self::Note => "Prüfnotiz",
        }
    }
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EvidenceType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "file" => Ok(Self::File),
            "policy_link" => Ok(Self::PolicyLink),
            "external_url" => Ok(Self::ExternalUrl),
            "note" => Ok(Self::Note),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Nachweistyp: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingType {
    Equivalent,
    Partial,
    Superset,
}

impl MappingType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Partial => "partial",
            Self::Superset => "superset",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Equivalent => "Gleichwertig",
            Self::Partial => "Teilweise",
            Self::Superset => "Umfassender",
        }
    }
}

impl fmt::Display for MappingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MappingType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "equivalent" => Ok(Self::Equivalent),
            "partial" => Ok(Self::Partial),
            "superset" => Ok(Self::Superset),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Mapping-Typ: {other}"
            )])),
        }
    }
}

pub fn validate_soa_justification(
    is_applicable: bool,
    justification: &str,
) -> Result<(), AppError> {
    if !is_applicable && justification.trim().is_empty() {
        return Err(AppError::Validation(vec![
            "Bei Ausschluss eines Controls (Nicht anwendbar) ist eine Begründung für das Audit zwingend erforderlich.".to_string(),
        ]));
    }
    Ok(())
}

pub fn validate_verified_status_permission(
    user: &CurrentUser,
    status: ImplementationStatus,
) -> Result<(), AppError> {
    if status == ImplementationStatus::Verified && !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Administratoren und ISBs dürfen den Status „Verifiziert“ setzen.".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_section_anchor(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !is_valid_anchor_id(trimmed) {
        return Err(AppError::Validation(vec![
            "Der Abschnitts-Anker darf nur Kleinbuchstaben, Ziffern, Bindestriche und Unterstriche enthalten.".to_string(),
        ]));
    }
    Ok(Some(trimmed.to_string()))
}

pub fn validate_evidence_url(raw: &str, is_production: bool) -> Result<String, AppError> {
    validate_external_url(raw, is_production)
}

pub fn domain_display_label(raw: &str) -> &str {
    match raw {
        "Organizational" => "Organisatorisch (A.5)",
        "People" => "Personell (A.6)",
        "Physical" => "Physisch (A.7)",
        "Technological" => "Technologisch (A.8)",
        "Governance" => "Governance (§ 30/38 BSIG)",
        "Risk & Policies" => "Risikomanagement & Richtlinien",
        "Incident Management" => "Vorfallmanagement & Meldepflichten",
        "Business Continuity" => "Betriebskontinuität",
        "Supply Chain" => "Lieferkettensicherheit",
        "Technical Security" => "Technische Sicherheit",
        "Audit & Assurance" => "Wirksamkeit & Audits",
        "People & Hygiene" => "Cyberhygiene & Schulung",
        "Access & HR" => "Zugriff & Personal",
        other => other,
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/soa", get(matrix::list_soa_handler))
        .route("/soa/export.pdf", get(export::export_soa_pdf_handler))
        .route("/soa/export.csv", get(export::export_soa_csv_handler))
        .route("/soa/{id}", post(actions::update_soa_entry_handler))
        .route("/soa/{id}/drawer", get(matrix::soa_drawer_handler))
        .route(
            "/soa/{id}/applicability-modal",
            get(matrix::applicability_modal_handler),
        )
        .route(
            "/soa/{id}/cycle-status",
            post(actions::cycle_status_handler),
        )
        .route(
            "/soa/{id}/toggle-applicability",
            post(actions::toggle_applicability_handler),
        )
        .route(
            "/soa/{id}/evidences/new",
            get(matrix::new_evidence_form_handler),
        )
        .route(
            "/soa/{id}/evidences",
            post(actions::create_evidence_handler),
        )
        .route(
            "/soa/{id}/evidences/{eid}/verify",
            post(actions::verify_evidence_handler),
        )
        .route(
            "/soa/{id}/evidences/{eid}/delete",
            post(actions::delete_evidence_handler),
        )
        .route(
            "/soa/{id}/evidences/{eid}/download",
            get(actions::download_evidence_file_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_justification_when_not_applicable() {
        assert!(validate_soa_justification(false, "").is_err());
        assert!(validate_soa_justification(false, "   \t\n").is_err());
        assert!(validate_soa_justification(false, "Kein eigener Serverraum vorhanden.").is_ok());
        assert!(validate_soa_justification(true, "").is_ok());
    }

    #[test]
    fn cycles_status_respecting_role() {
        assert_eq!(
            ImplementationStatus::NotStarted.next_for_role(Role::Owner),
            ImplementationStatus::InProgress
        );
        assert_eq!(
            ImplementationStatus::InProgress.next_for_role(Role::Owner),
            ImplementationStatus::Implemented
        );
        assert_eq!(
            ImplementationStatus::Implemented.next_for_role(Role::Owner),
            ImplementationStatus::NotStarted
        );
        assert_eq!(
            ImplementationStatus::Implemented.next_for_role(Role::Iso),
            ImplementationStatus::Verified
        );
        assert_eq!(
            ImplementationStatus::Verified.next_for_role(Role::Admin),
            ImplementationStatus::NotStarted
        );
    }

    #[test]
    fn validates_anchor_slug() {
        assert_eq!(validate_section_anchor(None).unwrap(), None);
        assert_eq!(validate_section_anchor(Some("  ")).unwrap(), None);
        assert_eq!(
            validate_section_anchor(Some("clean-desk")).unwrap(),
            Some("clean-desk".to_string())
        );
        assert!(validate_section_anchor(Some("Clean Desk!")).is_err());
    }
}
