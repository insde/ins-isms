pub mod actions;
pub mod export;
pub mod register;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};

use crate::{auth::rbac::CurrentUser, error::AppError, state::AppState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreatmentStrategy {
    Mitigate,
    Accept,
    Avoid,
    Transfer,
}

impl TreatmentStrategy {
    pub const ALL: [Self; 4] = [Self::Mitigate, Self::Accept, Self::Avoid, Self::Transfer];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mitigate => "mitigate",
            Self::Accept => "accept",
            Self::Avoid => "avoid",
            Self::Transfer => "transfer",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mitigate => "Mindern",
            Self::Accept => "Akzeptieren",
            Self::Avoid => "Vermeiden",
            Self::Transfer => "Übertragen",
        }
    }
}

impl fmt::Display for TreatmentStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TreatmentStrategy {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "mitigate" => Ok(Self::Mitigate),
            "accept" => Ok(Self::Accept),
            "avoid" => Ok(Self::Avoid),
            "transfer" => Ok(Self::Transfer),
            other => Err(AppError::Validation(vec![format!(
                "Ungültige Behandlungsstrategie: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskStatus {
    Identified,
    Assessed,
    Treating,
    Accepted,
    Closed,
}

impl RiskStatus {
    pub const ALL: [Self; 5] = [
        Self::Identified,
        Self::Assessed,
        Self::Treating,
        Self::Accepted,
        Self::Closed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identified => "identified",
            Self::Assessed => "assessed",
            Self::Treating => "treating",
            Self::Accepted => "accepted",
            Self::Closed => "closed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Identified => "Identifiziert",
            Self::Assessed => "Bewertet",
            Self::Treating => "In Behandlung",
            Self::Accepted => "Akzeptiert",
            Self::Closed => "Geschlossen",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Identified => "badge-draft",
            Self::Assessed => "badge-info",
            Self::Treating => "badge-warning",
            Self::Accepted => "badge-approved",
            Self::Closed => "badge-neutral",
        }
    }
}

impl fmt::Display for RiskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RiskStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "identified" => Ok(Self::Identified),
            "assessed" => Ok(Self::Assessed),
            "treating" => Ok(Self::Treating),
            "accepted" => Ok(Self::Accepted),
            "closed" => Ok(Self::Closed),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Risikostatus: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskRating {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskRating {
    pub fn from_score(score: i16) -> Self {
        match score {
            ..=4 => Self::Low,
            5..=9 => Self::Medium,
            10..=15 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Gering",
            Self::Medium => "Mittel",
            Self::High => "Hoch",
            Self::Critical => "Kritisch",
        }
    }

    pub fn badge_css(self) -> &'static str {
        match self {
            Self::Low => "badge-approved",
            Self::Medium => "badge-warning",
            Self::High => "badge-high",
            Self::Critical => "badge-danger",
        }
    }

    pub fn heatmap_css(self) -> &'static str {
        match self {
            Self::Low => "hm-low",
            Self::Medium => "hm-med",
            Self::High => "hm-high",
            Self::Critical => "hm-crit",
        }
    }

    pub fn requires_elevated_acceptance(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

pub fn risk_score(likelihood: i16, impact: i16) -> i16 {
    likelihood.saturating_mul(impact)
}

pub fn validate_scale(value: i16, field_label: &str) -> Result<i16, AppError> {
    if !(1..=5).contains(&value) {
        return Err(AppError::Validation(vec![format!(
            "{field_label} muss zwischen 1 und 5 liegen."
        )]));
    }
    Ok(value)
}

pub fn suggested_impact_for_classification_rank(rank: i32) -> Option<i16> {
    match rank {
        3 => Some(4),
        4.. => Some(5),
        _ => None,
    }
}

pub fn validate_acceptance_guard(
    user: &CurrentUser,
    status: RiskStatus,
    residual_rating: RiskRating,
    acceptance_justification: Option<&str>,
) -> Result<(), AppError> {
    if status != RiskStatus::Accepted {
        return Ok(());
    }

    if residual_rating.requires_elevated_acceptance() {
        if !user.role.is_iso_or_admin() {
            return Err(AppError::Forbidden(
                "Die Akzeptanz hoher oder kritischer Restrisiken ist ausschließlich Administratoren und ISBs vorbehalten.".to_string(),
            ));
        }

        let has_justification = acceptance_justification
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !has_justification {
            return Err(AppError::Validation(vec![
                "Ein hohes oder kritisches Restrisiko darf nicht ohne dokumentierte Akzeptanzbegründung akzeptiert werden.".to_string(),
            ]));
        }
    }

    Ok(())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/risks",
            get(register::list_risks_handler).post(actions::create_risk_handler),
        )
        .route("/risks/new", get(register::new_risk_form_handler))
        .route("/risks/impact-hint", get(register::impact_hint_handler))
        .route("/risks/export.pdf", get(export::export_risks_pdf_handler))
        .route("/risks/export.csv", get(export::export_risks_csv_handler))
        .route("/risks/{id}", post(actions::update_risk_handler))
        .route("/risks/{id}/drawer", get(register::risk_drawer_handler))
        .route("/risks/{id}/delete", post(actions::delete_risk_handler))
        .route("/risks/{id}/controls", post(actions::link_control_handler))
        .route(
            "/risks/{id}/controls/{soa_id}/unlink",
            post(actions::unlink_control_handler),
        )
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::auth::rbac::Role;

    fn test_user(role: Role) -> CurrentUser {
        CurrentUser {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            full_name: "Test".to_string(),
            role,
            organization_unit_id: None,
            csrf_token: "csrf".to_string(),
        }
    }

    #[test]
    fn calculates_scores_and_ratings() {
        assert_eq!(risk_score(1, 4), 4);
        assert_eq!(RiskRating::from_score(4), RiskRating::Low);
        assert_eq!(RiskRating::from_score(5), RiskRating::Medium);
        assert_eq!(RiskRating::from_score(9), RiskRating::Medium);
        assert_eq!(RiskRating::from_score(10), RiskRating::High);
        assert_eq!(RiskRating::from_score(15), RiskRating::High);
        assert_eq!(RiskRating::from_score(16), RiskRating::Critical);
        assert_eq!(RiskRating::from_score(25), RiskRating::Critical);
    }

    #[test]
    fn suggests_minimum_impact_for_c3_and_c4() {
        assert_eq!(suggested_impact_for_classification_rank(1), None);
        assert_eq!(suggested_impact_for_classification_rank(2), None);
        assert_eq!(suggested_impact_for_classification_rank(3), Some(4));
        assert_eq!(suggested_impact_for_classification_rank(4), Some(5));
    }

    #[test]
    fn enforces_acceptance_guard_and_rbac() {
        let owner = test_user(Role::Owner);
        let iso = test_user(Role::Iso);

        // Niedriges/mittleres Risiko darf ohne erweiterte Sperre akzeptiert werden
        assert!(
            validate_acceptance_guard(&owner, RiskStatus::Accepted, RiskRating::Medium, None)
                .is_ok()
        );

        // Hohes Risiko für Owner -> Forbidden
        let err_owner = validate_acceptance_guard(
            &owner,
            RiskStatus::Accepted,
            RiskRating::High,
            Some("Begründung"),
        )
        .unwrap_err();
        assert!(matches!(err_owner, AppError::Forbidden(_)));

        // Hohes Risiko für ISB ohne Begründung -> Validation (422)
        let err_empty =
            validate_acceptance_guard(&iso, RiskStatus::Accepted, RiskRating::High, Some("   "))
                .unwrap_err();
        assert!(matches!(err_empty, AppError::Validation(_)));

        // Kritisches Risiko für ISB mit Begründung -> Ok
        assert!(
            validate_acceptance_guard(
                &iso,
                RiskStatus::Accepted,
                RiskRating::Critical,
                Some("Kompensierende Offline-Backups vorhanden.")
            )
            .is_ok()
        );
    }
}
