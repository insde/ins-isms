pub mod actions;
pub mod register;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];

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
            Self::Low => "Niedrig",
            Self::Medium => "Mittel",
            Self::High => "Hoch",
            Self::Critical => "Kritisch",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Low => "badge-low",
            Self::Medium => "badge-normal",
            Self::High => "badge-high",
            Self::Critical => "badge-critical",
        }
    }
}

impl fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IncidentSeverity {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Schweregrad: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    Detected,
    Analyzing,
    Contained,
    Eradicated,
    Closed,
}

impl IncidentStatus {
    pub const ALL: [Self; 5] = [
        Self::Detected,
        Self::Analyzing,
        Self::Contained,
        Self::Eradicated,
        Self::Closed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Analyzing => "analyzing",
            Self::Contained => "contained",
            Self::Eradicated => "eradicated",
            Self::Closed => "closed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Detected => "Erkannt",
            Self::Analyzing => "In Analyse",
            Self::Contained => "Eingedämmt",
            Self::Eradicated => "Behoben",
            Self::Closed => "Geschlossen",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Detected => "badge-crit",
            Self::Analyzing => "badge-high",
            Self::Contained => "badge-warn",
            Self::Eradicated => "badge-info",
            Self::Closed => "badge-approved",
        }
    }
}

impl fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IncidentStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "detected" => Ok(Self::Detected),
            "analyzing" => Ok(Self::Analyzing),
            "contained" => Ok(Self::Contained),
            "eradicated" => Ok(Self::Eradicated),
            "closed" => Ok(Self::Closed),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Vorfallsstatus: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Nis2Deadlines {
    pub early_warning_due_at: Option<DateTime<Utc>>,
    pub incident_report_due_at: Option<DateTime<Utc>>,
    pub final_report_due_at: Option<DateTime<Utc>>,
}

pub fn compute_nis2_deadlines(
    is_nis2_significant: bool,
    detected_at: DateTime<Utc>,
    early_warning_submitted_at: Option<DateTime<Utc>>,
    incident_report_submitted_at: Option<DateTime<Utc>>,
    final_report_submitted_at: Option<DateTime<Utc>>,
    existing: Nis2Deadlines,
) -> Nis2Deadlines {
    if !is_nis2_significant {
        return Nis2Deadlines {
            early_warning_due_at: if early_warning_submitted_at.is_some() {
                existing.early_warning_due_at
            } else {
                None
            },
            incident_report_due_at: if incident_report_submitted_at.is_some() {
                existing.incident_report_due_at
            } else {
                None
            },
            final_report_due_at: if final_report_submitted_at.is_some() {
                existing.final_report_due_at
            } else {
                None
            },
        };
    }

    let early_warning_due_at = if early_warning_submitted_at.is_none() {
        Some(detected_at + Duration::hours(24))
    } else {
        existing
            .early_warning_due_at
            .or_else(|| Some(detected_at + Duration::hours(24)))
    };

    let incident_report_due_at = if incident_report_submitted_at.is_none() {
        Some(detected_at + Duration::hours(72))
    } else {
        existing
            .incident_report_due_at
            .or_else(|| Some(detected_at + Duration::hours(72)))
    };

    let final_report_due_at = match incident_report_submitted_at {
        Some(submitted) => {
            if final_report_submitted_at.is_none() {
                Some(submitted + Duration::days(30))
            } else {
                existing
                    .final_report_due_at
                    .or_else(|| Some(submitted + Duration::days(30)))
            }
        }
        None => None,
    };

    Nis2Deadlines {
        early_warning_due_at,
        incident_report_due_at,
        final_report_due_at,
    }
}

pub fn validate_closure_guard(
    status: IncidentStatus,
    root_cause_analysis: Option<&str>,
    lessons_learned: Option<&str>,
) -> Result<(), AppError> {
    if status != IncidentStatus::Closed {
        return Ok(());
    }

    let mut errors = Vec::new();
    if root_cause_analysis.map(str::trim).unwrap_or("").is_empty() {
        errors.push(
            "Für den Abschluss eines Vorfalls ist eine Ursachenanalyse (Root Cause Analysis) erforderlich."
                .to_string(),
        );
    }
    if lessons_learned.map(str::trim).unwrap_or("").is_empty() {
        errors.push(
            "Für den Abschluss eines Vorfalls sind dokumentierte Erkenntnisse (Lessons Learned) erforderlich."
                .to_string(),
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(errors))
    }
}

#[derive(Debug, Clone)]
pub struct CountdownBadge {
    pub label: String,
    pub css_class: &'static str,
}

pub fn format_nis2_countdown(
    prefix: &str,
    due_at: Option<DateTime<Utc>>,
    submitted_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<CountdownBadge> {
    if submitted_at.is_some() {
        return Some(CountdownBadge {
            label: format!("{prefix} ✓"),
            css_class: "badge-ok",
        });
    }

    let due = due_at?;
    let remaining = due.signed_duration_since(now);
    if remaining <= Duration::zero() {
        let overdue_h = (-remaining.num_hours()).max(1);
        return Some(CountdownBadge {
            label: format!("{prefix} -{overdue_h}h"),
            css_class: "badge-crit",
        });
    }

    let hours = remaining.num_hours();
    if remaining <= Duration::hours(12) {
        let label = if hours >= 1 {
            format!("{prefix} {hours}h")
        } else {
            let mins = remaining.num_minutes().max(1);
            format!("{prefix} {mins}m")
        };
        return Some(CountdownBadge {
            label,
            css_class: "badge-warn",
        });
    }

    let label = if hours >= 48 {
        format!("{prefix} {}d", remaining.num_days())
    } else {
        format!("{prefix} {hours}h")
    };
    Some(CountdownBadge {
        label,
        css_class: "badge-ok",
    })
}

pub fn can_view_incident(
    user: &CurrentUser,
    owner_unit_id: Option<Uuid>,
    reported_by_user_id: Option<Uuid>,
    lead_handler_id: Option<Uuid>,
) -> bool {
    match user.role {
        Role::Admin | Role::Iso | Role::Auditor => true,
        Role::Owner => {
            (owner_unit_id.is_some() && owner_unit_id == user.organization_unit_id)
                || reported_by_user_id == Some(user.id)
                || lead_handler_id == Some(user.id)
        }
        Role::Employee => reported_by_user_id == Some(user.id),
    }
}

pub fn can_edit_incident_or_timeline(
    user: &CurrentUser,
    owner_unit_id: Option<Uuid>,
    reported_by_user_id: Option<Uuid>,
    lead_handler_id: Option<Uuid>,
) -> bool {
    match user.role {
        Role::Admin | Role::Iso => true,
        Role::Owner => {
            (owner_unit_id.is_some() && owner_unit_id == user.organization_unit_id)
                || reported_by_user_id == Some(user.id)
                || lead_handler_id == Some(user.id)
        }
        Role::Auditor | Role::Employee => false,
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/incidents",
            get(register::list_incidents_handler).post(actions::create_incident_handler),
        )
        .route("/incidents/new", get(register::new_incident_form_handler))
        .route(
            "/incidents/report",
            get(register::report_form_handler).post(actions::submit_employee_report_handler),
        )
        .route(
            "/incidents/{id}",
            get(register::incident_detail_handler).post(actions::update_incident_handler),
        )
        .route(
            "/incidents/{id}/drawer",
            get(register::incident_drawer_handler),
        )
        .route(
            "/incidents/{id}/timeline",
            post(actions::add_timeline_event_handler),
        )
        .route(
            "/incidents/{id}/nis2/submit",
            post(actions::submit_nis2_report_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_nis2_deadlines_calculates_24h_72h_and_30d() {
        let detected = DateTime::parse_from_rfc3339("2026-11-21T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let initial =
            compute_nis2_deadlines(true, detected, None, None, None, Nis2Deadlines::default());
        assert_eq!(
            initial.early_warning_due_at,
            Some(detected + Duration::hours(24))
        );
        assert_eq!(
            initial.incident_report_due_at,
            Some(detected + Duration::hours(72))
        );
        assert_eq!(initial.final_report_due_at, None);

        let report_sub = detected + Duration::hours(40);
        let with_report = compute_nis2_deadlines(
            true,
            detected,
            Some(detected + Duration::hours(10)),
            Some(report_sub),
            None,
            initial,
        );
        assert_eq!(
            with_report.final_report_due_at,
            Some(report_sub + Duration::days(30))
        );

        let cleared = compute_nis2_deadlines(false, detected, None, None, None, initial);
        assert_eq!(cleared.early_warning_due_at, None);
        assert_eq!(cleared.incident_report_due_at, None);
        assert_eq!(cleared.final_report_due_at, None);
    }

    #[test]
    fn closure_guard_requires_root_cause_and_lessons_learned() {
        assert!(validate_closure_guard(IncidentStatus::Eradicated, None, None).is_ok());
        assert!(validate_closure_guard(IncidentStatus::Closed, Some("Ursache"), None).is_err());
        assert!(validate_closure_guard(IncidentStatus::Closed, Some(" "), Some("Lehre")).is_err());
        assert!(
            validate_closure_guard(IncidentStatus::Closed, Some("Phishing"), Some("MFA")).is_ok()
        );
    }

    #[test]
    fn countdown_badge_reflects_thresholds() {
        let now = DateTime::parse_from_rfc3339("2026-11-21T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let green =
            format_nis2_countdown("24h", Some(now + Duration::hours(18)), None, now).unwrap();
        assert_eq!(green.css_class, "badge-ok");

        let yellow =
            format_nis2_countdown("24h", Some(now + Duration::hours(6)), None, now).unwrap();
        assert_eq!(yellow.css_class, "badge-warn");

        let red = format_nis2_countdown("24h", Some(now - Duration::hours(2)), None, now).unwrap();
        assert_eq!(red.css_class, "badge-crit");

        let done = format_nis2_countdown("24h", Some(now), Some(now), now).unwrap();
        assert_eq!(done.css_class, "badge-ok");
        assert_eq!(done.label, "24h ✓");
    }
}
