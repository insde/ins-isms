pub mod board;
pub mod capa;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};
use chrono::{Months, NaiveDate, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role, forbid_auditor},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionSourceType {
    RiskTreatment,
    SoaGap,
    AuditFinding,
    IncidentCapa,
    RecurringCompliance,
    General,
}

impl ActionSourceType {
    pub const ALL: [Self; 6] = [
        Self::RiskTreatment,
        Self::SoaGap,
        Self::AuditFinding,
        Self::IncidentCapa,
        Self::RecurringCompliance,
        Self::General,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RiskTreatment => "risk_treatment",
            Self::SoaGap => "soa_gap",
            Self::AuditFinding => "audit_finding",
            Self::IncidentCapa => "incident_capa",
            Self::RecurringCompliance => "recurring_compliance",
            Self::General => "general",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::RiskTreatment => "Risikobehandlung",
            Self::SoaGap => "SoA-Lücke",
            Self::AuditFinding => "Audit-Abweichung",
            Self::IncidentCapa => "Vorfalls-CAPA",
            Self::RecurringCompliance => "Routineaufgabe",
            Self::General => "Allgemein",
        }
    }

    pub fn requires_iso102_verification(self) -> bool {
        matches!(self, Self::AuditFinding | Self::IncidentCapa)
    }
}

impl fmt::Display for ActionSourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionSourceType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "risk_treatment" => Ok(Self::RiskTreatment),
            "soa_gap" => Ok(Self::SoaGap),
            "audit_finding" => Ok(Self::AuditFinding),
            "incident_capa" => Ok(Self::IncidentCapa),
            "recurring_compliance" => Ok(Self::RecurringCompliance),
            "general" => Ok(Self::General),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Maßnahmentyp: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl ActionPriority {
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

impl fmt::Display for ActionPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionPriority {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(AppError::Validation(vec![format!(
                "Ungültige Priorität: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Open,
    InProgress,
    Review,
    Done,
    Cancelled,
}

impl ActionStatus {
    pub const ALL: [Self; 5] = [
        Self::Open,
        Self::InProgress,
        Self::Review,
        Self::Done,
        Self::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Review => "review",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "Offen",
            Self::InProgress => "In Bearbeitung",
            Self::Review => "In Prüfung",
            Self::Done => "Erledigt",
            Self::Cancelled => "Verworfen",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Open => "badge-neutral",
            Self::InProgress => "badge-info",
            Self::Review => "badge-warn",
            Self::Done => "badge-ok",
            Self::Cancelled => "badge-neutral",
        }
    }

    pub fn next_cycle(self, can_close_directly: bool) -> Self {
        match self {
            Self::Open => Self::InProgress,
            Self::InProgress => Self::Review,
            Self::Review => {
                if can_close_directly {
                    Self::Done
                } else {
                    Self::Open
                }
            }
            Self::Done | Self::Cancelled => Self::Open,
        }
    }
}

impl fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "open" => Ok(Self::Open),
            "in_progress" => Ok(Self::InProgress),
            "review" => Ok(Self::Review),
            "done" => Ok(Self::Done),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Maßnahmen-Status: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurrenceInterval {
    Monthly,
    Quarterly,
    SemiAnnually,
    Annually,
}

impl RecurrenceInterval {
    pub const ALL: [Self; 4] = [
        Self::Monthly,
        Self::Quarterly,
        Self::SemiAnnually,
        Self::Annually,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
            Self::SemiAnnually => "semi_annually",
            Self::Annually => "annually",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Monthly => "Monatlich",
            Self::Quarterly => "Quartalsweise",
            Self::SemiAnnually => "Halbjährlich",
            Self::Annually => "Jährlich",
        }
    }

    pub fn months(self) -> u32 {
        match self {
            Self::Monthly => 1,
            Self::Quarterly => 3,
            Self::SemiAnnually => 6,
            Self::Annually => 12,
        }
    }
}

impl fmt::Display for RecurrenceInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecurrenceInterval {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "monthly" => Ok(Self::Monthly),
            "quarterly" => Ok(Self::Quarterly),
            "semi_annually" => Ok(Self::SemiAnnually),
            "annually" => Ok(Self::Annually),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiges Wiederholungsintervall: {other}"
            )])),
        }
    }
}

pub fn shift_due_date(base: NaiveDate, interval: RecurrenceInterval) -> NaiveDate {
    base.checked_add_months(Months::new(interval.months()))
        .unwrap_or(base)
}

pub fn validate_action_transition(
    user: &CurrentUser,
    source_type: ActionSourceType,
    target_status: ActionStatus,
    verification_note: Option<&str>,
) -> Result<(), AppError> {
    if source_type.requires_iso102_verification() && target_status == ActionStatus::Done {
        if !user.role.is_iso_or_admin() {
            return Err(AppError::Forbidden(
                "Die finale Wirksamkeitsprüfung (Erledigt) für Audit-Abweichungen und Vorfalls-CAPAs ist ausschließlich Admin oder ISB vorbehalten."
                    .to_string(),
            ));
        }
        if verification_note.map(str::trim).unwrap_or("").is_empty() {
            return Err(AppError::Validation(vec![
                "Für Audit-Abweichungen und Vorfalls-CAPAs ist beim Abschluss ein Wirksamkeitsnachweis (ISO 10.2) erforderlich."
                    .to_string(),
            ]));
        }
    }
    Ok(())
}

pub fn ensure_action_read_access(
    user: &CurrentUser,
    assignee_user_id: Option<Uuid>,
    owner_unit_id: Option<Uuid>,
) -> Result<(), AppError> {
    match user.role {
        Role::Admin | Role::Iso | Role::Auditor => Ok(()),
        Role::Owner => {
            let in_unit =
                user.organization_unit_id.is_some() && owner_unit_id == user.organization_unit_id;
            let is_assignee = assignee_user_id == Some(user.id);
            if in_unit || is_assignee {
                Ok(())
            } else {
                Err(AppError::Forbidden(
                    "Kein Zugriff auf Maßnahmen außerhalb Ihrer Organisationseinheit.".to_string(),
                ))
            }
        }
        Role::Employee => {
            if assignee_user_id == Some(user.id) {
                Ok(())
            } else {
                Err(AppError::Forbidden(
                    "Sie können nur direkt Ihnen zugewiesene Aufgaben einsehen.".to_string(),
                ))
            }
        }
    }
}

pub fn ensure_action_write_access(
    user: &CurrentUser,
    assignee_user_id: Option<Uuid>,
    owner_unit_id: Option<Uuid>,
) -> Result<(), AppError> {
    forbid_auditor(user)?;
    match user.role {
        Role::Admin | Role::Iso => Ok(()),
        Role::Owner => {
            let in_unit =
                user.organization_unit_id.is_some() && owner_unit_id == user.organization_unit_id;
            let is_assignee = assignee_user_id == Some(user.id);
            if in_unit || is_assignee {
                Ok(())
            } else {
                Err(AppError::Forbidden(
                    "Sie dürfen nur Maßnahmen Ihrer Organisationseinheit oder eigene Aufgaben bearbeiten."
                        .to_string(),
                ))
            }
        }
        Role::Employee => Err(AppError::Forbidden(
            "Mitarbeitende haben nur Lesezugriff auf zugewiesene Aufgaben.".to_string(),
        )),
        Role::Auditor => unreachable!("forbid_auditor schließt Auditor aus"),
    }
}

pub async fn next_action_reference_code(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<String, AppError> {
    let next_num: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(
            MAX(
                CASE
                    WHEN reference_code ~ '^ACT-[0-9]+$'
                    THEN SUBSTRING(reference_code FROM 5)::BIGINT
                    ELSE 0
                END
            ),
            0
        ) + 1
        FROM action_items
        "#,
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(format!("ACT-{next_num:03}"))
}

pub async fn generate_next_recurrence_tx(
    tx: &mut Transaction<'_, Postgres>,
    action_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            title,
            description,
            source_type,
            linked_risk_id,
            linked_soa_entry_id,
            linked_audit_finding_id,
            linked_incident_id,
            assignee_user_id,
            owner_unit_id,
            priority,
            due_date,
            recurrence_interval,
            recurrence_parent_id,
            recurrence_next_generated
        FROM action_items
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(action_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some(r) = row else {
        return Ok(None);
    };

    let next_generated: bool = r.get("recurrence_next_generated");
    let interval_raw: Option<String> = r.get("recurrence_interval");
    let Some(interval_str) = interval_raw else {
        return Ok(None);
    };
    if next_generated {
        return Ok(None);
    }

    let interval = RecurrenceInterval::from_str(&interval_str)?;
    let base_date: NaiveDate = r
        .get::<Option<NaiveDate>, _>("due_date")
        .unwrap_or_else(|| Utc::now().date_naive());
    let next_due = shift_due_date(base_date, interval);
    let next_code = next_action_reference_code(tx).await?;
    let parent_id: Uuid = r
        .get::<Option<Uuid>, _>("recurrence_parent_id")
        .unwrap_or_else(|| r.get("id"));

    let new_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO action_items (
            reference_code,
            title,
            description,
            source_type,
            linked_risk_id,
            linked_soa_entry_id,
            linked_audit_finding_id,
            linked_incident_id,
            assignee_user_id,
            owner_unit_id,
            priority,
            status,
            due_date,
            recurrence_interval,
            recurrence_parent_id,
            recurrence_next_generated
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'open', $12, $13, $14, FALSE)
        RETURNING id
        "#,
    )
    .bind(&next_code)
    .bind(r.get::<String, _>("title"))
    .bind(r.get::<Option<String>, _>("description"))
    .bind(r.get::<String, _>("source_type"))
    .bind(r.get::<Option<Uuid>, _>("linked_risk_id"))
    .bind(r.get::<Option<Uuid>, _>("linked_soa_entry_id"))
    .bind(r.get::<Option<Uuid>, _>("linked_audit_finding_id"))
    .bind(r.get::<Option<Uuid>, _>("linked_incident_id"))
    .bind(r.get::<Option<Uuid>, _>("assignee_user_id"))
    .bind(r.get::<Option<Uuid>, _>("owner_unit_id"))
    .bind(r.get::<String, _>("priority"))
    .bind(next_due)
    .bind(interval.as_str())
    .bind(parent_id)
    .fetch_one(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE action_items
        SET recurrence_next_generated = TRUE,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(action_id)
    .execute(&mut **tx)
    .await?;

    Ok(Some(new_id))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/actions",
            get(board::list_actions_handler).post(board::create_action_handler),
        )
        .route("/actions/new", get(board::new_action_drawer_handler))
        .route("/actions/{id}", post(board::update_action_handler))
        .route("/actions/{id}/drawer", get(board::action_drawer_handler))
        .route(
            "/actions/{id}/verify-modal",
            get(board::verify_modal_handler),
        )
        .route("/actions/{id}/status", post(board::quick_status_handler))
        .route("/actions/{id}/assign", post(board::quick_assign_handler))
        .route(
            "/incidents/{id}/capa",
            post(capa::create_incident_capa_handler),
        )
        .route(
            "/audits/{audit_id}/findings/{finding_id}/capa",
            post(capa::create_finding_capa_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn shift_due_date_handles_intervals_and_month_end() {
        let base = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        assert_eq!(
            shift_due_date(base, RecurrenceInterval::Monthly),
            NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()
        );
        assert_eq!(
            shift_due_date(base, RecurrenceInterval::Quarterly),
            NaiveDate::from_ymd_opt(2026, 4, 30).unwrap()
        );
        assert_eq!(
            shift_due_date(base, RecurrenceInterval::SemiAnnually),
            NaiveDate::from_ymd_opt(2026, 7, 31).unwrap()
        );
        assert_eq!(
            shift_due_date(base, RecurrenceInterval::Annually),
            NaiveDate::from_ymd_opt(2027, 1, 31).unwrap()
        );
    }

    #[test]
    fn iso102_guard_blocks_owner_and_empty_verification_note() {
        let owner = CurrentUser {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4().to_string(),
            email: "owner@example.com".to_string(),
            full_name: "Owner".to_string(),
            role: Role::Owner,
            organization_unit_id: None,
            csrf_token: String::new(),
        };
        let iso = CurrentUser {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4().to_string(),
            email: "iso@example.com".to_string(),
            full_name: "ISB".to_string(),
            role: Role::Iso,
            organization_unit_id: None,
            csrf_token: String::new(),
        };

        assert!(matches!(
            validate_action_transition(
                &owner,
                ActionSourceType::AuditFinding,
                ActionStatus::Done,
                Some("Geprüft"),
            ),
            Err(AppError::Forbidden(_))
        ));

        assert!(matches!(
            validate_action_transition(
                &iso,
                ActionSourceType::IncidentCapa,
                ActionStatus::Done,
                Some("   "),
            ),
            Err(AppError::Validation(_))
        ));

        assert!(
            validate_action_transition(
                &iso,
                ActionSourceType::IncidentCapa,
                ActionStatus::Done,
                Some("Wirksamkeit im Wiederholungstest bestätigt"),
            )
            .is_ok()
        );
    }
}
