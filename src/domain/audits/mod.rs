#[allow(clippy::module_inception)]
pub mod audits;
pub mod export;
pub mod reviews;

use std::{fmt, str::FromStr};

use axum::{
    Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    Planned,
    InProgress,
    Completed,
}

impl AuditStatus {
    pub const ALL: [Self; 3] = [Self::Planned, Self::InProgress, Self::Completed];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Planned => "Geplant",
            Self::InProgress => "In Durchführung",
            Self::Completed => "Abgeschlossen",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Planned => "badge-neutral",
            Self::InProgress => "badge-warn",
            Self::Completed => "badge-ok",
        }
    }
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuditStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "planned" => Ok(Self::Planned),
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Audit-Status: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingType {
    MajorNc,
    MinorNc,
    Observation,
    Opportunity,
}

impl FindingType {
    pub const ALL: [Self; 4] = [
        Self::MajorNc,
        Self::MinorNc,
        Self::Observation,
        Self::Opportunity,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MajorNc => "major_nc",
            Self::MinorNc => "minor_nc",
            Self::Observation => "observation",
            Self::Opportunity => "opportunity",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MajorNc => "Major NC (Hauptabweichung)",
            Self::MinorNc => "Minor NC (Nebenabweichung)",
            Self::Observation => "Beobachtung",
            Self::Opportunity => "Verbesserungspotenzial",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Self::MajorNc => "Major NC",
            Self::MinorNc => "Minor NC",
            Self::Observation => "Beobachtung",
            Self::Opportunity => "Potenzial",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::MajorNc => "badge-critical",
            Self::MinorNc => "badge-high",
            Self::Observation => "badge-info",
            Self::Opportunity => "badge-neutral",
        }
    }

    pub fn requires_capa_verification(self) -> bool {
        matches!(self, Self::MajorNc | Self::MinorNc)
    }
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FindingType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "major_nc" => Ok(Self::MajorNc),
            "minor_nc" => Ok(Self::MinorNc),
            "observation" => Ok(Self::Observation),
            "opportunity" => Ok(Self::Opportunity),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Finding-Typ: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    ActionPlanned,
    VerifiedClosed,
}

impl FindingStatus {
    pub const ALL: [Self; 3] = [Self::Open, Self::ActionPlanned, Self::VerifiedClosed];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ActionPlanned => "action_planned",
            Self::VerifiedClosed => "verified_closed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "Offen",
            Self::ActionPlanned => "Maßnahme geplant",
            Self::VerifiedClosed => "Wirksamkeit bestätigt",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Open => "badge-warn",
            Self::ActionPlanned => "badge-info",
            Self::VerifiedClosed => "badge-ok",
        }
    }
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FindingStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "open" => Ok(Self::Open),
            "action_planned" => Ok(Self::ActionPlanned),
            "verified_closed" => Ok(Self::VerifiedClosed),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Finding-Status: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewStatus {
    Draft,
    Approved,
}

impl ReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Approved => "approved",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Draft => "Entwurf",
            Self::Approved => "Freigegeben",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Draft => "badge-warn",
            Self::Approved => "badge-ok",
        }
    }
}

impl fmt::Display for ReviewStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReviewStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "draft" => Ok(Self::Draft),
            "approved" => Ok(Self::Approved),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Review-Status: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SoaKpi {
    pub applicable_count: i64,
    pub implemented_count: i64,
    pub open_gaps_count: i64,
    pub implementation_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskKpi {
    pub total_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub unaccepted_high_critical: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncidentKpi {
    pub total_count: i64,
    pub nis2_significant_count: i64,
    pub timely_bsi_reports: i64,
    pub overdue_bsi_reports: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DocumentKpi {
    pub total_documents: i64,
    pub approved_documents: i64,
    pub approved_ratio_percent: f64,
    pub overdue_reviews: i64,
    pub acknowledgment_rate_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditActionKpi {
    pub open_major_nc: i64,
    pub open_minor_nc: i64,
    pub open_findings_total: i64,
    pub open_actions: i64,
    pub overdue_actions: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KpiSnapshot {
    pub generated_at: String,
    pub soa: SoaKpi,
    pub risks: RiskKpi,
    pub incidents: IncidentKpi,
    pub documents: DocumentKpi,
    pub audits_and_actions: AuditActionKpi,
}

pub async fn aggregate_iso93_kpis(pool: &PgPool) -> Result<KpiSnapshot, AppError> {
    let soa_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE se.is_applicable = TRUE) AS applicable_count,
            COUNT(*) FILTER (
                WHERE se.is_applicable = TRUE
                  AND se.implementation_status IN ('implemented', 'verified')
            ) AS implemented_count,
            COUNT(*) FILTER (
                WHERE se.is_applicable = TRUE
                  AND se.implementation_status IN ('not_started', 'in_progress')
            ) AS open_gaps_count
        FROM soa_entries se
        "#,
    )
    .fetch_one(pool)
    .await?;

    let applicable_count: i64 = soa_row.get("applicable_count");
    let implemented_count: i64 = soa_row.get("implemented_count");
    let open_gaps_count: i64 = soa_row.get("open_gaps_count");
    let implementation_percent = if applicable_count > 0 {
        ((implemented_count as f64 / applicable_count as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let risk_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE (residual_likelihood * residual_impact) >= 16) AS critical_count,
            COUNT(*) FILTER (WHERE (residual_likelihood * residual_impact) BETWEEN 10 AND 15) AS high_count,
            COUNT(*) FILTER (WHERE (residual_likelihood * residual_impact) BETWEEN 5 AND 9) AS medium_count,
            COUNT(*) FILTER (WHERE (residual_likelihood * residual_impact) <= 4) AS low_count,
            COUNT(*) FILTER (
                WHERE (residual_likelihood * residual_impact) >= 10
                  AND status NOT IN ('accepted', 'closed')
            ) AS unaccepted_high_critical
        FROM risk_scenarios
        "#,
    )
    .fetch_one(pool)
    .await?;

    let inc_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE is_nis2_significant = TRUE) AS nis2_significant_count,
            COUNT(*) FILTER (
                WHERE is_nis2_significant = TRUE
                  AND early_warning_submitted_at IS NOT NULL
                  AND early_warning_due_at IS NOT NULL
                  AND early_warning_submitted_at <= early_warning_due_at
                  AND (
                      incident_report_due_at IS NULL
                      OR (incident_report_submitted_at IS NOT NULL AND incident_report_submitted_at <= incident_report_due_at)
                  )
            ) AS timely_bsi_reports,
            COUNT(*) FILTER (
                WHERE is_nis2_significant = TRUE
                  AND status <> 'closed'
                  AND (
                      (early_warning_due_at IS NOT NULL AND early_warning_submitted_at IS NULL AND early_warning_due_at < NOW())
                      OR (incident_report_due_at IS NOT NULL AND incident_report_submitted_at IS NULL AND incident_report_due_at < NOW())
                      OR (final_report_due_at IS NOT NULL AND final_report_submitted_at IS NULL AND final_report_due_at < NOW())
                  )
            ) AS overdue_bsi_reports
        FROM security_incidents
        "#,
    )
    .fetch_one(pool)
    .await?;

    let doc_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total_documents,
            COUNT(*) FILTER (
                WHERE EXISTS (
                    SELECT 1 FROM document_versions dv
                    WHERE dv.document_id = d.id AND dv.status = 'approved'
                )
            ) AS approved_documents,
            COUNT(*) FILTER (
                WHERE d.next_review_due_at IS NOT NULL AND d.next_review_due_at <= NOW()
            ) AS overdue_reviews
        FROM documents d
        "#,
    )
    .fetch_one(pool)
    .await?;

    let total_documents: i64 = doc_row.get("total_documents");
    let approved_documents: i64 = doc_row.get("approved_documents");
    let overdue_reviews: i64 = doc_row.get("overdue_reviews");
    let approved_ratio_percent = if total_documents > 0 {
        ((approved_documents as f64 / total_documents as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let ack_row = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM users WHERE is_active = TRUE) AS active_users,
            (
                SELECT COUNT(*)
                FROM documents d
                JOIN document_versions dv ON dv.document_id = d.id AND dv.status = 'approved'
                WHERE d.requires_acknowledgment = TRUE
            ) AS ack_required_docs,
            (
                SELECT COUNT(*)
                FROM document_acknowledgments da
                JOIN document_versions dv ON dv.id = da.document_version_id AND dv.status = 'approved'
                JOIN documents d ON d.id = dv.document_id AND d.requires_acknowledgment = TRUE
                JOIN users u ON u.id = da.user_id AND u.is_active = TRUE
            ) AS ack_done_count
        "#,
    )
    .fetch_one(pool)
    .await?;

    let active_users: i64 = ack_row.get("active_users");
    let ack_required_docs: i64 = ack_row.get("ack_required_docs");
    let ack_done_count: i64 = ack_row.get("ack_done_count");
    let expected_acks = active_users * ack_required_docs;
    let acknowledgment_rate_percent = if expected_acks > 0 {
        ((ack_done_count as f64 / expected_acks as f64) * 1000.0).round() / 10.0
    } else {
        100.0
    };

    let finding_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE status <> 'verified_closed' AND finding_type = 'major_nc') AS open_major_nc,
            COUNT(*) FILTER (WHERE status <> 'verified_closed' AND finding_type = 'minor_nc') AS open_minor_nc,
            COUNT(*) FILTER (WHERE status <> 'verified_closed') AS open_findings_total
        FROM audit_findings
        "#,
    )
    .fetch_one(pool)
    .await?;

    let actions_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.action_items')::text")
            .fetch_one(pool)
            .await?;

    let (open_actions, overdue_actions) = if actions_table.is_some() {
        let act_row = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status IN ('open', 'in_progress', 'review')) AS open_actions,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_progress', 'review')
                      AND due_date < CURRENT_DATE
                ) AS overdue_actions
            FROM action_items
            "#,
        )
        .fetch_one(pool)
        .await?;
        (act_row.get("open_actions"), act_row.get("overdue_actions"))
    } else {
        (0, 0)
    };

    Ok(KpiSnapshot {
        generated_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        soa: SoaKpi {
            applicable_count,
            implemented_count,
            open_gaps_count,
            implementation_percent,
        },
        risks: RiskKpi {
            total_count: risk_row.get("total_count"),
            critical_count: risk_row.get("critical_count"),
            high_count: risk_row.get("high_count"),
            medium_count: risk_row.get("medium_count"),
            low_count: risk_row.get("low_count"),
            unaccepted_high_critical: risk_row.get("unaccepted_high_critical"),
        },
        incidents: IncidentKpi {
            total_count: inc_row.get("total_count"),
            nis2_significant_count: inc_row.get("nis2_significant_count"),
            timely_bsi_reports: inc_row.get("timely_bsi_reports"),
            overdue_bsi_reports: inc_row.get("overdue_bsi_reports"),
        },
        documents: DocumentKpi {
            total_documents,
            approved_documents,
            approved_ratio_percent,
            overdue_reviews,
            acknowledgment_rate_percent,
        },
        audits_and_actions: AuditActionKpi {
            open_major_nc: finding_row.get("open_major_nc"),
            open_minor_nc: finding_row.get("open_minor_nc"),
            open_findings_total: finding_row.get("open_findings_total"),
            open_actions,
            overdue_actions,
        },
    })
}

pub async fn ensure_finding_closable(
    tx: &mut Transaction<'_, Postgres>,
    user: &CurrentUser,
    finding_id: Uuid,
    finding_type: FindingType,
    target_status: FindingStatus,
) -> Result<(), AppError> {
    if target_status != FindingStatus::VerifiedClosed {
        return Ok(());
    }
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Abweichungen wirksam schließen.".to_string(),
        ));
    }
    if !finding_type.requires_capa_verification() {
        return Ok(());
    }

    let actions_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.action_items')::text")
            .fetch_one(&mut **tx)
            .await?;

    if actions_table.is_some() {
        let pending_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM action_items
            WHERE linked_audit_finding_id = $1
              AND (status <> 'done' OR verified_by_user_id IS NULL)
            "#,
        )
        .bind(finding_id)
        .fetch_one(&mut **tx)
        .await?;

        if pending_count > 0 {
            return Err(AppError::Validation(vec![
                "Haupt- und Nebenabweichungen können erst geschlossen werden, wenn alle verknüpften CAPA-Maßnahmen erledigt und wirksamkeitsgeprüft sind."
                    .to_string(),
            ]));
        }
    }

    Ok(())
}

pub fn ensure_audit_read_access(user: &CurrentUser) -> Result<(), AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf Audits und Management-Bewertungen.".to_string(),
        ));
    }
    Ok(())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/audits",
            get(audits::list_audits_handler).post(audits::create_audit_handler),
        )
        .route("/audits/new", get(audits::new_audit_drawer_handler))
        .route(
            "/audits/{id}",
            get(audits::audit_detail_handler).post(audits::update_audit_handler),
        )
        .route("/audits/{id}/drawer", get(audits::audit_drawer_handler))
        .route(
            "/audits/{id}/report",
            get(audits::download_audit_report_handler).post(audits::upload_audit_report_handler),
        )
        .route(
            "/audits/{id}/findings",
            post(audits::create_finding_handler),
        )
        .route(
            "/audits/findings/{fid}/status",
            post(audits::update_finding_status_handler),
        )
        .route(
            "/management-reviews",
            get(reviews::list_reviews_handler).post(reviews::create_review_handler),
        )
        .route("/management-reviews/new", get(reviews::new_review_handler))
        .route(
            "/management-reviews/{id}",
            get(reviews::review_detail_handler).post(reviews::update_review_handler),
        )
        .route(
            "/management-reviews/{id}/refresh-kpis",
            post(reviews::refresh_review_kpis_handler),
        )
        .route(
            "/management-reviews/{id}/approve",
            post(reviews::approve_review_handler),
        )
        .route(
            "/management-reviews/{id}/export.pdf",
            get(export::export_review_pdf_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_roundtrip_and_capa_rules() {
        assert_eq!(
            AuditStatus::from_str("planned").unwrap(),
            AuditStatus::Planned
        );
        assert_eq!(
            AuditStatus::from_str("in_progress").unwrap(),
            AuditStatus::InProgress
        );
        assert_eq!(
            AuditStatus::from_str("completed").unwrap(),
            AuditStatus::Completed
        );

        assert!(FindingType::MajorNc.requires_capa_verification());
        assert!(FindingType::MinorNc.requires_capa_verification());
        assert!(!FindingType::Observation.requires_capa_verification());
        assert!(!FindingType::Opportunity.requires_capa_verification());

        assert_eq!(
            FindingStatus::from_str("verified_closed").unwrap(),
            FindingStatus::VerifiedClosed
        );
        assert_eq!(
            ReviewStatus::from_str("approved").unwrap(),
            ReviewStatus::Approved
        );
    }
}
