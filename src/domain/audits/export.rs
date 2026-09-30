use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser},
    domain::audits::{KpiSnapshot, ReviewStatus, ensure_audit_read_access},
    error::AppError,
    pdf::{PdfDocumentMetadata, PdfRenderer, TypstCliRenderer},
    state::AppState,
};

pub async fn render_review_pdf_bytes(
    pool: &sqlx::PgPool,
    config: &crate::config::Config,
    review_id: Uuid,
) -> Result<(String, ReviewStatus, Vec<u8>), AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            mr.id,
            mr.review_date,
            mr.period_label,
            mr.participants,
            mr.status,
            mr.kpi_snapshot_json,
            mr.management_decisions,
            mr.approved_at,
            u.full_name AS approved_by_name
        FROM management_reviews mr
        LEFT JOIN users u ON u.id = mr.approved_by_user_id
        WHERE mr.id = $1
        "#,
    )
    .bind(review_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Management-Bewertung nicht gefunden.".to_string()))?;

    let status = ReviewStatus::from_str(row.get::<&str, _>("status"))?;

    let company_name: String =
        sqlx::query_scalar("SELECT company_name FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?
            .unwrap_or_else(|| "Meine Organisation".to_string());

    let review_date: NaiveDate = row.get("review_date");
    let period_label: String = row.get("period_label");
    let participants: String = row.get("participants");
    let decisions: String = row.get("management_decisions");
    let approved_at: Option<DateTime<Utc>> = row.get("approved_at");
    let approved_by_name: Option<String> = row.get("approved_by_name");
    let kpi: KpiSnapshot = serde_json::from_value(row.get("kpi_snapshot_json"))
        .map_err(|e| AppError::Internal(format!("Ungültiger KPI-Snapshot: {e}")))?;

    let markdown =
        build_review_markdown(&period_label, review_date, &participants, &decisions, &kpi);

    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: format!("MR-{}", review_date.format("%Y-%m")),
        title: format!("Management-Bewertung (ISO 27001 Kap. 9.3) · {period_label}"),
        version: if status == ReviewStatus::Approved {
            "1.0 (Freigegeben)".to_string()
        } else {
            "0.1 (Entwurf)".to_string()
        },
        status: status.label().to_string(),
        classification: "C2 · Intern".to_string(),
        owner_unit: "Geschäftsführung & ISB".to_string(),
        approved_by: approved_by_name.unwrap_or_else(|| "–".to_string()),
        approved_at: approved_at
            .map(|ts| ts.format("%d.%m.%Y %H:%M UTC").to_string())
            .unwrap_or_else(|| "Ausstehend".to_string()),
        next_review_at: "Turnusgemäß jährlich (ISO 9.3)".to_string(),
    };

    let renderer = TypstCliRenderer::from_config(config);
    let pdf_bytes = renderer.render_markdown_document(&meta, &markdown).await?;
    Ok((period_label, status, pdf_bytes))
}

pub async fn export_review_pdf_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    Path(review_id): Path<Uuid>,
) -> Result<Response, AppError> {
    ensure_audit_read_access(&user)?;

    let (period_label, status, pdf_bytes) =
        render_review_pdf_bytes(&state.pool, &state.config, review_id).await?;
    if status == ReviewStatus::Draft && !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Entwürfe von Management-Bewertungen können nur von Admin oder ISB exportiert werden."
                .to_string(),
        ));
    }

    AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip),
        "management_review.exported_pdf",
        "management_reviews",
        &review_id.to_string(),
        &format!("Management-Bewertung '{period_label}' als PDF exportiert."),
        None,
        None,
    )
    .await?;

    let safe_period: String = period_label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let filename = format!("Management-Bewertung_{safe_period}.pdf");
    let disposition = format!("attachment; filename=\"{filename}\"");

    let mut resp = (StatusCode::OK, pdf_bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(val) = HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, val);
    }
    Ok(resp)
}

fn build_review_markdown(
    period_label: &str,
    review_date: NaiveDate,
    participants: &str,
    decisions: &str,
    kpi: &KpiSnapshot,
) -> String {
    let decisions_body = if decisions.trim().is_empty() {
        "Keine gesonderten Beschlüsse protokolliert."
    } else {
        decisions.trim()
    };

    format!(
        r#"# 1. Rahmenbedingungen & Teilnehmer

- **Berichtszeitraum:** {period_label}
- **Bewertungsdatum:** {date}
- **KPI-Snapshot-Zeitpunkt:** {snap_ts}
- **Teilnehmerkreis:** {participants}

# 2. ISO 27001 Kap. 9.3 Kennzahlen-Snapshot

| Themenbereich | Kennzahl | Wert |
|---|---|---|
| SoA & Controls | Anwendbare Controls umgesetzt / verifiziert | {soa_impl} / {soa_app} ({soa_pct:.1} %) |
| SoA & Controls | Offene Umsetzungslücken | {soa_gaps} |
| Risikomanagement | Risiken gesamt (Kritisch / Hoch / Mittel / Niedrig) | {risk_tot} ({r_crit} / {r_high} / {r_med} / {r_low}) |
| Risikomanagement | Unakzeptierte hohe/kritische Risiken | {r_unacc} |
| Sicherheitsvorfälle | Vorfälle gesamt / davon NIS2-relevant | {inc_tot} / {inc_nis2} |
| Sicherheitsvorfälle | Fristgerechte / überfällige BSI-Meldungen | {inc_ok} / {inc_over} |
| Dokumentenlenkung | Freigegebene Dokumente | {doc_app} / {doc_tot} ({doc_pct:.1} %) |
| Dokumentenlenkung | Überfällige Reviews / Lesebestätigungsquote | {doc_over} / {doc_ack:.1} % |
| Audits & Maßnahmen | Offene Major NC / Minor NC (gesamt offen) | {nc_maj} / {nc_min} ({nc_tot}) |
| Audits & Maßnahmen | Offene / überfällige Maßnahmen (CAPA) | {act_open} / {act_over} |

# 3. Beschlüsse der Geschäftsführung

{decisions_body}
"#,
        date = review_date.format("%d.%m.%Y"),
        snap_ts = kpi.generated_at,
        soa_impl = kpi.soa.implemented_count,
        soa_app = kpi.soa.applicable_count,
        soa_pct = kpi.soa.implementation_percent,
        soa_gaps = kpi.soa.open_gaps_count,
        risk_tot = kpi.risks.total_count,
        r_crit = kpi.risks.critical_count,
        r_high = kpi.risks.high_count,
        r_med = kpi.risks.medium_count,
        r_low = kpi.risks.low_count,
        r_unacc = kpi.risks.unaccepted_high_critical,
        inc_tot = kpi.incidents.total_count,
        inc_nis2 = kpi.incidents.nis2_significant_count,
        inc_ok = kpi.incidents.timely_bsi_reports,
        inc_over = kpi.incidents.overdue_bsi_reports,
        doc_app = kpi.documents.approved_documents,
        doc_tot = kpi.documents.total_documents,
        doc_pct = kpi.documents.approved_ratio_percent,
        doc_over = kpi.documents.overdue_reviews,
        doc_ack = kpi.documents.acknowledgment_rate_percent,
        nc_maj = kpi.audits_and_actions.open_major_nc,
        nc_min = kpi.audits_and_actions.open_minor_nc,
        nc_tot = kpi.audits_and_actions.open_findings_total,
        act_open = kpi.audits_and_actions.open_actions,
        act_over = kpi.audits_and_actions.overdue_actions,
    )
}
