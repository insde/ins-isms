use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    domain::soa::{EvidenceType, ImplementationStatus, MappingType, domain_display_label},
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, render_template},
};

#[derive(Debug, Deserialize)]
pub struct SoaFilterQuery {
    pub framework: Option<String>,
    pub filter: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FrameworkTab {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub version: String,
    pub is_selected: bool,
}

#[derive(Debug, Clone)]
pub struct SoaRowView {
    pub soa_id: Uuid,
    pub control_id: Uuid,
    pub control_code: String,
    pub title: String,
    pub domain_label: String,
    pub is_applicable: bool,
    pub status_str: &'static str,
    pub status_label: &'static str,
    pub status_css: &'static str,
    pub owner_label: String,
    pub target_date_label: String,
    pub is_overdue: bool,
    pub evidence_count: i64,
    pub mapping_count: i64,
    pub can_edit: bool,
}

#[derive(Debug, Clone)]
pub struct SoaDomainGroup {
    pub domain_label: String,
    pub rows: Vec<SoaRowView>,
}

#[derive(Debug, Clone)]
pub struct SoaKpis {
    pub total: usize,
    pub applicable: usize,
    pub not_applicable: usize,
    pub implemented_or_verified: usize,
    pub verified: usize,
    pub gaps: usize,
    pub no_evidence: usize,
    pub overdue: usize,
}

#[derive(Template)]
#[template(path = "soa/matrix.html")]
struct SoaMatrixTemplate {
    frameworks: Vec<FrameworkTab>,
    selected_framework_code: String,
    selected_framework_name: String,
    active_filter: String,
    filter_q: String,
    kpis: SoaKpis,
    groups: Vec<SoaDomainGroup>,
    is_auditor: bool,
}

#[derive(Debug, Clone)]
pub struct EvidenceView {
    pub id: Uuid,
    pub title: String,
    pub evidence_type_str: &'static str,
    pub evidence_type_label: &'static str,
    pub original_filename: String,
    pub file_sha256_short: String,
    pub linked_document_id: Option<Uuid>,
    pub document_label: String,
    pub section_anchor: String,
    pub section_label: String,
    pub document_has_approved: bool,
    pub show_unapproved_warning: bool,
    pub evidence_url: String,
    pub evidence_note: String,
    pub is_verified: bool,
    pub verified_info: String,
}

#[derive(Debug, Clone)]
pub struct CrossMappingView {
    pub target_soa_id: Uuid,
    pub framework_code: String,
    pub control_code: String,
    pub title: String,
    pub mapping_type_label: &'static str,
    pub status_label: &'static str,
    pub status_css: &'static str,
    pub is_applicable: bool,
}

#[derive(Debug, Clone)]
pub struct SelectOption {
    pub id: Uuid,
    pub label: String,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "soa/drawer.html")]
struct SoaDrawerTemplate {
    soa_id: Uuid,
    framework_code: String,
    control_code: String,
    domain_label: String,
    title: String,
    description: String,
    audit_question: String,
    default_na_reason: String,
    is_applicable: bool,
    justification: String,
    status_str: &'static str,
    status_label: &'static str,
    status_css: &'static str,
    implementation_notes: String,
    target_date_value: String,
    owner_label: String,
    unit_options: Vec<SelectOption>,
    user_options: Vec<SelectOption>,
    evidences: Vec<EvidenceView>,
    mappings: Vec<CrossMappingView>,
    can_edit: bool,
    can_verify: bool,
    is_auditor: bool,
}

#[derive(Template)]
#[template(path = "soa/applicability_modal.html")]
struct ApplicabilityModalTemplate {
    soa_id: Uuid,
    control_code: String,
    title: String,
    default_na_reason: String,
    current_justification: String,
}

#[derive(Template)]
#[template(path = "soa/evidence_form.html")]
struct EvidenceFormTemplate {
    soa_id: Uuid,
    control_code: String,
    title: String,
    doc_options: Vec<SelectOption>,
}

pub async fn list_soa_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(query): Query<SoaFilterQuery>,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf die Statement of Applicability.".to_string(),
        ));
    }

    let fw_rows = sqlx::query(
        r#"
        SELECT id, code, name, version
        FROM compliance_frameworks
        WHERE is_active = TRUE
        ORDER BY (code = 'ISO27001_2022_STARTER') DESC, name ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    if fw_rows.is_empty() {
        return Err(AppError::NotFound(
            "Kein aktives Compliance-Framework gefunden.".to_string(),
        ));
    }

    let requested_fw = query.framework.as_deref().unwrap_or("").trim();
    let mut selected_fw_id = fw_rows[0].get::<Uuid, _>("id");
    let mut selected_fw_code = fw_rows[0].get::<String, _>("code");
    let mut selected_fw_name = fw_rows[0].get::<String, _>("name");

    for r in &fw_rows {
        let code: &str = r.get("code");
        if !requested_fw.is_empty() && code.eq_ignore_ascii_case(requested_fw) {
            selected_fw_id = r.get("id");
            selected_fw_code = code.to_string();
            selected_fw_name = r.get("name");
            break;
        }
    }

    let frameworks: Vec<FrameworkTab> = fw_rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            FrameworkTab {
                id,
                code: r.get("code"),
                name: r.get("name"),
                version: r.get("version"),
                is_selected: id == selected_fw_id,
            }
        })
        .collect();

    let rows = sqlx::query(
        r#"
        SELECT
            se.id AS soa_id,
            fc.id AS control_id,
            fc.code AS control_code,
            fc.domain,
            fc.title,
            se.is_applicable,
            se.implementation_status,
            se.owner_unit_id,
            se.owner_user_id,
            se.target_date,
            COALESCE(u.full_name, ou.name, 'Nicht zugewiesen') AS owner_label,
            (SELECT COUNT(*) FROM control_evidences ce WHERE ce.soa_entry_id = se.id) AS evidence_count,
            (SELECT COUNT(*) FROM control_mappings cm WHERE cm.source_control_id = fc.id OR cm.target_control_id = fc.id) AS mapping_count
        FROM framework_controls fc
        JOIN soa_entries se ON se.control_id = fc.id
        LEFT JOIN users u ON u.id = se.owner_user_id
        LEFT JOIN organization_units ou ON ou.id = se.owner_unit_id
        WHERE fc.framework_id = $1
        ORDER BY fc.sort_order ASC, fc.code ASC
        "#,
    )
    .bind(selected_fw_id)
    .fetch_all(&state.pool)
    .await?;

    let today = Utc::now().date_naive();
    let active_filter = query
        .filter
        .as_deref()
        .unwrap_or("all")
        .trim()
        .to_ascii_lowercase();
    let filter_q = query.q.unwrap_or_default().trim().to_string();
    let q_lower = filter_q.to_ascii_lowercase();

    let mut total = 0usize;
    let mut applicable = 0usize;
    let mut not_applicable = 0usize;
    let mut implemented_or_verified = 0usize;
    let mut verified = 0usize;
    let mut gaps = 0usize;
    let mut no_evidence = 0usize;
    let mut overdue = 0usize;

    let mut groups: Vec<SoaDomainGroup> = Vec::new();

    for r in rows {
        let soa_id: Uuid = r.get("soa_id");
        let control_id: Uuid = r.get("control_id");
        let control_code: String = r.get("control_code");
        let domain_raw: String = r.get("domain");
        let title: String = r.get("title");
        let is_applicable: bool = r.get("is_applicable");
        let status = ImplementationStatus::from_str(r.get::<&str, _>("implementation_status"))?;
        let owner_unit_id: Option<Uuid> = r.get("owner_unit_id");
        let owner_user_id: Option<Uuid> = r.get("owner_user_id");
        let target_date: Option<NaiveDate> = r.get("target_date");
        let owner_label: String = r.get("owner_label");
        let evidence_count: i64 = r.get("evidence_count");
        let mapping_count: i64 = r.get("mapping_count");

        let is_overdue = is_applicable
            && !matches!(
                status,
                ImplementationStatus::Implemented | ImplementationStatus::Verified
            )
            && target_date.is_some_and(|d| d < today);

        total += 1;
        if is_applicable {
            applicable += 1;
            if matches!(
                status,
                ImplementationStatus::Implemented | ImplementationStatus::Verified
            ) {
                implemented_or_verified += 1;
            }
            if status == ImplementationStatus::Verified {
                verified += 1;
            }
            if matches!(
                status,
                ImplementationStatus::NotStarted | ImplementationStatus::InProgress
            ) {
                gaps += 1;
            }
            if evidence_count == 0 {
                no_evidence += 1;
            }
            if is_overdue {
                overdue += 1;
            }
        } else {
            not_applicable += 1;
        }

        let matches_filter = match active_filter.as_str() {
            "applicable" => is_applicable,
            "not_applicable" => !is_applicable,
            "gaps" => {
                is_applicable
                    && matches!(
                        status,
                        ImplementationStatus::NotStarted | ImplementationStatus::InProgress
                    )
            }
            "no_evidence" => is_applicable && evidence_count == 0,
            "overdue" => is_overdue,
            _ => true,
        };

        let matches_q = q_lower.is_empty()
            || control_code.to_ascii_lowercase().contains(&q_lower)
            || title.to_ascii_lowercase().contains(&q_lower)
            || owner_label.to_ascii_lowercase().contains(&q_lower);

        if !matches_filter || !matches_q {
            continue;
        }

        let domain_label = domain_display_label(&domain_raw).to_string();
        let can_edit = ensure_owner_scope(&user, owner_unit_id, owner_user_id).is_ok();
        let target_date_label = target_date
            .map(|d| d.format("%d.%m.%Y").to_string())
            .unwrap_or_else(|| "–".to_string());

        let item = SoaRowView {
            soa_id,
            control_id,
            control_code,
            title,
            domain_label: domain_label.clone(),
            is_applicable,
            status_str: status.as_str(),
            status_label: status.label(),
            status_css: status.css_class(),
            owner_label,
            target_date_label,
            is_overdue,
            evidence_count,
            mapping_count,
            can_edit,
        };

        if let Some(group) = groups.iter_mut().find(|g| g.domain_label == domain_label) {
            group.rows.push(item);
        } else {
            groups.push(SoaDomainGroup {
                domain_label,
                rows: vec![item],
            });
        }
    }

    let kpis = SoaKpis {
        total,
        applicable,
        not_applicable,
        implemented_or_verified,
        verified,
        gaps,
        no_evidence,
        overdue,
    };

    let shell = ShellContext::from_user(
        &user,
        "Governance & Compliance",
        "Statement of Applicability (SoA)",
        "soa",
    );

    render_page(
        &headers,
        shell,
        &SoaMatrixTemplate {
            frameworks,
            selected_framework_code: selected_fw_code,
            selected_framework_name: selected_fw_name,
            active_filter,
            filter_q,
            kpis,
            groups,
            is_auditor: user.role == Role::Auditor,
        },
    )
}

pub async fn soa_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(soa_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf die Statement of Applicability.".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT
            se.id AS soa_id,
            cf.code AS framework_code,
            fc.id AS control_id,
            fc.code AS control_code,
            fc.domain,
            fc.title,
            fc.description,
            COALESCE(fc.audit_question, '') AS audit_question,
            COALESCE(fc.default_not_applicable_reason, '') AS default_na_reason,
            se.is_applicable,
            se.justification,
            se.implementation_status,
            COALESCE(se.implementation_notes, '') AS implementation_notes,
            se.owner_unit_id,
            se.owner_user_id,
            se.target_date,
            COALESCE(u.full_name, ou.name, 'Nicht zugewiesen') AS owner_label
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        LEFT JOIN users u ON u.id = se.owner_user_id
        LEFT JOIN organization_units ou ON ou.id = se.owner_unit_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    let control_id: Uuid = row.get("control_id");
    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    let can_edit = ensure_owner_scope(&user, owner_unit_id, owner_user_id).is_ok();
    let status = ImplementationStatus::from_str(row.get::<&str, _>("implementation_status"))?;
    let target_date: Option<NaiveDate> = row.get("target_date");

    let ev_rows = sqlx::query(
        r#"
        SELECT
            ce.id,
            ce.title,
            ce.evidence_type,
            COALESCE(ce.original_filename, '') AS original_filename,
            COALESCE(ce.file_sha256, '') AS file_sha256,
            ce.linked_document_id,
            COALESCE(d.doc_code, '') AS doc_code,
            COALESCE(d.title, '') AS doc_title,
            COALESCE(ce.section_anchor, '') AS section_anchor,
            COALESCE(ce.section_label, '') AS section_label,
            COALESCE(ce.evidence_url, '') AS evidence_url,
            COALESCE(ce.evidence_note, '') AS evidence_note,
            ce.verified_at,
            COALESCE(vu.full_name, '') AS verified_by_name,
            EXISTS (
                SELECT 1 FROM document_versions dv
                WHERE dv.document_id = ce.linked_document_id AND dv.status = 'approved'
            ) AS doc_has_approved
        FROM control_evidences ce
        LEFT JOIN documents d ON d.id = ce.linked_document_id
        LEFT JOIN users vu ON vu.id = ce.verified_by_user_id
        WHERE ce.soa_entry_id = $1
        ORDER BY ce.created_at DESC
        "#,
    )
    .bind(soa_id)
    .fetch_all(&state.pool)
    .await?;

    let evidences: Vec<EvidenceView> = ev_rows
        .into_iter()
        .map(|er| {
            let et = EvidenceType::from_str(er.get::<&str, _>("evidence_type"))?;
            let sha: String = er.get("file_sha256");
            let sha_short = if sha.len() >= 12 {
                sha[..12].to_string()
            } else {
                sha
            };
            let doc_code: String = er.get("doc_code");
            let doc_title: String = er.get("doc_title");
            let doc_has_approved: bool = er.get("doc_has_approved");
            let verified_at: Option<DateTime<Utc>> = er.get("verified_at");
            let verified_by_name: String = er.get("verified_by_name");
            let verified_info = verified_at
                .map(|ts| {
                    format!(
                        "Verifiziert von {verified_by_name} am {}",
                        ts.format("%d.%m.%Y")
                    )
                })
                .unwrap_or_default();

            Ok(EvidenceView {
                id: er.get("id"),
                title: er.get("title"),
                evidence_type_str: et.as_str(),
                evidence_type_label: et.label(),
                original_filename: er.get("original_filename"),
                file_sha256_short: sha_short,
                linked_document_id: er.get("linked_document_id"),
                document_label: if doc_code.is_empty() {
                    String::new()
                } else {
                    format!("{doc_code} – {doc_title}")
                },
                section_anchor: er.get("section_anchor"),
                section_label: er.get("section_label"),
                document_has_approved: doc_has_approved,
                show_unapproved_warning: et == EvidenceType::PolicyLink
                    && !doc_has_approved
                    && user.role.is_iso_or_admin(),
                evidence_url: er.get("evidence_url"),
                evidence_note: er.get("evidence_note"),
                is_verified: verified_at.is_some(),
                verified_info,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let map_rows = sqlx::query(
        r#"
        SELECT
            other_se.id AS target_soa_id,
            other_cf.code AS framework_code,
            other_fc.code AS control_code,
            other_fc.title,
            cm.mapping_type,
            other_se.implementation_status,
            other_se.is_applicable
        FROM control_mappings cm
        JOIN framework_controls other_fc
          ON other_fc.id = CASE
              WHEN cm.source_control_id = $1 THEN cm.target_control_id
              ELSE cm.source_control_id
          END
        JOIN compliance_frameworks other_cf ON other_cf.id = other_fc.framework_id
        JOIN soa_entries other_se ON other_se.control_id = other_fc.id
        WHERE cm.source_control_id = $1 OR cm.target_control_id = $1
        ORDER BY other_cf.code ASC, other_fc.sort_order ASC
        "#,
    )
    .bind(control_id)
    .fetch_all(&state.pool)
    .await?;

    let mappings: Vec<CrossMappingView> = map_rows
        .into_iter()
        .map(|mr| {
            let mt = MappingType::from_str(mr.get::<&str, _>("mapping_type"))?;
            let st = ImplementationStatus::from_str(mr.get::<&str, _>("implementation_status"))?;
            Ok(CrossMappingView {
                target_soa_id: mr.get("target_soa_id"),
                framework_code: mr.get("framework_code"),
                control_code: mr.get("control_code"),
                title: mr.get("title"),
                mapping_type_label: mt.label(),
                status_label: st.label(),
                status_css: st.css_class(),
                is_applicable: mr.get("is_applicable"),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    let mut unit_options = Vec::new();
    let mut user_options = Vec::new();
    if can_edit {
        let u_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
            .fetch_all(&state.pool)
            .await?;
        unit_options = u_rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                SelectOption {
                    id,
                    label: r.get("name"),
                    selected: owner_unit_id == Some(id),
                }
            })
            .collect();

        let p_rows = sqlx::query(
            "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
        )
        .fetch_all(&state.pool)
        .await?;
        user_options = p_rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                SelectOption {
                    id,
                    label: r.get("full_name"),
                    selected: owner_user_id == Some(id),
                }
            })
            .collect();
    }

    render_template(&SoaDrawerTemplate {
        soa_id,
        framework_code: row.get("framework_code"),
        control_code: row.get("control_code"),
        domain_label: domain_display_label(row.get::<&str, _>("domain")).to_string(),
        title: row.get("title"),
        description: row.get("description"),
        audit_question: row.get("audit_question"),
        default_na_reason: row.get("default_na_reason"),
        is_applicable: row.get("is_applicable"),
        justification: row.get("justification"),
        status_str: status.as_str(),
        status_label: status.label(),
        status_css: status.css_class(),
        implementation_notes: row.get("implementation_notes"),
        target_date_value: target_date
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        owner_label: row.get("owner_label"),
        unit_options,
        user_options,
        evidences,
        mappings,
        can_edit,
        can_verify: user.role.is_iso_or_admin(),
        is_auditor: user.role == Role::Auditor,
    })
}

pub async fn applicability_modal_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(soa_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            fc.code AS control_code,
            fc.title,
            COALESCE(fc.default_not_applicable_reason, '') AS default_na_reason,
            se.justification,
            se.owner_unit_id,
            se.owner_user_id
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(&user, row.get("owner_unit_id"), row.get("owner_user_id"))?;

    render_template(&ApplicabilityModalTemplate {
        soa_id,
        control_code: row.get("control_code"),
        title: row.get("title"),
        default_na_reason: row.get("default_na_reason"),
        current_justification: row.get("justification"),
    })
}

pub async fn new_evidence_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(soa_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT fc.code AS control_code, fc.title, se.owner_unit_id, se.owner_user_id
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(&user, row.get("owner_unit_id"), row.get("owner_user_id"))?;

    let doc_rows = sqlx::query("SELECT id, doc_code, title FROM documents ORDER BY doc_code ASC")
        .fetch_all(&state.pool)
        .await?;

    let doc_options = doc_rows
        .into_iter()
        .map(|d| SelectOption {
            id: d.get("id"),
            label: format!(
                "{} – {}",
                d.get::<String, _>("doc_code"),
                d.get::<String, _>("title")
            ),
            selected: false,
        })
        .collect();

    render_template(&EvidenceFormTemplate {
        soa_id,
        control_code: row.get("control_code"),
        title: row.get("title"),
        doc_options,
    })
}
