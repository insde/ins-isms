use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use axum::{
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser},
    db::begin_audited_tx,
    domain::{
        documents::SourceType,
        soa::{ImplementationStatus, domain_display_label},
    },
    error::AppError,
    pdf::{
        PdfDocumentMetadata, PdfRenderer, TypstCliRenderer, build_iso_document_typst, escape_typst,
        markdown_to_typst_with_labels,
    },
    state::AppState,
};

fn sanitize_label_slug(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(['-', '_']).to_string();
    if trimmed.is_empty() {
        "abschnitt".to_string()
    } else if !trimmed
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        format!("x-{trimmed}")
    } else {
        trimmed
    }
}

struct ApprovedPolicyDoc {
    id: Uuid,
    doc_code: String,
    title: String,
    version_number: String,
    source_type: SourceType,
    content_markdown: String,
    external_url: String,
    original_filename: String,
    file_sha256: String,
    approved_by_name: String,
    approved_at: Option<DateTime<Utc>>,
}

struct CompendiumEvidence {
    title: String,
    evidence_type: String,
    linked_document_id: Option<Uuid>,
    section_anchor: Option<String>,
    section_label: Option<String>,
}

pub async fn audit_compendium_pdf_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
) -> Result<Response, AppError> {
    if !user.role.is_iso_or_admin() && !user.role.is_auditor() {
        return Err(AppError::Forbidden(
            "Nur Administratoren, ISB und Auditoren dürfen das Audit-Kompendium exportieren."
                .to_string(),
        ));
    }

    let org_row = sqlx::query(
        r#"
        SELECT company_name, scope_statement, target_frameworks
        FROM organization_profile
        WHERE id = 1
        "#,
    )
    .fetch_optional(&state.pool)
    .await?;

    let (company_name, scope_statement, target_frameworks) = match org_row {
        Some(r) => {
            let tf_val: serde_json::Value = r.get("target_frameworks");
            let tf_str = match tf_val {
                serde_json::Value::Array(items) => items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (
                r.get::<String, _>("company_name"),
                r.get::<String, _>("scope_statement"),
                tf_str,
            )
        }
        None => (
            "Meine Organisation".to_string(),
            "Nicht definiert".to_string(),
            "ISO/IEC 27001:2022".to_string(),
        ),
    };

    let unit_rows = sqlx::query("SELECT name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;

    // Ausschließlich freigegebene Dokumentversionen in das Kompendium aufnehmen.
    let doc_rows = sqlx::query(
        r#"
        SELECT
            d.id,
            d.doc_code,
            d.title,
            d.source_type,
            dv.version_number,
            COALESCE(dv.content_markdown, '') AS content_markdown,
            COALESCE(dv.external_url, '') AS external_url,
            COALESCE(dv.original_filename, '') AS original_filename,
            COALESCE(dv.file_sha256, '') AS file_sha256,
            COALESCE(ap.full_name, '–') AS approved_by_name,
            dv.approved_at
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        LEFT JOIN users ap ON ap.id = dv.approved_by_id
        WHERE dv.status = 'approved'
        ORDER BY d.doc_code ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut approved_docs = Vec::with_capacity(doc_rows.len());
    let mut doc_label_by_id: HashMap<Uuid, (String, String)> = HashMap::new();
    for r in doc_rows {
        let id: Uuid = r.get("id");
        let doc_code: String = r.get("doc_code");
        let doc_label = format!("doc-{}", sanitize_label_slug(&doc_code));
        doc_label_by_id.insert(id, (doc_code.clone(), doc_label));
        approved_docs.push(ApprovedPolicyDoc {
            id,
            doc_code,
            title: r.get("title"),
            version_number: r.get("version_number"),
            source_type: SourceType::from_str(r.get::<&str, _>("source_type"))?,
            content_markdown: r.get("content_markdown"),
            external_url: r.get("external_url"),
            original_filename: r.get("original_filename"),
            file_sha256: r.get("file_sha256"),
            approved_by_name: r.get("approved_by_name"),
            approved_at: r.get("approved_at"),
        });
    }

    let mut emitted_labels: HashSet<String> = HashSet::new();
    let mut policies_typst = String::new();
    if approved_docs.is_empty() {
        policies_typst.push_str("_Keine freigegebenen Richtlinien vorhanden._\n\n");
    } else {
        for doc in &approved_docs {
            let doc_label = doc_label_by_id
                .get(&doc.id)
                .map(|(_, l)| l.clone())
                .unwrap_or_else(|| format!("doc-{}", sanitize_label_slug(&doc.doc_code)));
            emitted_labels.insert(doc_label.clone());

            let approved_date = doc
                .approved_at
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "–".to_string());

            policies_typst.push_str(&format!(
                "== {}: {} (v{}) <{}>\n\n",
                escape_typst(&doc.doc_code),
                escape_typst(&doc.title),
                escape_typst(&doc.version_number),
                doc_label
            ));
            policies_typst.push_str(&format!(
                "_Freigegeben durch {} am {}_\n\n",
                escape_typst(&doc.approved_by_name),
                escape_typst(&approved_date)
            ));

            match doc.source_type {
                SourceType::MarkdownEditor => {
                    let (rendered, labels) =
                        markdown_to_typst_with_labels(&doc.content_markdown, Some(&doc_label));
                    emitted_labels.extend(labels);
                    policies_typst.push_str(&rendered);
                    policies_typst.push('\n');
                }
                SourceType::ExternalLink => {
                    policies_typst.push_str(&format!(
                        "- Externes Dokument: {}\n\n",
                        escape_typst(&doc.external_url)
                    ));
                }
                SourceType::UploadedFile => {
                    policies_typst.push_str(&format!(
                        "- Dateianhang: {} (SHA-256: `{}`)\n\n",
                        escape_typst(&doc.original_filename),
                        escape_typst(&doc.file_sha256)
                    ));
                }
            }
            policies_typst.push_str("#pagebreak(weak: true)\n");
        }
    }

    let fw_row = sqlx::query(
        r#"
        SELECT id, code, name
        FROM compliance_frameworks
        WHERE is_active = TRUE
        ORDER BY (code = 'ISO27001_2022_STARTER') DESC, name ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.pool)
    .await?;

    let mut soa_typst = String::new();
    let mut soa_count: usize = 0;

    if let Some(fw) = fw_row {
        let fw_id: Uuid = fw.get("id");
        let fw_code: String = fw.get("code");
        let fw_name: String = fw.get("name");

        let soa_rows = sqlx::query(
            r#"
            SELECT
                se.id AS soa_entry_id,
                fc.code,
                fc.domain,
                fc.title,
                se.is_applicable,
                se.justification,
                se.implementation_status
            FROM framework_controls fc
            JOIN soa_entries se ON se.control_id = fc.id
            WHERE fc.framework_id = $1
            ORDER BY fc.sort_order ASC, fc.code ASC
            "#,
        )
        .bind(fw_id)
        .fetch_all(&state.pool)
        .await?;

        soa_count = soa_rows.len();

        let evidence_rows = sqlx::query(
            r#"
            SELECT
                ce.soa_entry_id,
                ce.title,
                ce.evidence_type,
                ce.linked_document_id,
                ce.section_anchor,
                ce.section_label
            FROM control_evidences ce
            JOIN soa_entries se ON se.id = ce.soa_entry_id
            JOIN framework_controls fc ON fc.id = se.control_id
            WHERE fc.framework_id = $1
            ORDER BY ce.created_at ASC
            "#,
        )
        .bind(fw_id)
        .fetch_all(&state.pool)
        .await?;

        let mut evidences_by_soa: HashMap<Uuid, Vec<CompendiumEvidence>> = HashMap::new();
        for ev in evidence_rows {
            let soa_entry_id: Uuid = ev.get("soa_entry_id");
            evidences_by_soa
                .entry(soa_entry_id)
                .or_default()
                .push(CompendiumEvidence {
                    title: ev.get("title"),
                    evidence_type: ev.get("evidence_type"),
                    linked_document_id: ev.get("linked_document_id"),
                    section_anchor: ev.get("section_anchor"),
                    section_label: ev.get("section_label"),
                });
        }

        soa_typst.push_str(&format!(
            "Aktives Referenz-Framework: *{}* (`{}`), {} Controls.\n\n",
            escape_typst(&fw_name),
            escape_typst(&fw_code),
            soa_count
        ));
        soa_typst.push_str("#table(\n  columns: (auto, 1.3fr, auto, auto, 1.8fr),\n  inset: 5pt,\n  stroke: 0.4pt + luma(190),\n");
        soa_typst.push_str("  [*Code*], [*Control & Domäne*], [*Anw.*], [*Status*], [*Begründung & Nachweise (Querverweise)*],\n");

        for row in soa_rows {
            let soa_entry_id: Uuid = row.get("soa_entry_id");
            let code: String = row.get("code");
            let domain = domain_display_label(row.get::<&str, _>("domain"));
            let title: String = row.get("title");
            let is_applicable: bool = row.get("is_applicable");
            let justification: String = row.get("justification");
            let status =
                ImplementationStatus::from_str(row.get::<&str, _>("implementation_status"))?;

            let mut parts: Vec<String> = Vec::new();
            if !justification.trim().is_empty() {
                parts.push(format!(
                    "Begründung: {}",
                    escape_typst(justification.trim())
                ));
            }

            if let Some(evs) = evidences_by_soa.get(&soa_entry_id) {
                for ev in evs {
                    if ev.evidence_type == "policy_link"
                        && let Some(doc_id) = ev.linked_document_id
                        && let Some((doc_code, doc_label)) = doc_label_by_id.get(&doc_id)
                    {
                        let link_text = match ev.section_label.as_deref() {
                            Some(lbl) if !lbl.trim().is_empty() => {
                                format!("{doc_code} ({})", lbl.trim())
                            }
                            _ => format!("{doc_code}: {}", ev.title),
                        };
                        let candidate_anchor = ev
                            .section_anchor
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(|slug| format!("{doc_label}-{}", sanitize_label_slug(slug)));

                        let target_label = candidate_anchor
                            .filter(|lbl| emitted_labels.contains(lbl))
                            .or_else(|| {
                                if emitted_labels.contains(doc_label) {
                                    Some(doc_label.clone())
                                } else {
                                    None
                                }
                            });

                        if let Some(label) = target_label {
                            parts.push(format!(
                                "#link(<{label}>)[#underline[{}]]",
                                escape_typst(&link_text)
                            ));
                        } else {
                            parts.push(escape_typst(&link_text));
                        }
                    } else {
                        parts.push(escape_typst(&ev.title));
                    }
                }
            }

            if parts.is_empty() {
                parts.push("–".to_string());
            }

            soa_typst.push_str(&format!(
                "  [{}], [*{}* \\ _{}_], [{}], [{}], [{}],\n",
                escape_typst(&code),
                escape_typst(&title),
                escape_typst(domain),
                if is_applicable { "Ja" } else { "Nein" },
                escape_typst(status.label()),
                parts.join(" \\ ")
            ));
        }
        soa_typst.push_str(")\n\n");
    } else {
        soa_typst.push_str("_Kein aktives Compliance-Framework vorhanden._\n\n");
    }

    let mut full_body = String::new();
    full_body.push_str("= 1. Organisationsprofil & Geltungsbereich (Scope)\n\n");
    full_body.push_str(&format!(
        "- *Organisation:* {}\n- *Ziel-Regelwerke:* {}\n\n*Geltungsbereich:* {}\n\n",
        escape_typst(&company_name),
        escape_typst(&target_frameworks),
        escape_typst(&scope_statement)
    ));
    if !unit_rows.is_empty() {
        full_body.push_str("== Organisationseinheiten\n\n");
        for u in &unit_rows {
            let uname: String = u.get("name");
            full_body.push_str(&format!("- *{}*\n", escape_typst(&uname)));
        }
        full_body.push('\n');
    }

    full_body.push_str("#pagebreak(weak: true)\n");
    full_body.push_str("= 2. Statement of Applicability (SoA)\n\n");
    full_body.push_str(&soa_typst);

    full_body.push_str("#pagebreak(weak: true)\n");
    full_body.push_str("= 3. Freigegebene Richtlinien & Leitlinien\n\n");
    full_body.push_str(&policies_typst);

    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: "KOMPENDIUM-ISMS".to_string(),
        title: "Gesamt-Audit-Kompendium (Scope, SoA & Freigegebene Richtlinien)".to_string(),
        version: Utc::now().format("%Y-%m-%d").to_string(),
        status: "Audit-Export".to_string(),
        classification: "C2 · Intern".to_string(),
        owner_unit: "Informationssicherheit (ISB)".to_string(),
        approved_by: user.full_name.clone(),
        approved_at: Utc::now().format("%d.%m.%Y").to_string(),
        next_review_at: "Gemäß ISMS-Zyklus".to_string(),
    };

    let typst_src = build_iso_document_typst(&meta, &full_body);
    let renderer = TypstCliRenderer::from_config(&state.config);
    let pdf_bytes = renderer.render_raw_typst(&typst_src).await?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "export.audit_compendium_pdf",
        "exports",
        "audit-compendium.pdf",
        &format!(
            "Gesamt-Audit-Kompendium als PDF exportiert ({} freigegebene Richtlinien, {} Controls)",
            approved_docs.len(),
            soa_count
        ),
        None,
        Some(serde_json::json!({
            "approved_documents": approved_docs.len(),
            "soa_controls": soa_count,
            "size_bytes": pdf_bytes.len(),
        })),
    )
    .await?;
    tx.commit().await?;

    let filename = format!(
        "ins-isms-audit-kompendium-{}.pdf",
        Utc::now().format("%Y-%m-%d")
    );
    let mut resp = Response::new(axum::body::Body::from(pdf_bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }
    Ok(resp)
}
