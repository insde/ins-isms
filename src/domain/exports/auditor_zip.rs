use std::{
    collections::BTreeMap,
    io::{Read, Write},
    str::FromStr,
};

use axum::{
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    audit::{AuditService, verify_hash_chain},
    auth::rbac::{ClientIp, CurrentUser},
    db::begin_audited_tx,
    domain::{
        audits::{AuditStatus, export::render_review_pdf_bytes},
        documents::editor::render_document_version_pdf_bytes,
        risks::export::{render_risks_csv_bytes, render_risks_pdf_bytes},
        soa::export::{render_soa_csv_bytes, render_soa_pdf_bytes},
    },
    error::AppError,
    state::AppState,
    storage::compute_sha256_hex,
};

#[derive(Debug, Deserialize)]
pub struct AuditorZipQuery {
    pub include_ip: Option<bool>,
}

#[derive(Debug, Serialize)]
struct HashChainVerificationJson {
    status: &'static str,
    total_entries: i64,
    first_broken_id: Option<i64>,
    last_hash: Option<String>,
    verified_at: DateTime<Utc>,
}

fn sanitize_zip_segment(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '_']);
    if trimmed.is_empty() {
        "datei".to_string()
    } else {
        trimmed.to_string()
    }
}

fn unique_zip_path(files: &BTreeMap<String, Vec<u8>>, desired_path: String) -> String {
    if !files.contains_key(&desired_path) {
        return desired_path;
    }
    if let Some((stem, ext)) = desired_path.rsplit_once('.') {
        for idx in 2..=999 {
            let candidate = format!("{stem}_{idx}.{ext}");
            if !files.contains_key(&candidate) {
                return candidate;
            }
        }
    }
    for idx in 2..=999 {
        let candidate = format!("{desired_path}_{idx}");
        if !files.contains_key(&candidate) {
            return candidate;
        }
    }
    format!("{desired_path}_{}", Uuid::new_v4())
}

fn csv_cell(val: &str, sep: char) -> String {
    let needs_quotes =
        val.contains(sep) || val.contains('"') || val.contains('\n') || val.contains('\r');
    if needs_quotes {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

async fn build_internal_audits_csv(pool: &sqlx::PgPool) -> Result<Vec<u8>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
            ia.audit_code,
            ia.title,
            ia.scope,
            ia.auditor_name,
            ia.audit_date,
            ia.status,
            COUNT(af.id)::BIGINT AS findings_total,
            COUNT(af.id) FILTER (WHERE af.status <> 'verified_closed')::BIGINT AS findings_open
        FROM internal_audits ia
        LEFT JOIN audit_findings af ON af.audit_id = ia.id
        GROUP BY ia.id
        ORDER BY ia.audit_date DESC, ia.audit_code ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let sep = ';';
    let mut csv = String::from("\u{FEFF}");
    let headers = [
        "Audit-Code",
        "Titel",
        "Prüfumfang",
        "Auditor",
        "Datum",
        "Status",
        "Findings gesamt",
        "Findings offen",
    ];
    csv.push_str(&headers.join(";"));
    csv.push('\n');

    for row in rows {
        let code: String = row.get("audit_code");
        let title: String = row.get("title");
        let scope: String = row.get("scope");
        let auditor_name: String = row.get("auditor_name");
        let audit_date: NaiveDate = row.get("audit_date");
        let status_raw: &str = row.get("status");
        let status_label = AuditStatus::from_str(status_raw)
            .map(|s| s.label())
            .unwrap_or(status_raw);
        let findings_total: i64 = row.get("findings_total");
        let findings_open: i64 = row.get("findings_open");

        let line = [
            csv_cell(&code, sep),
            csv_cell(&title, sep),
            csv_cell(&scope, sep),
            csv_cell(&auditor_name, sep),
            audit_date.format("%Y-%m-%d").to_string(),
            csv_cell(status_label, sep),
            findings_total.to_string(),
            findings_open.to_string(),
        ]
        .join(";");
        csv.push_str(&line);
        csv.push('\n');
    }

    Ok(csv.into_bytes())
}

async fn build_audit_logs_csv(pool: &sqlx::PgPool, include_ip: bool) -> Result<Vec<u8>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
            al.id,
            al.occurred_at,
            COALESCE(u.full_name || ' (' || u.email || ')', 'System') AS actor_label,
            COALESCE(al.actor_ip::text, '') AS actor_ip,
            al.action,
            al.entity_type,
            al.entity_id,
            al.summary,
            al.prev_hash,
            al.row_hash
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id
        ORDER BY al.id ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let sep = ';';
    let mut csv = String::from("\u{FEFF}");
    if include_ip {
        csv.push_str(
            "ID;Zeitstempel (UTC);Akteur;IP-Adresse;Aktion;Entitätstyp;Entitäts-ID;Zusammenfassung;Vorheriger Hash;Eintrags-Hash\n",
        );
    } else {
        csv.push_str(
            "ID;Zeitstempel (UTC);Akteur;Aktion;Entitätstyp;Entitäts-ID;Zusammenfassung;Vorheriger Hash;Eintrags-Hash\n",
        );
    }

    for row in rows {
        let id: i64 = row.get("id");
        let occurred_at: DateTime<Utc> = row.get("occurred_at");
        let actor_label: String = row.get("actor_label");
        let actor_ip: String = row.get("actor_ip");
        let action: String = row.get("action");
        let entity_type: String = row.get("entity_type");
        let entity_id: String = row.get("entity_id");
        let summary: String = row.get("summary");
        let prev_hash: String = row.get("prev_hash");
        let row_hash: String = row.get("row_hash");

        let ts = occurred_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let line = if include_ip {
            [
                id.to_string(),
                ts,
                csv_cell(&actor_label, sep),
                csv_cell(&actor_ip, sep),
                csv_cell(&action, sep),
                csv_cell(&entity_type, sep),
                csv_cell(&entity_id, sep),
                csv_cell(&summary, sep),
                csv_cell(&prev_hash, sep),
                csv_cell(&row_hash, sep),
            ]
            .join(";")
        } else {
            [
                id.to_string(),
                ts,
                csv_cell(&actor_label, sep),
                csv_cell(&action, sep),
                csv_cell(&entity_type, sep),
                csv_cell(&entity_id, sep),
                csv_cell(&summary, sep),
                csv_cell(&prev_hash, sep),
                csv_cell(&row_hash, sep),
            ]
            .join(";")
        };
        csv.push_str(&line);
        csv.push('\n');
    }

    Ok(csv.into_bytes())
}

pub async fn auditor_zip_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    Query(query): Query<AuditorZipQuery>,
) -> Result<Response, AppError> {
    if !user.role.is_iso_or_admin() && !user.role.is_auditor() {
        return Err(AppError::Forbidden(
            "Nur Administratoren, ISB und Auditoren dürfen das Auditor-Evidence-Paket exportieren."
                .to_string(),
        ));
    }

    // DSGVO-Guard: IP-Adressen dürfen ausschließlich von Admins explizit angefordert werden.
    let include_ip = query.include_ip.unwrap_or(false) && user.role.is_admin();

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let (_fw_code, _soa_count, soa_pdf) =
        render_soa_pdf_bytes(&state.pool, &state.config, None, &user.full_name).await?;
    let (_fw_code_csv, _soa_csv_count, soa_csv) =
        render_soa_csv_bytes(&state.pool, None, ';').await?;
    files.insert("01_SoA/Statement_of_Applicability.pdf".to_string(), soa_pdf);
    files.insert("01_SoA/Statement_of_Applicability.csv".to_string(), soa_csv);

    let (_risk_count, rtp_pdf) =
        render_risks_pdf_bytes(&state.pool, &state.config, &user.full_name).await?;
    let (_risk_csv_count, risks_csv) = render_risks_csv_bytes(&state.pool, ';').await?;
    files.insert(
        "02_Risikomanagement/Risikobehandlungsplan.pdf".to_string(),
        rtp_pdf,
    );
    files.insert("02_Risikomanagement/Risiken.csv".to_string(), risks_csv);

    // Ausschließlich freigegebene Richtlinien (status = 'approved') exportieren.
    let approved_docs = sqlx::query(
        r#"
        SELECT
            d.id AS document_id,
            d.doc_code,
            d.source_type,
            dv.id AS version_id,
            dv.version_number,
            dv.attached_file_key,
            dv.original_filename,
            dv.file_sha256
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.status = 'approved'
        ORDER BY d.doc_code ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for row in approved_docs {
        let doc_id: Uuid = row.get("document_id");
        let version_id: Uuid = row.get("version_id");
        let source_type: &str = row.get("source_type");
        let attached_file_key: Option<String> = row.get("attached_file_key");
        let original_filename: Option<String> = row.get("original_filename");
        let expected_sha256: Option<String> = row.get("file_sha256");

        let (doc_code, version_number, _status, pdf_bytes) =
            render_document_version_pdf_bytes(&state.pool, &state.config, doc_id, version_id)
                .await?;
        let safe_code = sanitize_zip_segment(&doc_code);
        let safe_ver = sanitize_zip_segment(&version_number);

        let pdf_path = unique_zip_path(
            &files,
            format!("03_Richtlinien_Freigegeben/{safe_code}_v{safe_ver}.pdf"),
        );
        files.insert(pdf_path, pdf_bytes);

        if source_type == "uploaded_file"
            && let Some(key) = attached_file_key
        {
            let attachment_bytes = state.storage.get(&key).await?;
            if let Some(ref expected) = expected_sha256
                && !expected.is_empty()
            {
                let actual = compute_sha256_hex(&attachment_bytes);
                if &actual != expected {
                    return Err(AppError::Internal(format!(
                        "Integritätsprüfung für Richtlinienanhang '{doc_code}' fehlgeschlagen."
                    )));
                }
            }
            let safe_orig =
                sanitize_zip_segment(original_filename.as_deref().unwrap_or("anhang.bin"));
            let att_path = unique_zip_path(
                &files,
                format!("03_Richtlinien_Freigegeben/{safe_code}_v{safe_ver}_{safe_orig}"),
            );
            files.insert(att_path, attachment_bytes);
        }
    }

    let file_evidences = sqlx::query(
        r#"
        SELECT
            fc.code AS control_code,
            ce.file_storage_key,
            ce.original_filename,
            ce.file_sha256
        FROM control_evidences ce
        JOIN soa_entries se ON se.id = ce.soa_entry_id
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE ce.evidence_type = 'file'
          AND ce.file_storage_key IS NOT NULL
        ORDER BY fc.code ASC, ce.created_at ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for row in file_evidences {
        let control_code: String = row.get("control_code");
        let storage_key: String = row.get("file_storage_key");
        let original_filename: Option<String> = row.get("original_filename");
        let expected_sha256: Option<String> = row.get("file_sha256");

        let evidence_bytes = state.storage.get(&storage_key).await?;
        if let Some(ref expected) = expected_sha256
            && !expected.is_empty()
        {
            let actual = compute_sha256_hex(&evidence_bytes);
            if &actual != expected {
                return Err(AppError::Internal(format!(
                    "Integritätsprüfung für Nachweis '{control_code}' fehlgeschlagen."
                )));
            }
        }

        let safe_ctrl = sanitize_zip_segment(&control_code);
        let safe_fname =
            sanitize_zip_segment(original_filename.as_deref().unwrap_or("nachweis.bin"));
        let ev_path = unique_zip_path(&files, format!("04_Nachweise/{safe_ctrl}_{safe_fname}"));
        files.insert(ev_path, evidence_bytes);
    }

    let approved_reviews = sqlx::query(
        r#"
        SELECT id
        FROM management_reviews
        WHERE status = 'approved'
        ORDER BY review_date DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for row in approved_reviews {
        let review_id: Uuid = row.get("id");
        let (period_label, _status, pdf_bytes) =
            render_review_pdf_bytes(&state.pool, &state.config, review_id).await?;
        let safe_period = sanitize_zip_segment(&period_label);
        let rev_path = unique_zip_path(
            &files,
            format!("05_Management_Review_und_Audits/Management_Review_{safe_period}.pdf"),
        );
        files.insert(rev_path, pdf_bytes);
    }

    let audits_csv = build_internal_audits_csv(&state.pool).await?;
    files.insert(
        "05_Management_Review_und_Audits/Interne_Audits.csv".to_string(),
        audits_csv,
    );

    let audit_logs_csv = build_audit_logs_csv(&state.pool, include_ip).await?;
    files.insert(
        "06_Audit_Trail/audit_logs_extract.csv".to_string(),
        audit_logs_csv,
    );

    let verification = verify_hash_chain(&state.pool).await?;
    let verification_json = serde_json::to_vec_pretty(&HashChainVerificationJson {
        status: verification.status_label(),
        total_entries: verification.total_entries,
        first_broken_id: verification.first_broken_id,
        last_hash: verification.last_hash,
        verified_at: Utc::now(),
    })
    .map_err(|e| AppError::Internal(format!("JSON-Serialisierung fehlgeschlagen: {e}")))?;
    files.insert(
        "06_Audit_Trail/hash_chain_verification.json".to_string(),
        verification_json,
    );

    let mut manifest = String::new();
    for (path, bytes) in &files {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest_hex = hex::encode(hasher.finalize());
        manifest.push_str(&format!("{digest_hex}  {path}\n"));
    }
    let manifest_bytes = manifest.into_bytes();
    let file_count = files.len() + 1;

    let zip_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AppError> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        {
            let mut writer = ZipWriter::new(temp_file.as_file_mut());
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

            writer
                .start_file("00_MANIFEST.sha256", opts)
                .map_err(|e| AppError::Internal(format!("ZIP-Manifest-Fehler: {e}")))?;
            writer.write_all(&manifest_bytes)?;

            for (path, bytes) in files {
                writer
                    .start_file(&path, opts)
                    .map_err(|e| AppError::Internal(format!("ZIP-Eintrag-Fehler: {e}")))?;
                writer.write_all(&bytes)?;
            }

            writer
                .finish()
                .map_err(|e| AppError::Internal(format!("ZIP-Abschlussfehler: {e}")))?;
        }

        let mut file = temp_file.reopen()?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(buf)
    })
    .await
    .map_err(|e| AppError::Internal(format!("ZIP-Worker fehlgeschlagen: {e}")))??;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "export.auditor_zip",
        "exports",
        "auditor-package.zip",
        &format!("Auditor-Evidence-Paket (ZIP) exportiert ({file_count} Dateien)"),
        None,
        Some(serde_json::json!({
            "include_ip": include_ip,
            "file_count": file_count,
            "size_bytes": zip_bytes.len(),
        })),
    )
    .await?;
    tx.commit().await?;

    let filename = format!("ins-isms-audit-{}.zip", Utc::now().format("%Y-%m-%d"));
    let mut resp = Response::new(axum::body::Body::from(zip_bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
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
