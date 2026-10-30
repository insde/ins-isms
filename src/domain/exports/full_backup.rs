use axum::{
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::Utc;
use serde_json::{Value, json};

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser},
    db::begin_audited_tx,
    error::AppError,
    state::AppState,
};

async fn fetch_json_array(pool: &sqlx::PgPool, sql: &str) -> Result<Value, AppError> {
    let val: Value = sqlx::query_scalar(sql).fetch_one(pool).await?;
    Ok(val)
}

pub async fn full_backup_json_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
) -> Result<Response, AppError> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "Nur Administratoren dürfen den vollständigen Instanz-Export ausführen.".to_string(),
        ));
    }

    let organization_profile = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM organization_profile t",
    )
    .await?;
    let organization_units = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.name), '[]'::jsonb) FROM organization_units t",
    )
    .await?;
    let users = fetch_json_array(
        &state.pool,
        r#"
        SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.created_at), '[]'::jsonb)
        FROM (
            SELECT id, email, full_name, role, organization_unit_id, is_active, expires_at, created_at, updated_at
            FROM users
        ) t
        "#,
    )
    .await?;
    let system_assets = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.asset_code), '[]'::jsonb) FROM system_assets t",
    )
    .await?;
    let classification_levels = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.rank), '[]'::jsonb) FROM classification_levels t",
    )
    .await?;
    let classification_handling_rules = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.level_id, t.sort_order), '[]'::jsonb) FROM classification_handling_rules t",
    )
    .await?;
    let information_assets = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.name), '[]'::jsonb) FROM information_assets t",
    )
    .await?;
    let information_asset_systems = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM information_asset_systems t",
    )
    .await?;
    let documents = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.doc_code), '[]'::jsonb) FROM documents t",
    )
    .await?;
    let document_versions = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.document_id, t.created_at), '[]'::jsonb) FROM document_versions t",
    )
    .await?;
    let document_acknowledgments = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.acknowledged_at), '[]'::jsonb) FROM document_acknowledgments t",
    )
    .await?;
    let compliance_frameworks = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.code), '[]'::jsonb) FROM compliance_frameworks t",
    )
    .await?;
    let framework_controls = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.framework_id, t.sort_order, t.code), '[]'::jsonb) FROM framework_controls t",
    )
    .await?;
    let control_mappings = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM control_mappings t",
    )
    .await?;
    let soa_entries = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.control_id), '[]'::jsonb) FROM soa_entries t",
    )
    .await?;
    let control_evidences = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.created_at), '[]'::jsonb) FROM control_evidences t",
    )
    .await?;
    let risk_scenarios = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.reference_code), '[]'::jsonb) FROM risk_scenarios t",
    )
    .await?;
    let risk_control_links = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM risk_control_links t",
    )
    .await?;
    let security_incidents = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.detected_at), '[]'::jsonb) FROM security_incidents t",
    )
    .await?;
    let incident_timeline_events = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.occurred_at), '[]'::jsonb) FROM incident_timeline_events t",
    )
    .await?;
    let internal_audits = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.audit_date), '[]'::jsonb) FROM internal_audits t",
    )
    .await?;
    let audit_findings = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.audit_id, t.finding_code), '[]'::jsonb) FROM audit_findings t",
    )
    .await?;
    let management_reviews = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.review_date), '[]'::jsonb) FROM management_reviews t",
    )
    .await?;
    let action_items = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.reference_code), '[]'::jsonb) FROM action_items t",
    )
    .await?;
    let audit_logs = fetch_json_array(
        &state.pool,
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM audit_logs t",
    )
    .await?;

    let payload = json!({
        "schema_version": "1.0",
        "exported_at": Utc::now(),
        "organization_profile": organization_profile,
        "organization_units": organization_units,
        "users": users,
        "system_assets": system_assets,
        "classification_levels": classification_levels,
        "classification_handling_rules": classification_handling_rules,
        "information_assets": information_assets,
        "information_asset_systems": information_asset_systems,
        "documents": documents,
        "document_versions": document_versions,
        "document_acknowledgments": document_acknowledgments,
        "compliance_frameworks": compliance_frameworks,
        "framework_controls": framework_controls,
        "control_mappings": control_mappings,
        "soa_entries": soa_entries,
        "control_evidences": control_evidences,
        "risk_scenarios": risk_scenarios,
        "risk_control_links": risk_control_links,
        "security_incidents": security_incidents,
        "incident_timeline_events": incident_timeline_events,
        "internal_audits": internal_audits,
        "audit_findings": audit_findings,
        "management_reviews": management_reviews,
        "action_items": action_items,
        "audit_logs": audit_logs,
    });

    let json_bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| AppError::Internal(format!("JSON-Serialisierung fehlgeschlagen: {e}")))?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "export.full_json",
        "exports",
        "full-backup.json",
        "Vollständigen Instanz-Portabilitätsexport (JSON) erstellt",
        None,
        Some(json!({ "size_bytes": json_bytes.len() })),
    )
    .await?;
    tx.commit().await?;

    let filename = format!(
        "ins-isms-full-backup-{}.json",
        Utc::now().format("%Y-%m-%d")
    );
    let mut resp = Response::new(axum::body::Body::from(json_bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
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
