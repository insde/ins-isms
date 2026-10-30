use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use askama::Template;
use axum::{
    Form,
    extract::{Multipart, State},
    response::IntoResponse,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, RequireIsoOrAdmin},
    db::begin_audited_tx,
    domain::{
        classification::CiaLevel,
        organization::assets::{AssetType, Criticality},
        risks::TreatmentStrategy,
    },
    error::AppError,
    state::AppState,
    web::{render_template, with_toast},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsvEntityType {
    SystemAssets,
    InformationAssets,
    RiskScenarios,
}

impl CsvEntityType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemAssets => "system_assets",
            Self::InformationAssets => "information_assets",
            Self::RiskScenarios => "risk_scenarios",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SystemAssets => "System-Assets",
            Self::InformationAssets => "Informationswerte",
            Self::RiskScenarios => "Risikoszenarien",
        }
    }
}

impl FromStr for CsvEntityType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "system_assets" => Ok(Self::SystemAssets),
            "information_assets" => Ok(Self::InformationAssets),
            "risk_scenarios" => Ok(Self::RiskScenarios),
            other => Err(AppError::Validation(vec![format!(
                "Unbekannter CSV-Entitätstyp: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedSystemAssetRow {
    pub asset_code: String,
    pub name: String,
    pub asset_type: String,
    pub vendor_name: Option<String>,
    pub hosting_location: Option<String>,
    pub criticality: String,
    pub owner_unit_id: Option<Uuid>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedInfoAssetRow {
    pub name: String,
    pub classification_level_id: Uuid,
    pub confidentiality: String,
    pub integrity: String,
    pub availability: String,
    pub owner_unit_id: Option<Uuid>,
    pub retention_period: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedRiskRow {
    pub reference_code: String,
    pub title: String,
    pub threat_description: String,
    pub affected_system_asset_id: Option<Uuid>,
    pub inherent_likelihood: i16,
    pub inherent_impact: i16,
    pub treatment_strategy: String,
    pub residual_likelihood: i16,
    pub residual_impact: i16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entity_type", content = "rows", rename_all = "snake_case")]
pub enum CsvCommitPayload {
    SystemAssets(Vec<ValidatedSystemAssetRow>),
    InformationAssets(Vec<ValidatedInfoAssetRow>),
    RiskScenarios(Vec<ValidatedRiskRow>),
}

impl CsvCommitPayload {
    fn len(&self) -> usize {
        match self {
            Self::SystemAssets(v) => v.len(),
            Self::InformationAssets(v) => v.len(),
            Self::RiskScenarios(v) => v.len(),
        }
    }

    fn entity_type(&self) -> CsvEntityType {
        match self {
            Self::SystemAssets(_) => CsvEntityType::SystemAssets,
            Self::InformationAssets(_) => CsvEntityType::InformationAssets,
            Self::RiskScenarios(_) => CsvEntityType::RiskScenarios,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CsvPreviewRowView {
    pub row_number: usize,
    pub key_label: String,
    pub summary_label: String,
    pub is_valid: bool,
    pub errors: Vec<String>,
}

#[derive(Template)]
#[template(path = "exports/csv_preview.html")]
struct CsvPreviewTemplate {
    entity_label: &'static str,
    delimiter_label: &'static str,
    total_rows: usize,
    valid_count: usize,
    error_count: usize,
    rows: Vec<CsvPreviewRowView>,
    payload_json: String,
    payload_hmac: String,
}

#[derive(Template)]
#[template(path = "exports/csv_result.html")]
struct CsvCommitResultTemplate {
    entity_label: &'static str,
    imported_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct CsvCommitForm {
    pub payload_json: String,
    pub payload_hmac: String,
}

fn detect_csv_delimiter(text: &str) -> u8 {
    let first_line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut in_quotes = false;
    let mut commas = 0usize;
    let mut semicolons = 0usize;
    for ch in first_line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => commas += 1,
            ';' if !in_quotes => semicolons += 1,
            _ => {}
        }
    }
    if semicolons > commas { b';' } else { b',' }
}

fn sign_payload(secret: &[u8], payload_json: &str) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| AppError::Internal("HMAC-Initialisierung fehlgeschlagen.".to_string()))?;
    mac.update(payload_json.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_payload(secret: &[u8], payload_json: &str, provided_hex: &str) -> Result<(), AppError> {
    let expected = sign_payload(secret, payload_json)?;
    if expected.len() != provided_hex.len()
        || expected
            .as_bytes()
            .ct_eq(provided_hex.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(AppError::Forbidden(
            "Ungültige oder manipulierte Import-Vorschau-Signatur.".to_string(),
        ));
    }
    Ok(())
}

fn col_val<'a>(
    record: &'a csv::StringRecord,
    idx_map: &HashMap<String, usize>,
    name: &str,
) -> &'a str {
    idx_map
        .get(name)
        .and_then(|&i| record.get(i))
        .map(str::trim)
        .unwrap_or("")
}

fn opt_val(
    record: &csv::StringRecord,
    idx_map: &HashMap<String, usize>,
    name: &str,
) -> Option<String> {
    let v = col_val(record, idx_map, name);
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

fn parse_scale_1_to_5(raw: &str, field_label: &str) -> Result<i16, String> {
    let val: i16 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{field_label} muss eine Ganzzahl zwischen 1 und 5 sein."))?;
    if !(1..=5).contains(&val) {
        return Err(format!("{field_label} muss zwischen 1 und 5 liegen."));
    }
    Ok(val)
}

pub async fn preview_csv_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(_user): RequireIsoOrAdmin,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let mut entity_type_raw: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Ungültiger Multipart-Upload: {e}")))?
    {
        match field.name() {
            Some("entity_type") => {
                entity_type_raw = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Feld-Fehler: {e}")))?,
                );
            }
            Some("file") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("Datei-Lesefehler: {e}")))?;
                if bytes.len() > state.config.max_upload_bytes {
                    return Err(AppError::Validation(vec![format!(
                        "CSV-Datei überschreitet das Upload-Limit von {} Bytes.",
                        state.config.max_upload_bytes
                    )]));
                }
                file_bytes = Some(bytes.to_vec());
            }
            _ => {}
        }
    }

    let entity_type = CsvEntityType::from_str(entity_type_raw.as_deref().unwrap_or(""))?;
    let raw_bytes = file_bytes.ok_or_else(|| {
        AppError::Validation(vec![
            "Bitte eine CSV-Datei für die Vorschau auswählen.".to_string(),
        ])
    })?;

    let raw_text = std::str::from_utf8(&raw_bytes).map_err(|_| {
        AppError::Validation(vec![
            "Die CSV-Datei muss UTF-8-kodiert sein (optional mit UTF-8-BOM).".to_string(),
        ])
    })?;
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text);
    if text.trim().is_empty() {
        return Err(AppError::Validation(vec![
            "Die CSV-Datei enthält keine Daten.".to_string(),
        ]));
    }

    let delimiter = detect_csv_delimiter(text);
    let delimiter_label = if delimiter == b';' {
        "Semikolon (;)"
    } else {
        "Komma (,)"
    };

    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| AppError::Validation(vec![format!("CSV-Header ungültig: {e}")]))?
        .clone();

    let mut idx_map = HashMap::new();
    for (idx, h) in headers.iter().enumerate() {
        idx_map.insert(h.trim().to_ascii_lowercase(), idx);
    }

    let required_cols: &[&str] = match entity_type {
        CsvEntityType::SystemAssets => &["asset_code", "name", "asset_type", "criticality"],
        CsvEntityType::InformationAssets => &[
            "name",
            "classification_code",
            "confidentiality",
            "integrity",
            "availability",
        ],
        CsvEntityType::RiskScenarios => &[
            "reference_code",
            "title",
            "threat_description",
            "inherent_likelihood",
            "inherent_impact",
            "treatment_strategy",
            "residual_likelihood",
            "residual_impact",
        ],
    };
    let missing_cols: Vec<&str> = required_cols
        .iter()
        .copied()
        .filter(|col| !idx_map.contains_key(*col))
        .collect();
    if !missing_cols.is_empty() {
        return Err(AppError::Validation(vec![format!(
            "Fehlende Pflichtspalten im CSV-Header: {}",
            missing_cols.join(", ")
        )]));
    }

    let unit_rows = sqlx::query("SELECT id, LOWER(name) AS lname FROM organization_units")
        .fetch_all(&state.pool)
        .await?;
    let unit_by_name: HashMap<String, Uuid> = unit_rows
        .into_iter()
        .map(|r| (r.get::<String, _>("lname"), r.get::<Uuid, _>("id")))
        .collect();

    let mut preview_rows = Vec::new();

    let commit_payload = match entity_type {
        CsvEntityType::SystemAssets => {
            let existing_codes: HashSet<String> =
                sqlx::query_scalar::<_, String>("SELECT UPPER(asset_code) FROM system_assets")
                    .fetch_all(&state.pool)
                    .await?
                    .into_iter()
                    .collect();
            let mut seen_in_csv = HashSet::new();
            let mut valid_rows = Vec::new();

            for (i, rec_res) in reader.records().enumerate() {
                let row_no = i + 2;
                let record = rec_res.map_err(|e| {
                    AppError::Validation(vec![format!("Zeile {row_no} nicht lesbar: {e}")])
                })?;

                let code = col_val(&record, &idx_map, "asset_code").to_string();
                let name = col_val(&record, &idx_map, "name").to_string();
                let asset_type_raw = col_val(&record, &idx_map, "asset_type");
                let criticality_raw = col_val(&record, &idx_map, "criticality");
                let unit_name = col_val(&record, &idx_map, "owner_unit_name");

                let mut row_errs = Vec::new();
                if code.is_empty() || code.len() > 32 {
                    row_errs.push("asset_code muss 1–32 Zeichen lang sein.".to_string());
                } else {
                    let upper = code.to_ascii_uppercase();
                    if existing_codes.contains(&upper) {
                        row_errs.push(format!("asset_code '{code}' existiert bereits."));
                    }
                    if !seen_in_csv.insert(upper) {
                        row_errs.push(format!("Doppelter asset_code '{code}' in CSV."));
                    }
                }
                if name.is_empty() || name.len() > 200 {
                    row_errs.push("name darf nicht leer sein (max. 200 Zeichen).".to_string());
                }
                let asset_type = match AssetType::from_str(asset_type_raw) {
                    Ok(t) => Some(t.as_str().to_string()),
                    Err(_) => {
                        row_errs.push(format!(
                            "Ungültiger asset_type '{asset_type_raw}' (erlaubt: server, application, cloud_service, network, endpoint, facility, ot_equipment, vendor, other)."
                        ));
                        None
                    }
                };
                let criticality = if criticality_raw.is_empty() {
                    Some("normal".to_string())
                } else {
                    match Criticality::from_str(criticality_raw) {
                        Ok(c) => Some(c.as_str().to_string()),
                        Err(_) => {
                            row_errs.push(format!("Ungültige criticality '{criticality_raw}'."));
                            None
                        }
                    }
                };
                let owner_unit_id = if unit_name.is_empty() {
                    None
                } else {
                    match unit_by_name.get(&unit_name.to_ascii_lowercase()) {
                        Some(id) => Some(*id),
                        None => {
                            row_errs.push(format!(
                                "Organisationseinheit '{unit_name}' nicht gefunden."
                            ));
                            None
                        }
                    }
                };

                let is_valid = row_errs.is_empty();
                if is_valid && let (Some(at), Some(crit)) = (asset_type, criticality) {
                    valid_rows.push(ValidatedSystemAssetRow {
                        asset_code: code.clone(),
                        name: name.clone(),
                        asset_type: at,
                        vendor_name: opt_val(&record, &idx_map, "vendor_name"),
                        hosting_location: opt_val(&record, &idx_map, "hosting_location"),
                        criticality: crit,
                        owner_unit_id,
                        description: opt_val(&record, &idx_map, "description"),
                    });
                }

                preview_rows.push(CsvPreviewRowView {
                    row_number: row_no,
                    key_label: if code.is_empty() {
                        "—".to_string()
                    } else {
                        code
                    },
                    summary_label: name,
                    is_valid,
                    errors: row_errs,
                });
            }
            CsvCommitPayload::SystemAssets(valid_rows)
        }
        CsvEntityType::InformationAssets => {
            let level_rows =
                sqlx::query("SELECT id, UPPER(code) AS ucode FROM classification_levels")
                    .fetch_all(&state.pool)
                    .await?;
            let level_by_code: HashMap<String, Uuid> = level_rows
                .into_iter()
                .map(|r| (r.get::<String, _>("ucode"), r.get::<Uuid, _>("id")))
                .collect();

            let mut valid_rows = Vec::new();
            for (i, rec_res) in reader.records().enumerate() {
                let row_no = i + 2;
                let record = rec_res.map_err(|e| {
                    AppError::Validation(vec![format!("Zeile {row_no} nicht lesbar: {e}")])
                })?;

                let name = col_val(&record, &idx_map, "name").to_string();
                let class_code = col_val(&record, &idx_map, "classification_code");
                let conf_raw = col_val(&record, &idx_map, "confidentiality");
                let int_raw = col_val(&record, &idx_map, "integrity");
                let avail_raw = col_val(&record, &idx_map, "availability");
                let unit_name = col_val(&record, &idx_map, "owner_unit_name");

                let mut row_errs = Vec::new();
                if name.is_empty() || name.len() > 200 {
                    row_errs.push("name darf nicht leer sein (max. 200 Zeichen).".to_string());
                }
                let level_id = level_by_code.get(&class_code.to_ascii_uppercase()).copied();
                if level_id.is_none() {
                    row_errs.push(format!("Schutzstufe '{class_code}' nicht gefunden."));
                }

                let conf = CiaLevel::from_str(conf_raw)
                    .ok()
                    .map(|v| v.as_str().to_string());
                if conf.is_none() {
                    row_errs.push(format!("Ungültige confidentiality '{conf_raw}'."));
                }
                let integ = CiaLevel::from_str(int_raw)
                    .ok()
                    .map(|v| v.as_str().to_string());
                if integ.is_none() {
                    row_errs.push(format!("Ungültige integrity '{int_raw}'."));
                }
                let avail = CiaLevel::from_str(avail_raw)
                    .ok()
                    .map(|v| v.as_str().to_string());
                if avail.is_none() {
                    row_errs.push(format!("Ungültige availability '{avail_raw}'."));
                }

                let owner_unit_id = if unit_name.is_empty() {
                    None
                } else {
                    match unit_by_name.get(&unit_name.to_ascii_lowercase()) {
                        Some(id) => Some(*id),
                        None => {
                            row_errs.push(format!(
                                "Organisationseinheit '{unit_name}' nicht gefunden."
                            ));
                            None
                        }
                    }
                };

                let is_valid = row_errs.is_empty();
                if is_valid
                    && let (Some(lid), Some(c), Some(ig), Some(av)) = (level_id, conf, integ, avail)
                {
                    valid_rows.push(ValidatedInfoAssetRow {
                        name: name.clone(),
                        classification_level_id: lid,
                        confidentiality: c,
                        integrity: ig,
                        availability: av,
                        owner_unit_id,
                        retention_period: opt_val(&record, &idx_map, "retention_period"),
                        description: opt_val(&record, &idx_map, "description"),
                    });
                }

                preview_rows.push(CsvPreviewRowView {
                    row_number: row_no,
                    key_label: class_code.to_string(),
                    summary_label: name,
                    is_valid,
                    errors: row_errs,
                });
            }
            CsvCommitPayload::InformationAssets(valid_rows)
        }
        CsvEntityType::RiskScenarios => {
            let existing_refs: HashSet<String> =
                sqlx::query_scalar::<_, String>("SELECT UPPER(reference_code) FROM risk_scenarios")
                    .fetch_all(&state.pool)
                    .await?
                    .into_iter()
                    .collect();
            let sys_rows = sqlx::query("SELECT id, UPPER(asset_code) AS ucode FROM system_assets")
                .fetch_all(&state.pool)
                .await?;
            let sys_by_code: HashMap<String, Uuid> = sys_rows
                .into_iter()
                .map(|r| (r.get::<String, _>("ucode"), r.get::<Uuid, _>("id")))
                .collect();

            let mut seen_in_csv = HashSet::new();
            let mut valid_rows = Vec::new();

            for (i, rec_res) in reader.records().enumerate() {
                let row_no = i + 2;
                let record = rec_res.map_err(|e| {
                    AppError::Validation(vec![format!("Zeile {row_no} nicht lesbar: {e}")])
                })?;

                let ref_code = col_val(&record, &idx_map, "reference_code").to_string();
                let title = col_val(&record, &idx_map, "title").to_string();
                let threat = col_val(&record, &idx_map, "threat_description").to_string();
                let sys_code = col_val(&record, &idx_map, "affected_system_code");
                let inh_l_raw = col_val(&record, &idx_map, "inherent_likelihood");
                let inh_i_raw = col_val(&record, &idx_map, "inherent_impact");
                let strat_raw = col_val(&record, &idx_map, "treatment_strategy");
                let res_l_raw = col_val(&record, &idx_map, "residual_likelihood");
                let res_i_raw = col_val(&record, &idx_map, "residual_impact");

                let mut row_errs = Vec::new();
                if ref_code.is_empty() || ref_code.len() > 32 {
                    row_errs.push("reference_code muss 1–32 Zeichen lang sein.".to_string());
                } else {
                    let upper = ref_code.to_ascii_uppercase();
                    if existing_refs.contains(&upper) {
                        row_errs.push(format!("reference_code '{ref_code}' existiert bereits."));
                    }
                    if !seen_in_csv.insert(upper) {
                        row_errs.push(format!("Doppelter reference_code '{ref_code}' in CSV."));
                    }
                }
                if title.is_empty() || title.len() > 200 {
                    row_errs.push("title darf nicht leer sein (max. 200 Zeichen).".to_string());
                }
                if threat.is_empty() {
                    row_errs.push("threat_description darf nicht leer sein.".to_string());
                }

                let affected_system_asset_id = if sys_code.is_empty() {
                    None
                } else {
                    match sys_by_code.get(&sys_code.to_ascii_uppercase()) {
                        Some(id) => Some(*id),
                        None => {
                            row_errs.push(format!("System-Asset '{sys_code}' nicht gefunden."));
                            None
                        }
                    }
                };

                let inh_l = match parse_scale_1_to_5(inh_l_raw, "inherent_likelihood") {
                    Ok(v) => Some(v),
                    Err(e) => {
                        row_errs.push(e);
                        None
                    }
                };
                let inh_i = match parse_scale_1_to_5(inh_i_raw, "inherent_impact") {
                    Ok(v) => Some(v),
                    Err(e) => {
                        row_errs.push(e);
                        None
                    }
                };
                let res_l = match parse_scale_1_to_5(res_l_raw, "residual_likelihood") {
                    Ok(v) => Some(v),
                    Err(e) => {
                        row_errs.push(e);
                        None
                    }
                };
                let res_i = match parse_scale_1_to_5(res_i_raw, "residual_impact") {
                    Ok(v) => Some(v),
                    Err(e) => {
                        row_errs.push(e);
                        None
                    }
                };
                let strategy = match TreatmentStrategy::from_str(strat_raw) {
                    Ok(s) => Some(s.as_str().to_string()),
                    Err(_) => {
                        row_errs.push(format!("Ungültige treatment_strategy '{strat_raw}'."));
                        None
                    }
                };

                let is_valid = row_errs.is_empty();
                if is_valid
                    && let (Some(il), Some(ii), Some(rl), Some(ri), Some(st)) =
                        (inh_l, inh_i, res_l, res_i, strategy)
                {
                    valid_rows.push(ValidatedRiskRow {
                        reference_code: ref_code.clone(),
                        title: title.clone(),
                        threat_description: threat,
                        affected_system_asset_id,
                        inherent_likelihood: il,
                        inherent_impact: ii,
                        treatment_strategy: st,
                        residual_likelihood: rl,
                        residual_impact: ri,
                    });
                }

                preview_rows.push(CsvPreviewRowView {
                    row_number: row_no,
                    key_label: if ref_code.is_empty() {
                        "—".to_string()
                    } else {
                        ref_code
                    },
                    summary_label: title,
                    is_valid,
                    errors: row_errs,
                });
            }
            CsvCommitPayload::RiskScenarios(valid_rows)
        }
    };

    let total_rows = preview_rows.len();
    let valid_count = commit_payload.len();
    let error_count = total_rows.saturating_sub(valid_count);

    let payload_json = serde_json::to_string(&commit_payload)
        .map_err(|e| AppError::Internal(format!("Serialisierungsfehler: {e}")))?;
    let payload_hmac = sign_payload(&state.config.session_secret, &payload_json)?;

    let tmpl = CsvPreviewTemplate {
        entity_label: entity_type.label(),
        delimiter_label,
        total_rows,
        valid_count,
        error_count,
        rows: preview_rows,
        payload_json,
        payload_hmac,
    };
    let html = render_template(&tmpl)?;
    Ok(axum::response::Html(html))
}

pub async fn commit_csv_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(client_ip): ClientIp,
    Form(form): Form<CsvCommitForm>,
) -> Result<impl IntoResponse, AppError> {
    verify_payload(
        &state.config.session_secret,
        &form.payload_json,
        &form.payload_hmac,
    )?;

    let payload: CsvCommitPayload = serde_json::from_str(&form.payload_json)
        .map_err(|e| AppError::BadRequest(format!("Ungültige Commit-Nutzdaten: {e}")))?;

    let count = payload.len();
    if count == 0 {
        return Err(AppError::Validation(vec![
            "Keine gültigen Zeilen zum Importieren vorhanden.".to_string(),
        ]));
    }

    let entity_type = payload.entity_type();
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;

    match payload {
        CsvCommitPayload::SystemAssets(rows) => {
            for r in rows {
                sqlx::query(
                    r#"
                    INSERT INTO system_assets (
                        asset_code, name, asset_type, description,
                        owner_unit_id, vendor_name, hosting_location, criticality
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    "#,
                )
                .bind(&r.asset_code)
                .bind(&r.name)
                .bind(&r.asset_type)
                .bind(&r.description)
                .bind(r.owner_unit_id)
                .bind(&r.vendor_name)
                .bind(&r.hosting_location)
                .bind(&r.criticality)
                .execute(&mut *tx)
                .await
                .map_err(map_unique_csv_error)?;
            }
        }
        CsvCommitPayload::InformationAssets(rows) => {
            for r in rows {
                sqlx::query(
                    r#"
                    INSERT INTO information_assets (
                        name, description, owner_unit_id, classification_level_id,
                        confidentiality, integrity, availability, retention_period
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    "#,
                )
                .bind(&r.name)
                .bind(&r.description)
                .bind(r.owner_unit_id)
                .bind(r.classification_level_id)
                .bind(&r.confidentiality)
                .bind(&r.integrity)
                .bind(&r.availability)
                .bind(&r.retention_period)
                .execute(&mut *tx)
                .await?;
            }
        }
        CsvCommitPayload::RiskScenarios(rows) => {
            for r in rows {
                sqlx::query(
                    r#"
                    INSERT INTO risk_scenarios (
                        reference_code, title, threat_description,
                        affected_system_asset_id, inherent_likelihood, inherent_impact,
                        treatment_strategy, residual_likelihood, residual_impact, status
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'assessed')
                    "#,
                )
                .bind(&r.reference_code)
                .bind(&r.title)
                .bind(&r.threat_description)
                .bind(r.affected_system_asset_id)
                .bind(r.inherent_likelihood)
                .bind(r.inherent_impact)
                .bind(&r.treatment_strategy)
                .bind(r.residual_likelihood)
                .bind(r.residual_impact)
                .execute(&mut *tx)
                .await
                .map_err(map_unique_csv_error)?;
            }
        }
    }

    let summary = format!(
        "CSV-Bulk-Import ({}) abgeschlossen: {count} Datensätze übernommen",
        entity_type.as_str()
    );
    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "csv.imported",
        entity_type.as_str(),
        "bulk",
        &summary,
        None,
        Some(json!({
            "entity_type": entity_type.as_str(),
            "imported_count": count,
        })),
    )
    .await?;

    tx.commit().await?;

    let tmpl = CsvCommitResultTemplate {
        entity_label: entity_type.label(),
        imported_count: count,
    };
    let html = render_template(&tmpl)?;
    Ok(with_toast(
        axum::response::Html(html).into_response(),
        "success",
        "CSV-Daten erfolgreich importiert.",
    ))
}

fn map_unique_csv_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &err
        && db_err.code().as_deref() == Some("23505")
    {
        return AppError::Conflict(
            "Mindestens ein Datensatz wurde zwischen Vorschau und Import bereits angelegt."
                .to_string(),
        );
    }
    AppError::Database(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_semicolon_and_comma_delimiters() {
        assert_eq!(
            detect_csv_delimiter("\u{FEFF}asset_code;name;asset_type\nSRV-1;App;server"),
            b';'
        );
        assert_eq!(
            detect_csv_delimiter("asset_code,name,asset_type\nSRV-1,\"App, Neu\",server"),
            b','
        );
    }

    #[test]
    fn hmac_signature_rejects_tampering() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let payload = r#"{"entity_type":"system_assets","rows":[]}"#;
        let sig = sign_payload(secret, payload).expect("HMAC sign");
        verify_payload(secret, payload, &sig).expect("gültige Signatur");
        let tampered = r#"{"entity_type":"risk_scenarios","rows":[]}"#;
        assert!(verify_payload(secret, tampered, &sig).is_err());
    }
}
