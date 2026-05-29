use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{
        ClientIp, CurrentUser, RequireIsoOrAdmin, Role, ensure_owner_scope, forbid_auditor,
    },
    db::begin_audited_tx,
    domain::{
        classification::{
            EffectiveSystemClassification, load_effective_system_classification,
            load_effective_system_classifications,
        },
        organization::profile::{SelectOption, parse_optional_uuid},
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, with_toast},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    Server,
    Application,
    CloudService,
    Network,
    Endpoint,
    Facility,
    OtEquipment,
    Vendor,
    Other,
}

impl AssetType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Application => "application",
            Self::CloudService => "cloud_service",
            Self::Network => "network",
            Self::Endpoint => "endpoint",
            Self::Facility => "facility",
            Self::OtEquipment => "ot_equipment",
            Self::Vendor => "vendor",
            Self::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Server => "Server / Infrastruktur",
            Self::Application => "Anwendung / Software",
            Self::CloudService => "Cloud-Dienst",
            Self::Network => "Netzwerk",
            Self::Endpoint => "Endgerät (Gruppe)",
            Self::Facility => "Standort / Raum",
            Self::OtEquipment => "Maschine / OT-Anlage",
            Self::Vendor => "Dienstleister / Lieferant",
            Self::Other => "Sonstiges Asset",
        }
    }
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AssetType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "server" => Ok(Self::Server),
            "application" => Ok(Self::Application),
            "cloud_service" => Ok(Self::CloudService),
            "network" => Ok(Self::Network),
            "endpoint" => Ok(Self::Endpoint),
            "facility" => Ok(Self::Facility),
            "ot_equipment" => Ok(Self::OtEquipment),
            "vendor" => Ok(Self::Vendor),
            "other" => Ok(Self::Other),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiger Asset-Typ: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    Low,
    Normal,
    High,
    Critical,
}

impl Criticality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Niedrig",
            Self::Normal => "Normal",
            Self::High => "Hoch",
            Self::Critical => "Kritisch",
        }
    }
}

impl FromStr for Criticality {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(AppError::Validation(vec![format!(
                "Ungültige Kritikalität: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetRowView {
    pub id: Uuid,
    pub asset_code: String,
    pub name: String,
    pub asset_type_code: String,
    pub asset_type_label: &'static str,
    pub owner_unit_name: String,
    pub owner_user_name: String,
    pub vendor_name: String,
    pub hosting_location: String,
    pub criticality_code: String,
    pub criticality_label: &'static str,
    pub description: String,
    pub can_edit: bool,
    pub effective_level_code: String,
    pub effective_badge_css: &'static str,
    pub effective_cia_summary: String,
}

#[derive(Debug, Deserialize)]
pub struct AssetFilter {
    pub q: Option<String>,
    pub asset_type: Option<String>,
    pub criticality: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssetForm {
    pub asset_code: String,
    pub name: String,
    pub asset_type: String,
    pub description: Option<String>,
    pub owner_unit_id: Option<String>,
    pub owner_user_id: Option<String>,
    pub vendor_name: Option<String>,
    pub hosting_location: Option<String>,
    pub criticality: String,
}

#[derive(Template)]
#[template(path = "organization/assets.html")]
struct AssetsTemplate {
    assets: Vec<AssetRowView>,
    filter_q: String,
    filter_type: String,
    filter_criticality: String,
    can_create: bool,
}

#[derive(Template)]
#[template(path = "organization/asset_drawer.html")]
struct AssetDrawerTemplate {
    asset: AssetRowView,
    can_edit: bool,
    can_delete: bool,
}

#[derive(Template)]
#[template(path = "organization/asset_form.html")]
struct AssetFormTemplate {
    action_url: String,
    submit_label: &'static str,
    asset_code: String,
    name: String,
    asset_type: String,
    description: String,
    selected_unit_id: String,
    selected_owner_id: String,
    vendor_name: String,
    hosting_location: String,
    criticality: String,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    csrf_token: String,
}

fn format_cia_summary(eff: Option<&EffectiveSystemClassification>) -> String {
    match eff {
        Some(e) => format!(
            "V: {} · I: {} · Vfb: {} ({} Informationswert(e))",
            e.confidentiality.label(),
            e.integrity.label(),
            e.availability.label(),
            e.linked_info_count
        ),
        None => "Keine Informationswerte verknüpft".to_string(),
    }
}

fn require_asset_reader(user: &CurrentUser) -> Result<(), AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Zugriff auf System-Assets.".to_string(),
        ));
    }
    Ok(())
}

fn can_user_edit_asset(
    user: &CurrentUser,
    unit_id: Option<Uuid>,
    owner_user_id: Option<Uuid>,
) -> bool {
    match user.role {
        Role::Admin | Role::Iso => true,
        Role::Owner => {
            let same_unit = matches!(
                (user.organization_unit_id, unit_id),
                (Some(u), Some(e)) if u == e
            );
            same_unit || owner_user_id == Some(user.id)
        }
        Role::Auditor | Role::Employee => false,
    }
}

async fn load_select_options(
    state: &AppState,
) -> Result<(Vec<SelectOption>, Vec<SelectOption>), AppError> {
    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;
    let mut units = Vec::with_capacity(unit_rows.len());
    for r in unit_rows {
        units.push(SelectOption {
            id: r.try_get("id")?,
            label: r.try_get("name")?,
        });
    }

    let user_rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut users = Vec::with_capacity(user_rows.len());
    for r in user_rows {
        users.push(SelectOption {
            id: r.try_get("id")?,
            label: r.try_get("full_name")?,
        });
    }

    Ok((units, users))
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(filter): Query<AssetFilter>,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;

    let q_trim = filter.q.unwrap_or_default().trim().to_string();
    let q_like = format!("%{q_trim}%");
    let f_type = filter.asset_type.unwrap_or_default().trim().to_string();
    let f_crit = filter.criticality.unwrap_or_default().trim().to_string();

    let rows = sqlx::query(
        r#"
        SELECT
            a.id,
            a.asset_code,
            a.name,
            a.asset_type,
            a.description,
            a.owner_unit_id,
            COALESCE(ou.name, '–') AS owner_unit_name,
            a.owner_user_id,
            COALESCE(u.full_name, '–') AS owner_user_name,
            COALESCE(a.vendor_name, '–') AS vendor_name,
            COALESCE(a.hosting_location, '–') AS hosting_location,
            a.criticality
        FROM system_assets a
        LEFT JOIN organization_units ou ON ou.id = a.owner_unit_id
        LEFT JOIN users u ON u.id = a.owner_user_id
        WHERE ($1 = '' OR a.asset_code ILIKE $2 OR a.name ILIKE $2 OR COALESCE(a.vendor_name, '') ILIKE $2)
          AND ($3 = '' OR a.asset_type = $3)
          AND ($4 = '' OR a.criticality = $4)
        ORDER BY a.asset_code ASC
        "#,
    )
    .bind(&q_trim)
    .bind(&q_like)
    .bind(&f_type)
    .bind(&f_crit)
    .fetch_all(&state.pool)
    .await?;

    let mut assets = Vec::with_capacity(rows.len());
    let mut sys_ids = Vec::with_capacity(rows.len());
    for r in &rows {
        sys_ids.push(r.try_get::<Uuid, _>("id")?);
    }
    let effective_map = load_effective_system_classifications(&state.pool, &sys_ids).await?;

    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let type_str: String = r.try_get("asset_type")?;
        let crit_str: String = r.try_get("criticality")?;
        let unit_id: Option<Uuid> = r.try_get("owner_unit_id")?;
        let owner_id: Option<Uuid> = r.try_get("owner_user_id")?;
        let parsed_type = AssetType::from_str(&type_str).unwrap_or(AssetType::Application);
        let parsed_crit = Criticality::from_str(&crit_str).unwrap_or(Criticality::Normal);
        let eff = effective_map.get(&id);

        assets.push(AssetRowView {
            id,
            asset_code: r.try_get("asset_code")?,
            name: r.try_get("name")?,
            asset_type_code: type_str,
            asset_type_label: parsed_type.label(),
            owner_unit_name: r.try_get("owner_unit_name")?,
            owner_user_name: r.try_get("owner_user_name")?,
            vendor_name: r.try_get("vendor_name")?,
            hosting_location: r.try_get("hosting_location")?,
            criticality_code: crit_str,
            criticality_label: parsed_crit.label(),
            description: r
                .try_get::<Option<String>, _>("description")?
                .unwrap_or_default(),
            can_edit: can_user_edit_asset(&user, unit_id, owner_id),
            effective_level_code: eff
                .map(|e| e.level_code.clone())
                .unwrap_or_else(|| "–".to_string()),
            effective_badge_css: eff.map(|e| e.badge_css_class).unwrap_or("badge-inactive"),
            effective_cia_summary: format_cia_summary(eff),
        });
    }

    let can_create = matches!(user.role, Role::Admin | Role::Iso | Role::Owner);
    let shell =
        ShellContext::from_user(&user, "System-Assets", "Inventar & Schutzbedarf", "assets");
    render_page(
        &headers,
        shell,
        &AssetsTemplate {
            assets,
            filter_q: q_trim,
            filter_type: f_type,
            filter_criticality: f_crit,
            can_create,
        },
    )
}

pub async fn asset_detail_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            a.id,
            a.asset_code,
            a.name,
            a.asset_type,
            a.description,
            a.owner_unit_id,
            COALESCE(ou.name, '–') AS owner_unit_name,
            a.owner_user_id,
            COALESCE(u.full_name, '–') AS owner_user_name,
            COALESCE(a.vendor_name, '–') AS vendor_name,
            COALESCE(a.hosting_location, '–') AS hosting_location,
            a.criticality
        FROM system_assets a
        LEFT JOIN organization_units ou ON ou.id = a.owner_unit_id
        LEFT JOIN users u ON u.id = a.owner_user_id
        WHERE a.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("System-Asset nicht gefunden.".to_string()))?;

    let type_str: String = row.try_get("asset_type")?;
    let crit_str: String = row.try_get("criticality")?;
    let unit_id: Option<Uuid> = row.try_get("owner_unit_id")?;
    let owner_id: Option<Uuid> = row.try_get("owner_user_id")?;
    let parsed_type = AssetType::from_str(&type_str).unwrap_or(AssetType::Application);
    let parsed_crit = Criticality::from_str(&crit_str).unwrap_or(Criticality::Normal);
    let can_edit = can_user_edit_asset(&user, unit_id, owner_id);
    let eff = load_effective_system_classification(&state.pool, id).await?;

    let asset = AssetRowView {
        id: row.try_get("id")?,
        asset_code: row.try_get("asset_code")?,
        name: row.try_get("name")?,
        asset_type_code: type_str,
        asset_type_label: parsed_type.label(),
        owner_unit_name: row.try_get("owner_unit_name")?,
        owner_user_name: row.try_get("owner_user_name")?,
        vendor_name: row.try_get("vendor_name")?,
        hosting_location: row.try_get("hosting_location")?,
        criticality_code: crit_str,
        criticality_label: parsed_crit.label(),
        description: row
            .try_get::<Option<String>, _>("description")?
            .unwrap_or_default(),
        can_edit,
        effective_level_code: eff
            .as_ref()
            .map(|e| format!("{} · {}", e.level_code, e.level_name))
            .unwrap_or_else(|| "Nicht zugeordnet".to_string()),
        effective_badge_css: eff
            .as_ref()
            .map(|e| e.badge_css_class)
            .unwrap_or("badge-inactive"),
        effective_cia_summary: format_cia_summary(eff.as_ref()),
    };

    render_template(&AssetDrawerTemplate {
        asset,
        can_edit,
        can_delete: user.role.is_iso_or_admin(),
    })
}

pub async fn new_asset_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;
    forbid_auditor(&user)?;

    let (units, users) = load_select_options(&state).await?;
    let default_unit = if user.role == Role::Owner {
        user.organization_unit_id
            .map(|u| u.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    render_template(&AssetFormTemplate {
        action_url: "/organization/assets".to_string(),
        submit_label: "System-Asset anlegen",
        asset_code: String::new(),
        name: String::new(),
        asset_type: "application".to_string(),
        description: String::new(),
        selected_unit_id: default_unit,
        selected_owner_id: user.id.to_string(),
        vendor_name: String::new(),
        hosting_location: String::new(),
        criticality: "normal".to_string(),
        units,
        users,
        csrf_token: user.csrf_token,
    })
}

pub async fn create_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<AssetForm>,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;
    forbid_auditor(&user)?;

    let asset_code = form.asset_code.trim().to_ascii_uppercase();
    let name = form.name.trim().to_string();
    if asset_code.is_empty() || asset_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Der Asset-Code muss zwischen 1 und 32 Zeichen lang sein.".to_string(),
        ]));
    }
    if name.is_empty() || name.len() > 200 {
        return Err(AppError::Validation(vec![
            "Der Name des System-Assets muss zwischen 1 und 200 Zeichen lang sein.".to_string(),
        ]));
    }

    let asset_type = AssetType::from_str(&form.asset_type)?;
    let criticality = Criticality::from_str(&form.criticality)?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;
    let owner_user_id = parse_optional_uuid(form.owner_user_id.as_deref())?;

    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let vendor_name = clean_opt(form.vendor_name);
    let hosting_location = clean_opt(form.hosting_location);
    let description = clean_opt(form.description);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query(
        r#"
        INSERT INTO system_assets (
            asset_code, name, asset_type, description,
            owner_unit_id, owner_user_id, vendor_name, hosting_location, criticality
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&asset_code)
    .bind(&name)
    .bind(asset_type.as_str())
    .bind(&description)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(&vendor_name)
    .bind(&hosting_location)
    .bind(criticality.as_str())
    .execute(&mut *tx)
    .await;

    if let Err(err) = res {
        if let sqlx::Error::Database(ref db_err) = err
            && db_err.is_unique_violation()
        {
            return Err(AppError::Conflict(format!(
                "Ein System-Asset mit Code '{asset_code}' existiert bereits."
            )));
        }
        return Err(AppError::Database(err));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization/assets");
    Ok(with_toast(resp, "success", "System-Asset angelegt."))
}

pub async fn edit_asset_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT asset_code, name, asset_type, description,
               owner_unit_id, owner_user_id, vendor_name, hosting_location, criticality
        FROM system_assets
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("System-Asset nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.try_get("owner_unit_id")?;
    let owner_user_id: Option<Uuid> = row.try_get("owner_user_id")?;
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let (units, users) = load_select_options(&state).await?;

    render_template(&AssetFormTemplate {
        action_url: format!("/organization/assets/{id}"),
        submit_label: "Änderungen speichern",
        asset_code: row.try_get("asset_code")?,
        name: row.try_get("name")?,
        asset_type: row.try_get("asset_type")?,
        description: row
            .try_get::<Option<String>, _>("description")?
            .unwrap_or_default(),
        selected_unit_id: owner_unit_id.map(|u| u.to_string()).unwrap_or_default(),
        selected_owner_id: owner_user_id.map(|u| u.to_string()).unwrap_or_default(),
        vendor_name: row
            .try_get::<Option<String>, _>("vendor_name")?
            .unwrap_or_default(),
        hosting_location: row
            .try_get::<Option<String>, _>("hosting_location")?
            .unwrap_or_default(),
        criticality: row.try_get("criticality")?,
        units,
        users,
        csrf_token: user.csrf_token,
    })
}

pub async fn update_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AssetForm>,
) -> Result<impl IntoResponse, AppError> {
    require_asset_reader(&user)?;
    forbid_auditor(&user)?;

    let existing =
        sqlx::query("SELECT owner_unit_id, owner_user_id FROM system_assets WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::NotFound("System-Asset nicht gefunden.".to_string()))?;

    let existing_unit_id: Option<Uuid> = existing.try_get("owner_unit_id")?;
    let existing_owner_id: Option<Uuid> = existing.try_get("owner_user_id")?;
    ensure_owner_scope(&user, existing_unit_id, existing_owner_id)?;

    let asset_code = form.asset_code.trim().to_ascii_uppercase();
    let name = form.name.trim().to_string();
    if asset_code.is_empty() || asset_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Der Asset-Code muss zwischen 1 und 32 Zeichen lang sein.".to_string(),
        ]));
    }
    if name.is_empty() || name.len() > 200 {
        return Err(AppError::Validation(vec![
            "Der Name des System-Assets muss zwischen 1 und 200 Zeichen lang sein.".to_string(),
        ]));
    }

    let asset_type = AssetType::from_str(&form.asset_type)?;
    let criticality = Criticality::from_str(&form.criticality)?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;
    let owner_user_id = parse_optional_uuid(form.owner_user_id.as_deref())?;

    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let vendor_name = clean_opt(form.vendor_name);
    let hosting_location = clean_opt(form.hosting_location);
    let description = clean_opt(form.description);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    sqlx::query(
        r#"
        UPDATE system_assets
        SET asset_code = $1,
            name = $2,
            asset_type = $3,
            description = $4,
            owner_unit_id = $5,
            owner_user_id = $6,
            vendor_name = $7,
            hosting_location = $8,
            criticality = $9,
            updated_at = NOW()
        WHERE id = $10
        "#,
    )
    .bind(&asset_code)
    .bind(&name)
    .bind(asset_type.as_str())
    .bind(&description)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(&vendor_name)
    .bind(&hosting_location)
    .bind(criticality.as_str())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization/assets");
    Ok(with_toast(resp, "success", "System-Asset aktualisiert."))
}

pub async fn delete_asset_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query("DELETE FROM system_assets WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "System-Asset nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization/assets");
    Ok(with_toast(resp, "success", "System-Asset gelöscht."))
}

fn clean_opt(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
