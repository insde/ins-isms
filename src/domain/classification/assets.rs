use std::{collections::HashSet, net::IpAddr, str::FromStr};

use askama::Template;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::{
        classification::{BadgeColor, CiaLevel},
        organization::profile::parse_optional_uuid,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, with_toast},
};

#[derive(Debug, Clone)]
pub struct InfoAssetRowView {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub level_id: Uuid,
    pub level_code: String,
    pub level_name: String,
    pub badge_css_class: &'static str,
    pub owner_unit_name: String,
    pub owner_user_name: String,
    pub confidentiality_label: &'static str,
    pub confidentiality_css: &'static str,
    pub integrity_label: &'static str,
    pub integrity_css: &'static str,
    pub availability_label: &'static str,
    pub availability_css: &'static str,
    pub retention_period: String,
    pub review_interval_months: i32,
    pub last_reviewed_label: String,
    pub next_review_label: String,
    pub is_overdue: bool,
    pub system_count: i64,
    pub can_edit: bool,
}

#[derive(Debug, Clone)]
pub struct LinkedSystemView {
    pub id: Uuid,
    pub asset_code: String,
    pub name: String,
    pub criticality_label: String,
}

#[derive(Debug, Clone)]
pub struct SelectOption {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct SystemCheckboxOption {
    pub id: Uuid,
    pub label: String,
    pub selected: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct InfoAssetFilter {
    pub q: Option<String>,
    pub level_id: Option<String>,
    pub unit_id: Option<String>,
    pub overdue: Option<String>,
}

#[derive(Template)]
#[template(path = "classification/assets.html")]
struct InfoAssetsTemplate {
    assets: Vec<InfoAssetRowView>,
    levels: Vec<SelectOption>,
    units: Vec<SelectOption>,
    filter_q: String,
    filter_level_id: String,
    filter_unit_id: String,
    filter_overdue: bool,
    can_create: bool,
}

#[derive(Template)]
#[template(path = "classification/asset_drawer.html")]
struct InfoAssetDrawerTemplate {
    asset: InfoAssetRowView,
    linked_systems: Vec<LinkedSystemView>,
    can_edit: bool,
    can_delete: bool,
}

#[derive(Template)]
#[template(path = "classification/asset_form.html")]
struct InfoAssetFormTemplate {
    action_url: String,
    submit_label: &'static str,
    name: String,
    description: String,
    classification_level_id: String,
    confidentiality: String,
    integrity: String,
    availability: String,
    owner_unit_id: String,
    owner_user_id: String,
    retention_period: String,
    review_interval_months: i32,
    levels: Vec<SelectOption>,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    systems: Vec<SystemCheckboxOption>,
}

fn require_info_asset_reader(user: &CurrentUser) -> Result<(), AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Mitarbeitende dürfen nur die Handling-Matrix und den One-Pager einsehen.".to_string(),
        ));
    }
    Ok(())
}

fn can_user_edit_info_asset(
    user: &CurrentUser,
    unit_id: Option<Uuid>,
    owner_id: Option<Uuid>,
) -> bool {
    match user.role {
        Role::Admin | Role::Iso => true,
        Role::Owner => ensure_owner_scope(user, unit_id, owner_id).is_ok(),
        Role::Auditor | Role::Employee => false,
    }
}

fn format_date_opt(dt: Option<DateTime<Utc>>) -> String {
    dt.map(|d| d.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "–".to_string())
}

async fn load_level_options(pool: &sqlx::PgPool) -> Result<Vec<SelectOption>, AppError> {
    let rows =
        sqlx::query("SELECT id, code, name FROM classification_levels ORDER BY rank ASC, code ASC")
            .fetch_all(pool)
            .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let code: String = r.try_get("code")?;
        let name: String = r.try_get("name")?;
        out.push(SelectOption {
            id: id.to_string(),
            label: format!("{code} · {name}"),
        });
    }
    Ok(out)
}

async fn load_unit_options(pool: &sqlx::PgPool) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(pool)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        out.push(SelectOption {
            id: id.to_string(),
            label: r.try_get("name")?,
        });
    }
    Ok(out)
}

async fn load_user_options(pool: &sqlx::PgPool) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        out.push(SelectOption {
            id: id.to_string(),
            label: r.try_get("full_name")?,
        });
    }
    Ok(out)
}

async fn load_system_options(
    pool: &sqlx::PgPool,
    selected_ids: &HashSet<Uuid>,
) -> Result<Vec<SystemCheckboxOption>, AppError> {
    let rows = sqlx::query(
        "SELECT id, asset_code, name FROM system_assets ORDER BY asset_code ASC, name ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let code: String = r.try_get("asset_code")?;
        let name: String = r.try_get("name")?;
        out.push(SystemCheckboxOption {
            id,
            label: format!("{code} · {name}"),
            selected: selected_ids.contains(&id),
        });
    }
    Ok(out)
}

fn map_row_to_view(
    r: &sqlx::postgres::PgRow,
    user: &CurrentUser,
) -> Result<InfoAssetRowView, AppError> {
    let conf_str: String = r.try_get("confidentiality")?;
    let int_str: String = r.try_get("integrity")?;
    let avail_str: String = r.try_get("availability")?;
    let badge_str: String = r.try_get("badge_color")?;

    let conf = CiaLevel::from_str(&conf_str).unwrap_or(CiaLevel::Normal);
    let int = CiaLevel::from_str(&int_str).unwrap_or(CiaLevel::Normal);
    let avail = CiaLevel::from_str(&avail_str).unwrap_or(CiaLevel::Normal);
    let badge = BadgeColor::from_str(&badge_str).unwrap_or(BadgeColor::Neutral);

    let unit_id: Option<Uuid> = r.try_get("owner_unit_id")?;
    let owner_id: Option<Uuid> = r.try_get("owner_user_id")?;
    let last_reviewed: Option<DateTime<Utc>> = r.try_get("last_reviewed_at")?;
    let next_review: Option<DateTime<Utc>> = r.try_get("next_review_due_at")?;
    let is_overdue = next_review.is_some_and(|due| due < Utc::now());

    Ok(InfoAssetRowView {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        description: r
            .try_get::<Option<String>, _>("description")?
            .unwrap_or_default(),
        level_id: r.try_get("classification_level_id")?,
        level_code: r.try_get("level_code")?,
        level_name: r.try_get("level_name")?,
        badge_css_class: badge.css_class(),
        owner_unit_name: r.try_get("owner_unit_name")?,
        owner_user_name: r.try_get("owner_user_name")?,
        confidentiality_label: conf.label(),
        confidentiality_css: conf.badge_class(),
        integrity_label: int.label(),
        integrity_css: int.badge_class(),
        availability_label: avail.label(),
        availability_css: avail.badge_class(),
        retention_period: r
            .try_get::<Option<String>, _>("retention_period")?
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "–".to_string()),
        review_interval_months: r.try_get("review_interval_months")?,
        last_reviewed_label: format_date_opt(last_reviewed),
        next_review_label: format_date_opt(next_review),
        is_overdue,
        system_count: r.try_get("system_count")?,
        can_edit: can_user_edit_info_asset(user, unit_id, owner_id),
    })
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(filter): Query<InfoAssetFilter>,
) -> Result<impl IntoResponse, AppError> {
    require_info_asset_reader(&user)?;

    let q_trim = filter.q.unwrap_or_default().trim().to_string();
    let q_like = format!("%{q_trim}%");
    let filter_level_id = filter.level_id.unwrap_or_default().trim().to_string();
    let filter_unit_id = filter.unit_id.unwrap_or_default().trim().to_string();
    let filter_overdue = matches!(
        filter.overdue.as_deref().map(str::trim),
        Some("1" | "true" | "on")
    );

    let level_uuid = parse_optional_uuid(Some(&filter_level_id))?;
    let unit_uuid = parse_optional_uuid(Some(&filter_unit_id))?;

    let rows = sqlx::query(
        r#"
        SELECT
            ia.id,
            ia.name,
            ia.description,
            ia.owner_unit_id,
            COALESCE(ou.name, '–') AS owner_unit_name,
            ia.owner_user_id,
            COALESCE(u.full_name, '–') AS owner_user_name,
            ia.classification_level_id,
            cl.code AS level_code,
            cl.name AS level_name,
            cl.badge_color,
            ia.confidentiality,
            ia.integrity,
            ia.availability,
            ia.retention_period,
            ia.review_interval_months,
            ia.last_reviewed_at,
            ia.next_review_due_at,
            (SELECT COUNT(*) FROM information_asset_systems ias WHERE ias.information_asset_id = ia.id) AS system_count
        FROM information_assets ia
        JOIN classification_levels cl ON cl.id = ia.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = ia.owner_unit_id
        LEFT JOIN users u ON u.id = ia.owner_user_id
        WHERE ($1 = '' OR ia.name ILIKE $2 OR COALESCE(ia.description, '') ILIKE $2)
          AND ($3::uuid IS NULL OR ia.classification_level_id = $3)
          AND ($4::uuid IS NULL OR ia.owner_unit_id = $4)
          AND ($5 = FALSE OR (ia.next_review_due_at IS NOT NULL AND ia.next_review_due_at < NOW()))
        ORDER BY cl.rank DESC, ia.name ASC
        "#,
    )
    .bind(&q_trim)
    .bind(&q_like)
    .bind(level_uuid)
    .bind(unit_uuid)
    .bind(filter_overdue)
    .fetch_all(&state.pool)
    .await?;

    let mut assets = Vec::with_capacity(rows.len());
    for r in rows {
        assets.push(map_row_to_view(&r, &user)?);
    }

    let levels = load_level_options(&state.pool).await?;
    let units = load_unit_options(&state.pool).await?;
    let can_create = matches!(user.role, Role::Admin | Role::Iso | Role::Owner);

    let shell = ShellContext::from_user(
        &user,
        "Informationswerte",
        "Klassifizierung",
        "classification",
    );
    render_page(
        &headers,
        shell,
        &InfoAssetsTemplate {
            assets,
            levels,
            units,
            filter_q: q_trim,
            filter_level_id,
            filter_unit_id,
            filter_overdue,
            can_create,
        },
    )
}

pub async fn new_asset_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    require_info_asset_reader(&user)?;

    let levels = load_level_options(&state.pool).await?;
    let units = load_unit_options(&state.pool).await?;
    let users = load_user_options(&state.pool).await?;
    let systems = load_system_options(&state.pool, &HashSet::new()).await?;

    let default_level = levels.first().map(|l| l.id.clone()).unwrap_or_default();
    let default_unit = if user.role == Role::Owner {
        user.organization_unit_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let default_user = if user.role == Role::Owner {
        user.id.to_string()
    } else {
        String::new()
    };

    render_template(&InfoAssetFormTemplate {
        action_url: "/classification/assets".to_string(),
        submit_label: "Informationswert anlegen",
        name: String::new(),
        description: String::new(),
        classification_level_id: default_level,
        confidentiality: "normal".to_string(),
        integrity: "normal".to_string(),
        availability: "normal".to_string(),
        owner_unit_id: default_unit,
        owner_user_id: default_user,
        retention_period: String::new(),
        review_interval_months: 12,
        levels,
        units,
        users,
        systems,
    })
}

pub async fn asset_detail_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_info_asset_reader(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            ia.id,
            ia.name,
            ia.description,
            ia.owner_unit_id,
            COALESCE(ou.name, '–') AS owner_unit_name,
            ia.owner_user_id,
            COALESCE(u.full_name, '–') AS owner_user_name,
            ia.classification_level_id,
            cl.code AS level_code,
            cl.name AS level_name,
            cl.badge_color,
            ia.confidentiality,
            ia.integrity,
            ia.availability,
            ia.retention_period,
            ia.review_interval_months,
            ia.last_reviewed_at,
            ia.next_review_due_at,
            (SELECT COUNT(*) FROM information_asset_systems ias WHERE ias.information_asset_id = ia.id) AS system_count
        FROM information_assets ia
        JOIN classification_levels cl ON cl.id = ia.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = ia.owner_unit_id
        LEFT JOIN users u ON u.id = ia.owner_user_id
        WHERE ia.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Informationswert nicht gefunden.".to_string()))?;

    let asset = map_row_to_view(&row, &user)?;

    let sys_rows = sqlx::query(
        r#"
        SELECT sa.id, sa.asset_code, sa.name, sa.criticality
        FROM information_asset_systems ias
        JOIN system_assets sa ON sa.id = ias.system_asset_id
        WHERE ias.information_asset_id = $1
        ORDER BY sa.asset_code ASC
        "#,
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let mut linked_systems = Vec::with_capacity(sys_rows.len());
    for sr in sys_rows {
        let crit_raw: String = sr.try_get("criticality")?;
        let crit_label = match crit_raw.as_str() {
            "low" => "Niedrig",
            "high" => "Hoch",
            "critical" => "Kritisch",
            _ => "Normal",
        };
        linked_systems.push(LinkedSystemView {
            id: sr.try_get("id")?,
            asset_code: sr.try_get("asset_code")?,
            name: sr.try_get("name")?,
            criticality_label: crit_label.to_string(),
        });
    }

    let can_edit = asset.can_edit;
    let can_delete = user.role.is_iso_or_admin();

    render_template(&InfoAssetDrawerTemplate {
        asset,
        linked_systems,
        can_edit,
        can_delete,
    })
}

pub async fn edit_asset_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    require_info_asset_reader(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            id,
            name,
            description,
            owner_unit_id,
            owner_user_id,
            classification_level_id,
            confidentiality,
            integrity,
            availability,
            retention_period,
            review_interval_months
        FROM information_assets
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Informationswert nicht gefunden.".to_string()))?;

    let unit_id: Option<Uuid> = row.try_get("owner_unit_id")?;
    let owner_id: Option<Uuid> = row.try_get("owner_user_id")?;
    if !can_user_edit_info_asset(&user, unit_id, owner_id) {
        return Err(AppError::Forbidden(
            "Sie dürfen nur Informationswerte Ihres eigenen Bereichs bearbeiten.".to_string(),
        ));
    }

    let linked_rows: Vec<Uuid> = sqlx::query_scalar(
        "SELECT system_asset_id FROM information_asset_systems WHERE information_asset_id = $1",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let selected_set: HashSet<Uuid> = linked_rows.into_iter().collect();

    let levels = load_level_options(&state.pool).await?;
    let units = load_unit_options(&state.pool).await?;
    let users = load_user_options(&state.pool).await?;
    let systems = load_system_options(&state.pool, &selected_set).await?;

    render_template(&InfoAssetFormTemplate {
        action_url: format!("/classification/assets/{id}"),
        submit_label: "Änderungen speichern",
        name: row.try_get("name")?,
        description: row
            .try_get::<Option<String>, _>("description")?
            .unwrap_or_default(),
        classification_level_id: row
            .try_get::<Uuid, _>("classification_level_id")?
            .to_string(),
        confidentiality: row.try_get("confidentiality")?,
        integrity: row.try_get("integrity")?,
        availability: row.try_get("availability")?,
        owner_unit_id: unit_id.map(|u| u.to_string()).unwrap_or_default(),
        owner_user_id: owner_id.map(|u| u.to_string()).unwrap_or_default(),
        retention_period: row
            .try_get::<Option<String>, _>("retention_period")?
            .unwrap_or_default(),
        review_interval_months: row.try_get("review_interval_months")?,
        levels,
        units,
        users,
        systems,
    })
}

struct ParsedInfoAssetForm {
    name: String,
    description: Option<String>,
    classification_level_id: Uuid,
    confidentiality: CiaLevel,
    integrity: CiaLevel,
    availability: CiaLevel,
    owner_unit_id: Option<Uuid>,
    owner_user_id: Option<Uuid>,
    retention_period: Option<String>,
    review_interval_months: i32,
    system_asset_ids: Vec<Uuid>,
}

fn parse_info_asset_form(body: &[u8]) -> Result<ParsedInfoAssetForm, AppError> {
    let mut name = String::new();
    let mut description = String::new();
    let mut level_id_raw = String::new();
    let mut conf_raw = "normal".to_string();
    let mut int_raw = "normal".to_string();
    let mut avail_raw = "normal".to_string();
    let mut unit_raw = String::new();
    let mut user_raw = String::new();
    let mut retention = String::new();
    let mut review_raw = "12".to_string();
    let mut system_asset_ids = Vec::new();

    for (k, v) in url::form_urlencoded::parse(body) {
        match k.as_ref() {
            "name" => name = v.trim().to_string(),
            "description" => description = v.trim().to_string(),
            "classification_level_id" => level_id_raw = v.trim().to_string(),
            "confidentiality" => conf_raw = v.trim().to_string(),
            "integrity" => int_raw = v.trim().to_string(),
            "availability" => avail_raw = v.trim().to_string(),
            "owner_unit_id" => unit_raw = v.trim().to_string(),
            "owner_user_id" => user_raw = v.trim().to_string(),
            "retention_period" => retention = v.trim().to_string(),
            "review_interval_months" => review_raw = v.trim().to_string(),
            "system_asset_ids" if !v.trim().is_empty() => {
                let sys_id = Uuid::parse_str(v.trim()).map_err(|_| {
                    AppError::Validation(vec!["Ungültige System-Asset-ID.".to_string()])
                })?;
                if !system_asset_ids.contains(&sys_id) {
                    system_asset_ids.push(sys_id);
                }
            }
            _ => {}
        }
    }

    let mut errors = Vec::new();
    if name.is_empty() || name.len() > 200 {
        errors.push("Name muss zwischen 1 und 200 Zeichen lang sein.".to_string());
    }
    let classification_level_id = Uuid::parse_str(&level_id_raw).map_err(|_| {
        AppError::Validation(vec![
            "Bitte eine gültige Schutzstufe auswählen.".to_string(),
        ])
    })?;

    let review_interval_months = review_raw.parse::<i32>().unwrap_or(0);
    if !(1..=60).contains(&review_interval_months) {
        errors.push("Review-Intervall muss zwischen 1 und 60 Monaten liegen.".to_string());
    }
    if retention.len() > 100 {
        errors.push("Aufbewahrungsfrist darf maximal 100 Zeichen lang sein.".to_string());
    }

    let confidentiality = CiaLevel::from_str(&conf_raw)?;
    let integrity = CiaLevel::from_str(&int_raw)?;
    let availability = CiaLevel::from_str(&avail_raw)?;
    let owner_unit_id = parse_optional_uuid(Some(&unit_raw))?;
    let owner_user_id = parse_optional_uuid(Some(&user_raw))?;

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    Ok(ParsedInfoAssetForm {
        name,
        description: (!description.is_empty()).then_some(description),
        classification_level_id,
        confidentiality,
        integrity,
        availability,
        owner_unit_id,
        owner_user_id,
        retention_period: (!retention.is_empty()).then_some(retention),
        review_interval_months,
        system_asset_ids,
    })
}

async fn sync_linked_systems(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    actor_ip: Option<IpAddr>,
    info_asset_id: Uuid,
    desired_system_ids: &[Uuid],
) -> Result<(), AppError> {
    let existing: Vec<Uuid> = sqlx::query_scalar(
        "SELECT system_asset_id FROM information_asset_systems WHERE information_asset_id = $1",
    )
    .bind(info_asset_id)
    .fetch_all(&mut **tx)
    .await?;

    let existing_set: HashSet<Uuid> = existing.into_iter().collect();
    let desired_set: HashSet<Uuid> = desired_system_ids.iter().copied().collect();

    for sys_id in desired_set.difference(&existing_set) {
        sqlx::query(
            r#"
            INSERT INTO information_asset_systems (information_asset_id, system_asset_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(info_asset_id)
        .bind(sys_id)
        .execute(&mut **tx)
        .await?;

        AuditService::log_event(
            &mut **tx,
            Some(actor_id),
            actor_ip,
            "information_asset_systems.linked",
            "information_asset_systems",
            &info_asset_id.to_string(),
            "System-Asset mit Informationswert verknüpft",
            None,
            Some(json!({
                "information_asset_id": info_asset_id,
                "system_asset_id": sys_id
            })),
        )
        .await?;
    }

    for sys_id in existing_set.difference(&desired_set) {
        sqlx::query(
            r#"
            DELETE FROM information_asset_systems
            WHERE information_asset_id = $1 AND system_asset_id = $2
            "#,
        )
        .bind(info_asset_id)
        .bind(sys_id)
        .execute(&mut **tx)
        .await?;

        AuditService::log_event(
            &mut **tx,
            Some(actor_id),
            actor_ip,
            "information_asset_systems.unlinked",
            "information_asset_systems",
            &info_asset_id.to_string(),
            "System-Asset-Verknüpfung vom Informationswert entfernt",
            Some(json!({
                "information_asset_id": info_asset_id,
                "system_asset_id": sys_id
            })),
            None,
        )
        .await?;
    }

    Ok(())
}

pub async fn create_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    require_info_asset_reader(&user)?;

    let mut form = parse_info_asset_form(&body)?;
    if user.role == Role::Owner {
        if form.owner_unit_id.is_none() && form.owner_user_id.is_none() {
            form.owner_unit_id = user.organization_unit_id;
            form.owner_user_id = Some(user.id);
        }
        ensure_owner_scope(&user, form.owner_unit_id, form.owner_user_id)?;
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let asset_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO information_assets (
            name,
            description,
            owner_unit_id,
            owner_user_id,
            classification_level_id,
            confidentiality,
            integrity,
            availability,
            retention_period,
            review_interval_months,
            next_review_due_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            NOW() + make_interval(months => $10)
        )
        RETURNING id
        "#,
    )
    .bind(&form.name)
    .bind(&form.description)
    .bind(form.owner_unit_id)
    .bind(form.owner_user_id)
    .bind(form.classification_level_id)
    .bind(form.confidentiality.as_str())
    .bind(form.integrity.as_str())
    .bind(form.availability.as_str())
    .bind(&form.retention_period)
    .bind(form.review_interval_months)
    .fetch_one(&mut *tx)
    .await?;

    sync_linked_systems(&mut tx, user.id, Some(ip), asset_id, &form.system_asset_ids).await?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/assets"),
        "success",
        "Informationswert angelegt.",
    ))
}

pub async fn update_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    require_info_asset_reader(&user)?;

    let form = parse_info_asset_form(&body)?;
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let existing =
        sqlx::query("SELECT owner_unit_id, owner_user_id FROM information_assets WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Informationswert nicht gefunden.".to_string()))?;

    let cur_unit: Option<Uuid> = existing.try_get("owner_unit_id")?;
    let cur_owner: Option<Uuid> = existing.try_get("owner_user_id")?;
    ensure_owner_scope(&user, cur_unit, cur_owner)?;
    if user.role == Role::Owner {
        ensure_owner_scope(&user, form.owner_unit_id, form.owner_user_id)?;
    }

    sqlx::query(
        r#"
        UPDATE information_assets
        SET name = $2,
            description = $3,
            owner_unit_id = $4,
            owner_user_id = $5,
            classification_level_id = $6,
            confidentiality = $7,
            integrity = $8,
            availability = $9,
            retention_period = $10,
            review_interval_months = $11,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(&form.name)
    .bind(&form.description)
    .bind(form.owner_unit_id)
    .bind(form.owner_user_id)
    .bind(form.classification_level_id)
    .bind(form.confidentiality.as_str())
    .bind(form.integrity.as_str())
    .bind(form.availability.as_str())
    .bind(&form.retention_period)
    .bind(form.review_interval_months)
    .execute(&mut *tx)
    .await?;

    sync_linked_systems(&mut tx, user.id, Some(ip), id, &form.system_asset_ids).await?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/assets"),
        "success",
        "Informationswert aktualisiert.",
    ))
}

pub async fn delete_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Informationswerte löschen.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let affected = sqlx::query("DELETE FROM information_assets WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound(
            "Informationswert nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/assets"),
        "success",
        "Informationswert gelöscht.",
    ))
}

pub async fn review_asset_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    require_info_asset_reader(&user)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let existing =
        sqlx::query("SELECT owner_unit_id, owner_user_id FROM information_assets WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Informationswert nicht gefunden.".to_string()))?;

    let cur_unit: Option<Uuid> = existing.try_get("owner_unit_id")?;
    let cur_owner: Option<Uuid> = existing.try_get("owner_user_id")?;
    ensure_owner_scope(&user, cur_unit, cur_owner)?;

    sqlx::query(
        r#"
        UPDATE information_assets
        SET last_reviewed_at = NOW(),
            next_review_due_at = NOW() + make_interval(months => review_interval_months),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/assets"),
        "success",
        "Review als geprüft markiert.",
    ))
}
