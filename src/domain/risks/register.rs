use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role, ensure_owner_scope},
    domain::risks::{
        RiskRating, RiskStatus, TreatmentStrategy, risk_score,
        suggested_impact_for_classification_rank,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, render_template},
};

#[derive(Debug, Deserialize)]
pub struct RiskFilterQuery {
    pub mode: Option<String>,
    pub likelihood: Option<i16>,
    pub impact: Option<i16>,
    pub status: Option<String>,
    pub strategy: Option<String>,
    pub unit_id: Option<String>,
    pub overdue: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImpactHintQuery {
    pub affected_information_asset_id: Option<String>,
    pub affected_system_asset_id: Option<String>,
}

struct SelectOption {
    id: String,
    label: String,
    selected: bool,
}

struct HeatmapCell {
    likelihood: i16,
    impact: i16,
    count: usize,
    css_class: &'static str,
    is_active: bool,
    href: String,
}

struct HeatmapRow {
    likelihood: i16,
    cells: Vec<HeatmapCell>,
}

struct RiskRowView {
    id: Uuid,
    reference_code: String,
    title: String,
    asset_label: String,
    owner_label: String,
    inherent_likelihood: i16,
    inherent_impact: i16,
    inherent_score: i16,
    inherent_rating_label: &'static str,
    inherent_badge_css: &'static str,
    residual_likelihood: i16,
    residual_impact: i16,
    residual_score: i16,
    residual_rating_label: &'static str,
    residual_badge_css: &'static str,
    strategy_label: &'static str,
    status_label: &'static str,
    status_css: &'static str,
    control_count: i64,
    is_overdue: bool,
    next_review_label: String,
}

#[derive(Template)]
#[template(path = "risks/register.html")]
struct RiskRegisterTemplate {
    mode: String,
    is_inherent_mode: bool,
    filter_likelihood: i16,
    filter_impact: i16,
    has_cell_filter: bool,
    filter_status: String,
    filter_strategy: String,
    filter_overdue: bool,
    filter_q: String,
    units: Vec<SelectOption>,
    heatmap_rows: Vec<HeatmapRow>,
    count_critical: usize,
    count_high: usize,
    count_medium: usize,
    count_low: usize,
    c3_c4_coupled_count: usize,
    total_count: usize,
    overdue_count: usize,
    rows: Vec<RiskRowView>,
    can_create: bool,
    clear_cell_href: String,
    mode_residual_href: String,
    mode_inherent_href: String,
}

#[allow(clippy::too_many_arguments)]
fn build_risks_href(
    mode: &str,
    likelihood: Option<i16>,
    impact: Option<i16>,
    status: &str,
    strategy: &str,
    unit_id: &str,
    overdue: bool,
    q: &str,
) -> String {
    let mut parts = vec![format!("mode={mode}")];
    if let (Some(l), Some(i)) = (likelihood, impact) {
        parts.push(format!("likelihood={l}"));
        parts.push(format!("impact={i}"));
    }
    if !status.is_empty() {
        parts.push(format!("status={status}"));
    }
    if !strategy.is_empty() {
        parts.push(format!("strategy={strategy}"));
    }
    if !unit_id.is_empty() {
        parts.push(format!("unit_id={unit_id}"));
    }
    if overdue {
        parts.push("overdue=true".to_string());
    }
    if !q.is_empty() {
        parts.push(format!("q={}", urlencoding_simple(q)));
    }
    format!("/risks?{}", parts.join("&"))
}

fn urlencoding_simple(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub async fn list_risks_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(query): Query<RiskFilterQuery>,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf das Risikoregister.".to_string(),
        ));
    }

    let mode = match query.mode.as_deref() {
        Some("inherent") => "inherent",
        _ => "residual",
    };
    let is_inherent_mode = mode == "inherent";

    let filter_l = query.likelihood.filter(|v| (1..=5).contains(v));
    let filter_i = query.impact.filter(|v| (1..=5).contains(v));
    let (active_l, active_i) = match (filter_l, filter_i) {
        (Some(l), Some(i)) => (Some(l), Some(i)),
        _ => (None, None),
    };

    let filter_status = query.status.unwrap_or_default().trim().to_string();
    if !filter_status.is_empty() {
        let _ = RiskStatus::from_str(&filter_status)?;
    }
    let filter_strategy = query.strategy.unwrap_or_default().trim().to_string();
    if !filter_strategy.is_empty() {
        let _ = TreatmentStrategy::from_str(&filter_strategy)?;
    }

    let filter_unit_uuid = query
        .unit_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| AppError::Validation(vec!["Ungültige Einheits-ID.".to_string()]))?;
    let filter_unit_id = filter_unit_uuid.map(|u| u.to_string()).unwrap_or_default();

    let filter_overdue = matches!(query.overdue.as_deref(), Some("true" | "1" | "on"));
    let filter_q = query.q.unwrap_or_default().trim().to_string();

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;
    let units = unit_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let id_str = id.to_string();
            SelectOption {
                selected: id_str == filter_unit_id,
                id: id_str,
                label: r.get("name"),
            }
        })
        .collect();

    let db_rows = sqlx::query(
        r#"
        SELECT
            rs.id,
            rs.reference_code,
            rs.title,
            rs.inherent_likelihood,
            rs.inherent_impact,
            rs.residual_likelihood,
            rs.residual_impact,
            rs.treatment_strategy,
            rs.status,
            rs.owner_unit_id,
            rs.next_review_due_at,
            ia.name AS info_asset_name,
            cl.code AS info_level_code,
            cl.rank AS info_level_rank,
            sa.asset_code AS sys_asset_code,
            sa.name AS sys_asset_name,
            COALESCE(u.full_name, ou.name, 'Nicht zugewiesen') AS owner_label,
            (SELECT COUNT(*) FROM risk_control_links rcl WHERE rcl.risk_id = rs.id) AS control_count
        FROM risk_scenarios rs
        LEFT JOIN information_assets ia ON ia.id = rs.affected_information_asset_id
        LEFT JOIN classification_levels cl ON cl.id = ia.classification_level_id
        LEFT JOIN system_assets sa ON sa.id = rs.affected_system_asset_id
        LEFT JOIN users u ON u.id = rs.owner_user_id
        LEFT JOIN organization_units ou ON ou.id = rs.owner_unit_id
        ORDER BY (rs.residual_likelihood * rs.residual_impact) DESC, rs.reference_code ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let mut cell_counts = [[0usize; 6]; 6];
    let mut count_critical = 0usize;
    let mut count_high = 0usize;
    let mut count_medium = 0usize;
    let mut count_low = 0usize;
    let mut c3_c4_coupled_count = 0usize;
    let mut overdue_count = 0usize;
    let total_count = db_rows.len();

    let lower_q = filter_q.to_ascii_lowercase();
    let mut rows = Vec::new();

    for r in db_rows {
        let inh_l: i16 = r.get("inherent_likelihood");
        let inh_i: i16 = r.get("inherent_impact");
        let res_l: i16 = r.get("residual_likelihood");
        let res_i: i16 = r.get("residual_impact");

        let (matrix_l, matrix_i) = if is_inherent_mode {
            (inh_l, inh_i)
        } else {
            (res_l, res_i)
        };
        if (1..=5).contains(&matrix_l) && (1..=5).contains(&matrix_i) {
            cell_counts[matrix_l as usize][matrix_i as usize] += 1;
        }
        let matrix_rating = RiskRating::from_score(risk_score(matrix_l, matrix_i));
        match matrix_rating {
            RiskRating::Critical => count_critical += 1,
            RiskRating::High => count_high += 1,
            RiskRating::Medium => count_medium += 1,
            RiskRating::Low => count_low += 1,
        }

        let info_level_rank: Option<i32> = r.get("info_level_rank");
        if info_level_rank.unwrap_or(0) >= 3 {
            c3_c4_coupled_count += 1;
        }

        let next_review: Option<DateTime<Utc>> = r.get("next_review_due_at");
        let is_overdue = next_review.map(|d| d <= now).unwrap_or(false);
        if is_overdue {
            overdue_count += 1;
        }

        let status_raw: &str = r.get("status");
        let strategy_raw: &str = r.get("treatment_strategy");
        let owner_unit_id: Option<Uuid> = r.get("owner_unit_id");
        let reference_code: String = r.get("reference_code");
        let title: String = r.get("title");
        let owner_label: String = r.get("owner_label");

        if let (Some(fl), Some(fi)) = (active_l, active_i)
            && (matrix_l != fl || matrix_i != fi)
        {
            continue;
        }
        if !filter_status.is_empty() && status_raw != filter_status {
            continue;
        }
        if !filter_strategy.is_empty() && strategy_raw != filter_strategy {
            continue;
        }
        if let Some(uid) = filter_unit_uuid
            && owner_unit_id != Some(uid)
        {
            continue;
        }
        if filter_overdue && !is_overdue {
            continue;
        }
        if !lower_q.is_empty()
            && !reference_code.to_ascii_lowercase().contains(&lower_q)
            && !title.to_ascii_lowercase().contains(&lower_q)
            && !owner_label.to_ascii_lowercase().contains(&lower_q)
        {
            continue;
        }

        let info_asset_name: Option<String> = r.get("info_asset_name");
        let info_level_code: Option<String> = r.get("info_level_code");
        let sys_asset_code: Option<String> = r.get("sys_asset_code");
        let sys_asset_name: Option<String> = r.get("sys_asset_name");

        let asset_label = match (
            info_asset_name,
            info_level_code,
            sys_asset_code,
            sys_asset_name,
        ) {
            (Some(ia), Some(lvl), Some(sc), _) => format!("{lvl} · {ia} ({sc})"),
            (Some(ia), Some(lvl), None, _) => format!("{lvl} · {ia}"),
            (None, _, Some(sc), Some(sn)) => format!("{sc} · {sn}"),
            _ => "Allgemein".to_string(),
        };

        let inh_score = risk_score(inh_l, inh_i);
        let inh_rating = RiskRating::from_score(inh_score);
        let res_score = risk_score(res_l, res_i);
        let res_rating = RiskRating::from_score(res_score);
        let strategy = TreatmentStrategy::from_str(strategy_raw)?;
        let status = RiskStatus::from_str(status_raw)?;

        rows.push(RiskRowView {
            id: r.get("id"),
            reference_code,
            title,
            asset_label,
            owner_label,
            inherent_likelihood: inh_l,
            inherent_impact: inh_i,
            inherent_score: inh_score,
            inherent_rating_label: inh_rating.label(),
            inherent_badge_css: inh_rating.badge_css(),
            residual_likelihood: res_l,
            residual_impact: res_i,
            residual_score: res_score,
            residual_rating_label: res_rating.label(),
            residual_badge_css: res_rating.badge_css(),
            strategy_label: strategy.label(),
            status_label: status.label(),
            status_css: status.css_class(),
            control_count: r.get("control_count"),
            is_overdue,
            next_review_label: next_review
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "—".to_string()),
        });
    }

    let mut heatmap_rows = Vec::with_capacity(5);
    for l in (1i16..=5).rev() {
        let mut cells = Vec::with_capacity(5);
        for i in 1i16..=5 {
            let rating = RiskRating::from_score(risk_score(l, i));
            let is_active = active_l == Some(l) && active_i == Some(i);
            let href = if is_active {
                build_risks_href(
                    mode,
                    None,
                    None,
                    &filter_status,
                    &filter_strategy,
                    &filter_unit_id,
                    filter_overdue,
                    &filter_q,
                )
            } else {
                build_risks_href(
                    mode,
                    Some(l),
                    Some(i),
                    &filter_status,
                    &filter_strategy,
                    &filter_unit_id,
                    filter_overdue,
                    &filter_q,
                )
            };
            cells.push(HeatmapCell {
                likelihood: l,
                impact: i,
                count: cell_counts[l as usize][i as usize],
                css_class: rating.heatmap_css(),
                is_active,
                href,
            });
        }
        heatmap_rows.push(HeatmapRow {
            likelihood: l,
            cells,
        });
    }

    let clear_cell_href = build_risks_href(
        mode,
        None,
        None,
        &filter_status,
        &filter_strategy,
        &filter_unit_id,
        filter_overdue,
        &filter_q,
    );
    let mode_residual_href = build_risks_href(
        "residual",
        active_l,
        active_i,
        &filter_status,
        &filter_strategy,
        &filter_unit_id,
        filter_overdue,
        &filter_q,
    );
    let mode_inherent_href = build_risks_href(
        "inherent",
        active_l,
        active_i,
        &filter_status,
        &filter_strategy,
        &filter_unit_id,
        filter_overdue,
        &filter_q,
    );

    let shell = ShellContext::from_user(
        &user,
        "Risikomanagement",
        "Governance & Compliance",
        "risks",
    );
    render_page(
        &headers,
        shell,
        &RiskRegisterTemplate {
            mode: mode.to_string(),
            is_inherent_mode,
            filter_likelihood: active_l.unwrap_or(0),
            filter_impact: active_i.unwrap_or(0),
            has_cell_filter: active_l.is_some() && active_i.is_some(),
            filter_status,
            filter_strategy,
            filter_overdue,
            filter_q,
            units,
            heatmap_rows,
            count_critical,
            count_high,
            count_medium,
            count_low,
            c3_c4_coupled_count,
            total_count,
            overdue_count,
            rows,
            can_create: user.role != Role::Auditor,
            clear_cell_href,
            mode_residual_href,
            mode_inherent_href,
        },
    )
}

#[derive(Template)]
#[template(path = "risks/form.html")]
struct RiskFormTemplate {
    suggested_code: String,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    info_assets: Vec<SelectOption>,
    system_assets: Vec<SelectOption>,
}

pub async fn new_risk_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Auditor || user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Anlegen von Risikoszenarien.".to_string(),
        ));
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_scenarios")
        .fetch_one(&state.pool)
        .await?;
    let suggested_code = format!("RSK-{:03}", count + 1);

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;
    let units = unit_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: user.organization_unit_id == Some(id),
                id: id.to_string(),
                label: r.get("name"),
            }
        })
        .collect();

    let user_rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    let users = user_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: user.id == id,
                id: id.to_string(),
                label: r.get("full_name"),
            }
        })
        .collect();

    let ia_rows = sqlx::query(
        r#"
        SELECT ia.id, ia.name, cl.code AS level_code
        FROM information_assets ia
        JOIN classification_levels cl ON cl.id = ia.classification_level_id
        ORDER BY cl.rank DESC, ia.name ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;
    let info_assets = ia_rows
        .into_iter()
        .map(|r| SelectOption {
            id: r.get::<Uuid, _>("id").to_string(),
            label: format!(
                "{} · {}",
                r.get::<String, _>("level_code"),
                r.get::<String, _>("name")
            ),
            selected: false,
        })
        .collect();

    let sa_rows =
        sqlx::query("SELECT id, asset_code, name FROM system_assets ORDER BY asset_code ASC")
            .fetch_all(&state.pool)
            .await?;
    let system_assets = sa_rows
        .into_iter()
        .map(|r| SelectOption {
            id: r.get::<Uuid, _>("id").to_string(),
            label: format!(
                "{} · {}",
                r.get::<String, _>("asset_code"),
                r.get::<String, _>("name")
            ),
            selected: false,
        })
        .collect();

    render_template(&RiskFormTemplate {
        suggested_code,
        units,
        users,
        info_assets,
        system_assets,
    })
}

#[derive(Template)]
#[template(path = "risks/impact_hint.html")]
struct ImpactHintTemplate {
    has_hint: bool,
    suggested_impact: i16,
    info_hint: String,
    system_hint: String,
}

pub async fn impact_hint_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<ImpactHintQuery>,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden("Kein Zugriff.".to_string()));
    }

    let mut info_hint = String::new();
    let mut system_hint = String::new();
    let mut suggested_impact: i16 = 0;

    if let Some(raw_ia) = query
        .affected_information_asset_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Ok(ia_id) = Uuid::parse_str(raw_ia)
        && let Some(row) = sqlx::query(
            r#"
            SELECT ia.name, cl.code, cl.name AS level_name, cl.rank
            FROM information_assets ia
            JOIN classification_levels cl ON cl.id = ia.classification_level_id
            WHERE ia.id = $1
            "#,
        )
        .bind(ia_id)
        .fetch_optional(&state.pool)
        .await?
    {
        let code: String = row.get("code");
        let level_name: String = row.get("level_name");
        let rank: i32 = row.get("rank");
        if let Some(min_imp) = suggested_impact_for_classification_rank(rank) {
            suggested_impact = min_imp;
            info_hint = format!(
                "Informationswert mit Schutzstufe {code} ({level_name}): Empfohlene Brutto-Auswirkung mindestens {min_imp}."
            );
        } else {
            info_hint = format!("Informationswert mit Schutzstufe {code} ({level_name}).");
        }
    }

    if let Some(raw_sa) = query
        .affected_system_asset_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Ok(sa_id) = Uuid::parse_str(raw_sa)
        && let Some(row) = sqlx::query(
            r#"
            SELECT MAX(cl.rank) AS max_rank
            FROM information_asset_systems ias
            JOIN information_assets ia ON ia.id = ias.information_asset_id
            JOIN classification_levels cl ON cl.id = ia.classification_level_id
            WHERE ias.system_asset_id = $1
            "#,
        )
        .bind(sa_id)
        .fetch_optional(&state.pool)
        .await?
        && let Some(max_rank) = row.try_get::<Option<i32>, _>("max_rank")?
        && let Some(level_row) =
            sqlx::query("SELECT code, name FROM classification_levels WHERE rank = $1 LIMIT 1")
                .bind(max_rank)
                .fetch_optional(&state.pool)
                .await?
    {
        let code: String = level_row.get("code");
        let lname: String = level_row.get("name");
        if let Some(min_imp) = suggested_impact_for_classification_rank(max_rank) {
            suggested_impact = suggested_impact.max(min_imp);
        }
        system_hint = format!("System-Asset erbt per Maximumprinzip Schutzstufe {code} ({lname}).");
    }

    let has_hint = !info_hint.is_empty() || !system_hint.is_empty();
    render_template(&ImpactHintTemplate {
        has_hint,
        suggested_impact,
        info_hint,
        system_hint,
    })
}

struct LinkedControlView {
    soa_entry_id: Uuid,
    control_code: String,
    framework_code: String,
    title: String,
    status_label: String,
}

#[derive(Template)]
#[template(path = "risks/drawer.html")]
struct RiskDrawerTemplate {
    id: Uuid,
    reference_code: String,
    title: String,
    threat_description: String,
    vulnerability_description: String,
    inherent_likelihood: i16,
    inherent_impact: i16,
    inherent_score: i16,
    inherent_rating_label: &'static str,
    inherent_badge_css: &'static str,
    residual_likelihood: i16,
    residual_impact: i16,
    residual_score: i16,
    residual_rating_label: &'static str,
    residual_badge_css: &'static str,
    treatment_strategy: String,
    treatment_plan: String,
    acceptance_justification: String,
    accepted_by_name: String,
    accepted_at_label: String,
    status: String,
    status_label: &'static str,
    status_css: &'static str,
    next_review_date: String,
    classification_note: String,
    can_edit: bool,
    can_accept_elevated: bool,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    info_assets: Vec<SelectOption>,
    system_assets: Vec<SelectOption>,
    linked_controls: Vec<LinkedControlView>,
    available_controls: Vec<SelectOption>,
}

pub async fn risk_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(risk_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf das Risikoregister.".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT
            rs.*,
            au.full_name AS accepted_by_name
        FROM risk_scenarios rs
        LEFT JOIN users au ON au.id = rs.accepted_by_user_id
        WHERE rs.id = $1
        "#,
    )
    .bind(risk_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Risikoszenario nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    let aff_ia_id: Option<Uuid> = row.get("affected_information_asset_id");
    let aff_sa_id: Option<Uuid> = row.get("affected_system_asset_id");

    let can_edit = match user.role {
        Role::Admin | Role::Iso => true,
        Role::Owner => ensure_owner_scope(&user, owner_unit_id, owner_user_id).is_ok(),
        Role::Auditor | Role::Employee => false,
    };

    let inh_l: i16 = row.get("inherent_likelihood");
    let inh_i: i16 = row.get("inherent_impact");
    let res_l: i16 = row.get("residual_likelihood");
    let res_i: i16 = row.get("residual_impact");
    let inh_score = risk_score(inh_l, inh_i);
    let res_score = risk_score(res_l, res_i);
    let inh_rating = RiskRating::from_score(inh_score);
    let res_rating = RiskRating::from_score(res_score);

    let status_str: String = row.get("status");
    let status = RiskStatus::from_str(&status_str)?;
    let accepted_at: Option<DateTime<Utc>> = row.get("accepted_at");
    let next_review: Option<DateTime<Utc>> = row.get("next_review_due_at");

    let mut classification_note = String::new();
    if let Some(ia_id) = aff_ia_id
        && let Some(ia_row) = sqlx::query(
            "SELECT cl.code, cl.name, cl.rank FROM information_assets ia JOIN classification_levels cl ON cl.id = ia.classification_level_id WHERE ia.id = $1",
        )
        .bind(ia_id)
        .fetch_optional(&state.pool)
        .await?
    {
        let code: String = ia_row.get("code");
        let rank: i32 = ia_row.get("rank");
        if let Some(min_imp) = suggested_impact_for_classification_rank(rank) {
            classification_note = format!("Verknüpfter Informationswert ({code}): Mindest-Impact {min_imp} empfohlen.");
        }
    }

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;
    let units = unit_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: owner_unit_id == Some(id),
                id: id.to_string(),
                label: r.get("name"),
            }
        })
        .collect();

    let user_rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    let users = user_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: owner_user_id == Some(id),
                id: id.to_string(),
                label: r.get("full_name"),
            }
        })
        .collect();

    let ia_rows = sqlx::query(
        "SELECT ia.id, ia.name, cl.code AS level_code FROM information_assets ia JOIN classification_levels cl ON cl.id = ia.classification_level_id ORDER BY cl.rank DESC, ia.name ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    let info_assets = ia_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: aff_ia_id == Some(id),
                id: id.to_string(),
                label: format!(
                    "{} · {}",
                    r.get::<String, _>("level_code"),
                    r.get::<String, _>("name")
                ),
            }
        })
        .collect();

    let sa_rows =
        sqlx::query("SELECT id, asset_code, name FROM system_assets ORDER BY asset_code ASC")
            .fetch_all(&state.pool)
            .await?;
    let system_assets = sa_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                selected: aff_sa_id == Some(id),
                id: id.to_string(),
                label: format!(
                    "{} · {}",
                    r.get::<String, _>("asset_code"),
                    r.get::<String, _>("name")
                ),
            }
        })
        .collect();

    let linked_rows = sqlx::query(
        r#"
        SELECT se.id AS soa_entry_id, fc.code, fc.title, cf.code AS fw_code, se.implementation_status
        FROM risk_control_links rcl
        JOIN soa_entries se ON se.id = rcl.soa_entry_id
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE rcl.risk_id = $1
        ORDER BY fc.sort_order ASC, fc.code ASC
        "#,
    )
    .bind(risk_id)
    .fetch_all(&state.pool)
    .await?;

    let mut linked_ids = Vec::with_capacity(linked_rows.len());
    let mut linked_controls = Vec::with_capacity(linked_rows.len());
    for lr in linked_rows {
        let soa_entry_id: Uuid = lr.get("soa_entry_id");
        linked_ids.push(soa_entry_id);
        let st = crate::domain::soa::ImplementationStatus::from_str(
            lr.get::<&str, _>("implementation_status"),
        )?;
        linked_controls.push(LinkedControlView {
            soa_entry_id,
            control_code: lr.get("code"),
            framework_code: lr.get("fw_code"),
            title: lr.get("title"),
            status_label: st.label().to_string(),
        });
    }

    let avail_rows = sqlx::query(
        r#"
        SELECT se.id AS soa_entry_id, fc.code, fc.title, cf.code AS fw_code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.is_active = TRUE
        ORDER BY (cf.code = 'ISO27001_2022_STARTER') DESC, fc.sort_order ASC, fc.code ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let available_controls = avail_rows
        .into_iter()
        .filter_map(|r| {
            let sid: Uuid = r.get("soa_entry_id");
            if linked_ids.contains(&sid) {
                return None;
            }
            Some(SelectOption {
                id: sid.to_string(),
                label: format!(
                    "{} · {} ({})",
                    r.get::<String, _>("code"),
                    r.get::<String, _>("title"),
                    r.get::<String, _>("fw_code")
                ),
                selected: false,
            })
        })
        .collect();

    render_template(&RiskDrawerTemplate {
        id: risk_id,
        reference_code: row.get("reference_code"),
        title: row.get("title"),
        threat_description: row.get("threat_description"),
        vulnerability_description: row
            .get::<Option<String>, _>("vulnerability_description")
            .unwrap_or_default(),
        inherent_likelihood: inh_l,
        inherent_impact: inh_i,
        inherent_score: inh_score,
        inherent_rating_label: inh_rating.label(),
        inherent_badge_css: inh_rating.badge_css(),
        residual_likelihood: res_l,
        residual_impact: res_i,
        residual_score: res_score,
        residual_rating_label: res_rating.label(),
        residual_badge_css: res_rating.badge_css(),
        treatment_strategy: row.get("treatment_strategy"),
        treatment_plan: row
            .get::<Option<String>, _>("treatment_plan")
            .unwrap_or_default(),
        acceptance_justification: row
            .get::<Option<String>, _>("acceptance_justification")
            .unwrap_or_default(),
        accepted_by_name: row
            .get::<Option<String>, _>("accepted_by_name")
            .unwrap_or_else(|| "—".to_string()),
        accepted_at_label: accepted_at
            .map(|d| d.format("%d.%m.%Y %H:%M UTC").to_string())
            .unwrap_or_else(|| "—".to_string()),
        status: status_str,
        status_label: status.label(),
        status_css: status.css_class(),
        next_review_date: next_review
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        classification_note,
        can_edit,
        can_accept_elevated: user.role.is_iso_or_admin(),
        units,
        users,
        info_assets,
        system_assets,
        linked_controls,
        available_controls,
    })
}
