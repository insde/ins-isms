pub mod assets;
pub mod export;
pub mod levels;

use std::{collections::HashMap, fmt, str::FromStr};

use axum::{
    Router,
    response::{IntoResponse, Redirect},
    routing::{get, patch, post},
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CiaLevel {
    Normal = 1,
    High = 2,
    VeryHigh = 3,
}

impl CiaLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
            Self::VeryHigh => "very_high",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::High => "Hoch",
            Self::VeryHigh => "Sehr hoch",
        }
    }

    pub fn from_rank(rank: i32) -> Self {
        match rank {
            3 => Self::VeryHigh,
            2 => Self::High,
            _ => Self::Normal,
        }
    }

    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Normal => "badge-normal",
            Self::High => "badge-high",
            Self::VeryHigh => "badge-critical",
        }
    }
}

impl fmt::Display for CiaLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CiaLevel {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            "very_high" => Ok(Self::VeryHigh),
            other => Err(AppError::Validation(vec![format!(
                "Ungültiges Schutzbedarf-Niveau: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlingCategory {
    Storage,
    Transmission,
    Labeling,
    Access,
    Disposal,
}

impl HandlingCategory {
    pub const ALL: [Self; 5] = [
        Self::Storage,
        Self::Transmission,
        Self::Labeling,
        Self::Access,
        Self::Disposal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Transmission => "transmission",
            Self::Labeling => "labeling",
            Self::Access => "access",
            Self::Disposal => "disposal",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Storage => "Speicherung",
            Self::Transmission => "Übertragung",
            Self::Labeling => "Kennzeichnung",
            Self::Access => "Zugriff",
            Self::Disposal => "Vernichtung",
        }
    }
}

impl fmt::Display for HandlingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HandlingCategory {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "storage" => Ok(Self::Storage),
            "transmission" => Ok(Self::Transmission),
            "labeling" => Ok(Self::Labeling),
            "access" => Ok(Self::Access),
            "disposal" => Ok(Self::Disposal),
            other => Err(AppError::Validation(vec![format!(
                "Ungültige Handling-Kategorie: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeColor {
    Neutral,
    Info,
    Warning,
    Danger,
}

impl BadgeColor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Danger => "danger",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Neutral => "Neutral",
            Self::Info => "Blau (Info)",
            Self::Warning => "Amber (Warnung)",
            Self::Danger => "Rot (Kritisch)",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Neutral => "badge-c1",
            Self::Info => "badge-c2",
            Self::Warning => "badge-c3",
            Self::Danger => "badge-c4",
        }
    }
}

impl fmt::Display for BadgeColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BadgeColor {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "neutral" => Ok(Self::Neutral),
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "danger" => Ok(Self::Danger),
            other => Err(AppError::Validation(vec![format!(
                "Ungültige Badge-Farbe: {other}"
            )])),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveSystemClassification {
    pub system_asset_id: Uuid,
    pub level_code: String,
    pub level_name: String,
    pub level_rank: i32,
    pub badge_css_class: &'static str,
    pub confidentiality: CiaLevel,
    pub integrity: CiaLevel,
    pub availability: CiaLevel,
    pub linked_info_count: i64,
}

pub async fn load_effective_system_classifications(
    pool: &PgPool,
    system_ids: &[Uuid],
) -> Result<HashMap<Uuid, EffectiveSystemClassification>, AppError> {
    if system_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(
        r#"
        WITH agg AS (
            SELECT
                ias.system_asset_id,
                MAX(cl.rank) AS max_rank,
                MAX(CASE ia.confidentiality WHEN 'very_high' THEN 3 WHEN 'high' THEN 2 ELSE 1 END) AS max_c,
                MAX(CASE ia.integrity       WHEN 'very_high' THEN 3 WHEN 'high' THEN 2 ELSE 1 END) AS max_i,
                MAX(CASE ia.availability    WHEN 'very_high' THEN 3 WHEN 'high' THEN 2 ELSE 1 END) AS max_a,
                COUNT(ia.id) AS info_count
            FROM information_asset_systems ias
            JOIN information_assets ia ON ia.id = ias.information_asset_id
            JOIN classification_levels cl ON cl.id = ia.classification_level_id
            WHERE ias.system_asset_id = ANY($1)
            GROUP BY ias.system_asset_id
        )
        SELECT
            agg.system_asset_id,
            agg.max_rank,
            agg.max_c,
            agg.max_i,
            agg.max_a,
            agg.info_count,
            cl.code,
            cl.name,
            cl.badge_color
        FROM agg
        JOIN classification_levels cl ON cl.rank = agg.max_rank
        "#,
    )
    .bind(system_ids)
    .fetch_all(pool)
    .await?;

    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let system_asset_id: Uuid = row.try_get("system_asset_id")?;
        let badge_str: String = row.try_get("badge_color")?;
        let badge = BadgeColor::from_str(&badge_str).unwrap_or(BadgeColor::Neutral);

        map.insert(
            system_asset_id,
            EffectiveSystemClassification {
                system_asset_id,
                level_code: row.try_get("code")?,
                level_name: row.try_get("name")?,
                level_rank: row.try_get("max_rank")?,
                badge_css_class: badge.css_class(),
                confidentiality: CiaLevel::from_rank(row.try_get("max_c")?),
                integrity: CiaLevel::from_rank(row.try_get("max_i")?),
                availability: CiaLevel::from_rank(row.try_get("max_a")?),
                linked_info_count: row.try_get("info_count")?,
            },
        );
    }

    Ok(map)
}

pub async fn load_effective_system_classification(
    pool: &PgPool,
    system_id: Uuid,
) -> Result<Option<EffectiveSystemClassification>, AppError> {
    let mut map = load_effective_system_classifications(pool, &[system_id]).await?;
    Ok(map.remove(&system_id))
}

async fn classification_root_redirect(user: CurrentUser) -> impl IntoResponse {
    if user.role == Role::Employee {
        Redirect::to("/classification/levels")
    } else {
        Redirect::to("/classification/assets")
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/classification", get(classification_root_redirect))
        .route(
            "/classification/assets",
            get(assets::list_assets_handler).post(assets::create_asset_handler),
        )
        .route(
            "/classification/assets/new",
            get(assets::new_asset_form_handler),
        )
        .route(
            "/classification/assets/{id}",
            get(assets::asset_detail_handler).post(assets::update_asset_handler),
        )
        .route(
            "/classification/assets/{id}/edit",
            get(assets::edit_asset_form_handler),
        )
        .route(
            "/classification/assets/{id}/delete",
            post(assets::delete_asset_handler),
        )
        .route(
            "/classification/assets/{id}/review",
            post(assets::review_asset_handler),
        )
        .route(
            "/classification/levels",
            get(levels::matrix_handler).post(levels::create_level_handler),
        )
        .route(
            "/classification/levels/restore-defaults",
            post(levels::restore_defaults_handler),
        )
        .route(
            "/classification/levels/{id}",
            patch(levels::update_level_handler).post(levels::update_level_handler),
        )
        .route(
            "/classification/levels/{id}/delete",
            post(levels::delete_level_handler),
        )
        .route(
            "/classification/rules/{id}",
            patch(levels::update_rule_handler).post(levels::update_rule_handler),
        )
        .route(
            "/classification/export/policy.pdf",
            get(export::policy_pdf_handler),
        )
        .route(
            "/classification/export/cheatsheet",
            get(export::cheatsheet_html_handler),
        )
        .route(
            "/classification/export/cheatsheet.pdf",
            get(export::cheatsheet_pdf_handler),
        )
}
