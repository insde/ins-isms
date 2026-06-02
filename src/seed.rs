use std::{collections::HashMap, path::Path};

use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::{password::hash_password, rbac::Role},
    config::Config,
    db::begin_audited_tx,
    error::AppError,
};

struct DefaultLevelSpec {
    code: &'static str,
    rank: i32,
    name: &'static str,
    description: &'static str,
    badge_color: &'static str,
    rules: &'static [(&'static str, &'static str, i32)],
}

const DEFAULT_CLASSIFICATION_LEVELS: &[DefaultLevelSpec] = &[
    DefaultLevelSpec {
        code: "C1",
        rank: 1,
        name: "Öffentlich",
        description: "Zur Veröffentlichung freigegebene Informationen (z. B. Website, Produktbroschüren, Stellenanzeigen). Eine unbefugte Weitergabe verursacht keinen Schaden.",
        badge_color: "neutral",
        rules: &[
            (
                "storage",
                "Freigegebene Ablage auf öffentlichen Webservern, Intranet oder Cloud-Speichern ohne besondere Verschlüsselungspflicht.",
                1,
            ),
            (
                "transmission",
                "Unverschlüsselter Versand per E-Mail oder Download möglich; Integrität über HTTPS/Signatur empfohlen.",
                2,
            ),
            (
                "labeling",
                "Kennzeichnung optional als „C1 · Öffentlich“ in Dokumenten-Fußzeilen.",
                3,
            ),
            (
                "access",
                "Freier Lesezugriff für Mitarbeitende und externe Dritte; Schreibrechte nur für autorisierte Redakteure.",
                4,
            ),
            (
                "disposal",
                "Reguläre Löschung oder Papierkorb ohne spezielle Vernichtungsanforderung.",
                5,
            ),
        ],
    },
    DefaultLevelSpec {
        code: "C2",
        rank: 2,
        name: "Intern",
        description: "Standard für den täglichen Geschäftsbetrieb (z. B. interne Arbeitsanweisungen, Projektpläne, Organigramme). Unbefugte externe Weitergabe verursacht geringen Schaden.",
        badge_color: "info",
        rules: &[
            (
                "storage",
                "Ablage ausschließlich auf freigegebenen Unternehmenssystemen (Netzlaufwerke, geschützte Cloud-Mandanten mit Zugriffsschutz).",
                1,
            ),
            (
                "transmission",
                "Elektronischer Versand nur über transportverschlüsselte Kanäle (TLS/S/MIME); keine unkontrollierte Weiterleitung an private Postfächer.",
                2,
            ),
            (
                "labeling",
                "Kennzeichnung im Dokumentenkopf oder Dateieigenschaften als „C2 · Intern“.",
                3,
            ),
            (
                "access",
                "Zugriff für alle internen Mitarbeitenden nach betrieblichem Bedarf; Weitergabe an Externe nur mit NDA oder berechtigtem Interesse.",
                4,
            ),
            (
                "disposal",
                "Datenträger sicher löschen; Papierausdrucke über betriebliche Datenschutz-Sammelbehälter (mind. Sicherheitsstufe P-2) entsorgen.",
                5,
            ),
        ],
    },
    DefaultLevelSpec {
        code: "C3",
        rank: 3,
        name: "Vertraulich",
        description: "Sensible Geschäfts- oder personenbezogene Daten (z. B. Kundenverträge, Personalakten, Finanz- und Gehaltsdaten). Unbefugte Offenlegung verursacht erheblichen Schaden.",
        badge_color: "warning",
        rules: &[
            (
                "storage",
                "Verschlüsselte Speicherung auf zugriffsbeschränkten Systemen (BitLocker/FileVault/LUKS); keine Ablage auf privaten Endgeräten.",
                1,
            ),
            (
                "transmission",
                "Ende-zu-Ende-verschlüsselter Versand (z. B. S/MIME, PGP oder passwortgeschütztes Archiv mit getrennt übermitteltem Kennwort).",
                2,
            ),
            (
                "labeling",
                "Verbindliche Kennzeichnung auf Deckblatt und jeder Seite als „C3 · Vertraulich“.",
                3,
            ),
            (
                "access",
                "Strenges Need-to-Know-Prinzip (Rollenberechtigung) mit dokumentierter Freigabe durch den Informations-Eigentümer.",
                4,
            ),
            (
                "disposal",
                "Kryptografisches Überschreiben/Wiping bei Datenträgern; Aktenvernichtung nach DIN 66399 mindestens Sicherheitsstufe P-4.",
                5,
            ),
        ],
    },
    DefaultLevelSpec {
        code: "C4",
        rank: 4,
        name: "Streng vertraulich",
        description: "Existenzkritische Geschäftsgeheimnisse, Zugangsdaten/Schlüsselmaterial, M&A-Unterlagen oder Kern-IP. Unbefugte Offenlegung gefährdet den Fortbestand des Unternehmens.",
        badge_color: "danger",
        rules: &[
            (
                "storage",
                "Ausschließlich in gehärteten, MFA-geschützten Tresor-/Vault-Systemen oder dedizierten verschlüsselten Containern; kein lokaler Cache.",
                1,
            ),
            (
                "transmission",
                "Nur über explizit freigegebene Ende-zu-Ende-verschlüsselte Kanäle mit Vier-Augen-Freigabe; physischer Transport nur versiegelt.",
                2,
            ),
            (
                "labeling",
                "Deutliche Kennzeichnung als „C4 · Streng vertraulich“ inklusive Empfänger- und Versionsnachweis.",
                3,
            ),
            (
                "access",
                "Minimaler namentlich benannter Personenkreis mit MFA-Pflicht, protokolliertem Zugriff und jährlicher Re-Zertifizierung.",
                4,
            ),
            (
                "disposal",
                "Zertifizierte physische Vernichtung (DIN 66399 P-5 oder höher) bzw. nachweisbare kryptografische Schlüsselvernichtung.",
                5,
            ),
        ],
    },
];

pub async fn seed_initial_data(pool: &PgPool, config: &Config) -> Result<(), AppError> {
    let has_profile: Option<i32> =
        sqlx::query_scalar("SELECT id FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    if has_profile.is_none() {
        let mut tx = begin_audited_tx(pool, None, None).await?;
        sqlx::query(
            r#"
            INSERT INTO organization_profile (id, company_name)
            VALUES (1, 'Meine Organisation')
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    if let (Some(email), Some(password)) = (&config.init_admin_email, &config.init_admin_password) {
        let admin_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
                .fetch_optional(pool)
                .await?;

        if admin_exists.is_none() {
            let email_norm = email.trim().to_ascii_lowercase();
            let pw_hash = hash_password(password).await?;

            let mut tx = begin_audited_tx(pool, None, None).await?;
            sqlx::query(
                r#"
                INSERT INTO users (email, full_name, password_hash, role, is_active)
                VALUES ($1, $2, $3, $4, TRUE)
                ON CONFLICT (email) DO NOTHING
                "#,
            )
            .bind(&email_norm)
            .bind("Administrator")
            .bind(&pw_hash)
            .bind(Role::Admin.as_str())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            tracing::info!(email = %email_norm, "Initialer Administrator angelegt");
        }
    }

    let mut tx = begin_audited_tx(pool, None, None).await?;
    seed_classification_defaults_tx(&mut tx, false).await?;

    if config.seed_starter_content && config.seed_dir.is_dir() {
        seed_from_dir_tx(&mut tx, &config.seed_dir).await?;
    }
    tx.commit().await?;

    Ok(())
}

pub async fn seed_from_dir(pool: &PgPool, dir: &Path) -> Result<(), AppError> {
    let mut tx = begin_audited_tx(pool, None, None).await?;
    seed_from_dir_tx(&mut tx, dir).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn seed_from_dir_tx(
    tx: &mut Transaction<'_, Postgres>,
    dir: &Path,
) -> Result<(), AppError> {
    seed_soa_catalogs_from_dir_tx(tx, dir).await?;
    let policies_dir = dir.join("policies");
    if policies_dir.is_dir() {
        seed_policies_from_dir_tx(tx, &policies_dir).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
struct PolicyFrontmatter {
    doc_code: Option<String>,
    title: Option<String>,
    doc_type: Option<String>,
    classification_code: Option<String>,
    requires_acknowledgment: Option<bool>,
}

pub fn split_policy_frontmatter(raw: &str) -> Result<(Option<String>, String), AppError> {
    let normalized = raw.trim_start_matches('\u{FEFF}');
    let Some(rest) = normalized.strip_prefix("---") else {
        return Ok((None, normalized.to_string()));
    };
    let rest = if let Some(r) = rest.strip_prefix("\r\n") {
        r
    } else if let Some(r) = rest.strip_prefix('\n') {
        r
    } else {
        return Ok((None, normalized.to_string()));
    };

    if let Some(end_idx) = rest.find("\n---") {
        let yaml_part = &rest[..end_idx];
        let after = &rest[end_idx + 4..];
        let body = after
            .strip_prefix("\r\n")
            .or_else(|| after.strip_prefix('\n'))
            .unwrap_or(after);
        Ok((Some(yaml_part.to_string()), body.to_string()))
    } else {
        Ok((None, normalized.to_string()))
    }
}

fn derive_doc_code_from_filename(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("DOC-001");
    let code = stem.split('_').next().unwrap_or(stem).trim();
    let truncated: String = code.chars().take(32).collect();
    if truncated.is_empty() {
        "DOC-001".to_string()
    } else {
        truncated.to_ascii_uppercase()
    }
}

fn derive_title_from_markdown(body: &str, path: &Path) -> String {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            let clean = heading.trim();
            if !clean.is_empty() {
                return clean.chars().take(255).collect();
            }
        }
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Richtlinie");
    stem.split_once('_')
        .map(|(_, rest)| rest.replace(['_', '-'], " "))
        .unwrap_or_else(|| stem.to_string())
        .chars()
        .take(255)
        .collect()
}

pub fn verify_policy_anchors_in_dir(dir: &Path) -> Result<(), AppError> {
    const EXPECTED: &[(&str, &[&str])] = &[
        (
            "POL-001",
            &[
                "zielsetzung",
                "schutzziele",
                "verantwortung-geschaeftsfuehrung",
                "organisation-rollen",
                "risikomanagement-pdca",
            ],
        ),
        (
            "POL-002",
            &[
                "passwort-regeln",
                "mfa-pflicht",
                "zugriffsrechte",
                "admin-konten",
            ],
        ),
        (
            "POL-003",
            &[
                "homeoffice",
                "endgeraete-sicherheit",
                "clean-desk",
                "datentraeger-transport",
            ],
        ),
        (
            "POL-004",
            &["meldepflicht", "meldewege", "nis2-fristen", "nachbereitung"],
        ),
    ];

    let policies_dir = dir.join("policies");
    let entries = std::fs::read_dir(&policies_dir).map_err(|e| {
        AppError::Internal(format!(
            "Richtlinien-Verzeichnis {} konnte nicht gelesen werden: {e}",
            policies_dir.display()
        ))
    })?;

    let mut files = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("md") {
            let content = std::fs::read_to_string(&p)?;
            files.push((derive_doc_code_from_filename(&p), content));
        }
    }

    for (code, anchors) in EXPECTED {
        let (_, content) = files
            .iter()
            .find(|(c, _)| c == code)
            .ok_or_else(|| AppError::Internal(format!("Starter-Richtlinie {code} fehlt.")))?;
        for anchor in *anchors {
            let needle = format!(r#"<a id="{anchor}"></a>"#);
            if !content.contains(&needle) {
                return Err(AppError::Internal(format!(
                    "Starter-Richtlinie {code} fehlt Pflicht-Anker {needle}."
                )));
            }
        }
    }
    Ok(())
}

pub async fn seed_policies_from_dir_tx(
    tx: &mut Transaction<'_, Postgres>,
    policies_dir: &Path,
) -> Result<(), AppError> {
    let author_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users ORDER BY (role = 'admin') DESC, created_at ASC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await?;

    let Some(author_id) = author_id else {
        tracing::debug!("Richtlinien-Seeding übersprungen: noch kein Benutzer vorhanden.");
        return Ok(());
    };

    let mut md_paths: Vec<_> = std::fs::read_dir(policies_dir)
        .map_err(|e| {
            AppError::Internal(format!(
                "Richtlinien-Verzeichnis {} konnte nicht gelesen werden: {e}",
                policies_dir.display()
            ))
        })?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        })
        .collect();
    md_paths.sort();

    for path in md_paths {
        let raw = std::fs::read_to_string(&path)?;
        let (frontmatter_yaml, body_markdown) = split_policy_frontmatter(&raw)?;
        let fm: PolicyFrontmatter = match frontmatter_yaml {
            Some(yaml) => serde_yml::from_str(&yaml).map_err(|err| {
                AppError::Internal(format!(
                    "Ungültiges YAML-Frontmatter in {}: {err}",
                    path.display()
                ))
            })?,
            None => PolicyFrontmatter::default(),
        };

        let doc_code = fm
            .doc_code
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| derive_doc_code_from_filename(&path));

        let existing_doc_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = $1")
                .bind(&doc_code)
                .fetch_optional(&mut **tx)
                .await?;

        if existing_doc_id.is_some() {
            continue;
        }

        let title = fm
            .title
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| derive_title_from_markdown(&body_markdown, &path));

        let doc_type = fm
            .doc_type
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| {
                matches!(
                    s.as_str(),
                    "policy" | "guideline" | "sop" | "record" | "template" | "runbook"
                )
            })
            .unwrap_or_else(|| "policy".to_string());

        let class_code = fm
            .classification_code
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "C2".to_string());

        let level_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM classification_levels ORDER BY (code = $1) DESC, (code = 'C2') DESC, rank ASC LIMIT 1",
        )
        .bind(&class_code)
        .fetch_optional(&mut **tx)
        .await?;

        let Some(level_id) = level_id else {
            return Err(AppError::Internal(
                "Keine Schutzstufe für Richtlinien-Seeding gefunden.".to_string(),
            ));
        };

        let requires_ack = fm.requires_acknowledgment.unwrap_or(true);

        let doc_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO documents (
                doc_code, title, doc_type, source_type,
                classification_level_id, owner_user_id,
                review_interval_months, requires_acknowledgment
            )
            VALUES ($1, $2, $3, 'markdown_editor', $4, $5, 12, $6)
            RETURNING id
            "#,
        )
        .bind(&doc_code)
        .bind(&title)
        .bind(&doc_type)
        .bind(level_id)
        .bind(author_id)
        .bind(requires_ack)
        .fetch_one(&mut **tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO document_versions (
                document_id, version_number, status, content_markdown,
                change_summary, author_id
            )
            VALUES ($1, '0.1', 'draft', $2, 'Initialer Entwurf aus Seed-Verzeichnis', $3)
            "#,
        )
        .bind(doc_id)
        .bind(&body_markdown)
        .bind(author_id)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

pub async fn seed_classification_defaults_tx(
    tx: &mut Transaction<'_, Postgres>,
    overwrite_existing: bool,
) -> Result<(), AppError> {
    for spec in DEFAULT_CLASSIFICATION_LEVELS {
        let existing_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = $1")
                .bind(spec.code)
                .fetch_optional(&mut **tx)
                .await?;

        let level_id = match existing_id {
            Some(id) => {
                if overwrite_existing {
                    sqlx::query(
                        r#"
                        UPDATE classification_levels
                        SET name = $2,
                            description = $3,
                            badge_color = $4,
                            updated_at = NOW()
                        WHERE id = $1
                        "#,
                    )
                    .bind(id)
                    .bind(spec.name)
                    .bind(spec.description)
                    .bind(spec.badge_color)
                    .execute(&mut **tx)
                    .await?;
                }
                id
            }
            None => {
                let rank_taken: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM classification_levels WHERE rank = $1")
                        .bind(spec.rank)
                        .fetch_optional(&mut **tx)
                        .await?;
                let effective_rank = if rank_taken.is_some() {
                    let max_rank: i32 = sqlx::query_scalar(
                        "SELECT COALESCE(MAX(rank), 0) FROM classification_levels",
                    )
                    .fetch_one(&mut **tx)
                    .await?;
                    max_rank + 1
                } else {
                    spec.rank
                };

                sqlx::query_scalar(
                    r#"
                    INSERT INTO classification_levels (code, rank, name, description, badge_color)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                    "#,
                )
                .bind(spec.code)
                .bind(effective_rank)
                .bind(spec.name)
                .bind(spec.description)
                .bind(spec.badge_color)
                .fetch_one(&mut **tx)
                .await?
            }
        };

        let existing_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM classification_handling_rules WHERE level_id = $1",
        )
        .bind(level_id)
        .fetch_one(&mut **tx)
        .await?;

        if overwrite_existing && existing_rules > 0 {
            sqlx::query("DELETE FROM classification_handling_rules WHERE level_id = $1")
                .bind(level_id)
                .execute(&mut **tx)
                .await?;
        }

        if overwrite_existing || existing_rules == 0 {
            for (category, rule_text, sort_order) in spec.rules {
                sqlx::query(
                    r#"
                    INSERT INTO classification_handling_rules (level_id, category, rule_text, sort_order)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(level_id)
                .bind(*category)
                .bind(*rule_text)
                .bind(*sort_order)
                .execute(&mut **tx)
                .await?;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct StarterCatalog {
    framework: StarterFramework,
    controls: Vec<StarterControl>,
    #[serde(default)]
    mappings: Vec<StarterMapping>,
}

#[derive(Debug, Deserialize)]
struct StarterFramework {
    code: String,
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct StarterControl {
    code: String,
    domain: String,
    sort_order: i32,
    title: String,
    description: String,
    audit_question: Option<String>,
    default_not_applicable_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StarterMapping {
    #[serde(alias = "source_control_code")]
    source_code: String,
    #[serde(alias = "target_framework_code")]
    target_framework: String,
    #[serde(alias = "target_control_code")]
    target_code: String,
    mapping_type: String,
}

pub async fn seed_soa_catalogs_from_dir_tx(
    tx: &mut Transaction<'_, Postgres>,
    dir: &Path,
) -> Result<(), AppError> {
    let mut json_paths: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| {
            AppError::Internal(format!(
                "Seed-Verzeichnis {} konnte nicht gelesen werden: {e}",
                dir.display()
            ))
        })?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    json_paths.sort();

    let mut catalogs = Vec::with_capacity(json_paths.len());
    for path in json_paths {
        let raw = std::fs::read_to_string(&path)?;
        let parsed: StarterCatalog = serde_json::from_str(&raw).map_err(|err| {
            AppError::Internal(format!(
                "Ungültiges Katalog-JSON in {}: {err}",
                path.display()
            ))
        })?;
        catalogs.push(parsed);
    }

    let mut control_index: HashMap<(String, String), Uuid> = HashMap::new();

    for catalog in &catalogs {
        let fw_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO compliance_frameworks (code, name, version, is_active)
            VALUES ($1, $2, $3, TRUE)
            ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name,
                    version = EXCLUDED.version
            RETURNING id
            "#,
        )
        .bind(&catalog.framework.code)
        .bind(&catalog.framework.name)
        .bind(&catalog.framework.version)
        .fetch_one(&mut **tx)
        .await?;

        for ctrl in &catalog.controls {
            let ctrl_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO framework_controls (
                    framework_id, code, domain, title, description,
                    audit_question, default_not_applicable_reason, sort_order
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (framework_id, code) DO UPDATE
                    SET domain = EXCLUDED.domain,
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        audit_question = COALESCE(EXCLUDED.audit_question, framework_controls.audit_question),
                        default_not_applicable_reason = COALESCE(
                            EXCLUDED.default_not_applicable_reason,
                            framework_controls.default_not_applicable_reason
                        ),
                        sort_order = EXCLUDED.sort_order
                RETURNING id
                "#,
            )
            .bind(fw_id)
            .bind(&ctrl.code)
            .bind(&ctrl.domain)
            .bind(&ctrl.title)
            .bind(&ctrl.description)
            .bind(&ctrl.audit_question)
            .bind(&ctrl.default_not_applicable_reason)
            .bind(ctrl.sort_order)
            .fetch_one(&mut **tx)
            .await?;

            sqlx::query(
                r#"
                INSERT INTO soa_entries (control_id)
                VALUES ($1)
                ON CONFLICT (control_id) DO NOTHING
                "#,
            )
            .bind(ctrl_id)
            .execute(&mut **tx)
            .await?;

            control_index.insert((catalog.framework.code.clone(), ctrl.code.clone()), ctrl_id);
        }
    }

    for catalog in &catalogs {
        for mapping in &catalog.mappings {
            let Some(&source_id) =
                control_index.get(&(catalog.framework.code.clone(), mapping.source_code.clone()))
            else {
                continue;
            };
            let Some(&target_id) = control_index.get(&(
                mapping.target_framework.clone(),
                mapping.target_code.clone(),
            )) else {
                continue;
            };
            if source_id == target_id {
                continue;
            }

            sqlx::query(
                r#"
                INSERT INTO control_mappings (source_control_id, target_control_id, mapping_type)
                VALUES ($1, $2, $3)
                ON CONFLICT (source_control_id, target_control_id) DO UPDATE
                    SET mapping_type = EXCLUDED.mapping_type
                "#,
            )
            .bind(source_id)
            .bind(target_id)
            .bind(&mapping.mapping_type)
            .execute(&mut **tx)
            .await?;
        }
    }

    Ok(())
}
