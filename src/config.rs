use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use chrono_tz::Tz;
use thiserror::Error;
use url::Url;

const DEFAULT_MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
const HARD_MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;
const MIN_SESSION_SECRET_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Pflichtvariable '{0}' fehlt oder ist leer")]
    MissingRequired(&'static str),

    #[error("Datei für '{key}_FILE' ({path}) konnte nicht gelesen werden: {source}")]
    SecretFileRead {
        key: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Ungültiger Wert für '{key}': {reason}")]
    InvalidValue { key: &'static str, reason: String },

    #[error("Sicherheitsverstoß in Produktion: {0}")]
    InsecureProductionConfig(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Production,
    Development,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendConfig {
    Local {
        path: PathBuf,
    },
    S3 {
        endpoint: Option<String>,
        bucket: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
    },
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: Url,
    pub client_id: String,
    pub client_secret: String,
    pub role_claim: String,
    pub auto_provision: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub app_env: AppEnv,
    pub bind_addr: SocketAddr,
    pub app_base_url: Url,
    pub app_timezone: Tz,
    pub database_url: String,
    pub migration_database_url: String,
    pub session_secret: Vec<u8>,
    pub session_ttl_hours: i64,
    pub cookie_secure: bool,
    pub trust_proxy: bool,
    pub init_admin_email: Option<String>,
    pub init_admin_password: Option<String>,
    pub oidc: Option<OidcConfig>,
    pub storage: StorageBackendConfig,
    pub max_upload_bytes: usize,
    pub typst_bin_path: PathBuf,
    pub typst_font_paths: Option<PathBuf>,
    pub pdf_template_dir: Option<PathBuf>,
    pub seed_starter_content: bool,
    pub seed_dir: PathBuf,
    pub smtp: Option<SmtpConfig>,
    pub rust_log: String,
}

impl Config {
    pub fn is_production(&self) -> bool {
        self.app_env == AppEnv::Production
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let app_env = match lookup_trimmed(&lookup, "APP_ENV") {
            Some(v) if v.eq_ignore_ascii_case("development") => AppEnv::Development,
            _ => AppEnv::Production,
        };
        let is_prod = app_env == AppEnv::Production;

        let bind_addr_raw =
            lookup_trimmed(&lookup, "BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let bind_addr =
            SocketAddr::from_str(&bind_addr_raw).map_err(|e| ConfigError::InvalidValue {
                key: "BIND_ADDR",
                reason: e.to_string(),
            })?;

        let app_base_url_raw = match lookup_trimmed(&lookup, "APP_BASE_URL") {
            Some(v) => v,
            None if is_prod => return Err(ConfigError::MissingRequired("APP_BASE_URL")),
            None => "http://localhost:8080".to_string(),
        };
        let app_base_url =
            Url::parse(&app_base_url_raw).map_err(|e| ConfigError::InvalidValue {
                key: "APP_BASE_URL",
                reason: e.to_string(),
            })?;
        if !matches!(app_base_url.scheme(), "http" | "https") {
            return Err(ConfigError::InvalidValue {
                key: "APP_BASE_URL",
                reason: "Schema muss http oder https sein".to_string(),
            });
        }

        let tz_raw =
            lookup_trimmed(&lookup, "APP_TIMEZONE").unwrap_or_else(|| "Europe/Berlin".to_string());
        let app_timezone = Tz::from_str(&tz_raw).map_err(|e| ConfigError::InvalidValue {
            key: "APP_TIMEZONE",
            reason: e.to_string(),
        })?;

        let database_url = resolve_secret_required(&lookup, "DATABASE_URL")?;
        let migration_database_url = resolve_secret_optional(&lookup, "MIGRATION_DATABASE_URL")?
            .unwrap_or_else(|| database_url.clone());

        let session_secret_raw = resolve_secret_required(&lookup, "SESSION_SECRET")?;
        if session_secret_raw.len() < MIN_SESSION_SECRET_BYTES {
            return Err(ConfigError::InvalidValue {
                key: "SESSION_SECRET",
                reason: format!("muss mindestens {MIN_SESSION_SECRET_BYTES} Bytes lang sein"),
            });
        }
        let session_secret = session_secret_raw.into_bytes();

        let session_ttl_hours = match lookup_trimmed(&lookup, "SESSION_TTL_HOURS") {
            Some(raw) => {
                let parsed: i64 = raw.parse().map_err(|_| ConfigError::InvalidValue {
                    key: "SESSION_TTL_HOURS",
                    reason: "muss eine positive Ganzzahl sein".to_string(),
                })?;
                if parsed <= 0 {
                    return Err(ConfigError::InvalidValue {
                        key: "SESSION_TTL_HOURS",
                        reason: "muss größer als 0 sein".to_string(),
                    });
                }
                parsed
            }
            None => 12,
        };

        let cookie_secure = parse_bool(&lookup, "COOKIE_SECURE", true)?;
        if is_prod && !cookie_secure {
            return Err(ConfigError::InsecureProductionConfig(
                "COOKIE_SECURE darf in production nicht false sein",
            ));
        }

        let trust_proxy = parse_bool(&lookup, "TRUST_PROXY", is_prod)?;

        let init_admin_email = lookup_trimmed(&lookup, "INIT_ADMIN_EMAIL");
        let init_admin_password = resolve_secret_optional(&lookup, "INIT_ADMIN_PASSWORD")?;
        if let Some(ref pw) = init_admin_password
            && pw.chars().count() < 12
        {
            return Err(ConfigError::InvalidValue {
                key: "INIT_ADMIN_PASSWORD",
                reason: "muss mindestens 12 Zeichen lang sein".to_string(),
            });
        }

        let oidc = match lookup_trimmed(&lookup, "OIDC_ISSUER_URL") {
            Some(issuer_raw) => {
                let issuer_url =
                    Url::parse(&issuer_raw).map_err(|e| ConfigError::InvalidValue {
                        key: "OIDC_ISSUER_URL",
                        reason: e.to_string(),
                    })?;
                let client_id = lookup_trimmed(&lookup, "OIDC_CLIENT_ID")
                    .ok_or(ConfigError::MissingRequired("OIDC_CLIENT_ID"))?;
                let client_secret = resolve_secret_required(&lookup, "OIDC_CLIENT_SECRET")?;
                let role_claim = lookup_trimmed(&lookup, "OIDC_ROLE_CLAIM")
                    .unwrap_or_else(|| "groups".to_string());
                let auto_provision = parse_bool(&lookup, "OIDC_AUTO_PROVISION", false)?;
                Some(OidcConfig {
                    issuer_url,
                    client_id,
                    client_secret,
                    role_claim,
                    auto_provision,
                })
            }
            None => None,
        };

        let storage_backend_raw =
            lookup_trimmed(&lookup, "STORAGE_BACKEND").unwrap_or_else(|| "local".to_string());
        let storage = match storage_backend_raw.to_ascii_lowercase().as_str() {
            "local" => {
                let path = lookup_trimmed(&lookup, "STORAGE_LOCAL_PATH")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| Path::new("data").join("blobs"));
                StorageBackendConfig::Local { path }
            }
            "s3" => {
                let endpoint = lookup_trimmed(&lookup, "S3_ENDPOINT");
                let bucket = lookup_trimmed(&lookup, "S3_BUCKET")
                    .ok_or(ConfigError::MissingRequired("S3_BUCKET"))?;
                let region = lookup_trimmed(&lookup, "S3_REGION")
                    .ok_or(ConfigError::MissingRequired("S3_REGION"))?;
                let access_key_id = lookup_trimmed(&lookup, "S3_ACCESS_KEY_ID")
                    .ok_or(ConfigError::MissingRequired("S3_ACCESS_KEY_ID"))?;
                let secret_access_key = resolve_secret_required(&lookup, "S3_SECRET_ACCESS_KEY")?;
                StorageBackendConfig::S3 {
                    endpoint,
                    bucket,
                    region,
                    access_key_id,
                    secret_access_key,
                }
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    key: "STORAGE_BACKEND",
                    reason: format!("unbekanntes Backend '{other}' (erlaubt: local, s3)"),
                });
            }
        };

        let max_upload_bytes = match lookup_trimmed(&lookup, "MAX_UPLOAD_BYTES") {
            Some(raw) => {
                let val: usize = raw.parse().map_err(|_| ConfigError::InvalidValue {
                    key: "MAX_UPLOAD_BYTES",
                    reason: "muss eine positive Zahl sein".to_string(),
                })?;
                if val == 0 || val > HARD_MAX_UPLOAD_BYTES {
                    return Err(ConfigError::InvalidValue {
                        key: "MAX_UPLOAD_BYTES",
                        reason: format!("muss zwischen 1 und {HARD_MAX_UPLOAD_BYTES} Bytes liegen"),
                    });
                }
                val
            }
            None => DEFAULT_MAX_UPLOAD_BYTES,
        };

        let typst_bin_path = lookup_trimmed(&lookup, "TYPST_BIN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("typst"));
        let typst_font_paths = lookup_trimmed(&lookup, "TYPST_FONT_PATHS").map(PathBuf::from);
        let pdf_template_dir = lookup_trimmed(&lookup, "PDF_TEMPLATE_DIR").map(PathBuf::from);

        let seed_dir = lookup_trimmed(&lookup, "SEED_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./seeds"));
        let default_seed_starter = !is_prod && seed_dir.exists();
        let seed_starter_content =
            parse_bool(&lookup, "SEED_STARTER_CONTENT", default_seed_starter)?;

        let smtp = match lookup_trimmed(&lookup, "SMTP_HOST") {
            Some(host) => {
                let port = match lookup_trimmed(&lookup, "SMTP_PORT") {
                    Some(raw) => raw.parse().map_err(|_| ConfigError::InvalidValue {
                        key: "SMTP_PORT",
                        reason: "ungültige Portnummer".to_string(),
                    })?,
                    None => 587,
                };
                let username = lookup_trimmed(&lookup, "SMTP_USERNAME");
                let password = resolve_secret_optional(&lookup, "SMTP_PASSWORD")?;
                let from = lookup_trimmed(&lookup, "SMTP_FROM")
                    .ok_or(ConfigError::MissingRequired("SMTP_FROM"))?;
                Some(SmtpConfig {
                    host,
                    port,
                    username,
                    password,
                    from,
                })
            }
            None => None,
        };

        let rust_log = lookup_trimmed(&lookup, "RUST_LOG").unwrap_or_else(|| {
            if is_prod {
                "info".to_string()
            } else {
                "debug".to_string()
            }
        });

        Ok(Self {
            app_env,
            bind_addr,
            app_base_url,
            app_timezone,
            database_url,
            migration_database_url,
            session_secret,
            session_ttl_hours,
            cookie_secure,
            trust_proxy,
            init_admin_email,
            init_admin_password,
            oidc,
            storage,
            max_upload_bytes,
            typst_bin_path,
            typst_font_paths,
            pdf_template_dir,
            seed_starter_content,
            seed_dir,
            smtp,
            rust_log,
        })
    }
}

fn lookup_trimmed<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn resolve_secret_optional<F>(lookup: &F, key: &'static str) -> Result<Option<String>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let file_key = format!("{key}_FILE");
    if let Some(path_str) = lookup_trimmed(lookup, &file_key) {
        let path = PathBuf::from(path_str);
        let content = std::fs::read_to_string(&path)
            .map_err(|source| ConfigError::SecretFileRead { key, path, source })?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            return Err(ConfigError::MissingRequired(key));
        }
        return Ok(Some(trimmed));
    }
    Ok(lookup_trimmed(lookup, key))
}

fn resolve_secret_required<F>(lookup: &F, key: &'static str) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    resolve_secret_optional(lookup, key)?.ok_or(ConfigError::MissingRequired(key))
}

fn parse_bool<F>(lookup: &F, key: &'static str, default: bool) -> Result<bool, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup_trimmed(lookup, key) {
        None => Ok(default),
        Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => Ok(false),
        Some(other) => Err(ConfigError::InvalidValue {
            key,
            reason: format!("ungültiger Wahrheitswert '{other}'"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    fn base_prod_env() -> HashMap<&'static str, String> {
        HashMap::from([
            ("APP_BASE_URL", "https://isms.example.com".to_string()),
            (
                "DATABASE_URL",
                "postgres://ins_app:secret@127.0.0.1:5432/ins_isms".to_string(),
            ),
            (
                "SESSION_SECRET",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
        ])
    }

    #[test]
    fn defaults_to_production_and_fails_on_typo() {
        let mut env = base_prod_env();
        env.insert("APP_ENV", "prod".to_string());
        let cfg = Config::from_lookup(|k| env.get(k).cloned()).expect("valid prod config");
        assert!(cfg.is_production());
        assert!(cfg.cookie_secure);
        assert!(cfg.trust_proxy);
    }

    #[test]
    fn production_rejects_insecure_cookie() {
        let mut env = base_prod_env();
        env.insert("COOKIE_SECURE", "false".to_string());
        let err = Config::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(err, ConfigError::InsecureProductionConfig(_)));
    }

    #[test]
    fn development_allows_http_cookies() {
        let mut env = base_prod_env();
        env.insert("APP_ENV", "DeVeLoPmEnT".to_string());
        env.insert("COOKIE_SECURE", "false".to_string());
        let cfg = Config::from_lookup(|k| env.get(k).cloned()).expect("valid dev config");
        assert!(!cfg.is_production());
        assert!(!cfg.cookie_secure);
        assert!(!cfg.trust_proxy);
    }

    #[test]
    fn rejects_short_session_secret() {
        let mut env = base_prod_env();
        env.insert("SESSION_SECRET", "too-short".to_string());
        let err = Config::from_lookup(|k| env.get(k).cloned()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidValue {
                key: "SESSION_SECRET",
                ..
            }
        ));
    }

    #[test]
    fn reads_secret_from_file_suffix() {
        let secret_file = NamedTempFile::new().expect("temp file");
        std::fs::write(
            secret_file.path(),
            "  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  \n",
        )
        .expect("write secret");

        let mut env = base_prod_env();
        env.remove("SESSION_SECRET");
        env.insert(
            "SESSION_SECRET_FILE",
            secret_file.path().to_string_lossy().into_owned(),
        );

        let cfg = Config::from_lookup(|k| env.get(k).cloned()).expect("config with _FILE");
        assert_eq!(cfg.session_secret.len(), 64);
    }
}
