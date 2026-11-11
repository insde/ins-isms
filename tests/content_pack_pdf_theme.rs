use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    auth::{
        password::hash_password,
        rbac::Role,
        session::{create_session, sign_session_id},
    },
    build_router,
    config::{AppEnv, Config, StorageBackendConfig},
    pdf::{PdfDocumentMetadata, PdfRenderer, TypstCliRenderer},
    seed::{seed_from_dir, seed_initial_data},
    state::AppState,
    storage::LocalBlobStorage,
};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

fn base_config(seed_starter_content: bool, pdf_template_dir: Option<PathBuf>) -> Arc<Config> {
    Arc::new(Config {
        app_env: AppEnv::Production,
        bind_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        app_base_url: Url::parse("https://isms.example.com").unwrap(),
        app_timezone: Berlin,
        database_url: "postgres://unused".to_string(),
        migration_database_url: "postgres://unused".to_string(),
        session_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        session_ttl_hours: 12,
        cookie_secure: true,
        trust_proxy: true,
        init_admin_email: Some("admin@example.com".to_string()),
        init_admin_password: Some("AdminStartPasswort123!".to_string()),
        oidc: None,
        storage: StorageBackendConfig::Local {
            path: PathBuf::from("./target/test-blobs-m44"),
        },
        max_upload_bytes: 2 * 1024 * 1024,
        typst_bin_path: PathBuf::from("typst"),
        typst_font_paths: None,
        pdf_template_dir,
        seed_starter_content,
        seed_dir: PathBuf::from("./seeds"),
        smtp: None,
        rust_log: "warn".to_string(),
    })
}

fn test_state(pool: PgPool, config: Arc<Config>) -> AppState {
    AppState {
        pool,
        config,
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from(
            "./target/test-blobs-m44",
        ))),
    }
}

async fn create_user_with_session(
    pool: &PgPool,
    cfg: &Config,
    email: &str,
    role: Role,
) -> (Uuid, String, String) {
    let pw_hash = hash_password("SicheresTestPasswort123!").await.unwrap();
    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, TRUE)
        RETURNING id
        "#,
    )
    .bind(email)
    .bind(format!("User {email}"))
    .bind(pw_hash)
    .bind(role.as_str())
    .fetch_one(pool)
    .await
    .unwrap();

    let (session_id, csrf) = create_session(pool, user_id, None, None, 12).await.unwrap();
    let signed = sign_session_id(&session_id, &cfg.session_secret).unwrap();
    (user_id, format!("ins_session={signed}"), csrf)
}

fn multipart_request(
    uri: &str,
    cookie: &str,
    csrf: &str,
    boundary: &str,
    body: Vec<u8>,
) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
        .header("HX-Request", "true")
        .header(
            header::ORIGIN,
            HeaderValue::from_static("https://isms.example.com"),
        )
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn decoupled_startup_seeds_only_c1_c4_and_loads_example_pack_on_demand(pool: PgPool) {
    let cfg = base_config(false, None);
    seed_initial_data(&pool, &cfg).await.unwrap();

    let levels_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM classification_levels")
        .fetch_one(&pool)
        .await
        .unwrap();
    let frameworks_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM compliance_frameworks")
        .fetch_one(&pool)
        .await
        .unwrap();
    let controls_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM framework_controls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let docs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(levels_count, 4);
    assert_eq!(frameworks_count, 0);
    assert_eq!(controls_count, 0);
    assert_eq!(docs_count, 0);

    seed_from_dir(&pool, Path::new("seeds/example_pack"))
        .await
        .unwrap();
    seed_from_dir(&pool, Path::new("seeds/example_pack"))
        .await
        .unwrap();

    let demo_fw: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM compliance_frameworks WHERE code = 'DEMO_ISMS'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let demo_controls: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM framework_controls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let demo_doc: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM documents WHERE doc_code = 'DEMO-001'")
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(demo_fw, 1);
    assert_eq!(demo_controls, 2);
    assert_eq!(demo_doc, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn policy_import_preserves_approved_versions_and_logs_audit_event(pool: PgPool) {
    let cfg = base_config(false, None);
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-pol@example.com", Role::Iso).await;
    let (_owner_id, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "owner-pol@example.com", Role::Owner).await;

    let boundary = "----InsIsmsPolicyBoundary";
    let md_v1 = "---\ndoc_code: POL-CUSTOM-01\ntitle: Eigene Test-Richtlinie\nclassification_code: C3\n---\n# Eigene Test-Richtlinie\n\n<a id=\"geltung\"></a>\n## 1. Geltung\nErster Stand.\n";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"POL-CUSTOM-01.md\"\r\nContent-Type: text/markdown\r\n\r\n{md_v1}\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );

    let resp_forbidden = app
        .clone()
        .oneshot(multipart_request(
            "/exports/import/policy",
            &owner_cookie,
            &owner_csrf,
            boundary,
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(resp_forbidden.status(), StatusCode::FORBIDDEN);

    let resp_ok = app
        .clone()
        .oneshot(multipart_request(
            "/exports/import/policy",
            &iso_cookie,
            &iso_csrf,
            boundary,
            body,
        ))
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);

    let doc_id: Uuid =
        sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'POL-CUSTOM-01'")
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query(
        "UPDATE document_versions SET status = 'approved', approved_by_id = $2, approved_at = NOW() WHERE document_id = $1 AND version_number = '0.1'",
    )
    .bind(doc_id)
    .bind(iso_id)
    .execute(&pool)
    .await
    .unwrap();

    let md_v2 = "---\ndoc_code: POL-CUSTOM-01\ntitle: Eigene Test-Richtlinie\nclassification_code: C3\n---\n# Eigene Test-Richtlinie\n\n<a id=\"geltung\"></a>\n## 1. Geltung\nAktualisierter Stand.\n";
    let mut body2 = Vec::new();
    body2.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"POL-CUSTOM-01.md\"\r\nContent-Type: text/markdown\r\n\r\n{md_v2}\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );

    let resp_v2 = app
        .clone()
        .oneshot(multipart_request(
            "/exports/import/policy",
            &iso_cookie,
            &iso_csrf,
            boundary,
            body2,
        ))
        .await
        .unwrap();
    assert_eq!(resp_v2.status(), StatusCode::OK);

    let versions = sqlx::query(
        "SELECT version_number, status FROM document_versions WHERE document_id = $1 ORDER BY version_number ASC",
    )
    .bind(doc_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].get::<String, _>("version_number"), "0.1");
    assert_eq!(versions[0].get::<String, _>("status"), "approved");
    assert_eq!(versions[1].get::<String, _>("version_number"), "0.2");
    assert_eq!(versions[1].get::<String, _>("status"), "draft");

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'policy.imported' AND entity_id = $1",
    )
    .bind(doc_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 2);

    let resp_tpl = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/exports/templates/example-catalog.json")
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_tpl.status(), StatusCode::OK);
    let tpl_bytes = to_bytes(resp_tpl.into_body(), 1024 * 1024).await.unwrap();
    let tpl_text = std::str::from_utf8(&tpl_bytes).unwrap();
    assert!(tpl_text.contains("DEMO_ISMS"));
}

#[sqlx::test(migrations = "./migrations")]
async fn external_pdf_theme_override_renders_valid_pdf_and_catches_syntax_errors(pool: PgPool) {
    let temp_theme_dir = tempfile::TempDir::new().unwrap();
    let custom_theme_path = temp_theme_dir.path().join("theme.typ");

    let custom_theme = r#"
#let isms_document(
  org: "",
  code: "",
  title: "",
  version: "",
  status: "",
  classification: "",
  owner: "",
  approved_by: "",
  approved_at: "",
  next_review: "",
  logo_path: none,
  body,
) = {
  set page(paper: "a4")
  text(size: 16pt, weight: "bold")[CUSTOM THEME #title]
  v(1em)
  body
}
"#;
    std::fs::write(&custom_theme_path, custom_theme).unwrap();

    let cfg = base_config(false, Some(temp_theme_dir.path().to_path_buf()));
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_iso_id, iso_cookie, _iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-pdf@example.com", Role::Iso).await;

    let resp_theme = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/organization/pdf-theme.typ")
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_theme.status(), StatusCode::OK);
    let theme_bytes = to_bytes(resp_theme.into_body(), 1024 * 1024).await.unwrap();
    let theme_str = std::str::from_utf8(&theme_bytes).unwrap();
    assert!(theme_str.contains("CUSTOM THEME"));

    let renderer = TypstCliRenderer::from_config(&cfg);
    let meta = PdfDocumentMetadata {
        organization_name: "Muster GmbH".to_string(),
        doc_code: "POL-TEST".to_string(),
        title: "Testdokument".to_string(),
        version: "1.0".to_string(),
        status: "Freigegeben".to_string(),
        classification: "C2".to_string(),
        owner_unit: "IT".to_string(),
        approved_by: "GF".to_string(),
        approved_at: "2026-11-21".to_string(),
        next_review_at: "2027-11-21".to_string(),
    };
    let pdf_bytes = renderer
        .render_markdown_document(&meta, "## Abschnitt\n\nInhaltstext.")
        .await
        .unwrap();
    assert!(pdf_bytes.starts_with(b"%PDF-"));

    std::fs::write(&custom_theme_path, "#let kaputt( = {").unwrap();
    let err = renderer
        .render_markdown_document(&meta, "## Abschnitt\n\nInhaltstext.")
        .await
        .unwrap_err();
    assert!(matches!(err, ins_isms::error::AppError::Validation(_)));
}
