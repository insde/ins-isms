use std::{net::SocketAddr, path::PathBuf, sync::Arc};

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
    seed::{seed_initial_data, verify_policy_anchors_in_dir},
    state::AppState,
    storage::LocalBlobStorage,
};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

fn test_config() -> Arc<Config> {
    Arc::new(Config {
        app_env: AppEnv::Development,
        bind_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        app_base_url: Url::parse("http://localhost:8080").unwrap(),
        app_timezone: Berlin,
        database_url: "postgres://unused".to_string(),
        migration_database_url: "postgres://unused".to_string(),
        session_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        session_ttl_hours: 12,
        cookie_secure: false,
        trust_proxy: false,
        init_admin_email: Some("admin@example.com".to_string()),
        init_admin_password: Some("AdminStartPasswort123!".to_string()),
        oidc: None,
        storage: StorageBackendConfig::Local {
            path: PathBuf::from("./target/test-blobs"),
        },
        max_upload_bytes: 1024 * 1024,
        typst_bin_path: PathBuf::from("typst"),
        typst_font_paths: None,
        pdf_template_dir: None,
        seed_starter_content: true,
        seed_dir: PathBuf::from("seeds/example_pack"),
        smtp: None,
        rust_log: "warn".to_string(),
    })
}

fn test_state(pool: PgPool, config: Arc<Config>) -> AppState {
    AppState {
        pool,
        config,
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from("./target/test-blobs"))),
    }
}

async fn create_user_with_session(
    pool: &PgPool,
    cfg: &Config,
    email: &str,
    role: Role,
    unit_id: Option<Uuid>,
) -> (Uuid, String, String) {
    let pw_hash = hash_password("SicheresTestPasswort123!").await.unwrap();
    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, organization_unit_id, is_active)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        RETURNING id
        "#,
    )
    .bind(email)
    .bind(format!("User {email}"))
    .bind(pw_hash)
    .bind(role.as_str())
    .bind(unit_id)
    .fetch_one(pool)
    .await
    .unwrap();

    let (session_id, csrf) = create_session(pool, user_id, None, None, 12).await.unwrap();
    let signed = sign_session_id(&session_id, &cfg.session_secret).unwrap();
    (user_id, format!("ins_session={signed}"), csrf)
}

fn post_form(uri: &str, cookie: &str, csrf: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
        .header("HX-Request", "true")
        .header(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:8080"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn create_policy_seed_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let policies = dir.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();

    let fixtures = [
        (
            "POL-001_leitlinie.md",
            "# Informationssicherheitsleitlinie\n\n\
             <a id=\"zielsetzung\"></a>\n## 1. Zielsetzung\nText.\n\n\
             <a id=\"schutzziele\"></a>\n## 2. Schutzziele\nText.\n\n\
             <a id=\"verantwortung-geschaeftsfuehrung\"></a>\n## 3. Verantwortung\nText.\n\n\
             <a id=\"organisation-rollen\"></a>\n## 4. Rollen\nText.\n\n\
             <a id=\"risikomanagement-pdca\"></a>\n## 5. PDCA\nText.\n",
        ),
        (
            "POL-002_zugriff.md",
            "# Zugriffs- und Passwortrichtlinie\n\n\
             <a id=\"passwort-regeln\"></a>\n## 1. Passwortregeln\nText.\n\n\
             <a id=\"mfa-pflicht\"></a>\n## 2. MFA\nText.\n\n\
             <a id=\"zugriffsrechte\"></a>\n## 3. Zugriffsrechte\nText.\n\n\
             <a id=\"admin-konten\"></a>\n## 4. Admin-Konten\nText.\n",
        ),
        (
            "POL-003_endgeraete.md",
            "# Endgeraete- und Homeoffice-Richtlinie\n\n\
             <a id=\"homeoffice\"></a>\n## 1. Homeoffice\nText.\n\n\
             <a id=\"endgeraete-sicherheit\"></a>\n## 2. Endgeraete\nText.\n\n\
             <a id=\"clean-desk\"></a>\n## 3. Clean Desk\nText.\n\n\
             <a id=\"datentraeger-transport\"></a>\n## 4. Transport\nText.\n",
        ),
        (
            "POL-004_vorfaelle.md",
            "# Richtlinie Sicherheitsvorfaelle\n\n\
             <a id=\"meldepflicht\"></a>\n## 1. Meldepflicht\nText.\n\n\
             <a id=\"meldewege\"></a>\n## 2. Meldewege\nText.\n\n\
             <a id=\"nis2-fristen\"></a>\n## 3. NIS2-Fristen\nText.\n\n\
             <a id=\"nachbereitung\"></a>\n## 4. Nachbereitung\nText.\n",
        ),
    ];

    for (name, content) in fixtures {
        std::fs::write(policies.join(name), content).unwrap();
    }

    dir
}

#[sqlx::test(migrations = "./migrations")]
async fn repeatable_starter_policy_seeding_with_verified_anchors(pool: PgPool) {
    let seed_tmp = create_policy_seed_dir();
    verify_policy_anchors_in_dir(seed_tmp.path()).unwrap();

    let mut cfg_val = (*test_config()).clone();
    cfg_val.seed_dir = seed_tmp.path().to_path_buf();
    let cfg = Arc::new(cfg_val);
    seed_initial_data(&pool, &cfg).await.unwrap();
    seed_initial_data(&pool, &cfg).await.unwrap();

    let doc_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(doc_count, 4);

    let rows = sqlx::query(
        r#"
        SELECT d.doc_code, dv.version_number, dv.status, dv.content_markdown
        FROM documents d
        JOIN document_versions dv ON dv.document_id = d.id
        ORDER BY d.doc_code ASC
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 4);
    for r in rows {
        assert_eq!(r.get::<String, _>("version_number"), "0.1");
        assert_eq!(r.get::<String, _>("status"), "draft");
        let md: String = r.get("content_markdown");
        assert!(md.contains(r#"<a id=""#));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn atomic_approval_archives_previous_approved_and_sets_review_due(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-doc@example.com", Role::Iso, None).await;

    let doc_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'DEMO-001'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let v1_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM document_versions WHERE document_id = $1 AND version_number = '0.1'",
    )
    .bind(doc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{v1_id}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let next_review: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT next_review_due_at FROM documents WHERE id = $1")
            .bind(doc_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(next_review.is_some());

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions"),
            &iso_cookie,
            &iso_csrf,
            "version_number=1.0&change_summary=Erste+Vollversion".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v2_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM document_versions WHERE document_id = $1 AND version_number = '1.0'",
    )
    .bind(doc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{v2_id}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v1_status: String =
        sqlx::query_scalar("SELECT status FROM document_versions WHERE id = $1")
            .bind(v1_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let v2_status: String =
        sqlx::query_scalar("SELECT status FROM document_versions WHERE id = $1")
            .bind(v2_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(v1_status, "archived");
    assert_eq!(v2_status, "approved");

    let approved_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'document_versions.approved' AND entity_id = $1",
    )
    .bind(v2_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approved_audit, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn immutability_blocks_editing_approved_or_archived_versions_with_409(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-immut@example.com", Role::Iso, None).await;

    let doc_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'DEMO-001'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let vid: Uuid = sqlx::query_scalar(
        "SELECT id FROM document_versions WHERE document_id = $1 AND version_number = '0.1'",
    )
    .bind(doc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{vid}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{vid}"),
            &iso_cookie,
            &iso_csrf,
            "content_markdown=Manipulierter+Inhalt".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/documents/{doc_id}/versions/{vid}/edit"))
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn visibility_guards_block_drafts_for_auditor_and_employee_and_approve_for_owner(
    pool: PgPool,
) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_aud_id, aud_cookie, _) =
        create_user_with_session(&pool, &cfg, "auditor-doc@example.com", Role::Auditor, None).await;
    let (_emp_id, emp_cookie, _) =
        create_user_with_session(&pool, &cfg, "emp-doc@example.com", Role::Employee, None).await;
    let (_own_id, own_cookie, own_csrf) =
        create_user_with_session(&pool, &cfg, "owner-doc@example.com", Role::Owner, None).await;

    let doc_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'DEMO-001'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let vid: Uuid = sqlx::query_scalar(
        "SELECT id FROM document_versions WHERE document_id = $1 AND version_number = '0.1'",
    )
    .bind(doc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    for cookie in [&aud_cookie, &emp_cookie] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/documents")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(!html.contains("DEMO-001"));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/documents/{doc_id}"))
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/documents/{doc_id}?version={vid}"))
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{vid}/approve"),
            &own_cookie,
            &own_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn acknowledgment_audit_log_and_url_scheme_validation_work(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-ack@example.com", Role::Iso, None).await;
    let (emp_id, emp_cookie, emp_csrf) =
        create_user_with_session(&pool, &cfg, "emp-ack@example.com", Role::Employee, None).await;

    let level_id: Uuid =
        sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C2'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            "/documents",
            &iso_cookie,
            &iso_csrf,
            format!(
                "doc_code=RUN-999&title=Test&doc_type=runbook&source_type=external_link&classification_level_id={level_id}&external_url=javascript%3Aalert(1)"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 2. DEMO-001 freigeben und durch Employee bestätigen lassen
    let doc_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'DEMO-001'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let vid: Uuid = sqlx::query_scalar(
        "SELECT id FROM document_versions WHERE document_id = $1 AND version_number = '0.1'",
    )
    .bind(doc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/versions/{vid}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/documents/{doc_id}/acknowledge"),
            &emp_cookie,
            &emp_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ack_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM document_acknowledgments WHERE document_version_id = $1 AND user_id = $2)",
    )
    .bind(vid)
    .bind(emp_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(ack_exists);

    let ack_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'document.acknowledged' AND entity_id = $1",
    )
    .bind(vid.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ack_audit, 1);
}
