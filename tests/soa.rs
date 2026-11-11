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
    seed::seed_initial_data,
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
        init_admin_email: None,
        init_admin_password: None,
        oidc: None,
        storage: StorageBackendConfig::Local {
            path: PathBuf::from("./target/test-blobs-soa"),
        },
        max_upload_bytes: 2 * 1024 * 1024,
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
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from(
            "./target/test-blobs-soa",
        ))),
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

fn build_multipart_body(
    boundary: &str,
    fields: &[(&str, &str)],
    file: Option<(&str, &str, &[u8])>,
) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    if let Some((field_name, filename, bytes)) = file {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/pdf\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn post_multipart(
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
            HeaderValue::from_static("http://localhost:8080"),
        )
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

fn create_soa_seed_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let fw_a = r#"{
      "framework": {
        "code": "TEST_ISO",
        "name": "Test-Regelwerk A",
        "version": "1.0"
      },
      "controls": [
        {
          "code": "T-01",
          "domain": "Organisation",
          "sort_order": 1,
          "title": "Test-Control 1",
          "description": "Beschreibung fuer Test-Control 1."
        },
        {
          "code": "T-02",
          "domain": "Technik",
          "sort_order": 2,
          "title": "Test-Control 2",
          "description": "Beschreibung fuer Test-Control 2."
        }
      ],
      "mappings": [
        {
          "source_control_code": "T-01",
          "target_framework_code": "TEST_NIS2",
          "target_control_code": "N-01",
          "mapping_type": "equivalent"
        }
      ]
    }"#;
    let fw_b = r#"{
      "framework": {
        "code": "TEST_NIS2",
        "name": "Test-Regelwerk B",
        "version": "1.0"
      },
      "controls": [
        {
          "code": "N-01",
          "domain": "Governance",
          "sort_order": 1,
          "title": "Test-Anforderung B1",
          "description": "Beschreibung fuer Test-Anforderung B1."
        }
      ],
      "mappings": []
    }"#;
    std::fs::write(dir.path().join("01_test_iso.json"), fw_a).unwrap();
    std::fs::write(dir.path().join("02_test_nis2.json"), fw_b).unwrap();
    dir
}

#[sqlx::test(migrations = "./migrations")]
async fn repeatable_soa_catalog_seeding_preserves_existing_assessments(pool: PgPool) {
    let seed_tmp = create_soa_seed_dir();
    let mut cfg_val = (*test_config()).clone();
    cfg_val.seed_dir = seed_tmp.path().to_path_buf();
    let cfg = Arc::new(cfg_val);
    seed_initial_data(&pool, &cfg).await.unwrap();

    let iso_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM framework_controls fc
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.code = 'TEST_ISO'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(iso_count, 2);

    let nis2_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM framework_controls fc
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.code = 'TEST_NIS2'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(nis2_count, 1);

    let mapping_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_mappings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(mapping_count, 1);

    // Bestehende Bewertung auf T-01 anpassen
    let soa_t01: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'T-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE soa_entries SET implementation_status = 'verified', justification = 'Leitlinie freigegeben' WHERE id = $1",
    )
    .bind(soa_t01)
    .execute(&pool)
    .await
    .unwrap();

    // Re-Seeding darf bestehende Bewertung nicht überschreiben
    seed_initial_data(&pool, &cfg).await.unwrap();

    let row =
        sqlx::query("SELECT implementation_status, justification FROM soa_entries WHERE id = $1")
            .bind(soa_t01)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.get::<&str, _>("implementation_status"), "verified");
    assert_eq!(row.get::<&str, _>("justification"), "Leitlinie freigegeben");
}

#[sqlx::test(migrations = "./migrations")]
async fn exclusion_justification_guard_rejects_empty_and_accepts_reason(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-soa@example.de", Role::Iso, None).await;

    let soa_id: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'DEMO-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let res_err = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_id}/toggle-applicability"),
            &iso_cookie,
            &iso_csrf,
            "is_applicable=false&justification=%20%20".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(res_err.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let res_ok = app
        .oneshot(post_form(
            &format!("/soa/{soa_id}/toggle-applicability"),
            &iso_cookie,
            &iso_csrf,
            "is_applicable=false&justification=Vollst%C3%A4ndig+in+ISO-zertifiziertem+Rechenzentrum"
                .to_string(),
        ))
        .await
        .unwrap();
    assert!(
        res_ok.status().is_success() || res_ok.status() == StatusCode::SEE_OTHER,
        "Unerwarteter Status: {}",
        res_ok.status()
    );

    let is_applicable: bool =
        sqlx::query_scalar("SELECT is_applicable FROM soa_entries WHERE id = $1")
            .bind(soa_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!is_applicable);
}

#[sqlx::test(migrations = "./migrations")]
async fn verification_guard_and_rbac_scoping_for_owner_and_auditor(pool: PgPool) {
    let seed_tmp = create_soa_seed_dir();
    let mut cfg_val = (*test_config()).clone();
    cfg_val.seed_dir = seed_tmp.path().to_path_buf();
    let cfg = Arc::new(cfg_val);
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let unit_a: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('IT-Betrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unit_b: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Personalwesen') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let (_, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "owner-a@example.de", Role::Owner, Some(unit_a))
            .await;
    let (_, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor@example.de", Role::Auditor, None).await;
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-rbac@example.de", Role::Iso, None).await;

    let soa_a: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'T-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let soa_b: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'T-02'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query("UPDATE soa_entries SET owner_unit_id = $1 WHERE id = $2")
        .bind(unit_a)
        .bind(soa_a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE soa_entries SET owner_unit_id = $1 WHERE id = $2")
        .bind(unit_b)
        .bind(soa_b)
        .execute(&pool)
        .await
        .unwrap();

    // Owner darf eigenen Eintrag nicht auf 'verified' setzen -> 403
    let res_verify_owner = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_a}"),
            &owner_cookie,
            &owner_csrf,
            "is_applicable=true&implementation_status=verified".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(res_verify_owner.status(), StatusCode::FORBIDDEN);

    // Owner darf fremde Unit nicht bearbeiten -> 403
    let res_foreign = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_b}/cycle-status"),
            &owner_cookie,
            &owner_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res_foreign.status(), StatusCode::FORBIDDEN);

    // Owner darf eigenen Eintrag auf 'implemented' setzen -> OK
    let res_own = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_a}"),
            &owner_cookie,
            &owner_csrf,
            "is_applicable=true&implementation_status=implemented".to_string(),
        ))
        .await
        .unwrap();
    assert!(res_own.status().is_success() || res_own.status() == StatusCode::SEE_OTHER);

    let res_iso = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_a}"),
            &iso_cookie,
            &iso_csrf,
            "is_applicable=true&implementation_status=verified".to_string(),
        ))
        .await
        .unwrap();
    assert!(res_iso.status().is_success() || res_iso.status() == StatusCode::SEE_OTHER);

    let res_auditor_post = app
        .clone()
        .oneshot(post_form(
            &format!("/soa/{soa_a}/cycle-status"),
            &auditor_cookie,
            &auditor_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res_auditor_post.status(), StatusCode::FORBIDDEN);

    let res_auditor_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/soa?framework=TEST_NIS2")
                .header(header::COOKIE, &auditor_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_auditor_get.status(), StatusCode::OK);

    let res_csv = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/soa/export.csv?framework=TEST_ISO")
                .header(header::COOKIE, &auditor_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_csv.status(), StatusCode::OK);
    let csv_bytes = to_bytes(res_csv.into_body(), 1024 * 1024).await.unwrap();
    let csv_text = String::from_utf8_lossy(&csv_bytes);
    assert!(csv_text.contains("T-01;"));
}

#[sqlx::test(migrations = "./migrations")]
async fn all_four_evidence_types_deep_links_and_audit_logs(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-ev@example.de", Role::Iso, None).await;
    let (_, auditor_cookie, _) =
        create_user_with_session(&pool, &cfg, "auditor-ev@example.de", Role::Auditor, None).await;
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let soa_id: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'DEMO-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let demo_001_id: Uuid =
        sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'DEMO-001'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let b1 = "----BOUNDARY1";
    let body_file = build_multipart_body(
        b1,
        &[
            ("title", "Clean-Desk Begehungsprotokoll"),
            ("evidence_type", "file"),
        ],
        Some(("file", "begehung.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n")),
    );
    let r1 = app
        .clone()
        .oneshot(post_multipart(
            &format!("/soa/{soa_id}/evidences"),
            &iso_cookie,
            &iso_csrf,
            b1,
            body_file,
        ))
        .await
        .unwrap();
    assert!(r1.status().is_success() || r1.status() == StatusCode::SEE_OTHER);

    let b2 = "----BOUNDARY2";
    let body_pol = build_multipart_body(
        b2,
        &[
            ("title", "Richtlinie Clean-Desk"),
            ("evidence_type", "policy_link"),
            ("linked_document_id", &demo_001_id.to_string()),
            ("section_anchor", "geltungsbereich"),
            ("section_label", "Kap. 1: Geltungsbereich"),
        ],
        None,
    );
    let r2 = app
        .clone()
        .oneshot(post_multipart(
            &format!("/soa/{soa_id}/evidences"),
            &iso_cookie,
            &iso_csrf,
            b2,
            body_pol,
        ))
        .await
        .unwrap();
    assert!(r2.status().is_success() || r2.status() == StatusCode::SEE_OTHER);

    let b3_bad = "----BOUNDARY3B";
    let body_url_bad = build_multipart_body(
        b3_bad,
        &[
            ("title", "XSS Link"),
            ("evidence_type", "external_url"),
            ("evidence_url", "javascript:alert(1)"),
        ],
        None,
    );
    let r3_bad = app
        .clone()
        .oneshot(post_multipart(
            &format!("/soa/{soa_id}/evidences"),
            &iso_cookie,
            &iso_csrf,
            b3_bad,
            body_url_bad,
        ))
        .await
        .unwrap();
    assert_eq!(r3_bad.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let b3 = "----BOUNDARY3";
    let body_url = build_multipart_body(
        b3,
        &[
            ("title", "MDM Bildschirmsperre-Profil"),
            ("evidence_type", "external_url"),
            (
                "evidence_url",
                "https://mdm.example.com/profiles/screenlock",
            ),
        ],
        None,
    );
    let r3 = app
        .clone()
        .oneshot(post_multipart(
            &format!("/soa/{soa_id}/evidences"),
            &iso_cookie,
            &iso_csrf,
            b3,
            body_url,
        ))
        .await
        .unwrap();
    assert!(r3.status().is_success() || r3.status() == StatusCode::SEE_OTHER);

    let b4 = "----BOUNDARY4";
    let body_note = build_multipart_body(
        b4,
        &[
            ("title", "Stichprobe Büroetage"),
            ("evidence_type", "note"),
            (
                "evidence_note",
                "Alle 12 Arbeitsplätze am 18.11. geprüft; keine offenen Unterlagen.",
            ),
        ],
        None,
    );
    let r4 = app
        .clone()
        .oneshot(post_multipart(
            &format!("/soa/{soa_id}/evidences"),
            &iso_cookie,
            &iso_csrf,
            b4,
            body_note,
        ))
        .await
        .unwrap();
    assert!(r4.status().is_success() || r4.status() == StatusCode::SEE_OTHER);

    let drawer_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/soa/{soa_id}/drawer"))
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(drawer_res.status(), StatusCode::OK);
    let drawer_html = String::from_utf8(
        to_bytes(drawer_res.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(drawer_html.contains(&format!("/documents/{demo_001_id}#geltungsbereich")));
    assert!(drawer_html.contains("Verknüpfte Richtlinie noch nicht freigegeben"));

    let file_ev_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM control_evidences WHERE soa_entry_id = $1 AND evidence_type = 'file' LIMIT 1",
    )
    .bind(soa_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let dl_res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/soa/{soa_id}/evidences/{file_ev_id}/download"))
                .header(header::COOKIE, &auditor_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dl_res.status(), StatusCode::OK);
    assert_eq!(
        dl_res
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'control_evidences' AND action = 'control_evidences.created'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 4);
}
