use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    audit::AuditService,
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
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;
use zip::ZipArchive;

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
            path: PathBuf::from("./target/test-blobs-exports-pkg"),
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
            "./target/test-blobs-exports-pkg",
        ))),
    }
}

async fn create_user_with_session(
    pool: &PgPool,
    cfg: &Config,
    email: &str,
    role: Role,
) -> (Uuid, String) {
    let pw_hash = hash_password("SicheresTestPasswort123!").await.unwrap();
    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, organization_unit_id, is_active)
        VALUES ($1, $2, $3, $4, NULL, TRUE)
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

    let (session_id, _csrf) = create_session(pool, user_id, None, None, 12).await.unwrap();
    let signed = sign_session_id(&session_id, &cfg.session_secret).unwrap();
    (user_id, format!("ins_session={signed}"))
}

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

fn create_export_seed_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let policies = dir.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();

    let catalog = r#"{
      "framework": {
        "code": "DEMO_ISMS",
        "name": "Beispiel-Regelwerk",
        "version": "1.0"
      },
      "controls": [
        {
          "code": "DEMO-01",
          "domain": "Governance",
          "sort_order": 1,
          "title": "Beispiel-Control 1",
          "description": "Beschreibung fuer Beispiel-Control 1."
        },
        {
          "code": "DEMO-02",
          "domain": "Technik",
          "sort_order": 2,
          "title": "Beispiel-Control 2",
          "description": "Beschreibung fuer Beispiel-Control 2."
        }
      ],
      "mappings": []
    }"#;
    std::fs::write(dir.path().join("demo.json"), catalog).unwrap();

    std::fs::write(
        policies.join("POL-001_leitlinie.md"),
        "# Leitlinie\n\n<a id=\"zielsetzung\"></a>\n## 1. Zielsetzung\nText.\n",
    )
    .unwrap();
    std::fs::write(
        policies.join("POL-002_zugriff.md"),
        "# Zugriffsrichtlinie\n\n<a id=\"passwort-regeln\"></a>\n## 1. Passwortregeln\nText.\n",
    )
    .unwrap();

    dir
}

#[sqlx::test]
async fn auditor_zip_verifies_manifest_excludes_drafts_and_scrubs_ip_unless_admin(pool: PgPool) {
    let seed_tmp = create_export_seed_dir();
    let mut cfg_val = (*test_config()).clone();
    cfg_val.seed_dir = seed_tmp.path().to_path_buf();
    let cfg = Arc::new(cfg_val);
    let (admin_id, admin_cookie) =
        create_user_with_session(&pool, &cfg, "admin-zip@example.de", Role::Admin).await;
    let (_auditor_id, auditor_cookie) =
        create_user_with_session(&pool, &cfg, "auditor-zip@example.de", Role::Auditor).await;
    seed_initial_data(&pool, &cfg).await.unwrap();
    let state = test_state(pool.clone(), cfg.clone());
    let app = build_router(state.clone());

    sqlx::query(
        r#"
        UPDATE document_versions
        SET status = 'approved', approved_by_id = $1, approved_at = NOW()
        WHERE document_id = (SELECT id FROM documents WHERE doc_code = 'POL-001')
        "#,
    )
    .bind(admin_id)
    .execute(&pool)
    .await
    .unwrap();

    let stored = state
        .storage
        .put(b"Backup-Protokoll 2026 erfolgreich", Some("text/plain"))
        .await
        .unwrap();
    let soa_demo01: Uuid = sqlx::query_scalar(
        r#"
        SELECT se.id
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE fc.code = 'DEMO-01'
        LIMIT 1
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO control_evidences (
            soa_entry_id, title, evidence_type, file_storage_key,
            original_filename, file_sha256, uploaded_by_user_id
        )
        VALUES ($1, 'Backup-Test', 'file', $2, 'backup_nachweis.txt', $3, $4)
        "#,
    )
    .bind(soa_demo01)
    .bind(&stored.storage_key)
    .bind(&stored.sha256_hex)
    .bind(admin_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO management_reviews (
            review_date, period_label, participants, status,
            kpi_snapshot_json, management_decisions, approved_by_user_id, approved_at
        )
        VALUES (
            CURRENT_DATE, '2026-Q4', 'GF, ISB', 'approved',
            '{
              "generated_at": "2026-11-21T00:00:00Z",
              "soa": {"applicable_count": 93, "implemented_count": 50, "implementation_percent": 53.8, "open_gaps_count": 43},
              "risks": {"total_count": 1, "critical_count": 0, "high_count": 0, "medium_count": 1, "low_count": 0, "unaccepted_high_critical": 0},
              "incidents": {"total_count": 0, "nis2_significant_count": 0, "timely_bsi_reports": 0, "overdue_bsi_reports": 0},
              "documents": {"total_documents": 4, "approved_documents": 1, "approved_ratio_percent": 25.0, "overdue_reviews": 0, "acknowledgment_rate_percent": 0.0},
              "audits_and_actions": {"open_major_nc": 0, "open_minor_nc": 0, "open_findings_total": 0, "open_actions": 0, "overdue_actions": 0}
            }'::jsonb,
            'Budget für Backup-Tests freigegeben.',
            $1,
            NOW()
        )
        "#,
    )
    .bind(admin_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO internal_audits (audit_code, title, scope, auditor_name, audit_date, status, summary_report)
        VALUES ('AUD-2026-01', 'Jahresaudit ISMS', 'Gesamt-ISMS', 'Dr. Prüfer', CURRENT_DATE, 'completed', 'Keine Major NCs')
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    AuditService::log_event(
        &pool,
        Some(admin_id),
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
        "test.ip_marker",
        "exports",
        "marker",
        "IP-Testmarker",
        None,
        None,
    )
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(get_req(
            "/exports/auditor-package.zip?include_ip=true",
            &auditor_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/zip"
    );
    let zip_bytes = to_bytes(resp.into_body(), 64 * 1024 * 1024).await.unwrap();

    let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    let mut unpacked: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        unpacked.insert(entry.name().unwrap().into_owned(), buf);
    }

    let manifest_raw = String::from_utf8(unpacked.remove("00_MANIFEST.sha256").unwrap()).unwrap();
    let manifest_lines: Vec<&str> = manifest_raw.lines().collect();
    assert_eq!(manifest_lines.len(), unpacked.len());
    for line in manifest_lines {
        let (expected_hex, rel_path) = line.split_once("  ").unwrap();
        let file_bytes = unpacked.get(rel_path).expect("Datei aus Manifest fehlt");
        let mut hasher = Sha256::new();
        hasher.update(file_bytes);
        let actual_hex = hex::encode(hasher.finalize());
        assert_eq!(actual_hex, expected_hex, "SHA-256 Mismatch für {rel_path}");
    }

    assert!(unpacked["01_SoA/Statement_of_Applicability.pdf"].starts_with(b"%PDF-"));
    assert!(unpacked.contains_key("01_SoA/Statement_of_Applicability.csv"));
    assert!(unpacked["02_Risikomanagement/Risikobehandlungsplan.pdf"].starts_with(b"%PDF-"));
    assert!(unpacked.contains_key("02_Risikomanagement/Risiken.csv"));
    assert!(unpacked.contains_key("03_Richtlinien_Freigegeben/POL-001_v0.1.pdf"));
    assert!(
        !unpacked
            .keys()
            .any(|k| k.starts_with("03_Richtlinien_Freigegeben/POL-002")),
        "Draft-Richtlinie POL-002 darf nicht im Auditor-ZIP enthalten sein!"
    );
    assert_eq!(
        unpacked["04_Nachweise/DEMO-01_backup_nachweis.txt"],
        b"Backup-Protokoll 2026 erfolgreich"
    );
    assert!(
        unpacked["05_Management_Review_und_Audits/Management_Review_2026-Q4.pdf"]
            .starts_with(b"%PDF-")
    );
    assert!(unpacked.contains_key("05_Management_Review_und_Audits/Interne_Audits.csv"));

    let chain_json: Value =
        serde_json::from_slice(&unpacked["06_Audit_Trail/hash_chain_verification.json"]).unwrap();
    assert_eq!(chain_json["status"], "VALID");

    let audit_csv =
        String::from_utf8(unpacked["06_Audit_Trail/audit_logs_extract.csv"].clone()).unwrap();
    assert!(!audit_csv.contains("198.51.100.42"));
    assert!(!audit_csv.contains("IP-Adresse"));

    let admin_resp = app
        .clone()
        .oneshot(get_req(
            "/exports/auditor-package.zip?include_ip=true",
            &admin_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(admin_resp.status(), StatusCode::OK);
    let admin_zip_bytes = to_bytes(admin_resp.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap();
    let mut admin_archive = ZipArchive::new(Cursor::new(admin_zip_bytes)).unwrap();
    let mut admin_csv = String::new();
    admin_archive
        .by_name("06_Audit_Trail/audit_logs_extract.csv")
        .unwrap()
        .read_to_string(&mut admin_csv)
        .unwrap();
    assert!(admin_csv.contains("198.51.100.42"));
    assert!(admin_csv.contains("IP-Adresse"));

    let zip_audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = 'export.auditor_zip'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(zip_audit_count, 2);
}

#[sqlx::test]
async fn audit_compendium_pdf_renders_with_policy_links_and_logs_audit(pool: PgPool) {
    let seed_tmp = create_export_seed_dir();
    let mut cfg_val = (*test_config()).clone();
    cfg_val.seed_dir = seed_tmp.path().to_path_buf();
    let cfg = Arc::new(cfg_val);
    let (admin_id, _) =
        create_user_with_session(&pool, &cfg, "admin-comp@example.de", Role::Admin).await;
    let (_, auditor_cookie) =
        create_user_with_session(&pool, &cfg, "auditor-comp@example.de", Role::Auditor).await;
    seed_initial_data(&pool, &cfg).await.unwrap();
    let state = test_state(pool.clone(), cfg.clone());
    let app = build_router(state);

    let pol2_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'POL-002'")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE document_versions SET status = 'approved', approved_by_id = $1, approved_at = NOW() WHERE document_id = $2",
    )
    .bind(admin_id)
    .bind(pol2_id)
    .execute(&pool)
    .await
    .unwrap();

    let pol1_id: Uuid = sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = 'POL-001'")
        .fetch_one(&pool)
        .await
        .unwrap();

    let soa_demo02: Uuid = sqlx::query_scalar(
        "SELECT se.id FROM soa_entries se JOIN framework_controls fc ON fc.id = se.control_id WHERE fc.code = 'DEMO-02' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO control_evidences (soa_entry_id, title, evidence_type, linked_document_id, section_anchor, section_label, uploaded_by_user_id)
        VALUES ($1, 'Passwort-Vorgabe', 'policy_link', $2, 'passwort-regeln', 'Kap. Passwortregeln', $3)
        "#,
    )
    .bind(soa_demo02)
    .bind(pol2_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .unwrap();

    let soa_demo01: Uuid = sqlx::query_scalar(
        "SELECT se.id FROM soa_entries se JOIN framework_controls fc ON fc.id = se.control_id WHERE fc.code = 'DEMO-01' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO control_evidences (soa_entry_id, title, evidence_type, linked_document_id, section_anchor, section_label, uploaded_by_user_id)
        VALUES ($1, 'Leitlinie Entwurf', 'policy_link', $2, 'zielsetzung', 'Kap. Zielsetzung', $3)
        "#,
    )
    .bind(soa_demo01)
    .bind(pol1_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .unwrap();

    let resp = app
        .oneshot(get_req("/exports/audit-compendium.pdf", &auditor_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/pdf"
    );

    let pdf_bytes = to_bytes(resp.into_body(), 32 * 1024 * 1024).await.unwrap();
    assert!(pdf_bytes.starts_with(b"%PDF-"));

    let logged: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'export.audit_compendium_pdf'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(logged, 1);
}

#[sqlx::test]
async fn full_backup_json_and_export_rbac_enforced(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let state = test_state(pool.clone(), cfg.clone());
    let app = build_router(state);

    let (_, admin_cookie) =
        create_user_with_session(&pool, &cfg, "admin-json@example.de", Role::Admin).await;
    let (_, iso_cookie) =
        create_user_with_session(&pool, &cfg, "iso-json@example.de", Role::Iso).await;
    let (_, auditor_cookie) =
        create_user_with_session(&pool, &cfg, "auditor-json@example.de", Role::Auditor).await;
    let (_, owner_cookie) =
        create_user_with_session(&pool, &cfg, "owner-json@example.de", Role::Owner).await;
    let (_, emp_cookie) =
        create_user_with_session(&pool, &cfg, "emp-json@example.de", Role::Employee).await;

    let resp = app
        .clone()
        .oneshot(get_req("/exports/full-backup.json", &admin_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json; charset=utf-8"
    );
    let body = to_bytes(resp.into_body(), 32 * 1024 * 1024).await.unwrap();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_text.contains("password_hash"));
    assert!(!body_text.contains("\"sessions\""));
    assert!(!body_text.contains("\"login_attempts\""));

    let json: Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(json["schema_version"], "1.0");
    assert!(json["exported_at"].is_string());
    assert!(json["users"].as_array().is_some_and(|a| !a.is_empty()));
    assert!(
        json["soa_entries"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    assert!(json["audit_logs"].as_array().is_some_and(|a| !a.is_empty()));
    assert!(json["users"][0].get("password_hash").is_none());

    let logged: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = 'export.full_json'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(logged, 1);

    for cookie in [&iso_cookie, &auditor_cookie, &owner_cookie, &emp_cookie] {
        let r = app
            .clone()
            .oneshot(get_req("/exports/full-backup.json", cookie))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    for cookie in [&owner_cookie, &emp_cookie] {
        let r_zip = app
            .clone()
            .oneshot(get_req("/exports/auditor-package.zip", cookie))
            .await
            .unwrap();
        assert_eq!(r_zip.status(), StatusCode::FORBIDDEN);

        let r_pdf = app
            .clone()
            .oneshot(get_req("/exports/audit-compendium.pdf", cookie))
            .await
            .unwrap();
        assert_eq!(r_pdf.status(), StatusCode::FORBIDDEN);
    }

    let hub = app
        .oneshot(get_req("/exports", &admin_cookie))
        .await
        .unwrap();
    assert_eq!(hub.status(), StatusCode::OK);
    let hub_html = String::from_utf8(
        to_bytes(hub.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(hub_html.contains("/exports/auditor-package.zip"));
    assert!(hub_html.contains("/exports/audit-compendium.pdf"));
    assert!(hub_html.contains("/exports/full-backup.json"));
}
