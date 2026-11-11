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
            path: PathBuf::from("./target/test-blobs-exports"),
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
            "./target/test-blobs-exports",
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
    if let Some((field_name, filename, content)) = file {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
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

fn extract_hidden_input(html: &str, name: &str) -> String {
    let needle = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&needle)
        .unwrap_or_else(|| panic!("Feld {name} nicht in HTML gefunden: {html}"))
        + needle.len();
    let rest = &html[start..];
    let end = rest.find('"').unwrap();
    rest[..end]
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn catalog_import_supports_json_yaml_mappings_audit_and_preserves_soa_entries(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-cat@example.com", Role::Iso, None).await;

    // 1. JSON-Import mit Mapping auf DEMO_ISMS DEMO-01
    let json_catalog = br#"{
        "framework": {
            "code": "CUSTOM_ITG",
            "name": "KMU-Basis-Regelwerk",
            "version": "2026.1"
        },
        "controls": [
            {
                "code": "KMU-01",
                "domain": "Organisation",
                "title": "Verantwortlichkeiten festlegen",
                "description": "Eindeutige Benennung von System- und Informationsverantwortlichen im Unternehmen.",
                "sort_order": 1
            }
        ],
        "mappings": [
            {
                "source_framework_code": "CUSTOM_ITG",
                "source_control_code": "KMU-01",
                "target_framework_code": "DEMO_ISMS",
                "target_control_code": "DEMO-01",
                "mapping_type": "equivalent"
            }
        ]
    }"#;

    let body = build_multipart_body(
        "----CatJsonBoundary",
        &[],
        Some(("file", "kmu.json", json_catalog)),
    );
    let resp = app
        .clone()
        .oneshot(post_multipart(
            "/exports/import/catalog",
            &iso_cookie,
            &iso_csrf,
            "----CatJsonBoundary",
            body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("CUSTOM_ITG"));
    assert!(html.contains("1 neue Controls"));

    sqlx::query(
        r#"
        UPDATE soa_entries se
        SET is_applicable = FALSE,
            justification = 'Bewusst ausgeschlossen für Test',
            implementation_status = 'implemented'
        FROM framework_controls fc
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.control_id = fc.id
          AND cf.code = 'CUSTOM_ITG'
          AND fc.code = 'KMU-01'
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let yaml_catalog = br#"
framework:
  code: CUSTOM_ITG
  name: KMU-Basis-Regelwerk
  version: "2026.2"
controls:
  - code: KMU-01
    domain: Organisation
    title: Verantwortlichkeiten klar festlegen
    description: Aktualisierte Beschreibung der Sicherheitsverantwortung im KMU-Betrieb.
    sort_order: 1
  - code: KMU-02
    domain: Technik
    title: Sichere Datensicherung
    description: Regelmaessige automatische Backups und Wiederherstellungstests fuer Kernsysteme.
    sort_order: 2
"#;

    let body2 = build_multipart_body(
        "----CatYamlBoundary",
        &[],
        Some(("file", "kmu.yaml", yaml_catalog)),
    );
    let resp2 = app
        .clone()
        .oneshot(post_multipart(
            "/exports/import/catalog",
            &iso_cookie,
            &iso_csrf,
            "----CatYamlBoundary",
            body2,
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let html2 = String::from_utf8(
        to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html2.contains("1 neue Controls, 1 aktualisiert"));

    let soa_row = sqlx::query(
        r#"
        SELECT se.is_applicable, se.justification, se.implementation_status, fc.title
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.code = 'CUSTOM_ITG' AND fc.code = 'KMU-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!soa_row.get::<bool, _>("is_applicable"));
    assert_eq!(
        soa_row.get::<String, _>("justification"),
        "Bewusst ausgeschlossen für Test"
    );
    assert_eq!(
        soa_row.get::<String, _>("implementation_status"),
        "implemented"
    );
    assert_eq!(
        soa_row.get::<String, _>("title"),
        "Verantwortlichkeiten klar festlegen"
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'catalog.imported' AND new_values ->> 'framework_code' = 'CUSTOM_ITG'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 2);

    let view_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM v_soa_export_summary WHERE framework_code = 'CUSTOM_ITG'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(view_count, 2);

    let bad_catalog = br#"{
        "framework": { "code": "BAD_1", "name": "Bad", "version": "1.0" },
        "controls": [
            { "code": "B-1", "domain": "Org", "title": "Test", "description": "TODO", "sort_order": 1 }
        ]
    }"#;
    let bad_body = build_multipart_body(
        "----CatBadBoundary",
        &[],
        Some(("file", "bad.json", bad_catalog)),
    );
    let bad_resp = app
        .oneshot(post_multipart(
            "/exports/import/catalog",
            &iso_cookie,
            &iso_csrf,
            "----CatBadBoundary",
            bad_body,
        ))
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test(migrations = "./migrations")]
async fn csv_two_step_import_validates_bom_semicolon_errors_and_commits_atomically(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    sqlx::query("INSERT INTO organization_units (name) VALUES ('IT-Betrieb')")
        .execute(&pool)
        .await
        .unwrap();

    let (_, admin_cookie, admin_csrf) =
        create_user_with_session(&pool, &cfg, "admin-csv@example.com", Role::Admin, None).await;

    let mut sys_csv = Vec::from("\u{FEFF}".as_bytes());
    sys_csv.extend_from_slice(
        b"asset_code;name;asset_type;vendor_name;hosting_location;criticality;owner_unit_name;description\n\
          SYS-CSV-01;ERP-Produktionsserver;server;Eigenbetrieb;RZ-Frankfurt;high;IT-Betrieb;Zentrales ERP\n\
          FAC-CSV-01;Rechenzentrum Nord;facility;Eigenbetrieb;Hamburg;high;IT-Betrieb;Physischer Standort\n\
          OT-CSV-01;Montageroboter Linie 1;ot_equipment;Hersteller GmbH;Werk 1;high;IT-Betrieb;Produktionsanlage\n\
          OTH-CSV-01;Schliessanlage;other;Sicherheit AG;Werk 1;normal;IT-Betrieb;Sonstiges Asset\n\
          SYS-CSV-02;Fehler-System;ungueltiger_typ;Test;Cloud;normal;IT-Betrieb;Ungueltig\n",
    );

    let prev_body = build_multipart_body(
        "----CsvSysPrev",
        &[("entity_type", "system_assets")],
        Some(("file", "systems.csv", &sys_csv)),
    );
    let prev_resp = app
        .clone()
        .oneshot(post_multipart(
            "/exports/import/csv/preview",
            &admin_cookie,
            &admin_csrf,
            "----CsvSysPrev",
            prev_body,
        ))
        .await
        .unwrap();
    assert_eq!(prev_resp.status(), StatusCode::OK);
    let prev_html = String::from_utf8(
        to_bytes(prev_resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(prev_html.contains("Semikolon (;)"));
    assert!(prev_html.contains("4 gültig, 1 fehlerhaft"));
    assert!(prev_html.contains("Ungültiger asset_type"));
    assert!(prev_html.contains("ot_equipment"));

    let count_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM system_assets WHERE asset_code = 'SYS-CSV-01'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_before, 0);

    let payload_json = extract_hidden_input(&prev_html, "payload_json");
    let payload_hmac = extract_hidden_input(&prev_html, "payload_hmac");
    let commit_body = format!(
        "payload_json={}&payload_hmac={}",
        url_encode(&payload_json),
        url_encode(&payload_hmac)
    );
    let commit_resp = app
        .clone()
        .oneshot(post_form(
            "/exports/import/csv/commit",
            &admin_cookie,
            &admin_csrf,
            commit_body,
        ))
        .await
        .unwrap();
    assert_eq!(commit_resp.status(), StatusCode::OK);

    let count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM system_assets WHERE asset_code = 'SYS-CSV-01'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count_after, 1);

    let info_csv = b"name,classification_code,confidentiality,integrity,availability,owner_unit_name,retention_period,description\n\
                     Kundendatenbank,C3,high,high,normal,IT-Betrieb,10 Jahre,Stammdaten\n";
    let info_prev = build_multipart_body(
        "----CsvInfoPrev",
        &[("entity_type", "information_assets")],
        Some(("file", "info.csv", info_csv)),
    );
    let info_prev_resp = app
        .clone()
        .oneshot(post_multipart(
            "/exports/import/csv/preview",
            &admin_cookie,
            &admin_csrf,
            "----CsvInfoPrev",
            info_prev,
        ))
        .await
        .unwrap();
    assert_eq!(info_prev_resp.status(), StatusCode::OK);
    let info_html = String::from_utf8(
        to_bytes(info_prev_resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let info_commit_body = format!(
        "payload_json={}&payload_hmac={}",
        url_encode(&extract_hidden_input(&info_html, "payload_json")),
        url_encode(&extract_hidden_input(&info_html, "payload_hmac"))
    );
    let info_commit_resp = app
        .clone()
        .oneshot(post_form(
            "/exports/import/csv/commit",
            &admin_cookie,
            &admin_csrf,
            info_commit_body,
        ))
        .await
        .unwrap();
    assert_eq!(info_commit_resp.status(), StatusCode::OK);

    let risk_csv = b"reference_code;title;threat_description;affected_system_code;inherent_likelihood;inherent_impact;treatment_strategy;residual_likelihood;residual_impact\n\
                     RSK-CSV-01;Ausfall ERP;Hardwaredefekt oder Ransomware;SYS-CSV-01;3;5;mitigate;2;4\n";
    let risk_prev = build_multipart_body(
        "----CsvRiskPrev",
        &[("entity_type", "risk_scenarios")],
        Some(("file", "risks.csv", risk_csv)),
    );
    let risk_prev_resp = app
        .clone()
        .oneshot(post_multipart(
            "/exports/import/csv/preview",
            &admin_cookie,
            &admin_csrf,
            "----CsvRiskPrev",
            risk_prev,
        ))
        .await
        .unwrap();
    assert_eq!(risk_prev_resp.status(), StatusCode::OK);
    let risk_html = String::from_utf8(
        to_bytes(risk_prev_resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let risk_commit_body = format!(
        "payload_json={}&payload_hmac={}",
        url_encode(&extract_hidden_input(&risk_html, "payload_json")),
        url_encode(&extract_hidden_input(&risk_html, "payload_hmac"))
    );
    let risk_commit_resp = app
        .oneshot(post_form(
            "/exports/import/csv/commit",
            &admin_cookie,
            &admin_csrf,
            risk_commit_body,
        ))
        .await
        .unwrap();
    assert_eq!(risk_commit_resp.status(), StatusCode::OK);

    let view_sys_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM v_system_asset_effective_protection WHERE asset_code = 'SYS-CSV-01'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(view_sys_count, 1);

    let risk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM risk_scenarios WHERE reference_code = 'RSK-CSV-01'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(risk_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn import_endpoints_enforce_rbac_for_owner_auditor_and_employee(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "owner-exp@example.com", Role::Owner, None).await;
    let (_, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor-exp@example.com", Role::Auditor, None).await;
    let (_, emp_cookie, emp_csrf) =
        create_user_with_session(&pool, &cfg, "emp-exp@example.com", Role::Employee, None).await;

    let auditor_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/exports")
                .header(header::COOKIE, &auditor_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auditor_get.status(), StatusCode::OK);

    for cookie in [&owner_cookie, &emp_cookie] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/exports")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    for (cookie, csrf) in [
        (&owner_cookie, &owner_csrf),
        (&auditor_cookie, &auditor_csrf),
        (&emp_cookie, &emp_csrf),
    ] {
        let cat_body = build_multipart_body("----RbacCat", &[], Some(("file", "c.json", b"{}")));
        let cat_resp = app
            .clone()
            .oneshot(post_multipart(
                "/exports/import/catalog",
                cookie,
                csrf,
                "----RbacCat",
                cat_body,
            ))
            .await
            .unwrap();
        assert_eq!(cat_resp.status(), StatusCode::FORBIDDEN);

        let csv_prev_body = build_multipart_body(
            "----RbacCsv",
            &[("entity_type", "system_assets")],
            Some(("file", "a.csv", b"asset_code,name\n")),
        );
        let csv_prev_resp = app
            .clone()
            .oneshot(post_multipart(
                "/exports/import/csv/preview",
                cookie,
                csrf,
                "----RbacCsv",
                csv_prev_body,
            ))
            .await
            .unwrap();
        assert_eq!(csv_prev_resp.status(), StatusCode::FORBIDDEN);

        let csv_commit_resp = app
            .clone()
            .oneshot(post_form(
                "/exports/import/csv/commit",
                cookie,
                csrf,
                "payload_json=%7B%7D&payload_hmac=deadbeef".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(csv_commit_resp.status(), StatusCode::FORBIDDEN);
    }
}
