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
            path: PathBuf::from("./target/test-blobs-audits"),
        },
        max_upload_bytes: 2 * 1024 * 1024,
        typst_bin_path: PathBuf::from("typst"),
        typst_font_paths: None,
        pdf_template_dir: None,
        seed_starter_content: true,
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
            "./target/test-blobs-audits",
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

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn audits_and_findings_with_pdf_report_upload_and_audit_logs(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-audit@example.de", Role::Iso, None).await;

    let resp = app
        .clone()
        .oneshot(post_form(
            "/audits",
            &iso_cookie,
            &iso_csrf,
            "audit_code=AUD-2026-01&title=Jahresaudit+2026&scope=ISO+27001+Gesamt&auditor_name=Dr.+Pruefer&audit_date=2026-11-15&status=in_progress".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let audit_id: Uuid =
        sqlx::query_scalar("SELECT id FROM internal_audits WHERE audit_code = 'AUD-2026-01'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/audits/{audit_id}/findings"),
            &iso_cookie,
            &iso_csrf,
            "finding_code=FND-01&finding_type=major_nc&description=Fehlende+MFA+bei+Admin-Konten"
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let finding_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_findings WHERE audit_id = $1 AND finding_code = 'FND-01'",
    )
    .bind(audit_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let boundary = "----insismsauditboundary";
    let mut mp_body = Vec::new();
    mp_body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"report_file\"; filename=\"auditbericht.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    mp_body.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n");
    mp_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let upload_req = Request::builder()
        .method(Method::POST)
        .uri(format!("/audits/{audit_id}/report"))
        .header(header::COOKIE, &iso_cookie)
        .header("X-CSRF-Token", &iso_csrf)
        .header("HX-Request", "true")
        .header(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:8080"),
        )
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(mp_body))
        .unwrap();
    let resp = app.clone().oneshot(upload_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let sha: Option<String> =
        sqlx::query_scalar("SELECT attached_report_sha256 FROM internal_audits WHERE id = $1")
            .bind(audit_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sha.as_deref().map(str::len), Some(64));

    // Bericht herunterladen & Headers prüfen
    let resp = app
        .clone()
        .oneshot(get_req(&format!("/audits/{audit_id}/report"), &iso_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    let disp = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(disp.starts_with("attachment;"));

    // Finding ohne verknüpfte Maßnahme direkt durch ISB schließen
    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/audits/findings/{finding_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=verified_closed".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_logs WHERE entity_type IN ('internal_audits', 'audit_findings') ORDER BY id ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(actions.iter().any(|a| a == "internal_audits.created"));
    assert!(actions.iter().any(|a| a == "audit_findings.created"));
    assert!(
        actions
            .iter()
            .any(|a| a == "internal_audit.report_downloaded")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn management_review_kpi_aggregation_and_freeze_on_approve(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-mr@example.de", Role::Iso, None).await;

    // Beispieldaten für KPI-Aggregation anlegen (1 Risiko + 1 Audit-Finding)
    sqlx::query(
        r#"
        INSERT INTO risk_scenarios (
            reference_code, title, threat_description, vulnerability_description,
            inherent_likelihood, inherent_impact, treatment_strategy,
            residual_likelihood, residual_impact, status
        )
        VALUES ('RSK-MR-1', 'Ransomware', 'Verschluesselung', 'Fehlendes Backup', 4, 5, 'mitigate', 4, 4, 'treating')
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let audit_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO internal_audits (audit_code, title, scope, auditor_name, audit_date, status)
        VALUES ('AUD-MR-1', 'Audit 1', 'Gesamt', 'Auditor', '2026-11-01', 'completed')
        RETURNING id
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO audit_findings (audit_id, finding_code, finding_type, description, status)
        VALUES ($1, 'FND-01', 'major_nc', 'Offene Hauptabweichung', 'open')
        "#,
    )
    .bind(audit_id)
    .execute(&pool)
    .await
    .unwrap();

    // Management-Review anlegen
    let resp = app
        .clone()
        .oneshot(post_form(
            "/management-reviews",
            &iso_cookie,
            &iso_csrf,
            "review_date=2026-11-20&period_label=GJ+2026&participants=GF%2C+ISB&management_decisions=Budget+freigegeben"
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let review_row = sqlx::query(
        "SELECT id, status, kpi_snapshot_json FROM management_reviews WHERE period_label = 'GJ 2026'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let review_id: Uuid = review_row.get("id");
    assert_eq!(review_row.get::<String, _>("status"), "draft");
    let kpi: serde_json::Value = review_row.get("kpi_snapshot_json");
    assert_eq!(kpi["risks"]["critical_count"], 1);
    assert_eq!(kpi["risks"]["unaccepted_high_critical"], 1);
    assert_eq!(kpi["audits_and_actions"]["open_major_nc"], 1);

    // Freigabe friert Snapshot ein
    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/management-reviews/{review_id}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let approved_row = sqlx::query(
        "SELECT status, approved_by_user_id, approved_at FROM management_reviews WHERE id = $1",
    )
    .bind(review_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approved_row.get::<String, _>("status"), "approved");
    assert!(
        approved_row
            .get::<Option<Uuid>, _>("approved_by_user_id")
            .is_some()
    );
    assert!(
        approved_row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("approved_at")
            .is_some()
    );

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/management-reviews/{review_id}"),
            &iso_cookie,
            &iso_csrf,
            "review_date=2026-11-20&period_label=GJ+2026&participants=GF&management_decisions=Manipuliert"
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/management-reviews/{review_id}/refresh-kpis"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/management-reviews/{review_id}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn management_review_pdf_export_respects_rbac_and_typst(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-pdf@example.de", Role::Iso, None).await;
    let (_, auditor_cookie, _) =
        create_user_with_session(&pool, &cfg, "auditor-pdf@example.de", Role::Auditor, None).await;

    let resp = app
        .clone()
        .oneshot(post_form(
            "/management-reviews",
            &iso_cookie,
            &iso_csrf,
            "review_date=2026-11-20&period_label=GJ+2026+PDF&participants=GF%2C+ISB&management_decisions=Freigabe"
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let review_id: Uuid =
        sqlx::query_scalar("SELECT id FROM management_reviews WHERE period_label = 'GJ 2026 PDF'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = app
        .clone()
        .oneshot(get_req(
            &format!("/management-reviews/{review_id}/export.pdf"),
            &auditor_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/management-reviews/{review_id}/approve"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(get_req(
            &format!("/management-reviews/{review_id}/export.pdf"),
            &auditor_cookie,
        ))
        .await
        .unwrap();

    let typst_available = std::process::Command::new("typst")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if typst_available {
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 2 * 1024 * 1024).await.unwrap();
        assert!(bytes.starts_with(b"%PDF-"));
    } else {
        assert!(matches!(
            resp.status(),
            StatusCode::OK | StatusCode::INTERNAL_SERVER_ERROR
        ));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn audits_and_reviews_rbac_enforcement(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let unit_a: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('IT-Betrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unit_b: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Vertrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let (_, owner_cookie, owner_csrf) = create_user_with_session(
        &pool,
        &cfg,
        "owner-aud@example.de",
        Role::Owner,
        Some(unit_a),
    )
    .await;
    let (_, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor-rbac@example.de", Role::Auditor, None).await;
    let (_, emp_cookie, _) = create_user_with_session(
        &pool,
        &cfg,
        "emp-rbac@example.de",
        Role::Employee,
        Some(unit_a),
    )
    .await;

    let audit_own: Uuid = sqlx::query_scalar(
        "INSERT INTO internal_audits (audit_code, title, scope, auditor_name, audit_date, status) VALUES ('AUD-OWN', 'Audit IT', 'IT', 'Pruefer', '2026-11-10', 'completed') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO audit_findings (audit_id, finding_code, finding_type, owner_unit_id, description, status) VALUES ($1, 'FND-01', 'minor_nc', $2, 'IT-Finding', 'open')",
    )
    .bind(audit_own)
    .bind(unit_a)
    .execute(&pool)
    .await
    .unwrap();

    let audit_foreign: Uuid = sqlx::query_scalar(
        "INSERT INTO internal_audits (audit_code, title, scope, auditor_name, audit_date, status) VALUES ('AUD-FOR', 'Audit Vertrieb', 'Vertrieb', 'Pruefer', '2026-11-11', 'completed') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO audit_findings (audit_id, finding_code, finding_type, owner_unit_id, description, status) VALUES ($1, 'FND-01', 'minor_nc', $2, 'Vertrieb-Finding', 'open')",
    )
    .bind(audit_foreign)
    .bind(unit_b)
    .execute(&pool)
    .await
    .unwrap();

    let draft_review: Uuid = sqlx::query_scalar(
        "INSERT INTO management_reviews (review_date, period_label, participants, status, kpi_snapshot_json) VALUES ('2026-11-18', 'Entwurf 2026', 'GF', 'draft', '{\"generated_at\":\"2026-11-18T00:00:00Z\",\"soa\":{\"applicable_count\":0,\"implemented_count\":0,\"open_gaps_count\":0,\"implementation_percent\":0.0},\"risks\":{\"total_count\":0,\"critical_count\":0,\"high_count\":0,\"medium_count\":0,\"low_count\":0,\"unaccepted_high_critical\":0},\"incidents\":{\"total_count\":0,\"nis2_significant_count\":0,\"timely_bsi_reports\":0,\"overdue_bsi_reports\":0},\"documents\":{\"total_documents\":0,\"approved_documents\":0,\"approved_ratio_percent\":0.0,\"overdue_reviews\":0,\"acknowledgment_rate_percent\":100.0},\"audits_and_actions\":{\"open_major_nc\":0,\"open_minor_nc\":0,\"open_findings_total\":0,\"open_actions\":0,\"overdue_actions\":0}}'::jsonb) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        app.clone()
            .oneshot(get_req("/audits", &emp_cookie))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(get_req("/management-reviews", &emp_cookie))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        app.clone()
            .oneshot(get_req(&format!("/audits/{audit_own}"), &owner_cookie))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(get_req(&format!("/audits/{audit_foreign}"), &owner_cookie))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(get_req(
                &format!("/management-reviews/{draft_review}"),
                &owner_cookie,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(post_form(
                "/audits",
                &owner_cookie,
                &owner_csrf,
                "title=X&scope=Y&auditor_name=Z&audit_date=2026-11-20".to_string(),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        app.clone()
            .oneshot(get_req(
                &format!("/audits/{audit_foreign}"),
                &auditor_cookie
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(get_req(
                &format!("/management-reviews/{draft_review}"),
                &auditor_cookie,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(post_form(
                "/management-reviews",
                &auditor_cookie,
                &auditor_csrf,
                "review_date=2026-11-20&period_label=X&participants=Y".to_string(),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}
