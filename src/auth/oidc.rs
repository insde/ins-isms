use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite, time::Duration as CookieDuration};
use hmac::{Hmac, Mac};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::{
        rbac::{ClientIp, Role, extract_cookie_value},
        session::{build_session_cookie, create_session, sign_session_id},
    },
    config::OidcConfig,
    db::begin_audited_tx,
    error::AppError,
    state::AppState,
};

const OIDC_TX_COOKIE: &str = "ins_oidc_tx";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct OidcTxState {
    state: String,
    nonce: String,
    pkce_verifier: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

fn build_http_client() -> Result<openidconnect::reqwest::Client, AppError> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(format!("OIDC HTTP-Client-Fehler: {e}")))
}

fn sign_tx_state(tx: &OidcTxState, secret: &[u8]) -> Result<String, AppError> {
    let json = serde_json::to_vec(tx)
        .map_err(|e| AppError::Internal(format!("OIDC State Serialisierung: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(json);
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| AppError::Internal(format!("OIDC Key-Fehler: {e}")))?;
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

fn verify_tx_state(cookie_val: &str, secret: &[u8]) -> Option<OidcTxState> {
    let (payload_b64, sig_b64) = cookie_val.split_once('.')?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    let json_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let parsed: OidcTxState = serde_json::from_slice(&json_bytes).ok()?;
    if chrono::Utc::now().timestamp() > parsed.exp {
        return None;
    }
    Some(parsed)
}

fn redirect_url_from_config(state: &AppState) -> Result<RedirectUrl, AppError> {
    let url = state
        .config
        .app_base_url
        .join("auth/oidc/callback")
        .map_err(|e| AppError::Internal(format!("OIDC Redirect-URL ungültig: {e}")))?;
    RedirectUrl::new(url.to_string())
        .map_err(|e| AppError::Internal(format!("OIDC RedirectUrl Fehler: {e}")))
}

fn require_oidc_config(state: &AppState) -> Result<&OidcConfig, AppError> {
    state
        .config
        .oidc
        .as_ref()
        .ok_or_else(|| AppError::NotFound("OIDC ist nicht konfiguriert.".to_string()))
}

pub async fn oidc_login_handler(State(state): State<AppState>) -> Result<Response, AppError> {
    let oidc_cfg = require_oidc_config(&state)?;
    let http_client = build_http_client()?;

    let issuer = IssuerUrl::new(oidc_cfg.issuer_url.to_string())
        .map_err(|e| AppError::Internal(format!("OIDC Issuer ungültig: {e}")))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
        .await
        .map_err(|e| AppError::Internal(format!("OIDC Discovery fehlgeschlagen: {e}")))?;

    let redirect_url = redirect_url_from_config(&state)?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc_cfg.client_id.clone()),
        Some(ClientSecret::new(oidc_cfg.client_secret.clone())),
    )
    .set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let tx_state = OidcTxState {
        state: csrf_state.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        exp: chrono::Utc::now().timestamp() + 600,
    };

    let signed_tx = sign_tx_state(&tx_state, &state.config.session_secret)?;
    let tx_cookie = Cookie::build((OIDC_TX_COOKIE, signed_tx))
        .path("/auth/oidc")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .max_age(CookieDuration::minutes(10))
        .build();

    let mut resp = Redirect::to(auth_url.as_str()).into_response();
    if let Ok(val) = HeaderValue::from_str(&tx_cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    Ok(resp)
}

pub async fn oidc_callback_handler(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, AppError> {
    let oidc_cfg = require_oidc_config(&state)?;

    if query.error.is_some() {
        return Err(AppError::Unauthorized);
    }

    let code = query.code.ok_or(AppError::BadRequest(
        "OIDC Authorization-Code fehlt.".to_string(),
    ))?;
    let returned_state = query
        .state
        .ok_or(AppError::BadRequest("OIDC State fehlt.".to_string()))?;

    let raw_tx_cookie = extract_cookie_value(&headers, OIDC_TX_COOKIE)
        .ok_or_else(|| AppError::Forbidden("OIDC Transaktions-Cookie fehlt.".to_string()))?;
    let tx_state = verify_tx_state(&raw_tx_cookie, &state.config.session_secret)
        .ok_or_else(|| AppError::Forbidden("OIDC Transaktions-Cookie ungültig.".to_string()))?;

    if !bool::from(returned_state.as_bytes().ct_eq(tx_state.state.as_bytes())) {
        return Err(AppError::Forbidden(
            "OIDC State stimmt nicht überein.".to_string(),
        ));
    }

    let http_client = build_http_client()?;
    let issuer = IssuerUrl::new(oidc_cfg.issuer_url.to_string())
        .map_err(|e| AppError::Internal(format!("OIDC Issuer ungültig: {e}")))?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
        .await
        .map_err(|e| AppError::Internal(format!("OIDC Discovery fehlgeschlagen: {e}")))?;

    let redirect_url = redirect_url_from_config(&state)?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc_cfg.client_id.clone()),
        Some(ClientSecret::new(oidc_cfg.client_secret.clone())),
    )
    .set_redirect_uri(redirect_url);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| AppError::Internal(format!("OIDC Token-Exchange-Konfiguration: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(tx_state.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|_| AppError::Unauthorized)?;

    let id_token = token_response.id_token().ok_or(AppError::Unauthorized)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(tx_state.nonce))
        .map_err(|_| AppError::Unauthorized)?;

    let subject = claims.subject().as_str();
    let email_opt = claims
        .email()
        .map(|e| e.as_str().trim().to_ascii_lowercase());
    let email_verified = claims.email_verified().unwrap_or(false);
    let display_name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.as_str().to_string())
        .or_else(|| email_opt.clone())
        .unwrap_or_else(|| "OIDC Benutzer".to_string());

    let existing_by_sub = sqlx::query(
        r#"
        SELECT id, email, is_active, (expires_at IS NOT NULL AND expires_at <= NOW()) AS is_expired
        FROM users
        WHERE oidc_subject = $1
        "#,
    )
    .bind(subject)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, user_email) = if let Some(row) = existing_by_sub {
        let active: bool = row.try_get("is_active")?;
        let expired: bool = row.try_get("is_expired")?;
        if !active || expired {
            return Err(AppError::Forbidden(
                "Ihr Benutzerkonto ist deaktiviert oder abgelaufen.".to_string(),
            ));
        }
        (
            row.try_get::<Uuid, _>("id")?,
            row.try_get::<String, _>("email")?,
        )
    } else if let Some(ref email) = email_opt {
        if !email_verified {
            return Err(AppError::Forbidden(
                "E-Mail-Adresse muss vom Identity-Provider verifiziert sein.".to_string(),
            ));
        }
        let existing_by_email = sqlx::query(
            r#"
            SELECT id, email, is_active, (expires_at IS NOT NULL AND expires_at <= NOW()) AS is_expired
            FROM users
            WHERE LOWER(email) = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(row) = existing_by_email {
            let active: bool = row.try_get("is_active")?;
            let expired: bool = row.try_get("is_expired")?;
            if !active || expired {
                return Err(AppError::Forbidden(
                    "Ihr Benutzerkonto ist deaktiviert oder abgelaufen.".to_string(),
                ));
            }
            let uid: Uuid = row.try_get("id")?;
            let mut tx = begin_audited_tx(&state.pool, Some(uid), Some(ip)).await?;
            sqlx::query("UPDATE users SET oidc_subject = $1, updated_at = NOW() WHERE id = $2")
                .bind(subject)
                .bind(uid)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            (uid, row.try_get::<String, _>("email")?)
        } else if oidc_cfg.auto_provision {
            let mut tx = begin_audited_tx(&state.pool, None, Some(ip)).await?;
            let new_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO users (email, full_name, oidc_subject, role)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
            )
            .bind(email)
            .bind(&display_name)
            .bind(subject)
            .bind(Role::Employee.as_str())
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            (new_id, email.clone())
        } else {
            return Err(AppError::Forbidden(
                "Kein passendes Benutzerkonto vorhanden (Auto-Provisioning deaktiviert)."
                    .to_string(),
            ));
        }
    } else {
        return Err(AppError::Forbidden(
            "OIDC-Token enthält keine E-Mail-Adresse.".to_string(),
        ));
    };

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let (session_id, _) = create_session(
        &state.pool,
        user_id,
        Some(ip),
        user_agent,
        state.config.session_ttl_hours,
    )
    .await?;

    AuditService::log_oidc_login(&state.pool, user_id, ip, &user_email).await?;

    let signed_cookie = sign_session_id(&session_id, &state.config.session_secret)?;
    let session_cookie = build_session_cookie(signed_cookie, &state.config);
    let clear_tx_cookie = Cookie::build((OIDC_TX_COOKIE, ""))
        .path("/auth/oidc")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .max_age(CookieDuration::ZERO)
        .build();

    let mut resp = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    if let Ok(val) = HeaderValue::from_str(&session_cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    if let Ok(val) = HeaderValue::from_str(&clear_tx_cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    Ok(resp)
}
