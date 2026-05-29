use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{
    auth::{
        rbac::extract_cookie_value,
        session::{SESSION_COOKIE_NAME, verify_signed_cookie},
    },
    error::AppError,
    state::AppState,
};

const CSP_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    insert_static_header(headers, "x-content-type-options", "nosniff");
    insert_static_header(headers, "x-frame-options", "DENY");
    insert_static_header(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
    insert_static_header(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    insert_static_header(headers, "content-security-policy", CSP_POLICY);

    resp
}

fn insert_static_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    if let Ok(k) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
        headers.insert(k, HeaderValue::from_static(value));
    }
}

pub async fn csrf_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }

    let path = req.uri().path();
    if path == "/auth/oidc/callback" {
        return next.run(req).await;
    }

    if path == "/login" {
        if let Err(err) = verify_origin_if_present(req.headers(), &state.config.app_base_url) {
            return err.into_response();
        }
        return next.run(req).await;
    }

    if let Err(err) = verify_origin_strict(req.headers(), &state.config.app_base_url) {
        return err.into_response();
    }

    let Some(cookie_val) = extract_cookie_value(req.headers(), SESSION_COOKIE_NAME) else {
        return AppError::Forbidden("CSRF-Prüfung fehlgeschlagen: Keine gültige Sitzung.".into())
            .into_response();
    };
    let Some(session_id) = verify_signed_cookie(&cookie_val, &state.config.session_secret) else {
        return AppError::Forbidden("CSRF-Prüfung fehlgeschlagen: Ungültige Sitzung.".into())
            .into_response();
    };

    let expected_csrf: Option<String> = match sqlx::query_scalar(
        "SELECT csrf_token FROM sessions WHERE id = $1 AND expires_at > NOW()",
    )
    .bind(session_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(tok) => tok,
        Err(err) => return AppError::Database(err).into_response(),
    };

    let Some(expected_token) = expected_csrf else {
        return AppError::Forbidden("CSRF-Prüfung fehlgeschlagen: Sitzung abgelaufen.".into())
            .into_response();
    };

    if let Some(header_tok) = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
    {
        if constant_time_eq(header_tok, &expected_token) {
            return next.run(req).await;
        }
        return AppError::Forbidden("Ungültiges CSRF-Token.".into()).into_response();
    }

    let is_form = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));

    if is_form {
        let (parts, body) = req.into_parts();
        let bytes = match to_bytes(body, state.config.max_upload_bytes).await {
            Ok(b) => b,
            Err(_) => {
                return (StatusCode::PAYLOAD_TOO_LARGE, "Anfrage zu groß").into_response();
            }
        };

        let form_csrf = url::form_urlencoded::parse(&bytes)
            .find(|(k, _)| k == "_csrf")
            .map(|(_, v)| v.into_owned());

        if let Some(tok) = form_csrf
            && constant_time_eq(&tok, &expected_token)
        {
            let rebuilt = Request::from_parts(parts, Body::from(bytes));
            return next.run(rebuilt).await;
        }
    }

    AppError::Forbidden("Fehlendes oder ungültiges CSRF-Token.".into()).into_response()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn verify_origin_if_present(headers: &HeaderMap, base_url: &Url) -> Result<(), AppError> {
    if headers.contains_key("origin") || headers.contains_key("referer") {
        verify_origin_strict(headers, base_url)
    } else {
        Ok(())
    }
}

fn verify_origin_strict(headers: &HeaderMap, base_url: &Url) -> Result<(), AppError> {
    let raw = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Forbidden("CSRF-Prüfung fehlgeschlagen: Origin/Referer fehlt.".into())
        })?;

    let parsed = Url::parse(raw).map_err(|_| {
        AppError::Forbidden("CSRF-Prüfung fehlgeschlagen: Ungültige Origin-URL.".into())
    })?;

    if parsed.scheme() != base_url.scheme()
        || parsed.host_str() != base_url.host_str()
        || parsed.port_or_known_default() != base_url.port_or_known_default()
    {
        return Err(AppError::Forbidden(
            "CSRF-Prüfung fehlgeschlagen: Origin stimmt nicht mit APP_BASE_URL überein.".into(),
        ));
    }

    Ok(())
}
