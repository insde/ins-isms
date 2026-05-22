use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use cookie::Cookie;
use uuid::Uuid;

use crate::{
    auth::session::{SESSION_COOKIE_NAME, load_and_refresh_session, verify_signed_cookie},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum Role {
    Admin,
    Iso,
    Owner,
    Auditor,
    Employee,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Iso => "iso",
            Self::Owner => "owner",
            Self::Auditor => "auditor",
            Self::Employee => "employee",
        }
    }

    pub fn is_admin(self) -> bool {
        self == Self::Admin
    }

    pub fn is_iso_or_admin(self) -> bool {
        matches!(self, Self::Admin | Self::Iso)
    }

    pub fn is_auditor(self) -> bool {
        self == Self::Auditor
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "iso" => Ok(Self::Iso),
            "owner" => Ok(Self::Owner),
            "auditor" => Ok(Self::Auditor),
            "employee" => Ok(Self::Employee),
            other => Err(AppError::BadRequest(format!("Ungültige Rolle: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl<S> FromRequestParts<S> for ClientIp
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        if app_state.config.trust_proxy {
            if let Some(xff) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                && let Some(ip) = xff
                    .rsplit(',')
                    .map(str::trim)
                    .find_map(|raw| raw.parse::<IpAddr>().ok())
            {
                return Ok(Self(ip));
            }
            if let Some(xri) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok())
                && let Ok(ip) = xri.trim().parse::<IpAddr>()
            {
                return Ok(Self(ip));
            }
        }

        if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            return Ok(Self(addr.ip()));
        }

        Ok(Self(IpAddr::V4(Ipv4Addr::LOCALHOST)))
    }
}

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: Role,
    pub organization_unit_id: Option<Uuid>,
    pub session_id: String,
    pub csrf_token: String,
}

pub struct AuthRedirect {
    pub is_htmx: bool,
}

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        if self.is_htmx {
            let mut resp = (StatusCode::OK, "").into_response();
            if let Ok(val) = HeaderValue::from_str("/login") {
                resp.headers_mut().insert("HX-Redirect", val);
            }
            resp
        } else {
            Redirect::to("/login").into_response()
        }
    }
}

pub fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers
        .get("hx-request")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

pub fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw_cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for item in Cookie::split_parse(raw_cookies).flatten() {
        if item.name() == name {
            return Some(item.value().to_string());
        }
    }
    None
}

impl<S> FromRequestParts<S> for CurrentUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let is_htmx = is_htmx_request(&parts.headers);

        let Some(cookie_val) = extract_cookie_value(&parts.headers, SESSION_COOKIE_NAME) else {
            return Err(AuthRedirect { is_htmx });
        };

        let Some(session_id) = verify_signed_cookie(&cookie_val, &app_state.config.session_secret)
        else {
            return Err(AuthRedirect { is_htmx });
        };

        match load_and_refresh_session(
            &app_state.pool,
            session_id,
            app_state.config.session_ttl_hours,
        )
        .await
        {
            Ok(Some(loaded)) => Ok(Self {
                id: loaded.user_id,
                email: loaded.email,
                full_name: loaded.full_name,
                role: loaded.role,
                organization_unit_id: loaded.organization_unit_id,
                session_id: loaded.session_id,
                csrf_token: loaded.csrf_token,
            }),
            Ok(None) | Err(_) => Err(AuthRedirect { is_htmx }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequireAdmin(pub CurrentUser);

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if !user.role.is_admin() {
            return Err(AppError::Forbidden(
                "Administrator-Berechtigung erforderlich.".to_string(),
            )
            .into_response());
        }
        Ok(Self(user))
    }
}

#[derive(Debug, Clone)]
pub struct RequireIsoOrAdmin(pub CurrentUser);

impl<S> FromRequestParts<S> for RequireIsoOrAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if !user.role.is_iso_or_admin() {
            return Err(AppError::Forbidden(
                "ISB- oder Administrator-Berechtigung erforderlich.".to_string(),
            )
            .into_response());
        }
        Ok(Self(user))
    }
}

#[derive(Debug, Clone)]
pub struct RequireAuditViewer(pub CurrentUser);

impl<S> FromRequestParts<S> for RequireAuditViewer
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if !matches!(user.role, Role::Admin | Role::Iso | Role::Auditor) {
            return Err(AppError::Forbidden(
                "Keine Berechtigung zur Einsicht des Audit-Logs.".to_string(),
            )
            .into_response());
        }
        Ok(Self(user))
    }
}

pub fn forbid_auditor(user: &CurrentUser) -> Result<(), AppError> {
    if user.role.is_auditor() {
        return Err(AppError::Forbidden(
            "Prüfer-Accounts (auditor) haben ausschließlich Lesezugriff.".to_string(),
        ));
    }
    Ok(())
}

pub fn ensure_owner_scope(
    user: &CurrentUser,
    entity_unit_id: Option<Uuid>,
    entity_owner_user_id: Option<Uuid>,
) -> Result<(), AppError> {
    forbid_auditor(user)?;

    match user.role {
        Role::Admin | Role::Iso => Ok(()),
        Role::Owner => {
            let same_unit = matches!(
                (user.organization_unit_id, entity_unit_id),
                (Some(u), Some(e)) if u == e
            );
            let same_owner = entity_owner_user_id == Some(user.id);
            if same_unit || same_owner {
                Ok(())
            } else {
                Err(AppError::Forbidden(
                    "Zugriff außerhalb Ihrer Organisationseinheit nicht zulässig.".to_string(),
                ))
            }
        }
        Role::Auditor | Role::Employee => Err(AppError::Forbidden(
            "Keine Schreibberechtigung für diese Ressource.".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(role: Role, unit: Option<Uuid>, id: Uuid) -> CurrentUser {
        CurrentUser {
            id,
            email: "test@example.com".to_string(),
            full_name: "Test".to_string(),
            role,
            organization_unit_id: unit,
            session_id: "sid".to_string(),
            csrf_token: "csrf".to_string(),
        }
    }

    #[test]
    fn enforces_auditor_read_only_and_owner_scoping() {
        let unit_a = Uuid::new_v4();
        let unit_b = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();

        let auditor = test_user(Role::Auditor, None, user_id);
        assert!(forbid_auditor(&auditor).is_err());
        assert!(ensure_owner_scope(&auditor, Some(unit_a), Some(user_id)).is_err());

        let owner = test_user(Role::Owner, Some(unit_a), user_id);
        assert!(ensure_owner_scope(&owner, Some(unit_a), Some(other_id)).is_ok());
        assert!(ensure_owner_scope(&owner, Some(unit_b), Some(user_id)).is_ok());
        assert!(ensure_owner_scope(&owner, Some(unit_b), Some(other_id)).is_err());
        assert!(ensure_owner_scope(&owner, None, None).is_err());

        let iso = test_user(Role::Iso, None, user_id);
        assert!(ensure_owner_scope(&iso, Some(unit_b), Some(other_id)).is_ok());
    }
}
