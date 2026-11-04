//! OAuth HTTP endpoints:
//!
//! - `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728) and
//!   `GET /.well-known/oauth-authorization-server` (RFC 8414): metadata;
//! - `POST /oauth/register` (RFC 7591): a client registers itself;
//! - `GET /oauth/authorize`: sign-in (through `[oidc]`) and the consent
//!   screen; `POST /oauth/authorize`: the person's decision;
//! - `POST /oauth/token`: `authorization_code` (with PKCE) and
//!   `refresh_token`; `POST /oauth/revoke` (RFC 7009);
//! - `GET /api/me/ai-grants`, `DELETE /api/me/ai-grants/{id}`: "My AI access";
//! - `GET /api/admin/oauth-clients`, `POST /api/admin/oauth-clients/{name}/approve`
//!   and `/deny`, `GET /api/admin/ai-grants`, `DELETE /api/admin/ai-grants/{id}`.

// Handlers return a `Response` as their error: that is the answer they give.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Extension, Form, Json};
use serde::Deserialize;
use serde_json::json;

use super::store::{self, Grant};
use super::{now, parse_scopes, pkce_matches, redirect_matches, valid_redirect_uri};
use crate::api::ConnectionsState;
use crate::auth::AuthIdentity;
use crate::config::OAuthConfig;
use crate::db::Db;
use crate::oidc::{IdpError, OidcState};

/// How long a consent screen may wait for its answer.
const CONSENT_SECS: u64 = 600;
const MAX_REDIRECT_URIS: usize = 10;

/// What the OAuth routes share.
pub struct OAuthState {
    pub cfg: OAuthConfig,
    pub db: Db,
    pub conns: ConnectionsState,
    pub oidc: OidcState,
    consents: Mutex<HashMap<String, Consent>>,
}

impl OAuthState {
    pub fn new(cfg: OAuthConfig, db: Db, conns: ConnectionsState, oidc: OidcState) -> Arc<Self> {
        Arc::new(OAuthState {
            cfg,
            db,
            conns,
            oidc,
            consents: Mutex::new(HashMap::new()),
        })
    }
}

/// A consent screen waiting for its answer, by its CSRF token.
struct Consent {
    session_hash: String,
    email: String,
    client: store::Client,
    redirect_uri: String,
    code_challenge: String,
    scopes: Vec<&'static str>,
    state: Option<String>,
    idp_refresh: Option<String>,
    at: Instant,
}

type Shared = Extension<Arc<OAuthState>>;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{t}</title><link rel=\"stylesheet\" href=\"/mybastion.css\">\
         <style>body{{max-width:560px;margin:3em auto;padding:0 1em;font-family:system-ui,sans-serif;line-height:1.5}}\
         .card{{border:1px solid var(--border,#ccc);border-radius:8px;padding:1.2em 1.4em}}\
         .actions{{display:flex;gap:.8em;margin-top:1.2em}} ul{{padding-left:1.2em}} code{{font-size:.95em}}</style>\
         </head><body><div class=\"card\"><h2>{t}</h2>{b}</div></body></html>",
        t = esc(title),
        b = body
    )
}

fn error_page(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Html(page("Cannot continue", &format!("<p>{}</p>", esc(msg)))),
    )
        .into_response()
}

fn oauth_error(status: StatusCode, error: &str, desc: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": desc })),
    )
        .into_response()
}

/// Send the browser back to the client with `params`.
fn back_to_client(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let mut u = match url::Url::parse(redirect_uri) {
        Ok(u) => u,
        Err(_) => return error_page(StatusCode::BAD_REQUEST, "invalid redirect_uri"),
    };
    {
        let mut q = u.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    Redirect::to(u.as_str()).into_response()
}

async fn blocking<T: Send + 'static>(
    db: &Db,
    f: impl FnOnce(&rusqlite::Connection) -> T + Send + 'static,
) -> Result<T, Response> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        Ok(f(&conn))
    })
    .await
    .map_err(|e: tokio::task::JoinError| e.to_string())
    .and_then(|r: Result<T, String>| r)
    .map_err(|e| oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e))
}

// ── Metadata ──

pub async fn protected_resource(Extension(s): Shared) -> Response {
    Json(json!({
        "resource": s.cfg.resource(),
        "authorization_servers": [s.cfg.issuer()],
        "scopes_supported": [super::SCOPE_READ, super::SCOPE_ACT],
        "bearer_methods_supported": ["header"],
        "resource_name": "My Bastion",
    }))
    .into_response()
}

pub async fn authorization_server(Extension(s): Shared) -> Response {
    let i = s.cfg.issuer();
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{}/oauth/authorize", i),
        "token_endpoint": format!("{}/oauth/token", i),
        "registration_endpoint": format!("{}/oauth/register", i),
        "revocation_endpoint": format!("{}/oauth/revoke", i),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [super::SCOPE_READ, super::SCOPE_ACT],
    }))
    .into_response()
}

// ── Registration ──

#[derive(Deserialize)]
pub struct RegisterBody {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
}

pub async fn register(Extension(s): Shared, Json(b): Json<RegisterBody>) -> Response {
    let name = b.client_name.unwrap_or_default().trim().to_string();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_name must be 1-64 characters",
        );
    }
    if b.redirect_uris.is_empty()
        || b.redirect_uris.len() > MAX_REDIRECT_URIS
        || !b.redirect_uris.iter().all(|u| valid_redirect_uri(u))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must be https, or http on localhost, without a fragment",
        );
    }
    if b.token_endpoint_auth_method
        .as_deref()
        .is_some_and(|m| m != "none")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only public clients (token_endpoint_auth_method none)",
        );
    }
    let client = store::Client {
        client_id: format!("mbc_{}", uuid::Uuid::new_v4().simple()),
        client_name: name.clone(),
        redirect_uris: b.redirect_uris,
    };
    let preapproved = s.cfg.approved_clients.iter().any(|n| n == &name);
    let c2 = client.clone();
    let status = match blocking(&s.db, move |conn| {
        let now = now();
        store::insert_client(conn, &c2, now)?;
        let status = store::name_status(conn, &c2.client_name, preapproved, now)?;
        let detail = json!({ "client_id": c2.client_id, "name_status": status }).to_string();
        super::audit(
            conn,
            "oauth_client_registered",
            "anonymous",
            &format!("ai:{}", c2.client_name),
            Some(&detail),
        );
        Ok::<_, rusqlite::Error>(status)
    })
    .await
    {
        Ok(Ok(st)) => st,
        Ok(Err(e)) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        }
        Err(r) => return r,
    };
    tracing::info!(client = %name, status = %status, "OAuth client registered");
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": now(),
        })),
    )
        .into_response()
}

// ── Authorization ──

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    resource: Option<String>,
}

/// The signed-in browser user, from the session cookie only (never a token).
async fn browser_user(db: &Db, headers: &HeaderMap) -> Option<(String, crate::db::User)> {
    let token = crate::auth::cookie_value(headers, "mybastion_session")?;
    let db = db.clone();
    let t2 = token.clone();
    let user = tokio::task::spawn_blocking(move || crate::db::validate_auth_session(&db, &t2))
        .await
        .ok()?
        .ok()?;
    Some((token, user))
}

pub async fn authorize(
    Extension(s): Shared,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    // Until the client and its redirect_uri check out, errors stay here: a
    // redirect to an unchecked URI would be an open redirect.
    let Some(client_id) = q.client_id.clone() else {
        return error_page(StatusCode::BAD_REQUEST, "client_id is missing.");
    };
    let cid = client_id.clone();
    let client = match blocking(&s.db, move |c| store::get_client(c, &cid)).await {
        Ok(Ok(Some(c))) => c,
        Ok(_) => return error_page(StatusCode::BAD_REQUEST, "This AI client is not registered."),
        Err(r) => return r,
    };
    let Some(redirect_uri) = q
        .redirect_uri
        .clone()
        .filter(|r| redirect_matches(&client.redirect_uris, r))
    else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "redirect_uri does not match the client's registration.",
        );
    };
    let state = q.state.clone();
    let fail = |error: &str, desc: &str| {
        let mut p = vec![("error", error), ("error_description", desc)];
        if let Some(st) = state.as_deref() {
            p.push(("state", st));
        }
        back_to_client(&redirect_uri, &p)
    };
    if q.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type", "only response_type=code");
    }
    let Some(challenge) = q
        .code_challenge
        .clone()
        .filter(|c| (43..=128).contains(&c.len()))
    else {
        return fail("invalid_request", "PKCE code_challenge is required");
    };
    if q.code_challenge_method.as_deref() != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    if let Some(r) = q.resource.as_deref() {
        if r.trim_end_matches('/') != s.cfg.resource() {
            return fail(
                "invalid_target",
                "this server only issues tokens for its /mcp resource",
            );
        }
    }
    let scopes = match parse_scopes(q.scope.as_deref()) {
        Ok(sc) => sc,
        Err(e) => return fail("invalid_scope", &e),
    };

    // Sign in, through the identity provider, with a login that keeps its
    // refresh token for this grant.
    let here = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/oauth/authorize".into());
    let login = format!("/auth/login?offline=1&next={}", urlencoding::encode(&here));
    let Some((session, user)) = browser_user(&s.db, &headers).await else {
        return Redirect::to(&login).into_response();
    };
    let Some(idp_refresh) = s.oidc.take_kept_refresh(&session).await else {
        // Signed in, but not by a login made for this: go through the
        // provider once more (seamless while its own session lasts).
        return Redirect::to(&login).into_response();
    };

    let name = client.client_name.clone();
    let pre = s.cfg.approved_clients.iter().any(|n| n == &name);
    let status = match blocking(&s.db, move |c| store::name_status(c, &name, pre, now())).await {
        Ok(Ok(st)) => st,
        Ok(Err(e)) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        Err(r) => return r,
    };
    match status.as_str() {
        "approved" => {}
        "denied" => return fail("access_denied", "an admin has not allowed this AI client"),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Html(page(
                    "Waiting for an admin",
                    &format!(
                        "<p>The AI client <strong>{}</strong> has not been approved for this bastion yet.</p>\
                         <p>Ask an admin to approve it (Admin page → AI Agents → AI clients), then connect again.</p>",
                        esc(&client.client_name)
                    ),
                )),
            )
                .into_response()
        }
    }

    // What the client would reach: the person's own folders where AI may go.
    let caller = crate::mcp::Caller::User {
        email: user.email.clone(),
        role: user.role.clone(),
        groups: user.groups_vec(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
    };
    let folders = crate::mcp::server::ai_folders(&s.conns, &caller)
        .await
        .unwrap_or_default();
    let csrf = crate::db::generate_key();
    {
        let mut consents = s.consents.lock().unwrap_or_else(|e| e.into_inner());
        consents.retain(|_, c| c.at.elapsed() < Duration::from_secs(CONSENT_SECS));
        consents.insert(
            csrf.clone(),
            Consent {
                session_hash: store::hash(&session),
                email: user.email.clone(),
                client: client.clone(),
                redirect_uri: redirect_uri.clone(),
                code_challenge: challenge,
                scopes: scopes.clone(),
                state: q.state.clone(),
                idp_refresh,
                at: Instant::now(),
            },
        );
    }
    let scope_lines: String = scopes
        .iter()
        .map(|s| {
            let what = if *s == super::SCOPE_ACT {
                "act: click, type and press keys in sessions, and run commands"
            } else {
                "read: list connections, open sessions and see their screens"
            };
            format!("<li><code>{}</code>: {}</li>", s, what)
        })
        .collect();
    let folder_lines: String = if folders.is_empty() {
        "<li>none yet: no folder you can reach lets AI in</li>".into()
    } else {
        folders
            .iter()
            .map(|(sc, p, m)| {
                format!(
                    "<li><code>{}/{}</code>: {}</li>",
                    esc(sc),
                    esc(p),
                    m.as_str()
                )
            })
            .collect()
    };
    let body = format!(
        "<p><strong>{client}</strong> wants to act as <strong>{email}</strong> on this bastion.</p>\
         <p>It may:</p><ul>{scopes}</ul>\
         <p>Only in these folders (and only as far as you may yourself, and the policies allow):</p><ul>{folders}</ul>\
         <p style=\"font-size:.9em;color:var(--text-muted,#666)\">Everything it does is recorded and audited as \
         <code>user:{email} via ai:{client}</code>. In <em>approve</em> folders a person (not you) approves each action. \
         You can revoke this at any time under My Tokens → My AI access.</p>\
         <form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <div class=\"actions\"><button class=\"btn-primary\" name=\"decision\" value=\"approve\" id=\"oauth-approve\">Allow</button>\
         <button name=\"decision\" value=\"deny\" id=\"oauth-deny\">Deny</button></div></form>",
        client = esc(&client.client_name),
        email = esc(&user.email),
        scopes = scope_lines,
        folders = folder_lines,
        csrf = csrf,
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::HeaderName::from_static("x-frame-options"), "DENY"),
        ],
        Html(page("Allow an AI client?", &body)),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct DecisionForm {
    csrf: String,
    decision: String,
}

pub async fn decide(
    Extension(s): Shared,
    headers: HeaderMap,
    Form(f): Form<DecisionForm>,
) -> Response {
    let Some((session, user)) = browser_user(&s.db, &headers).await else {
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Your sign-in has ended; connect the AI client again.",
        );
    };
    let consent = s
        .consents
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&f.csrf);
    let Some(c) = consent.filter(|c| {
        c.session_hash == store::hash(&session)
            && c.email.eq_ignore_ascii_case(&user.email)
            && c.at.elapsed() < Duration::from_secs(CONSENT_SECS)
    }) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "This consent screen has expired; connect the AI client again.",
        );
    };
    let state = c.state.clone();
    let with_state = |mut p: Vec<(&'static str, String)>| {
        if let Some(st) = &state {
            p.push(("state", st.clone()));
        }
        p
    };
    if f.decision != "approve" {
        let p = with_state(vec![("error", "access_denied".into())]);
        let refs: Vec<(&str, &str)> = p.iter().map(|(k, v)| (*k, v.as_str())).collect();
        return back_to_client(&c.redirect_uri, &refs);
    }
    let grant = Grant {
        id: uuid::Uuid::new_v4().to_string(),
        email: user.email.clone(),
        client_id: c.client.client_id.clone(),
        client_name: c.client.client_name.clone(),
        scopes: c.scopes.join(" "),
        idp_linked: c.idp_refresh.is_some(),
        created_at: now(),
        last_used_at: None,
        revoked_at: None,
        revoked_why: None,
    };
    // The provider's refresh token goes to the secret store, encrypted.
    if let Some(rt) = &c.idp_refresh {
        if let Err(e) = s.conns.put_oauth_secret(&grant.id, rt).await {
            tracing::error!(error = %e, "Cannot keep the identity provider token for an OAuth grant");
            return error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "The secret store is not available; try again later.",
            );
        }
    }
    let (g2, redirect, challenge) = (
        grant.clone(),
        c.redirect_uri.clone(),
        c.code_challenge.clone(),
    );
    let code = match blocking(&s.db, move |conn| {
        store::insert_grant(conn, &g2)?;
        let detail =
            json!({ "grant": g2.id, "scopes": g2.scopes, "idp_linked": g2.idp_linked }).to_string();
        super::audit(
            conn,
            "oauth_consent",
            &g2.email,
            &format!("ai:{}", g2.client_name),
            Some(&detail),
        );
        super::new_code(conn, &g2.id, &g2.client_id, &redirect, &challenge)
    })
    .await
    {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        Err(r) => return r,
    };
    tracing::info!(email = %user.email, client = %grant.client_name, "OAuth grant created");
    let p = with_state(vec![("code", code), ("iss", s.cfg.issuer())]);
    let refs: Vec<(&str, &str)> = p.iter().map(|(k, v)| (*k, v.as_str())).collect();
    back_to_client(&c.redirect_uri, &refs)
}

// ── Tokens ──

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
}

fn issued(i: super::Issued) -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(i),
    )
        .into_response()
}

pub async fn token(Extension(s): Shared, Form(f): Form<TokenForm>) -> Response {
    if let Some(r) = f.resource.as_deref() {
        if r.trim_end_matches('/') != s.cfg.resource() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "unknown resource",
            );
        }
    }
    match f.grant_type.as_str() {
        "authorization_code" => code_grant(&s, f).await,
        "refresh_token" => refresh_grant(&s, f).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "authorization_code or refresh_token",
        ),
    }
}

async fn code_grant(s: &OAuthState, f: TokenForm) -> Response {
    let (Some(code), Some(client_id), Some(verifier)) = (f.code, f.client_id, f.code_verifier)
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, client_id and code_verifier are required",
        );
    };
    let redirect = f.redirect_uri.unwrap_or_default();
    let cfg = s.cfg.clone();
    let out = blocking(
        &s.db,
        move |conn| -> Result<super::Issued, (&'static str, String)> {
            let bad = |d: &str| ("invalid_grant", d.to_string());
            let c = store::take_code(conn, &code)
                .map_err(|e| ("server_error", e.to_string()))?
                .ok_or_else(|| bad("unknown or used code"))?;
            if c.expires_at <= now() || c.client_id != client_id || c.redirect_uri != redirect {
                return Err(bad("the code does not match"));
            }
            if !pkce_matches(&verifier, &c.code_challenge) {
                return Err(bad("PKCE verification failed"));
            }
            let g = store::get_grant(conn, &c.grant_id)
                .map_err(|e| ("server_error", e.to_string()))?
                .filter(|g| g.revoked_at.is_none())
                .ok_or_else(|| bad("the grant was revoked"))?;
            super::issue(conn, &cfg, &g).map_err(|e| ("server_error", e.to_string()))
        },
    )
    .await;
    match out {
        Ok(Ok(i)) => issued(i),
        Ok(Err((e, d))) => oauth_error(StatusCode::BAD_REQUEST, e, &d),
        Err(r) => r,
    }
}

/// Revoke `grant` (and drop its provider token) for `why`.
async fn revoke(s: &OAuthState, grant: &Grant, why: &'static str) {
    let (id, email, client) = (
        grant.id.clone(),
        grant.email.clone(),
        grant.client_name.clone(),
    );
    let _ = blocking(&s.db, move |conn| {
        if store::revoke_grant(conn, &id, why, now()).unwrap_or(false) {
            let detail = json!({ "grant": id, "why": why }).to_string();
            super::audit(
                conn,
                "oauth_grant_revoked",
                "system",
                &format!("user:{} via ai:{}", email, client),
                Some(&detail),
            );
        }
    })
    .await;
    let _ = s.conns.delete_oauth_secret(&grant.id).await;
    tracing::warn!(grant = %grant.id, email = %grant.email, why, "OAuth grant revoked");
}

async fn refresh_grant(s: &OAuthState, f: TokenForm) -> Response {
    let invalid = |d: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", d);
    let (Some(rt), Some(client_id)) = (f.refresh_token, f.client_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token and client_id are required",
        );
    };
    let rt2 = rt.clone();
    let found = match blocking(&s.db, move |conn| {
        let t = store::get_token(conn, &rt2)
            .ok()
            .flatten()
            .filter(|t| t.kind == "refresh")?;
        let g = store::get_grant(conn, &t.grant_id).ok().flatten()?;
        let user = crate::db::user_by_email(conn, &g.email);
        Some((t, g, user))
    })
    .await
    {
        Ok(Some(x)) => x,
        Ok(None) => return invalid("unknown refresh token"),
        Err(r) => return r,
    };
    let (t, grant, user) = found;
    if grant.revoked_at.is_some() {
        return invalid("the grant was revoked");
    }
    if grant.client_id != client_id {
        return invalid("the refresh token belongs to another client");
    }
    if t.used_at.is_some() {
        // A refresh token used twice: someone else has a copy.
        revoke(s, &grant, "refresh token reused").await;
        return invalid("refresh token reused; the grant is revoked");
    }
    if t.expires_at <= now() {
        return invalid("refresh token expired");
    }
    let Some(user) = user.filter(|u| !u.disabled) else {
        revoke(s, &grant, "user disabled or removed").await;
        return invalid("the user may no longer sign in");
    };

    // Ask the identity provider again.
    if grant.idp_linked {
        let idp_rt = match s.conns.get_oauth_secret(&grant.id).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                revoke(s, &grant, "identity provider token missing").await;
                return invalid("sign in again");
            }
            Err(e) => {
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    &e.to_string(),
                )
            }
        };
        match s.oidc.refresh_identity(&idp_rt).await {
            Ok(r) => {
                if r.email
                    .as_deref()
                    .is_some_and(|e| !e.eq_ignore_ascii_case(&user.email))
                {
                    revoke(s, &grant, "identity provider returned another user").await;
                    return invalid("sign in again");
                }
                if let Some(next) = &r.refresh_token {
                    if let Err(e) = s.conns.put_oauth_secret(&grant.id, next).await {
                        tracing::warn!(error = %e, "Cannot store the rotated identity provider token");
                    }
                }
                if let Some(groups) = r.groups {
                    let (email, db) = (user.email.clone(), s.db.clone());
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Ok(conn) = db.lock() {
                            let _ = store::set_user_groups(&conn, &email, &groups);
                        }
                        if let Ok(Some(role)) = crate::db::resolve_role_from_groups(&db, &groups) {
                            let _ = crate::db::set_user_role(&db, &email, &role);
                        }
                    })
                    .await;
                }
            }
            Err(IdpError::Revoked(why)) => {
                tracing::warn!(email = %user.email, why = %why, "Identity provider refused the refresh");
                revoke(s, &grant, "identity provider refused the user").await;
                return invalid("the identity provider no longer lets you in; sign in again");
            }
            Err(IdpError::Unavailable(e)) => {
                tracing::warn!(error = %e, "Identity provider unavailable for an OAuth refresh");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the identity provider cannot be reached",
                );
            }
        }
    } else if now() - grant.created_at > i64::from(s.cfg.reauth_hours) * 3600 {
        return invalid("sign in again (the identity provider gave no refresh token)");
    }

    let cfg = s.cfg.clone();
    let g2 = grant.clone();
    let out = blocking(&s.db, move |conn| -> Result<super::Issued, &'static str> {
        // Atomic: a second use of the same refresh token loses here.
        if !store::use_refresh(conn, &rt, now()).unwrap_or(false) {
            return Err("reused");
        }
        super::issue(conn, &cfg, &g2).map_err(|_| "server_error")
    })
    .await;
    match out {
        Ok(Ok(i)) => issued(i),
        Ok(Err("reused")) => {
            revoke(s, &grant, "refresh token reused").await;
            invalid("refresh token reused; the grant is revoked")
        }
        Ok(Err(e)) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct RevokeForm {
    token: String,
}

/// RFC 7009: revoking either token of a grant revokes the grant.
pub async fn revoke_token(Extension(s): Shared, Form(f): Form<RevokeForm>) -> Response {
    let tok = f.token.clone();
    if let Ok(Some(g)) = blocking(&s.db, move |conn| {
        let t = store::get_token(conn, &tok).ok().flatten()?;
        store::get_grant(conn, &t.grant_id).ok().flatten()
    })
    .await
    {
        revoke(&s, &g, "revoked by the client").await;
    }
    StatusCode::OK.into_response()
}

// ── My AI access, and admin ──

fn signed_in(identity: Option<Extension<AuthIdentity>>) -> Result<AuthIdentity, Response> {
    identity.map(|Extension(i)| i).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "authentication required"})),
        )
            .into_response()
    })
}

fn admin(identity: Option<Extension<AuthIdentity>>) -> Result<AuthIdentity, Response> {
    let id = signed_in(identity)?;
    if id.has_role("admin") {
        Ok(id)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response())
    }
}

pub async fn my_grants(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    let AuthIdentity::User { email, .. } = (match signed_in(identity) {
        Ok(i) => i,
        Err(r) => return r,
    }) else {
        return Json(json!([])).into_response();
    };
    match blocking(&db, move |c| store::list_grants(c, Some(&email))).await {
        Ok(Ok(g)) => Json(json!(g)).into_response(),
        Ok(Err(e)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
        Err(r) => r,
    }
}

async fn revoke_by_id(
    db: &Db,
    conns: &ConnectionsState,
    id: String,
    owner: Option<String>,
    by: String,
) -> Response {
    let gid = id.clone();
    let res = blocking(db, move |c| {
        let g = store::get_grant(c, &gid).ok().flatten()?;
        if owner
            .as_deref()
            .is_some_and(|o| !o.eq_ignore_ascii_case(&g.email))
        {
            return None;
        }
        let done = store::revoke_grant(c, &gid, "revoked by a person", now()).unwrap_or(false);
        if done {
            let detail = json!({ "grant": gid }).to_string();
            super::audit(
                c,
                "oauth_grant_revoked",
                &by,
                &format!("user:{} via ai:{}", g.email, g.client_name),
                Some(&detail),
            );
        }
        Some(done)
    })
    .await;
    match res {
        Ok(Some(_)) => {
            let _ = conns.delete_oauth_secret(&id).await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such grant"})),
        )
            .into_response(),
        Err(r) => r,
    }
}

pub async fn revoke_my_grant(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Extension(conns): Extension<ConnectionsState>,
    Path(id): Path<String>,
) -> Response {
    let AuthIdentity::User { email, .. } = (match signed_in(identity) {
        Ok(i) => i,
        Err(r) => return r,
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such grant"})),
        )
            .into_response();
    };
    revoke_by_id(&db, &conns, id, Some(email.clone()), email).await
}

pub async fn admin_grants(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    match blocking(&db, |c| store::list_grants(c, None)).await {
        Ok(Ok(g)) => Json(json!(g)).into_response(),
        Ok(Err(e)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
        Err(r) => r,
    }
}

pub async fn admin_revoke_grant(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Extension(conns): Extension<ConnectionsState>,
    Path(id): Path<String>,
) -> Response {
    let by = match admin(identity) {
        Ok(i) => i.display_name().to_string(),
        Err(r) => return r,
    };
    revoke_by_id(&db, &conns, id, None, by).await
}

pub async fn admin_clients(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    match blocking(&db, store::list_names).await {
        Ok(Ok(n)) => Json(json!(n)).into_response(),
        Ok(Err(e)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
        Err(r) => r,
    }
}

async fn decide_client(
    identity: Option<Extension<AuthIdentity>>,
    db: Db,
    conns: ConnectionsState,
    name: String,
    approve: bool,
) -> Response {
    let by = match admin(identity) {
        Ok(i) => i.display_name().to_string(),
        Err(r) => return r,
    };
    let res = blocking(&db, move |c| {
        let done = store::decide_name(c, &name, approve, &by, now()).unwrap_or(false);
        // Denying a client also ends what it already holds.
        let revoked = if done && !approve {
            store::revoke_name_grants(c, &name, now()).unwrap_or_default()
        } else {
            Vec::new()
        };
        if done {
            let ev = if approve {
                "oauth_client_approved"
            } else {
                "oauth_client_denied"
            };
            let detail = json!({ "grants_revoked": revoked.len() }).to_string();
            super::audit(c, ev, &by, &format!("ai:{}", name), Some(&detail));
        }
        (done, revoked)
    })
    .await;
    match res {
        Ok((true, revoked)) => {
            for id in revoked {
                let _ = conns.delete_oauth_secret(&id).await;
            }
            Json(json!({"ok": true})).into_response()
        }
        Ok((false, _)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such client name"})),
        )
            .into_response(),
        Err(r) => r,
    }
}

pub async fn approve_client(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Extension(conns): Extension<ConnectionsState>,
    Path(name): Path<String>,
) -> Response {
    decide_client(identity, db, conns, name, true).await
}

pub async fn deny_client(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Extension(conns): Extension<ConnectionsState>,
    Path(name): Path<String>,
) -> Response {
    decide_client(identity, db, conns, name, false).await
}
