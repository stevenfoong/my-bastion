//! The core side of the database access proxy (Phase 4 of
//! `docs/fork-design.md`). The proxy (`dbproxy/`, a separate Go service)
//! speaks the database wire protocol; policy, credentials and audit stay
//! here:
//!
//! - **DB tokens**: `POST /api/addressbook/folders/{scope}/{folder}/entries/{entry}/db-token`
//!   gives a signed-in user (operator+) with access to a database entry a
//!   short-lived token (`mbdb_…`) to use as the password with `psql` and the
//!   like, after the entry's `connect` policies. The user never sees the
//!   database's own credentials.
//! - **Internal API** for the proxy, under `/internal/db/`, authenticated
//!   with the shared secret (`X-Mybastion-Proxy-Secret`):
//!   `connect` (token → identity, connect policy again, the real
//!   credentials and the checked address), `check` (one statement and its
//!   classes → `db_query` policies: allow, deny, or held for approval),
//!   `audit` (how a statement ended, with its row count) and `disconnect`.
//!
//! Every statement is in the policy audit log with the user's identity.

// Handlers return a `Response` as their error: that is the answer they give.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::{AppState, ConnectionsState};
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::policy::store::{self as pstore, AuditEvent};
use crate::policy::{Gate, Resource};

const TOKEN_PREFIX: &str = "mbdb_";
/// Database entry types the proxy serves.
const DB_TYPES: [&str; 2] = ["postgres", "mysql"];
/// The longest statement kept in an audit row.
const MAX_AUDIT_STATEMENT: usize = 4000;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS db_tokens (
            token_hash TEXT PRIMARY KEY,
            email      TEXT,
            api_key    TEXT,
            scope      TEXT NOT NULL,
            folder     TEXT NOT NULL,
            entry      TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );",
    )
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn now() -> i64 {
    pstore::now_secs()
}

/// A live proxy connection: who, to what.
#[derive(Clone)]
struct DbSession {
    id: AuthIdentity,
    resource: Resource,
    client_ip: String,
    started: i64,
}

fn sessions() -> &'static Mutex<HashMap<String, DbSession>> {
    static S: OnceLock<Mutex<HashMap<String, DbSession>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn audit_row(conn: &Connection, event: &str, s: &DbSession, detail: &serde_json::Value) {
    let who = crate::policy::Requester::from_identity(&s.id);
    let detail = detail.to_string();
    let target = s.resource.label();
    let row = AuditEvent {
        event,
        actor: s.id.display_name(),
        requester: &who.id(),
        action: crate::policy::Action::DbQuery.as_str(),
        target: &target,
        detail: Some(&detail),
        ip: Some(&s.client_ip),
        ..Default::default()
    };
    if let Err(e) = pstore::audit(conn, &row, now()) {
        tracing::warn!(error = %e, "Failed to audit a database event");
    }
}

async fn with_db<T: Send + 'static>(
    db: &Db,
    f: impl FnOnce(&Connection) -> T + Send + 'static,
) -> Result<T, Response> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        Ok::<T, String>(f(&conn))
    })
    .await
    .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

// ── DB tokens ──

/// POST .../entries/{entry}/db-token — a short-lived token for the proxy.
#[allow(clippy::too_many_arguments)]
pub async fn issue_token(
    State(manager): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<crate::auth::TrustedProxies>>,
    Extension(db): Extension<Db>,
    Extension(vault): Extension<ConnectionsState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
) -> Response {
    let Some(cfg) = manager.config().dbproxy.clone().filter(|c| c.enabled) else {
        return error(StatusCode::NOT_FOUND, "the database proxy is not enabled");
    };
    let id = match identity {
        Some(Extension(id)) if id.has_role("operator") => id,
        _ => return error(StatusCode::FORBIDDEN, "operator role required"),
    };
    let (email, api_key) = match &id {
        AuthIdentity::User { email, .. } => (Some(email.clone()), None),
        AuthIdentity::ApiKey(name) => (None, Some(name.clone())),
        _ => return error(StatusCode::FORBIDDEN, "not for this kind of caller"),
    };
    if let Err(r) = crate::api::check_folder_access(&vault, &scope, &folder, &id).await {
        return r;
    }
    let ab = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(e) => e,
        Err(_) => return error(StatusCode::NOT_FOUND, "entry not found"),
    };
    if !DB_TYPES.contains(&ab.session_type.as_str()) {
        return error(StatusCode::BAD_REQUEST, "not a database entry");
    }
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = crate::auth::client_ip(&headers, addr.ip(), &proxies).to_string();
    let res = Resource::Entry {
        scope: scope.clone(),
        folder: folder.clone(),
        entry: entry.clone(),
    };
    // Connecting to a database is a connect, under the same policies.
    if let Err(r) = crate::policy::api::connect_gate(&db, &id, res.clone(), ip.clone()).await {
        return r;
    }
    let token = format!("{}{}", TOKEN_PREFIX, crate::db::generate_key());
    let expires_at = now() + i64::from(cfg.token_minutes.max(1)) * 60;
    let (t2, s2, f2, e2) = (token.clone(), scope.clone(), folder.clone(), entry.clone());
    let actor = id.display_name().to_string();
    let label = res.label();
    let stored = with_db(&db, move |c| {
        c.execute(
            "INSERT INTO db_tokens (token_hash, email, api_key, scope, folder, entry, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![crate::db::hash_key(&t2), email, api_key, s2, f2, e2, now(), expires_at],
        )?;
        let _ = c.execute("DELETE FROM db_tokens WHERE expires_at < ?1", [now()]);
        let row = AuditEvent {
            event: "db_token_issued",
            actor: &actor,
            requester: &actor,
            action: "connect",
            target: &label,
            ip: Some(&ip),
            ..Default::default()
        };
        pstore::audit(c, &row, now())
    })
    .await;
    match stored {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(r) => return r,
    }
    let mysql = ab.session_type == "mysql";
    let address = if mysql {
        cfg.mysql_address()
    } else {
        cfg.address.clone()
    };
    let (host, port) = address
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.to_string()))
        .unwrap_or((address.clone(), if mysql { "3307" } else { "5433" }.into()));
    let user = id.display_name().to_string();
    let dbname = default_database(&ab);
    // The command line to connect with (the token in place of <token>).
    let command = if mysql {
        let db = if dbname.is_empty() {
            String::new()
        } else {
            format!(" {}", dbname)
        };
        format!(
            "MYSQL_PWD=<token> mysql -h {} -P {} -u {} --ssl{}",
            host,
            port,
            shell_word(&user),
            db
        )
    } else {
        format!(
            "PGPASSWORD=<token> psql \"host={} port={} dbname={} user={} sslmode=require\"",
            host, port, dbname, user
        )
    };
    Json(json!({
        "token": token,
        "expires_at": expires_at,
        "protocol": if mysql { "mysql" } else { "postgres" },
        "host": host,
        "port": port,
        "user": user,
        "database": dbname,
        "command": command,
        "psql": command,
    }))
    .into_response()
}

// ── Internal API for the proxy ──

fn proxy_authorized(manager: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    use subtle::ConstantTimeEq;
    let secret = manager
        .config()
        .dbproxy
        .as_ref()
        .filter(|c| c.enabled)
        .and_then(|c| c.secret())
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "the database proxy is not enabled"))?;
    let given = headers
        .get("x-mybastion-proxy-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if given.len() == secret.len() && bool::from(given.as_bytes().ct_eq(secret.as_bytes())) {
        Ok(())
    } else {
        tracing::warn!("Database proxy call with a wrong secret");
        Err(error(StatusCode::UNAUTHORIZED, "wrong proxy secret"))
    }
}

#[derive(Deserialize)]
pub struct ConnectBody {
    token: String,
    #[serde(default)]
    client_ip: String,
    /// The proxy listener the client came in on: `postgres` (the default,
    /// for proxies before MySQL support) or `mysql`.
    #[serde(default)]
    protocol: Option<String>,
}

/// The database a client lands in: the entry's, else the server's default
/// (`postgres` for PostgreSQL, none for MySQL).
fn default_database(ab: &crate::connections::AddressBookEntry) -> String {
    match ab.database.clone().filter(|d| !d.is_empty()) {
        Some(d) => d,
        None if ab.session_type == "mysql" => String::new(),
        None => "postgres".into(),
    }
}

/// Quote a word for a shell command line when it needs it.
fn shell_word(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "@._-+".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// A `db_tokens` row: email, API key, scope, folder, entry, expiry.
type TokenRow = (Option<String>, Option<String>, String, String, String, i64);

/// The identity behind a token, as it is now.
fn token_identity(
    conn: &Connection,
    token: &str,
) -> Result<(AuthIdentity, Resource), &'static str> {
    if !token.starts_with(TOKEN_PREFIX) {
        return Err("invalid token");
    }
    let row: Option<TokenRow> = conn
        .query_row(
            "SELECT email, api_key, scope, folder, entry, expires_at FROM db_tokens WHERE token_hash = ?1",
            [crate::db::hash_key(token)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
        .map_err(|_| "invalid token")?;
    let (email, api_key, scope, folder, entry, expires) = row.ok_or("invalid token")?;
    if expires <= now() {
        return Err("token expired");
    }
    let id = match (email, api_key) {
        (Some(email), _) => {
            let u = crate::db::user_by_email(conn, &email).ok_or("user no longer exists")?;
            if u.disabled {
                return Err("user is disabled");
            }
            AuthIdentity::User {
                groups: u.groups_vec(),
                email: u.email,
                role: u.role,
            }
        }
        (None, Some(k)) => AuthIdentity::ApiKey(k),
        _ => return Err("invalid token"),
    };
    Ok((
        id,
        Resource::Entry {
            scope,
            folder,
            entry,
        },
    ))
}

pub async fn connect(
    State(manager): State<AppState>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Extension(vault): Extension<ConnectionsState>,
    Json(b): Json<ConnectBody>,
) -> Response {
    if let Err(r) = proxy_authorized(&manager, &headers) {
        return r;
    }
    let token = b.token.clone();
    let (id, res) = match with_db(&db, move |c| token_identity(c, &token)).await {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return error(StatusCode::UNAUTHORIZED, e),
        Err(r) => return r,
    };
    let Resource::Entry {
        scope,
        folder,
        entry,
    } = res.clone()
    else {
        return error(StatusCode::BAD_REQUEST, "not a database entry");
    };
    // Access and policy now, not when the token was issued.
    if crate::api::check_folder_access(&vault, &scope, &folder, &id)
        .await
        .is_err()
    {
        return error(StatusCode::FORBIDDEN, "no access to this folder any more");
    }
    if let Err(r) =
        crate::policy::api::connect_gate(&db, &id, res.clone(), b.client_ip.clone()).await
    {
        let status = r.status();
        return error(
            if status == StatusCode::ACCEPTED { StatusCode::FORBIDDEN } else { status },
            "connecting to this database is not allowed now (denied by policy or waiting for approval)",
        );
    }
    let ab = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(e) => e,
        Err(_) => return error(StatusCode::NOT_FOUND, "entry not found"),
    };
    let ab = crate::api::lend_folder_defaults(vault.as_ref(), &scope, &folder, &entry, ab).await;
    let ab = match crate::api::resolve_entry_credentials(&vault, &id, ab).await {
        Ok(e) => e,
        Err(_) => {
            return error(
                StatusCode::PRECONDITION_FAILED,
                "the entry's credential variables are missing",
            )
        }
    };
    let protocol = b.protocol.as_deref().unwrap_or("postgres");
    if ab.session_type != protocol {
        return error(
            StatusCode::BAD_REQUEST,
            format!(
                "this token is for a {} database; connect to the bastion's {} port",
                ab.session_type,
                if ab.session_type == "mysql" {
                    "MySQL"
                } else {
                    "PostgreSQL"
                }
            ),
        );
    }
    let Some(host) = ab.hostname.clone().filter(|h| !h.is_empty()) else {
        return error(StatusCode::BAD_REQUEST, "entry has no hostname");
    };
    let port = ab
        .port
        .unwrap_or(if protocol == "mysql" { 3306 } else { 5432 });
    let allowed = manager
        .config()
        .dbproxy
        .as_ref()
        .map(|c| c.allowed_networks.clone())
        .unwrap_or_default();
    let addr = match crate::session::allowed_address(&host, port, &allowed).await {
        Ok(ip) => ip,
        Err(e) => return error(StatusCode::FORBIDDEN, e.to_string()),
    };
    let sid = Uuid::new_v4().to_string();
    let s = DbSession {
        id: id.clone(),
        resource: res.clone(),
        client_ip: b.client_ip.clone(),
        started: now(),
    };
    sessions()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(sid.clone(), s.clone());
    let detail = json!({ "session": sid, "database": ab.database });
    let _ = with_db(&db, move |c| audit_row(c, "db_connect", &s, &detail)).await;
    tracing::info!(user = %id.display_name(), target = %res.label(), "Database proxy connection");
    let database = default_database(&ab);
    Json(json!({
        "session_id": sid,
        "actor": id.display_name(),
        "target": {
            "host": addr.to_string(),
            "port": port,
            "user": ab.username.unwrap_or_default(),
            "password": ab.password.unwrap_or_default(),
            "database": database,
        },
    }))
    .into_response()
}

fn session(id: &str) -> Result<DbSession, Response> {
    sessions()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "no such database session"))
}

#[derive(Deserialize)]
pub struct CheckBody {
    session_id: String,
    statement: String,
    #[serde(default)]
    classes: Vec<String>,
}

pub async fn check(
    State(manager): State<AppState>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Json(b): Json<CheckBody>,
) -> Response {
    if let Err(r) = proxy_authorized(&manager, &headers) {
        return r;
    }
    let s = match session(&b.session_id) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let classes: Vec<String> = b
        .classes
        .into_iter()
        .filter(|c| crate::policy::DB_CLASSES.contains(&c.as_str()))
        .collect();
    let statement: String = b.statement.chars().take(MAX_AUDIT_STATEMENT * 4).collect();
    let decision = crate::policy::gate_db(
        &db,
        &s.id,
        s.resource.clone(),
        statement.clone(),
        classes.clone(),
        s.client_ip.clone(),
    )
    .await;
    let (decision, message, approval) = match decision {
        Ok(Gate::Allowed) => ("allow", String::new(), None),
        Ok(Gate::Denied { policy }) => (
            "deny",
            format!("statement denied by policy '{}'", policy),
            None,
        ),
        Ok(Gate::Pending(req)) => (
            "pending",
            format!(
                "statement held for approval (request {}, policy '{}'); run it again once a person approves it",
                req.id, req.policy_name
            ),
            Some(req.id.clone()),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Policy check failed for a statement");
            ("deny", "policy check failed; try again later".into(), None)
        }
    };
    if decision != "allow" {
        let detail = json!({
            "session": b.session_id,
            "statement": statement.chars().take(MAX_AUDIT_STATEMENT).collect::<String>(),
            "classes": classes,
            "decision": decision,
        });
        let _ = with_db(&db, move |c| audit_row(c, "db_query_blocked", &s, &detail)).await;
    }
    Json(json!({ "decision": decision, "message": message, "approval_id": approval }))
        .into_response()
}

#[derive(Deserialize)]
pub struct AuditBody {
    session_id: String,
    statement: String,
    #[serde(default)]
    classes: Vec<String>,
    /// ok | error | refused (the proxy would not pass it, e.g. unparseable)
    status: String,
    #[serde(default)]
    rows: Option<i64>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn audit(
    State(manager): State<AppState>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Json(b): Json<AuditBody>,
) -> Response {
    if let Err(r) = proxy_authorized(&manager, &headers) {
        return r;
    }
    let s = match session(&b.session_id) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let event = match b.status.as_str() {
        "ok" => "db_query",
        "refused" => "db_query_blocked",
        _ => "db_query_failed",
    };
    let detail = json!({
        "session": b.session_id,
        "statement": b.statement.chars().take(MAX_AUDIT_STATEMENT).collect::<String>(),
        "classes": b.classes,
        "rows": b.rows,
        "tag": b.tag,
        "error": b.error,
    });
    let _ = with_db(&db, move |c| audit_row(c, event, &s, &detail)).await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct DisconnectBody {
    session_id: String,
}

pub async fn disconnect(
    State(manager): State<AppState>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Json(b): Json<DisconnectBody>,
) -> Response {
    if let Err(r) = proxy_authorized(&manager, &headers) {
        return r;
    }
    let s = sessions()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&b.session_id);
    if let Some(s) = s {
        let detail = json!({ "session": b.session_id, "duration_secs": now() - s.started });
        let _ = with_db(&db, move |c| audit_row(c, "db_disconnect", &s, &detail)).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_belong_to_a_user_and_an_entry_and_expire() {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT, oidc_subject TEXT,
                 role TEXT, disabled INTEGER, created_at TEXT, last_login_at TEXT, oidc_groups TEXT);
             INSERT INTO users VALUES (1, 'op@x', '', NULL, 'operator', 0, '', NULL, 'dba');",
        )
        .unwrap();
        let ins = |t: &str, exp: i64| {
            c.execute(
                "INSERT INTO db_tokens VALUES (?1, 'op@x', NULL, 'shared', 'prod', 'pg', 0, ?2)",
                params![crate::db::hash_key(t), exp],
            )
            .unwrap();
        };
        ins("mbdb_good", now() + 60);
        ins("mbdb_old", now() - 1);
        let (id, res) = token_identity(&c, "mbdb_good").unwrap();
        assert_eq!(id.display_name(), "op@x");
        assert_eq!(id.groups(), &["dba".to_string()]);
        assert_eq!(res.label(), "shared/prod/pg");
        assert_eq!(token_identity(&c, "mbdb_old").err(), Some("token expired"));
        assert_eq!(token_identity(&c, "mbdb_nope").err(), Some("invalid token"));
        assert_eq!(token_identity(&c, "good").err(), Some("invalid token"));
        c.execute("UPDATE users SET disabled = 1", []).unwrap();
        assert_eq!(
            token_identity(&c, "mbdb_good").err(),
            Some("user is disabled")
        );
    }
}
