//! Admin API for AI agent keys:
//! - `GET /api/admin/ai-agents`: list (no key material);
//! - `POST /api/admin/ai-agents`: `{"name", "folders"?, "allowed_ips"?,
//!   "expires"?}`, answering the key once;
//! - `POST /api/admin/ai-agents/{name}/disable`, `/enable`;
//! - `DELETE /api/admin/ai-agents/{name}`.
//!
//! Each change goes to the policy audit log.

// Handlers return a `Response` as their error: that is the answer they give.
#![allow(clippy::result_large_err)]

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use super::agents;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::policy::store::{self, AuditEvent};

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn admin(identity: Option<Extension<AuthIdentity>>) -> Result<AuthIdentity, Response> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(id),
        _ => Err(error(StatusCode::FORBIDDEN, "admin role required")),
    }
}

async fn with_db<T: Send + 'static>(
    db: &Db,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, Response> + Send + 'static,
) -> Result<T, Response> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))?;
        f(&conn)
    })
    .await
    .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn audit(conn: &rusqlite::Connection, event: &str, by: &str, name: &str, detail: Option<&str>) {
    let target = format!("ai:{}", name);
    let row = AuditEvent {
        event,
        actor: by,
        target: &target,
        detail,
        ..Default::default()
    };
    if let Err(e) = store::audit(conn, &row, store::now_secs()) {
        tracing::warn!(error = %e, "Failed to audit an AI agent change");
    }
}

pub async fn list(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    match with_db(&db, |c| {
        agents::list(c).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    })
    .await
    {
        Ok(rows) => Json(json!(rows)).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct CreateBody {
    name: String,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    allowed_ips: Option<String>,
    #[serde(default)]
    expires: Option<String>,
}

pub async fn create(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Json(body): Json<CreateBody>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let folders = match agents::normalize_folders(body.folders) {
        Ok(f) => f,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let by = id.display_name().to_string();
    let name = body.name.trim().to_string();
    match with_db(&db, move |c| {
        let key = agents::create(
            c,
            &name,
            &folders,
            body.allowed_ips.as_deref(),
            body.expires.as_deref(),
            &by,
        )
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
        let detail = json!({ "folders": folders }).to_string();
        audit(c, "ai_agent_created", &by, &name, Some(&detail));
        let agent = agents::get(c, &name)
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok((key, agent))
    })
    .await
    {
        Ok((key, agent)) => (
            StatusCode::CREATED,
            Json(json!({ "key": key, "agent": agent })),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn change(
    identity: Option<Extension<AuthIdentity>>,
    db: Db,
    name: String,
    event: &'static str,
    f: fn(&rusqlite::Connection, &str) -> rusqlite::Result<bool>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let by = id.display_name().to_string();
    match with_db(&db, move |c| {
        let found =
            f(c, &name).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if found {
            audit(c, event, &by, &name, None);
        }
        Ok(found)
    })
    .await
    {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such agent"),
        Err(r) => r,
    }
}

pub async fn delete(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(name): Path<String>,
) -> Response {
    change(identity, db, name, "ai_agent_deleted", agents::delete).await
}

pub async fn disable(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(name): Path<String>,
) -> Response {
    change(identity, db, name, "ai_agent_disabled", |c, n| {
        agents::set_disabled(c, n, true)
    })
    .await
}

pub async fn enable(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(name): Path<String>,
) -> Response {
    change(identity, db, name, "ai_agent_enabled", |c, n| {
        agents::set_disabled(c, n, false)
    })
    .await
}
