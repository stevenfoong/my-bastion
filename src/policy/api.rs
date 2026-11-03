//! HTTP handlers for policies and approvals.
//!
//! - `GET/POST /api/admin/policies`, `PUT/DELETE /api/admin/policies/{id}`,
//!   `GET /api/admin/policy-audit`, `GET /api/admin/ssh-commands`: admin only.
//! - `GET /api/approvals`: requests the caller can decide, and their own.
//! - `GET /api/approvals/{id}`, `POST /api/approvals/{id}/{reason,approve,deny,cancel}`.
//! - `POST /api/break-glass`: an admin's own override, with a reason.
//!
//! Connect routes call `connect_gate` before creating a session.

// Handlers return a `Response` as their error: that is the answer they give.
#![allow(clippy::result_large_err)]

use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use super::store::{self, ApprovalRequest, AuditEvent};
use super::{
    break_glass, decide_request, gate, may_decide, session_controls, Action, DecideError, Gate,
    Requester, Resource, Rule, SessionControls, Via, BREAK_GLASS_MINUTES, FRESH_SIGNIN_SECS,
    MIN_BREAK_GLASS_REASON,
};
use crate::auth::AuthIdentity;
use crate::db::Db;

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// Run `f` on the database from a blocking thread.
async fn with_db<T: Send + 'static>(
    db: &Db,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, String> + Send + 'static,
) -> Result<T, Response> {
    let db = db.clone();
    match tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        f(&conn)
    })
    .await
    {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, e)),
        Err(e) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

fn caller(identity: Option<Extension<AuthIdentity>>) -> Result<AuthIdentity, Response> {
    identity
        .map(|Extension(id)| id)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "authentication required"))
}

fn admin(identity: Option<Extension<AuthIdentity>>) -> Result<AuthIdentity, Response> {
    let id = caller(identity)?;
    if id.has_role("admin") {
        Ok(id)
    } else {
        Err(error(StatusCode::FORBIDDEN, "admin role required"))
    }
}

/// The policy check of a connect route. Going ahead, it answers the
/// session's clipboard and file transfer controls; otherwise the response
/// to give instead: 403 when a policy denies it, 202 with the approval
/// request when it waits for one. A failed check refuses rather than
/// letting it through.
pub async fn connect_gate(
    db: &Db,
    id: &AuthIdentity,
    res: Resource,
    ip: String,
) -> Result<SessionControls, Response> {
    let failed = |e: String| {
        tracing::error!(error = %e, "Policy check failed; refusing the connect");
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "policy check failed; try again or ask an admin",
        )
    };
    match gate(db, id, Action::Connect, res.clone(), None, ip).await {
        Ok(Gate::Allowed) => session_controls(db, id, res).await.map_err(failed),
        Ok(Gate::Denied { policy }) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!("denied by policy '{}'", policy),
                "policy": policy,
            })),
        )
            .into_response()),
        Ok(Gate::Pending(req)) => Err((
            StatusCode::ACCEPTED,
            Json(json!({ "approval_required": true, "approval": req })),
        )
            .into_response()),
        Err(e) => Err(failed(e)),
    }
}

/// `connect_gate` for a command run through the bastion: the policy check
/// covers the exact command, and so does an approval.
pub async fn command_gate(
    db: &Db,
    id: &AuthIdentity,
    res: Resource,
    command: &str,
    ip: String,
) -> Option<Response> {
    match gate(
        db,
        id,
        Action::SshCommand,
        res,
        Some(command.to_string()),
        ip,
    )
    .await
    {
        Ok(Gate::Allowed) => None,
        Ok(Gate::Denied { policy }) => Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!("command denied by policy '{}'", policy),
                    "policy": policy,
                })),
            )
                .into_response(),
        ),
        Ok(Gate::Pending(req)) => Some(
            (
                StatusCode::ACCEPTED,
                Json(json!({ "approval_required": true, "approval": req })),
            )
                .into_response(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Policy check failed; refusing the command");
            Some(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "policy check failed; try again or ask an admin",
            ))
        }
    }
}

// ── Policies (admin) ──

pub async fn list_policies(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    match with_db(&db, |c| store::list_rules(c).map_err(|e| e.to_string())).await {
        Ok(rules) => Json(json!(rules)).into_response(),
        Err(r) => r,
    }
}

fn policy_event<'a>(event: &'a str, actor: &'a str, rule: &'a Rule) -> AuditEvent<'a> {
    AuditEvent {
        event,
        actor,
        action: rule.action.as_str(),
        policy: Some(&rule.name),
        effect: Some(rule.effect.as_str()),
        ..Default::default()
    }
}

pub async fn create_policy(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Json(mut rule): Json<Rule>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    if let Err(e) = rule.validate() {
        return error(StatusCode::BAD_REQUEST, e);
    }
    let by = id.display_name().to_string();
    match with_db(&db, move |c| {
        rule.id = store::insert_rule(c, &rule, &by).map_err(|e| e.to_string())?;
        store::audit(
            c,
            &policy_event("policy_created", &by, &rule),
            store::now_secs(),
        )
        .map_err(|e| e.to_string())?;
        Ok(rule)
    })
    .await
    {
        Ok(rule) => (StatusCode::CREATED, Json(json!(rule))).into_response(),
        Err(r) => r,
    }
}

pub async fn update_policy(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(policy_id): Path<i64>,
    Json(mut rule): Json<Rule>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    rule.id = policy_id;
    if let Err(e) = rule.validate() {
        return error(StatusCode::BAD_REQUEST, e);
    }
    let by = id.display_name().to_string();
    match with_db(&db, move |c| {
        if !store::update_rule(c, &rule).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        store::audit(
            c,
            &policy_event("policy_updated", &by, &rule),
            store::now_secs(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Some(rule))
    })
    .await
    {
        Ok(Some(rule)) => Json(json!(rule)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such policy"),
        Err(r) => r,
    }
}

pub async fn delete_policy(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(policy_id): Path<i64>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let by = id.display_name().to_string();
    match with_db(&db, move |c| {
        let Some(rule) = store::get_rule(c, policy_id).map_err(|e| e.to_string())? else {
            return Ok(false);
        };
        store::delete_rule(c, policy_id).map_err(|e| e.to_string())?;
        store::audit(
            c,
            &policy_event("policy_deleted", &by, &rule),
            store::now_secs(),
        )
        .map_err(|e| e.to_string())?;
        Ok(true)
    })
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such policy"),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct LimitQuery {
    limit: Option<u32>,
}

pub async fn policy_audit(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Query(q): Query<LimitQuery>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    let limit = q.limit.unwrap_or(200).min(1000);
    match with_db(&db, move |c| {
        store::list_audit(c, limit).map_err(|e| e.to_string())
    })
    .await
    {
        Ok(rows) => Json(json!(rows)).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct CommandQuery {
    session_id: Option<String>,
    q: Option<String>,
    #[serde(default)]
    alerts: bool,
    limit: Option<u32>,
}

/// GET /api/admin/ssh-commands: lines typed in interactive SSH sessions,
/// newest first; `session_id`, `q` (text search) and `alerts=true` narrow.
pub async fn ssh_commands(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Query(q): Query<CommandQuery>,
) -> Response {
    if let Err(r) = admin(identity) {
        return r;
    }
    let limit = q.limit.unwrap_or(200).min(1000);
    let blank = |s: Option<String>| s.filter(|s| !s.trim().is_empty());
    let (session, text) = (blank(q.session_id), blank(q.q));
    match with_db(&db, move |c| {
        super::keylog::list(c, session.as_deref(), text.as_deref(), q.alerts, limit)
            .map_err(|e| e.to_string())
    })
    .await
    {
        Ok(rows) => Json(json!(rows)).into_response(),
        Err(r) => r,
    }
}

// ── Approvals ──

/// Whether `who` may see `req`: its requester, anyone who may decide it,
/// and admins.
fn may_see(req: &ApprovalRequest, id: &AuthIdentity, who: &Requester) -> bool {
    who.id() == req.requester
        || id.has_role("admin")
        || may_decide(&req.approvers, who, &req.requester).is_ok()
}

/// GET /api/approvals — `to_decide`: pending requests the caller may
/// decide; `mine`: the caller's own; `recent`: everything, for admins.
pub async fn list_approvals(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    let id = match caller(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let who = Requester::from_identity(&id);
    let is_admin = id.has_role("admin");
    match with_db(&db, |c| {
        store::list_requests(c, None, 500).map_err(|e| e.to_string())
    })
    .await
    {
        Ok(all) => {
            let now = store::now_secs();
            let to_decide: Vec<&ApprovalRequest> = all
                .iter()
                .filter(|r| r.status == "pending" && r.expires_at > now)
                .filter(|r| may_decide(&r.approvers, &who, &r.requester).is_ok())
                .collect();
            let mine: Vec<&ApprovalRequest> = all
                .iter()
                .filter(|r| r.requester == who.id())
                .take(50)
                .collect();
            let recent: Vec<&ApprovalRequest> = if is_admin {
                all.iter().take(100).collect()
            } else {
                Vec::new()
            };
            Json(json!({ "to_decide": to_decide, "mine": mine, "recent": recent })).into_response()
        }
        Err(r) => r,
    }
}

async fn load_visible(
    db: &Db,
    id: &AuthIdentity,
    req_id: String,
) -> Result<ApprovalRequest, Response> {
    let who = Requester::from_identity(id);
    let req = with_db(db, move |c| {
        store::get_request(c, &req_id).map_err(|e| e.to_string())
    })
    .await?;
    match req {
        Some(r) if may_see(&r, id, &who) => Ok(r),
        _ => Err(error(StatusCode::NOT_FOUND, "no such request")),
    }
}

pub async fn get_approval(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
) -> Response {
    let id = match caller(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    match load_visible(&db, &id, req_id).await {
        Ok(r) => Json(json!(r)).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct ReasonBody {
    reason: String,
}

/// POST /api/approvals/{id}/reason — the requester explains, while it waits.
pub async fn set_reason(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> Response {
    let id = match caller(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let reason: String = body.reason.trim().chars().take(500).collect();
    let rid = Requester::from_identity(&id).id();
    let rq = req_id.clone();
    match with_db(&db, move |c| {
        store::set_reason(c, &rq, &rid, &reason).map_err(|e| e.to_string())
    })
    .await
    {
        Ok(true) => {
            crate::telegram::notify(&req_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "no pending request of yours with that id",
        ),
        Err(r) => r,
    }
}

#[derive(Deserialize, Default)]
pub struct DecisionBody {
    #[serde(default)]
    comment: String,
}

async fn decide(
    identity: Option<Extension<AuthIdentity>>,
    headers: HeaderMap,
    db: Db,
    req_id: String,
    body: DecisionBody,
    approve: bool,
) -> Response {
    let id = match caller(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let who = Requester::from_identity(&id);
    let by = id.display_name().to_string();
    let comment: String = body.comment.trim().chars().take(500).collect();
    // A fresh sign-in is a web session cookie from the last few minutes; a
    // token or API key never counts.
    let session = crate::auth::cookie_value(&headers, "mybastion_session");
    let result = with_db(&db, move |c| {
        let now = store::now_secs();
        let fresh = session
            .and_then(|t| crate::db::auth_session_started(c, &t))
            .is_some_and(|at| now - at <= FRESH_SIGNIN_SECS);
        Ok(decide_request(
            c,
            &req_id,
            &who,
            &by,
            &comment,
            approve,
            Via::Web { fresh },
            now,
        ))
    })
    .await;
    match result {
        Ok(Err(DecideError::NotFound)) => error(StatusCode::NOT_FOUND, "no such request"),
        Ok(Err(DecideError::Forbidden(e))) => error(StatusCode::FORBIDDEN, e),
        Ok(Err(DecideError::NeedsFreshSignIn)) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "this request needs a fresh sign-in: sign out, sign in again and decide within 15 minutes",
                "fresh_signin_required": true,
            })),
        )
            .into_response(),
        Ok(Err(DecideError::Conflict(e))) => error(StatusCode::CONFLICT, e),
        Ok(Err(DecideError::Db(e))) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Ok(Ok(done)) => {
            tracing::info!(
                approver = %done.decided_by.as_deref().unwrap_or(""),
                requester = %done.requester,
                target = %done.target_label,
                status = %done.status,
                "Approval request decided"
            );
            Json(json!(done)).into_response()
        }
        Err(r) => r,
    }
}

pub async fn approve(
    identity: Option<Extension<AuthIdentity>>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        identity,
        headers,
        db,
        req_id,
        body.map(|Json(b)| b).unwrap_or_default(),
        true,
    )
    .await
}

pub async fn deny(
    identity: Option<Extension<AuthIdentity>>,
    headers: HeaderMap,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        identity,
        headers,
        db,
        req_id,
        body.map(|Json(b)| b).unwrap_or_default(),
        false,
    )
    .await
}

/// POST /api/approvals/{id}/cancel — the requester withdraws it.
pub async fn cancel(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
) -> Response {
    let id = match caller(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let rid = Requester::from_identity(&id).id();
    let by = id.display_name().to_string();
    match with_db(&db, move |c| {
        let now = store::now_secs();
        if !store::cancel(c, &req_id, &rid, now).map_err(|e| e.to_string())? {
            return Ok(false);
        }
        if let Some(r) = store::get_request(c, &req_id).map_err(|e| e.to_string())? {
            store::audit(
                c,
                &AuditEvent {
                    event: "cancelled",
                    actor: &by,
                    requester: &r.requester,
                    action: &r.action,
                    target: &r.target_label,
                    policy: Some(&r.policy_name),
                    approval_id: Some(&r.id),
                    ..Default::default()
                },
                now,
            )
            .map_err(|e| e.to_string())?;
            crate::telegram::notify(&r.id);
        }
        Ok(true)
    })
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "no pending request of yours with that id",
        ),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct BreakGlassBody {
    scope: String,
    folder: String,
    entry: String,
    /// `connect` (the default) or `ssh_command` with `command`.
    #[serde(default)]
    action: Option<Action>,
    #[serde(default)]
    command: Option<String>,
    reason: String,
}

/// POST /api/break-glass — an admin overrides policy for themself on one
/// entry for `BREAK_GLASS_MINUTES`, with a reason, after a fresh sign-in.
/// Always audited and sent to Telegram.
pub async fn break_glass_route(
    identity: Option<Extension<AuthIdentity>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    trusted: Option<Extension<crate::auth::TrustedProxies>>,
    Extension(db): Extension<Db>,
    Json(body): Json<BreakGlassBody>,
) -> Response {
    let id = match admin(identity) {
        Ok(id) => id,
        Err(r) => return r,
    };
    let who = Requester::from_identity(&id);
    if who.email.is_none() {
        return error(
            StatusCode::FORBIDDEN,
            "break-glass is for people, not API keys",
        );
    }
    let reason: String = body.reason.trim().chars().take(500).collect();
    if reason.chars().count() < MIN_BREAK_GLASS_REASON {
        return error(
            StatusCode::BAD_REQUEST,
            format!(
                "break-glass needs a reason of at least {} characters",
                MIN_BREAK_GLASS_REASON
            ),
        );
    }
    let action = body.action.unwrap_or(Action::Connect);
    let command = match (action, body.command) {
        (Action::Connect, None) => None,
        (Action::SshCommand, Some(c)) if !c.is_empty() => Some(c),
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "break-glass covers connect, or ssh_command with its command",
            )
        }
    };
    if body.folder.trim().is_empty() || body.entry.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "folder and entry are required");
    }
    let res = Resource::Entry {
        scope: body.scope,
        folder: body.folder,
        entry: body.entry,
    };
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = crate::auth::client_ip(&headers, addr.ip(), &proxies).to_string();
    let display = id.display_name().to_string();
    let session = crate::auth::cookie_value(&headers, "mybastion_session");
    let result = with_db(&db, move |c| {
        let now = store::now_secs();
        let fresh = session
            .and_then(|t| crate::db::auth_session_started(c, &t))
            .is_some_and(|at| now - at <= FRESH_SIGNIN_SECS);
        if !fresh {
            return Ok(Err(()));
        }
        break_glass(c, &who, &display, action, &res, command, &reason, &ip, now).map(Ok)
    })
    .await;
    match result {
        Ok(Ok(grant)) => Json(json!({
            "approval": grant,
            "minutes": BREAK_GLASS_MINUTES,
        }))
        .into_response(),
        Ok(Err(())) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "break-glass needs a fresh sign-in: sign out, sign in again and retry within 15 minutes",
                "fresh_signin_required": true,
            })),
        )
            .into_response(),
        Err(r) => r,
    }
}
