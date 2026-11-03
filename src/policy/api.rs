//! HTTP handlers for policies and approvals.
//!
//! - `GET/POST /api/admin/policies`, `PUT/DELETE /api/admin/policies/{id}`,
//!   `GET /api/admin/policy-audit`: admin only.
//! - `GET /api/approvals`: requests the caller can decide, and their own.
//! - `GET /api/approvals/{id}`, `POST /api/approvals/{id}/{reason,approve,deny,cancel}`.
//!
//! Connect routes call `connect_gate` before creating a session.

// Handlers return a `Response` as their error: that is the answer they give.
#![allow(clippy::result_large_err)]

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use super::store::{self, ApprovalRequest, AuditEvent};
use super::{gate, may_decide, Action, Gate, Requester, Resource, Rule};
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

/// What a connect route returns instead of a session, or `None` to go
/// ahead: 403 when a policy denies it, 202 with the approval request when it
/// waits for one. A failed check refuses rather than letting it through.
pub async fn connect_gate(
    db: &Db,
    id: &AuthIdentity,
    res: Resource,
    ip: String,
) -> Option<Response> {
    match gate(db, id, Action::Connect, res, None, ip).await {
        Ok(Gate::Allowed) => None,
        Ok(Gate::Denied { policy }) => Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!("denied by policy '{}'", policy),
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
            tracing::error!(error = %e, "Policy check failed; refusing the connect");
            Some(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "policy check failed; try again or ask an admin",
            ))
        }
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
    match with_db(&db, move |c| {
        store::set_reason(c, &req_id, &rid, &reason).map_err(|e| e.to_string())
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

#[derive(Deserialize, Default)]
pub struct DecisionBody {
    #[serde(default)]
    comment: String,
}

async fn decide(
    identity: Option<Extension<AuthIdentity>>,
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
    let result = with_db(&db, move |c| {
        let Some(req) = store::get_request(c, &req_id).map_err(|e| e.to_string())? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such request".to_string())));
        };
        if let Err(e) = may_decide(&req.approvers, &who, &req.requester) {
            return Ok(Err((StatusCode::FORBIDDEN, e)));
        }
        let now = store::now_secs();
        match store::decide(c, &req_id, approve, &by, &comment, now) {
            Ok(done) => {
                store::audit(
                    c,
                    &AuditEvent {
                        event: if approve {
                            "approved"
                        } else {
                            "approval_denied"
                        },
                        actor: &by,
                        requester: &done.requester,
                        action: &done.action,
                        target: &done.target_label,
                        policy: Some(&done.policy_name),
                        approval_id: Some(&done.id),
                        detail: (!comment.is_empty()).then_some(comment.as_str()),
                        ..Default::default()
                    },
                    now,
                )
                .map_err(|e| e.to_string())?;
                Ok(Ok(done))
            }
            Err(e) => Ok(Err((StatusCode::CONFLICT, e))),
        }
    })
    .await;
    match result {
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
        Ok(Err((status, msg))) => error(status, msg),
        Err(r) => r,
    }
}

pub async fn approve(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        identity,
        db,
        req_id,
        body.map(|Json(b)| b).unwrap_or_default(),
        true,
    )
    .await
}

pub async fn deny(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Path(req_id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    decide(
        identity,
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
