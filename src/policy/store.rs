//! Policies, approval requests and the policy audit log, in the main SQLite
//! database (`db_path`). Plain functions over a `Connection`; callers hold
//! the `Db` lock, from `spawn_blocking`.

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;

use super::{Action, Approver, Direction, Effect, Resource, Rule, Subject, Target};

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS policies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            subject         TEXT NOT NULL,
            target          TEXT NOT NULL,
            action          TEXT NOT NULL,
            effect          TEXT NOT NULL,
            approvers       TEXT NOT NULL DEFAULT '[]',
            grant_minutes   INTEGER NOT NULL DEFAULT 60,
            timeout_minutes INTEGER NOT NULL DEFAULT 30,
            enabled         INTEGER NOT NULL DEFAULT 1,
            commands        TEXT NOT NULL DEFAULT '[]',
            web_only        INTEGER NOT NULL DEFAULT 0,
            direction       TEXT,
            created_by      TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS approval_requests (
            id                TEXT PRIMARY KEY,
            requester         TEXT NOT NULL,
            requester_display TEXT NOT NULL,
            action            TEXT NOT NULL,
            resource          TEXT NOT NULL,
            resource_key      TEXT NOT NULL,
            target_label      TEXT NOT NULL,
            policy_id         INTEGER NOT NULL,
            policy_name       TEXT NOT NULL,
            approvers         TEXT NOT NULL,
            grant_minutes     INTEGER NOT NULL,
            reason            TEXT NOT NULL DEFAULT '',
            status            TEXT NOT NULL,
            created_at        INTEGER NOT NULL,
            expires_at        INTEGER NOT NULL,
            decided_at        INTEGER,
            decided_by        TEXT,
            comment           TEXT,
            grant_until       INTEGER,
            client_ip         TEXT,
            command           TEXT,
            web_only          INTEGER NOT NULL DEFAULT 0,
            break_glass       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS approval_requests_lookup
            ON approval_requests (requester, action, resource_key, status);

        CREATE TABLE IF NOT EXISTS policy_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            at          INTEGER NOT NULL,
            event       TEXT NOT NULL,
            actor       TEXT NOT NULL,
            requester   TEXT NOT NULL DEFAULT '',
            action      TEXT NOT NULL DEFAULT '',
            target      TEXT NOT NULL DEFAULT '',
            policy      TEXT,
            effect      TEXT,
            approval_id TEXT,
            detail      TEXT,
            ip          TEXT
        );",
    )?;
    for (table, column, decl) in [
        ("policies", "commands", "TEXT NOT NULL DEFAULT '[]'"),
        ("approval_requests", "command", "TEXT"),
        ("policies", "web_only", "INTEGER NOT NULL DEFAULT 0"),
        (
            "approval_requests",
            "web_only",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("policies", "direction", "TEXT"),
        (
            "approval_requests",
            "break_glass",
            "INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        add_column(conn, table, column, decl)?;
    }
    Ok(())
}

/// Add a column to a table made before it existed.
fn add_column(conn: &Connection, table: &str, column: &str, decl: &str) -> rusqlite::Result<()> {
    let has = conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{table}') WHERE name = '{column}'"
        ))?
        .exists([])?;
    if !has {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        )?;
    }
    Ok(())
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn json_err(e: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

fn from_json<T: serde::de::DeserializeOwned>(col: usize, s: String) -> rusqlite::Result<T> {
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn bad_value(col: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        col,
        rusqlite::types::Type::Text,
        format!("unknown {}", what).into(),
    )
}

// ── Policies ──

const RULE_COLS: &str = "id, name, subject, target, action, effect, approvers, grant_minutes,
    timeout_minutes, enabled, commands, web_only, direction";

fn rule_from_row(r: &Row) -> rusqlite::Result<Rule> {
    let action: String = r.get(4)?;
    let effect: String = r.get(5)?;
    Ok(Rule {
        id: r.get(0)?,
        name: r.get(1)?,
        subject: from_json::<Subject>(2, r.get(2)?)?,
        target: from_json::<Target>(3, r.get(3)?)?,
        action: Action::parse(&action).ok_or_else(|| bad_value(4, "action"))?,
        effect: Effect::parse(&effect).ok_or_else(|| bad_value(5, "effect"))?,
        approvers: from_json::<Vec<Approver>>(6, r.get(6)?)?,
        grant_minutes: r.get(7)?,
        timeout_minutes: r.get(8)?,
        enabled: r.get::<_, i64>(9)? != 0,
        commands: from_json::<Vec<String>>(10, r.get(10)?)?,
        web_only: r.get::<_, i64>(11)? != 0,
        direction: match r.get::<_, Option<String>>(12)? {
            None => None,
            Some(d) => Some(Direction::parse(&d).ok_or_else(|| bad_value(12, "direction"))?),
        },
    })
}

pub fn list_rules(conn: &Connection) -> rusqlite::Result<Vec<Rule>> {
    let mut stmt = conn.prepare(&format!("SELECT {RULE_COLS} FROM policies ORDER BY id"))?;
    let rows = stmt.query_map([], rule_from_row)?;
    rows.collect()
}

pub fn get_rule(conn: &Connection, id: i64) -> rusqlite::Result<Option<Rule>> {
    conn.query_row(
        &format!("SELECT {RULE_COLS} FROM policies WHERE id = ?1"),
        [id],
        rule_from_row,
    )
    .optional()
}

pub fn insert_rule(conn: &Connection, rule: &Rule, by: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO policies (name, subject, target, action, effect, approvers,
             grant_minutes, timeout_minutes, enabled, created_by, commands, web_only, direction)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            rule.name,
            serde_json::to_string(&rule.subject).map_err(json_err)?,
            serde_json::to_string(&rule.target).map_err(json_err)?,
            rule.action.as_str(),
            rule.effect.as_str(),
            serde_json::to_string(&rule.approvers).map_err(json_err)?,
            rule.grant_minutes,
            rule.timeout_minutes,
            rule.enabled as i64,
            by,
            serde_json::to_string(&rule.commands).map_err(json_err)?,
            rule.web_only as i64,
            rule.direction.map(Direction::as_str),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Replace rule `rule.id`. `false` when there is no such rule.
pub fn update_rule(conn: &Connection, rule: &Rule) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE policies SET name = ?1, subject = ?2, target = ?3, action = ?4, effect = ?5,
             approvers = ?6, grant_minutes = ?7, timeout_minutes = ?8, enabled = ?9,
             commands = ?11, web_only = ?12, direction = ?13, updated_at = datetime('now')
         WHERE id = ?10",
        params![
            rule.name,
            serde_json::to_string(&rule.subject).map_err(json_err)?,
            serde_json::to_string(&rule.target).map_err(json_err)?,
            rule.action.as_str(),
            rule.effect.as_str(),
            serde_json::to_string(&rule.approvers).map_err(json_err)?,
            rule.grant_minutes,
            rule.timeout_minutes,
            rule.enabled as i64,
            rule.id,
            serde_json::to_string(&rule.commands).map_err(json_err)?,
            rule.web_only as i64,
            rule.direction.map(Direction::as_str),
        ],
    )?;
    Ok(n > 0)
}

pub fn delete_rule(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM policies WHERE id = ?1", [id])? > 0)
}

// ── Approval requests ──

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequest {
    pub id: String,
    /// `Requester::id()`: a lowercased email, or `api-key:<name>`.
    pub requester: String,
    pub requester_display: String,
    pub action: String,
    pub resource: Resource,
    pub target_label: String,
    pub policy_id: i64,
    pub policy_name: String,
    pub approvers: Vec<Approver>,
    pub grant_minutes: u32,
    pub reason: String,
    /// pending | approved | denied | expired | cancelled
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub comment: Option<String>,
    pub grant_until: Option<i64>,
    pub client_ip: Option<String>,
    /// For `ssh_command`: the command waiting for approval.
    pub command: Option<String>,
    /// From the policy: decided on the web UI after a fresh sign-in only;
    /// Telegram just notifies.
    pub web_only: bool,
    /// An admin's own override with a reason, granted on the spot.
    pub break_glass: bool,
}

const REQ_COLS: &str = "id, requester, requester_display, action, resource, target_label,
    policy_id, policy_name, approvers, grant_minutes, reason, status, created_at, expires_at,
    decided_at, decided_by, comment, grant_until, client_ip, command, web_only, break_glass";

fn request_from_row(r: &Row) -> rusqlite::Result<ApprovalRequest> {
    Ok(ApprovalRequest {
        id: r.get(0)?,
        requester: r.get(1)?,
        requester_display: r.get(2)?,
        action: r.get(3)?,
        resource: from_json::<Resource>(4, r.get(4)?)?,
        target_label: r.get(5)?,
        policy_id: r.get(6)?,
        policy_name: r.get(7)?,
        approvers: from_json::<Vec<Approver>>(8, r.get(8)?)?,
        grant_minutes: r.get(9)?,
        reason: r.get(10)?,
        status: r.get(11)?,
        created_at: r.get(12)?,
        expires_at: r.get(13)?,
        decided_at: r.get(14)?,
        decided_by: r.get(15)?,
        comment: r.get(16)?,
        grant_until: r.get(17)?,
        client_ip: r.get(18)?,
        command: r.get(19)?,
        web_only: r.get::<_, i64>(20)? != 0,
        break_glass: r.get::<_, i64>(21)? != 0,
    })
}

pub fn create_request(conn: &Connection, req: &ApprovalRequest) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO approval_requests (id, requester, requester_display, action, resource,
             resource_key, target_label, policy_id, policy_name, approvers, grant_minutes,
             reason, status, created_at, expires_at, client_ip, command, web_only,
             decided_at, decided_by, comment, grant_until, break_glass)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                 ?19, ?20, ?21, ?22, ?23)",
        params![
            req.id,
            req.requester,
            req.requester_display,
            req.action,
            serde_json::to_string(&req.resource).map_err(json_err)?,
            req.resource.key_for(req.command.as_deref()),
            req.target_label,
            req.policy_id,
            req.policy_name,
            serde_json::to_string(&req.approvers).map_err(json_err)?,
            req.grant_minutes,
            req.reason,
            req.status,
            req.created_at,
            req.expires_at,
            req.client_ip,
            req.command,
            req.web_only as i64,
            req.decided_at,
            req.decided_by,
            req.comment,
            req.grant_until,
            req.break_glass as i64,
        ],
    )?;
    Ok(())
}

pub fn get_request(conn: &Connection, id: &str) -> rusqlite::Result<Option<ApprovalRequest>> {
    conn.query_row(
        &format!("SELECT {REQ_COLS} FROM approval_requests WHERE id = ?1"),
        [id],
        request_from_row,
    )
    .optional()
}

/// An approval for `requester` doing `action` on `key` that still lets them in.
pub fn active_grant(
    conn: &Connection,
    requester: &str,
    action: Action,
    key: &str,
    now: i64,
) -> rusqlite::Result<Option<ApprovalRequest>> {
    grant_query(conn, requester, action, key, now, false)
}

/// A live break-glass grant: the only kind that also overrides a deny.
pub fn active_break_glass(
    conn: &Connection,
    requester: &str,
    action: Action,
    key: &str,
    now: i64,
) -> rusqlite::Result<Option<ApprovalRequest>> {
    grant_query(conn, requester, action, key, now, true)
}

fn grant_query(
    conn: &Connection,
    requester: &str,
    action: Action,
    key: &str,
    now: i64,
    break_glass_only: bool,
) -> rusqlite::Result<Option<ApprovalRequest>> {
    conn.query_row(
        &format!(
            "SELECT {REQ_COLS} FROM approval_requests
             WHERE requester = ?1 AND action = ?2 AND resource_key = ?3
               AND status = 'approved' AND grant_until > ?4
               AND (?5 = 0 OR break_glass = 1)
             ORDER BY grant_until DESC LIMIT 1"
        ),
        params![
            requester,
            action.as_str(),
            key,
            now,
            break_glass_only as i64
        ],
        request_from_row,
    )
    .optional()
}

/// Withdraw the requests still waiting for this; their ids.
pub fn cancel_open(
    conn: &Connection,
    requester: &str,
    action: Action,
    key: &str,
    now: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "UPDATE approval_requests SET status = 'cancelled', decided_at = ?4, decided_by = ?1
         WHERE requester = ?1 AND action = ?2 AND resource_key = ?3 AND status = 'pending'
         RETURNING id",
    )?;
    let ids = stmt.query_map(params![requester, action.as_str(), key, now], |r| r.get(0))?;
    ids.collect()
}

/// A request already waiting for the same thing, so a retried connect does
/// not open a second one.
pub fn open_request(
    conn: &Connection,
    requester: &str,
    action: Action,
    key: &str,
    now: i64,
) -> rusqlite::Result<Option<ApprovalRequest>> {
    conn.query_row(
        &format!(
            "SELECT {REQ_COLS} FROM approval_requests
             WHERE requester = ?1 AND action = ?2 AND resource_key = ?3
               AND status = 'pending' AND expires_at > ?4
             ORDER BY created_at DESC LIMIT 1"
        ),
        params![requester, action.as_str(), key, now],
        request_from_row,
    )
    .optional()
}

/// Newest first; `status` narrows to one status.
pub fn list_requests(
    conn: &Connection,
    status: Option<&str>,
    limit: u32,
) -> rusqlite::Result<Vec<ApprovalRequest>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {REQ_COLS} FROM approval_requests
         WHERE ?1 IS NULL OR status = ?1
         ORDER BY created_at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![status, limit], request_from_row)?;
    rows.collect()
}

/// The requester adds or changes their reason while the request waits.
pub fn set_reason(
    conn: &Connection,
    id: &str,
    requester: &str,
    reason: &str,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE approval_requests SET reason = ?3
         WHERE id = ?1 AND requester = ?2 AND status = 'pending'",
        params![id, requester, reason],
    )? > 0)
}

/// Approve or deny a pending request. Errors (for the decider): not found,
/// already decided, or expired (which also marks it expired).
pub fn decide(
    conn: &Connection,
    id: &str,
    approve: bool,
    by: &str,
    comment: &str,
    now: i64,
) -> Result<ApprovalRequest, String> {
    let req = get_request(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("no such request")?;
    if req.status != "pending" {
        return Err(format!("request is already {}", req.status));
    }
    if req.expires_at <= now {
        conn.execute(
            "UPDATE approval_requests SET status = 'expired' WHERE id = ?1 AND status = 'pending'",
            [id],
        )
        .map_err(|e| e.to_string())?;
        return Err("request has expired".into());
    }
    let status = if approve { "approved" } else { "denied" };
    let grant_until = approve.then(|| now + i64::from(req.grant_minutes) * 60);
    let n = conn
        .execute(
            "UPDATE approval_requests
             SET status = ?2, decided_at = ?3, decided_by = ?4, comment = ?5, grant_until = ?6
             WHERE id = ?1 AND status = 'pending'",
            params![id, status, now, by, comment, grant_until],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("request was decided by someone else".into());
    }
    get_request(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no such request".into())
}

/// The requester withdraws a pending request.
pub fn cancel(conn: &Connection, id: &str, requester: &str, now: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE approval_requests SET status = 'cancelled', decided_at = ?3, decided_by = ?2
         WHERE id = ?1 AND requester = ?2 AND status = 'pending'",
        params![id, requester, now],
    )? > 0)
}

/// Mark every pending request past its deadline as expired; returns them.
pub fn expire_due(conn: &Connection, now: i64) -> rusqlite::Result<Vec<ApprovalRequest>> {
    let due: Vec<ApprovalRequest> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT {REQ_COLS} FROM approval_requests WHERE status = 'pending' AND expires_at <= ?1"
        ))?;
        let rows = stmt.query_map([now], request_from_row)?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    conn.execute(
        "UPDATE approval_requests SET status = 'expired', decided_at = ?1
         WHERE status = 'pending' AND expires_at <= ?1",
        [now],
    )?;
    Ok(due)
}

// ── Audit ──

#[derive(Debug, Default)]
pub struct AuditEvent<'a> {
    /// denied | requested | approved | approval_denied | expired | cancelled |
    /// allowed_by_grant | alert | policy_created | policy_updated | policy_deleted
    pub event: &'a str,
    /// Who caused it: the requester, the approver, the admin, or "system".
    pub actor: &'a str,
    pub requester: &'a str,
    pub action: &'a str,
    pub target: &'a str,
    pub policy: Option<&'a str>,
    pub effect: Option<&'a str>,
    pub approval_id: Option<&'a str>,
    pub detail: Option<&'a str>,
    pub ip: Option<&'a str>,
}

pub fn audit(conn: &Connection, e: &AuditEvent, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO policy_audit_log (at, event, actor, requester, action, target, policy,
             effect, approval_id, detail, ip)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            now,
            e.event,
            e.actor,
            e.requester,
            e.action,
            e.target,
            e.policy,
            e.effect,
            e.approval_id,
            e.detail,
            e.ip
        ],
    )?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub at: i64,
    pub event: String,
    pub actor: String,
    pub requester: String,
    pub action: String,
    pub target: String,
    pub policy: Option<String>,
    pub effect: Option<String>,
    pub approval_id: Option<String>,
    pub detail: Option<String>,
    pub ip: Option<String>,
}

pub fn list_audit(conn: &Connection, limit: u32) -> rusqlite::Result<Vec<AuditRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, at, event, actor, requester, action, target, policy, effect, approval_id,
             detail, ip
         FROM policy_audit_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok(AuditRow {
            id: r.get(0)?,
            at: r.get(1)?,
            event: r.get(2)?,
            actor: r.get(3)?,
            requester: r.get(4)?,
            action: r.get(5)?,
            target: r.get(6)?,
            policy: r.get(7)?,
            effect: r.get(8)?,
            approval_id: r.get(9)?,
            detail: r.get(10)?,
            ip: r.get(11)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    fn sample_rule() -> Rule {
        Rule {
            id: 0,
            name: "contractors to prod".into(),
            subject: Subject::Group("contractors".into()),
            target: Target::Folder {
                scope: "shared".into(),
                path: "prod".into(),
            },
            action: Action::Connect,
            effect: Effect::RequireApproval,
            approvers: vec![Approver::Role("admin".into())],
            grant_minutes: 60,
            timeout_minutes: 30,
            enabled: true,
            commands: vec![],
            web_only: false,
            direction: None,
        }
    }

    fn sample_request(id: &str, now: i64) -> ApprovalRequest {
        ApprovalRequest {
            id: id.into(),
            requester: "c@x".into(),
            requester_display: "c@x".into(),
            action: "connect".into(),
            resource: Resource::Entry {
                scope: "shared".into(),
                folder: "prod".into(),
                entry: "web01".into(),
            },
            target_label: "shared/prod/web01".into(),
            policy_id: 1,
            policy_name: "contractors to prod".into(),
            approvers: vec![Approver::Role("admin".into())],
            grant_minutes: 60,
            reason: String::new(),
            status: "pending".into(),
            created_at: now,
            expires_at: now + 1800,
            decided_at: None,
            decided_by: None,
            comment: None,
            grant_until: None,
            client_ip: Some("192.0.2.1".into()),
            command: None,
            web_only: false,
            break_glass: false,
        }
    }

    #[test]
    fn rules_round_trip() {
        let c = conn();
        let id = insert_rule(&c, &sample_rule(), "admin@x").unwrap();
        let mut r = get_rule(&c, id).unwrap().unwrap();
        assert_eq!(r.subject, Subject::Group("contractors".into()));
        assert_eq!(r.approvers, vec![Approver::Role("admin".into())]);
        r.enabled = false;
        r.effect = Effect::Deny;
        assert!(update_rule(&c, &r).unwrap());
        let all = list_rules(&c).unwrap();
        assert_eq!(
            (all.len(), all[0].enabled, all[0].effect),
            (1, false, Effect::Deny)
        );
        assert!(delete_rule(&c, id).unwrap());
        assert!(!delete_rule(&c, id).unwrap());
    }

    #[test]
    fn approve_grants_access_for_the_window() {
        let c = conn();
        let now = 1_000_000;
        create_request(&c, &sample_request("r1", now)).unwrap();
        let key = "entry:shared/prod/web01";
        assert!(open_request(&c, "c@x", Action::Connect, key, now)
            .unwrap()
            .is_some());
        assert!(active_grant(&c, "c@x", Action::Connect, key, now)
            .unwrap()
            .is_none());

        let done = decide(&c, "r1", true, "boss@x", "ok", now + 10).unwrap();
        assert_eq!(done.status, "approved");
        assert_eq!(done.grant_until, Some(now + 10 + 3600));
        assert!(active_grant(&c, "c@x", Action::Connect, key, now + 100)
            .unwrap()
            .is_some());
        assert!(
            active_grant(&c, "c@x", Action::Connect, key, now + 10 + 3600)
                .unwrap()
                .is_none()
        );
        // Someone else's grant is not yours.
        assert!(active_grant(&c, "d@x", Action::Connect, key, now + 100)
            .unwrap()
            .is_none());
        // Decided once only.
        assert!(decide(&c, "r1", false, "boss@x", "", now + 20)
            .unwrap_err()
            .contains("already"));
    }

    #[test]
    fn requests_expire() {
        let c = conn();
        let now = 1_000_000;
        create_request(&c, &sample_request("r1", now)).unwrap();
        create_request(&c, &sample_request("r2", now)).unwrap();
        // Deciding after the deadline fails and marks it expired.
        let e = decide(&c, "r1", true, "boss@x", "", now + 1800).unwrap_err();
        assert!(e.contains("expired"), "{e}");
        assert_eq!(get_request(&c, "r1").unwrap().unwrap().status, "expired");
        // The reaper picks up the rest.
        let due = expire_due(&c, now + 1801).unwrap();
        assert_eq!(
            due.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["r2"]
        );
        assert!(expire_due(&c, now + 1802).unwrap().is_empty());
    }

    #[test]
    fn reason_and_cancel_are_the_requesters_alone() {
        let c = conn();
        let now = 1_000_000;
        create_request(&c, &sample_request("r1", now)).unwrap();
        assert!(!set_reason(&c, "r1", "someone@x", "mine").unwrap());
        assert!(set_reason(&c, "r1", "c@x", "patching").unwrap());
        assert_eq!(get_request(&c, "r1").unwrap().unwrap().reason, "patching");
        assert!(!cancel(&c, "r1", "someone@x", now).unwrap());
        assert!(cancel(&c, "r1", "c@x", now).unwrap());
        assert!(decide(&c, "r1", true, "boss@x", "", now).is_err());
    }

    #[test]
    fn older_tables_gain_the_new_columns() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE policies (id INTEGER PRIMARY KEY, name TEXT, subject TEXT, target TEXT,
                 action TEXT, effect TEXT, approvers TEXT, grant_minutes INTEGER,
                 timeout_minutes INTEGER, enabled INTEGER, created_by TEXT,
                 created_at TEXT, updated_at TEXT);
             CREATE TABLE approval_requests (id TEXT PRIMARY KEY, requester TEXT,
                 requester_display TEXT, action TEXT, resource TEXT, resource_key TEXT,
                 target_label TEXT, policy_id INTEGER, policy_name TEXT, approvers TEXT,
                 grant_minutes INTEGER, reason TEXT, status TEXT, created_at INTEGER,
                 expires_at INTEGER, decided_at INTEGER, decided_by TEXT, comment TEXT,
                 grant_until INTEGER, client_ip TEXT);",
        )
        .unwrap();
        migrate(&c).unwrap();
        migrate(&c).unwrap();
        insert_rule(&c, &sample_rule(), "a").unwrap();
        let rule = &list_rules(&c).unwrap()[0];
        assert!(rule.commands.is_empty() && !rule.web_only);
        let mut req = sample_request("r1", 10);
        req.command = Some("uptime".into());
        req.web_only = true;
        create_request(&c, &req).unwrap();
        let got = get_request(&c, "r1").unwrap().unwrap();
        assert_eq!(
            (got.command.as_deref(), got.web_only),
            (Some("uptime"), true)
        );
    }

    #[test]
    fn audit_rows_keep_requester_and_actor() {
        let c = conn();
        audit(
            &c,
            &AuditEvent {
                event: "approved",
                actor: "boss@x",
                requester: "c@x",
                action: "connect",
                target: "shared/prod/web01",
                policy: Some("contractors to prod"),
                approval_id: Some("r1"),
                ..Default::default()
            },
            42,
        )
        .unwrap();
        let rows = list_audit(&c, 10).unwrap();
        assert_eq!(
            (
                rows[0].actor.as_str(),
                rows[0].requester.as_str(),
                rows[0].at
            ),
            ("boss@x", "c@x", 42)
        );
    }
}
