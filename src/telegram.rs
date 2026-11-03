//! Telegram approvals (Phase 2c of `docs/fork-design.md`).
//!
//! A bot posts each approval request to the configured chats and to the
//! linked approvers who may decide it, with Approve / Deny buttons, and
//! edits those messages as the request changes, so a group chat doubles as
//! a log. It long-polls `getUpdates`, so nothing listens for Telegram.
//!
//! - **Linking:** a user gets a one-time code on the Approvals page and sends
//!   it to the bot (`/link CODE`, or the `t.me/<bot>?start=CODE` link).
//! - **Decisions:** a button press counts only from a linked account whose
//!   user may decide that request (the same rules as the web UI, so never
//!   their own), and never for a web-only request.
//! - The bot token is read from the secret store (`bot_token_path`).
//!
//! Everything else calls `notify(request_id)` when a request is created or
//! changes, and `alert` for an interactive SSH command a policy flags (sent
//! to the `chat_ids` only); both do nothing unless `[telegram]` is enabled.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rand::RngExt;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::api::StoreCell;
use crate::auth::AuthIdentity;
use crate::config::TelegramConfig;
use crate::db::Db;
use crate::policy::store::{self, ApprovalRequest};
use crate::policy::{decide_request, may_decide, DecideError, Requester, Via};

/// What the delivery task has to send.
enum Outgoing {
    /// A request whose messages need sending or updating.
    Request(String),
    Command(CommandAlert),
}

static EVENTS: OnceLock<mpsc::UnboundedSender<Outgoing>> = OnceLock::new();
/// The bot's @username, once `getMe` has answered.
static BOT_USERNAME: OnceLock<String> = OnceLock::new();

/// How long a link code is good for.
const LINK_CODE_SECS: i64 = 10 * 60;
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LEN: usize = 10;
/// Commands longer than this are cut in messages (Telegram allows 4096).
const MAX_SHOWN_COMMAND: usize = 1000;

/// Request `request_id` was created or changed: send or update its messages.
pub fn notify(request_id: &str) {
    if let Some(tx) = EVENTS.get() {
        let _ = tx.send(Outgoing::Request(request_id.to_string()));
    }
}

/// An interactive SSH line a command rule flags.
#[derive(Debug, Clone)]
pub struct CommandAlert {
    pub actor: String,
    pub target: String,
    pub line: String,
    pub policy: String,
    /// The rule denies it (rather than holding or alerting).
    pub denied: bool,
    pub uncertain: bool,
}

/// Tell the `chat_ids` about a flagged SSH command.
pub fn alert(a: CommandAlert) {
    if let Some(tx) = EVENTS.get() {
        let _ = tx.send(Outgoing::Command(a));
    }
}

fn render_command_alert(a: &CommandAlert) -> String {
    let mut t = format!(
        "{} <b>SSH command flagged</b>\n<b>Who:</b> {}\n<b>On:</b> {}\n<b>Typed:</b> <code>{}</code>\n<b>Policy:</b> {}{}",
        if a.denied { "⛔" } else { "⚠️" },
        esc(&a.actor),
        esc(&a.target),
        esc(&a.line.chars().take(MAX_SHOWN_COMMAND).collect::<String>()),
        esc(&a.policy),
        if a.denied { " (would be denied in command mode)" } else { "" },
    );
    if a.uncertain {
        t += "\n<i>Rebuilt from keystrokes with completion or history: the shell may have run something else.</i>";
    }
    t
}

// ── Store ──

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS telegram_links (
            email             TEXT PRIMARY KEY,
            telegram_user_id  INTEGER NOT NULL UNIQUE,
            telegram_username TEXT,
            linked_at         INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS telegram_link_codes (
            code_hash  TEXT PRIMARY KEY,
            email      TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS telegram_messages (
            request_id TEXT NOT NULL,
            chat_id    INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            PRIMARY KEY (request_id, chat_id)
        );",
    )
}

fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.trim().to_ascii_uppercase().as_bytes()))
}

fn random_code() -> String {
    let mut code = String::with_capacity(CODE_LEN);
    let mut buf = [0u8; 32];
    // Reject bytes past the last whole multiple of the alphabet: no bias.
    let limit = (256 / CODE_ALPHABET.len() * CODE_ALPHABET.len()) as u8;
    while code.len() < CODE_LEN {
        rand::rng().fill(&mut buf);
        for b in buf.iter().filter(|b| **b < limit) {
            if code.len() == CODE_LEN {
                break;
            }
            code.push(CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char);
        }
    }
    code
}

/// A new one-time link code for `email`, replacing any earlier one.
fn new_link_code(conn: &Connection, email: &str, now: i64) -> rusqlite::Result<(String, i64)> {
    let code = random_code();
    let expires_at = now + LINK_CODE_SECS;
    conn.execute(
        "DELETE FROM telegram_link_codes WHERE email = ?1 OR expires_at <= ?2",
        params![email, now],
    )?;
    conn.execute(
        "INSERT INTO telegram_link_codes (code_hash, email, expires_at) VALUES (?1, ?2, ?3)",
        params![hash_code(&code), email, expires_at],
    )?;
    Ok((code, expires_at))
}

/// Use up `code` and link its user to this Telegram account, replacing
/// either side's earlier link. The linked email, or `None` for a code that
/// is unknown, used or expired.
fn redeem_link_code(
    conn: &Connection,
    code: &str,
    tg_user: i64,
    tg_username: Option<&str>,
    now: i64,
) -> rusqlite::Result<Option<String>> {
    let hash = hash_code(code);
    let email: Option<String> = conn
        .query_row(
            "SELECT email FROM telegram_link_codes WHERE code_hash = ?1 AND expires_at > ?2",
            params![hash, now],
            |r| r.get(0),
        )
        .optional()?;
    conn.execute(
        "DELETE FROM telegram_link_codes WHERE code_hash = ?1",
        [&hash],
    )?;
    let Some(email) = email else { return Ok(None) };
    conn.execute(
        "DELETE FROM telegram_links WHERE email = ?1 OR telegram_user_id = ?2",
        params![email, tg_user],
    )?;
    conn.execute(
        "INSERT INTO telegram_links (email, telegram_user_id, telegram_username, linked_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![email, tg_user, tg_username, now],
    )?;
    Ok(Some(email))
}

fn email_for(conn: &Connection, tg_user: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT email FROM telegram_links WHERE telegram_user_id = ?1",
        [tg_user],
        |r| r.get(0),
    )
    .optional()
}

/// The Telegram account linked to `email`: user id, @username, linked at.
fn link_of(conn: &Connection, email: &str) -> rusqlite::Result<Option<(i64, Option<String>, i64)>> {
    conn.query_row(
        "SELECT telegram_user_id, telegram_username, linked_at FROM telegram_links
         WHERE email = ?1",
        [email],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
}

/// Remove a link by email or Telegram user; the email it belonged to.
fn unlink(conn: &Connection, email: Option<&str>, tg_user: Option<i64>) -> Option<String> {
    conn.query_row(
        "DELETE FROM telegram_links WHERE email = ?1 OR telegram_user_id = ?2 RETURNING email",
        params![email, tg_user],
        |r| r.get(0),
    )
    .ok()
}

/// Linked accounts whose users may decide `req` now (enabled, approver,
/// not the requester).
fn approver_chats(conn: &Connection, req: &ApprovalRequest) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT email, telegram_user_id FROM telegram_links")?;
    let links = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(links
        .into_iter()
        .filter(|(email, _)| {
            requester_for(conn, email)
                .is_some_and(|who| may_decide(&req.approvers, &who, &req.requester).is_ok())
        })
        .map(|(_, chat)| chat)
        .collect())
}

/// A linked user as the policy engine sees them, from their user record;
/// `None` if the user is gone or disabled.
fn requester_for(conn: &Connection, email: &str) -> Option<Requester> {
    let user = crate::db::user_by_email(conn, email).filter(|u| !u.disabled)?;
    Some(Requester {
        groups: user.groups_vec(),
        email: Some(user.email),
        api_key: None,
        ai_agent: None,
        role: user.role,
    })
}

fn messages_of(conn: &Connection, req_id: &str) -> rusqlite::Result<Vec<(i64, i64)>> {
    let mut stmt =
        conn.prepare("SELECT chat_id, message_id FROM telegram_messages WHERE request_id = ?1")?;
    let rows = stmt.query_map([req_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

fn audit_link(conn: &Connection, event: &str, email: &str, detail: Option<&str>) {
    let _ = store::audit(
        conn,
        &store::AuditEvent {
            event,
            actor: email,
            requester: email,
            detail,
            ..Default::default()
        },
        store::now_secs(),
    );
}

// ── Messages ──

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn when(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

/// The message text (HTML) and buttons for `req` as it stands at `now`.
fn render(req: &ApprovalRequest, now: i64) -> (String, Value) {
    if req.break_glass {
        return (render_break_glass(req), json!({ "inline_keyboard": [] }));
    }
    let mut t = String::from("🔐 <b>Approval request</b>\n");
    t += &format!("<b>Who:</b> {}\n", esc(&req.requester_display));
    match &req.command {
        Some(cmd) => {
            let mut shown: String = cmd.chars().take(MAX_SHOWN_COMMAND).collect();
            if shown.len() < cmd.len() {
                shown.push('…');
            }
            t += &format!(
                "<b>Request:</b> run on {}:\n<code>{}</code>\n",
                esc(&req.target_label),
                esc(&shown)
            );
        }
        None => t += &format!("<b>Request:</b> connect to {}\n", esc(&req.target_label)),
    }
    t += &format!("<b>Policy:</b> {}\n", esc(&req.policy_name));
    if !req.reason.is_empty() {
        t += &format!("<b>Reason:</b> {}\n", esc(&req.reason));
    }
    if let Some(ip) = &req.client_ip {
        t += &format!("<b>From:</b> {}\n", esc(ip));
    }
    t.push('\n');
    let by = esc(req.decided_by.as_deref().unwrap_or("?"));
    let comment = req
        .comment
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(|c| format!(": {}", esc(c)))
        .unwrap_or_default();
    let open = req.status == "pending" && req.expires_at > now;
    match req.status.as_str() {
        "pending" if !open => t += "⌛ Expired: nobody decided in time",
        "pending" if req.web_only => {
            t += &format!(
                "🔒 Web only: decide on the Approvals page after a fresh sign-in (expires {})",
                when(req.expires_at)
            )
        }
        "pending" => {
            t += &format!(
                "⏳ Waiting for an approver (expires {})",
                when(req.expires_at)
            )
        }
        "approved" => {
            t += &format!("✅ Approved by {}{}", by, comment);
            if let Some(until) = req.grant_until {
                t += &format!("\nAccess until {}", when(until));
            }
        }
        "denied" => t += &format!("❌ Denied by {}{}", by, comment),
        "expired" => t += "⌛ Expired: nobody decided in time",
        "cancelled" => t += "↩️ Withdrawn by the requester",
        other => t += &esc(other),
    }
    let buttons = if open && !req.web_only {
        json!([[
            {"text": "✅ Approve", "callback_data": format!("ap:{}", req.id)},
            {"text": "❌ Deny", "callback_data": format!("dn:{}", req.id)},
        ]])
    } else {
        json!([])
    };
    (t, json!({ "inline_keyboard": buttons }))
}

/// The alert for an admin's break-glass override.
fn render_break_glass(req: &ApprovalRequest) -> String {
    let what = match &req.command {
        Some(cmd) => format!(
            "run on {}: <code>{}</code>",
            esc(&req.target_label),
            esc(&cmd.chars().take(MAX_SHOWN_COMMAND).collect::<String>())
        ),
        None => format!("connect to {}", esc(&req.target_label)),
    };
    let mut t = format!(
        "🚨 <b>Break-glass</b>\n<b>Who:</b> {}\n<b>Override:</b> {}\n<b>Reason:</b> {}\n",
        esc(&req.requester_display),
        what,
        esc(&req.reason)
    );
    if let Some(ip) = &req.client_ip {
        t += &format!("<b>From:</b> {}\n", esc(ip));
    }
    if let Some(until) = req.grant_until {
        t += &format!("\nAccess until {}", when(until));
    }
    t
}

/// Linked admins other than `requester`: who hears of a break-glass.
fn admin_chats(conn: &Connection, requester: &str) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT email, telegram_user_id FROM telegram_links")?;
    let links = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(links
        .into_iter()
        .filter(|(email, _)| {
            requester_for(conn, email)
                .is_some_and(|who| who.role == "admin" && who.id() != requester)
        })
        .map(|(_, chat)| chat)
        .collect())
}

/// A button's data: approve or deny, and the request id.
fn parse_button(data: &str) -> Option<(bool, &str)> {
    let (verb, id) = data.split_once(':')?;
    let approve = match verb {
        "ap" => true,
        "dn" => false,
        _ => return None,
    };
    (!id.is_empty()).then_some((approve, id))
}

/// Decide from a button press by Telegram user `tg_user`. Whether it
/// counted, and what to tell them.
fn decide_from_button(conn: &Connection, tg_user: i64, data: &str, now: i64) -> (bool, String) {
    let Some((approve, req_id)) = parse_button(data) else {
        return (false, "Unknown button.".into());
    };
    let email = match email_for(conn, tg_user) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                false,
                "Link your Telegram account first: Approvals page → Link Telegram.".into(),
            )
        }
        Err(e) => return (false, e.to_string()),
    };
    let Some(who) = requester_for(conn, &email) else {
        return (false, "Your My Bastion account is disabled or gone.".into());
    };
    match decide_request(conn, req_id, &who, &email, "", approve, Via::Telegram, now) {
        Ok(_) if approve => (true, "Approved.".into()),
        Ok(_) => (true, "Denied.".into()),
        Err(DecideError::NotFound) => (false, "No such request.".into()),
        Err(DecideError::NeedsFreshSignIn) => (
            false,
            "This request can only be decided on the web UI.".into(),
        ),
        Err(DecideError::Forbidden(e) | DecideError::Conflict(e) | DecideError::Db(e)) => {
            (false, e)
        }
    }
}

const HELP: &str = "I post My Bastion approval requests. To get them and decide from here, \
open the Approvals page, press Link Telegram and send me the code: /link CODE. \
/unlink removes the link.";

/// The reply to a text message in a private chat.
fn reply_to(
    conn: &Connection,
    text: &str,
    tg_user: i64,
    tg_username: Option<&str>,
    now: i64,
) -> String {
    let mut words = text.split_whitespace();
    let cmd = words.next().unwrap_or("");
    // Commands may come as /link@BotName in groups; private chats too.
    let cmd = cmd.split('@').next().unwrap_or(cmd);
    let arg = words.next();
    match (cmd, arg) {
        ("/start" | "/link", Some(code)) => {
            match redeem_link_code(conn, code, tg_user, tg_username, now) {
                Ok(Some(email)) => {
                    audit_link(conn, "telegram_linked", &email, tg_username);
                    format!(
                        "Linked to {}. Requests you may decide will come here.",
                        email
                    )
                }
                Ok(None) => {
                    "That code is unknown or expired. Get a new one on the Approvals page.".into()
                }
                Err(e) => format!("Linking failed: {}", e),
            }
        }
        ("/unlink", _) => match unlink(conn, None, Some(tg_user)) {
            Some(email) => {
                audit_link(conn, "telegram_unlinked", &email, None);
                format!("Unlinked from {}.", email)
            }
            None => "This Telegram account is not linked.".into(),
        },
        _ => HELP.into(),
    }
}

// ── Bot ──

struct Bot {
    http: reqwest::Client,
    /// `<api_url>/bot<token>`; never logged.
    base: String,
}

impl Bot {
    async fn call(&self, method: &str, body: Value) -> Result<Value, String> {
        let resp = self
            .http
            .post(format!("{}/{}", self.base, method))
            .json(&body)
            .send()
            .await
            // The URL has the token in it.
            .map_err(|e| e.without_url().to_string())?;
        let v: Value = resp.json().await.map_err(|e| e.without_url().to_string())?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["result"].clone())
        } else {
            Err(v["description"]
                .as_str()
                .unwrap_or("Telegram refused the call")
                .to_string())
        }
    }
}

async fn blocking<T: Send + 'static>(
    db: &Db,
    f: impl FnOnce(&Connection) -> T + Send + 'static,
) -> Result<T, String> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        Ok(f(&conn))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Start the bot if `[telegram]` is enabled: read its token from the store
/// (retrying until the store is up), then deliver messages and poll for
/// replies. `notify` queues from the moment this returns.
pub fn spawn(cfg: TelegramConfig, db: Db, cell: StoreCell) {
    if !cfg.enabled {
        return;
    }
    let (tx, rx) = mpsc::unbounded_channel();
    if EVENTS.set(tx).is_err() {
        return;
    }
    tokio::spawn(async move {
        let token = loop {
            let found = match cell.read().await.as_ref() {
                Some(store) => store
                    .read_kv_field(&cfg.bot_token_path, "token")
                    .await
                    .map_err(|e| e.to_string()),
                None => Err("the secret store is not available yet".into()),
            };
            match found {
                Ok(t) if !t.trim().is_empty() => break t.trim().to_string(),
                Ok(_) => tracing::warn!(path = %cfg.bot_token_path, "Telegram bot token is empty"),
                Err(e) => tracing::warn!(
                    path = %cfg.bot_token_path,
                    error = %e,
                    "Cannot read the Telegram bot token; retrying in 30s"
                ),
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        };
        let http = match reqwest::Client::builder()
            .timeout(Duration::from_secs(70))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Telegram HTTP client failed");
                return;
            }
        };
        let bot = Arc::new(Bot {
            http,
            base: format!("{}/bot{}", cfg.api_url.trim_end_matches('/'), token),
        });
        loop {
            match bot.call("getMe", json!({})).await {
                Ok(me) => {
                    let name = me["username"].as_str().unwrap_or_default().to_string();
                    tracing::info!(bot = %name, "Telegram approvals enabled");
                    let _ = BOT_USERNAME.set(name);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Telegram getMe failed; retrying in 30s");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
        tokio::spawn(poll(bot.clone(), db.clone()));
        deliver(bot, db, cfg, rx).await;
    });
}

async fn deliver(
    bot: Arc<Bot>,
    db: Db,
    cfg: TelegramConfig,
    mut rx: mpsc::UnboundedReceiver<Outgoing>,
) {
    while let Some(out) = rx.recv().await {
        match out {
            Outgoing::Request(id) => {
                if let Err(e) = deliver_one(&bot, &db, &cfg, &id).await {
                    tracing::warn!(request = %id, error = %e, "Telegram update failed");
                }
            }
            Outgoing::Command(a) => {
                let text = render_command_alert(&a);
                for chat in &cfg.chat_ids {
                    if let Err(e) = bot
                        .call(
                            "sendMessage",
                            json!({"chat_id": chat, "text": text, "parse_mode": "HTML",
                                   "link_preview_options": {"is_disabled": true}}),
                        )
                        .await
                    {
                        tracing::warn!(chat, error = %e, "Telegram alert failed");
                    }
                }
            }
        }
    }
}

/// Send the messages for a new request, or bring the sent ones up to date.
async fn deliver_one(bot: &Bot, db: &Db, cfg: &TelegramConfig, id: &str) -> Result<(), String> {
    let (rid, cfg2) = (id.to_string(), cfg.clone());
    let (req, sent, chats) = blocking(db, move |c| -> Result<_, String> {
        let req = store::get_request(c, &rid).map_err(|e| e.to_string())?;
        let sent = messages_of(c, &rid).map_err(|e| e.to_string())?;
        let mut chats = cfg2.chat_ids.clone();
        if let (Some(r), true, true) = (&req, sent.is_empty(), cfg2.notify_approvers) {
            if r.break_glass {
                chats.extend(admin_chats(c, &r.requester).map_err(|e| e.to_string())?);
            } else {
                chats.extend(approver_chats(c, r).map_err(|e| e.to_string())?);
            }
        }
        chats.dedup();
        Ok((req, sent, chats))
    })
    .await??;
    let Some(req) = req else { return Ok(()) };
    let (text, buttons) = render(&req, store::now_secs());

    if !sent.is_empty() {
        for (chat, msg) in sent {
            let edit = bot
                .call(
                    "editMessageText",
                    json!({"chat_id": chat, "message_id": msg, "text": text,
                           "parse_mode": "HTML", "reply_markup": buttons}),
                )
                .await;
            match edit {
                Err(e) if !e.contains("not modified") => {
                    tracing::warn!(chat, error = %e, "Telegram edit failed")
                }
                _ => {}
            }
        }
        return Ok(());
    }
    // Only a request still waiting, or a break-glass alert, is worth a new
    // message.
    if req.status != "pending" && !req.break_glass {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    for chat in chats.into_iter().filter(|c| seen.insert(*c)) {
        match bot
            .call(
                "sendMessage",
                json!({"chat_id": chat, "text": text, "parse_mode": "HTML",
                       "reply_markup": buttons, "link_preview_options": {"is_disabled": true}}),
            )
            .await
        {
            Ok(m) => {
                if let Some(msg) = m["message_id"].as_i64() {
                    let rid = req.id.clone();
                    blocking(db, move |c| {
                        c.execute(
                            "INSERT OR REPLACE INTO telegram_messages (request_id, chat_id, message_id)
                             VALUES (?1, ?2, ?3)",
                            params![rid, chat, msg],
                        )
                    })
                    .await?
                    .map_err(|e| e.to_string())?;
                }
            }
            Err(e) => tracing::warn!(chat, error = %e, "Telegram send failed"),
        }
    }
    Ok(())
}

async fn poll(bot: Arc<Bot>, db: Db) {
    let mut offset: i64 = 0;
    loop {
        let updates = bot
            .call(
                "getUpdates",
                json!({"offset": offset, "timeout": 50,
                       "allowed_updates": ["message", "callback_query"]}),
            )
            .await;
        match updates {
            Ok(Value::Array(list)) => {
                for u in list {
                    offset = offset.max(u["update_id"].as_i64().unwrap_or(0) + 1);
                    if let Err(e) = handle_update(&bot, &db, &u).await {
                        tracing::warn!(error = %e, "Telegram update handling failed");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Telegram getUpdates failed; retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn handle_update(bot: &Bot, db: &Db, u: &Value) -> Result<(), String> {
    if let Some(cq) = u.get("callback_query") {
        let (Some(from), Some(cq_id)) = (cq["from"]["id"].as_i64(), cq["id"].as_str()) else {
            return Ok(());
        };
        let data = cq["data"].as_str().unwrap_or_default().to_string();
        let d = data.clone();
        let (ok, answer) = blocking(db, move |c| {
            decide_from_button(c, from, &d, store::now_secs())
        })
        .await?;
        tracing::info!(telegram_user = from, counted = ok, answer = %answer, "Telegram decision");
        bot.call(
            "answerCallbackQuery",
            json!({"callback_query_id": cq_id, "text": answer, "show_alert": !ok}),
        )
        .await?;
        // A decision updates the messages itself; a refused press may have
        // come from stale buttons, so bring them up to date.
        if let (false, Some((_, id))) = (ok, parse_button(&data)) {
            notify(id);
        }
        return Ok(());
    }
    let Some(msg) = u.get("message") else {
        return Ok(());
    };
    let (Some(chat), Some(from), Some(text)) = (
        msg["chat"]["id"].as_i64(),
        msg["from"]["id"].as_i64(),
        msg["text"].as_str(),
    ) else {
        return Ok(());
    };
    if msg["chat"]["type"].as_str() != Some("private") {
        // Links happen in private chats only, so a code is never shown to a group.
        return Ok(());
    }
    let username = msg["from"]["username"].as_str().map(|s| format!("@{}", s));
    let text = text.to_string();
    let reply = blocking(db, move |c| {
        reply_to(c, &text, from, username.as_deref(), store::now_secs())
    })
    .await?;
    bot.call("sendMessage", json!({"chat_id": chat, "text": reply}))
        .await?;
    Ok(())
}

// ── Web API: linking ──
//
// GET /api/telegram, POST /api/telegram/link (a new code),
// DELETE /api/telegram/link. People only: an API key has no Telegram.

// The error is the answer the handler gives.
#[allow(clippy::result_large_err)]
fn person(identity: Option<Extension<AuthIdentity>>) -> Result<String, Response> {
    match identity {
        Some(Extension(AuthIdentity::User { email, .. })) => Ok(email),
        Some(_) => Err(error(
            StatusCode::FORBIDDEN,
            "only signed-in users link Telegram",
        )),
        None => Err(error(StatusCode::UNAUTHORIZED, "authentication required")),
    }
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

pub async fn status(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    let email = match person(identity) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match blocking(&db, move |c| link_of(c, &email)).await {
        Ok(Ok(link)) => Json(json!({
            "enabled": EVENTS.get().is_some(),
            "bot_username": BOT_USERNAME.get(),
            "linked": link.map(|(_, username, at)| json!({
                "telegram_username": username,
                "linked_at": at,
            })),
        }))
        .into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

pub async fn create_link_code(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    let email = match person(identity) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if EVENTS.get().is_none() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Telegram is not enabled on this server",
        );
    }
    match blocking(&db, move |c| new_link_code(c, &email, store::now_secs())).await {
        Ok(Ok((code, expires_at))) => Json(json!({
            "code": code,
            "expires_at": expires_at,
            "url": BOT_USERNAME
                .get()
                .filter(|u| !u.is_empty())
                .map(|u| format!("https://t.me/{}?start={}", u, code)),
        }))
        .into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

pub async fn delete_link(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
) -> Response {
    let email = match person(identity) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let result = blocking(&db, move |c| {
        let gone = unlink(c, Some(&email), None);
        if let Some(e) = &gone {
            audit_link(c, "telegram_unlinked", e, None);
        }
        gone.is_some()
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no Telegram account is linked"),
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Approver, Resource};

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT,
                 oidc_subject TEXT, role TEXT, disabled INTEGER DEFAULT 0, created_at TEXT,
                 last_login_at TEXT, oidc_groups TEXT NOT NULL DEFAULT '');
             INSERT INTO users (email, name, role, oidc_groups, created_at) VALUES
                 ('boss@x', 'Boss', 'admin', '', ''),
                 ('op@x', 'Op', 'operator', '', ''),
                 ('sec@x', 'Sec', 'viewer', 'secops', ''),
                 ('gone@x', 'Gone', 'admin', '', '');
             UPDATE users SET disabled = 1 WHERE email = 'gone@x';",
        )
        .unwrap();
        store::migrate(&c).unwrap();
        migrate(&c).unwrap();
        c
    }

    fn request(id: &str, requester: &str, now: i64) -> ApprovalRequest {
        ApprovalRequest {
            id: id.into(),
            requester: requester.into(),
            requester_display: requester.into(),
            action: "connect".into(),
            resource: Resource::Entry {
                scope: "shared".into(),
                folder: "prod".into(),
                entry: "web01".into(),
            },
            target_label: "shared/prod/web01".into(),
            policy_id: 1,
            policy_name: "prod <needs> approval".into(),
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

    fn link(c: &Connection, email: &str, tg: i64) {
        let (code, _) = new_link_code(c, email, 100).unwrap();
        assert_eq!(
            redeem_link_code(c, &code, tg, None, 101)
                .unwrap()
                .as_deref(),
            Some(email)
        );
    }

    #[test]
    fn codes_are_one_time_and_expire() {
        let c = conn();
        let (code, exp) = new_link_code(&c, "boss@x", 100).unwrap();
        assert_eq!((code.len(), exp), (CODE_LEN, 100 + LINK_CODE_SECS));
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        // Case and spaces don't matter; the second use fails.
        let typed = format!(" {} ", code.to_lowercase());
        assert_eq!(
            redeem_link_code(&c, &typed, 7, Some("@boss"), 101)
                .unwrap()
                .as_deref(),
            Some("boss@x")
        );
        assert_eq!(redeem_link_code(&c, &code, 8, None, 102).unwrap(), None);
        assert_eq!(email_for(&c, 7).unwrap().as_deref(), Some("boss@x"));
        // An expired code links nothing.
        let (old, _) = new_link_code(&c, "op@x", 100).unwrap();
        assert_eq!(
            redeem_link_code(&c, &old, 9, None, 100 + LINK_CODE_SECS).unwrap(),
            None
        );
        // A new code replaces the user's earlier one.
        let (first, _) = new_link_code(&c, "op@x", 200).unwrap();
        let (second, _) = new_link_code(&c, "op@x", 201).unwrap();
        assert_eq!(redeem_link_code(&c, &first, 9, None, 202).unwrap(), None);
        assert!(redeem_link_code(&c, &second, 9, None, 202)
            .unwrap()
            .is_some());
    }

    #[test]
    fn relinking_replaces_both_sides() {
        let c = conn();
        link(&c, "boss@x", 7);
        // The same Telegram account linked to another user moves over.
        link(&c, "op@x", 7);
        assert_eq!(email_for(&c, 7).unwrap().as_deref(), Some("op@x"));
        assert!(link_of(&c, "boss@x").unwrap().is_none());
        // The same user on a new Telegram account.
        link(&c, "op@x", 8);
        assert_eq!(email_for(&c, 7).unwrap(), None);
        assert_eq!(unlink(&c, None, Some(8)).as_deref(), Some("op@x"));
        assert_eq!(unlink(&c, Some("op@x"), None), None);
    }

    #[test]
    fn only_eligible_linked_approvers_get_requests() {
        let c = conn();
        link(&c, "boss@x", 1);
        link(&c, "op@x", 2);
        link(&c, "sec@x", 3);
        link(&c, "gone@x", 4);
        let mut req = request("r1", "op@x", 1000);
        req.approvers = vec![
            Approver::Role("admin".into()),
            Approver::Group("secops".into()),
        ];
        let mut chats = approver_chats(&c, &req).unwrap();
        chats.sort();
        assert_eq!(chats, vec![1, 3]);
        // The requester never gets their own, even as an approver.
        let own = request("r2", "boss@x", 1000);
        assert!(approver_chats(&c, &own).unwrap().is_empty());
    }

    #[test]
    fn buttons_decide_like_the_web_ui() {
        let c = conn();
        link(&c, "boss@x", 1);
        link(&c, "op@x", 2);
        link(&c, "gone@x", 4);
        store::create_request(&c, &request("r1", "op@x", 1000)).unwrap();
        // Unlinked, the requester themself, a disabled user: refused.
        assert!(!decide_from_button(&c, 99, "ap:r1", 1001).0);
        let (ok, why) = decide_from_button(&c, 2, "ap:r1", 1001);
        assert!(!ok && why.contains("own"), "{why}");
        assert!(!decide_from_button(&c, 4, "ap:r1", 1001).0);
        assert!(!decide_from_button(&c, 1, "zz:r1", 1001).0);
        // An approver decides, once.
        assert_eq!(
            decide_from_button(&c, 1, "ap:r1", 1002),
            (true, "Approved.".into())
        );
        let done = store::get_request(&c, "r1").unwrap().unwrap();
        assert_eq!(
            (done.status.as_str(), done.decided_by.as_deref()),
            ("approved", Some("boss@x"))
        );
        assert!(!decide_from_button(&c, 1, "dn:r1", 1003).0);
        let audit = store::list_audit(&c, 10).unwrap();
        assert!(audit.iter().any(|r| r.event == "approved"
            && r.actor == "boss@x"
            && r.detail.as_deref() == Some("via Telegram")));
    }

    #[test]
    fn web_only_requests_are_not_decided_from_telegram() {
        let c = conn();
        link(&c, "boss@x", 1);
        let mut req = request("r1", "op@x", 1000);
        req.web_only = true;
        store::create_request(&c, &req).unwrap();
        let (ok, why) = decide_from_button(&c, 1, "ap:r1", 1001);
        assert!(!ok && why.contains("web UI"), "{why}");
        assert_eq!(
            store::get_request(&c, "r1").unwrap().unwrap().status,
            "pending"
        );
        // And the message has no buttons.
        let (text, buttons) = render(&req, 1001);
        assert!(text.contains("Web only"));
        assert_eq!(buttons, json!({"inline_keyboard": []}));
    }

    #[test]
    fn messages_escape_and_show_the_state() {
        let mut req = request("r1", "op@x", 1000);
        req.command = Some("echo <b>&".into());
        req.reason = "patch <now>".into();
        let (text, buttons) = render(&req, 1001);
        assert!(text.contains("<code>echo &lt;b&gt;&amp;</code>"), "{text}");
        assert!(text.contains("prod &lt;needs&gt; approval"));
        assert!(text.contains("patch &lt;now&gt;"));
        assert!(text.contains("Waiting"));
        assert_eq!(buttons["inline_keyboard"][0][0]["callback_data"], "ap:r1");
        assert_eq!(buttons["inline_keyboard"][0][1]["callback_data"], "dn:r1");
        // Past its deadline: no buttons even before the reaper runs.
        let (text, buttons) = render(&req, 1000 + 1800);
        assert!(text.contains("Expired"));
        assert_eq!(buttons, json!({"inline_keyboard": []}));
        req.status = "approved".into();
        req.decided_by = Some("boss@x".into());
        req.grant_until = Some(5000);
        let (text, buttons) = render(&req, 1001);
        assert!(text.contains("Approved by boss@x") && text.contains("Access until"));
        assert_eq!(buttons, json!({"inline_keyboard": []}));
        // Long commands are cut.
        req.command = Some("x".repeat(MAX_SHOWN_COMMAND + 50));
        assert!(render(&req, 1001).0.contains('…'));
    }

    #[test]
    fn private_chat_commands() {
        let c = conn();
        let (code, _) = new_link_code(&c, "boss@x", 100).unwrap();
        let r = reply_to(&c, &format!("/start {}", code), 1, Some("@boss"), 101);
        assert!(r.contains("Linked to boss@x"), "{r}");
        assert_eq!(
            link_of(&c, "boss@x").unwrap().unwrap().1.as_deref(),
            Some("@boss")
        );
        assert!(reply_to(&c, "/link NOPE", 1, None, 102).contains("unknown or expired"));
        assert!(reply_to(&c, "hello", 1, None, 102).contains("/link CODE"));
        assert!(reply_to(&c, "/unlink", 1, None, 103).contains("Unlinked from boss@x"));
        assert!(reply_to(&c, "/unlink", 1, None, 104).contains("not linked"));
        let audit = store::list_audit(&c, 10).unwrap();
        assert!(audit
            .iter()
            .any(|r| r.event == "telegram_linked" && r.actor == "boss@x"));
        assert!(audit.iter().any(|r| r.event == "telegram_unlinked"));
    }

    #[test]
    fn break_glass_alerts_have_no_buttons_and_reach_other_admins() {
        let c = conn();
        link(&c, "boss@x", 1);
        link(&c, "op@x", 2);
        let mut req = request("bg1", "boss@x", 1000);
        req.break_glass = true;
        req.status = "approved".into();
        req.reason = "outage <db>".into();
        req.grant_until = Some(4600);
        let (text, buttons) = render(&req, 1001);
        assert!(
            text.contains("Break-glass") && text.contains("outage &lt;db&gt;"),
            "{text}"
        );
        assert_eq!(buttons, json!({"inline_keyboard": []}));
        // The admin who broke the glass is not told; operators never are.
        assert!(admin_chats(&c, "boss@x").unwrap().is_empty());
        assert_eq!(admin_chats(&c, "op@x").unwrap(), vec![1]);
    }

    #[test]
    fn button_data_parses() {
        assert_eq!(parse_button("ap:abc"), Some((true, "abc")));
        assert_eq!(parse_button("dn:abc"), Some((false, "abc")));
        assert_eq!(parse_button("ap:"), None);
        assert_eq!(parse_button("xx:abc"), None);
        assert_eq!(parse_button("ap"), None);
    }
}
