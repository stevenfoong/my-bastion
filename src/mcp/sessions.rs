//! Desktop sessions an agent opens over MCP. The bastion is the session's
//! Guacamole client (`render::client::Headless`): it takes the guacd stream
//! as the owner connection right after the session is created, so the
//! session is recorded (always, for AI) and ends like any other.
//!
//! Tools: `open_session`, `screenshot`, `wait`, `list_sessions`,
//! `close_session`, and the input tools `click`, `type_text`, `key`,
//! `scroll`. A session belongs to the agent that opened it; one left idle
//! for `IDLE_SECS` is closed.
//!
//! Input is checked on every call: the folder's AI mode (now, not when the
//! session opened) must allow acting, `input` policies apply, and in
//! `approve` mode each input waits for a person's approval of exactly that
//! input. Coordinates are those of the agent's last screenshot, mapped back
//! to the screen. Each input is audited (`ai_input`) with what it was but
//! not what was typed, unless `[mcp] log_typed_text`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock, JsonObject};
use serde_json::{json, Value};
use uuid::Uuid;

use super::agents::Agent;
use super::server::{approve_mode_rule, fail, ok, parse_connection_id, refusal, McpServer};
use crate::auth::AuthIdentity;
use crate::connections::AiMode;
use crate::policy::{Action, Gate, Resource};
use crate::render::client::Headless;
use crate::render::input;

/// The most sessions one agent may have open.
const MAX_PER_AGENT: usize = 5;
/// An agent session nobody has used for this long is closed.
const IDLE_SECS: u64 = 15 * 60;
/// How long `open_session` waits for the first complete frame.
const FIRST_FRAME: Duration = Duration::from_secs(20);
/// How long an input waits for the screen to react before it answers.
const SETTLE: Duration = Duration::from_millis(500);
/// The longest `wait`.
const MAX_WAIT_MS: u64 = 10_000;
const DEFAULT_SIZE: (u32, u32) = (1280, 800);
const DEFAULT_SHOT_WIDTH: u32 = 1280;
/// Session types an agent can open (the renderer draws these).
const TYPES: [&str; 3] = ["rdp", "vnc", "ssh"];
/// Rate limits per agent, as (burst, per second).
const INPUT_RATE: (f64, f64) = (20.0, 5.0);
const SHOT_RATE: (f64, f64) = (10.0, 2.0);

struct AgentSession {
    owner: String,
    connection: String,
    session_type: String,
    scope: String,
    folder: String,
    entry: String,
    client: Arc<Headless>,
    last_used: Instant,
    /// The last screenshot's (image, screen) size, to map coordinates.
    shot: Option<((u32, u32), (u32, u32))>,
}

/// What a tool needs of a session it may use.
struct Used {
    client: Arc<Headless>,
    scope: String,
    folder: String,
    entry: String,
    shot: Option<((u32, u32), (u32, u32))>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<Uuid, AgentSession>>,
    buckets: Mutex<HashMap<(String, &'static str), Bucket>>,
}

/// The one registry of the process, for the admin kill switch.
static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();

/// The registry the MCP server uses.
pub fn registry() -> Arc<Registry> {
    REGISTRY.get_or_init(Arc::default).clone()
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, AgentSession>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `owner`'s session `id`, marked used.
    fn use_session(&self, id: Uuid, owner: &str) -> Option<Used> {
        let mut map = self.lock();
        let s = map.get_mut(&id).filter(|s| s.owner == owner)?;
        s.last_used = Instant::now();
        Some(Used {
            client: s.client.clone(),
            scope: s.scope.clone(),
            folder: s.folder.clone(),
            entry: s.entry.clone(),
            shot: s.shot,
        })
    }

    /// Sessions idle too long, and ended ones nobody looked at since.
    fn idle(&self) -> Vec<Uuid> {
        self.lock()
            .iter()
            .filter(|(_, s)| s.last_used.elapsed() > Duration::from_secs(IDLE_SECS))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Take a token from `owner`'s `kind` bucket.
    fn allow(&self, owner: &str, kind: &'static str, (burst, rate): (f64, f64)) -> bool {
        let mut b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let bucket = b.entry((owner.to_string(), kind)).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        bucket.tokens =
            (bucket.tokens + now.duration_since(bucket.at).as_secs_f64() * rate).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Every agent session, for admins.
    pub fn all(&self) -> Vec<Value> {
        let mut list: Vec<Value> = self
            .lock()
            .iter()
            .map(|(sid, s)| {
                json!({
                    "session_id": sid,
                    "agent": s.owner,
                    "connection": s.connection,
                    "type": s.session_type,
                    "ended": s.client.ended().map(|e| e.reason.unwrap_or_else(|| "closed".into())),
                    "idle_secs": s.last_used.elapsed().as_secs(),
                })
            })
            .collect();
        list.sort_by_key(|v| v["agent"].as_str().unwrap_or("").to_string());
        list
    }

    /// End every agent session (the kill switch); how many.
    pub async fn kill_all(&self, manager: &crate::session::SessionManager) -> usize {
        let ids: Vec<Uuid> = self.lock().drain().map(|(id, _)| id).collect();
        for id in &ids {
            manager.delete_session(*id).await;
        }
        ids.len()
    }
}

/// Close idle agent sessions, every minute.
pub fn spawn_reaper(server: McpServer) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            for id in server.sessions.idle() {
                tracing::info!(session_id = %id, "Closing an idle AI agent session");
                server.manager.delete_session(id).await;
                server.sessions.lock().remove(&id);
            }
        }
    });
}

/// The `session_id` argument.
fn session_arg(args: &JsonObject) -> Option<Uuid> {
    args.get("session_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

fn ended_message(client: &Headless) -> Option<String> {
    client.ended().map(|e| {
        format!(
            "the session has ended: {}",
            e.reason.unwrap_or_else(|| "closed".into())
        )
    })
}

/// Screenshot coordinates to screen coordinates. `None` when outside it.
fn to_screen(
    x: u64,
    y: u64,
    shot: Option<((u32, u32), (u32, u32))>,
    screen: (u32, u32),
) -> Option<(u32, u32)> {
    let ((iw, ih), (sw, sh)) = shot.unwrap_or((screen, screen));
    if iw == 0 || ih == 0 || x >= iw as u64 || y >= ih as u64 {
        return None;
    }
    let sx = (x * sw as u64 / iw as u64).min(sw.saturating_sub(1) as u64);
    let sy = (y * sh as u64 / ih as u64).min(sh.saturating_sub(1) as u64);
    Some((sx as u32, sy as u32))
}

/// One input, ready to check and send.
struct Input {
    /// What it is, for the policy check and an approval (with the text).
    describe: String,
    /// What it is, for the audit log (without the text).
    audit: Value,
    data: String,
}

fn coords(args: &JsonObject, used: &Used, screen: (u32, u32)) -> Result<(u32, u32), String> {
    let x = args
        .get("x")
        .and_then(Value::as_u64)
        .ok_or("x is required")?;
    let y = args
        .get("y")
        .and_then(Value::as_u64)
        .ok_or("y is required")?;
    to_screen(x, y, used.shot, screen).ok_or_else(|| {
        "x, y are outside the screen (use the coordinates of your last screenshot)".to_string()
    })
}

fn build_input(
    tool: &str,
    args: &JsonObject,
    used: &Used,
    screen: (u32, u32),
) -> Result<Input, String> {
    match tool {
        "click" => {
            let (x, y) = coords(args, used, screen)?;
            let name = args.get("button").and_then(Value::as_str).unwrap_or("left");
            let mask = input::button(name).ok_or("button must be left, middle or right")?;
            let double = args.get("double").and_then(Value::as_bool).unwrap_or(false);
            let what = if double { "double-click" } else { "click" };
            Ok(Input {
                describe: format!("{} {} at {},{}", what, name, x, y),
                audit: json!({ "kind": what, "button": name, "x": x, "y": y }),
                data: input::click(x, y, mask, double),
            })
        }
        "scroll" => {
            let (x, y) = coords(args, used, screen)?;
            let dy = args
                .get("dy")
                .and_then(Value::as_i64)
                .ok_or("dy is required")?;
            let dy = dy.clamp(-(input::MAX_SCROLL as i64), input::MAX_SCROLL as i64) as i32;
            Ok(Input {
                describe: format!("scroll {} at {},{}", dy, x, y),
                audit: json!({ "kind": "scroll", "x": x, "y": y, "dy": dy }),
                data: input::scroll(x, y, dy),
            })
        }
        "type_text" => {
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .ok_or("text is required")?;
            let n = text.chars().count();
            if n == 0 || n > input::MAX_TEXT {
                return Err(format!("text must be 1-{} characters", input::MAX_TEXT));
            }
            Ok(Input {
                describe: format!("type {:?}", text),
                audit: json!({ "kind": "type_text", "chars": n }),
                data: input::text(text),
            })
        }
        "key" => {
            let spec = args
                .get("combo")
                .and_then(Value::as_str)
                .ok_or("combo is required")?;
            let data =
                input::combo(spec).ok_or_else(|| format!("unknown key combination '{}'", spec))?;
            let spec = spec.trim().to_ascii_lowercase();
            Ok(Input {
                describe: format!("key {}", spec),
                audit: json!({ "kind": "key", "combo": spec }),
                data,
            })
        }
        _ => Err("unknown input".into()),
    }
}

impl McpServer {
    pub(super) async fn open_session(
        &self,
        id: &AuthIdentity,
        agent: &Agent,
        ip: String,
        args: &JsonObject,
    ) -> CallToolResponse {
        let Some(conn_id) = args.get("connection").and_then(Value::as_str) else {
            return fail("connection is required");
        };
        let Some((scope, folder, entry)) = parse_connection_id(conn_id) else {
            return fail("connection must be an id from list_connections, like shared/lab/win01");
        };
        let mode = match self.conns.resolve_ai_mode(scope, folder).await {
            Ok(m) => m,
            Err(e) => return fail(format!("cannot read the folder: {}", e)),
        };
        if mode == AiMode::None || !agent.reaches(scope, folder) {
            return fail("no such connection for this agent");
        }
        let session_type = match self.conns.get_entry(scope, folder, entry).await {
            Ok(e) => e.session_type,
            Err(_) => return fail("no such connection for this agent"),
        };
        if !TYPES.contains(&session_type.as_str()) {
            return fail(format!(
                "{} sessions cannot be opened by AI agents (only {})",
                session_type,
                TYPES.join(", ")
            ));
        }
        let owner = id.display_name().to_string();
        let open = self
            .sessions
            .lock()
            .values()
            .filter(|s| s.owner == owner && s.client.ended().is_none())
            .count();
        if open >= MAX_PER_AGENT {
            return fail(format!(
                "this agent already has {} sessions open; close one first",
                open
            ));
        }
        let dim = |k: &str, d: u32| {
            args.get(k)
                .and_then(Value::as_u64)
                .map(|v| (v as u32).clamp(320, 4096))
                .unwrap_or(d)
        };
        let (width, height) = (dim("width", DEFAULT_SIZE.0), dim("height", DEFAULT_SIZE.1));
        let req = crate::api::ConnectRequest {
            width: Some(width),
            height: Some(height),
            screen_width: None,
            screen_height: None,
            dpi: None,
            keyboard_layout: None,
            banner: None,
            username: None,
            password: None,
            domain: None,
        };
        // AI sessions are always recorded.
        let resp = crate::api::connect_entry(
            &self.manager,
            &self.db,
            &self.conns,
            id,
            scope,
            folder,
            entry,
            req,
            ip,
            true,
        )
        .await;
        let status = resp.status();
        let body: Value = match axum::body::to_bytes(resp.into_body(), 1024 * 1024).await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
            Err(e) => return fail(format!("could not read the result: {}", e)),
        };
        if status != StatusCode::CREATED && status != StatusCode::OK {
            return refusal(status, &body, "open_session");
        }
        let Some(session_id) = body["session_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return fail("the session was not created");
        };

        // guacd drops a session nobody attaches to: take it now, as owner.
        let Some((stream, cancel)) = self.manager.take_guacd_stream(session_id).await else {
            return fail("the session could not start");
        };
        let recording_on = self.manager.is_recording_enabled(session_id).await;
        let recording = crate::websocket::open_recording(&self.manager, session_id).await;
        let (client, task) = Headless::start(stream, cancel, recording);
        self.sessions.lock().insert(
            session_id,
            AgentSession {
                owner: owner.clone(),
                connection: conn_id.trim().trim_matches('/').to_string(),
                session_type: session_type.clone(),
                scope: scope.to_string(),
                folder: folder.to_string(),
                entry: entry.to_string(),
                client: client.clone(),
                last_used: Instant::now(),
                shot: None,
            },
        );
        let manager = self.manager.clone();
        let started = Instant::now();
        tokio::spawn(async move {
            let ended = task.await.ok();
            let elapsed = started.elapsed();
            let failed =
                elapsed.as_secs() < 5 && ended.as_ref().is_some_and(|e| e.reason.is_some());
            tracing::info!(
                session_id = %session_id,
                reason = ?ended.as_ref().and_then(|e| e.reason.clone()),
                "AI agent session ended"
            );
            crate::websocket::finish_connection(
                &manager,
                session_id,
                failed,
                ended.is_some_and(|e| e.server_disconnected),
                elapsed,
                recording_on,
            )
            .await;
        });
        tracing::info!(agent = %owner, session_id = %session_id, connection = %conn_id, "AI agent opened a session");

        let ready = client.wait_frame(0, FIRST_FRAME).await;
        if let Some(msg) = ended_message(&client) {
            return fail(msg);
        }
        let (sw, sh) = client.screen_size();
        ok(json!({
            "session_id": session_id,
            "connection": conn_id.trim().trim_matches('/'),
            "type": session_type,
            "width": if sw > 0 { sw } else { width },
            "height": if sh > 0 { sh } else { height },
            "ready": ready,
            "ai_mode": mode.as_str(),
        }))
    }

    pub(super) async fn screenshot(
        &self,
        id: &AuthIdentity,
        args: &JsonObject,
    ) -> CallToolResponse {
        let Some(sid) = session_arg(args) else {
            return fail("session_id is required (from open_session)");
        };
        let Some(used) = self.sessions.use_session(sid, id.display_name()) else {
            return fail("no such session for this agent");
        };
        if let Some(msg) = ended_message(&used.client) {
            return fail(msg);
        }
        if !self
            .sessions
            .allow(id.display_name(), "screenshot", SHOT_RATE)
        {
            return fail("too many screenshots: wait a moment");
        }
        let max_width = args
            .get("max_width")
            .and_then(Value::as_u64)
            .map(|w| (w as u32).clamp(64, 4096))
            .unwrap_or(DEFAULT_SHOT_WIDTH);
        match used.client.screenshot(max_width) {
            Ok(shot) => {
                if let Some(s) = self.sessions.lock().get_mut(&sid) {
                    s.shot = Some((shot.image, shot.screen));
                }
                let meta = json!({
                    "screen": { "width": shot.screen.0, "height": shot.screen.1 },
                    "image": { "width": shot.image.0, "height": shot.image.1 },
                    "frame": used.client.frames(),
                    "note": "click and scroll take coordinates in this image",
                });
                CallToolResult::success(vec![
                    ContentBlock::text(meta.to_string()),
                    ContentBlock::image(
                        base64::engine::general_purpose::STANDARD.encode(shot.png),
                        "image/png",
                    ),
                ])
                .into()
            }
            Err(e) => fail(e),
        }
    }

    /// `click`, `scroll`, `type_text` and `key`.
    pub(super) async fn input(
        &self,
        tool: &str,
        id: &AuthIdentity,
        agent: &Agent,
        ip: String,
        args: &JsonObject,
    ) -> CallToolResponse {
        let Some(sid) = session_arg(args) else {
            return fail("session_id is required (from open_session)");
        };
        let owner = id.display_name();
        let Some(used) = self.sessions.use_session(sid, owner) else {
            return fail("no such session for this agent");
        };
        if let Some(msg) = ended_message(&used.client) {
            return fail(msg);
        }
        if !self.sessions.allow(owner, "input", INPUT_RATE) {
            return fail("too much input too fast: wait a moment");
        }
        // The mode now, so an admin's change applies at once.
        let mode = match self.conns.resolve_ai_mode(&used.scope, &used.folder).await {
            Ok(m) => m,
            Err(e) => return fail(format!("cannot read the folder: {}", e)),
        };
        if mode == AiMode::None || !agent.reaches(&used.scope, &used.folder) {
            return fail("AI agents may no longer use this connection");
        }
        if !mode.may_act() {
            return fail(format!(
                "{}/{} is observe-only for AI agents: input is not allowed",
                used.scope, used.folder
            ));
        }
        let inp = match build_input(tool, args, &used, used.client.screen_size()) {
            Ok(i) => i,
            Err(e) => return fail(e),
        };
        let folder_label = format!("{}/{}", used.scope, used.folder);
        let res = Resource::Entry {
            scope: used.scope.clone(),
            folder: used.folder.clone(),
            entry: used.entry.clone(),
        };
        let forced =
            (mode == AiMode::Approve).then(|| approve_mode_rule(&folder_label, Action::Input));
        match crate::policy::gate_forced(
            &self.db,
            id,
            Action::Input,
            res.clone(),
            Some(inp.describe.clone()),
            ip.clone(),
            forced,
        )
        .await
        {
            Ok(Gate::Allowed) => {}
            Ok(Gate::Denied { policy }) => {
                return fail(format!("input denied by policy '{}'", policy))
            }
            Ok(Gate::Pending(req)) => {
                return refusal(StatusCode::ACCEPTED, &json!({ "approval": *req }), tool)
            }
            Err(e) => {
                tracing::error!(error = %e, "Policy check failed; refusing AI input");
                return fail("policy check failed; try again later");
            }
        }
        let before = used.client.frames();
        if let Err(e) = used.client.send(&inp.data).await {
            return fail(format!("could not send the input: {}", e));
        }
        self.audit_input(id, &res, sid, inp.audit, &inp.describe, ip);
        let changed = used.client.wait_frame(before, SETTLE).await;
        ok(json!({ "done": true, "screen_changed": changed, "frame": used.client.frames() }))
    }

    fn audit_input(
        &self,
        id: &AuthIdentity,
        res: &Resource,
        sid: Uuid,
        mut detail: Value,
        describe: &str,
        ip: String,
    ) {
        detail["session_id"] = json!(sid);
        if self.log_typed_text {
            detail["input"] = json!(describe);
        }
        let (db, actor, target) = (self.db.clone(), id.display_name().to_string(), res.label());
        tokio::task::spawn_blocking(move || {
            let Ok(conn) = db.lock() else { return };
            let detail = detail.to_string();
            let row = crate::policy::store::AuditEvent {
                event: "ai_input",
                actor: &actor,
                requester: &actor,
                action: Action::Input.as_str(),
                target: &target,
                detail: Some(&detail),
                ip: Some(&ip),
                ..Default::default()
            };
            if let Err(e) =
                crate::policy::store::audit(&conn, &row, crate::policy::store::now_secs())
            {
                tracing::warn!(error = %e, "Failed to audit AI input");
            }
        });
    }

    pub(super) async fn wait(&self, id: &AuthIdentity, args: &JsonObject) -> CallToolResponse {
        let Some(sid) = session_arg(args) else {
            return fail("session_id is required (from open_session)");
        };
        let Some(used) = self.sessions.use_session(sid, id.display_name()) else {
            return fail("no such session for this agent");
        };
        let ms = args
            .get("ms")
            .and_then(Value::as_u64)
            .unwrap_or(1000)
            .min(MAX_WAIT_MS);
        let before = used.client.frames();
        let changed = used
            .client
            .wait_frame(before, Duration::from_millis(ms))
            .await;
        if let Some(msg) = ended_message(&used.client) {
            return fail(msg);
        }
        ok(json!({ "new_frame": changed, "frame": used.client.frames() }))
    }

    pub(super) async fn close_session(
        &self,
        id: &AuthIdentity,
        args: &JsonObject,
    ) -> CallToolResponse {
        let Some(sid) = session_arg(args) else {
            return fail("session_id is required (from open_session)");
        };
        if self.sessions.use_session(sid, id.display_name()).is_none() {
            return fail("no such session for this agent");
        }
        self.sessions.lock().remove(&sid);
        self.manager.delete_session(sid).await;
        tracing::info!(agent = %id.display_name(), session_id = %sid, "AI agent closed a session");
        ok(json!({ "closed": sid }))
    }

    pub(super) fn list_sessions(&self, id: &AuthIdentity) -> CallToolResponse {
        let map = self.sessions.lock();
        let list: Vec<Value> = map
            .iter()
            .filter(|(_, s)| s.owner == id.display_name())
            .map(|(sid, s)| {
                json!({
                    "session_id": sid,
                    "connection": s.connection,
                    "type": s.session_type,
                    "ended": s.client.ended().map(|e| e.reason.unwrap_or_else(|| "closed".into())),
                    "idle_secs": s.last_used.elapsed().as_secs(),
                })
            })
            .collect();
        ok(json!({ "sessions": list }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screenshot_coordinates_map_back_to_the_screen() {
        let shot = Some(((1280, 800), (2560, 1600)));
        assert_eq!(to_screen(640, 400, shot, (2560, 1600)), Some((1280, 800)));
        assert_eq!(to_screen(1279, 799, shot, (2560, 1600)), Some((2558, 1598)));
        assert_eq!(to_screen(1280, 10, shot, (2560, 1600)), None);
        // Before any screenshot: screen coordinates.
        assert_eq!(to_screen(5, 5, None, (1024, 768)), Some((5, 5)));
        assert_eq!(to_screen(5, 5, None, (0, 0)), None);
    }

    #[test]
    fn rate_limits_refill() {
        let r = Registry::default();
        let rate = (3.0, 1000.0);
        assert!((0..3).all(|_| r.allow("ai:a", "input", (3.0, 0.0))));
        assert!(!r.allow("ai:a", "input", (3.0, 0.0)));
        // Another agent, or another kind, has its own bucket.
        assert!(r.allow("ai:b", "input", (3.0, 0.0)));
        assert!(r.allow("ai:a", "screenshot", (3.0, 0.0)));
        // A fast refill comes back.
        assert!(r.allow("ai:c", "input", rate));
        std::thread::sleep(Duration::from_millis(5));
        assert!((0..3).all(|_| r.allow("ai:c", "input", rate)));
    }

    #[test]
    fn inputs_describe_themselves_without_leaking_text_to_the_audit() {
        let used = Used {
            client: dummy_client(),
            scope: "shared".into(),
            folder: "lab".into(),
            entry: "desk".into(),
            shot: Some(((640, 400), (1280, 800))),
        };
        let args = |v: Value| v.as_object().cloned().unwrap();
        let t = build_input(
            "type_text",
            &args(json!({"text": "s3cret!"})),
            &used,
            (1280, 800),
        )
        .unwrap();
        assert_eq!(t.describe, "type \"s3cret!\"");
        assert!(!t.audit.to_string().contains("s3cret"));
        assert_eq!(t.audit["chars"], 7);
        let c = build_input(
            "click",
            &args(json!({"x": 100, "y": 50, "double": true})),
            &used,
            (1280, 800),
        )
        .unwrap();
        assert_eq!(c.describe, "double-click left at 200,100");
        let k = build_input(
            "key",
            &args(json!({"combo": "Ctrl+Alt+Del"})),
            &used,
            (1280, 800),
        )
        .unwrap();
        assert_eq!(k.describe, "key ctrl+alt+del");
        assert!(build_input(
            "key",
            &args(json!({"combo": "hyper+q"})),
            &used,
            (1280, 800)
        )
        .is_err());
        assert!(build_input(
            "click",
            &args(json!({"x": 700, "y": 1})),
            &used,
            (1280, 800)
        )
        .is_err());
        assert!(build_input("type_text", &args(json!({"text": ""})), &used, (1280, 800)).is_err());
    }

    /// A client over a socket nobody reads, for tests that never send.
    fn dummy_client() -> Arc<Headless> {
        let (a, _b) = tokio::io::duplex(64);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (c, _task) = Headless::start(
                Box::new(a),
                tokio_util::sync::CancellationToken::new(),
                None,
            );
            c
        })
    }
}
