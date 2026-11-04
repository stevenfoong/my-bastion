//! Desktop sessions an agent opens over MCP. The bastion is the session's
//! Guacamole client (`render::client::Headless`): it takes the guacd stream
//! as the owner connection right after the session is created, so the
//! session is recorded and ends like any other.
//!
//! Tools: `open_session`, `screenshot`, `wait`, `close_session`. A session
//! belongs to the agent that opened it; one left idle for `IDLE_SECS` is
//! closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock, JsonObject};
use serde_json::{json, Value};
use uuid::Uuid;

use super::agents::Agent;
use super::server::{fail, ok, parse_connection_id, refusal, McpServer};
use crate::auth::AuthIdentity;
use crate::connections::AiMode;
use crate::render::client::Headless;

/// The most sessions one agent may have open.
const MAX_PER_AGENT: usize = 5;
/// An agent session nobody has used for this long is closed.
const IDLE_SECS: u64 = 15 * 60;
/// How long `open_session` waits for the first complete frame.
const FIRST_FRAME: Duration = Duration::from_secs(20);
/// The longest `wait`.
const MAX_WAIT_MS: u64 = 10_000;
const DEFAULT_SIZE: (u32, u32) = (1280, 800);
const DEFAULT_SHOT_WIDTH: u32 = 1280;
/// Session types an agent can open (the renderer draws these).
const TYPES: [&str; 3] = ["rdp", "vnc", "ssh"];

struct AgentSession {
    owner: String,
    connection: String,
    session_type: String,
    client: Arc<Headless>,
    last_used: Instant,
}

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<Uuid, AgentSession>>,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, AgentSession>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The client of `owner`'s session `id`, marked used.
    fn use_session(&self, id: Uuid, owner: &str) -> Option<Arc<Headless>> {
        let mut map = self.lock();
        let s = map.get_mut(&id).filter(|s| s.owner == owner)?;
        s.last_used = Instant::now();
        Some(s.client.clone())
    }

    /// Sessions idle too long, and ended ones nobody looked at since.
    fn idle(&self) -> Vec<Uuid> {
        self.lock()
            .iter()
            .filter(|(_, s)| s.last_used.elapsed() > Duration::from_secs(IDLE_SECS))
            .map(|(id, _)| *id)
            .collect()
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
                client: client.clone(),
                last_used: Instant::now(),
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
        let (sw, sh) = client
            .screenshot(1)
            .map(|s| s.screen)
            .unwrap_or((width, height));
        ok(json!({
            "session_id": session_id,
            "connection": conn_id.trim().trim_matches('/'),
            "type": session_type,
            "width": sw,
            "height": sh,
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
        let Some(client) = self.sessions.use_session(sid, id.display_name()) else {
            return fail("no such session for this agent");
        };
        if let Some(msg) = ended_message(&client) {
            return fail(msg);
        }
        let max_width = args
            .get("max_width")
            .and_then(Value::as_u64)
            .map(|w| (w as u32).clamp(64, 4096))
            .unwrap_or(DEFAULT_SHOT_WIDTH);
        match client.screenshot(max_width) {
            Ok(shot) => {
                let meta = json!({
                    "screen": { "width": shot.screen.0, "height": shot.screen.1 },
                    "image": { "width": shot.image.0, "height": shot.image.1 },
                    "frame": client.frames(),
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

    pub(super) async fn wait(&self, id: &AuthIdentity, args: &JsonObject) -> CallToolResponse {
        let Some(sid) = session_arg(args) else {
            return fail("session_id is required (from open_session)");
        };
        let Some(client) = self.sessions.use_session(sid, id.display_name()) else {
            return fail("no such session for this agent");
        };
        let ms = args
            .get("ms")
            .and_then(Value::as_u64)
            .unwrap_or(1000)
            .min(MAX_WAIT_MS);
        let before = client.frames();
        let changed = client.wait_frame(before, Duration::from_millis(ms)).await;
        if let Some(msg) = ended_message(&client) {
            return fail(msg);
        }
        ok(json!({ "new_frame": changed, "frame": client.frames() }))
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
