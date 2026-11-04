//! The MCP server at `/mcp` (Streamable HTTP, the official `rmcp` SDK),
//! stateless: every request carries the agent's key and is checked again.
//!
//! Tools, so far:
//! - `list_connections(folder?)`: entries in folders whose AI mode is not
//!   `none` and that the agent's key reaches. Never credentials.
//! - `run_ssh(connection, command, timeout_secs?)`: one command on an SSH
//!   entry, through the same checks as the REST `/run` route (`ssh_command`
//!   policies, approvals, the network check, the audit log). The folder's AI
//!   mode must allow acting: `approve` holds every command for a person's
//!   approval, `auto` lets the policies decide, `observe` refuses.
//! - `open_session`, `screenshot`, `wait`, `list_sessions`,
//!   `close_session`: desktop sessions the bastion renders itself
//!   (`sessions.rs`); any AI mode but `none` may look.
//!
//! A refusal or a wait for approval is a tool error the model can read.

use std::sync::Arc;

use axum::http::{request::Parts, StatusCode};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{json, Value};

use super::agents::Agent;
use super::auth::McpClientIp;
use crate::api::{AppState, ConnectionsState};
use crate::auth::AuthIdentity;
use crate::connections::AiMode;
use crate::db::Db;

/// The most folders `list_connections` walks, and how deep.
const MAX_FOLDERS: usize = 500;
const MAX_DEPTH: usize = 8;
/// The most a `/run` answer may be (two streams of at most 1 MiB, in JSON).
const MAX_RUN_BODY: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct McpServer {
    pub db: Db,
    pub conns: ConnectionsState,
    pub manager: AppState,
    pub(super) sessions: Arc<super::sessions::Registry>,
    /// Keep what an agent types in the audit log (`[mcp] log_typed_text`).
    pub(super) log_typed_text: bool,
}

impl McpServer {
    /// The server, with the task that closes idle agent sessions.
    pub fn new(db: Db, conns: ConnectionsState, manager: AppState, log_typed_text: bool) -> Self {
        let server = McpServer {
            db,
            conns,
            manager,
            sessions: super::sessions::registry(),
            log_typed_text,
        };
        super::sessions::spawn_reaper(server.clone());
        server
    }
}

/// The `/mcp` service, to mount behind `auth::require_agent`.
pub fn service(server: McpServer) -> StreamableHttpService<McpServer, NeverSessionManager> {
    // Host and Origin checks guard local servers against DNS rebinding; this
    // one is public and every request needs a bearer key no page can send.
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .disable_allowed_hosts();
    StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

/// A connection's id for the tools: `scope/folder/path/entry`.
fn connection_id(scope: &str, folder: &str, entry: &str) -> String {
    format!("{}/{}/{}", scope, folder, entry)
}

/// `scope/folder/path/entry` back into its parts.
pub(super) fn parse_connection_id(id: &str) -> Option<(&str, &str, &str)> {
    let (scope, rest) = id.trim().trim_matches('/').split_once('/')?;
    let (folder, entry) = rest.rsplit_once('/')?;
    (matches!(scope, "shared" | "instance") && !folder.is_empty() && !entry.is_empty())
        .then_some((scope, folder, entry))
}

/// The rule that holds an agent's every action in an `approve` folder.
pub fn approve_mode_rule(folder: &str, action: crate::policy::Action) -> crate::policy::Rule {
    crate::policy::Rule {
        id: 0,
        name: format!("AI approve mode ({})", folder),
        subject: crate::policy::Subject::Any,
        target: crate::policy::Target::Any,
        action,
        effect: crate::policy::Effect::RequireApproval,
        approvers: vec![crate::policy::Approver::Role("admin".into())],
        grant_minutes: 60,
        timeout_minutes: 30,
        enabled: true,
        commands: Vec::new(),
        web_only: false,
        direction: None,
    }
}

fn schema(v: Value) -> Arc<JsonObject> {
    Arc::new(v.as_object().cloned().unwrap_or_default())
}

fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "list_connections",
            "List the connections this agent may use: id, type, host and the folder's AI mode \
             (observe: look only; approve: every action waits for a person; auto: allowed by \
             policy). Never returns credentials.",
            schema(json!({
                "type": "object",
                "properties": {
                    "folder": {
                        "type": "string",
                        "description": "Only this folder and its subfolders, as scope/path (e.g. shared/lab)"
                    }
                }
            })),
        ),
        Tool::new(
            "run_ssh",
            "Run one shell command on an SSH connection through the bastion and return its \
             exit status, stdout and stderr. Policies may refuse the command or hold it for a \
             person's approval: then call again with the same command once it is approved.",
            schema(json!({
                "type": "object",
                "properties": {
                    "connection": {
                        "type": "string",
                        "description": "Connection id from list_connections, e.g. shared/lab/web01"
                    },
                    "command": { "type": "string", "description": "One line, run by the target's shell" },
                    "timeout_secs": {
                        "type": "integer", "minimum": 1, "maximum": 600,
                        "description": "Seconds to wait for it (default 60)"
                    }
                },
                "required": ["connection", "command"]
            })),
        ),
        Tool::new(
            "open_session",
            "Open a desktop or terminal session (RDP, VNC or SSH) on a connection. The bastion \
             renders it: look at it with screenshot, and close it with close_session when done. \
             Sessions are recorded.",
            schema(json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string", "description": "Connection id from list_connections" },
                    "width": { "type": "integer", "minimum": 320, "maximum": 4096, "description": "Screen width (default 1280)" },
                    "height": { "type": "integer", "minimum": 320, "maximum": 4096, "description": "Screen height (default 800)" }
                },
                "required": ["connection"]
            })),
        ),
        Tool::new(
            "screenshot",
            "The session's screen as a PNG, scaled down to max_width (default 1280).",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "max_width": { "type": "integer", "minimum": 64, "maximum": 4096 }
                },
                "required": ["session_id"]
            })),
        ),
        Tool::new(
            "wait",
            "Wait until the screen next changes (or ms milliseconds pass, at most 10000).",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "ms": { "type": "integer", "minimum": 0, "maximum": 10000 }
                },
                "required": ["session_id"]
            })),
        ),
        Tool::new(
            "list_sessions",
            "The sessions this agent has open.",
            schema(json!({ "type": "object", "properties": {} })),
        ),
        Tool::new(
            "close_session",
            "End a session this agent opened.",
            schema(json!({
                "type": "object",
                "properties": { "session_id": { "type": "string" } },
                "required": ["session_id"]
            })),
        ),
        Tool::new(
            "click",
            "Click at x, y in the coordinates of your last screenshot of the session. In an \
             approve folder each input waits for a person's approval: call again with the same \
             arguments once approved.",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "x": { "type": "integer", "minimum": 0 },
                    "y": { "type": "integer", "minimum": 0 },
                    "button": { "type": "string", "enum": ["left", "middle", "right"] },
                    "double": { "type": "boolean" }
                },
                "required": ["session_id", "x", "y"]
            })),
        ),
        Tool::new(
            "type_text",
            "Type text into the session, as if on its keyboard (\\n is Enter).",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "text": { "type": "string", "maxLength": 4000 }
                },
                "required": ["session_id", "text"]
            })),
        ),
        Tool::new(
            "key",
            "Press a key or a combination: enter, esc, tab, f5, ctrl+c, alt+f4, win+r, \
             ctrl+alt+del, shift+tab, …",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "combo": { "type": "string" }
                },
                "required": ["session_id", "combo"]
            })),
        ),
        Tool::new(
            "scroll",
            "Turn the mouse wheel at x, y (screenshot coordinates): dy > 0 scrolls down, < 0 up.",
            schema(json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "x": { "type": "integer", "minimum": 0 },
                    "y": { "type": "integer", "minimum": 0 },
                    "dy": { "type": "integer", "minimum": -50, "maximum": 50 }
                },
                "required": ["session_id", "x", "y", "dy"]
            })),
        ),
    ]
}

pub(super) fn ok(v: Value) -> CallToolResponse {
    CallToolResult::success(vec![ContentBlock::text(v.to_string())]).into()
}

pub(super) fn fail(msg: impl Into<String>) -> CallToolResponse {
    CallToolResult::error(vec![ContentBlock::text(msg.into())]).into()
}

/// A REST answer that is not a success, as a tool error: a wait for
/// approval (202) says what to do next.
pub(super) fn refusal(status: StatusCode, body: &Value, tool: &str) -> CallToolResponse {
    if status == StatusCode::ACCEPTED {
        let a = &body["approval"];
        return fail(format!(
            "Waiting for approval (request {}, policy '{}'). A person must approve it on the \
             Approvals page; then call {} again with exactly the same arguments.",
            a["id"].as_str().unwrap_or("?"),
            a["policy_name"].as_str().unwrap_or("?"),
            tool
        ));
    }
    fail(
        body["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("refused ({})", status)),
    )
}

/// The caller, as `auth::require_agent` left it on the HTTP request.
fn caller(ctx: &RequestContext<RoleServer>) -> Option<(AuthIdentity, Agent, String)> {
    let parts = ctx.extensions.get::<Parts>()?;
    let id = parts.extensions.get::<AuthIdentity>()?.clone();
    let agent = parts.extensions.get::<Agent>()?.clone();
    let ip = parts
        .extensions
        .get::<McpClientIp>()
        .map(|i| i.0.clone())
        .unwrap_or_default();
    matches!(id, AuthIdentity::AiAgent(_)).then_some((id, agent, ip))
}

impl McpServer {
    /// Folders (scope, path, mode) the agent may use, walking down from the
    /// top-level folders; a folder's mode is its own or its parent's.
    async fn folders(&self, agent: &Agent) -> Result<Vec<(String, String, AiMode)>, String> {
        let (top, _) = self
            .conns
            .list_all_folders()
            .await
            .map_err(|e| e.to_string())?;
        let mut queue: Vec<(String, String, AiMode, usize)> = top
            .into_iter()
            .map(|f| {
                let path = f.path.unwrap_or(f.name);
                (f.scope, path, AiMode::None, 1)
            })
            .collect();
        let mut out = Vec::new();
        let mut seen = 0;
        while let Some((scope, path, inherited, depth)) = queue.pop() {
            seen += 1;
            if seen > MAX_FOLDERS {
                tracing::warn!("MCP list_connections: folder limit reached");
                break;
            }
            let mode = match self.conns.get_folder_config(&scope, &path).await {
                Ok(c) => c.ai_mode.unwrap_or(inherited),
                Err(_) => inherited,
            };
            if mode != AiMode::None && agent.reaches(&scope, &path) {
                out.push((scope.clone(), path.clone(), mode));
            }
            if depth < MAX_DEPTH {
                if let Ok(subs) = self.conns.list_subfolders(&scope, &path).await {
                    for s in subs {
                        let p = s.path.unwrap_or_else(|| format!("{}/{}", path, s.name));
                        queue.push((scope.clone(), p, mode, depth + 1));
                    }
                }
            }
        }
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        Ok(out)
    }

    async fn list_connections(&self, agent: &Agent, args: &JsonObject) -> CallToolResponse {
        let only = args
            .get("folder")
            .and_then(Value::as_str)
            .map(|f| f.trim().trim_matches('/').to_string())
            .filter(|f| !f.is_empty());
        let folders = match self.folders(agent).await {
            Ok(f) => f,
            Err(e) => return fail(format!("cannot list connections: {}", e)),
        };
        let mut list = Vec::new();
        for (scope, path, mode) in folders {
            let label = format!("{}/{}", scope, path);
            if let Some(o) = &only {
                if label != *o && !label.starts_with(&format!("{}/", o)) {
                    continue;
                }
            }
            let Ok(names) = self.conns.list_entries(&scope, &path).await else {
                continue;
            };
            for name in names {
                let Ok(e) = self.conns.get_entry(&scope, &path, &name).await else {
                    continue;
                };
                list.push(json!({
                    "id": connection_id(&scope, &path, &name),
                    "folder": label,
                    "name": name,
                    "display_name": e.display_name,
                    "type": e.session_type,
                    "hostname": e.hostname,
                    "port": e.port,
                    "ai_mode": mode.as_str(),
                }));
            }
        }
        ok(json!({ "connections": list }))
    }

    async fn run_ssh(
        &self,
        id: &AuthIdentity,
        agent: &Agent,
        ip: String,
        args: &JsonObject,
    ) -> CallToolResponse {
        let Some(conn_id) = args.get("connection").and_then(Value::as_str) else {
            return fail("connection is required");
        };
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return fail("command is required");
        };
        let timeout_secs = args.get("timeout_secs").and_then(Value::as_u64);
        let Some((scope, folder, entry)) = parse_connection_id(conn_id) else {
            return fail("connection must be an id from list_connections, like shared/lab/web01");
        };
        let mode = match self.conns.resolve_ai_mode(scope, folder).await {
            Ok(m) => m,
            Err(e) => return fail(format!("cannot read the folder: {}", e)),
        };
        if mode == AiMode::None || !agent.reaches(scope, folder) {
            return fail("no such connection for this agent");
        }
        if !mode.may_act() {
            return fail(format!(
                "{}/{} is observe-only for AI agents: commands are not allowed",
                scope, folder
            ));
        }
        let forced = (mode == AiMode::Approve).then(|| {
            approve_mode_rule(
                &format!("{}/{}", scope, folder),
                crate::policy::Action::SshCommand,
            )
        });
        let req = crate::api::RunCommandRequest {
            command: command.to_string(),
            timeout_secs,
        };
        let resp = crate::api::run_command(
            &self.manager,
            &self.db,
            &self.conns,
            id,
            scope,
            folder,
            entry,
            req,
            ip,
            forced,
        )
        .await;
        let status = resp.status();
        let body: Value = match axum::body::to_bytes(resp.into_body(), MAX_RUN_BODY).await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
            Err(e) => return fail(format!("could not read the result: {}", e)),
        };
        match status {
            StatusCode::OK => ok(body),
            _ => refusal(status, &body, "run_ssh"),
        }
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mybastion", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "My Bastion: privileged access through a recorded, policy-checked gateway. \
                 Call list_connections first. Everything you do is audited under your agent \
                 name; some actions wait for a person's approval.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some((id, agent, ip)) = caller(&context) else {
            return Err(McpError::invalid_request("not authenticated", None));
        };
        let args = request.arguments.unwrap_or_default();
        tracing::info!(agent = %id.display_name(), tool = %request.name, "MCP tool call");
        Ok(match request.name.as_ref() {
            "list_connections" => self.list_connections(&agent, &args).await,
            "run_ssh" => self.run_ssh(&id, &agent, ip, &args).await,
            "click" | "scroll" | "type_text" | "key" => {
                self.input(request.name.as_ref(), &id, &agent, ip, &args)
                    .await
            }
            "open_session" => self.open_session(&id, &agent, ip, &args).await,
            "screenshot" => self.screenshot(&id, &args).await,
            "wait" => self.wait(&id, &args).await,
            "list_sessions" => self.list_sessions(&id),
            "close_session" => self.close_session(&id, &args).await,
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown tool '{}'", other),
                    None,
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_round_trip() {
        let id = connection_id("shared", "lab/linux", "web01");
        assert_eq!(
            parse_connection_id(&id),
            Some(("shared", "lab/linux", "web01"))
        );
        assert_eq!(parse_connection_id("shared/web01"), None);
        assert_eq!(parse_connection_id("other/lab/web01"), None);
        assert_eq!(
            parse_connection_id("/instance/dev/box/"),
            Some(("instance", "dev", "box"))
        );
    }

    #[test]
    fn tools_have_object_schemas() {
        let t = tools();
        assert_eq!(
            t.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>(),
            vec![
                "list_connections",
                "run_ssh",
                "open_session",
                "screenshot",
                "wait",
                "list_sessions",
                "close_session",
                "click",
                "type_text",
                "key",
                "scroll"
            ]
        );
        assert!(t
            .iter()
            .all(|t| t.input_schema.get("type") == Some(&json!("object"))));
    }
}
