//! MCP endpoint (Phase 3 of `docs/fork-design.md`): AI agents reach
//! connections through `/mcp`, under the same policies, approvals and audit
//! as people, and only in folders whose AI mode lets them.
//!
//! - `agents.rs`: AI agent keys (`ai:<name>` identities), their table, CLI
//!   and admin API.
//! - `auth.rs`: `/mcp` authentication (agent keys only).
//! - `server.rs`: the MCP server and its tools.
//!
//! Off unless `[mcp] enabled = true`.

pub mod agents;
pub mod api;
pub mod auth;
pub mod server;
pub mod sessions;

use crate::api::Connections;
use crate::auth::role_level;

/// Who is calling `/mcp`.
#[derive(Debug, Clone)]
pub enum Caller {
    /// An AI agent key (`ai:<name>`).
    Agent(agents::Agent),
    /// A person through an AI client, with an OAuth token.
    User {
        email: String,
        role: String,
        groups: Vec<String>,
        scopes: Vec<String>,
    },
}

impl Caller {
    /// Whether the caller may use `folder` (its AI mode aside): an agent
    /// key's own folder list, or the person's own folder access.
    pub async fn reaches(&self, conns: &Connections, scope: &str, folder: &str) -> bool {
        match self {
            Caller::Agent(a) => a.reaches(scope, folder),
            Caller::User {
                email,
                role,
                groups,
                ..
            } => {
                role_level(role) >= role_level("admin")
                    || conns
                        .resolve_folder_access(
                            scope,
                            folder,
                            crate::connections::FolderSubject {
                                email: Some(email),
                                groups,
                            },
                        )
                        .await
                        .unwrap_or(false)
            }
        }
    }

    /// Whether the token's scopes allow `scope` (agent keys: always).
    pub fn has_scope(&self, scope: &str) -> bool {
        match self {
            Caller::Agent(_) => true,
            Caller::User { scopes, .. } => scopes.iter().any(|s| s == scope),
        }
    }

    /// Whether the caller may open sessions and act: a person needs at
    /// least the operator role, as on the web.
    pub fn may_connect(&self) -> bool {
        match self {
            Caller::Agent(_) => true,
            Caller::User { role, .. } => role_level(role) >= role_level("operator"),
        }
    }
}
