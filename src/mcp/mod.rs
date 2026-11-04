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
