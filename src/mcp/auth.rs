//! Who is calling `/mcp`: an AI agent key (`Authorization: Bearer mbai_…`).
//! Admin keys, user tokens and session cookies are not accepted here, so
//! nothing reaches MCP with more than an agent's rights. OAuth for people
//! using an AI client comes later and resolves here too.

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::SocketAddr;

use super::agents::{self, Agent};
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::Db;

fn refuse(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::WWW_AUTHENTICATE, r#"Bearer realm="mybastion-mcp""#)],
        axum::Json(json!({ "error": msg })),
    )
        .into_response()
}

/// Puts the caller's `AuthIdentity::AiAgent`, its `Agent` and the client
/// address (`McpClientIp`) on the request, or answers 401/403.
pub async fn require_agent(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(db) = request.extensions().get::<Db>().cloned() else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "no database");
    };
    let proxies = request
        .extensions()
        .get::<TrustedProxies>()
        .map(|t| t.0.clone())
        .unwrap_or_default();
    let ip = client_ip(request.headers(), addr.ip(), &proxies);
    let Some(key) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|k| k.trim().to_string())
    else {
        return refuse(StatusCode::UNAUTHORIZED, "an AI agent key is required");
    };
    let result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().map_err(|_| agents::KeyError::Invalid)?;
        agents::validate(&conn, &key, Some(ip))
    })
    .await
    .unwrap_or(Err(agents::KeyError::Invalid));
    match result {
        Ok(agent) => {
            let id = AuthIdentity::AiAgent(agent.identity());
            request.extensions_mut().insert(id);
            request.extensions_mut().insert::<Agent>(agent);
            request.extensions_mut().insert(McpClientIp(ip.to_string()));
            next.run(request).await
        }
        Err(agents::KeyError::Invalid) => {
            tracing::warn!(client_ip = %ip, "MCP: invalid AI agent key");
            refuse(StatusCode::UNAUTHORIZED, "invalid AI agent key")
        }
        Err(e) => {
            tracing::warn!(client_ip = %ip, reason = %e, "MCP: AI agent key refused");
            refuse(StatusCode::FORBIDDEN, &e.to_string())
        }
    }
}

/// The caller's address, resolved through `trusted_proxies`.
#[derive(Clone, Debug)]
pub struct McpClientIp(pub String);
