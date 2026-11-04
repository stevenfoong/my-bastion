//! Who is calling `/mcp`: an AI agent key (`Authorization: Bearer mbai_…`),
//! or, with `[mcp.oauth]`, a person's OAuth access token (`mbat_…`) from an
//! AI client. Admin keys, user tokens and session cookies are not accepted
//! here, so nothing reaches MCP with more than an agent's (or that person
//! through their AI client's) rights.

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::SocketAddr;

use super::agents;
use super::Caller;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::Db;

/// `[mcp.oauth]`, when on: the 401 tells clients where to sign in.
#[derive(Clone)]
pub struct OAuthHint(pub Option<crate::config::OAuthConfig>);

fn refuse(hint: &OAuthHint, status: StatusCode, error: Option<&str>, msg: &str) -> Response {
    let mut challenge = r#"Bearer realm="mybastion-mcp""#.to_string();
    if let Some(cfg) = &hint.0 {
        challenge += &format!(
            r#", resource_metadata="{}/.well-known/oauth-protected-resource""#,
            cfg.issuer()
        );
    }
    if let Some(e) = error {
        challenge += &format!(r#", error="{}""#, e);
    }
    (
        status,
        [(header::WWW_AUTHENTICATE, challenge)],
        axum::Json(json!({ "error": msg })),
    )
        .into_response()
}

/// Puts the caller's `AuthIdentity` (`AiAgent` or `AiUser`), its `Caller`
/// and the client address (`McpClientIp`) on the request, or answers
/// 401/403.
pub async fn require_mcp_caller(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let hint = request
        .extensions()
        .get::<OAuthHint>()
        .cloned()
        .unwrap_or(OAuthHint(None));
    let Some(db) = request.extensions().get::<Db>().cloned() else {
        return refuse(
            &hint,
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "no database",
        );
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
        return refuse(
            &hint,
            StatusCode::UNAUTHORIZED,
            None,
            "authentication required",
        );
    };

    if hint.0.is_some() && key.starts_with(crate::oauth::ACCESS_PREFIX) {
        let db2 = db.clone();
        let result = tokio::task::spawn_blocking(move || crate::oauth::check_access(&db2, &key))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        return match result {
            Ok(of) => {
                let id = crate::oauth::identity(&of);
                let caller = Caller::User {
                    email: of.user.email.clone(),
                    role: of.user.role.clone(),
                    groups: of.user.groups_vec(),
                    scopes: of
                        .grant
                        .scopes
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                };
                request.extensions_mut().insert(id);
                request.extensions_mut().insert(caller);
                request.extensions_mut().insert(McpClientIp(ip.to_string()));
                next.run(request).await
            }
            Err(e) => {
                tracing::warn!(client_ip = %ip, reason = %e, "MCP: OAuth token refused");
                refuse(&hint, StatusCode::UNAUTHORIZED, Some("invalid_token"), &e)
            }
        };
    }

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
            request.extensions_mut().insert(Caller::Agent(agent));
            request.extensions_mut().insert(McpClientIp(ip.to_string()));
            next.run(request).await
        }
        Err(agents::KeyError::Invalid) => {
            tracing::warn!(client_ip = %ip, "MCP: invalid AI agent key or token");
            refuse(
                &hint,
                StatusCode::UNAUTHORIZED,
                Some("invalid_token"),
                "invalid AI agent key or token",
            )
        }
        Err(e) => {
            tracing::warn!(client_ip = %ip, reason = %e, "MCP: AI agent key refused");
            refuse(&hint, StatusCode::FORBIDDEN, None, &e.to_string())
        }
    }
}

/// The caller's address, resolved through `trusted_proxies`.
#[derive(Clone, Debug)]
pub struct McpClientIp(pub String);
