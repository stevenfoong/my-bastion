//! OAuth 2.1 for people using an AI client on `/mcp` (Phase 3 of
//! `docs/fork-design.md`), following the MCP authorization spec.
//!
//! The bastion is its own authorization server, built on the `[oidc]`
//! login: a person signs in through the usual identity provider, approves a
//! consent screen for the client, and the client gets short-lived access
//! tokens bound to `<public_url>/mcp` plus a rotating refresh token.
//!
//! - **Clients** register themselves (RFC 7591); a client *name* (e.g.
//!   "Claude") is approved once by an admin, or in `approved_clients`.
//! - **Authorization code + PKCE (S256)** only: no implicit flow, no
//!   password grant, no client secrets (public clients).
//! - **Tokens** are opaque and stored hashed: access `mbat_…` (default 15
//!   minutes), refresh `mbrt_…` (30 days), rotated on every use; a refresh
//!   token used twice revokes the whole grant.
//! - **The person's access is checked again on every refresh**: the user
//!   must still exist and not be disabled, and when the identity provider
//!   gave a refresh token at consent (kept encrypted in the secret store),
//!   it is asked again, so a removal there (or from a group) cuts the AI off
//!   by the next refresh. Without one, a grant needs a new sign-in after
//!   `reauth_hours`.
//! - On `/mcp` the caller is `AuthIdentity::AiUser`, `user:<email> via
//!   ai:<client>`: the person's own role, groups and folder access, only in
//!   folders whose AI mode lets AI in. Scopes: `mcp:read` (list, open,
//!   look), `mcp:act` (input, `run_ssh`).

pub mod routes;
pub mod store;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::config::OAuthConfig;
use crate::db::Db;

pub const SCOPE_READ: &str = "mcp:read";
pub const SCOPE_ACT: &str = "mcp:act";
pub const ACCESS_PREFIX: &str = "mbat_";
const REFRESH_PREFIX: &str = "mbrt_";
/// How long an authorization code is good for.
const CODE_SECS: i64 = 60;

pub fn now() -> i64 {
    crate::policy::store::now_secs()
}

fn secret(prefix: &str) -> String {
    format!("{}{}", prefix, crate::db::generate_key())
}

/// `S256`: the challenge is base64url(sha256(verifier)), without padding.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    use subtle::ConstantTimeEq;
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// A redirect URI a client may register: https anywhere, or http on the
/// loopback interface (native apps); no fragment.
pub fn valid_redirect_uri(uri: &str) -> bool {
    let Ok(u) = url::Url::parse(uri) else {
        return false;
    };
    if u.fragment().is_some() || uri.len() > 2000 {
        return false;
    }
    match (u.scheme(), u.host_str()) {
        ("https", Some(_)) => true,
        ("http", Some(h)) => is_loopback(h),
        _ => false,
    }
}

/// Whether `asked` is one of `registered`: exactly, or for a loopback URI
/// with any port (RFC 8252 §7.3).
pub fn redirect_matches(registered: &[String], asked: &str) -> bool {
    if registered.iter().any(|r| r == asked) {
        return true;
    }
    let Ok(a) = url::Url::parse(asked) else {
        return false;
    };
    if a.scheme() != "http" || !a.host_str().is_some_and(is_loopback) {
        return false;
    }
    registered.iter().any(|r| {
        url::Url::parse(r).is_ok_and(|r| {
            r.scheme() == a.scheme()
                && r.host_str() == a.host_str()
                && r.path() == a.path()
                && r.query() == a.query()
        })
    })
}

/// The scopes asked for, checked; none asked means both.
pub fn parse_scopes(scope: Option<&str>) -> Result<Vec<&'static str>, String> {
    let asked: Vec<&str> = scope.unwrap_or("").split_whitespace().collect();
    if asked.is_empty() {
        return Ok(vec![SCOPE_READ, SCOPE_ACT]);
    }
    let mut out = Vec::new();
    for s in asked {
        let known = match s {
            SCOPE_READ => SCOPE_READ,
            SCOPE_ACT => SCOPE_ACT,
            other => return Err(format!("unknown scope '{}'", other)),
        };
        if !out.contains(&known) {
            out.push(known);
        }
    }
    Ok(out)
}

/// Tokens issued to a client.
#[derive(Debug, serde::Serialize)]
pub struct Issued {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
}

/// Issue a fresh access + refresh token pair for a grant.
pub fn issue(
    conn: &rusqlite::Connection,
    cfg: &OAuthConfig,
    grant: &store::Grant,
) -> rusqlite::Result<Issued> {
    let now = now();
    let access = secret(ACCESS_PREFIX);
    let refresh = secret(REFRESH_PREFIX);
    let access_secs = i64::from(cfg.access_token_minutes.max(1)) * 60;
    store::insert_token(conn, &access, "access", &grant.id, now + access_secs)?;
    store::insert_token(
        conn,
        &refresh,
        "refresh",
        &grant.id,
        now + i64::from(cfg.refresh_token_days.max(1)) * 86_400,
    )?;
    store::touch_grant(conn, &grant.id, now);
    Ok(Issued {
        access_token: access,
        token_type: "Bearer",
        expires_in: access_secs,
        refresh_token: refresh,
        scope: grant.scopes.clone(),
    })
}

/// A new authorization code for `grant`.
pub fn new_code(
    conn: &rusqlite::Connection,
    grant_id: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
) -> rusqlite::Result<String> {
    let code = crate::db::generate_key();
    store::insert_code(
        conn,
        &code,
        &store::Code {
            grant_id: grant_id.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            code_challenge: code_challenge.into(),
            expires_at: now() + CODE_SECS,
        },
    )?;
    Ok(code)
}

/// Who a valid access token acts for.
pub struct AccessOf {
    pub grant: store::Grant,
    pub user: crate::db::User,
}

/// Check an access token: live, of a live grant, for a user who is still
/// allowed in.
pub fn check_access(db: &Db, token: &str) -> Result<AccessOf, String> {
    if !token.starts_with(ACCESS_PREFIX) {
        return Err("invalid token".into());
    }
    let conn = db
        .lock()
        .map_err(|_| "database lock poisoned".to_string())?;
    let t = store::get_token(&conn, token)
        .map_err(|e| e.to_string())?
        .filter(|t| t.kind == "access")
        .ok_or("invalid token")?;
    if t.expires_at <= now() {
        return Err("token expired".into());
    }
    let grant = store::get_grant(&conn, &t.grant_id)
        .map_err(|e| e.to_string())?
        .filter(|g| g.revoked_at.is_none())
        .ok_or("grant revoked")?;
    let user = crate::db::user_by_email(&conn, &grant.email).ok_or("user no longer exists")?;
    if user.disabled {
        return Err("user is disabled".into());
    }
    store::touch_grant(&conn, &grant.id, now());
    Ok(AccessOf { grant, user })
}

/// The identity a token's caller has on `/mcp`.
pub fn identity(of: &AccessOf) -> crate::auth::AuthIdentity {
    crate::auth::AuthIdentity::AiUser {
        email: of.user.email.clone(),
        role: of.user.role.clone(),
        groups: of.user.groups_vec(),
        client: of.grant.client_name.clone(),
        display: format!("user:{} via ai:{}", of.user.email, of.grant.client_name),
    }
}

/// Write an audit row for an OAuth event.
pub fn audit(
    conn: &rusqlite::Connection,
    event: &str,
    actor: &str,
    target: &str,
    detail: Option<&str>,
) {
    let row = crate::policy::store::AuditEvent {
        event,
        actor,
        target,
        detail,
        ..Default::default()
    };
    if let Err(e) = crate::policy::store::audit(conn, &row, now()) {
        tracing::warn!(error = %e, "Failed to audit an OAuth event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX"
        ));
        assert!(!pkce_matches("short", "x"));
    }

    #[test]
    fn redirect_uris() {
        assert!(valid_redirect_uri(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(valid_redirect_uri("http://127.0.0.1:33418/callback"));
        assert!(valid_redirect_uri("http://localhost/cb"));
        assert!(!valid_redirect_uri("http://evil.example/cb"));
        assert!(!valid_redirect_uri("https://x/cb#frag"));
        assert!(!valid_redirect_uri("javascript:alert(1)"));
        let reg = vec![
            "http://127.0.0.1:1000/cb".to_string(),
            "https://a.example/cb".to_string(),
        ];
        assert!(redirect_matches(&reg, "http://127.0.0.1:5555/cb"));
        assert!(!redirect_matches(&reg, "http://127.0.0.1:5555/other"));
        assert!(redirect_matches(&reg, "https://a.example/cb"));
        assert!(!redirect_matches(&reg, "https://a.example/cb2"));
        assert!(!redirect_matches(&reg, "https://a.example:444/cb"));
    }

    #[test]
    fn scopes() {
        assert_eq!(parse_scopes(None).unwrap(), vec![SCOPE_READ, SCOPE_ACT]);
        assert_eq!(
            parse_scopes(Some("mcp:read mcp:read")).unwrap(),
            vec![SCOPE_READ]
        );
        assert!(parse_scopes(Some("mcp:read admin")).is_err());
    }

    #[test]
    fn a_persons_ai_is_not_the_person() {
        use crate::policy::{may_decide, Approver, Requester};
        let ai = Requester::from_identity(&crate::auth::AuthIdentity::AiUser {
            email: "Alice@x".into(),
            role: "admin".into(),
            groups: vec![],
            client: "Claude".into(),
            display: "user:Alice@x via ai:Claude".into(),
        });
        assert_eq!(ai.id(), "user:alice@x via ai:Claude");
        let alice = Requester::from_identity(&crate::auth::AuthIdentity::User {
            email: "alice@x".into(),
            role: "admin".into(),
            groups: vec![],
        });
        let admins = [Approver::Role("admin".into())];
        assert!(
            may_decide(&admins, &alice, &ai.id()).is_err(),
            "nobody approves their own AI"
        );
        let bob = Requester::from_identity(&crate::auth::AuthIdentity::User {
            email: "bob@x".into(),
            role: "admin".into(),
            groups: vec![],
        });
        assert!(may_decide(&admins, &bob, &ai.id()).is_ok());
    }
}
