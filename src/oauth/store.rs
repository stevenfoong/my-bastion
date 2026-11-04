//! OAuth tables in the main database: registered clients, the client names
//! admins approve, grants (a person's consent to a client), one-time codes
//! and tokens. Codes and tokens are stored as SHA-256 hashes.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id     TEXT PRIMARY KEY,
            client_name   TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_client_names (
            name       TEXT PRIMARY KEY,
            status     TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            decided_by TEXT,
            decided_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS oauth_grants (
            id           TEXT PRIMARY KEY,
            email        TEXT NOT NULL,
            client_id    TEXT NOT NULL,
            client_name  TEXT NOT NULL,
            scopes       TEXT NOT NULL,
            idp_linked   INTEGER NOT NULL DEFAULT 0,
            created_at   INTEGER NOT NULL,
            last_used_at INTEGER,
            revoked_at   INTEGER,
            revoked_why  TEXT
        );
        CREATE INDEX IF NOT EXISTS oauth_grants_email ON oauth_grants (email);

        CREATE TABLE IF NOT EXISTS oauth_codes (
            code_hash      TEXT PRIMARY KEY,
            grant_id       TEXT NOT NULL,
            client_id      TEXT NOT NULL,
            redirect_uri   TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            expires_at     INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_tokens (
            token_hash TEXT PRIMARY KEY,
            kind       TEXT NOT NULL,
            grant_id   TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at    INTEGER
        );
        CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens (grant_id);",
    )
}

pub fn hash(secret: &str) -> String {
    crate::db::hash_key(secret)
}

// ── Clients ──

#[derive(Debug, Clone, Serialize)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

pub fn insert_client(conn: &Connection, c: &Client, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            c.client_id,
            c.client_name,
            serde_json::to_string(&c.redirect_uris).unwrap_or_default(),
            now
        ],
    )?;
    Ok(())
}

pub fn get_client(conn: &Connection, client_id: &str) -> rusqlite::Result<Option<Client>> {
    conn.query_row(
        "SELECT client_id, client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
        [client_id],
        |r| {
            let uris: String = r.get(2)?;
            Ok(Client {
                client_id: r.get(0)?,
                client_name: r.get(1)?,
                redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
            })
        },
    )
    .optional()
}

/// A client name's status: `approved`, `denied` or `pending`. A name seen
/// for the first time is recorded, approved if `preapproved`.
pub fn name_status(
    conn: &Connection,
    name: &str,
    preapproved: bool,
    now: i64,
) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT OR IGNORE INTO oauth_client_names (name, status, first_seen, decided_by)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            name,
            if preapproved { "approved" } else { "pending" },
            now,
            preapproved.then_some("config")
        ],
    )?;
    if preapproved {
        // A name added to `approved_clients` later approves what waits.
        conn.execute(
            "UPDATE oauth_client_names SET status = 'approved', decided_by = 'config'
             WHERE name = ?1 AND status = 'pending'",
            [name],
        )?;
    }
    conn.query_row(
        "SELECT status FROM oauth_client_names WHERE name = ?1",
        [name],
        |r| r.get(0),
    )
}

#[derive(Debug, Serialize)]
pub struct ClientName {
    pub name: String,
    pub status: String,
    pub first_seen: i64,
    pub decided_by: Option<String>,
    pub clients: i64,
    pub grants: i64,
}

pub fn list_names(conn: &Connection) -> rusqlite::Result<Vec<ClientName>> {
    let mut stmt = conn.prepare(
        "SELECT n.name, n.status, n.first_seen, n.decided_by,
             (SELECT count(*) FROM oauth_clients c WHERE c.client_name = n.name),
             (SELECT count(*) FROM oauth_grants g WHERE g.client_name = n.name AND g.revoked_at IS NULL)
         FROM oauth_client_names n ORDER BY n.status = 'pending' DESC, n.name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ClientName {
            name: r.get(0)?,
            status: r.get(1)?,
            first_seen: r.get(2)?,
            decided_by: r.get(3)?,
            clients: r.get(4)?,
            grants: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn decide_name(
    conn: &Connection,
    name: &str,
    approve: bool,
    by: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE oauth_client_names SET status = ?2, decided_by = ?3, decided_at = ?4 WHERE name = ?1",
        params![name, if approve { "approved" } else { "denied" }, by, now],
    )? > 0)
}

// ── Grants ──

#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    pub id: String,
    pub email: String,
    pub client_id: String,
    pub client_name: String,
    pub scopes: String,
    pub idp_linked: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_why: Option<String>,
}

const GRANT_COLS: &str = "id, email, client_id, client_name, scopes, idp_linked, created_at,
    last_used_at, revoked_at, revoked_why";

fn grant_row(r: &rusqlite::Row) -> rusqlite::Result<Grant> {
    Ok(Grant {
        id: r.get(0)?,
        email: r.get(1)?,
        client_id: r.get(2)?,
        client_name: r.get(3)?,
        scopes: r.get(4)?,
        idp_linked: r.get::<_, i64>(5)? != 0,
        created_at: r.get(6)?,
        last_used_at: r.get(7)?,
        revoked_at: r.get(8)?,
        revoked_why: r.get(9)?,
    })
}

pub fn insert_grant(conn: &Connection, g: &Grant) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO oauth_grants (id, email, client_id, client_name, scopes, idp_linked, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            g.id,
            g.email,
            g.client_id,
            g.client_name,
            g.scopes,
            g.idp_linked as i64,
            g.created_at
        ],
    )?;
    Ok(())
}

pub fn get_grant(conn: &Connection, id: &str) -> rusqlite::Result<Option<Grant>> {
    conn.query_row(
        &format!("SELECT {GRANT_COLS} FROM oauth_grants WHERE id = ?1"),
        [id],
        grant_row,
    )
    .optional()
}

/// Grants, newest first: one person's (`email`), or everyone's.
pub fn list_grants(conn: &Connection, email: Option<&str>) -> rusqlite::Result<Vec<Grant>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {GRANT_COLS} FROM oauth_grants
         WHERE (?1 IS NULL OR email = ?1 COLLATE NOCASE)
         ORDER BY revoked_at IS NOT NULL, created_at DESC LIMIT 500"
    ))?;
    let rows = stmt.query_map([email], grant_row)?;
    rows.collect()
}

/// Revoke a grant and every token of it. `false` when it was not live.
pub fn revoke_grant(conn: &Connection, id: &str, why: &str, now: i64) -> rusqlite::Result<bool> {
    conn.execute("DELETE FROM oauth_tokens WHERE grant_id = ?1", [id])?;
    conn.execute("DELETE FROM oauth_codes WHERE grant_id = ?1", [id])?;
    Ok(conn.execute(
        "UPDATE oauth_grants SET revoked_at = ?2, revoked_why = ?3 WHERE id = ?1 AND revoked_at IS NULL",
        params![id, now, why],
    )? > 0)
}

/// Revoke every live grant of a client name (an admin denied it); their ids.
pub fn revoke_name_grants(
    conn: &Connection,
    name: &str,
    now: i64,
) -> rusqlite::Result<Vec<String>> {
    let ids: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT id FROM oauth_grants WHERE client_name = ?1 AND revoked_at IS NULL")?;
        let rows = stmt.query_map([name], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for id in &ids {
        revoke_grant(conn, id, "client denied by an admin", now)?;
    }
    Ok(ids)
}

pub fn touch_grant(conn: &Connection, id: &str, now: i64) {
    let _ = conn.execute(
        "UPDATE oauth_grants SET last_used_at = ?2 WHERE id = ?1",
        params![id, now],
    );
}

// ── Codes ──

pub struct Code {
    pub grant_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub expires_at: i64,
}

pub fn insert_code(conn: &Connection, code: &str, c: &Code) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![hash(code), c.grant_id, c.client_id, c.redirect_uri, c.code_challenge, c.expires_at],
    )?;
    Ok(())
}

/// Take a code: it works once.
pub fn take_code(conn: &Connection, code: &str) -> rusqlite::Result<Option<Code>> {
    let h = hash(code);
    let c = conn
        .query_row(
            "SELECT grant_id, client_id, redirect_uri, code_challenge, expires_at
             FROM oauth_codes WHERE code_hash = ?1",
            [&h],
            |r| {
                Ok(Code {
                    grant_id: r.get(0)?,
                    client_id: r.get(1)?,
                    redirect_uri: r.get(2)?,
                    code_challenge: r.get(3)?,
                    expires_at: r.get(4)?,
                })
            },
        )
        .optional()?;
    conn.execute("DELETE FROM oauth_codes WHERE code_hash = ?1", [&h])?;
    Ok(c)
}

// ── Tokens ──

pub struct Token {
    pub kind: String,
    pub grant_id: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
}

pub fn insert_token(
    conn: &Connection,
    token: &str,
    kind: &str,
    grant_id: &str,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO oauth_tokens (token_hash, kind, grant_id, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![hash(token), kind, grant_id, expires_at],
    )?;
    Ok(())
}

pub fn get_token(conn: &Connection, token: &str) -> rusqlite::Result<Option<Token>> {
    conn.query_row(
        "SELECT kind, grant_id, expires_at, used_at FROM oauth_tokens WHERE token_hash = ?1",
        [hash(token)],
        |r| {
            Ok(Token {
                kind: r.get(0)?,
                grant_id: r.get(1)?,
                expires_at: r.get(2)?,
                used_at: r.get(3)?,
            })
        },
    )
    .optional()
}

/// Mark a refresh token used. `false` when it already was (a replay).
pub fn use_refresh(conn: &Connection, token: &str, now: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE oauth_tokens SET used_at = ?2
         WHERE token_hash = ?1 AND kind = 'refresh' AND used_at IS NULL",
        params![hash(token), now],
    )? > 0)
}

/// Drop expired codes and tokens, and used refresh tokens (kept a day so a
/// replay is still recognised).
pub fn prune(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    let a = conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?1", [now])?;
    let b = conn.execute(
        "DELETE FROM oauth_tokens WHERE expires_at < ?1 OR (used_at IS NOT NULL AND used_at < ?2)",
        params![now, now - 86_400],
    )?;
    Ok(a + b)
}

/// Update a user's groups (and nothing else) after the identity provider
/// was asked again.
pub fn set_user_groups(conn: &Connection, email: &str, groups: &[String]) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET oidc_groups = ?2 WHERE email = ?1 COLLATE NOCASE",
        params![email, groups.join(",")],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    fn grant(id: &str) -> Grant {
        Grant {
            id: id.into(),
            email: "u@x".into(),
            client_id: "c1".into(),
            client_name: "Claude".into(),
            scopes: "mcp:read mcp:act".into(),
            idp_linked: true,
            created_at: 10,
            last_used_at: None,
            revoked_at: None,
            revoked_why: None,
        }
    }

    #[test]
    fn client_names_wait_for_approval_unless_preapproved() {
        let c = conn();
        assert_eq!(name_status(&c, "Claude", false, 1).unwrap(), "pending");
        assert_eq!(name_status(&c, "Claude", false, 2).unwrap(), "pending");
        assert!(decide_name(&c, "Claude", false, "boss", 3).unwrap());
        assert_eq!(name_status(&c, "Claude", false, 4).unwrap(), "denied");
        // Config approves only what waits, never a name an admin denied.
        assert_eq!(name_status(&c, "Claude", true, 5).unwrap(), "denied");
        assert_eq!(name_status(&c, "Other", false, 5).unwrap(), "pending");
        assert_eq!(name_status(&c, "Other", true, 6).unwrap(), "approved");
    }

    #[test]
    fn codes_work_once_and_revoking_a_grant_drops_its_tokens() {
        let c = conn();
        insert_grant(&c, &grant("g1")).unwrap();
        let code = Code {
            grant_id: "g1".into(),
            client_id: "c1".into(),
            redirect_uri: "https://x/cb".into(),
            code_challenge: "abc".into(),
            expires_at: 100,
        };
        insert_code(&c, "the-code", &code).unwrap();
        assert!(take_code(&c, "the-code").unwrap().is_some());
        assert!(take_code(&c, "the-code").unwrap().is_none());

        insert_token(&c, "rt1", "refresh", "g1", 1000).unwrap();
        insert_token(&c, "at1", "access", "g1", 1000).unwrap();
        assert!(use_refresh(&c, "rt1", 50).unwrap());
        assert!(!use_refresh(&c, "rt1", 51).unwrap(), "a replay is seen");
        assert!(
            !use_refresh(&c, "at1", 51).unwrap(),
            "an access token is not a refresh token"
        );
        assert!(revoke_grant(&c, "g1", "test", 60).unwrap());
        assert!(get_token(&c, "at1").unwrap().is_none());
        assert!(!revoke_grant(&c, "g1", "again", 61).unwrap());
        assert_eq!(
            get_grant(&c, "g1").unwrap().unwrap().revoked_why.as_deref(),
            Some("test")
        );
        // Secrets are stored hashed.
        let raw: i64 = c
            .query_row(
                "SELECT count(*) FROM oauth_codes WHERE code_hash = 'the-code'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(raw, 0);
    }
}
