//! AI agent keys: the identity of an unattended agent (a script, a scheduled
//! job, Claude Code) on `/mcp`, as `ai:<name>`.
//!
//! A key works on `/mcp` only: it lives in its own table, which the REST
//! authentication never reads, so every REST and admin route refuses it.
//! Keys are stored as SHA-256 hashes, with an optional IP allowlist and
//! expiry like admin keys, and an optional list of folders (`scope/path`,
//! each with everything under it) that narrows what the agent reaches
//! beyond the folders' own AI mode.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::net::IpAddr;

/// Every agent key starts with this, so a leaked one is easy to recognise.
pub const KEY_PREFIX: &str = "mbai_";
const MAX_FOLDERS: usize = 100;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ai_agents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE,
            key_hash     TEXT NOT NULL,
            folders      TEXT NOT NULL DEFAULT '[]',
            allowed_ips  TEXT,
            expires_at   TEXT,
            disabled     INTEGER NOT NULL DEFAULT 0,
            created_by   TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            last_used_at TEXT
        );",
    )
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Agent {
    pub id: i64,
    pub name: String,
    /// `scope/path` folders it may reach; empty: every folder AI may use.
    pub folders: Vec<String>,
    pub allowed_ips: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl Agent {
    /// The identity it acts as: `ai:<name>`.
    pub fn identity(&self) -> String {
        format!("ai:{}", self.name)
    }

    /// Whether its own folder list lets it reach `folder` in `scope`.
    pub fn reaches(&self, scope: &str, folder: &str) -> bool {
        self.folders.is_empty()
            || self.folders.iter().any(|f| {
                let want = format!("{}/{}", scope, folder);
                want == *f || want.starts_with(&format!("{}/", f))
            })
    }
}

/// Why a key was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    Invalid,
    Disabled,
    Expired,
    IpNotAllowed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyError::Invalid => "invalid AI agent key",
            KeyError::Disabled => "AI agent is disabled",
            KeyError::Expired => "AI agent key has expired",
            KeyError::IpNotAllowed => "client IP not in the agent's allowed list",
        })
    }
}

pub fn valid_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err("agent name must be 1-64 letters, digits, '-', '_' or '.'".into())
    }
}

/// Check and tidy a folder list: `shared/<path>` or `instance/<path>`.
pub fn normalize_folders(folders: Vec<String>) -> Result<Vec<String>, String> {
    if folders.len() > MAX_FOLDERS {
        return Err(format!("at most {} folders", MAX_FOLDERS));
    }
    let mut out = Vec::new();
    for f in folders {
        let f = f.trim().trim_matches('/').to_string();
        if f.is_empty() {
            continue;
        }
        let (scope, path) = f.split_once('/').unwrap_or((&f, ""));
        if !matches!(scope, "shared" | "instance") || path.is_empty() {
            return Err(format!(
                "folder '{}' must be shared/<path> or instance/<path>",
                f
            ));
        }
        if path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s.starts_with('.'))
        {
            return Err(format!("folder '{}' is not a valid path", f));
        }
        if !out.contains(&f) {
            out.push(f);
        }
    }
    Ok(out)
}

/// Create an agent; its key, shown once.
pub fn create(
    conn: &Connection,
    name: &str,
    folders: &[String],
    allowed_ips: Option<&str>,
    expires_at: Option<&str>,
    by: &str,
) -> Result<String, String> {
    valid_name(name)?;
    if let Some(ips) = allowed_ips {
        for cidr in ips.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|_| format!("'{}' is not an IP network", cidr))?;
        }
    }
    if let Some(exp) = expires_at {
        crate::db::parse_expires_at(exp).ok_or("expires must be a date or RFC 3339 time")?;
    }
    let key = format!("{}{}", KEY_PREFIX, crate::db::generate_key());
    let folders = serde_json::to_string(folders).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO ai_agents (name, key_hash, folders, allowed_ips, expires_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            name,
            crate::db::hash_key(&key),
            folders,
            allowed_ips.filter(|s| !s.trim().is_empty()),
            expires_at.filter(|s| !s.trim().is_empty()),
            by
        ],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            format!("an agent named '{}' already exists", name)
        }
        e => e.to_string(),
    })?;
    Ok(key)
}

const COLS: &str =
    "id, name, folders, allowed_ips, expires_at, disabled, created_by, created_at, last_used_at";

fn from_row(r: &rusqlite::Row) -> rusqlite::Result<Agent> {
    let folders: String = r.get(2)?;
    Ok(Agent {
        id: r.get(0)?,
        name: r.get(1)?,
        folders: serde_json::from_str(&folders).unwrap_or_default(),
        allowed_ips: r.get(3)?,
        expires_at: r.get(4)?,
        disabled: r.get::<_, i64>(5)? != 0,
        created_by: r.get(6)?,
        created_at: r.get(7)?,
        last_used_at: r.get(8)?,
    })
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Agent>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM ai_agents ORDER BY name"))?;
    let rows = stmt.query_map([], from_row)?;
    rows.collect()
}

pub fn get(conn: &Connection, name: &str) -> rusqlite::Result<Option<Agent>> {
    conn.query_row(
        &format!("SELECT {COLS} FROM ai_agents WHERE name = ?1"),
        [name],
        from_row,
    )
    .optional()
}

pub fn delete(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM ai_agents WHERE name = ?1", [name])? > 0)
}

pub fn set_disabled(conn: &Connection, name: &str, disabled: bool) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE ai_agents SET disabled = ?2 WHERE name = ?1",
        params![name, disabled as i64],
    )? > 0)
}

/// The agent a key belongs to, if it may be used now from `ip`. Records
/// the use.
pub fn validate(conn: &Connection, key: &str, ip: Option<IpAddr>) -> Result<Agent, KeyError> {
    use subtle::ConstantTimeEq;
    if !key.starts_with(KEY_PREFIX) {
        return Err(KeyError::Invalid);
    }
    let hash = crate::db::hash_key(key);
    let mut stmt = conn
        .prepare(&format!("SELECT {COLS}, key_hash FROM ai_agents"))
        .map_err(|_| KeyError::Invalid)?;
    let agent = stmt
        .query_map([], |r| Ok((from_row(r)?, r.get::<_, String>(9)?)))
        .map_err(|_| KeyError::Invalid)?
        .filter_map(|r| r.ok())
        .find(|(_, stored)| hash.as_bytes().ct_eq(stored.as_bytes()).into())
        .map(|(a, _)| a)
        .ok_or(KeyError::Invalid)?;
    if agent.disabled {
        return Err(KeyError::Disabled);
    }
    if let Some(exp) = &agent.expires_at {
        match crate::db::parse_expires_at(exp) {
            Some(t) if chrono::Utc::now() <= t => {}
            _ => return Err(KeyError::Expired),
        }
    }
    if let (Some(cidrs), Some(ip)) = (&agent.allowed_ips, ip) {
        let allowed = cidrs.split(',').any(|c| {
            c.trim()
                .parse::<ipnetwork::IpNetwork>()
                .is_ok_and(|n| n.contains(ip))
        });
        if !allowed {
            return Err(KeyError::IpNotAllowed);
        }
    }
    let _ = conn.execute(
        "UPDATE ai_agents SET last_used_at = datetime('now') WHERE id = ?1",
        [agent.id],
    );
    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    #[test]
    fn keys_validate_and_respect_their_limits() {
        let c = conn();
        let key = create(&c, "nightly", &[], Some("10.0.0.0/8"), None, "admin").unwrap();
        assert!(key.starts_with(KEY_PREFIX));
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert_eq!(
            validate(&c, &key, ip("10.1.2.3")).unwrap().identity(),
            "ai:nightly"
        );
        assert_eq!(
            validate(&c, &key, ip("192.0.2.1")),
            Err(KeyError::IpNotAllowed)
        );
        assert_eq!(validate(&c, "mbai_nope", None), Err(KeyError::Invalid));
        // An admin-style key without the prefix is never an agent key.
        assert_eq!(
            validate(&c, &key[KEY_PREFIX.len()..], ip("10.1.2.3")),
            Err(KeyError::Invalid)
        );
        set_disabled(&c, "nightly", true).unwrap();
        assert_eq!(validate(&c, &key, ip("10.1.2.3")), Err(KeyError::Disabled));

        let old = create(&c, "old", &[], None, Some("2020-01-01"), "admin").unwrap();
        assert_eq!(validate(&c, &old, None), Err(KeyError::Expired));
        assert!(create(&c, "old", &[], None, None, "admin")
            .unwrap_err()
            .contains("already"));
        assert!(create(&c, "bad name", &[], None, None, "admin").is_err());
        assert!(create(&c, "x", &[], Some("not-a-net"), None, "admin").is_err());
        assert!(delete(&c, "old").unwrap());
        assert_eq!(list(&c).unwrap().len(), 1);
    }

    #[test]
    fn folder_lists_narrow_what_an_agent_reaches() {
        let f = normalize_folders(vec![
            "shared/lab/".into(),
            " shared/lab".into(),
            "instance/dev".into(),
        ])
        .unwrap();
        assert_eq!(f, vec!["shared/lab", "instance/dev"]);
        assert!(normalize_folders(vec!["lab".into()]).is_err());
        assert!(normalize_folders(vec!["shared/../prod".into()]).is_err());
        let a = Agent {
            id: 1,
            name: "a".into(),
            folders: f,
            allowed_ips: None,
            expires_at: None,
            disabled: false,
            created_by: String::new(),
            created_at: String::new(),
            last_used_at: None,
        };
        assert!(a.reaches("shared", "lab"));
        assert!(a.reaches("shared", "lab/linux"));
        assert!(!a.reaches("shared", "laboratory"));
        assert!(!a.reaches("shared", "prod"));
        assert!(a.reaches("instance", "dev"));
        let any = Agent {
            folders: vec![],
            ..a
        };
        assert!(any.reaches("shared", "prod"));
    }
}
