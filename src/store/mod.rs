//! Where connection entries, folder configs and credential variables are
//! kept. `ConnectionStore` holds the mybastion logic (ACLs, folder defaults,
//! credential variables) and does its I/O through a `SecretStore`: one JSON
//! document per path, KV v2 style.

pub mod cli;
pub mod crypto;
pub mod sqlite;
pub mod vault;

use async_trait::async_trait;
use std::sync::Arc;

use crate::config::StorageConfig;
use crate::connections::ConnectionStore;

/// Open the SQLite store `[storage]` describes, as the address-book client.
pub fn open_sqlite(sc: &StorageConfig) -> Result<Arc<sqlite::SqliteStore>, String> {
    let kek = crypto::Key::load(&sc.kek_source)?;
    sqlite::SqliteStore::open(&sc.path, &kek)
        .map(Arc::new)
        .map_err(|e| format!("{}: {}", sc.path.display(), e))
}

/// `open_sqlite`, wrapped as the address-book client.
pub fn sqlite_client(sc: &StorageConfig) -> Result<ConnectionStore, String> {
    Ok(ConnectionStore::with_store(
        open_sqlite(sc)?,
        sc.base_path.clone(),
        sc.instance_name.clone(),
    ))
}

/// A stored document and the version it was read at.
#[derive(Debug, Clone)]
pub struct Doc {
    pub data: serde_json::Value,
    /// The document's version, counting from 1. Read for check-and-set
    /// writes; 0 when the backend didn't say.
    #[allow(dead_code)] // Read once a caller does check-and-set on update
    pub version: u64,
}

#[derive(Debug)]
pub enum StoreError {
    /// Logging in to the backend failed.
    Auth(String),
    Http(reqwest::Error),
    Forbidden,
    /// `list` or `delete` of a path with nothing there. `get` answers
    /// `Ok(None)` instead.
    NotFound,
    /// A check-and-set write found a different version in place.
    CasConflict,
    /// The backend answered with a status the operation doesn't expect.
    /// `ConnectionStore` turns it into the message for that operation.
    Rejected {
        status: u16,
        body: String,
    },
    /// A local store failed: database, file or decryption error.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(msg) => write!(f, "auth error: {}", msg),
            Self::Http(e) => write!(f, "HTTP error: {}", e),
            Self::Forbidden => write!(f, "access denied"),
            Self::NotFound => write!(f, "not found"),
            Self::CasConflict => write!(f, "check-and-set conflict"),
            Self::Rejected { status, .. } => write!(f, "unexpected status {}", status),
            Self::Backend(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<reqwest::Error> for StoreError {
    fn from(e: reqwest::Error) -> Self {
        StoreError::Http(e)
    }
}

/// Paths are `/`-separated with no leading or trailing slash. `ConnectionStore`
/// validates the names in them before they reach the store.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// The document at `path`, or `None` when there is none.
    async fn get(&self, path: &str) -> Result<Option<Doc>, StoreError>;

    /// Write `data` as the new version of `path` and return that version.
    /// With `cas`, the write only happens if the current version is that
    /// one (`Some(0)`: only if nothing is there yet), else `CasConflict`.
    async fn put(
        &self,
        path: &str,
        data: &serde_json::Value,
        cas: Option<u64>,
    ) -> Result<u64, StoreError>;

    /// The names directly under `prefix`, Vault LIST style: a name ending
    /// in `/` has children of its own. `NotFound` when there are none.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;

    /// Remove `path` and every version of it. `NotFound` when nothing is
    /// there.
    async fn delete(&self, path: &str) -> Result<(), StoreError>;

    /// Remove every document under `prefix` (paths starting `prefix/`).
    /// Nothing there is not an error.
    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError>;

    /// Whether the store can serve requests now. A Vault store exists only
    /// once logged in and renews its own token, so both stores answer yes.
    fn is_available(&self) -> bool {
        true
    }

    /// Start whatever the backend needs kept up in the background (Vault:
    /// token renewal). Nothing by default.
    fn spawn_maintenance(self: Arc<Self>) {}
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn sqlite_is_the_default_store() {
        // Nothing configured: SQLite at the default paths.
        let none: Config = toml::from_str("").unwrap();
        let sc = none.sqlite_storage().unwrap();
        assert_eq!(
            sc.path,
            std::path::PathBuf::from("/var/lib/mybastion/secrets.db")
        );
        assert_eq!(sc.kek_source, "file:/etc/mybastion/kek");
        assert_eq!(sc.base_path, "mybastion");
        assert!(none.secrets_configured());

        // Only [vault]: an existing Vault setup keeps using Vault.
        let vault_only: Config = toml::from_str(
            "[vault]
addr = \"https://v:8200\"
role_id = \"r\"
",
        )
        .unwrap();
        assert!(vault_only.sqlite_storage().is_none());
        assert!(vault_only.secrets_configured());

        // An explicit [storage] decides, and its backend defaults to sqlite.
        let both: Config = toml::from_str(
            "[storage]
instance_name = \"n1\"
[vault]
addr = \"https://v:8200\"
role_id = \"r\"
",
        )
        .unwrap();
        assert_eq!(
            both.sqlite_storage().unwrap().instance_name.as_deref(),
            Some("n1")
        );
        let explicit_vault: Config = toml::from_str(
            "[storage]
backend = \"vault\"
",
        )
        .unwrap();
        assert!(explicit_vault.sqlite_storage().is_none());

        let typo: Config = toml::from_str(
            "[storage]
backend = \"sqlit\"
",
        )
        .unwrap();
        assert!(typo.validate_storage().is_err());
    }
}
