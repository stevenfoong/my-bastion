//! Where connection entries, folder configs and credential variables are
//! kept. `VaultClient` holds the rustguac logic (ACLs, folder defaults,
//! credential variables) and does its I/O through a `SecretStore`: one JSON
//! document per path, KV v2 style.

pub mod vault;

use async_trait::async_trait;
use std::sync::Arc;

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
    /// `VaultClient` turns it into the message for that operation.
    Rejected {
        status: u16,
        body: String,
    },
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
        }
    }
}

impl From<reqwest::Error> for StoreError {
    fn from(e: reqwest::Error) -> Self {
        StoreError::Http(e)
    }
}

/// Paths are `/`-separated with no leading or trailing slash. `VaultClient`
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

    /// Start whatever the backend needs kept up in the background (Vault:
    /// token renewal). Nothing by default.
    fn spawn_maintenance(self: Arc<Self>) {}
}
