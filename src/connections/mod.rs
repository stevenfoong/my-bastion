// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Connections: folders, connection entries, folder access control,
//! folder default credentials and per-user credential variables. They are
//! JSON documents in a `store::SecretStore` (SQLite or Vault/OpenBao), at
//! paths relative to the store's mount:
//!
//!   <base_path>/shared/<folder>/<entry>           shared across instances
//!   <base_path>/instance/<name>/<folder>/<entry>  this instance only
//!   <folder>/.config                              `FolderConfig`: who may open it
//!   <folder>/.defaults                            `FolderDefaults`: lent to entries
//!   <base_path>/users/<key>                       credential variables

mod credentials;
mod defaults;
mod entries;
mod folders;
mod model;
mod names;

pub use credentials::*;
pub use defaults::*;
pub use model::*;

use serde::Serialize;
use std::sync::Arc;

use crate::config::VaultConfig;
use crate::store::vault::VaultStore;
use crate::store::{SecretStore, StoreError};
use names::{validate_name, validate_path};

// ── Error type ──

#[derive(Debug)]
pub enum VaultError {
    Auth(String),
    NotFound,
    Forbidden,
    Http(reqwest::Error),
    Parse(String),
    BadName(String),
    /// The backend serving this scope is configured but not currently
    /// connected (initial connect pending or the Vault is down). Distinct from
    /// a Vault that returns an error: the request never left mybastion.
    Unavailable,
    /// A local secret store (SQLite) failed.
    Storage(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(msg) => write!(f, "vault auth error: {}", msg),
            Self::NotFound => write!(f, "not found in vault"),
            Self::Forbidden => write!(f, "vault access denied"),
            Self::Http(e) => write!(f, "vault HTTP error: {}", e),
            Self::Parse(msg) => write!(f, "vault response parse error: {}", msg),
            Self::BadName(msg) => write!(f, "invalid name: {}", msg),
            Self::Unavailable => write!(f, "vault backend not available"),
            Self::Storage(msg) => write!(f, "secret store error: {}", msg),
        }
    }
}

impl From<reqwest::Error> for VaultError {
    fn from(e: reqwest::Error) -> Self {
        VaultError::Http(e)
    }
}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Auth(msg) => VaultError::Auth(msg),
            StoreError::Http(e) => VaultError::Http(e),
            StoreError::Forbidden => VaultError::Forbidden,
            StoreError::NotFound => VaultError::NotFound,
            StoreError::CasConflict => VaultError::Parse("check-and-set conflict".into()),
            StoreError::Rejected { status, .. } => {
                VaultError::Parse(format!("unexpected status {}", status))
            }
            StoreError::Backend(msg) => VaultError::Storage(msg),
        }
    }
}

/// For `map_err`: a status the store rejected reads `"<op> failed (<status>)"`.
fn failed(op: &'static str) -> impl Fn(StoreError) -> VaultError {
    move |e| match e {
        StoreError::Rejected { status, .. } => {
            VaultError::Parse(format!("{} failed ({})", op, status))
        }
        e => e.into(),
    }
}

/// `failed`, with the store's response body after it, as writes report.
fn write_failed(op: &'static str) -> impl Fn(StoreError) -> VaultError {
    move |e| match e {
        StoreError::Rejected { status, body } => {
            VaultError::Parse(format!("{} failed ({}): {}", op, status, body))
        }
        e => e.into(),
    }
}

/// A typed value as the JSON document the store keeps.
fn to_doc<T: Serialize>(v: &T) -> Result<serde_json::Value, VaultError> {
    serde_json::to_value(v).map_err(|e| VaultError::Parse(e.to_string()))
}

// ── Vault client ──

pub struct VaultClient {
    store: Arc<dyn SecretStore>,
    base_path: String,
    instance_name: Option<String>,
}

impl VaultClient {
    /// Create a new Vault client and perform initial login.
    pub async fn new(config: &VaultConfig, secret_id: &str) -> Result<Self, VaultError> {
        let store = VaultStore::new(config, secret_id).await?;
        Ok(Self::with_store(
            Arc::new(store),
            config.base_path.clone(),
            config.instance_name.clone(),
        ))
    }

    /// A client over any store, e.g. SQLite. `base_path` prefixes the
    /// address-book paths as in `[vault]`; `instance_name` enables the
    /// instance scope.
    pub fn with_store(
        store: Arc<dyn SecretStore>,
        base_path: String,
        instance_name: Option<String>,
    ) -> Self {
        Self {
            store,
            base_path,
            instance_name,
        }
    }

    /// Spawn the store's background upkeep (for Vault, token renewal at 50%
    /// of TTL).
    pub fn spawn_renewal_task(self: &Arc<Self>) {
        Arc::clone(&self.store).spawn_maintenance();
    }

    // ── Path helpers ──

    /// Store path (relative to the KV mount) of `rest` under a scope.
    fn kv_path(&self, scope_prefix: &str, rest: &str) -> String {
        format!("{}/{}/{}", self.base_path, scope_prefix, rest)
    }

    /// The document at `path`, or `None` when there is none.
    async fn read_doc(&self, path: &str) -> Result<Option<serde_json::Value>, VaultError> {
        Ok(self.store.get(path).await?.map(|d| d.data))
    }

    // ── Generic KV v2 read ──

    /// Read a single field from an arbitrary KV v2 path (relative to base_path).
    /// Used for reading non-address-book secrets like the LUKS encryption key.
    pub async fn read_kv_field(&self, kv_path: &str, field: &str) -> Result<String, VaultError> {
        let data = self.read_doc(kv_path).await?.ok_or(VaultError::NotFound)?;
        data[field]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::Parse(format!("field '{}' not found in secret", field)))
    }

    // ── Internal helpers ──

    /// Resolve "shared" or "instance" scope label to the actual Vault path prefix.
    fn resolve_scope_prefix(&self, scope: &str) -> Result<String, VaultError> {
        match scope {
            "shared" => Ok("shared".to_string()),
            "instance" => match &self.instance_name {
                Some(name) => Ok(format!("instance/{}", name)),
                None => Err(VaultError::BadName("no instance_name configured".into())),
            },
            _ => Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        }
    }

    /// The keys directly under `dir`; subfolder names end with `/`.
    async fn kv_list(&self, dir: &str) -> Result<Vec<String>, VaultError> {
        self.store.list(dir).await.map_err(failed("list"))
    }
}
