//! `SecretStore` in an SQLite file, encrypted at rest (see `crypto`).
//!
//! One row per path, Vault KV v2 style: the latest version only, with a
//! version counter for check-and-set. Kept apart from the main database
//! (`db_path`) so the secrets file can have its own permissions and backups.

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;
use zeroize::Zeroizing;

use super::crypto::{row_aad, Key};
use super::{Doc, SecretStore, StoreError};

const SCHEMA_VERSION: &str = "1";

pub struct SqliteStore {
    conn: Mutex<Connection>,
    dek: Key,
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Backend(format!("sqlite: {}", e))
    }
}

fn backend(msg: String) -> StoreError {
    StoreError::Backend(msg)
}

/// Create `path` readable by its owner only, before SQLite opens it.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(backend(format!("cannot create {}: {}", path.display(), e))),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl SqliteStore {
    /// Open (or create) the secrets database. A new database gets a fresh
    /// data key wrapped under `kek`; an existing one must have been wrapped
    /// under the same KEK.
    pub fn open(path: &Path, kek: &Key) -> Result<Self, StoreError> {
        #[cfg(unix)]
        create_private(path)?;
        let mut conn = Connection::open(path)?;
        crate::db::repair_db_ownership(path);
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                path        TEXT PRIMARY KEY,
                version     INTEGER NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                updated_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets_meta (k TEXT PRIMARY KEY, v BLOB);",
        )?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = |k: &str| -> Result<Option<Vec<u8>>, rusqlite::Error> {
            tx.query_row("SELECT v FROM secrets_meta WHERE k = ?1", [k], |r| r.get(0))
                .optional()
        };
        let dek = match meta("dek")? {
            Some(wrapped) => {
                let schema = meta("schema_version")?.unwrap_or_default();
                if schema != SCHEMA_VERSION.as_bytes() {
                    return Err(backend(format!(
                        "{} has schema version {}, this mybastion reads {}",
                        path.display(),
                        String::from_utf8_lossy(&schema),
                        SCHEMA_VERSION
                    )));
                }
                kek.unwrap_dek(&wrapped).map_err(|_| {
                    let stored = meta("kek_id").ok().flatten().unwrap_or_default();
                    backend(format!(
                        "the KEK (id {}) does not open {}: it was set up with KEK id {}",
                        kek.id(),
                        path.display(),
                        String::from_utf8_lossy(&stored)
                    ))
                })?
            }
            None => {
                let dek = Key::generate().map_err(backend)?;
                let wrapped = kek.wrap(&dek).map_err(backend)?;
                let mut put = tx.prepare("INSERT INTO secrets_meta (k, v) VALUES (?1, ?2)")?;
                put.execute(params!["dek", wrapped])?;
                put.execute(params!["kek_id", kek.id().into_bytes()])?;
                put.execute(params!["schema_version", SCHEMA_VERSION.as_bytes()])?;
                drop(put);
                tracing::info!("Created secrets database {}", path.display());
                dek
            }
        };
        tx.commit()?;
        Ok(Self {
            conn: Mutex::new(conn),
            dek,
        })
    }

    /// Re-wrap the data key under `new_kek`. Rows are untouched; after this
    /// only `new_kek` opens the database.
    pub fn rewrap(&self, new_kek: &Key) -> Result<(), StoreError> {
        let wrapped = new_kek.wrap(&self.dek).map_err(backend)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE secrets_meta SET v = ?1 WHERE k = 'dek'",
            params![wrapped],
        )?;
        tx.execute(
            "UPDATE secrets_meta SET v = ?1 WHERE k = 'kek_id'",
            params![new_kek.id().into_bytes()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[async_trait]
impl SecretStore for SqliteStore {
    async fn get(&self, path: &str) -> Result<Option<Doc>, StoreError> {
        let row = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT version, nonce, ciphertext FROM secrets WHERE path = ?1",
                [path],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
        };
        let Some((version, nonce, ciphertext)) = row else {
            return Ok(None);
        };
        let version = version as u64;
        let plain = self
            .dek
            .open(&nonce, &ciphertext, &row_aad(path, version))
            .map_err(|_| backend(format!("secret at {} fails its integrity check", path)))?;
        let data = serde_json::from_slice(&plain)
            .map_err(|e| backend(format!("secret at {} is not JSON: {}", path, e)))?;
        Ok(Some(Doc { data, version }))
    }

    async fn put(
        &self,
        path: &str,
        data: &serde_json::Value,
        cas: Option<u64>,
    ) -> Result<u64, StoreError> {
        let plain = Zeroizing::new(
            serde_json::to_vec(data).map_err(|e| backend(format!("cannot encode: {}", e)))?,
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = tx
            .query_row("SELECT version FROM secrets WHERE path = ?1", [path], |r| {
                r.get(0)
            })
            .optional()?;
        let current = current.unwrap_or(0) as u64;
        if cas.is_some_and(|cas| cas != current) {
            return Err(StoreError::CasConflict);
        }
        let version = current + 1;
        let (nonce, ciphertext) = self
            .dek
            .seal(&plain, &row_aad(path, version))
            .map_err(backend)?;
        tx.execute(
            "INSERT INTO secrets (path, version, nonce, ciphertext, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path) DO UPDATE SET version = excluded.version,
                 nonce = excluded.nonce, ciphertext = excluded.ciphertext,
                 updated_at = excluded.updated_at",
            params![path, version as i64, nonce, ciphertext, now_secs()],
        )?;
        tx.commit()?;
        Ok(version)
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        // Every path under "p/" sorts in ["p/", "p0"): '0' follows '/'. A
        // range rather than LIKE, where '_' (allowed in names) is a wildcard.
        let lo = format!("{}/", prefix);
        let hi = format!("{}0", prefix);
        let paths: Vec<String> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt =
                conn.prepare("SELECT path FROM secrets WHERE path >= ?1 AND path < ?2")?;
            let rows = stmt.query_map([&lo, &hi], |r| r.get(0))?;
            rows.collect::<Result<Vec<String>, _>>()?
        };
        let children: BTreeSet<String> = paths
            .iter()
            .map(|p| match p[lo.len()..].split_once('/') {
                Some((dir, _)) => format!("{}/", dir),
                None => p[lo.len()..].to_string(),
            })
            .collect();
        if children.is_empty() {
            return Err(StoreError::NotFound);
        }
        Ok(children.into_iter().collect())
    }

    async fn delete(&self, path: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        match conn.execute("DELETE FROM secrets WHERE path = ?1", [path])? {
            0 => Err(StoreError::NotFound),
            _ => Ok(()),
        }
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError> {
        // The same range as `list`: every path under "p/".
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM secrets WHERE path >= ?1 AND path < ?2",
            [format!("{}/", prefix), format!("{}0", prefix)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::{AddressBookEntry, ConnectionError, ConnectionStore, FolderConfig};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// A secrets database in a fresh temp dir, removed on drop.
    struct TempDb {
        dir: PathBuf,
    }

    impl TempDb {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("mybastion-secrets-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
        fn path(&self) -> PathBuf {
            self.dir.join("secrets.db")
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn kek() -> Key {
        Key::parse(&"11".repeat(32)).unwrap()
    }

    #[tokio::test]
    async fn get_put_list_delete_follow_kv_v2() {
        let db = TempDb::new();
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        assert!(s.get("a/b").await.unwrap().is_none());
        assert_eq!(s.put("a/b", &json!({"x": 1}), None).await.unwrap(), 1);
        assert_eq!(s.put("a/b", &json!({"x": 2}), None).await.unwrap(), 2);
        let d = s.get("a/b").await.unwrap().unwrap();
        assert_eq!((d.data, d.version), (json!({"x": 2}), 2));

        s.put("a/c/d", &json!({}), None).await.unwrap();
        s.put("a/c/e/f", &json!({}), None).await.unwrap();
        s.put("ab", &json!({}), None).await.unwrap();
        s.put("a0", &json!({}), None).await.unwrap();
        assert_eq!(s.list("a").await.unwrap(), vec!["b", "c/"]);
        assert_eq!(s.list("a/c").await.unwrap(), vec!["d", "e/"]);
        assert!(matches!(s.list("a/b").await, Err(StoreError::NotFound)));
        assert!(matches!(s.list("zzz").await, Err(StoreError::NotFound)));

        s.delete("a/b").await.unwrap();
        assert!(s.get("a/b").await.unwrap().is_none());
        assert!(matches!(s.delete("a/b").await, Err(StoreError::NotFound)));
        // A recreated path starts again at version 1, as in Vault.
        assert_eq!(s.put("a/b", &json!({}), None).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn list_treats_underscore_and_percent_literally() {
        let db = TempDb::new();
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        s.put("f_1/x", &json!({}), None).await.unwrap();
        s.put("fa1/y", &json!({}), None).await.unwrap();
        s.put("f%/z", &json!({}), None).await.unwrap();
        assert_eq!(s.list("f_1").await.unwrap(), vec!["x"]);
        assert_eq!(s.list("f%").await.unwrap(), vec!["z"]);
    }

    #[tokio::test]
    async fn delete_prefix_removes_the_subtree_only() {
        let db = TempDb::new();
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        for p in ["a/b", "a/c/d", "a/c/.config", "ab", "a0", "a"] {
            s.put(p, &json!({}), None).await.unwrap();
        }
        s.delete_prefix("a").await.unwrap();
        assert!(matches!(s.list("a").await, Err(StoreError::NotFound)));
        for p in ["ab", "a0", "a"] {
            assert!(s.get(p).await.unwrap().is_some(), "{p} must survive");
        }
        s.delete_prefix("nothing/here").await.unwrap();
    }

    #[tokio::test]
    async fn check_and_set() {
        let db = TempDb::new();
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        assert_eq!(s.put("p", &json!(1), Some(0)).await.unwrap(), 1);
        assert!(matches!(
            s.put("p", &json!(2), Some(0)).await,
            Err(StoreError::CasConflict)
        ));
        assert!(matches!(
            s.put("p", &json!(2), Some(7)).await,
            Err(StoreError::CasConflict)
        ));
        assert_eq!(s.put("p", &json!(2), Some(1)).await.unwrap(), 2);
        assert_eq!(s.get("p").await.unwrap().unwrap().data, json!(2));
    }

    #[tokio::test]
    async fn data_survives_reopen_and_is_not_stored_in_clear() {
        let db = TempDb::new();
        {
            let s = SqliteStore::open(&db.path(), &kek()).unwrap();
            s.put("p", &json!({"password": "hunter2-plaintext"}), None)
                .await
                .unwrap();
        }
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        assert_eq!(
            s.get("p").await.unwrap().unwrap().data["password"],
            "hunter2-plaintext"
        );
        drop(s);
        let mut raw = std::fs::read(db.path()).unwrap();
        if let Ok(wal) = std::fs::read(db.path().with_extension("db-wal")) {
            raw.extend(wal);
        }
        assert!(!raw.windows(17).any(|w| w == b"hunter2-plaintext"));
    }

    #[cfg(unix)]
    #[test]
    fn new_database_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let db = TempDb::new();
        SqliteStore::open(&db.path(), &kek()).unwrap();
        let mode = std::fs::metadata(db.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    #[tokio::test]
    async fn wrong_kek_is_refused_with_both_ids() {
        let db = TempDb::new();
        SqliteStore::open(&db.path(), &kek()).unwrap();
        let other = Key::parse(&"22".repeat(32)).unwrap();
        let e = SqliteStore::open(&db.path(), &other)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains(&other.id()) && e.contains(&kek().id()), "{e}");
    }

    #[tokio::test]
    async fn rewrap_moves_the_database_to_the_new_kek() {
        let db = TempDb::new();
        let new = Key::parse(&"33".repeat(32)).unwrap();
        {
            let s = SqliteStore::open(&db.path(), &kek()).unwrap();
            s.put("p", &json!("v"), None).await.unwrap();
            s.rewrap(&new).unwrap();
        }
        assert!(SqliteStore::open(&db.path(), &kek()).is_err());
        let s = SqliteStore::open(&db.path(), &new).unwrap();
        assert_eq!(s.get("p").await.unwrap().unwrap().data, json!("v"));
    }

    /// Tampering with a row's path, version or ciphertext in the file must
    /// make the read fail, never return other data.
    #[tokio::test]
    async fn tampered_rows_fail_to_decrypt() {
        let db = TempDb::new();
        let s = SqliteStore::open(&db.path(), &kek()).unwrap();
        s.put("shared/a/one", &json!({"pw": "1"}), None)
            .await
            .unwrap();
        s.put("shared/a/two", &json!({"pw": "2"}), None)
            .await
            .unwrap();
        s.put("shared/a/three", &json!({"pw": "3"}), None)
            .await
            .unwrap();
        s.put("shared/a/four", &json!({"pw": "4"}), None)
            .await
            .unwrap();
        {
            let conn = s.conn.lock().unwrap();
            // Path: move row "one" to an unused path.
            conn.execute(
                "UPDATE secrets SET path = 'shared/a/moved' WHERE path = 'shared/a/one'",
                [],
            )
            .unwrap();
            // Swap: give "two" the ciphertext of "three".
            conn.execute(
                "UPDATE secrets SET nonce = (SELECT nonce FROM secrets WHERE path = 'shared/a/three'),
                     ciphertext = (SELECT ciphertext FROM secrets WHERE path = 'shared/a/three')
                 WHERE path = 'shared/a/two'",
                [],
            )
            .unwrap();
            // Version: bump "three" without re-encrypting.
            conn.execute(
                "UPDATE secrets SET version = version + 1 WHERE path = 'shared/a/three'",
                [],
            )
            .unwrap();
            // Ciphertext: flip a bit in "four".
            let ct: Vec<u8> = conn
                .query_row(
                    "SELECT ciphertext FROM secrets WHERE path = 'shared/a/four'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let mut ct = ct;
            ct[0] ^= 0x80;
            conn.execute(
                "UPDATE secrets SET ciphertext = ?1 WHERE path = 'shared/a/four'",
                [ct],
            )
            .unwrap();
        }
        for p in [
            "shared/a/moved",
            "shared/a/two",
            "shared/a/three",
            "shared/a/four",
        ] {
            let e = s
                .get(p)
                .await
                .err()
                .unwrap_or_else(|| panic!("{p} decrypted"));
            assert!(e.to_string().contains("integrity"), "{p}: {e}");
        }
    }

    // ── ConnectionStore over SQLite: the address-book operations end to end ──

    fn client(db: &TempDb) -> ConnectionStore {
        let store = SqliteStore::open(&db.path(), &kek()).unwrap();
        ConnectionStore::with_store(Arc::new(store), "mybastion".into(), Some("node1".into()))
    }

    fn rdp(host: &str) -> AddressBookEntry {
        AddressBookEntry {
            session_type: "rdp".into(),
            hostname: Some(host.into()),
            port: Some(3389),
            username: Some("admin".into()),
            password: Some("pw".into()),
            ..Default::default()
        }
    }

    fn folder(groups: &[&str], inherit: bool) -> FolderConfig {
        FolderConfig {
            allowed_groups: groups.iter().map(|g| g.to_string()).collect(),
            allowed_users: Vec::new(),
            description: "d".into(),
            display_name: String::new(),
            inherit_from_parent: inherit,
            ai_mode: None,
        }
    }

    #[tokio::test]
    async fn address_book_round_trip() {
        let db = TempDb::new();
        let c = client(&db);
        c.put_folder_config("shared", "Prod", &folder(&["ops"], false))
            .await
            .unwrap();
        c.put_folder_config("shared", "Prod/Web", &folder(&[], true))
            .await
            .unwrap();
        c.put_entry("shared", "Prod", "web01", &rdp("10.0.0.1"))
            .await
            .unwrap();
        c.put_entry("shared", "Prod/Web", "web02", &rdp("10.0.0.2"))
            .await
            .unwrap();

        let e = c.get_entry("shared", "Prod", "web01").await.unwrap();
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.1"));
        assert!(matches!(
            c.get_entry("shared", "Prod", "nope").await,
            Err(ConnectionError::NotFound)
        ));

        let top = c.list_folders_in_scope("shared").await.unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(
            (top[0].name.as_str(), top[0].has_children),
            ("Prod", Some(true))
        );
        assert_eq!(
            c.list_entries("shared", "Prod/Web").await.unwrap(),
            vec!["web02"]
        );
        let subs = c.list_subfolders("shared", "Prod").await.unwrap();
        assert_eq!(subs[0].path.as_deref(), Some("Prod/Web"));

        // Instance scope lives apart, under this instance's name.
        assert!(c
            .list_folders_in_scope("instance")
            .await
            .unwrap()
            .is_empty());
        c.put_entry("instance", "Lab", "box", &rdp("10.9.9.9"))
            .await
            .unwrap();
        assert!(c.get_entry("shared", "Lab", "box").await.is_err());
        assert!(c.get_entry("instance", "Lab", "box").await.is_ok());

        // Access walks up through the inheriting subfolder.
        let ops = vec!["ops".to_string()];
        let who = crate::connections::FolderSubject {
            email: Some("a@b.c"),
            groups: &ops,
        };
        assert!(c
            .resolve_folder_access("shared", "Prod/Web", who)
            .await
            .unwrap());

        // One subfolder (Web) and two entries; sentinels are not entries.
        assert_eq!(c.delete_folder("shared", "Prod").await.unwrap(), (1, 2));
        assert!(matches!(c.list_folders_in_scope("shared").await, Ok(v) if v.is_empty()));
        assert!(c.get_entry("shared", "Prod/Web", "web02").await.is_err());
    }

    #[tokio::test]
    async fn put_entry_if_absent_refuses_the_second_writer() {
        let db = TempDb::new();
        let c = client(&db);
        assert!(c
            .put_entry_if_absent("shared", "F", "e", &rdp("a"))
            .await
            .unwrap());
        assert!(!c
            .put_entry_if_absent("shared", "F", "e", &rdp("b"))
            .await
            .unwrap());
        assert_eq!(
            c.get_entry("shared", "F", "e")
                .await
                .unwrap()
                .hostname
                .as_deref(),
            Some("a")
        );
    }

    #[tokio::test]
    async fn folder_defaults_and_their_removal() {
        let db = TempDb::new();
        let c = client(&db);
        let d: crate::connections::FolderDefaults =
            serde_json::from_value(json!({"ssh": {"username": "u", "password": "p"}})).unwrap();
        c.put_folder_config("shared", "F", &folder(&["ops"], false))
            .await
            .unwrap();
        c.put_folder_defaults("shared", "F", &d).await.unwrap();
        assert_eq!(
            c.get_folder_defaults("shared", "F").await.unwrap()["ssh"]
                .username
                .as_deref(),
            Some("u")
        );
        assert!(c
            .effective_folder_defaults("shared", "F")
            .await
            .unwrap()
            .is_some());
        // An empty map removes the sentinel; removing it twice is fine.
        c.put_folder_defaults("shared", "F", &Default::default())
            .await
            .unwrap();
        c.delete_folder_defaults("shared", "F").await.unwrap();
        assert!(matches!(
            c.get_folder_defaults("shared", "F").await,
            Err(ConnectionError::NotFound)
        ));
        assert!(c.list_entries("shared", "F").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn user_credentials_and_unscoped_secrets() {
        let db = TempDb::new();
        let c = client(&db);
        assert!(c.get_user_credentials("a@b.c").await.unwrap().is_empty());
        let creds = [("corp_pw".to_string(), "x".to_string())]
            .into_iter()
            .collect();
        c.put_user_credentials("a@b.c", &creds).await.unwrap();
        assert_eq!(c.get_user_credentials("a@b.c").await.unwrap(), creds);
        c.delete_user_credentials("a@b.c").await.unwrap();
        c.delete_user_credentials("a@b.c").await.unwrap();

        // The LUKS key path is relative to the mount, outside base_path.
        assert!(matches!(
            c.read_kv_field("luks/drive", "key").await,
            Err(ConnectionError::NotFound)
        ));
        let store = SqliteStore::open(&db.path(), &kek()).unwrap();
        store
            .put("luks/drive", &json!({"key": "k"}), None)
            .await
            .unwrap();
        assert_eq!(c.read_kv_field("luks/drive", "key").await.unwrap(), "k");
    }
}
