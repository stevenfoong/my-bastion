// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Folder default credentials: what a folder lends, per session type, to
//! entries without credentials of their own, and the inheritance walk.

use super::*;
use serde::{Deserialize, Serialize};

/// Credentials a folder lends to entries that have none of their own, keyed
/// by session type (`ssh`, `rdp`, `vnc`, `web`, ...). Stored at
/// `<folder>/.defaults` beside `.config`, so an entry created without secrets
/// (a NetBox webhook, a bulk import) is connectable the moment it exists,
/// with no second pass to fill it in. A subfolder without its own `.defaults`
/// inherits its nearest ancestor's, per type, as far up as
/// `inherit_from_parent` allows (see `resolve_effective_defaults`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DefaultCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl DefaultCredentials {
    /// Whether these defaults carry something that can authenticate (a
    /// username alone does not).
    pub fn has_secret(&self) -> bool {
        self.password.as_deref().is_some_and(|p| !p.is_empty())
            || self.private_key.as_deref().is_some_and(|k| !k.is_empty())
    }
}

/// Per-session-type default credentials of one folder.
pub type FolderDefaults = std::collections::BTreeMap<String, DefaultCredentials>;

/// Whether the entry carries a password or private key of its own.
pub fn entry_has_own_credentials(e: &AddressBookEntry) -> bool {
    e.password.as_deref().is_some_and(|p| !p.is_empty())
        || e.private_key.as_deref().is_some_and(|k| !k.is_empty())
}

/// Whether an entry is a candidate for folder defaults: it has no password
/// or private key of its own and is not set to prompt at connect time (a
/// prompting entry keeps prompting, defaults or not).
pub fn entry_takes_folder_defaults(e: &AddressBookEntry) -> bool {
    !entry_has_own_credentials(e) && e.prompt_credentials != Some(true)
}

/// Give an entry without credentials of its own the folder defaults for its
/// session type. The entry's own username and domain win when set; the
/// defaults' password and private key are taken as they are. Returns whether
/// anything was applied: false when the entry already has a secret or is set
/// to prompt, when the folder has no defaults for the type, or when those
/// defaults have no secret.
pub fn apply_folder_defaults(entry: &mut AddressBookEntry, defaults: &FolderDefaults) -> bool {
    if !entry_takes_folder_defaults(entry) {
        return false;
    }
    let Some(d) = defaults.get(&entry.session_type) else {
        return false;
    };
    if !d.has_secret() {
        return false;
    }
    if entry.username.as_deref().is_none_or(str::is_empty) && d.username.is_some() {
        entry.username = d.username.clone();
    }
    if entry.domain.as_deref().is_none_or(str::is_empty) && d.domain.is_some() {
        entry.domain = d.domain.clone();
    }
    entry.password = d.password.clone().filter(|p| !p.is_empty());
    entry.private_key = d.private_key.clone().filter(|k| !k.is_empty());
    true
}

/// What the defaults walk reads per folder: its own `.defaults`, and whether
/// its `.config` lets it inherit from the parent. A trait so the walk in
/// `resolve_effective_defaults` is unit-testable without a Vault; both
/// `VaultClient` and the multi-backend router implement it.
#[allow(async_fn_in_trait)]
pub trait DefaultsSource {
    /// The folder's own `.defaults`; `None` when it has none.
    async fn folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError>;

    /// Whether the folder's parent may lend it defaults: see
    /// `FolderConfig::shares_parent_audience`. A folder with no `.config`
    /// does not inherit, which is how `resolve_folder_access` treats it too.
    async fn takes_parent_defaults(&self, scope: &str, folder: &str) -> Result<bool, VaultError>;
}

/// The defaults that apply to entries in `folder`: its own `.defaults`, then
/// each ancestor's for any session type still unset, walking up only while
/// the folder just visited is seen by exactly its parent's audience
/// (`FolderConfig::shares_parent_audience`).
///
/// A secret set on a parent must reach only people who could already reach
/// the parent. A folder with `inherit_from_parent: false` is isolated, and
/// one that inherits but also grants groups or users of its own admits
/// people the parent doesn't, so the walk stops at either: otherwise a
/// subfolder shared with a contractor through `allowed_users` would hand
/// them the parent's key. That folder's own `.defaults` still apply to its
/// entries. `None` when no folder on the walk has any.
pub async fn resolve_effective_defaults<S: DefaultsSource>(
    src: &S,
    scope: &str,
    folder: &str,
) -> Result<Option<FolderDefaults>, VaultError> {
    let mut merged = FolderDefaults::new();
    let mut path = folder.to_string();
    loop {
        if let Some(d) = src.folder_defaults(scope, &path).await? {
            for (session_type, creds) in d {
                merged.entry(session_type).or_insert(creds);
            }
        }
        // Top-level folder: nothing above it to consult.
        let Some(i) = path.rfind('/') else { break };
        // Isolated folder: what its parent lends stops here.
        if !src.takes_parent_defaults(scope, &path).await? {
            break;
        }
        path.truncate(i);
    }
    Ok(if merged.is_empty() {
        None
    } else {
        Some(merged)
    })
}

impl DefaultsSource for VaultClient {
    async fn folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError> {
        match self.get_folder_defaults(scope, folder).await {
            Ok(d) => Ok(Some(d)),
            Err(VaultError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn takes_parent_defaults(&self, scope: &str, folder: &str) -> Result<bool, VaultError> {
        match self.get_folder_config(scope, folder).await {
            Ok(c) => Ok(c.shares_parent_audience()),
            Err(VaultError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

impl VaultClient {
    /// Read a folder's `.defaults` (see `FolderDefaults`).
    pub async fn get_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderDefaults, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid .defaults: {}", e)))
    }

    /// Write a folder's `.defaults`. An empty map removes the key instead,
    /// so a folder with nothing to lend has no sentinel at all.
    pub async fn put_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
        defaults: &FolderDefaults,
    ) -> Result<(), VaultError> {
        if defaults.is_empty() {
            return self.delete_folder_defaults(scope, folder).await;
        }
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        self.store
            .put(&path, &to_doc(defaults)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put folder defaults"))
    }

    /// Remove a folder's `.defaults`. Absent is fine.
    pub async fn delete_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".defaults"));
        match self.store.delete(&path).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(e) => Err(failed("delete folder defaults")(e)),
        }
    }

    /// The defaults that apply to entries in `folder`: see
    /// `resolve_effective_defaults` for the walk and where it stops.
    pub async fn effective_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError> {
        validate_path(folder)?;
        resolve_effective_defaults(self, scope, folder).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_defaults_fill_only_entries_without_secrets() {
        let mut defaults = FolderDefaults::new();
        defaults.insert(
            "ssh".into(),
            DefaultCredentials {
                username: Some("root".into()),
                private_key: Some("-----BEGIN KEY-----".into()),
                ..Default::default()
            },
        );
        defaults.insert(
            "web".into(),
            DefaultCredentials {
                password: Some("router-pw".into()),
                ..Default::default()
            },
        );
        // username only: nothing to authenticate with
        defaults.insert(
            "rdp".into(),
            DefaultCredentials {
                username: Some("Administrator".into()),
                ..Default::default()
            },
        );

        // ssh entry without secrets: takes the key, keeps its own username
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            username: Some("admin".into()),
            ..Default::default()
        };
        assert!(apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.username.as_deref(), Some("admin"));
        assert_eq!(e.private_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert!(e.password.is_none());

        // no username at all: the default's username fills it
        let mut e = AddressBookEntry {
            session_type: "web".into(),
            ..Default::default()
        };
        assert!(apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.password.as_deref(), Some("router-pw"));
        assert!(e.username.is_none(), "web defaults carry no username");

        // an entry with its own secret is left alone
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            password: Some("own".into()),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert_eq!(e.password.as_deref(), Some("own"));
        assert!(e.private_key.is_none());

        // defaults with no secret do nothing; a type without defaults too
        let mut e = AddressBookEntry {
            session_type: "rdp".into(),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert!(e.username.is_none());
        let mut e = AddressBookEntry {
            session_type: "vnc".into(),
            ..Default::default()
        };
        assert!(!apply_folder_defaults(&mut e, &defaults));

        // an entry set to prompt keeps prompting: no defaults for it
        let mut e = AddressBookEntry {
            session_type: "ssh".into(),
            prompt_credentials: Some(true),
            ..Default::default()
        };
        assert!(!entry_takes_folder_defaults(&e));
        assert!(!apply_folder_defaults(&mut e, &defaults));
        assert!(e.private_key.is_none());
    }

    /// In-memory stand-in for the two per-folder reads the defaults walk
    /// makes. `inherit` lists the folders whose `.config` has
    /// `inherit_from_parent: true`; everything else is treated as isolated,
    /// including folders with no `.config` at all.
    struct FakeDefaults {
        defaults: std::collections::HashMap<String, FolderDefaults>,
        inherit: std::collections::HashSet<String>,
    }

    impl DefaultsSource for FakeDefaults {
        async fn folder_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<Option<FolderDefaults>, VaultError> {
            Ok(self.defaults.get(folder).cloned())
        }
        async fn takes_parent_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<bool, VaultError> {
            Ok(self.inherit.contains(folder))
        }
    }

    fn ssh_key(key: &str) -> FolderDefaults {
        let mut d = FolderDefaults::new();
        d.insert(
            "ssh".into(),
            DefaultCredentials {
                private_key: Some(key.into()),
                ..Default::default()
            },
        );
        d
    }

    fn web_pw(pw: &str) -> FolderDefaults {
        let mut d = FolderDefaults::new();
        d.insert(
            "web".into(),
            DefaultCredentials {
                password: Some(pw.into()),
                ..Default::default()
            },
        );
        d
    }

    #[tokio::test]
    async fn effective_defaults_merge_nearest_first_through_inheriting_folders() {
        // corp/.defaults: ssh key + web pw; corp/linux/.defaults: ssh key only;
        // corp/linux/web has none. Every subfolder inherits.
        let mut defaults = std::collections::HashMap::new();
        let mut corp = ssh_key("corp-key");
        corp.extend(web_pw("corp-web"));
        defaults.insert("corp".to_string(), corp);
        defaults.insert("corp/linux".to_string(), ssh_key("linux-key"));
        let src = FakeDefaults {
            defaults,
            inherit: ["corp/linux", "corp/linux/web"]
                .into_iter()
                .map(String::from)
                .collect(),
        };

        let d = resolve_effective_defaults(&src, "shared", "corp/linux/web")
            .await
            .unwrap()
            .expect("defaults found on the path");
        // nearest folder wins per type; a type it lacks comes from higher up
        assert_eq!(d["ssh"].private_key.as_deref(), Some("linux-key"));
        assert_eq!(d["web"].password.as_deref(), Some("corp-web"));

        // nothing anywhere on the path: None, not an empty map
        let bare = FakeDefaults {
            defaults: Default::default(),
            inherit: ["a/b"].into_iter().map(String::from).collect(),
        };
        assert!(resolve_effective_defaults(&bare, "shared", "a/b")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn effective_defaults_stop_at_a_folder_that_does_not_inherit() {
        // corp lends an ssh key. corp/guests is isolated for access
        // (inherit_from_parent: false, shared with an outside user through
        // allowed_users); corp/guests/lab inherits from corp/guests. The
        // corp key must reach neither of them.
        let mut defaults = std::collections::HashMap::new();
        defaults.insert("corp".to_string(), ssh_key("corp-key"));
        let src = FakeDefaults {
            defaults: defaults.clone(),
            inherit: ["corp/guests/lab"].into_iter().map(String::from).collect(),
        };
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/guests")
                .await
                .unwrap()
                .is_none(),
            "an isolated folder must not receive its parent's defaults"
        );
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/guests/lab")
                .await
                .unwrap()
                .is_none(),
            "the walk must not cross the isolated folder on its way up"
        );

        // the isolated folder's own .defaults still apply to its entries and
        // to subfolders that inherit from it, but corp's key stays out
        defaults.insert("corp/guests".to_string(), web_pw("guest-web"));
        let src = FakeDefaults {
            defaults,
            inherit: ["corp/guests/lab"].into_iter().map(String::from).collect(),
        };
        for folder in ["corp/guests", "corp/guests/lab"] {
            let d = resolve_effective_defaults(&src, "shared", folder)
                .await
                .unwrap()
                .expect("the isolated folder's own defaults apply");
            assert_eq!(d["web"].password.as_deref(), Some("guest-web"));
            assert!(
                !d.contains_key("ssh"),
                "{folder}: corp's key crossed the boundary"
            );
        }

        // a folder with no .config is treated as isolated, as access does
        let src = FakeDefaults {
            defaults: [("corp".to_string(), ssh_key("corp-key"))]
                .into_iter()
                .collect(),
            inherit: Default::default(),
        };
        assert!(
            resolve_effective_defaults(&src, "shared", "corp/unconfigured")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn effective_defaults_propagate_read_errors() {
        struct Failing;
        impl DefaultsSource for Failing {
            async fn folder_defaults(
                &self,
                _s: &str,
                _f: &str,
            ) -> Result<Option<FolderDefaults>, VaultError> {
                Ok(Some(ssh_key("k")))
            }
            async fn takes_parent_defaults(&self, _s: &str, _f: &str) -> Result<bool, VaultError> {
                Err(VaultError::Forbidden)
            }
        }
        // a .config that cannot be read must not be mistaken for "inherits"
        assert!(resolve_effective_defaults(&Failing, "shared", "a/b")
            .await
            .is_err());
        // but a top-level folder never needs its config
        let d = resolve_effective_defaults(&Failing, "shared", "a")
            .await
            .unwrap();
        assert!(d.is_some());
    }

    #[test]
    fn parent_defaults_reach_only_the_parents_audience() {
        // Folder access is a union: a subfolder that inherits and also grants
        // someone of its own admits people the parent doesn't. corp/partner
        // inherits from corp but adds a contractor, so corp's default key
        // must not flow into it, or the contractor connects with it.
        let cfg = |inherit: bool, groups: &[&str], users: &[&str]| -> FolderConfig {
            serde_json::from_value(serde_json::json!({
                "allowed_groups": groups,
                "allowed_users": users,
                "inherit_from_parent": inherit,
            }))
            .unwrap()
        };
        assert!(cfg(true, &[], &[]).shares_parent_audience());
        assert!(
            !cfg(true, &[], &["contractor@ext.example"]).shares_parent_audience(),
            "an extra user is an extra audience"
        );
        assert!(
            !cfg(true, &["partners"], &[]).shares_parent_audience(),
            "an extra group is an extra audience"
        );
        assert!(
            !cfg(false, &[], &[]).shares_parent_audience(),
            "an isolated folder takes nothing from its parent"
        );
    }
}
