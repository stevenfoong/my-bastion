// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Folders: listing, `.config` access control and the access walk, and
//! deleting a folder with everything under it.

use super::*;

impl VaultClient {
    // ── KV v2 operations ──

    /// List top-level folders for a single scope (`"shared"` or `"instance"`).
    ///
    /// Returns an empty vec (not an error) when the scope isn't applicable to
    /// this client — e.g. `"instance"` with no `instance_name` configured — so
    /// the multi-backend fan-out can call it unconditionally.
    pub async fn list_folders_in_scope(&self, scope: &str) -> Result<Vec<FolderInfo>, VaultError> {
        let prefix = match scope {
            "shared" => "shared".to_string(),
            "instance" => match &self.instance_name {
                Some(name) => format!("instance/{}", name),
                None => return Ok(Vec::new()),
            },
            _ => return Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        };

        let mut folders = Vec::new();
        let path = format!("{}/{}", self.base_path, prefix);
        match self.kv_list(&path).await {
            Ok(keys) => {
                for name in keys.iter().filter_map(|k| k.strip_suffix('/')) {
                    folders.push(FolderInfo {
                        name: name.to_string(),
                        description: String::new(),
                        display_name: String::new(),
                        scope: scope.to_string(),
                        path: Some(name.to_string()),
                        has_children: None, // enriched below
                    });
                }
            }
            Err(VaultError::NotFound) => {
                // No folders in this scope — that's fine
            }
            Err(e) => return Err(e),
        }

        // Enrich with descriptions and child detection
        for folder in &mut folders {
            if let Ok(config) = self.get_folder_config(&folder.scope, &folder.name).await {
                folder.description = config.description;
                folder.display_name = config.display_name;
            }
            // Check for subfolders by listing children
            if let Ok(children) = self.list_children(&folder.scope, &folder.name).await {
                folder.has_children = Some(children.iter().any(|c| c.strip_suffix('/').is_some()));
            }
        }

        Ok(folders)
    }

    /// List immediate children (subfolders and entries) at a given folder path.
    /// Subfolder names end with `/` in the returned list.
    pub async fn list_children(
        &self,
        scope: &str,
        folder_path: &str,
    ) -> Result<Vec<String>, VaultError> {
        validate_path(folder_path)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        self.kv_list(&self.kv_path(&scope_prefix, folder_path))
            .await
    }

    /// List subfolders at a given path within a scope.
    /// Returns FolderInfo for each subfolder, with has_children populated.
    pub async fn list_subfolders(
        &self,
        scope: &str,
        parent_path: &str,
    ) -> Result<Vec<FolderInfo>, VaultError> {
        let children = self.list_children(scope, parent_path).await?;
        let mut folders = Vec::new();

        for key in &children {
            if let Some(name) = key.strip_suffix('/') {
                let full_path = format!("{}/{}", parent_path, name);
                let mut info = FolderInfo {
                    name: name.to_string(),
                    description: String::new(),
                    display_name: String::new(),
                    scope: scope.to_string(),
                    path: Some(full_path.clone()),
                    has_children: None,
                };
                // Enrich with description
                if let Ok(config) = self.get_folder_config(scope, &full_path).await {
                    info.description = config.description;
                    info.display_name = config.display_name;
                }
                // Check for grandchildren
                if let Ok(grandchildren) = self.list_children(scope, &full_path).await {
                    info.has_children =
                        Some(grandchildren.iter().any(|c| c.strip_suffix('/').is_some()));
                }
                folders.push(info);
            }
        }

        Ok(folders)
    }

    /// Get the .config for a folder in a specific scope.
    pub async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderConfig, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid .config: {}", e)))
    }

    /// Resolve whether `who` may access `folder` under `scope`.
    ///
    /// Checks the folder's own `allowed_groups` and `allowed_users` first
    /// (see `FolderConfig::grants`). If neither matches and the
    /// folder's `inherit_from_parent` is true, walks up the slash-separated
    /// path and evaluates each ancestor's config the same way. Returns `false`
    /// once a folder denies and doesn't inherit, or once the walk reaches the
    /// top-level folder with no match. Missing (`NotFound`) folder configs
    /// are treated as deny; other Vault errors propagate so callers can log.
    pub async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        who: FolderSubject<'_>,
    ) -> Result<bool, VaultError> {
        let mut current = folder.to_string();
        loop {
            let config = match self.get_folder_config(scope, &current).await {
                Ok(c) => c,
                Err(VaultError::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            if config.grants(who) {
                return Ok(true);
            }
            if !config.inherit_from_parent {
                return Ok(false);
            }
            // Walk to parent segment; stop at the top-level folder.
            match current.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
                _ => return Ok(false),
            }
        }
    }

    /// Write a folder's .config.
    pub async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        self.store
            .put(&path, &to_doc(config)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put folder config"))
    }

    /// Delete a folder and everything under it: entries, subfolders and the
    /// `.config` / `.defaults` sentinels at every level.
    ///
    /// Returns (subfolder_count, entry_count) for audit/UI feedback, counted
    /// before the delete. Subfolder count excludes the folder itself (0 for a
    /// leaf); sentinels are not entries.
    pub async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let root = self.kv_path(&scope_prefix, folder);

        let (mut subfolders, mut entries) = (0usize, 0usize);
        let mut dirs = vec![root.clone()];
        while let Some(dir) = dirs.pop() {
            let names = match self.store.list(&dir).await {
                Ok(names) => names,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(failed("list")(e)),
            };
            for name in names {
                match name.strip_suffix('/') {
                    Some(sub) => {
                        subfolders += 1;
                        dirs.push(format!("{}/{}", dir, sub));
                    }
                    None if name == ".config" || name == ".defaults" => {}
                    None => entries += 1,
                }
            }
        }

        self.store
            .delete_prefix(&root)
            .await
            .map_err(failed("delete folder"))?;
        Ok((subfolders, entries))
    }
}
