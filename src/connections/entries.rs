// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Connection entries: list, get, put, put-if-absent, delete.

use super::*;

impl VaultClient {
    /// List entry names in a folder (excludes the `.config` and `.defaults`
    /// sentinels).
    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let keys = self.kv_list(&self.kv_path(&scope_prefix, folder)).await?;
        Ok(keys
            .into_iter()
            .filter(|k| k != ".config" && k != ".defaults")
            .collect())
    }

    /// Get a full entry (with credentials).
    pub async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let data = self.read_doc(&path).await?.ok_or(VaultError::NotFound)?;
        let mut entry: AddressBookEntry = serde_json::from_value(data)
            .map_err(|e| VaultError::Parse(format!("invalid entry: {}", e)))?;
        entry.normalize_jump_hosts();
        Ok(entry)
    }

    /// Write an entry to Vault.
    pub async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        self.write_entry(scope, folder, entry, data, false)
            .await
            .map(|_| ())
    }

    /// Write an entry only if none exists at that path, enforced by Vault
    /// itself (KV v2 check-and-set with `cas: 0`) rather than by a read
    /// beforehand, so two writers cannot both pass the check. Returns
    /// `Ok(false)` when an entry is already there.
    pub async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        self.write_entry(scope, folder, entry, data, true).await
    }

    async fn write_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
        only_if_absent: bool,
    ) -> Result<bool, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let cas = only_if_absent.then_some(0);
        match self.store.put(&path, &to_doc(data)?, cas).await {
            Ok(_) => Ok(true),
            Err(StoreError::CasConflict) => Ok(false),
            Err(e) => Err(write_failed("put entry")(e)),
        }
    }

    /// Delete an entry (all versions via metadata endpoint).
    pub async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), VaultError> {
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.kv_path(&scope_prefix, &format!("{}/{}", folder, entry));
        self.store
            .delete(&path)
            .await
            .map_err(failed("delete entry"))
    }
}
