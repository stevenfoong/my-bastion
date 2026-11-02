// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Per-user credential variables: values a user stores once and entries
//! refer to as `$name`.

use super::*;
use std::collections::HashMap;

/// Sanitize an email address for use as a Vault path component.
/// Replaces `@` with `_at_` and strips any characters not in `[a-zA-Z0-9._-]`.
fn sanitize_email_key(email: &str) -> String {
    email
        .replace('@', "_at_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Check if a string is a credential variable reference (starts with `$`).
pub fn is_credential_variable(s: &str) -> bool {
    s.starts_with('$')
        && s.len() > 1
        && s[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Extract the variable name from a `$variable` reference.
fn variable_name(s: &str) -> Option<&str> {
    if is_credential_variable(s) {
        Some(&s[1..])
    } else {
        None
    }
}

/// Collect all credential variable names referenced by an address book entry.
pub fn entry_credential_variables(entry: &AddressBookEntry) -> Vec<String> {
    [
        &entry.username,
        &entry.password,
        &entry.domain,
        &entry.private_key,
        &entry.container_username,
        &entry.container_password,
    ]
    .iter()
    .filter_map(|field| field.as_deref())
    .filter_map(variable_name)
    .map(|s| s.to_string())
    .collect()
}

/// Resolve credential variable references in an address book entry.
/// Returns the entry with `$var` fields substituted from the user's credential map.
/// Fields that are not variable references are left unchanged.
/// Returns `Err(vec_of_missing_var_names)` if any referenced variables are missing.
pub fn resolve_credential_variables(
    entry: &AddressBookEntry,
    user_creds: &HashMap<String, String>,
) -> Result<AddressBookEntry, Vec<String>> {
    let mut resolved = entry.clone();
    let mut missing = Vec::new();

    fn resolve_field(
        field: &mut Option<String>,
        creds: &HashMap<String, String>,
        missing: &mut Vec<String>,
    ) {
        if let Some(ref val) = field {
            if let Some(name) = variable_name(val) {
                if let Some(resolved_val) = creds.get(name) {
                    *field = Some(resolved_val.clone());
                } else {
                    missing.push(name.to_string());
                }
            }
        }
    }

    resolve_field(&mut resolved.username, user_creds, &mut missing);
    resolve_field(&mut resolved.password, user_creds, &mut missing);
    resolve_field(&mut resolved.domain, user_creds, &mut missing);
    resolve_field(&mut resolved.private_key, user_creds, &mut missing);
    resolve_field(&mut resolved.container_username, user_creds, &mut missing);
    resolve_field(&mut resolved.container_password, user_creds, &mut missing);

    if missing.is_empty() {
        Ok(resolved)
    } else {
        Err(missing)
    }
}

impl ConnectionStore {
    // ── User credential variables ──

    /// Read a user's stored credential variables from Vault.
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<HashMap<String, String>, ConnectionError> {
        self.get_user_credentials_by_key(&sanitize_email_key(email))
            .await
    }

    /// Write a user's credential variables to Vault (full replace).
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn put_user_credentials(
        &self,
        email: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), ConnectionError> {
        self.put_user_credentials_by_key(&sanitize_email_key(email), creds)
            .await
    }

    /// Read credential variables by the already-sanitised users key. Used by
    /// `vault-migrate` (which enumerates raw keys and must not re-sanitise).
    pub async fn get_user_credentials_by_key(
        &self,
        key: &str,
    ) -> Result<HashMap<String, String>, ConnectionError> {
        let path = format!("{}/users/{}", self.base_path, key);
        let doc = self
            .store
            .get(&path)
            .await
            .map_err(failed("get user credentials"))?;
        // No document: no credentials stored yet.
        let map = doc
            .and_then(|d| {
                d.data.as_object().map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
            })
            .unwrap_or_default();
        Ok(map)
    }

    /// Write credential variables by the already-sanitised users key (full
    /// replace). Companion to [`get_user_credentials_by_key`] for migration.
    pub async fn put_user_credentials_by_key(
        &self,
        key: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), ConnectionError> {
        let path = format!("{}/users/{}", self.base_path, key);
        self.store
            .put(&path, &to_doc(creds)?, None)
            .await
            .map(|_| ())
            .map_err(write_failed("put user credentials"))
    }

    /// List the raw key names under `<base_path>/users/` (each a sanitised
    /// email). Empty when no credentials have been stored yet.
    pub async fn list_user_keys(&self) -> Result<Vec<String>, ConnectionError> {
        let path = format!("{}/users", self.base_path);
        match self.kv_list(&path).await {
            Ok(keys) => Ok(keys.into_iter().filter(|k| !k.ends_with('/')).collect()),
            Err(ConnectionError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Delete a user's credential variables from Vault.
    #[allow(dead_code)] // Will be used by admin endpoint
    pub async fn delete_user_credentials(&self, email: &str) -> Result<(), ConnectionError> {
        let key = sanitize_email_key(email);
        let path = format!("{}/users/{}", self.base_path, key);
        match self.store.delete(&path).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()), // Already gone
            Err(e) => Err(failed("delete user credentials")(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_email_key() {
        assert_eq!(
            sanitize_email_key("alice@example.com"),
            "alice_at_example.com"
        );
        assert_eq!(sanitize_email_key("bob+tag@foo.co"), "bobtag_at_foo.co");
        assert_eq!(sanitize_email_key("../../evil"), "....evil");
    }

    #[test]
    fn test_is_credential_variable() {
        assert!(is_credential_variable("$corp_user"));
        assert!(is_credential_variable("$lab_password"));
        assert!(is_credential_variable("$x"));
        assert!(!is_credential_variable("$"));
        assert!(!is_credential_variable("plain_text"));
        assert!(!is_credential_variable(""));
        assert!(!is_credential_variable("$has spaces"));
        assert!(is_credential_variable("$has-dashes")); // hyphens allowed since v0.8.0
    }

    #[test]
    fn test_entry_credential_variables() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()), // literal, not a variable
            ..AddressBookEntry::default()
        };
        let vars = entry_credential_variables(&entry);
        assert_eq!(vars, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_success() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()),
            hostname: Some("rdp.example.com".into()),
            ..AddressBookEntry::default()
        };

        let mut creds = HashMap::new();
        creds.insert("corp_user".into(), "alice".into());
        creds.insert("corp_password".into(), "s3cret".into());

        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("s3cret"));
        assert_eq!(resolved.domain.as_deref(), Some("CORP")); // unchanged
        assert_eq!(resolved.hostname.as_deref(), Some("rdp.example.com")); // unchanged
    }

    #[test]
    fn test_resolve_credential_variables_missing() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new(); // empty
        let err = resolve_credential_variables(&entry, &creds).unwrap_err();
        assert_eq!(err, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_no_variables() {
        let entry = AddressBookEntry {
            username: Some("alice".into()),
            password: Some("literal_pass".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new();
        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("literal_pass"));
    }
}
