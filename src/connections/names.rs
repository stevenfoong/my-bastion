// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! Validation of folder and entry names before they become store paths.

use super::*;

/// Validate that a folder or entry name is safe (alphanumeric, hyphens, underscores, dots — no path traversal).
pub(super) fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() || name.len() > 64 {
        return Err(VaultError::BadName("name must be 1-64 characters".into()));
    }
    if name == ".config" || name == ".defaults" || name == "." || name == ".." {
        return Err(VaultError::BadName("reserved name".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(VaultError::BadName(
            "name cannot contain path separators".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(VaultError::BadName(
            "name must be alphanumeric, hyphens, underscores, or dots".into(),
        ));
    }
    Ok(())
}

/// Validate a folder path that may contain subfolders (e.g. "Clients/Acme/Servers").
/// Each segment is validated with the same rules as `validate_name`.
/// Empty segments, trailing slashes, and leading slashes are rejected.
pub(super) fn validate_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty() {
        return Err(VaultError::BadName("path cannot be empty".into()));
    }
    if path.len() > 256 {
        return Err(VaultError::BadName("path too long (max 256 chars)".into()));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(VaultError::BadName(
            "path cannot start or end with /".into(),
        ));
    }
    if path.contains("//") {
        return Err(VaultError::BadName(
            "path cannot contain empty segments".into(),
        ));
    }
    for segment in path.split('/') {
        validate_name(segment)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name_ok() {
        assert!(validate_name("my-entry.v2").is_ok());
        assert!(validate_name("a").is_ok());
    }

    #[test]
    fn test_validate_name_rejects_traversal() {
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn test_validate_name_rejects_empty_and_long() {
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_validate_path_ok() {
        assert!(validate_path("my-folder").is_ok());
        assert!(validate_path("Clients/Acme").is_ok());
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a/b/c/d").is_ok());
    }

    #[test]
    fn test_validate_path_rejects_bad_input() {
        assert!(validate_path("").is_err()); // empty
        assert!(validate_path("/leading").is_err()); // leading slash
        assert!(validate_path("trailing/").is_err()); // trailing slash
        assert!(validate_path("a//b").is_err()); // empty segment
        assert!(validate_path("a/../b").is_err()); // traversal
        assert!(validate_path("a/.config/b").is_err()); // reserved name
        assert!(validate_path(&format!("a/{}", "x".repeat(65))).is_err()); // segment too long
    }

    #[test]
    fn validate_name_accepts_plain_names() {
        assert!(validate_name("acme").is_ok());
        assert!(validate_name("acme-prod").is_ok());
        assert!(validate_name("acme_prod").is_ok());
        assert!(validate_name("host.example").is_ok());
        assert!(validate_name("A1b2C3").is_ok());
    }

    #[test]
    fn validate_name_rejects_traversal() {
        assert!(validate_name("..").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_name_rejects_reserved() {
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn validate_name_rejects_encoded_traversal() {
        // Encoded forms should fail because `%` is not in the whitelist.
        assert!(validate_name("%2e%2e").is_err());
        assert!(validate_name("%2E%2E%2F").is_err());
        assert!(validate_name("..%2F..").is_err());
    }

    #[test]
    fn validate_name_rejects_nul_and_control() {
        assert!(validate_name("foo\0bar").is_err());
        assert!(validate_name("foo\nbar").is_err());
        assert!(validate_name("foo\tbar").is_err());
    }

    #[test]
    fn validate_name_rejects_unicode() {
        // Unicode letters/digits shouldn't sneak past the ascii-alphanumeric
        // whitelist (blocks homoglyph and normalization tricks).
        assert!(validate_name("café").is_err());
        assert!(validate_name("Ⅰ").is_err()); // Roman numeral 1
        assert!(validate_name("а").is_err()); // Cyrillic 'a'
    }

    #[test]
    fn validate_name_rejects_empty_and_overlong() {
        assert!(validate_name("").is_err());
        let overlong = "a".repeat(65);
        assert!(validate_name(&overlong).is_err());
        let at_limit = "a".repeat(64);
        assert!(validate_name(&at_limit).is_ok());
    }

    #[test]
    fn validate_name_rejects_spaces_and_special() {
        assert!(validate_name("foo bar").is_err());
        assert!(validate_name("foo;rm -rf").is_err());
        assert!(validate_name("foo$bar").is_err());
        assert!(validate_name("foo@bar").is_err());
    }

    #[test]
    fn validate_path_accepts_nested() {
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a").is_ok());
        assert!(validate_path("a/b").is_ok());
    }

    #[test]
    fn validate_path_rejects_leading_or_trailing_slash() {
        assert!(validate_path("/foo").is_err());
        assert!(validate_path("foo/").is_err());
        assert!(validate_path("/").is_err());
    }

    #[test]
    fn validate_path_rejects_empty_segments() {
        assert!(validate_path("").is_err());
        assert!(validate_path("a//b").is_err());
        assert!(validate_path("a///b").is_err());
    }

    #[test]
    fn validate_path_rejects_traversal_in_any_segment() {
        assert!(validate_path("../etc").is_err());
        assert!(validate_path("foo/../etc").is_err());
        assert!(validate_path("foo/..").is_err());
        assert!(validate_path("foo/./bar").is_err());
    }

    #[test]
    fn validate_path_rejects_overlong() {
        let overlong = "a".repeat(257);
        assert!(validate_path(&overlong).is_err());
    }
}
