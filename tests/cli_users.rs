// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! CLI behaviour for `mybastion add-user` and `mybastion reset-oidc-subject`.
//!
//! Integration tests because they run the built binary (see
//! tests/cli_map_group.rs for why that has to happen here). Database
//! assertions go through rusqlite directly, since mybastion has no lib target.

use assert_cmd::Command;
use rusqlite::Connection;

/// Scratch directory for one test, removed on drop.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mybastion-cli-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        std::fs::write(path.join("config.toml"), "db_path = \"./mybastion.db\"\n")
            .expect("write config");
        ScratchDir(path)
    }

    fn conn(&self) -> Connection {
        Connection::open(self.0.join("mybastion.db")).expect("open database")
    }

    fn run(&self, args: &[&str]) -> assert_cmd::assert::Assert {
        let mut cmd = Command::cargo_bin("mybastion").unwrap();
        cmd.current_dir(&self.0)
            .args(["--config", "config.toml"])
            .args(args)
            .assert()
    }

    /// Every user as (email, role, oidc_subject), ordered by id.
    fn users(&self) -> Vec<(String, String, Option<String>)> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT email, role, oidc_subject FROM users ORDER BY id")
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query");
        rows.map(|r| r.expect("row")).collect()
    }

    /// The newest CLI audit row as (action, target, details).
    fn last_audit(&self) -> (String, String, Option<String>) {
        self.conn()
            .query_row(
                "SELECT action, target, details FROM cli_audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("an audit row should exist")
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_add_user() {
    let dir = ScratchDir::new("add-user");
    dir.run(&[
        "add-user",
        "--email",
        "JSmith@Example.com",
        "--role",
        "operator",
    ])
    .success();
    assert_eq!(
        dir.users(),
        vec![(
            "JSmith@Example.com".to_string(),
            "operator".to_string(),
            None
        )]
    );
    assert_eq!(
        dir.last_audit(),
        (
            "add_user".to_string(),
            "JSmith@Example.com".to_string(),
            Some("role=operator".to_string())
        )
    );

    // Logins match email ignoring case, so another case is the same user.
    dir.run(&[
        "add-user",
        "--email",
        "jsmith@example.com",
        "--role",
        "admin",
    ])
    .failure();
    // Not an email a provider would send.
    dir.run(&[
        "add-user",
        "--email",
        "bob smith@example.com",
        "--role",
        "viewer",
    ])
    .failure();
    dir.run(&["add-user", "--email", "bob", "--role", "viewer"])
        .failure();
    dir.run(&["add-user", "--email", "bob@example.com", "--role", "root"])
        .failure();
    assert_eq!(dir.users().len(), 1, "refused adds change nothing");
}

#[test]
fn cli_reset_oidc_subject() {
    let dir = ScratchDir::new("reset-oidc-subject");
    dir.run(&[
        "add-user",
        "--email",
        "alice@example.com",
        "--role",
        "admin",
    ])
    .success();
    // Stand in for a first login, which records the provider's subject.
    dir.conn()
        .execute(
            "UPDATE users SET oidc_subject = 'old-idp-alice' WHERE email = 'alice@example.com'",
            [],
        )
        .unwrap();

    dir.run(&["reset-oidc-subject", "--email", "ALICE@example.com"])
        .success();
    assert_eq!(
        dir.users(),
        vec![("alice@example.com".to_string(), "admin".to_string(), None)],
        "the binding is gone and the role is untouched"
    );
    assert_eq!(
        dir.last_audit(),
        (
            "reset_oidc_subject".to_string(),
            "alice@example.com".to_string(),
            None
        )
    );

    dir.run(&["reset-oidc-subject", "--email", "nobody@example.com"])
        .failure();
}
