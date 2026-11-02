//! Secret store commands: `mybastion storage migrate` (copy between Vault
//! and SQLite), `mybastion rotate-kek` (re-wrap the SQLite data key) and
//! `mybastion secret put` (write one secret, e.g. the LUKS drive key).

use std::sync::Arc;

use super::{crypto, SecretStore, StoreError};
use crate::config::Config;

#[derive(clap::Subcommand)]
pub enum StorageCommand {
    /// Copy every secret under the address-book base path from one backend
    /// to the other ("vault" or "sqlite"), plus any --path given. Existing
    /// secrets in the destination are kept unless --overwrite. Run with
    /// --dry-run first.
    Migrate {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// Another secret to copy as-is, by its path under the KV mount
        /// (e.g. the drive's luks_key_path). Repeatable.
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum SecretCommand {
    /// Write a secret, replacing what is there: e.g.
    /// `secret put mybastion/luks key=@/root/luks.key`. FIELD=@FILE reads the
    /// value from a file, which keeps it out of shell history.
    Put {
        /// Path under the KV mount
        path: String,
        /// FIELD=VALUE or FIELD=@FILE
        #[arg(required = true)]
        fields: Vec<String>,
        /// "vault" or "sqlite"; default: the backend in use
        #[arg(long)]
        backend: Option<String>,
    },
}

fn exit_on_error(result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

pub async fn run_storage(config: &Config, command: StorageCommand) {
    let StorageCommand::Migrate {
        from,
        to,
        paths,
        overwrite,
        dry_run,
    } = command;
    exit_on_error(migrate(config, &from, &to, &paths, overwrite, dry_run).await);
}

pub async fn run_secret(config: &Config, command: SecretCommand) {
    let SecretCommand::Put {
        path,
        fields,
        backend,
    } = command;
    let backend = backend.unwrap_or_else(|| {
        let name = if config.sqlite_storage().is_some() {
            "sqlite"
        } else {
            "vault"
        };
        name.to_string()
    });
    exit_on_error(put(config, &backend, &path, &fields).await);
}

/// `mybastion rotate-kek`: re-wrap the SQLite data key under a new KEK.
pub fn run_rotate_kek(config: &Config, new_kek_source: &str) {
    exit_on_error(rotate_kek(config, new_kek_source));
}

/// A backend opened for the CLI, with the base path of its address book.
struct Backend {
    store: Arc<dyn SecretStore>,
    base_path: String,
}

async fn open_backend(config: &Config, name: &str) -> Result<Backend, String> {
    match name {
        "vault" => {
            let vc = config
                .vault
                .as_ref()
                .ok_or("backend 'vault' needs a [vault] section")?;
            let secret_id = vc.login_secret("VAULT_SECRET_ID")?;
            let store = super::vault::VaultStore::new(vc, &secret_id)
                .await
                .map_err(|e| format!("connecting to {}: {}", vc.addr, e))?;
            Ok(Backend {
                store: Arc::new(store),
                base_path: vc.base_path.clone(),
            })
        }
        "sqlite" => {
            let sc = config.storage_settings();
            Ok(Backend {
                store: super::open_sqlite(&sc)?,
                base_path: sc.base_path.clone(),
            })
        }
        other => Err(format!("unknown backend '{}' (use vault or sqlite)", other)),
    }
}

async fn migrate(
    config: &Config,
    from: &str,
    to: &str,
    paths: &[String],
    overwrite: bool,
    dry_run: bool,
) -> Result<(), String> {
    if from == to {
        return Err("--from and --to must name different backends".into());
    }
    let src = open_backend(config, from).await?;
    let dst = open_backend(config, to).await?;
    let opts = CopyOptions { overwrite, dry_run };
    println!(
        "{}Copying {}/ ({}) -> {}/ ({})",
        if dry_run { "[DRY RUN] " } else { "" },
        src.base_path,
        from,
        dst.base_path,
        to
    );
    let mut report = copy_tree(
        &*src.store,
        &src.base_path,
        &*dst.store,
        &dst.base_path,
        opts,
    )
    .await
    .map_err(|e| e.to_string())?;
    for p in paths {
        copy_one(&*src.store, p, &*dst.store, p, opts, &mut report)
            .await
            .map_err(|e| e.to_string())?;
    }
    println!(
        "\n{} copied, {} skipped (already in {}), {} missing",
        report.copied, report.skipped, to, report.missing
    );
    if dry_run {
        println!("Re-run without --dry-run to perform the copy.");
    }
    Ok(())
}

fn rotate_kek(config: &Config, new_source: &str) -> Result<(), String> {
    let sc = config.storage_settings();
    let new = crypto::Key::load(new_source)?;
    let store = super::open_sqlite(&sc)?;
    store.rewrap(&new).map_err(|e| e.to_string())?;
    println!(
        "Re-wrapped the data key of {} under the new KEK (id {}).\n\
         Set [storage] kek_source = \"{}\" before the next restart; the old KEK no longer opens it.",
        sc.path.display(),
        new.id(),
        new_source
    );
    Ok(())
}

async fn put(config: &Config, backend: &str, path: &str, fields: &[String]) -> Result<(), String> {
    let mut doc = serde_json::Map::new();
    for f in fields {
        let (k, v) = f
            .split_once('=')
            .ok_or_else(|| format!("'{}' is not FIELD=VALUE", f))?;
        let v = match v.strip_prefix('@') {
            Some(file) => {
                std::fs::read_to_string(file).map_err(|e| format!("cannot read {}: {}", file, e))?
            }
            None => v.to_string(),
        };
        doc.insert(k.to_string(), serde_json::Value::String(v));
    }
    let b = open_backend(config, backend).await?;
    let version = b
        .store
        .put(path, &serde_json::Value::Object(doc), None)
        .await
        .map_err(|e| e.to_string())?;
    println!("Wrote {} on {} (version {})", path, backend, version);
    Ok(())
}

#[derive(Clone, Copy)]
pub struct CopyOptions {
    pub overwrite: bool,
    pub dry_run: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct CopyReport {
    pub copied: usize,
    pub skipped: usize,
    pub missing: usize,
}

fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{}/{}", a, b),
    }
}

/// Copy every document under `from` in `src` to the same relative path
/// under `to` in `dst`. Documents only: Vault keeps no folders of its own.
pub async fn copy_tree(
    src: &dyn SecretStore,
    from: &str,
    dst: &dyn SecretStore,
    to: &str,
    opts: CopyOptions,
) -> Result<CopyReport, StoreError> {
    let mut report = CopyReport::default();
    let mut dirs = vec![String::new()];
    while let Some(rel) = dirs.pop() {
        let names = match src.list(&join(from, &rel)).await {
            Ok(names) => names,
            Err(StoreError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        for name in names {
            match name.strip_suffix('/') {
                Some(sub) => dirs.push(join(&rel, sub)),
                None => {
                    let p = join(&rel, &name);
                    copy_one(src, &join(from, &p), dst, &join(to, &p), opts, &mut report).await?;
                }
            }
        }
    }
    Ok(report)
}

async fn copy_one(
    src: &dyn SecretStore,
    from: &str,
    dst: &dyn SecretStore,
    to: &str,
    opts: CopyOptions,
    report: &mut CopyReport,
) -> Result<(), StoreError> {
    let Some(doc) = src.get(from).await? else {
        println!("  missing {}", from);
        report.missing += 1;
        return Ok(());
    };
    if opts.dry_run {
        let exists = dst.get(to).await?.is_some();
        if exists && !opts.overwrite {
            println!("  would skip {} (exists)", to);
            report.skipped += 1;
        } else {
            println!("  would copy {}", to);
            report.copied += 1;
        }
        return Ok(());
    }
    // Without --overwrite, check-and-set 0 makes "only if absent" atomic.
    let cas = (!opts.overwrite).then_some(0);
    match dst.put(to, &doc.data, cas).await {
        Ok(_) => {
            println!("  copied {}", to);
            report.copied += 1;
        }
        Err(StoreError::CasConflict) => {
            println!("  skipped {} (exists)", to);
            report.skipped += 1;
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use serde_json::json;

    fn temp_store(dir: &std::path::Path, name: &str) -> SqliteStore {
        let kek = crypto::Key::parse(&"44".repeat(32)).unwrap();
        SqliteStore::open(&dir.join(name), &kek).unwrap()
    }

    async fn dump(s: &dyn SecretStore, base: &str) -> Vec<(String, serde_json::Value)> {
        let mut out = Vec::new();
        let mut dirs = vec![base.to_string()];
        while let Some(d) = dirs.pop() {
            let Ok(names) = s.list(&d).await else {
                continue;
            };
            for n in names {
                match n.strip_suffix('/') {
                    Some(sub) => dirs.push(format!("{}/{}", d, sub)),
                    None => {
                        let p = format!("{}/{}", d, n);
                        let doc = s.get(&p).await.unwrap().unwrap();
                        out.push((p[base.len()..].to_string(), doc.data));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    #[tokio::test]
    async fn round_trip_copy_gives_identical_documents() {
        let dir = std::env::temp_dir().join(format!("mybastion-migrate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = temp_store(&dir, "a.db");
        let b = temp_store(&dir, "b.db");
        let c = temp_store(&dir, "c.db");
        for (p, v) in [
            (
                "mybastion/shared/Prod/.config",
                json!({"allowed_groups": ["ops"]}),
            ),
            (
                "mybastion/shared/Prod/.defaults",
                json!({"ssh": {"username": "u"}}),
            ),
            (
                "mybastion/shared/Prod/web01",
                json!({"type": "rdp", "password": "p"}),
            ),
            ("mybastion/shared/Prod/Web/web02", json!({"type": "ssh"})),
            ("mybastion/instance/node1/Lab/box", json!({"type": "vnc"})),
            ("mybastion/users/a_at_b.c", json!({"corp_pw": "x"})),
            ("other/not-copied", json!({})),
        ] {
            a.put(p, &v, None).await.unwrap();
        }
        let opts = CopyOptions {
            overwrite: false,
            dry_run: false,
        };
        let r1 = copy_tree(&a, "mybastion", &b, "rg2", opts).await.unwrap();
        assert_eq!(
            r1,
            CopyReport {
                copied: 6,
                skipped: 0,
                missing: 0
            }
        );
        copy_tree(&b, "rg2", &c, "mybastion", opts).await.unwrap();
        assert_eq!(dump(&a, "mybastion").await, dump(&c, "mybastion").await);
        assert!(c.get("other/not-copied").await.unwrap().is_none());

        // Again: everything exists, so nothing is written without --overwrite.
        b.put("rg2/shared/Prod/web01", &json!({"changed": true}), None)
            .await
            .unwrap();
        let r2 = copy_tree(&b, "rg2", &c, "mybastion", opts).await.unwrap();
        assert_eq!((r2.copied, r2.skipped), (0, 6));
        assert_eq!(
            c.get("mybastion/shared/Prod/web01")
                .await
                .unwrap()
                .unwrap()
                .data["password"],
            "p"
        );
        let over = CopyOptions {
            overwrite: true,
            dry_run: false,
        };
        copy_tree(&b, "rg2", &c, "mybastion", over).await.unwrap();
        assert_eq!(
            c.get("mybastion/shared/Prod/web01")
                .await
                .unwrap()
                .unwrap()
                .data,
            json!({"changed": true})
        );

        // A dry run reports and writes nothing.
        let d = temp_store(&dir, "d.db");
        let dry = CopyOptions {
            overwrite: false,
            dry_run: true,
        };
        assert_eq!(
            copy_tree(&a, "mybastion", &d, "mybastion", dry)
                .await
                .unwrap()
                .copied,
            6
        );
        assert!(dump(&d, "mybastion").await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
