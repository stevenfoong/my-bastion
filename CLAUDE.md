# CLAUDE.md — My Bastion

## What this project is

My Bastion (`mybastion`) is one gateway for privileged access: people and AI
agents reaching desktops, servers and, later, databases, with every action
recorded, controlled and, when it matters, approved. It is a **hard fork** of
[sol1/rustguac](https://github.com/sol1/rustguac) v1.13.4 and does not track
upstream: refactor, rename and delete freely when it makes the design cleaner.

The plan and its phases are in `docs/fork-design.md`; read it before starting
a phase. Status:

- Phase 0 (rename, NOTICE, CI, inherited features off by default): done
- Phase 1 (SQLite secret store): code done (`src/store/`,
  `src/connections/`, SQLite default, DR split dropped, migration CLI). Left
  from its done-when: connecting to a real RDP target from the UI on a
  fresh install with no Vault
- Phase 2 (policy/approval engine): slice 2a done (rules, connect approvals,
  approvals page, admin policies, audit). Next: 2b `run_ssh`, 2c Telegram,
  2d clipboard/file transfer + break-glass, 2e interactive SSH logging
- Phases 3–4 (MCP, DB proxy): not started

## Architecture

- **Core** (`mybastion`, Rust): axum web UI + REST API, identity (OIDC, roles,
  API keys), secret store, audit + recordings, desktop proxy (WebSocket <->
  guacd). Later: policy/approval engine and the MCP endpoint.
- **guacd** (C, Apache Guacamole guacamole-server, built with `patches/`):
  RDP/VNC/SSH/SPICE protocol translation. Never modified beyond the patches.
- **Xvnc + Chromium**: web sessions, one per session. Off unless `[web]`.
- **Docker**: VDI containers. Off unless `[vdi]`; socket access is
  root-equivalent, so installers never add the service user to `docker`.

## Key files

- `src/main.rs` — entry point, CLI (clap), server setup, startup wiring
- `src/api.rs` — REST API (sessions, connections, recordings, admin)
- `src/session.rs` — session state machine, `SessionManager`, the
  per-type switches in `create_session`
- `src/config.rs` — TOML config with defaults
- `src/auth.rs` — API key auth (SHA-256, IP allowlists, expiry), roles
- `src/oidc.rs` — OIDC login, callback, logout, group extraction
- `src/connections/` — `ConnectionStore` over a `SecretStore`: `model.rs`
  (entries, folder config), `folders.rs` (listing, ACL walk, folder delete),
  `entries.rs`, `defaults.rs` (folder default credentials), `credentials.rs`
  (per-user credential variables), `names.rs` (path validation). In
  `api.rs`, `Connections` wraps the one store cell the handlers use
- `src/store/` — `SecretStore` trait (`mod.rs`), `vault.rs` (Vault/OpenBao
  KV v2 over HTTP: AppRole/JWT login, renewal, TLS), `sqlite.rs`, `crypto.rs`
  (AES-256-GCM envelope: KEK wraps a data key; row AAD = path + version),
  `cli.rs` (`mybastion storage migrate`, `rotate-kek`, `secret put`)
- `src/policy/` — policy engine (`mod.rs`: rules, evaluation, `gate()` used by
  every connect route), `store.rs` (policies, approval_requests,
  policy_audit_log tables), `api.rs` (admin + approvals endpoints). Docs:
  `docs/policies.md`
- `src/db.rs` — main SQLite database (users, sessions, tokens, audit)
- `src/guacd.rs`, `src/protocol.rs`, `src/websocket.rs` — guacd handshake,
  wire format, WebSocket <-> guacd bridge with recording tee
- `src/browser.rs`, `src/vdi/`, `src/pve.rs` — web, VDI, Proxmox sessions
- `static/` — web UI; `static/guac/` is the Apache Guacamole JS client
- `install.sh` (Debian 13 from source), `install-release.sh` (tarball),
  `debian/`, `mybastion.spec`, `Dockerfile` + `entrypoint.sh`

## Installed layout

- `/opt/mybastion` — `bin/mybastion`, `sbin/guacd`, `lib/`, `static/`,
  `LICENSE`, `NOTICE`
- `/etc/mybastion` (root:mybastion 0750) — `mybastion.toml` (0640), `env`
  (`VAULT_SECRET_ID`, `OIDC_CLIENT_SECRET`, …), `guacd.env`, `tls/`, `kek`
- `/var/lib/mybastion` (mybastion) — `mybastion.db`, `secrets.db`,
  `recordings/`, `drives.luks`
- systemd: `mybastion.service`, `mybastion-guacd.service`; user `mybastion`
  with a real home (`/home/mybastion`, Chromium's crashpad needs it)

Config is found via `--config`, else `/etc/mybastion/mybastion.toml`;
`mybastion.example.toml` documents every key.

## Configuration notes

- **Secret store:** SQLite by default (`[storage]`: `path`, `kek_source` =
  `file:`/`env:`/`systemd-creds:`, `base_path`, `instance_name`; installers
  create `/etc/mybastion/kek`). Vault with `[storage] backend = "vault"`, or
  `[vault]` and no `[storage]`: `[vault]`
  (`addr`, `role_id` or `[vault.jwt_auth]`, `mount`, `base_path` default
  `mybastion`, `namespace`, `instance_name`; secret via `VAULT_SECRET_ID`).
  Existing rustguac Vault data lives under `base_path = "rustguac"`.
- Store paths (relative to the KV mount): `<base>/shared/<folder>/<entry>`,
  `<base>/instance/<name>/<folder>/<entry>`, `<folder>/.config` (ACL),
  `<folder>/.defaults` (default credentials, inherited only while a subfolder
  has `inherit_from_parent` and no ACL of its own), `<base>/users/<key>`.
- **Inherited features, off by default:** `[web] enabled`, `[spice] enabled`
  (SPICE + Proxmox), `[vdi] enabled`. NetBox sync has no code of its own: it
  is NetBox calling the REST API with a key an admin creates.
- **OIDC:** `[oidc]` `issuer_url`, `client_id`, `client_secret` (or
  `OIDC_CLIENT_SECRET`), `redirect_uri`, `groups_claim`, `extra_scopes`.
- **Roles:** `admin` (4) > `poweruser` (3, ad-hoc sessions) > `operator` (2,
  connect from connections) > `viewer` (1).

## Licence rules (Apache-2.0)

- Keep `LICENSE` as is and keep `NOTICE` crediting sol1/rustguac and Apache
  Guacamole; every package ships both.
- A file inherited from rustguac that you change must carry the one-line
  "Changed for My Bastion" notice near its top (most already do). New files
  don't need it.

## Build notes

- guacd is built from `../guacamole-server` if present, else cloned at the
  pinned commit; `patches/` (see `patches/README.md`) is applied by every
  build script. Debian 13 ships FreeRDP 3 (`freerdp3-dev`).
- Chromium on headless VMs needs `--in-process-gpu`, `--use-gl=angle`,
  `--use-angle=swiftshader`, `--disable-gpu-*`, `--disable-dev-shm-usage`; each
  session gets its own `--user-data-dir`.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test` on Debian trixie. Releases
  (`release.yml`, on `v*` tags) build .deb/tarballs and push
  `ghcr.io/stevenfoong/mybastion`.

## Session types

SSH, RDP, VNC (guacd straight to the target); Web (Xvnc + Chromium, `[web]`);
SPICE and Proxmox (`[spice]`); VDI (Docker container with xrdp, `[vdi]`,
`mybastion-vdi-<user>`, image must take `VDI_USERNAME`/`VDI_PASSWORD`; test
image in `contrib/vdi-test-image/`).

## Ports

8089 My Bastion HTTP/WebSocket · 4822 guacd · 6000-6099 Xvnc (:100-:199)

## Testing

- `cargo test` — unit and CLI tests (`tests/cli_*.rs`)
- `tests/test_storage_sqlite.sh` — live: SQLite store with no Vault (API
  create/read across restarts, `secret put`, `rotate-kek`)
- `tests/test_policy_approval.sh` — live: contractors→prod held for approval,
  self-approval refused, deny wins, expiry, audit
- `tests/test_storage_openbao.sh` — live: Vault → SQLite → Vault migration
  against a dev-mode OpenBao (`bao` on PATH); documents must match
- `tests/test_browser_session.sh` — Xvnc + Chromium renders non-black pixels
- `tests/e2e/` — Playwright specs against the static UI with a stubbed API
- Remote test machine (Debian 13, Rust and OpenBao installed): see project
  memory for host, key and the `ec2-test.bat` start/stop helper.
