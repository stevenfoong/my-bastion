# my-bastion: design

Origin: hard fork of `sol1/rustguac` v1.13.4 (Apache-2.0). This repo does **not** track upstream any more.
Status: draft. Phases are built in order, and each phase has to be shippable on its own.

## Goals

1. **SQLite secret store.** Run without Vault/OpenBao. Connections, folders and credentials live in SQLite, encrypted at rest.
2. **MCP endpoint.** AI agents can open RDP/VNC sessions and work them like a person (see the screen, click, type), under the same access rules, recording and audit as human users.
3. **Action approval for people and AI.** One policy and approval engine decides what anyone may do: allow, deny, or wait for approval.
4. **Database access proxy.** Database sessions go through the bastion, every query is logged against a person, and policies limit which commands can run.

## Not goals

- Changing guacd (C) or the protocol libraries. guacd is used as shipped by Apache Guacamole.
- Staying compatible with upstream rustguac's code or config.
- Feature parity with Vault (multi-backend split, Vault auth methods, token renewal).

## Hard-fork principles

- **Refactor freely.** There are no upstream merges to protect, so restructure, rename and delete code whenever it makes the design cleaner.
- **One core, many proxies.** The Rust core owns identity, policy, approval, secrets and audit. Protocol proxies (desktop via guacd, SSH, databases) are clients of the core. A proxy may be a separate service in whatever language suits it best.
- **One audit trail.** Every proxy writes events in the same format, through the core, so a session, a command and a query can be traced back to the same person or agent.
- **Licence obligations (Apache-2.0):** keep `LICENSE` and sol1's copyright notices, add a `NOTICE` file crediting sol1/rustguac and Apache Guacamole, and state in modified files that they were changed.

## Target architecture

```
                 Browser / MCP client / DB client (psql, mysql, DBeaver)
                        |                 |                  |
                        v                 v                  v
   +--------------------------------------------+   +------------------+
   | Core (Rust)                                 |   | DB proxy         |
   |  web UI + REST API + MCP endpoint           |   | (separate svc,   |
   |  identity: OIDC, roles, API keys            |<--|  Go recommended) |
   |  policy + approval engine                   |   +------------------+
   |  secret store (SQLite / Vault)              |          |
   |  audit + recordings                         |          v
   |  desktop proxy (WebSocket <-> guacd)        |   MySQL / PostgreSQL
   +--------------------------------------------+
                        |
                      guacd (C) ---> RDP / VNC / SSH / SPICE targets
```

Proxies talk to the core over an **internal API** (HTTP + mTLS or gRPC, on a private port only):

- `authorize(subject, target, action)`, which returns allow, deny or pending (with an approval id)
- `await_approval(approval_id)`
- `fetch_credentials(target)`, which only hands credentials to registered proxies, never to users
- `audit(event)`

---

## Phase 0: hard-fork housekeeping

- Rename the project: binary, crate name, systemd units, `/opt/...` and `/etc/...` paths, config file name, UI branding and page titles.
- Add `NOTICE`, update `LICENSE` headers on changed files, rewrite `CLAUDE.md` for the new project.
- Point CI and release builds at this repo. Remove sol1-specific bits (commercial-support text, Docker Hub image name, NetBox/Knocknoc docs if not needed).
- Remove or isolate features you don't plan to keep (e.g. VDI, web-browser sessions) so the codebase stays small.

**Done when:** the renamed binary builds, installs and passes the existing test suite.

---

## Phase 1: SQLite secret store

### What Vault holds today

SQLite (`src/db.rs`, rusqlite) already holds users, auth sessions, API tokens, session history and audit logs. Vault (`src/vault.rs`) holds:

| Data | Vault path (under `<mount>/<base_path>`) |
|---|---|
| Connection entries, including credentials (`AddressBookEntry`) | `<scope>/<folder>/<entry>` |
| Folder config / ACL (`FolderConfig`) | `<scope>/<folder>/.config` |
| Folder default credentials | `<scope>/<folder>/.defaults` |
| Per-user credentials / credential variables | `users/<key>` |
| LUKS drive key | arbitrary `kv_path` via `read_kv_field` |

### Key finding

`vault.rs` is about 3,400 lines, but nearly all of it is application logic: ACLs, folder defaults, credential-variable resolution, entry normalisation. The actual Vault I/O is a small set of KV v2 operations (get / put / put-if-absent / list / delete on a path holding one JSON document).

### Design

Split `vault.rs` into:

```
src/store/mod.rs        trait SecretStore (raw KV)
src/store/sqlite.rs     default backend
src/store/vault.rs      optional backend (existing HTTP code)
src/store/crypto.rs     envelope encryption
src/connections/        ACLs, folders, defaults, credential variables (moved out of vault.rs)
```

Rename `VaultClient` to `ConnectionStore` (or similar) across `api.rs` and the rest of the code. With no upstream to merge, take this chance to make the API storage-neutral.

```rust
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, path: &str) -> Result<Option<Doc>, StoreError>;      // Doc = { data: serde_json::Value, version: u64 }
    async fn put(&self, path: &str, data: &Value, cas: Option<u64>) -> Result<u64, StoreError>; // cas Some(0) = create-if-absent
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;   // direct children; folders end in "/"
    async fn delete(&self, path: &str) -> Result<(), StoreError>;
    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError>;
    fn is_available(&self) -> bool;
}
```

**SQLite becomes the default.** Vault is optional.

### SQLite schema (separate `secrets.db`)

```sql
CREATE TABLE secrets (
  path        TEXT PRIMARY KEY,       -- logical path, e.g. "shared/prod/web01"
  version     INTEGER NOT NULL,
  nonce       BLOB NOT NULL,          -- 12 bytes
  ciphertext  BLOB NOT NULL,          -- AES-256-GCM(JSON), AAD = path || version
  updated_at  INTEGER NOT NULL
);
CREATE TABLE secrets_meta (k TEXT PRIMARY KEY, v BLOB);  -- key id, wrapped DEK, schema version
```

- `list(prefix)`: `WHERE path LIKE prefix || '%'`, then reduce to direct children in Rust.
- Check-and-set: one transaction, `UPDATE … WHERE path=? AND version=?`, or `INSERT` for cas=0.
- WAL mode, `busy_timeout`, file mode 0600, owned by the service user.

### Encryption

- **Envelope:** a random 256-bit data key (DEK) encrypts rows. A key-encryption key (KEK) wraps the DEK, and the wrapped DEK is kept in `secrets_meta`.
- **Where the KEK comes from** (`[storage] kek_source`):
  - `file:/etc/<name>/kek` (0400): the default
  - `systemd-creds:<name>-kek`
  - `env:<NAME>_KEK`
  - `aws-kms:<key-arn>`: later
- AAD binds each ciphertext to its path and version, so rows can't be swapped or rolled back.
- `rotate-kek` CLI re-wraps the DEK. Rows are not re-encrypted.
- Plaintext is zeroized after use where practical (`zeroize`).
- **Threat model:** this protects stolen DB files and backups, not a compromised host. Document it.

### Other changes

- LUKS key: read from the store like any other secret. Seed it with the `secret put` CLI.
- "Vault connected?" checks become `store.is_available()`. Connections UI always on.
- Multi-Vault DR split: drop it unless you need it.
- Migration CLI: `storage migrate --from vault --to sqlite`, for importing existing rustguac installs.

```toml
[storage]
backend = "sqlite"            # or "vault"
path = "/var/lib/<name>/secrets.db"
kek_source = "file:/etc/<name>/kek"
```

### Done when

- [ ] Full test suite passes on SQLite, and on Vault where those tests remain.
- [ ] Vault → SQLite migration copies every document byte-for-byte.
- [ ] A tampered row (path, version or ciphertext) fails to decrypt.
- [ ] Fresh install with no Vault: create folder, create RDP entry, connect, all from the UI.

---

## Phase 2: policy and approval engine (core)

Built before MCP and the DB proxy, because both depend on it.

### Model

```
Policy  = subject (user | group | role | api key | ai agent)
        + target  (folder | entry | db | any)
        + action  (connect | input | clipboard | file_transfer | ssh_command | db_query | …)
        + condition (time window, source IP, command/query pattern, read-only, …)
        -> effect: allow | deny | require_approval(approvers, timeout) | allow_and_alert
```

- Policies are stored in SQLite and edited in the admin UI. The most specific matching rule wins, and an explicit deny always wins.
- **Approval requests** record who, what, target, the reason the user typed, the time, the decision, the approver and the approver's comment.
- **Approvers:** by role or group. The requester can never approve their own request.
- **Notifications:** web UI first. Webhooks (Telegram / Slack / email) come later.
- **Break-glass:** an admin can override with a mandatory reason. It's always alerted.

### Where it applies

| Action | Enforcement point | Strength |
|---|---|---|
| Connect to a target (anyone) | core, before the session is created | strong |
| Clipboard / file transfer | core, filters Guacamole instructions | strong |
| AI input (click/type/key) | core, MCP tool layer | strong |
| SSH **one-off commands** (`run_ssh`, approved runbooks) | core SSH exec, the exact command string is known | strong |
| SSH **interactive shell** | keystroke line reconstruction in the WebSocket bridge | **best-effort only** |
| Database queries | DB proxy, parsed SQL | strong |

**About interactive SSH:** guacd draws the terminal as images, and users can hide commands (aliases, scripts, `bash -c`, base64). Reconstructing typed lines is good for **logging and alerting**, not for reliable blocking. For real control:
1. Require approval at the **session level** for sensitive servers (time-limited access).
2. Offer a **command mode**: users and AI run single commands through the bastion (`run_ssh`), where each command can be checked and approved.
3. Enforce on the target with sudo rules and restricted shells, using the bastion as the only way in.

### Done when

- [ ] A policy "group `contractors` → folder `prod` → connect = require_approval(admins)" holds the connection until an admin approves, then times out if nobody does.
- [ ] Self-approval is refused.
- [ ] Every decision appears in the audit log with the requester and approver.
- [ ] `run_ssh` with a denied pattern (e.g. `rm -rf /`) is refused before it reaches the target.

---

## Phase 3: MCP endpoint

### Constraints from the code

- The **first** WebSocket attach to a session is the *owner* connection and must come from the session's creator.
- guacd drops a session if no client attaches within about 15 seconds.
- The server never holds a picture of the screen. Thumbnails are drawn in the browser.

So the MCP server has to **be the Guacamole client**: create the session and attach as owner straight away.

### Components

```
src/mcp/server.rs     MCP over Streamable HTTP at /mcp (official Rust SDK `rmcp`), auth = API key
src/mcp/tools.rs      tool definitions; every input goes through the Phase 2 engine
src/render/mod.rs     headless Guacamole client: instructions -> RGBA framebuffer
src/render/layers.rs  layers and compositing
```

**Renderer:** parses instructions with `protocol.rs` and keeps a framebuffer. Minimum instruction set: `size`, `img`/`blob`/`end` (PNG/JPEG/WebP), `copy`, `rect`/`cfill`, `cursor`, `sync`, `dispose`, plus layer 0 and off-screen buffers. It replies with `ack`/`sync` so guacd keeps streaming. Uses the `image` crate.
*Prototype fallback:* headless Chromium (Playwright) opening `client_url?ticket=…`.

### Tools

| Tool | Notes |
|---|---|
| `list_connections(folder?)` | Only entries visible to the agent and in folders with `ai_allowed`. Never returns credentials. |
| `open_session(entry_id, width?, height?)` | Creates the session and attaches the renderer as owner. |
| `screenshot(session_id, scale?)` | PNG, downscaled to ≤1280 px wide by default. |
| `click(session_id, x, y, button?, double?)` | Screenshot coordinates, mapped back to the real screen. |
| `type_text(session_id, text)` | |
| `key(session_id, combo)` | e.g. `ctrl+alt+del`, `win+r`. |
| `scroll(session_id, x, y, dy)` | |
| `wait(session_id, ms)` | Returns after the next `sync`. |
| `close_session(session_id)` | |
| `run_ssh(entry_id, command)` | Plain-text exec through the jump-host chain. Policy-checked. |

### AI-specific safety

- Dedicated `ai_agent` role and API keys. Admin endpoints are always off-limits.
- Folder modes: `observe` (screenshots only), `approve` (each input batch needs approval), `auto` (allowed, fully recorded).
- Recording is forced on, tagged `actor=ai:<key-name>`. Sessions show an "AI" badge, and a human can shadow or take over.
- Kill switch: an admin can end all AI sessions at once.
- Clipboard off by default. Rate limits on input and screenshots. Typed text is redacted in the audit log by default.

### Done when

- [ ] Claude connects to `/mcp`, lists connections, opens RDP to a test Windows VM, opens Notepad, types and saves a file (`auto`).
- [ ] `screenshot` matches the browser client view (pixel-diff test).
- [ ] In `approve` mode input waits for approval, and a denial reaches the agent as a tool error.
- [ ] Credentials never appear in any MCP response or log.

---

## Phase 4: database access proxy (separate service)

### Why a separate service

It never touches guacd, it speaks completely different protocols, and Go has the most mature building blocks for it. Teleport's database access, the closest existing product, is written in Go. It plugs into the core through the internal API, so policy, approval, credentials and audit stay in one place.

### Suggested stack (Go)

- PostgreSQL wire protocol: `jackc/pgx` (`pgproto3`). SQL parsing: `pganalyze/pg_query_go` (the real Postgres parser).
- MySQL/MariaDB wire protocol: `go-mysql-org/go-mysql` (server + client). SQL parsing: TiDB's parser or Vitess `sqlparser`.

### Flow

1. The user gets a **short-lived DB token** from the bastion (web UI or CLI), tied to their identity and the target database.
2. Their client (`psql`, `mysql`, DBeaver) connects to the proxy using that token as the password. TLS is required.
3. The proxy calls `authorize(connect)`, then fetches the real DB credentials from the core. The user never sees them.
4. Each statement is parsed and classified (read / write / DDL / admin), checked with `authorize(db_query)`, then either forwarded, blocked, or held for approval.
5. Every statement, its result status and row count go to the core's audit log.

### Example policies

- Read-only by default for everyone except DBAs.
- Block `DROP`, `TRUNCATE` and `ALTER` outside a change window.
- Block `DELETE` / `UPDATE` without `WHERE`.
- Require approval for any write on `prod` databases.
- Mask selected columns (e.g. emails, IDs) in results: later.

### Limits to document

- Multi-statement strings, stored procedures and `EXECUTE` of dynamic SQL can hide intent. Treat procedure calls as their own policy class (deny or approve by name).
- Prepared statements need protocol-level handling (Postgres extended query protocol, MySQL `COM_STMT_PREPARE`).

### Done when

- [ ] `psql` through the proxy with a bastion token works. A read-only user's `INSERT` is refused with a clear error.
- [ ] `DELETE FROM t;` without `WHERE` is blocked. With `WHERE` on prod it waits for approval.
- [ ] Every statement appears in the core audit log with the user's identity.

---

## Later

- Approval through Telegram / Slack, with a screenshot or query preview.
- OCR / accessibility text in `screenshot` output to save model tokens.
- AWS KMS KEK source.
- Kubernetes access proxy (same core API).
- Per-client branding for consultancy deployments.

## Open questions

1. Project name (needed for Phase 0).
2. Which upstream features to drop (VDI? web sessions? SPICE/Proxmox? NetBox sync?).
3. Internal API: HTTP + mTLS or gRPC?
4. Approval notification channels for v1.
5. MCP auth: API key only, or also OAuth for hosted MCP clients?

## Suggested first prompt for Claude Code

> Read `CLAUDE.md` and `docs/fork-design.md`. This is a hard fork; refactoring is allowed. Do Phase 0 first, using the project name `<name>`. Then start Phase 1: introduce the `SecretStore` trait and move the existing Vault I/O behind it with no behaviour change, and run the full test suite. Stop and show me the plan for splitting `vault.rs` before writing the SQLite backend.
