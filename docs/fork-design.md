# My Bastion: design

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

Proxies talk to the core over an **internal API**: **HTTP/JSON**, on a Unix socket when the proxy runs on the same host, or over **mTLS** on a private port when it runs elsewhere. Reasons: the core already runs axum, it's easy to debug with `curl`, there's no protobuf toolchain to maintain, and call volume is low. The API is described in an OpenAPI file so the Go proxy's client can be generated from it. gRPC can be revisited if the DB proxy ever needs streaming at high volume.

Endpoints:

- `authorize(subject, target, action)`, which returns allow, deny or pending (with an approval id)
- `await_approval(approval_id)`
- `fetch_credentials(target)`, which only hands credentials to registered proxies, never to users
- `audit(event)`

---

## Phase 0: hard-fork housekeeping

- Rename the project to **My Bastion**:
  - display name: `My Bastion`
  - binary / crate / systemd unit: `mybastion`
  - paths: `/opt/mybastion`, `/etc/mybastion`, `/var/lib/mybastion`
  - config: `mybastion.toml`
  - plus UI branding and page titles
- Add `NOTICE`, update `LICENSE` headers on changed files, rewrite `CLAUDE.md` for the new project.
- Point CI and release builds at this repo. Remove sol1-specific bits (commercial-support text, Docker Hub image name, NetBox/Knocknoc docs if not needed).
- **Keep the inherited features** (VDI, web-browser sessions, SPICE/Proxmox, NetBox sync), but make each one **off by default** behind its own config section. The decision on dropping them is deferred. Every policy and approval check must still cover them while they exist, and VDI in particular must stay off unless needed, because Docker socket access is root-equivalent.

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
- **Notifications:** web UI and **Telegram** in v1. Slack and email come later.
  - **Telegram bot:** sends each approval request to the approvers with **Approve / Deny** inline buttons (who, target, action, command or query, reason).
  - **Long polling**, so no inbound webhook endpoint is exposed.
  - **Account linking:** each approver links their Telegram account to their bastion user with a one-time code from the web UI. Only callbacks from linked accounts with approver rights count, and a requester can never approve their own request from Telegram either.
  - **High-risk requests** (e.g. prod DDL, break-glass) can be marked "web-only". Telegram then only notifies, and approval needs a fresh sign-in on the web UI.
  - **Updates:** the message is edited to show the final decision and approver, so the group chat doubles as a log.
  - Bot token is kept in the secret store.
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
src/mcp/server.rs     MCP over Streamable HTTP at /mcp (official Rust SDK `rmcp`)
src/mcp/auth.rs       API key + OAuth 2.1 bearer validation -> Identity (see "Authentication")
src/oauth/            authorization server endpoints (built on the existing OIDC login)
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

### Authentication: API key and OAuth (both supported)

There are two kinds of AI identity, and every MCP request resolves to one of them:

| | API key | OAuth 2.1 |
|---|---|---|
| Identity | Its own agent identity, e.g. `ai:nightly-patch` | A real user acting through an AI client, e.g. `steven via claude` |
| Use for | Unattended agents, scripts, scheduled jobs, Claude Code | People using an AI assistant interactively; hosted clients (Claude desktop / claude.ai connectors) |
| Permissions | What the key's `ai_agent` grants allow | The user's own permissions **intersected with** the AI policy (an AI can never do more than its user, and only in `ai_allowed` folders) |
| Audit `actor` | `ai:<key-name>` | `user:<email> via ai:<client-name>` |
| Revocation | Delete the key | Tokens expire on their own; revoke the grant or disable the user |

**API key** (built first, extends the existing `auth.rs` keys):
- `Authorization: Bearer <key>` on `/mcp`. Keys are SHA-256 hashed, with IP allowlists and expiry as today.
- New key type `ai_agent`, which can only call `/mcp`. Admin and REST endpoints refuse it.

**OAuth 2.1** (following the MCP authorization spec):
- `/mcp` returns `401` with a `WWW-Authenticate` header pointing at the protected resource metadata (`/.well-known/oauth-protected-resource`, RFC 9728).
- The bastion is its own authorization server (`/.well-known/oauth-authorization-server`, RFC 8414). The login step reuses the existing OIDC flow, so users sign in through the same identity provider (Authentik, Keycloak, Google, …).
- Authorization code flow with **PKCE required**. No implicit flow, no password grant.
- Client registration: dynamic client registration (RFC 7591) for MCP clients, with admin approval of each new client name, and/or a pre-registered client allowlist.
- A **consent screen** shows the client name, the folders it will reach and the mode (observe / approve / auto). Users can see and revoke their grants under "My AI access".
- Access tokens: short-lived (≤15 min), audience-bound to the `/mcp` resource (RFC 8707), scopes `mcp:read` (list + screenshot) and `mcp:act` (input, `run_ssh`). Refresh tokens are rotated on every use and revoked if one is reused.
- Token and grant tables live in SQLite, and tokens are stored hashed.
- Group membership is re-checked against the identity provider on refresh, so removing someone from a group cuts off their AI access within one token lifetime.

### AI-specific safety

- API-key agents get the dedicated `ai_agent` role. OAuth sessions are capped by both the user's role and the AI policy. Admin endpoints are always off-limits to MCP.
- Folder modes: `observe` (screenshots only), `approve` (each input batch needs approval), `auto` (allowed, fully recorded).
- Recording is forced on, tagged `actor=ai:<key-name>`. Sessions show an "AI" badge, and a human can shadow or take over.
- Kill switch: an admin can end all AI sessions at once.
- Clipboard off by default. Rate limits on input and screenshots. Typed text is redacted in the audit log by default.

### Done when

- [ ] Claude connects to `/mcp`, lists connections, opens RDP to a test Windows VM, opens Notepad, types and saves a file (`auto`).
- [ ] `screenshot` matches the browser client view (pixel-diff test).
- [ ] In `approve` mode input waits for approval, and a denial reaches the agent as a tool error.
- [ ] Credentials never appear in any MCP response or log.
- [ ] API key: an `ai_agent` key works on `/mcp` and is refused on every REST/admin endpoint.
- [ ] OAuth: Claude desktop adds the bastion as a custom connector, the user signs in via OIDC, approves consent, and the audit log shows `user:<email> via ai:<client>`.
- [ ] OAuth: a user without access to folder `prod` cannot reach it through the AI either; removing the user from a group blocks AI access once the token next refreshes.

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

1. ~~Project name~~ **Decided:** My Bastion (`mybastion`).
2. ~~Which upstream features to drop~~ **Deferred:** keep them, off by default (see Phase 0).
3. ~~Internal API~~ **Decided:** HTTP/JSON with OpenAPI; Unix socket locally, mTLS remotely.
4. ~~Approval notification channels for v1~~ **Decided:** web UI + Telegram.
5. ~~MCP auth: API key only, or also OAuth?~~ **Decided:** both. API key first, then OAuth 2.1 (see Phase 3 "Authentication").

## Suggested first prompt for Claude Code

> Read `CLAUDE.md` and `docs/fork-design.md`. This is a hard fork; refactoring is allowed. Do Phase 0 first, using the project name **My Bastion** (`mybastion`). Then start Phase 1: introduce the `SecretStore` trait and move the existing Vault I/O behind it with no behaviour change, and run the full test suite. Stop and show me the plan for splitting `vault.rs` before writing the SQLite backend.
