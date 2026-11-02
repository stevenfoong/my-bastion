# rustguac fork: design

Base: `sol1/rustguac` @ main (21 Oct 2026), Apache-2.0
Status: draft. Phases are built in order, and each phase has to be shippable on its own.

## Goals

1. **SQLite secret store.** Run without Vault/OpenBao. Connections, folders and credentials live in SQLite, encrypted at rest.
2. **MCP endpoint.** AI agents can open RDP/VNC sessions and work them like a person (see the screen, click, type), under the same access rules, recording and audit as human users.
3. **Human approval.** Nothing the AI does on a real machine happens without a policy allowing it, and optionally a person approving it.

## Not goals

- Changing guacd (C) or the protocol libraries. guacd stays exactly as upstream ships it.
- Rewriting the web UI.
- Feature parity with Vault (multi-backend split, Vault auth methods, token renewal).

## Fork rules (to keep upstream merges cheap)

- New code goes in **new files**: `src/storage/`, `src/mcp/`, `src/render/`. Changes to existing files stay small and mechanical.
- Merge `upstream/main` every 1–2 weeks.
- Phase 1 should be written so it can be offered upstream. Open an issue with sol1 before starting it.
- Fork-specific config goes under new TOML sections only (`[storage]`, `[mcp]`), never by changing the meaning of an existing key.

---

## Phase 1: SQLite secret store

### What Vault holds today

SQLite (`src/db.rs`, rusqlite) already holds users, auth sessions, API tokens, session history and audit logs. Vault (`src/vault.rs`) holds:

| Data | Vault path (under `<mount>/<base_path>`) |
|---|---|
| Connection entries, including credentials (`AddressBookEntry`) | `<scope>/<folder>/<entry>` |
| Folder config / ACL (`FolderConfig`) | `<scope>/<folder>/.config` |
| Folder default credentials | per-folder defaults key |
| Per-user credentials / credential variables | `users/<key>` |
| LUKS drive key | arbitrary `kv_path` via `read_kv_field` |

Scopes are `shared` and `instance`.

### Key finding

`vault.rs` is about 3,400 lines, but nearly all of it is rustguac logic: ACLs, folder defaults, credential-variable resolution, entry normalisation. The actual Vault I/O is a small set of KV v2 operations (get / put / put-if-absent / list / delete on a path, holding one JSON document). **Replace the I/O layer and keep the logic.**

### Design

```
src/storage/mod.rs      trait SecretStore
src/storage/vault.rs    impl over the existing HTTP code (moved, unchanged)
src/storage/sqlite.rs   new impl
src/storage/crypto.rs   envelope encryption
```

```rust
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, path: &str) -> Result<Option<Doc>, StoreError>;      // Doc = { data: serde_json::Value, version: u64 }
    async fn put(&self, path: &str, data: &Value, cas: Option<u64>) -> Result<u64, StoreError>; // cas Some(0) = create-if-absent
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;   // Vault semantics: children, folders end in "/"
    async fn delete(&self, path: &str) -> Result<(), StoreError>;
    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError>;   // folder delete
    fn is_available(&self) -> bool;                                          // sqlite: always true
}
```

`VaultClient` becomes a client that holds `Arc<dyn SecretStore>` (renaming it can wait; it keeps the diff in `api.rs` small). Its public methods (`get_entry`, `list_subfolders`, `get_folder_config`, …) keep their signatures. Only their bodies change from building URLs to calling the trait with a logical path.

### SQLite schema (new file, e.g. `secrets.db`, kept separate from the main db)

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

- `list(prefix)`: `WHERE path LIKE prefix || '%'`, then reduce to the direct children in Rust (matches Vault's LIST).
- Check-and-set: one transaction, `UPDATE … WHERE path=? AND version=?`, or `INSERT` for cas=0. A conflict returns the same error variant the Vault path uses today.
- WAL mode, `busy_timeout`, file mode 0600, owned by the `rustguac` user.

### Encryption

- **Envelope:** a random 256-bit data key (DEK) encrypts the rows. A key-encryption key (KEK) wraps the DEK, and the wrapped DEK sits in `secrets_meta`.
- **Where the KEK comes from** (`[storage] kek_source`):
  - `file:/etc/rustguac/kek` (0400): the default
  - `systemd-creds:rustguac-kek`
  - `env:RUSTGUAC_KEK`
  - `aws-kms:<key-arn>`: optional, behind a later feature flag
- AAD binds each ciphertext to its path and version, so rows can't be swapped or rolled back.
- Key rotation is a CLI command (`rustguac rotate-kek`) that re-wraps the DEK. Rows are not re-encrypted.
- Plaintext lives only in memory and is zeroized (`zeroize` crate) where practical.
- **Threat model:** this protects stolen DB files and backups. It does *not* protect against a compromised host running rustguac. That limit is the same as Vault with an auto-unseal on the same host. Write it in the docs.

### Other changes

- **LUKS key:** `read_kv_field` maps to `secrets` like everything else. Seed it with a CLI command: `rustguac secret put luks/drive key=@/path`.
- **"Vault connected?" checks** in `api.rs` / UI: route them through `is_available()`. Connections UI always on in SQLite mode.
- **Multi-Vault split** (`VaultBackends.shared/local`): in SQLite mode all three cells point to the same store.
- **Migration CLI:** `rustguac storage migrate --from vault --to sqlite` (and the reverse), reading every path through one trait impl and writing it through the other.
- **Config:**

```toml
[storage]
backend = "sqlite"            # or "vault" (default, upstream behaviour)
path = "/var/lib/rustguac/secrets.db"
kek_source = "file:/etc/rustguac/kek"
```

### Done when

- [ ] Existing test suite passes with `backend = "vault"` (no behaviour change).
- [ ] Same suite passes against an SQLite backend (parameterise the tests that use the Vault mock).
- [ ] Round-trip migration Vault → SQLite → Vault produces identical documents.
- [ ] A tampered row (changed path, version or ciphertext) fails to decrypt.
- [ ] Fresh install with no Vault: connections UI works end to end (create folder, create RDP entry, connect).

---

## Phase 2: MCP endpoint

### What exists already

- REST API to create a session headlessly (`POST /api/sessions`) plus single-use WebSocket tickets (`POST /api/ws-ticket`).
- Roles, folder ACLs, CIDR allowlists, per-entry clipboard policy, session recording, share/shadow tokens.

### Constraints from the code (important)

- The **first** WebSocket attach is the *owner* connection and must come from the session's creator.
- guacd drops a session if no client attaches within about 15 seconds.
- The server never holds a picture of the screen. Thumbnails are drawn in the browser and uploaded.

So the MCP server has to **be the Guacamole client**: create the session and attach as owner within seconds.

### Components

```
src/mcp/server.rs     MCP over Streamable HTTP at /mcp (axum route), auth = API key
src/mcp/tools.rs      tool definitions + policy checks
src/render/mod.rs     headless Guacamole client: parse instructions -> framebuffer
src/render/layers.rs  layers, compositing (default layer 0 + buffers/negative layers)
```

**Headless renderer (`src/render`)** attaches to the session's guacd stream in-process, parses instructions with the existing `protocol.rs` parser, and keeps an RGBA framebuffer.

Minimum instruction set for a usable screenshot:
- `size`, `img` + `blob` + `end` (PNG/JPEG/WebP), `copy`, `rect` + `cfill`, `cursor`, `sync`, `dispose`
- layer handling for layer 0 and off-screen buffers

Output goes through `ack` / `sync` replies so guacd keeps streaming. Use the `image` crate for decoding.

The fallback if the renderer stalls is a headless Chromium (Playwright) opening `client_url?ticket=…` and taking screenshots. That's good enough for a demo, not for production.

### Tools

| Tool | Notes |
|---|---|
| `list_connections(folder?)` | Only entries the API key's identity can see, and only from folders flagged `ai_allowed`. Never returns credentials. |
| `open_session(entry_id, width?, height?)` | Creates the session, attaches the renderer as owner, returns `session_id`. |
| `screenshot(session_id, scale?)` | PNG. Default downscale to ≤1280 px wide (model token cost). |
| `click(session_id, x, y, button?, double?)` | Coordinates are in screenshot space; the server maps them back. |
| `type_text(session_id, text)` | Key events per character; respects the keyboard layout. |
| `key(session_id, combo)` | e.g. `ctrl+alt+del`, `win+r`. |
| `scroll(session_id, x, y, dy)` | |
| `wait(session_id, ms)` | Lets the screen settle; returns after the next `sync`. |
| `close_session(session_id)` | |
| `run_ssh(entry_id, command)` | *SSH only.* Plain-text exec over the same jump-host chain. No screenshots for terminals. |

### Safety model

- **Separate identity:** MCP uses dedicated API keys with a new role `ai_agent` (below `operator`). Admin endpoints are always off-limits.
- **Opt-in folders:** an entry is reachable only if its folder config has `ai_allowed = true`.
- **Modes per folder:**
  - `observe`: screenshots only, all input refused
  - `approve`: each input batch waits for a human approval in the UI
  - `auto`: input allowed, everything recorded
- **Always recorded:** recording is forced on for AI sessions regardless of the entry setting, and tagged `actor=ai:<key-name>`.
- **Live watch:** the session appears in Active Sessions with an "AI" badge, and a human can shadow or take over through the existing share/shadow tokens.
- **Kill switch:** an admin can end all AI sessions at once (`DELETE /api/mcp/sessions`).
- **Clipboard:** follows per-entry clipboard policy; default *off* for AI.
- **Rate limits:** per key, on input events and on screenshots.
- **Audit:** every tool call is written to `addressbook_audit_log`/new `mcp_audit_log` with the arguments (text input redacted by default).

### Config

```toml
[mcp]
enabled = true
path = "/mcp"
max_sessions_per_key = 2
default_mode = "approve"      # observe | approve | auto
screenshot_max_width = 1280
idle_timeout_secs = 600
```

### Done when

- [ ] Claude (Claude Code or desktop) connects to `/mcp`, lists connections and opens an RDP session to a test Windows VM.
- [ ] `screenshot` matches what the browser client shows (pixel-diff test against a recorded session).
- [ ] The agent can open Notepad, type text and save a file, with `mode = auto`.
- [ ] In `approve` mode, input is held until approved in the UI; a denial reaches the agent as a tool error.
- [ ] Credentials never appear in any MCP response or log.

---

## Phase 3: later

- Approval UI polish: batch preview showing the screenshot plus the planned actions.
- Optional OCR / accessibility text in `screenshot` output so the agent uses fewer image tokens.
- AWS KMS KEK source.
- Per-client branding (for consultancy deployments).

## Open questions

1. Does sol1 want the `SecretStore` trait upstream? This decides how much of Phase 1 lives only in the fork.
2. Renderer: reuse `protocol.rs` as-is, or does it need a streaming/blob-aware extension?
3. Approval channel: UI only, or also Telegram/Slack webhooks for remote approval?
4. MCP transport auth: API key only, or also OAuth for hosted MCP clients?

## Suggested first prompt for Claude Code

> Read `CLAUDE.md` and `docs/fork-design.md`. Implement Phase 1 only. Start by introducing the `SecretStore` trait and moving the existing Vault HTTP I/O behind it with **no behaviour change**; run the full test suite. Stop and show me the diff before writing the SQLite backend.
