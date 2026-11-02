<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# Security

My Bastion is designed with a security-first approach. This document covers all security features and their implementation.

## TLS encryption

### Client-facing HTTPS

When `cert_path` and `key_path` are set in the `[tls]` section, My Bastion serves HTTPS using rustls (a modern, memory-safe TLS implementation). The install script generates a self-signed certificate by default.

```toml
[tls]
cert_path = "/etc/mybastion/tls/cert.pem"
key_path = "/etc/mybastion/tls/key.pem"
```

If you're behind a TLS-terminating reverse proxy (e.g. Traefik, HAProxy, nginx), you can omit `cert_path`/`key_path` and My Bastion will serve plain HTTP.

Generate a certificate:

```bash
mybastion generate-cert --hostname your-hostname.example.com --out-dir /etc/mybastion/tls
```

### guacd TLS

The connection between My Bastion and guacd can also be encrypted with TLS. When `guacd_cert_path` is set, My Bastion connects to guacd over TLS, trusting the specified certificate. This is independent of server HTTPS — you can use guacd TLS without serving HTTPS yourself.

**Full HTTPS + guacd TLS:**
```toml
[tls]
cert_path = "/etc/mybastion/tls/cert.pem"
key_path = "/etc/mybastion/tls/key.pem"
guacd_cert_path = "/etc/mybastion/tls/cert.pem"
```

**HTTP server + guacd TLS** (behind a reverse proxy):
```toml
[tls]
guacd_cert_path = "/etc/mybastion/tls/guacd-cert.pem"
```

guacd must be started with matching TLS flags:

```bash
guacd -b 127.0.0.1 -l 4822 -L info -f -C /etc/mybastion/tls/cert.pem -K /etc/mybastion/tls/key.pem
```

The install script configures both sides automatically.

## Network allowlists (SSRF protection)

All session targets are validated against CIDR allowlists before connections are made. A hostname passes when it resolves to at least one address inside an allowed range; addresses outside the allowlist are ignored, so a dual-stack host whose IPv6 address is not listed still works over IPv4.

```toml
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
rdp_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
vnc_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
web_allowed_networks = ["127.0.0.0/8", "::1/128"]
```

**Default: localhost only** — all four default to `["127.0.0.0/8", "::1/128"]`, preventing SSRF attacks out of the box.

What each list covers:

| List | Checked |
|------|---------|
| `ssh_allowed_networks` | SSH targets. For ad-hoc sessions from non-admins, also the first jump host (My Bastion dials it directly) and the SSH host-key probe |
| `rdp_allowed_networks` | RDP targets |
| `vnc_allowed_networks` | VNC and SPICE targets. For ad-hoc sessions from non-admins, also the Proxmox VE API URL and the SPICE proxy that Proxmox returns |
| `web_allowed_networks` | The host in a web session's starting URL |

Jump hosts and Proxmox clusters in connection entries, and in sessions created by admins, are not checked: admins configure those, and bastions and clusters commonly sit outside the target networks. The extra checks stop a poweruser from using an ad-hoc session or the host-key probe to reach arbitrary addresses.

SSH and VNC connections are made to the address that was checked rather than to the hostname, so a name cannot resolve to an allowed address for the check and to another address for the connection. RDP, SPICE and web sessions keep the hostname, because TLS certificate names and Kerberos need it; for those, a user who controls a hostname's DNS could in principle answer differently between the check and the connection. Where that matters, use IP addresses in connection entries and keep the RDP list narrow. Targets reached through jump hosts are resolved by the bastion, so only the first jump host is checked locally.

### Ad-hoc sessions from non-admins

A session a poweruser creates from their own request (**Connect to a host** (beside the search box on every page), `POST /api/addressbook/adhoc/connect`, `POST /api/sessions`, or `GET /api/connect` without an entry) is not a connection entry, so it gets none of an entry's trust. Besides the allowlist checks above, which cover every target the entry editor can name, SPICE, Proxmox VE and jump hosts included:

- Settings an admin makes on an entry are ignored when a poweruser sends them: recording attribution and rotation (`address_book_entry`, `max_recordings`), typescript recording, sharing, Wake-on-LAN, a Kerberos credential cache path on the My Bastion host, and a fixed VDI account (`container_username` / `container_password`). A VDI session always runs in the caller's own container, with the caller's own home directory.
- Site-wide recording cannot be switched off for the session, and a drive disabled in `[drive]` cannot be switched on.
- VDI CPU, memory and idle timeout are capped at the `[vdi]` defaults.

Admins (an admin API key included) and connection entries are trusted to set all of these.

An ad-hoc connection may use [credential variables](credential-variables.md), but only the caller's own: they are resolved server side from the caller's My Credentials, and the values are never sent to the browser. [Folder default credentials](credential-variables.md#folder-default-credentials) never apply to one, since they belong to a folder and an ad-hoc connection has none.

## Authentication

My Bastion supports two parallel authentication paths. See [Roles and Access Control](roles-and-access-control.md) for the full role system.

### API key authentication

- Keys are 256-bit random values (64 hex characters)
- Stored as SHA-256 hashes in SQLite — the plaintext key is only shown once at creation
- Supported in `Authorization: Bearer <key>`, `X-API-Key: <key>` headers, and `?key=<key>` query parameter (WebSocket fallback)
- Optional IP allowlist (comma-separated CIDR ranges)
- Optional expiry timestamp (ISO 8601)
- API key admins always have full admin-level access

### OIDC session authentication

- Session tokens are 256-bit random values, stored in SQLite with a TTL
- Cookie: `mybastion_session` with `HttpOnly`, `Secure` (when TLS enabled), `SameSite=Lax`
- Configurable TTL (default: 24 hours)
- PKCE and nonce validation on every login flow
- Works with any OIDC provider (Authentik, Keycloak, Okta, Azure AD, Google, etc.)

### User API token authentication

User API tokens provide OIDC users with long-lived API credentials for automation and scripting, without sharing their OIDC session or admin API keys.

**Token format and storage:**

- Tokens are 60 hex characters with a `mbt_` prefix (e.g., `mbt_a1b2c3...`)
- Stored as SHA-256 hashes in SQLite — the plaintext token is shown once at creation and cannot be retrieved
- The `mbt_` prefix allows secret scanners and log monitoring tools to identify leaked tokens
- Token validation uses constant-time hash comparison (SHA-256 matching via SQLite query) to prevent timing attacks

**Effective role computation:**

When a user API token authenticates, the effective role is computed as `min(user_current_role, token_max_role)`. This means:
- If an admin demotes a user from poweruser to operator, all their existing tokens are immediately restricted to operator-level access
- The `max_role` cap on a token cannot grant more access than the user currently has
- Role evaluation happens at authentication time, not at token creation time

**Token lifecycle security:**

| Control | Implementation |
|---------|---------------|
| Creation | poweruser+ self-service; admin can create for any user |
| Revocation | immediate; hash deleted from database |
| Expiry | optional ISO 8601 timestamp, checked at authentication time |
| Disabled users | tokens for disabled users are automatically rejected |
| User deletion | all tokens cascade-deleted when user is removed |
| Cleanup | expired tokens are purged hourly by background task |

**Attack surface and mitigations:**

| Threat | Mitigation |
|--------|-----------|
| Token theft / leakage | `mbt_` prefix enables automated secret scanning; short token lifetime recommended; tokens can be revoked immediately |
| Privilege escalation via token | effective role is always `min(user_role, max_role)` — demoting the user restricts all their tokens |
| Brute-force token guessing | 240 bits of entropy (60 hex chars), which makes guessing infeasible regardless of rate limiting |
| Token abuse after user offboarding | user deletion cascade-deletes all tokens; disabling a user blocks all their tokens |
| Lateral movement from stolen token | tokens inherit the user's identity — all actions are logged with the user's email and client IP |
| Audit evasion | all token create/revoke/use events are logged in `token_audit_log` with IP addresses |

**Audit logging:**

All token operations are recorded in a dedicated `token_audit_log` table:
- **created** — token creation (by self-service or admin), with max_role and expiry details
- **revoked** — token revocation (by owner or admin), logged with revoker identity
- **admin_revoked** — admin revocation of another user's token

Audit logs are retained for 90 days and cleaned up hourly. Admins can view the log via the Admin UI or `GET /api/admin/token-audit`.

## Rate limiting

The OIDC login and callback routes are always rate limited, at 1 request per second per client IP with a burst of 20.

Setting `rate_limit = true` adds per-IP limits to the rest of the application. It is off by default, since deployments behind a reverse proxy usually limit there:

| Endpoint group | Rate | Burst |
|---------------|------|-------|
| API routes (including requests that fail authentication) | 20/sec | 100 |
| Session creation | 2/sec | 10 |
| WebSocket connections | 5/sec | 50 |

Every limiter keys on the resolved client IP. Forwarded headers are honoured only from `trusted_proxies`, so a client cannot get a fresh allowance by sending a different `X-Forwarded-For` on each request. Behind a proxy, set `trusted_proxies`, or every user shares the proxy's allowance.

## Security headers

All responses include the following headers:

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data: blob:; frame-ancestors 'none'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` (when TLS enabled) |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

The one exception to the framing headers is described below.

### Framing and clickjacking

Clickjacking is when another site loads a page in an invisible frame and lines it up under something harmless, so a visitor's clicks and keystrokes land on the framed page while they are logged in. For most applications that means a stray click on a button. For My Bastion it would be worse: a framed **live session** would pass the visitor's keystrokes and clicks to a remote server. So by default no My Bastion page can be framed by anyone, including My Bastion itself (`frame-ancestors 'none'`, `X-Frame-Options: DENY`).

**The exception: fullscreen on connect.** A browser only lets the tab that received the click go fullscreen. To open a session fullscreen on the Connect click, rather than in a new tab that needs a second click, the Connections page puts its own tab into fullscreen and loads the session in a frame inside it. For that one case, and only for it, the session client page is served with `frame-ancestors 'self'` and `X-Frame-Options: SAMEORIGIN`:

- Only the client page of a session opened from a saved entry with **Open in fullscreen on connect** turned on. That is an admin setting on the entry, so framing is opt-in per entry: with no such entries, nothing in My Bastion can be framed.
- Only by pages on the My Bastion origin. Every other site is still refused, exactly as for every other page.
- Never an ad-hoc session (whatever its request says), a normal entry's session, an unknown or ended session, or any other page (Connections, Admin, Tokens, Recordings and the rest).
- Someone joining such a session through a share link loads the same client page, so it is frameable by the My Bastion origin too.

The **⧉** (new window) button never uses a frame.

We weighed four approaches before settling on this one:

| Approach | For | Against |
|---|---|---|
| Deny all framing | Nothing to reason about | Fullscreen on connect needs a new tab and a second click, and the session resizes after it starts |
| Allow same-origin framing for every page | One simple rule | Every page, including Admin and Tokens, becomes frameable by any page on the origin, though only the client needs it |
| Allow it for the client page only | Management pages stay unframeable | Every session's client is frameable, though only fullscreen entries need it |
| Allow it per session, for fullscreen-on-connect entries only (chosen) | Smallest exposure; off unless an admin turns it on for an entry | One more rule in the server |

**What is left.** Same-origin framing is only a risk if something other than My Bastion can put a page on the My Bastion origin. Nothing does today: files downloaded from a session are saved to disk, never opened as pages; recordings are played by My Bastion's own script; web sessions are streamed as pixels, not rendered. An XSS flaw would already allow anything framing could. The case to avoid is a **shared origin**: if My Bastion is served at `/` on the same host and port as another application (for example another app at `/grafana/` behind the same reverse proxy), that application's pages count as the same origin. Give My Bastion its own hostname. To rule framing out entirely, leave **Open in fullscreen on connect** off on every entry.

## Audit logging

My Bastion logs security-relevant events via the `tracing` framework:

- Authentication failures (API key, user token, and OIDC)
- Session creation, connection, and termination
- WebSocket connect/disconnect events
- Admin operations (user management, key rotation)
- Client IP addresses (resolved via trusted proxies)

Additionally, user API token operations are logged to a persistent `token_audit_log` database table (see [User API token authentication](#user-api-token-authentication) above). This provides a queryable audit trail for token creation, revocation, and usage — retained for 90 days.

## Session security

- **Pending timeout** — sessions that don't receive a WebSocket connection within 60 seconds (configurable) are automatically cleaned up
- **Maximum duration** — active sessions are terminated after 8 hours (configurable) to prevent abandoned sessions
- **Session ownership** — non-admin users can only terminate their own sessions. Only the user who created a session can make its first (owner) connection; admins cannot claim another user's pending session, and watch live sessions through shadow tokens instead
- **Share tokens** — each shareable session has two share URLs, one view-only and one with keyboard and mouse control, valid until the session ends. View-only is enforced by guacd, which ignores input from a view-only participant

## Clipboard control

Clipboard copy (server → client) and paste (client → server) can be independently disabled per connections entry. This uses guacd's native `disable-copy` and `disable-paste` parameters, which work for all session types (SSH, RDP, VNC, and web browser sessions).

Use cases:
- **Disable copy** — prevents users from copying data out of sensitive sessions (data loss prevention)
- **Disable paste** — prevents users from pasting potentially malicious content into remote sessions
- **Disable both** — fully isolates the clipboard between the local browser and the remote session

## Web session hardening

Web browser sessions (headless Chromium on Xvnc) include several security layers:

### Chromium managed policy

A managed policy is installed at `/etc/chromium/policies/managed/mybastion.json` that restricts Chromium's capabilities. **This policy is global** — it affects all Chromium instances on the machine, not just My Bastion sessions. Do not install My Bastion on a machine where you want to use Chromium for normal browsing.

Policies applied:

| Policy | Value | Effect |
|--------|-------|--------|
| `AllowFileSelectionDialogs` | `false` | Blocks file open/save dialogs (prevents filesystem browsing) |
| `PasswordManagerEnabled` | `true` | Allows autofill to work |
| `ImportSavedPasswords` | `false` | Blocks password import UI (which exposes a file browser) |
| `DeveloperToolsAvailability` | `0` | DevTools/CDP allowed (needed for login scripts). Users can't access DevTools UI — `chrome://*` is in URLBlocklist. |
| `DownloadRestrictions` | `3` | Blocks all downloads |
| `PrintingEnabled` | `false` | Disables printing |
| `EditBookmarksEnabled` | `false` | Prevents bookmark editing |
| `BrowserSignin` | `0` | Disables browser sign-in |
| `SyncDisabled` | `true` | Disables Chrome Sync |
| `ExtensionInstallBlocklist` | `["*"]` | Blocks all extension installation |
| `URLBlocklist` | `file://*`, `chrome://*`, etc. | Blocks dangerous URL schemes |

### Per-entry domain allowlisting

Connections entries can specify an `allowed_domains` list. When set, Chromium can only reach those domains (plus localhost). All other domains are blocked via Chromium's `--host-rules` flag, which prevents DNS resolution for non-allowed hosts.

Subdomains are automatically included — adding `example.com` allows `*.example.com` as well.

**Important:** The `allowed_domains` field restricts which domains the browser can reach. This is separate from the server-side `web_allowed_networks` CIDR allowlist, which controls which target hosts My Bastion will connect to when creating sessions. Both can be active simultaneously:

- `web_allowed_networks` — server-side CIDR filter applied at session creation time (controls what the My Bastion server is allowed to connect to)
- `allowed_domains` — client-side DNS restriction applied inside Chromium at runtime (controls what sites the user can navigate to within the browser session)

### Profile isolation

Each web session gets a unique Chromium profile directory (UUID-based path in `/tmp/`). The profile is created fresh before launch and deleted when the session ends. Credentials stored in the autofill database exist only for the duration of the session.

### Sandbox

Chromium runs with its normal sandbox enabled. The `--no-sandbox` flag is not used. Chromium isolates its renderers in their own user, PID and network namespaces, and falls back to the SUID `chrome-sandbox` helper only where it cannot create them. If neither can start, Chromium refuses to run and the web session fails with an error that names the cause; it never runs unsandboxed.

Under Docker, the default seccomp profile blocks these namespaces. Run the container with the narrow profile shipped in `contrib/docker/seccomp-chromium.json` rather than `seccomp=unconfined`; see [Web sessions: Running under Docker](web-sessions.md#running-under-docker).

## File permissions

| Path | Mode | Owner |
|------|------|-------|
| Drive directories | 0750 (rwxr-x---) | mybastion:mybastion |
| LUKS device file | 0600 (rw-------) | mybastion:mybastion |
| Recording files | 0640 (rw-r-----) | mybastion:mybastion |
| Recording directory | 0750 (rwxr-x---) | mybastion:mybastion |
| TLS private key | 0600 (rw-------) | mybastion:mybastion |

## SQL injection protection

All database queries use parameterised statements via rusqlite's `params!` macro. No string concatenation is used in SQL queries.

## Path traversal protection

Recording file access validates filenames to block path traversal (`/`, `\`, `..`). The Vault connections also validates entry and folder names (alphanumeric, hyphens, underscores, dots only; length 1-64).

## XSS protection

The web UI uses DOM API methods (`createElement`, `textContent`, `appendChild`) instead of `innerHTML` for user-supplied content. Combined with the CSP header, this prevents cross-site scripting.

## Body size limits

HTTP request bodies are limited to 64KB to prevent memory exhaustion attacks.

## Trusted proxy support

When `trusted_proxies` is configured, My Bastion extracts the real client IP from the `X-Forwarded-For` header for connections originating from trusted proxy CIDRs. This ensures correct IP allowlists, rate limiting and audit logging behind reverse proxies.

The header is read from the right, skipping addresses that are themselves trusted proxies. The leftmost entry is never trusted on its own, because a proxy that appends to an incoming header passes along whatever the client put there.

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Credential handling

- **Vault credentials** — connections entries are read server-side from Vault. Connection passwords and private keys are never sent to the browser.
- **SSH tunnel credentials** — jump host passwords and private keys are stored in Vault alongside the connections entry. They are read server-side when establishing the tunnel chain and are never sent to the browser. For ad-hoc connections, jump host credentials are provided in the request and exist only in memory during tunnel setup.
- **API keys** — only the SHA-256 hash is stored. The plaintext key is shown once at creation and cannot be retrieved.
- **User API tokens** — same SHA-256 hash storage as admin API keys. The `mbt_` prefix enables secret scanning. Plaintext shown once at creation only.
- **OIDC client secret** — can be provided via `OIDC_CLIENT_SECRET` environment variable instead of the config file.
- **LUKS encryption key** — stored in Vault, passed to cryptsetup via stdin (never on the command line or on disk).
- **Ephemeral SSH keys** — the private key exists only in memory during the guacd handshake. It is never stored on disk or returned by the API.
