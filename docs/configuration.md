<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# Configuration Reference

My Bastion reads a TOML configuration file. All settings have sensible defaults and are optional.

```bash
mybastion --config /etc/mybastion/mybastion.toml serve
```

See `mybastion.example.toml` for a fully commented reference.

## Server settings

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `127.0.0.1:8089` | Address and port to listen on |
| `guacd_addr` | `127.0.0.1:4822` | guacd TCP address |
| `recording_path` | `./recordings` | Session recording directory |
| `static_path` | `./static` | Static web files directory |
| `db_path` | `./mybastion.db` | SQLite database path |
| `site_title` | `mybastion` | Browser tab and page header title |

## Session timeouts

| Key | Default | Description |
|-----|---------|-------------|
| `session_pending_timeout_secs` | `60` | Seconds before pending sessions expire |
| `session_max_duration_secs` | `28800` (8h) | Maximum active session duration |
| `auth_session_ttl_secs` | `86400` (24h) | OIDC auth session cookie TTL |

## Browser session settings

| Key | Default | Description |
|-----|---------|-------------|
| `xvnc_path` | `Xvnc` | Path to Xvnc binary |
| `chromium_path` | `chromium` | Path to Chromium binary |
| `display_range_start` | `100` | First X display number |
| `display_range_end` | `199` | Last X display number |
| `cdp_port_range_start` | `9200` | First Chrome DevTools Protocol port (for login scripts) |
| `cdp_port_range_end` | `9299` | Last CDP port |
| `login_scripts_dir` | `/opt/mybastion/scripts` | Directory containing login scripts |
| `login_script_timeout_secs` | `120` | Maximum runtime for login scripts before they are killed |

## Connection allowlists

CIDR ranges controlling which hosts sessions can connect to. All default to localhost only.

**Important:** These are top-level TOML keys and must appear *before* any `[section]` header. Keys placed after a section header (e.g., `[tls]`) are scoped to that section and will be silently ignored.

| Key | Default | Description |
|-----|---------|-------------|
| `ssh_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed SSH targets (plus first jump hosts and host-key probes for non-admin ad-hoc use) |
| `rdp_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed RDP targets |
| `vnc_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed VNC and SPICE targets (plus Proxmox VE API and SPICE proxy hosts for non-admin ad-hoc use; see [SPICE and Proxmox VE](spice-and-proxmox.md#network-allowlists)) |
| `web_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed web session URL hosts |

## Trusted proxies

| Key | Default | Description |
|-----|---------|-------------|
| `trusted_proxies` | `[]` | CIDRs of reverse proxies whose X-Forwarded-For to trust (read right to left, skipping trusted hops) |
| `rate_limit` | `false` | Enable API rate limiting. Not needed when behind a rate-limiting reverse proxy. |
| `session_history_retention_days` | `90` | Days to keep session history in the database. 0 = keep forever. |

## `[tls]` section

Configures TLS for the web server and/or the guacd connection. There is no `enabled` toggle — the presence of the relevant fields controls behaviour:

- **Server HTTPS**: Provide both `cert_path` and `key_path` to serve HTTPS. Omit them to serve plain HTTP (useful behind a TLS-terminating reverse proxy like Traefik/HAProxy).
- **guacd TLS**: Provide `guacd_cert_path` to connect to guacd over TLS. This is independent of server HTTPS.

All fields are optional. The `[tls]` section can contain any combination.

| Key | Description |
|-----|-------------|
| `cert_path` | HTTPS certificate path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `key_path` | HTTPS private key path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `guacd_cert_path` | Trust certificate for guacd TLS connection (independent of server HTTPS) |

**Examples:**

HTTPS + guacd TLS (self-hosted):
```toml
[tls]
cert_path = "/etc/mybastion/tls/cert.pem"
key_path = "/etc/mybastion/tls/key.pem"
guacd_cert_path = "/etc/mybastion/tls/cert.pem"
```

HTTP server + guacd TLS (behind a reverse proxy):
```toml
[tls]
guacd_cert_path = "/etc/mybastion/tls/guacd-cert.pem"
```

HTTPS only (guacd on localhost, no TLS needed):
```toml
[tls]
cert_path = "/etc/mybastion/tls/cert.pem"
key_path = "/etc/mybastion/tls/key.pem"
```

## `[oidc]` section

Enables OpenID Connect authentication. When configured, the web UI shows a login button. API key auth continues to work alongside OIDC.

| Key | Default | Description |
|-----|---------|-------------|
| `issuer_url` | — | OIDC provider issuer URL (required) |
| `client_id` | — | OIDC client ID (required) |
| `client_secret` | — | OIDC client secret (or use `OIDC_CLIENT_SECRET` env var) |
| `redirect_uri` | — | Redirect URI: `https://your-host/auth/callback` (required) |
| `default_role` | `operator` | Role assigned to new users on first login |
| `auto_create_users` | `true` | Create an account on first OIDC login. When `false`, only users already in the database can log in; add them with `mybastion add-user`, `POST /api/users` or the Admin page. See [Only users you have added](roles-and-access-control.md#only-users-you-have-added) |
| `groups_claim` | `groups` | JWT claim name containing group memberships |
| `extra_scopes` | `[]` | Additional OIDC scopes to request |
| `ca_cert` | — | Path to CA certificate (PEM) for verifying the OIDC provider |
| `tls_skip_verify` | `false` | Skip TLS verification (debugging only — exposes secrets to MITM) |

**Note:** `issuer_url` must match the discovered issuer URI **exactly**, including default ports and trailing slashes. For example, `https://idp.example.com/` and `https://idp.example.com` may be treated as different issuers. Check your provider's `.well-known/openid-configuration` for the canonical value.

## `[vault]` section

Enables the Vault-backed connections. Uses AppRole by default, requiring the
`VAULT_SECRET_ID` environment variable. Configure `[vault.jwt_auth]` to use a
workload JWT instead; JWT mode does not require an AppRole role ID or SecretID.

| Key | Default | Description |
|-----|---------|-------------|
| `addr` | — | Vault server address (required) |
| `role_id` | — | AppRole role ID (required unless `jwt_auth` is configured) |
| `mount` | `secret` | KV v2 mount path |
| `base_path` | `mybastion` | Base path under the mount |
| `namespace` | — | Vault Enterprise / OpenBao namespace |
| `instance_name` | — | Instance name for instance-scoped entries |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (dev only) |
| `ca_cert` | — | Path to custom CA certificate (PEM) for verifying the Vault server |
| `client_cert` | — | Path to client certificate (PEM) for mTLS |
| `client_key` | — | Path to client private key (PEM) for mTLS (required if `client_cert` is set) |

### Workload JWT authentication

```toml
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "mybastion"

[vault.jwt_auth]
mount = "workload-jwt"
role = "mybastion"
path = "/var/run/secrets/vault/token"
```

| Key | Default | Description |
|-----|---------|-------------|
| `mount` | (required) | The JWT auth method's mount, not the KV mount, e.g. `jwt` or `auth-k8s/jwt` |
| `role` | (required) | The role on that mount |
| `path` | | A file holding the JWT |
| `token_command` | | A program and its arguments that print the JWT, and nothing else, on stdout. Run directly, never through a shell; its output is never logged |
| `token_command_timeout_secs` | `10` | How long `token_command` may run before it is killed |

Give exactly one of `path` and `token_command`. The token is fetched again on
every login and reauthentication, so a rotated token is always the one used.
JWT mode takes precedence over AppRole and never falls back to it when the token
is missing, empty or rejected. The `import-guacamole` and
`storage migrate` commands log in the same way.
Use this with Vault/OpenBao JWT auth configured to verify the token issuer,
audience and exact workload identity. This is separate from users' OIDC login.

See [Integrations](integrations.md#workload-jwt-authentication) for Kubernetes,
Nomad, SPIRE and cloud VM setups.

## `[storage]` section

Keeps connections, folder configs and credential variables in an encrypted
SQLite file instead of Vault. Without this section, or with
`backend = "vault"`, they live in `[vault]` as before. With
`backend = "sqlite"`, the `[vault*]` sections are not used at runtime, and
one store serves both the shared and instance scopes.

```toml
[storage]
backend = "sqlite"
path = "/var/lib/mybastion/secrets.db"
kek_source = "file:/etc/mybastion/kek"
# instance_name = "prod-1"   # enables the instance scope
```

| Key | Default | Description |
|-----|---------|-------------|
| `backend` | `vault` | `vault` or `sqlite` |
| `path` | `/var/lib/mybastion/secrets.db` | The secrets file, kept apart from `db_path`. Created with mode 0600. |
| `kek_source` | `file:/etc/mybastion/kek` | Where the key-encryption key is: `file:<path>`, `env:<VAR>`, or `systemd-creds:<name>` (read from `$CREDENTIALS_DIRECTORY`, for `LoadCredentialEncrypted=`). 32 bytes as 64 hex digits or base64. |
| `base_path` | `mybastion` | Prefix of the address-book paths, as `[vault] base_path` |
| `instance_name` | — | Enables the instance scope, as `[vault] instance_name` |

Create a KEK before the first start:

```bash
sudo sh -c 'umask 277; openssl rand -hex 32 > /etc/mybastion/kek'
sudo chown mybastion /etc/mybastion/kek
```

**Encryption.** A random data key encrypts every row with AES-256-GCM. The
KEK wraps the data key, and only the wrapped key is stored in the file. Each
row is bound to its path and version, so a row copied to another path or
renumbered fails to decrypt instead of returning someone else's secret.

**What this protects.** A copied `secrets.db` or a backup of it is unreadable
without the KEK. It does **not** protect against someone who controls the
host running mybastion: that host has to read the KEK to start. This is the
same limit as Vault with an auto-unseal key on the same host. Keep the KEK
out of the backups of `secrets.db`. Replacing the whole file with an older
copy (rolling back every secret together) is not detected.

**Tools:**

- `mybastion storage migrate --from vault --to sqlite --dry-run`: copy
  everything under `base_path` between backends (either direction; existing
  secrets are kept unless `--overwrite`). Add `--path <kv path>` for secrets
  outside it, such as the drive's `luks_key_path`. Both `[vault]` and
  `[storage]` must be in the config; switch `backend` and restart afterwards.
- `mybastion storage rotate-kek --new-kek-source file:/etc/mybastion/kek.new`:
  re-wrap the data key under a new KEK (rows are not re-encrypted, and a
  running server keeps working), then point `kek_source` at the new one.
- `mybastion storage put mybastion/luks key=@/root/luks.key`: write one secret,
  e.g. the LUKS key that `[drive] luks_key_path` names.

## `[drive]` section

Enables file transfer for RDP (drive redirection) and SSH (SFTP).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable drive/file transfer |
| `drive_path` | `./drives` | Base directory for per-session storage |
| `drive_name` | `Shared Drive` | Name shown in remote RDP session |
| `allow_download` | `true` | Allow file download from remote |
| `allow_upload` | `true` | Allow file upload to remote |
| `cleanup_on_close` | `true` | Delete session drive directory on disconnect |
| `retention_secs` | `0` | Delay before cleanup (0 = immediate) |
| `luks_device` | — | LUKS container file path |
| `luks_name` | `mybastion-drives` | Device-mapper name |
| `luks_key_path` | — | Vault KV path for LUKS encryption key |

## `[theme]` section

Customises the UI appearance — base preset, individual colours, and logo. All fields are optional. A minimal example:

```toml
[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

**See [themes.md](themes.md) for the full reference**: built-in preset list, every overridable field, the per-user picker, and how to author your own themes as `.toml` files under `<static_path>/themes/` (no recompile needed).

Place the logo file in the `static_path` directory (e.g. `/opt/mybastion/static/acme-logo.png`). In Docker, mount it as a volume:
```
-v /path/to/acme-logo.png:/opt/mybastion/static/acme-logo.png:ro
```

## `[recording]` section

Controls session recording behaviour and disk management.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | `recording_path` | Path for recording files. Overrides the top-level `recording_path`. |
| `enabled` | bool | `true` | Whether recording is enabled globally. |
| `max_disk_percent` | integer | `80` | Delete oldest recordings when disk usage exceeds this percent. 0 = disabled. |
| `max_recordings` | integer | `0` | Keep at most this many recordings globally. 0 = unlimited. |
| `rotation_interval_secs` | integer | `300` | How often (seconds) to run the rotation check. |
| `typescript_path` | string | (unset) | Directory for SSH typescript (raw terminal text) files. Unset = disabled. See below. |
| `typescript_name` | string | `{connection}-{user}-{date}-{time}` | Filename template for typescripts. Tokens listed below. |
| `create_typescript_path` | bool | `false` | Ask guacd to create `typescript_path` if it does not exist. |
| `mp4_enabled` | bool | `true` | Offer recordings as MP4 downloads (see below). Off by itself when guacenc is not installed. |
| `guacenc_path` | string | `/opt/mybastion/bin/guacenc` | The guacenc binary that converts recordings. |
| `mp4_cache_path` | string | `<path>/mp4-cache` | Where converted MP4s are kept. |
| `mp4_cache_hours` | integer | `24` | Remove a converted MP4 this many hours after it was made. |
| `mp4_max_jobs` | integer | `1` | Conversions that run at once; more wait their turn. |
| `mp4_timeout_secs` | integer | `1800` | Give up on a conversion after this many seconds. |
| `mp4_bitrate` | integer | `2000000` | Video bitrate, in bits per second. |
| `mp4_max_width`, `mp4_max_height` | integer | `1920`, `1080` | Largest video size. Bigger recordings are scaled down to fit, keeping their shape. |

```toml
[recording]
enabled = true
max_disk_percent = 80
max_recordings = 1000
rotation_interval_secs = 300
```

### SSH typescript recording

The graphical recording above captures the session as a replayable
Guacamole stream. For SSH sessions you can additionally write a
**typescript**: a plain-text log of the full terminal output, compatible
with the standard `script` / `scriptreplay` tools and trivially
greppable. This is aimed at audit and compliance (a human-readable record
of what was typed and seen on a switch or server).

Typescript recording is **per-connection opt-in and off by default**. Two
things are required: `typescript_path` must be set here (the global "where"),
and the individual connection entry must have **Enable typescript recording
for this session** ticked in its Recording Settings (Connections page, SSH
entries only). A connection with the box unticked, or any session that is not
SSH, writes no typescript. Ad-hoc SSH connections (Connect to a host) have no
entry; for a non-admin they never record a typescript.

The typescript is produced by guacd, so `typescript_path` must be writable by
the guacd process. On a standard install guacd runs as the same `mybastion`
user as the main service, so a path it owns just works; `create_typescript_path
= true` lets guacd create the directory. guacd writes two files per session,
`NAME` and `NAME.timing`.

When typescripts exist, the Recordings page shows a **SSH Typescripts**
section (poweruser+) listing each one with its name, size, and time. This
is **list-only by design**: the text content is never downloadable through
the web UI (a typescript can contain passwords typed at prompts or secrets
printed to screen), so a poweruser can confirm a session was recorded
while retrieving the actual log still requires direct access to the
My Bastion host or storage.

```toml
[recording]
typescript_path = "/var/lib/mybastion/typescripts"
typescript_name = "{connection}-{user}-{date}-{time}"
create_typescript_path = true
```

**Filename tokens.** guacd does not template typescript names itself (it
uses the name verbatim and only appends a numeric suffix to avoid
overwriting an existing file). My Bastion therefore expands its own tokens
in `typescript_name` before handing it over, so each file is identifiable:

| Token | Expands to |
|-------|-----------|
| `{user}` | Session username |
| `{connection}` | Address-book entry name (falls back to the hostname for ad-hoc sessions) |
| `{host}` | Target hostname |
| `{date}` | Connect date, UTC `YYYYMMDD` |
| `{time}` | Connect time, UTC `HHMMSS` |
| `{session}` | First 8 characters of the session id |

Substituted values are sanitised to `[A-Za-z0-9_-]` (everything else
becomes `-`), so usernames like `alice@example.com` and free-text entry
names are always reduced to a safe basename with no path separators.
Unknown `{tokens}` are left untouched.

> **Note:** these are My Bastion's own tokens, not guacd's, and they are
> unrelated to [credential variables](credential-variables.md) (which use
> `$name` syntax and apply only to connection-entry credential fields).
> guacd's own `${GUAC_*}` tokens are **not** interpreted for typescripts.

Keystroke logging in the *graphical* recording (guacd's
`recording-include-keys`, parseable by `guaclog`) is a separate mechanism
that depends on guacd-driven graphical recording, which My Bastion does not
use (it records the proxied stream itself). It is therefore not wired up;
the typescript is the supported text-audit path.

### MP4 downloads

A `.guac` recording only plays in My Bastion's own player. The Recordings page
can also give you an MP4 that plays anywhere (VLC, a browser, a video
editor): click **mp4** next to a recording. My Bastion converts it in the
background with `guacenc`, which comes with guacamole-server, and the file
downloads when it is ready. Converting a long session takes a while, so the
button shows **converting...** until then.

- The same people can get the MP4 as can download the recording (poweruser
  and admin).
- A recording whose session is still running is not converted, since the
  file is not finished.
- Converted files are kept in `mp4_cache_path` for `mp4_cache_hours`, so a
  second download is instant, and removed when their recording is. When
  rotation needs disk space it removes them all before touching any
  recording.
- The video is the recording's own size, scaled down to fit
  `mp4_max_width` x `mp4_max_height`.
- The button only appears when guacenc is installed. It is part of the
  `.deb`, the Docker image and `install.sh` from 1.11.1; on a build without
  it the button is not shown.

To convert recordings yourself, for example a batch for an audit, run
guacenc on the My Bastion host. It writes `<recording>.m4v` (an MP4 file)
next to the input, so copy recordings somewhere writable first:

```bash
cp /var/lib/mybastion/recordings/<id>.guac /tmp/
/opt/mybastion/bin/guacenc -s 1920x1080 -r 2000000 /tmp/<id>.guac
# -> /tmp/<id>.guac.m4v
```

guacenc reports failures in its output but exits 0 either way, so check
that the `.m4v` file exists.

#### Encryption at rest (LUKS)

Typescripts are written in plain text. For encryption at rest with no extra
infrastructure, point `typescript_path` at a subdirectory of the
LUKS-encrypted drive volume My Bastion already manages (see the
[`[drive]` section](#drive-section)). My Bastion opens and mounts that volume at
startup (key fetched from Vault) and unmounts it at shutdown, so the directory
is available whenever My Bastion is running, and the files are encrypted on the
block device at rest (powered off, disk theft, block-device backups).

```toml
[drive]
drive_path = "/mnt/mybastion-drives"
luks_device = "/dev/disk/by-uuid/..."   # your LUKS volume
luks_key_path = "secret/mybastion/luks"  # Vault KV path holding the key

[recording]
typescript_path = "/mnt/mybastion-drives/typescripts"
create_typescript_path = true
```

This is the recommended way to protect typescripts at rest today. Note its
limits: while My Bastion is running the volume is mounted, so the files are
plain text to anyone with host access (the same threat model as the drive
feature), and it is one key for the whole volume rather than per-connection.
Per-file, per-connection-key encryption is tracked as a separate feature
request, pending demand.

## `[web]` and `[spice]` sections

Inherited session types are off on a fresh install, which offers only SSH,
RDP and VNC. Each one is switched on by its own section:

```toml
[web]
enabled = true     # headless-Chromium web sessions (see web-sessions.md)

[spice]
enabled = true     # SPICE and Proxmox VE console sessions
```

While a type is off, creating a session of that type, ad hoc or from a
connections entry, is refused with an error that names the section. VDI has
its own switch, `[vdi] enabled`, below, and is off by default too.

## `[vdi]` section

Enables VDI (Virtual Desktop Infrastructure) sessions using Docker containers. Each user gets an ephemeral Linux desktop in a Docker container, accessed via xrdp through guacd.

**Prerequisites:** Docker must be installed on the host and the `mybastion` user must be in the `docker` group. See [VDI Desktop Containers](vdi.md) for full setup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable VDI sessions. |
| `docker_socket` | string | `/var/run/docker.sock` | Docker daemon socket path. |
| `default_cpu_limit` | float | `0` | Default CPU limit for containers (fractional cores, e.g. 2.0). 0 = no limit. |
| `default_memory_limit` | integer | `0` | Default memory limit in MB. 0 = no limit. |
| `ready_timeout_secs` | integer | `30` | Seconds to wait for xrdp to become ready in a new container. |
| `port_range_start` | integer | *(none)* | First localhost port Docker may bind VDI RDP to. Must be set with `port_range_end`. |
| `port_range_end` | integer | *(none)* | Last localhost port Docker may bind VDI RDP to. Must be set with `port_range_start`. |
| `container_hook_script` | string | *(none)* | Optional VDI container hook script. Called as `<script> up <port> <container_id> <container_name>` before readiness checks and `<script> down <port> <container_id> <container_name>` before removal. |
| `container_hook_timeout_secs` | integer | `10` | Seconds to wait for the VDI container hook script. |
| `idle_timeout_mins` | integer | `60` | Minutes a container persists after last session disconnect. 0 = remove immediately. |
| `allowed_images` | list | `[]` | Allowed Docker images (exact match). Empty = allow all. |
| `home_base` | string | *(none)* | Base directory for persistent user home dirs. Each user gets `{home_base}/{username}` mounted into the container. |

```toml
[vdi]
enabled = true
idle_timeout_mins = 60
# port_range_start = 39000
# port_range_end = 39999
# container_hook_script = "/opt/mybastion/vdi-container-hook.sh"
# container_hook_timeout_secs = 10
home_base = "/vdi-homes"
# allowed_images = ["myregistry/desktop:latest"]
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `OIDC_CLIENT_SECRET` | Override OIDC client secret from config file |
| `VAULT_SECRET_ID` | Vault AppRole secret ID for `[vault]` |
| `RUST_LOG` | Log level (e.g., `info`, `debug`, `mybastion=debug`) |

### Setting environment variables for systemd

The shipped systemd unit (`mybastion.service`) does not include an `EnvironmentFile` directive by default. To provide secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`, create a systemd drop-in override:

**1. Create the env file** with your secrets:

```bash
cat > /etc/mybastion/env <<'EOF'
VAULT_SECRET_ID=your-vault-secret-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
EOF
chmod 600 /etc/mybastion/env
chown mybastion:mybastion /etc/mybastion/env
```

**2. Create a systemd override** to load the env file:

```bash
sudo systemctl edit mybastion
```

This opens an editor. Add the following:

```ini
[Service]
EnvironmentFile=/etc/mybastion/env
```

Save and close. This creates a drop-in file at `/etc/systemd/system/mybastion.service.d/override.conf`.

**3. Reload and restart:**

```bash
sudo systemctl daemon-reload
sudo systemctl restart mybastion
```

The override persists across package upgrades — `dpkg` will not overwrite files in the `.d/` directory.

### Verifying the environment

To confirm the env file is loaded:

```bash
sudo systemctl show mybastion | grep EnvironmentFile
```

You should see:

```
EnvironmentFile=/etc/mybastion/env
```
