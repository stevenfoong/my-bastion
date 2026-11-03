<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# SPICE and Proxmox VE Sessions

**Off by default.** Turn both session types on with `[spice] enabled = true` in `mybastion.toml` (see [Configuration](configuration.md#web-and-spice-sections)).

My Bastion has two session types built on the SPICE remote display protocol:

- **SPICE** (`spice`) connects directly to a SPICE server, such as a libvirt/QEMU VM console. You give it a host, a port and optionally a password, plus TLS, CA, certificate-subject and SPICE proxy settings.
- **Proxmox VE console** (`proxmox`) opens a Proxmox VE VM's console. You give it the PVE API URL, a VM ID and an API token. At connect time My Bastion asks the Proxmox API for a one-time SPICE ticket and connects with it. The API token is the only secret that is stored.

Both types go through guacd's SPICE plugin, so the browser needs no SPICE client or plugin.

For Proxmox VE VMs, use the Proxmox VE console type rather than plain SPICE. Proxmox SPICE tickets are single-use and expire after about 30 seconds, so a password saved in a SPICE entry cannot work. The Proxmox type fetches a new ticket on every connect.

## Requirements

### guacd with SPICE support

SPICE needs guacd's SPICE plugin, `libguac-client-spice`. Upstream guacamole-server does not include it yet. My Bastion adds it with its own patch `008-spice-protocol.patch`, which carries the upstream pull request [apache/guacamole-server#688](https://github.com/apache/guacamole-server/pull/688) (GUACAMOLE-261). Building it needs `libspice-client-glib-2.0-dev`, and guacd must be configured `--with-spice`. Running it needs `libspice-client-glib-2.0-8`. See [guacamole-server patches](installation.md#guacamole-server-patches).

| Install method | SPICE in the bundled guacd |
|----------------|----------------------------|
| Debian package (`.deb`) | Yes from **v1.12.0**. The packages from v1.9.0 to v1.11.0 were built without SPICE. |
| Docker image | Yes from **v1.9.8**. The images from v1.9.0 to v1.9.7 compiled the plugin but did not ship the runtime library it links against ([#195](https://github.com/sol1/rustguac/issues/195)). |
| `install.sh` (bare metal, Debian 13) | Yes. It installs `libspice-client-glib-2.0-dev` and builds guacd `--with-spice`. |
| RPM (`build-rpm.sh`) | Not guaranteed. The RPM build does not pass `--with-spice` and does not run the plugin check. |

guacd's `configure` quietly leaves out a protocol whose library is missing, even when you ask for it with `--with-spice`. That is how the SPICE plugin went missing from the `.deb` builds above. The Docker, `.deb` and `install.sh` builds now run `scripts/check-guacd-plugins.sh` after `make install`, and the build fails if the rdp, ssh, vnc or spice plugin, or `guacenc`, is missing.

To check an existing install:

```bash
ls /opt/mybastion/lib/libguac-client-spice.so*
ldd /opt/mybastion/lib/libguac-client-spice.so.0 | grep "not found"
```

The first command should list the plugin, and the second should print nothing. If a SPICE or Proxmox connection fails and guacd logs `Support for protocol "spice" is not installed`, guacd has no working SPICE plugin. Upgrade to a release that includes it (see the table above).

### Network access

| From | To | Used by |
|------|----|---------|
| guacd | SPICE server `hostname` and port (or TLS port) | SPICE |
| My Bastion | PVE API, usually `https://<node>:8006` | Proxmox VE |
| guacd | The SPICE proxy that Proxmox returns, usually `http://<node>:3128` | Proxmox VE |

My Bastion and guacd run on the same host, or in the same container. My Bastion also resolves the SPICE `hostname` itself, for the [allowlist](#network-allowlists) check. Port 8006 working is not enough for Proxmox: the console itself goes through the SPICE proxy on port 3128 ([#218](https://github.com/sol1/rustguac/issues/218)).

### Vault (for Connections entries)

Connections entries, including the Proxmox API token, are stored in Vault or OpenBao (see [Vault / OpenBao Connections](integrations.md#vault--openbao-connections)). Without Vault you can still create both session types ad hoc through the [API](#ad-hoc-sessions-via-the-api).

## SPICE entries

Admins create entries in the Connections editor: choose **New Entry**, then set **Type** to **SPICE**.

| Field | Entry field | Description |
|-------|-------------|-------------|
| Hostname | `hostname` | SPICE server hostname or IP (required) |
| Port | `port` | SPICE port (default 5900) |
| Password | `password` | SPICE password / ticket. Stored in Vault and never sent back to the browser. |
| Color depth | `color_depth` | 8, 16, 24 or 32-bit. Default 24-bit. |
| Connect using TLS | `spice_tls` | Connect over TLS. See [SPICE TLS](#spice-tls). |
| TLS port | `spice_tls_port` | The server's TLS port, when it is different from Port |
| Ignore certificate | `ignore_cert` | Accept any TLS certificate (insecure) |
| CA certificate | `spice_ca_cert` | PEM CA certificate for verifying the server's TLS certificate (optional) |
| Certificate subject | `spice_cert_subject` | Expected TLS certificate subject, e.g. `OU=..., CN=...` (optional) |
| Proxy | `spice_proxy` | SPICE proxy URL, e.g. `http://proxy.example.com:3128` (optional) |
| Prompt for credentials at connect time | `prompt_credentials` | Ask for credentials at connect time instead of using the stored ones |

A SPICE entry with no stored password also prompts at connect time: its button reads **Login...** instead of **Connect**. Prompted credentials are used for that session only and never stored (see [Credential prompting](integrations.md#credential-prompting)).

The editor has no Monitors field for SPICE entries. To give a SPICE entry more than one monitor, set `max_monitors` through the [entries API](api.md#post-apiaddressbookfoldersscopefolderentries-admin) (see [Multi-monitor](#multi-monitor)). Saving the entry in the editor afterwards removes `max_monitors` again, so set it last.

## Proxmox VE console entries

Set **Type** to **Proxmox VE console**.

| Field | Entry field | Description |
|-------|-------------|-------------|
| PVE API URL | `proxmox_url` | PVE API base URL, including scheme and port, e.g. `https://pve.example.internal:8006` (required) |
| Node | `proxmox_node` | Cluster node that hosts the VM. Optional: leave it blank to [auto-detect it](#node-auto-detection). |
| VM ID | `proxmox_vmid` | ID of the QEMU VM whose console to open (required) |
| Token ID | `proxmox_token_id` | API token ID, `user@realm!tokenid`, e.g. `mybastion@pve!mybastion` |
| Token secret | `proxmox_token_secret` | API token secret (the UUID part), e.g. `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Write-only: see [How the token is stored](#how-the-token-is-stored). |
| Color depth | `color_depth` | 8, 16, 24 or 32-bit. Default 24-bit. |
| Monitors | `max_monitors` | 1 to 4 in the editor. The guest must support more than one SPICE display (head). See [Multi-monitor](#multi-monitor). |
| Verify the PVE cluster TLS certificate | `proxmox_verify_tls` | Off by default. See [TLS verification for Proxmox](#tls-verification-for-proxmox). |

In the entry list, the Host column shows the API URL and VM ID (`https://pve.example.internal:8006 · VM 100`). The User column shows the Token ID. Proxmox entries never prompt for credentials: the token is all they need.

## Common entry settings

These sections of the editor apply to both types:

- **Clipboard**: *Disable clipboard copy* and *Disable paste* are passed to guacd's SPICE plugin as `disable-copy` / `disable-paste` (see [Clipboard control](security.md#clipboard-control)).
- **Recording Settings**: My Bastion records SPICE and Proxmox sessions the same way as any other session, in Guacamole format, and per-entry overrides work the same. Typescript recording is SSH-only.
- **SSH Tunnel / Jump Hosts**: see [SSH tunnels and jump hosts](#ssh-tunnels-and-jump-hosts).

The editor does not show file transfer, Wake-on-LAN, RemoteApp or Video Performance settings for these types. Audio is not enabled for SPICE sessions: My Bastion always sends guacd `enable-audio=false`.

## The Proxmox API token

### Format and privileges

A Proxmox API token has two parts:

- **Token ID**: `user@realm!tokenid`, for example `mybastion@pve!mybastion`. This part is not secret, and My Bastion shows it in the Connections list.
- **Token secret**: a UUID such as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

My Bastion joins them into `user@realm!tokenid=secret` and sends them in each PVE API request as an `Authorization: PVEAPIToken=...` header.

On the target VM, the token needs:

| Privilege | Needed for |
|-----------|------------|
| `VM.Console` | Opening the console (the `spiceproxy` call) |
| `VM.Audit` | [Node auto-detection](#node-auto-detection), when Node is left blank |

If the secret is empty, My Bastion treats the Token ID as the complete `id=secret` string. The API accepts that form, but do not use it in a Connections entry: the Token ID is shown in the Connections list and returned to the browser, so a secret put there would be exposed. Use the two fields.

### How the token is stored

- The token is saved with the rest of the entry in Vault, for example at `mybastion/shared/<folder>/<entry>` (see [KV v2 path structure](integrations.md#kv-v2-path-structure)).
- The secret is **write-only**. No read endpoint returns it. Instead, entries carry a `has_proxmox_token_secret` boolean, and the editor shows *(leave blank to keep existing)* in the Token secret field.
- Saving the editor with the secret field blank keeps the stored secret. API updates that leave out `proxmox_token_secret` keep it too (see [`PUT .../entries/:entry`](api.md#put-apiaddressbookfoldersscopefolderentriesentry-admin)).
- Moving or cloning an entry is done on the server from the stored entry, so the token secret stays with it (since v1.10.3).
- The SPICE ticket is never stored. My Bastion fetches a new one on every connect.

### Node auto-detection

The console API is per node (`/nodes/{node}/qemu/{vmid}/spiceproxy`). If **Node** is blank, My Bastion first calls `GET /api2/json/cluster/resources?type=vm` and takes the `node` of the VM with that ID. This is the same lookup the Proxmox web UI does. You can then point **PVE API URL** at any node in the cluster and give only the VM ID, and the console still opens after the VM migrates to another node.

If the lookup does not find the VM, the connection fails with `VM <id> not found in the cluster (check the VM id, or that the token can see it)`. This means the VM ID is wrong, or the token has no `VM.Audit` on the VM.

### The one-time SPICE ticket and proxy flow

Each connect runs this sequence:

```text
Browser
    |
    | 1. Connect (Connections entry, or POST /api/sessions)
    v
mybastion ---- 2. GET /api2/json/cluster/resources?type=vm ----------> PVE API (:8006)
    |            (only when Node is blank: VM ID -> node)
    |
    |    ---- 3. POST /api2/json/nodes/{node}/qemu/{vmid}/spiceproxy --> PVE API
    |    <--- host, proxy, tls-port, password (one-time ticket),
    |         ca, host-subject
    |
    | 4. Guacamole protocol: SPICE connect args,
    |    ticket as the SPICE password
    v
guacd (SPICE plugin)
    |
    | 5. Through the SPICE proxy (HTTP CONNECT), then SPICE over TLS
    v
SPICE proxy (http://<node>:3128) ---> VM console (tls-port)
```

1. My Bastion reads the entry and its token from Vault (or takes them from an ad-hoc request).
2. If Node is blank, My Bastion looks it up from the VM ID.
3. My Bastion calls the `spiceproxy` endpoint. The response contains:
   - `host`: an opaque routing token (`pvespiceproxy:...`) that the SPICE proxy uses to find the VM
   - `proxy`: the proxy URL to connect through
   - `tls-port`: the TLS port to use
   - `password`: the one-time ticket
   - `ca`: the cluster CA
   - `host-subject`: the expected certificate subject
4. My Bastion hands these to guacd straight away, in the same request. The ticket is valid for about 30 seconds and can be used once. My Bastion never logs the token or the ticket. When a Proxmox call fails, the error includes Proxmox's own message; only a successful response carries a ticket, and that is never put in an error.
5. guacd connects to the SPICE proxy, which forwards the connection to the VM's console. Proxmox SPICE is TLS-only, so My Bastion sends guacd only the TLS port.

The proxy URL is whatever Proxmox returns, and Proxmox gives the node's **name**, not the address you used in `proxmox_url` (for example `http://pve.example.internal:3128`). My Bastion does not send a `proxy` override, so Proxmox picks the proxy itself, by default the node that handled the API request. Unless you use jump hosts, the machine running My Bastion and guacd must be able to resolve that name and reach it on port 3128.

The Active Sessions list shows a Proxmox session's hostname as Proxmox's routing token (`pvespiceproxy:...`), not as the node name.

## SPICE TLS

### Direct SPICE entries

| Setting | Effect |
|---------|--------|
| **Connect using TLS** off | Plain SPICE to `hostname:port`. |
| **Connect using TLS** on | My Bastion sends guacd only the TLS port and no plain port, so the connection is TLS-only. **TLS port** is the server's TLS port. If it is blank, the TLS connection uses **Port**. |
| **CA certificate** | PEM CA used to verify the server certificate, for servers whose certificate is not signed by a public CA (e.g. a libvirt or Proxmox cluster CA). |
| **Certificate subject** | Pins the expected certificate subject, e.g. `OU=PVE Cluster Node,CN=pve.example.internal`. When it is set, guacd checks the certificate subject instead of the hostname. |
| **Ignore certificate** | Turns certificate verification off. Only for testing, or for self-signed displays you cannot otherwise verify. |
| **Proxy** | guacd connects through this SPICE proxy, e.g. `http://proxy.example.com:3128`. |

### TLS verification for Proxmox

For Proxmox entries, one setting, **Verify the PVE cluster TLS certificate** (`proxmox_verify_tls`), controls both TLS connections:

| | Off (default) | On |
|-|---------------|----|
| PVE API (`proxmox_url`) | Certificate not verified | Verified against the system trust store of the machine (or container) My Bastion runs in |
| SPICE console | Certificate not verified | Verified against the cluster CA (`ca`) and pinned to the certificate subject (`host-subject`), both from the `spiceproxy` response |

Proxmox ships a self-signed cluster certificate. Leave verification off unless the My Bastion host trusts the cluster's CA, or the PVE API has a certificate from a CA the host already trusts.

## SSH tunnels and jump hosts

Both session types can go through a chain of SSH jump hosts. Configure the chain under **SSH Tunnel / Jump Hosts** in the entry editor, or with `jump_hosts` in an API request. How the chain works, and per-hop credentials, are covered in [SSH Tunnel / Multi-Hop Jump Hosts](integrations.md#ssh-tunnel--multi-hop-jump-hosts).

**SPICE.** The tunnel forwards to the SPICE server. With TLS on it forwards to the TLS port (or to Port when TLS port is blank), otherwise to the plain port. guacd then connects to the local end of the tunnel on `127.0.0.1`. The server presents the same certificate either way, so a **Certificate subject** check still passes when tunnelled. Without a subject, guacd checks the certificate against the hostname it dials, `127.0.0.1`, which the certificate will not match. For tunnelled TLS entries, set **Certificate subject**.

**Proxmox VE.** My Bastion builds the tunnels itself, two through the same chain:

1. **The PVE API.** My Bastion calls `cluster/resources` and `spiceproxy` through a tunnel to the API host and port (8006 when the URL has no port). The tunnel ends on `127.0.0.1`, which no PVE certificate matches, so My Bastion does not verify the API certificate on this connection, even with **Verify** on. The SSH tunnel protects it instead.
2. **The SPICE proxy.** My Bastion tunnels to the proxy host and port that Proxmox returns (3128 when it has no port), and points guacd at the local end. The SPICE TLS connection runs inside the proxy's CONNECT tunnel. With **Verify** on, the console's certificate is therefore still checked against the cluster CA and subject.

Through jump hosts, the last bastion resolves the proxy's node name, so only the bastion needs to resolve it, not the My Bastion host. Tunnel failures are reported as `Proxmox API tunnel failed: ...` or `Proxmox SPICE proxy tunnel failed: ...`.

## Network allowlists

SPICE and Proxmox targets are checked against `vnc_allowed_networks` (see [Network allowlists](security.md#network-allowlists-ssrf-protection) and [Connection allowlists](configuration.md#connection-allowlists)). Like the other allowlists, it defaults to localhost only:

```toml
# Top-level key: put it before any [section] header
vnc_allowed_networks = ["127.0.0.0/8", "::1/128", "192.0.2.0/24"]
```

What is checked depends on who creates the session:

| Target | Connections entry, or admin | Ad-hoc session from a non-admin |
|--------|-----------------------------|---------------------------------|
| SPICE `hostname` (no jump hosts) | `vnc_allowed_networks` | `vnc_allowed_networks` |
| Proxmox `proxmox_url` host | Not checked | `vnc_allowed_networks` |
| SPICE proxy returned by Proxmox | Not checked | `vnc_allowed_networks` |
| First jump host | Not checked | `ssh_allowed_networks` |
| Anything behind a jump host | Not checked (the bastion resolves it) | Not checked (the bastion resolves it) |

Proxmox clusters in entries, and in sessions created by admins, are not checked, because clusters often sit outside the target networks. For non-admins, My Bastion checks the Proxmox API URL and the SPICE proxy because it calls the API itself, and guacd then connects to whatever proxy the API names. A refused Proxmox target fails with an error that starts `Proxmox API: host ...` or `Proxmox SPICE proxy: host ...` and ends `not in the allowed network list` (see [Ad-hoc sessions from non-admins](security.md#ad-hoc-sessions-from-non-admins)).

SPICE sessions connect to the hostname, not to the address that passed the check, so that TLS certificate names still match. If that matters for your environment, use IP addresses in entries.

## Ad-hoc sessions via the API

Ad-hoc SPICE and Proxmox sessions are created with [`POST /api/sessions`](api.md#post-apisessions), which needs the **poweruser** role or higher. The **Sessions** page form and quick-connect links (`GET /api/connect`) offer only SSH, RDP, VNC and web (plus VDI on the Sessions page). Neither can start a SPICE or Proxmox session.

### SPICE

```bash
curl -X POST https://mybastion.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "spice",
    "hostname": "192.0.2.20",
    "port": 5900,
    "password": "xxxxxxxx"
  }'
```

With TLS, a pinned subject and a SPICE proxy:

```json
{
  "session_type": "spice",
  "hostname": "192.0.2.20",
  "password": "xxxxxxxx",
  "spice_tls": true,
  "spice_tls_port": 5901,
  "spice_cert_subject": "CN=spice.example.com",
  "spice_proxy": "http://192.0.2.5:3128"
}
```

### Proxmox VE

```bash
curl -X POST https://mybastion.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "proxmox",
    "proxmox_url": "https://pve.example.internal:8006",
    "proxmox_vmid": 100,
    "proxmox_token_id": "mybastion@pve!mybastion",
    "proxmox_token_secret": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "proxmox_verify_tls": false
  }'
```

`proxmox_node` is left out, so My Bastion auto-detects the node. The same request through a bastion:

```json
{
  "session_type": "proxmox",
  "proxmox_url": "https://pve.example.internal:8006",
  "proxmox_vmid": 100,
  "proxmox_token_id": "mybastion@pve!mybastion",
  "proxmox_token_secret": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n"
    }
  ]
}
```

The full field lists are under [`POST /api/sessions`](api.md#post-apisessions). The response contains `client_url` and `ws_url`, as for any other session. My Bastion fetches the Proxmox ticket while it creates the session, so open the session promptly. For handing a session to a browser without an OIDC login, see [Headless API integration](api.md#headless-api-integration).

To manage entries through the API, use [`POST /api/addressbook/folders/:scope/:folder/entries`](api.md#post-apiaddressbookfoldersscopefolderentries-admin) with `"type": "spice"` or `"type": "proxmox"` and the same `spice_*` / `proxmox_*` fields.

## Multi-monitor

SPICE and Proxmox sessions can span more than one monitor. `max_monitors` is the total number of monitors (default 1). guacd is told `secondary-monitors = max_monitors - 1`. Set it with the **Monitors** field on Proxmox entries (1 to 4), or with `max_monitors` in an entry or session request.

The guest must present more than one display head. A Windows guest presents each head as a separate QXL device; a Linux guest uses a single QXL device with several heads. In the client, the Controls panel lists the monitors. Each extra monitor opens in its own browser window, so allow popups for the My Bastion site. Drag each window to a physical display and press F11 to fullscreen it.

## Troubleshooting

The API returns failures as `400` with `{"error": "validation error: ..."}`. The My Bastion log has the same message, under `Session creation failed`.

**guacd logs `Support for protocol "spice" is not installed`:**
- guacd has no working SPICE plugin. This affected the Docker images from v1.9.0 to v1.9.7 ([#195](https://github.com/sol1/rustguac/issues/195)) and the `.deb` packages from v1.9.0 to v1.11.0. Upgrade, then check with the commands in [Requirements](#guacd-with-spice-support).
- For your own guacd build, install `libspice-client-glib-2.0-dev` and configure `--with-spice`. Without the library, `configure` leaves SPICE out without an error.

**A Proxmox connection hangs, even though the node name was auto-detected:**
- Auto-detection working only proves that port 8006 (the API) is reachable. The console also needs the SPICE proxy on port 3128 of the node Proxmox returns ([#218](https://github.com/sol1/rustguac/issues/218)). Check that the machine running guacd can reach it.
- Check the `proxy=` value in the My Bastion log line `Creating Proxmox VE SPICE console session`. It is a node **name** (e.g. `http://pve.example.internal:3128`) even when `proxmox_url` uses an IP address, because that is what the Proxmox API returns. Make sure that name resolves from the My Bastion host (or from inside the container for Docker). DNS is the dependable fix. You can also route through a [jump host](#ssh-tunnels-and-jump-hosts) that can resolve the name.

**`Proxmox node lookup failed: ...`:**
- `VM <id> not found in the cluster (check the VM id, or that the token can see it)`: the VM ID is wrong, or the token has no `VM.Audit` on the VM.
- `PVE spiceproxy returned HTTP 401` (or another status) during the lookup: the message comes from the same error type as the console call, so it can mention `spiceproxy` even though the failed call was `cluster/resources`. Check the Token ID and secret.

**`Proxmox SPICE broker failed: PVE spiceproxy returned HTTP <code>: <message>`:**
- The `spiceproxy` call failed. `<message>` is Proxmox's own explanation, for example a wrong node, a VM that is not running, a display not set to SPICE, or a missing `VM.Console` privilege.
- If you set **Node** by hand, it must match the node that hosts the VM. Leave it blank to auto-detect it.

**`PVE API transport error: ...`:**
- My Bastion could not connect to the PVE API. Possible causes are a wrong host or port, a firewall, a timeout (10 seconds to connect, 15 seconds in total), or a TLS failure. If **Verify the PVE cluster TLS certificate** is on and the host does not trust the cluster CA, turn it off or install the CA. See [TLS verification for Proxmox](#tls-verification-for-proxmox).

**`PVE spiceproxy response parse error: ...`:**
- The API answered, but without the expected `host`, `proxy`, `tls-port` or `password` fields.

**`Proxmox sessions require proxmox_url` / `Proxmox sessions require proxmox_vmid` / `hostname is required for SPICE sessions`:**
- A required field is missing from the entry or the request.

**`Proxmox API: ...` / `Proxmox SPICE proxy: ...` / `jump host: ...` with `not in the allowed network list`:**
- A non-admin's ad-hoc session was refused by an allowlist. See [Network allowlists](#network-allowlists).

**`host ...` ending in `not in the allowed network list` for a SPICE entry:**
- Add the SPICE server's network to `vnc_allowed_networks`. It is a top-level key, so put it before any `[section]` header, or it is ignored.

**Quick-connect link for a SPICE or Proxmox entry fails with `Unknown session type: ...`:**
- `GET /api/connect` supports only SSH, RDP, VNC and web entries. A Proxmox entry has no password, so the link may show a credential form first. Open these entries from the Connections page, or with [`POST .../entries/:entry/connect`](api.md#post-apiaddressbookfoldersscopefolderentriesentryconnect).
