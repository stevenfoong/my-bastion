<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# My Bastion

**One gateway for every privileged access: people and AI agents, desktops, servers and databases. Every action is recorded, controlled and, when it matters, approved.**

This is a hard fork of [sol1/rustguac](https://github.com/sol1/rustguac), the lightweight Rust replacement for the Apache Guacamole web app. It keeps everything upstream does (browser-based SSH, RDP, VNC, SPICE and web sessions through guacd, OIDC SSO, roles, session recording, jump hosts) and extends it into a full bastion.

> **Status:** early development. Features below are the roadmap; see [docs/fork-design.md](docs/fork-design.md) for the design and progress.

## What this fork adds

### 🗄️ SQLite secret store: Vault optional
Run without HashiCorp Vault or OpenBao. Connections, folders and credentials are stored in SQLite, encrypted at rest with AES-256-GCM using envelope encryption (key from a file, systemd-creds, an environment variable or AWS KMS). Vault remains available as a backend, and a migration tool moves data in either direction.

### 🤖 MCP endpoint for AI agents
AI agents (Claude and other MCP clients) can open RDP and VNC sessions and work them like a person: see the screen, click, type. They can also run commands over SSH. Agents never see credentials, can only reach machines in folders marked for AI, and every AI session is recorded and can be watched or taken over live.

### ✅ Action approval for people *and* AI
Risky actions wait for a second person's approval, whoever is doing them:
- **Policies per folder or connection:** allow, deny, or require approval
- **SSH command control:** block or hold dangerous commands (`rm -rf`, `shutdown`, `systemctl stop`, …) for a user or an agent
- **Modes:** observe only, approve each action, or run freely with full recording
- **Approval in the web UI**, with notifications to chat tools planned

### 🛢️ Database access proxy
Database sessions go through the bastion like any other connection:
- **Proxies the native protocol** for MySQL/MariaDB and PostgreSQL, so users keep their usual clients (DBeaver, psql, mysql)
- **Logs every query** against the user who ran it
- **Applies command policies:** read-only access, block `DROP`/`TRUNCATE`/`DELETE` without `WHERE`, or require approval for writes
- **Keeps database passwords** stored in the bastion, never handed to users

## Why

Most teams protect servers, desktops and databases with different tools, or not at all, and AI agents are now joining the list of things that need access. This fork aims to put all of it behind one small, self-hosted gateway: one place to grant access, one audit trail, and one approval flow.

## Upstream & license

Built on [sol1/rustguac](https://github.com/sol1/rustguac) and [Apache Guacamole](https://guacamole.apache.org/) (`guacd`). Licensed under the Apache License 2.0, as upstream. This is a hard fork: it is developed independently and does not track upstream.

---

# Inherited features

The sections below are from upstream [sol1/rustguac](https://github.com/sol1/rustguac) and describe the features this fork inherits.


[![CI](https://github.com/stevenfoong/my-bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/stevenfoong/my-bastion/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/stevenfoong/my-bastion)](https://github.com/stevenfoong/my-bastion/releases/latest)
[![License](https://img.shields.io/github/license/stevenfoong/my-bastion)](LICENSE)

A lightweight Rust replacement for the Apache Guacamole Java webapp. Browser-based SSH, RDP, VNC, SPICE, Proxmox VE consoles, web browsing, and VDI desktop containers through [guacd](https://github.com/apache/guacamole-server).

No Java. No Tomcat. Single binary + guacd.

## Architecture

```
Browser (HTML/JS)
    |
    | WebSocket over HTTPS
    v
mybastion (Rust, axum)
    |
    | TLS (Guacamole protocol)
    v
guacd (C, from guacamole-server)
    |
    +---> SSH server
    +---> RDP server
    +---> VNC server
    +---> SPICE server (libvirt/QEMU displays)
    +---> Proxmox VE VM console (SPICE via the PVE spiceproxy API)
    +---> Xvnc + Chromium (web browser sessions)
    +---> Docker container + xrdp (VDI desktop sessions)
```

## Features

### Session types

| Type | Description |
|------|-------------|
| **SSH** | Browser-based terminal with password, private key, or ephemeral keypair auth. SFTP file transfer. |
| **RDP** | Windows/Linux RDP with auto-fit resize, Kerberos NLA, RemoteApp/RAIL, H.264 passthrough, GFX pipeline. |
| **VNC** | Connect to any VNC server (KVM/IPMI consoles, remote desktops, VM displays). |
| **SPICE** | Direct SPICE displays (libvirt/QEMU consoles) with TLS, CA verification, certificate-subject pinning, and SPICE-proxy support. |
| **Proxmox VE** | VM consoles brokered through the Proxmox API. One-time SPICE tickets fetched just-in-time at connect (only the API token is stored), node auto-detected from the VM ID, and SSH-tunnel aware. |
| **Web** | Headless Chromium on Xvnc with native autofill, domain allowlisting, login script automation. |
| **VDI** | Ephemeral Docker desktop containers per user. Persist after disconnect, auto-cleanup on idle. |

### Security & authentication

- **OIDC single sign-on**: Authentik, Google, Okta, Keycloak, or any OpenID Connect provider
- **4-tier role system**: admin, poweruser, operator, viewer with OIDC group mapping
- **API key auth**: SHA-256 hashed keys with IP allowlists and expiry
- **Vault-backed connections**: credentials in HashiCorp Vault or OpenBao KV v2, never reach the browser (see [Requirements](#requirements))
- **TLS everywhere**: HTTPS for clients, TLS between My Bastion and guacd
- **CIDR allowlists**: per-protocol network restrictions for session targets
- **Per-entry clipboard control**: disable copy and/or paste for data loss prevention
- **Rate limiting**: per-IP, per-endpoint via tower_governor
- **Session recording**: Guacamole format with playback UI, disk rotation, per-entry limits

### Connectivity

- **Multi-hop SSH tunnels**: chain jump hosts/bastions to reach isolated networks (all session types, including the Proxmox API and console hops)
- **Session sharing**: share links for view-only or collaborative access, plus admin shadowing
- **Headless API integration**: create a session over the REST API and hand a browser a ready-to-open URL via a single-use WebSocket ticket, with no OIDC login and no API key in the browser (see [Connecting to a session](docs/api.md#connecting-to-a-session))
- **Encrypted file transfer**: LUKS-encrypted per-session drive storage (RDP), SFTP (SSH)
- **Credential variables**: shared credentials across connections entries

### VDI desktop containers

- **Docker-based**: one container per user, deterministic naming, BYO image
- **Persist after disconnect**: reconnect to the same desktop within idle timeout
- **Logout detection**: desktop logout stops the container, tab close preserves it
- **Session thumbnails**: live preview in the connections, click to reconnect
- **Persistent home directories**: bind-mounted user data survives container restarts
- **Per-entry resource limits**: CPU, memory, idle timeout per connections entry
- **VdiDriver trait**: extensible for downstream forks (Nomad, Proxmox, cloud)

### UI

- **Connections** with folder-based organisation and OIDC group access control
- **Active Sessions** section with live thumbnail previews
- **Session ended overlay** with Reconnect/Close buttons
- **Clipboard panel controls** (Home + Fullscreen)
- **8 built-in themes** with CSS gradient backgrounds, or configure your own
- **Reports page** with session analytics, history, and CSV export

## Requirements

| Component | Status | Notes |
|-----------|--------|-------|
| guacd | Bundled | Built from `apache/guacamole-server`, ships in the .deb and Docker image. No separate install. |
| **Vault or OpenBao** | **Required for the Connections UI** | Stores connection entries and credentials server-side. Without it the Connections page is unavailable and users can only run ad-hoc sessions via the API. Use [`contrib/vault-quickstart.sh`](contrib/vault-quickstart.sh) for one-command setup (auto-detects `vault` or `bao`, supports `--dev` and `--local` modes). |
| OIDC provider | Optional | For SSO. API-key auth works on its own. Authentik/Google/Okta/Keycloak/JumpCloud all tested. |
| Docker | Optional | Only needed for VDI desktop containers. |

### Supported browsers

The client runs in any modern browser (Chrome, Firefox, Edge, Safari, Chromium, Brave). One caveat applies only to **H.264-accelerated RDP**, which is opt-in per connection (the per-entry H.264 toggle, off by default):

- **Standard connections** (SSH, RDP, VNC, web sessions, VDI) work in every modern browser.
- **H.264-accelerated connections** need a browser that can decode H.264 through the WebCodecs API. **Chrome** and **Firefox** work. Open-source **Chromium** and **Brave** builds without the bundled H.264 codec, and older Safari, render a blank display on those connections. Leave H.264 off (the default) for universal browser support, or use Chrome or Firefox where it is enabled.

## Quick start

### Debian 13 (.deb)

Pre-built packages for amd64 and arm64 are available from [Releases](https://github.com/stevenfoong/my-bastion/releases):

```bash
sudo apt install ./mybastion_*.deb
/opt/mybastion/bin/mybastion --config /etc/mybastion/mybastion.toml add-admin --name admin
sudo systemctl enable --now mybastion
```

### Docker

```bash
docker pull ghcr.io/stevenfoong/mybastion:latest
docker run --rm --entrypoint cat ghcr.io/stevenfoong/mybastion:latest /opt/mybastion/seccomp-chromium.json > seccomp-chromium.json
docker run -d -p 8089:8089 --security-opt seccomp=seccomp-chromium.json ghcr.io/stevenfoong/mybastion:latest
```

The seccomp profile lets Chromium's sandbox start for web browser sessions; see [Web sessions: Running under Docker](docs/web-sessions.md#running-under-docker).

For VDI support, mount the Docker socket:

```bash
docker run -d -p 8089:8089 \
  --security-opt seccomp=seccomp-chromium.json \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(getent group docker | cut -d: -f3) \
  ghcr.io/stevenfoong/mybastion:latest
```

### Other distributions

Pre-built packages are provided for Debian 13. For other distributions, build from source:

```bash
sudo ./install.sh
```

See the [Installation guide](docs/installation.md) for full details including Docker Compose, TLS setup, and development builds.

### VDI setup

VDI requires Docker on the host:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker mybastion
sudo systemctl restart mybastion
```

Add `[vdi]` to your config and create a VDI entry in the connections. See [VDI Desktop Containers](docs/vdi.md) for image requirements and configuration.

## Documentation

### Getting started
- [Installation](docs/installation.md): Debian packages, Docker, bare-metal, development builds
- [Configuration](docs/configuration.md): TOML config reference with all sections
- [Deployment Guide](docs/deployment-guide.md): step-by-step production setup

### Features
- [Roles & Access Control](docs/roles-and-access-control.md): OIDC, roles, group mappings, API tokens
- [Web Browser Sessions](docs/web-sessions.md): autofill, domain allowlisting, login scripts
- [SPICE and Proxmox VE Sessions](docs/spice-and-proxmox.md): SPICE displays, Proxmox VE consoles, API tokens, TLS, troubleshooting
- [VDI Desktop Containers](docs/vdi.md): Docker desktops, image requirements, persistent homes
- [RDP Video Performance](docs/rdp-video-performance.md): H.264 passthrough, GFX pipeline, xrdp tuning
- [RDP H.264 Passthrough](docs/rdp-h264.md): enabling it, and the Windows host settings it requires
- [Credential Variables](docs/credential-variables.md): shared credentials across entries
- [Reports](docs/reports.md): session analytics, history, CSV export

### Integration & reference
- [Integrations](docs/integrations.md): Vault, LUKS drives, SSH tunnels, Kerberos, HAProxy
- [NetBox](docs/netbox.md): connections sync via custom fields and webhooks
- [Security](docs/security.md): TLS, rate limiting, headers, audit logging, hardening
- [API Reference](docs/api.md): REST API endpoints, the session connection flow, and headless ws-ticket integration
- [Migration from Apache Guacamole](docs/migration.md): MySQL/MariaDB to Vault

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE): My Bastion is derived from [sol1/rustguac](https://github.com/sol1/rustguac) and includes [Apache Guacamole](https://guacamole.apache.org/).
