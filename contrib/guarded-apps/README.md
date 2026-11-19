# Guarded Apps

**One shared web login, many accountable people.**

Some providers give you a single account for their web portal and nothing
else: no per-user logins, no roles, no audit. Guarded Apps puts that portal
behind My Bastion so that:

- nobody but IT knows the shared password (or holds its 2FA);
- every person signs in to My Bastion as themselves, so every session has a
  name on it and is recorded;
- only one person uses the portal at a time;
- the browser is locked down: no other sites, no downloads, no printing, no
  DevTools, and clipboard and uploads controlled by My Bastion policies.

## How it works

```
User's browser
    │  HTTPS, signed in to My Bastion (OIDC, e.g. Google)
    ▼
My Bastion ── policies, approvals, recording, audit
    │
    ▼
guacd
    │  VNC (localhost or private network only)
    ▼
Guarded app container  (one per app)
    ├─ Xvnc            one viewer at a time, idle viewers dropped
    └─ Chromium        kiosk mode, managed policies, persistent profile
          │
          └─ https://provider.example.com  (logged in once by IT)
```

My Bastion already has **web sessions** (`[web]`), but those start a fresh
browser profile for every session and delete it afterwards. That suits
credentials My Bastion can autofill, but not a portal whose login needs a
2FA code from IT. A guarded app keeps **one long-running browser with a
persistent profile**: IT logs in once, and users arrive already logged in.

To My Bastion, a guarded app is just a **VNC connection**, so this needs
**no change to My Bastion's code**.

## What you get today

| Need | How |
|------|-----|
| Know who did what | Users sign in to My Bastion with their own identity; the VNC entry's sessions are recorded and audited against that person |
| Hide the shared password | Only IT logs in to the provider, inside the container; the login lives in the container's profile volume |
| One user at a time | Xvnc runs with `-NeverShared -DisconnectClients=0`: while someone is connected, the next connection is refused ("The server is already in use") instead of kicking them out |
| Free the lock when someone forgets | `IDLE_TIMEOUT` (default 15 min) drops an idle viewer |
| Only the provider's site | Chromium managed policy: `URLBlocklist: ["*"]` plus `URLAllowlist` from `ALLOWED_HOSTS` |
| No downloads, printing, DevTools, incognito, extensions | Chromium managed policies in `chromium/policies/` (root-owned; the user cannot change them) |
| No copy-out / paste-in, no file transfer | My Bastion `clipboard` and `file_transfer` policies on the entry (see [Policies](../../docs/policies.md#clipboard-and-file-transfer)) |
| Who may use it, approval to start a session | My Bastion `connect` policies, approvals in the web UI or Telegram |

## Quick start

Run these on the host where guacd runs, so VNC never leaves the machine.

### 1. Start the container

```bash
cd contrib/guarded-apps
printf 'Ab3xY9qz' > vnc_password.txt      # VNC passwords are max 8 characters
chmod 600 vnc_password.txt
# Edit docker-compose.yml: START_URL and ALLOWED_HOSTS for your provider
docker compose up -d --build
```

### 2. Add it to My Bastion

As an admin, create a connections entry, for example in a folder
`guarded-apps`:

| Field | Value |
|-------|-------|
| Type | `vnc` |
| Name | `provider-portal` |
| Hostname | `127.0.0.1` |
| Port | `5901` |
| Password | the VNC password from step 1 |

### 3. IT logs in to the provider once

Connect to the entry yourself, sign in to the provider portal with the
shared account and complete its 2FA. Chromium keeps the session in the
`/data` volume, so it survives container restarts. When the provider's
session expires, an admin logs in again the same way.

Then change the provider password to one only IT knows, and move the
provider's 2FA to a device or authenticator only IT holds.

### 4. Policies

In **Admin → Policies**, for the `guarded-apps` folder (or the one entry):

- `connect`: allow the group of people who may use the portal; optionally
  require approval
- `clipboard` `out` and `file_transfer`: deny, so nothing leaves the session
- `clipboard` `in`: allow or deny as the job needs

See [Policies and approvals](../../docs/policies.md).

### 5. Sign-in

Use My Bastion's OIDC sign-in with your identity provider (for example
Google Workspace), see [Roles & access control](../../docs/roles-and-access-control.md).
You can also put My Bastion behind a Cloudflare Tunnel with Cloudflare Access
as an extra layer, so it is never exposed directly.

## Customising

Everything is meant to be changed for your app. Copy this folder or the
compose service, one container per guarded app, each on its own port
(5901, 5902, …) and its own volume.

### Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `START_URL` | (required) | Page Chromium opens |
| `ALLOWED_HOSTS` | host of `START_URL` | Comma-separated hosts the browser may reach; subdomains included. Add the provider's login/SSO and CDN hosts if pages break |
| `VNC_PASSWORD` / `VNC_PASSWORD_FILE` | (required) | VNC password, max 8 characters |
| `GEOMETRY` | `1600x900` | Screen size |
| `IDLE_TIMEOUT` | `900` | Seconds before an idle viewer is dropped; `0` = never |
| `ALLOW_UPLOADS` | `false` | `true` lets the page open a file picker |

### Chromium policies

`chromium/policies/*.json` are copied into Chromium's managed policy folder
at start-up; the URL lists are generated into `90-guarded-urls.json`. Add or
edit JSON files there and rebuild. Policy names are in the
[Chrome Enterprise policy list](https://chromeenterprise.google/policies/).

Notes:

- `DefaultClipboardSetting: 2` only stops *web pages* reading the clipboard
  through scripts. Real copy/paste control is My Bastion's clipboard policy.
- Avoid setting the same policy in two files; Chromium does not define which
  one wins.

### Another browser or app

`chromium/` is the default. Anything that draws on an X display works the
same way: replace the Chromium loop in `entrypoint.sh` with your program and
keep Xvnc as it is.

## Security notes

- **VNC is unencrypted.** Publish the port on `127.0.0.1`, or a private
  network to guacd, never on a public interface.
- **The `/data` volume holds the logged-in provider session** (cookies).
  Treat it like a credential: restrict the Docker host and any backups.
- **Chromium's sandbox** needs the seccomp profile from
  `contrib/docker/seccomp-chromium.json` (already set in the compose file).
  See [Running under Docker](../../docs/web-sessions.md#running-under-docker).
- The provider still sees one account. The "who" comes from My Bastion's
  audit and recordings, so keep recording on for this folder.

## Known limitations

- A refused second user sees a generic connection error, not "in use by
  Ali since 12:30".
- Blocking specific buttons, pages or requests inside the portal for some
  roles is not there yet (see below).

## Roadmap (needs My Bastion code)

1. **"In use by" lock.** My Bastion tracks who holds a guarded app and tells
   the next person, with an admin "take over".
2. **In-app rules through the Chrome DevTools Protocol.** My Bastion connects
   to the container's Chromium over CDP (localhost or a pipe, never exposed)
   and enforces rules per role:
   - match a **page** (URL pattern), a **request** (method + URL) or an
     **element** (CSS selector / button text);
   - action: `allow`, `block`, `approve` (held until a supervisor approves in
     the web UI or Telegram) or `otp` (step-up sign-in);
   - an approval unlocks the rule for a few minutes or one use, and is
     audited as "Ali did X, approved by Siti".

   CDP's `Fetch` domain can *pause* a request while the approval is pending,
   which a browser extension cannot. This needs DevTools access for the
   controller, so `DeveloperToolsAvailability` will have to change from `2`
   once CDP is used; the user still has no way to open DevTools in kiosk mode.
3. **Watermark** with the user's email and time over the session.

Example of the planned rules (not implemented):

```yaml
rules:
  - name: Settings pages
    match: { page: "/settings/*" }
    allow: [supervisor]
    else: block

  - name: Cancel order
    match:
      request: "POST /api/orders/*/cancel"
      element: "button:has-text('Cancel order')"
    allow: [supervisor]
    else: approve
    unlock: { minutes: 5 }

  - name: Export data
    match: { request: "GET /api/export*" }
    else: otp
    unlock: { uses: 1 }
```
