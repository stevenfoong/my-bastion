<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# Screenshot environment

Rebuilds the images in [`screenshots/`](../../screenshots/) from scratch: a
fresh My Bastion with the default title, logo and theme, loaded with fictional
data, captured with a headless browser. Run it for each release so the
screenshots keep matching what a new install shows.

## What it runs

`compose.yaml` starts everything on a private compose network. No ports are
published on the host.

| Service | Image | Role |
|---------|-------|------|
| `mybastion` | `ghcr.io/stevenfoong/mybastion` | The server, with `config.toml` from this folder |
| `mybastion-init` | `ghcr.io/stevenfoong/mybastion` | Adds the first admin (`alex@example.com`) with `mybastion add-user` |
| `openbao`, `openbao-init` | `openbao/openbao` | OpenBao in dev mode, with the My Bastion policy and AppRole |
| `oidc` | `ghcr.io/navikt/mock-oauth2-server` | OIDC provider whose login form accepts any user and claims |
| `ssh` | built from `targets/ssh` | SSH host for every demo host name, with idle placeholder services |
| `web` | `nginx` | A static service status page at `status.example.internal` |
| `capture` | built from `capture/` | Seeds the data, then takes the screenshots with Playwright |

The capture service signs in as the admin, creates the users, folders,
entries, credential variables and API tokens through the My Bastion API, and
signs each user in once through the mock provider so their groups and last
login are set. It then runs a few real SSH and Web sessions, which produce
the recordings and the session history, and leaves four sessions open for
the Sessions page and the two live views. Nothing is written to the database
directly.

All data is reserved example data: users are `@example.com`, hosts are
`*.example.com`, `*.example.net` or `*.example.internal`, and addresses come
from 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. Only the Production
and Staging SSH entries and the status page are ever connected to; they
reach the `ssh` and `web` containers through network aliases.

## Usage

Requires Docker with Compose v2. A run takes about six minutes.

```sh
cd contrib/screenshots
docker compose up -d --build
docker compose run --rm capture
docker compose --profile capture down -v
```

The PNGs land in `out/`, in the same layout as `screenshots/`: the default
**aurora** theme at the top level and the page views again under `light/`.
Copy them over and check every image before committing:

```sh
cp -R out/. ../../screenshots/
```

The capture refuses to run against a My Bastion that already has data, so
always start from a clean stack (`down -v`). Optionally compress the images
with [oxipng](https://github.com/shssoichiro/oxipng) (`oxipng -o 4 --strip
safe out/*.png out/light/*.png`).

## Settings

Set these in the environment or in a `.env` file next to `compose.yaml`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `MYBASTION_IMAGE` | `ghcr.io/stevenfoong/mybastion:1.12.1` | The My Bastion image to capture. Build this tree with `docker build -t mybastion:dev .` and set `MYBASTION_IMAGE=mybastion:dev` to capture unreleased changes |
| `THEMES` | `aurora,light` | Themes to shoot the page views in. The first goes to `out/`, the rest to `out/<theme>/` |
| `OPENBAO_VERSION` | `2.7.1` | OpenBao image tag |
| `MOCK_OAUTH2_SERVER_VERSION` | `2.1.10` | Mock OIDC provider image tag |
| `PLAYWRIGHT_VERSION` | `1.48.2` | Playwright image and npm package; the two must match |
| `NGINX_VERSION` | `1.27-alpine` | nginx image tag for the status page |
| `ALPINE_VERSION` | `3.20` | Base of the SSH target |

## Notes

- **Seccomp:** the `mybastion` service runs with
  `security_opt: seccomp=unconfined`, because Chromium's sandbox for Web
  sessions needs namespace syscalls that Docker's default profile blocks
  (#307). This is a throwaway local environment; do not copy the setting to
  a deployment without reading [Security](../../docs/security.md).
- **History is short:** Reports and Recordings show only the sessions the
  run made, all from the last few minutes, so the totals are small. Dates
  and times are those of the run.
- **Names:** the admin's email is set in both `compose.yaml`
  (`mybastion-init`) and `capture/seed.mjs`. Change both together.
- **Fonts:** the UI uses the generic `monospace` font. The capture image
  installs DejaVu Sans Mono, the usual Linux default, so the pages look as
  they do on a typical desktop.
- **What each image shows** is described in
  [screenshots.md](../../screenshots/screenshots.md). Update it when a view
  changes.
