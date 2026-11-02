<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# Credential Variables

Credential variables let connections entries reference shared credentials by name instead of storing passwords directly. Users maintain their own credential values in Vault via the **My Credentials** dialog (the **Credentials** link in the top navigation, or the gear menu). When a session launches, My Bastion substitutes the variables from the user's saved values.

This gives a similar experience to LDAP credential passthrough in Apache Guacamole — users log in once and sessions just work — without My Bastion needing to bind to LDAP. Credentials stay in Vault, never on disk or in the browser.

## How it works

1. **Admin** creates connections entries with variable references like `$corp_username` and `$corp_password` in the credential fields
2. **Users** open **My Credentials** from the gear menu and fill in their values (stored per-user in Vault)
3. **At connect time**, My Bastion substitutes the variables. If all are set, the session launches silently. If any are missing, the user is prompted.

## Variable naming

Variables start with `$` and use the pattern `$<domain>_<suffix>`:

| Pattern | Purpose | Input type |
|---------|---------|------------|
| `$<domain>_username` | Username | Text |
| `$<domain>_password` | Password | Password (masked) |
| `$<domain>_domain` | AD/Windows domain | Text |
| `$<domain>_key` | SSH private key | Textarea |

The `<domain>` is a logical name chosen by the admin to group related credentials — for example `corp`, `jumpcloud`, `lab`, or `cloud-prod`. Multiple entries can reference the same domain, so users only configure their credentials once.

**Allowed characters:** lowercase letters, numbers, underscores, and hyphens. For example: `$corp_username`, `$jump-host_password`, `$cloud-prod_key`.

## Example

An admin creates two connections entries:

- **Production SSH** — username: `$corp_username`, password: `$corp_password`
- **Staging SSH** — username: `$corp_username`, password: `$corp_password`

Both reference the same `corp` domain. A user opens **My Credentials**, fills in their `corp` username and password once, and both entries work without further prompting.

An entry can also mix variables with static values. For example, an RDP entry might have a static hostname and port but use `$ad_username`, `$ad_password`, and `$ad_domain` for credentials.

## Importing from Guacamole

When migrating from Apache Guacamole, the `import-guacamole` command can convert Guacamole's `${GUAC_USERNAME}` / `${GUAC_PASSWORD}` passthrough tokens directly into credential variables with its `--map` flag, so imported connections arrive already wired to My Credentials. See [Mapping credential tokens](migration.md#mapping-credential-tokens).

## Where variables can be used

Credential variables are expanded at connect time in the following entry fields:

| Field | Applies to | Notes |
|-------|------------|-------|
| `username` | SSH, RDP, VNC, Web | Authentication username for the target |
| `password` | SSH, RDP, VNC, Web | Authentication password for the target |
| `domain` | RDP | AD/Windows domain |
| `private_key` | SSH | SSH private key contents |
| `container_username` | VDI | Username used to log into the VDI container (only when set on the entry; otherwise auto-derived from the operator identity) |
| `container_password` | VDI | Password used to log into the VDI container (only when set on the entry; otherwise ephemerally generated) |

VDI entries that auto-derive credentials (the default for images that honour `VDI_USERNAME`/`VDI_PASSWORD`) do not need credential variables. They only apply when an admin has set explicit `container_username` / `container_password` overrides for an image with a baked-in account.

### Ad-hoc connections

**Connect to a host** (beside the search box on every page) (poweruser and up) accepts your own variables in its credential fields, so an SSH key you use everywhere is one pick rather than a paste: choose `$my_ssh_key` from the list under the private key field, or type a name the username field suggests. Only the variable names reach the browser; the server resolves them from your My Credentials when connecting, exactly as for a saved entry, and a name you have not set is reported before anything connects.

Only your own variables are used, and folder default credentials never apply (an ad-hoc connection has no folder). Variables in jump host credentials are not resolved. An admin who saves an ad-hoc connection as an entry (**Save as entry**) saves the `$name` references, not the values. `POST /api/sessions` does not resolve variables; see [`POST /api/addressbook/adhoc/connect`](api.md#post-apiaddressbookadhocconnect).

## My Credentials dialog

Open it from the **Credentials** link in the top navigation bar, or from the
gear menu. The dialog:

- Shows all credential variables used across entries the user has access to
- Groups variables by domain prefix, with each group collapsible
- Provides a filter box (shown once the list is long) to find a variable by name or domain
- Indicates how many entries use each variable
- Masks password and key fields (saved values are not shown, but a placeholder confirms they exist)
- Scrolls its body while the title and the Save/Close buttons stay pinned, so it stays usable with many variables
- Supports partial saves: fill in what you have now, come back later for the rest

### Finding what needs setting up

The Connections page surfaces missing credentials before a connection fails:

- A **"credentials needed"** pill marks entries that reference a variable you have not set yet.
- A dismissible banner reports how many credentials are still to set up. The dismissal is remembered across refreshes and only reappears if a genuinely new unset credential shows up.

## Graceful degradation

- **All variables set:** the session launches immediately, no prompting.
- **Some missing:** the connect opens My Credentials focused on just the missing variables, and the connection resumes automatically once you save them.
- **None set:** full credential prompt (same as entries without variables).

## Vault storage

User credentials are stored in Vault KV v2 at:

```
<base_path>/users/<sanitized_email>
```

Each user gets a single Vault secret (per backend) containing their credential key-value pairs. Variable names are the keys, plaintext values are the values. The Vault policy must allow read/write to this path for authenticated users.

With multiple Vault backends configured, a user's credentials are split by scope: local credentials live at this path in the local backend, shared credentials at the same path in the shared backend. The `users/*` policy is needed on whichever backends hold credentials.

### Required Vault policy

In addition to the existing connections policy, add:

```hcl
# User credential variables (read/write own credentials)
path "secret/data/mybastion/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/mybastion/users/*" {
  capabilities = ["list", "read", "delete"]
}
```

## API endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/api/me/credentials` | operator+ | List own saved variables (passwords masked) |
| `PUT` | `/api/me/credentials` | operator+ | Save/update own variables |
| `GET` | `/api/credential-variables` | operator+ | List all variables used across accessible entries |

## Folder default credentials

A folder can lend credentials to entries that have none of their own, per session type. An entry created without secrets (a NetBox webhook, a bulk import) is then connectable the moment it exists, with no second pass to fill it in. Admins set them from the folder dialog in Connections ("Default credentials") or with the `/api/addressbook/folders/:scope/:folder/defaults` endpoints (see [API reference](api.md)).

### Where they live

Defaults are stored in Vault at `<folder>/.defaults`, beside the folder's `.config`:

```
<base_path>/shared/<folder>/.config      access settings
<base_path>/shared/<folder>/.defaults    default credentials, keyed by session type
```

```json
{
  "ssh": { "username": "root", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..." },
  "web": { "password": "router-password" }
}
```

Each type can carry `username`, `password`, `private_key` and `domain`. A type with no password or private key lends nothing (a username alone cannot authenticate). The existing connections Vault policy covers this path; no policy change is needed. `.defaults` is a reserved name, like `.config`: it is never listed as an entry and an entry cannot be called that.

### How they apply

At connect time, an entry with no password or private key of its own, and not set to `prompt_credentials`, takes the defaults for its session type. The entry's own `username` and `domain` win when set; otherwise the defaults' values fill them. An entry with its own secret is never touched, and an entry set to prompt still prompts. This happens on both connect paths, the Connections page (`POST .../entries/:entry/connect`) and quick-connect links (`GET /api/connect?scope=...&folder=...&entry=...`), through the same resolver, so an entry that works from the page works from a link.

Entries covered by defaults list with `has_credentials: true` and `inherited_credentials: true`, and show a `[folder]` marker in Connections.

A default password or username can be a credential variable such as `$tenant_password`. Defaults are applied before variables are resolved, so each user connects with their own value from My Credentials. The "credentials needed" marker in Connections only checks an entry's own fields, so it won't flag a variable that comes from a folder default.

### Inheritance and the `inherit_from_parent` boundary

A subfolder without its own `.defaults` uses its nearest ancestor's, per session type: the nearest folder on the path wins for each type, and a type it lacks comes from the next folder up.

A parent's defaults reach a subfolder only when exactly the parent's audience can open it: the subfolder's `.config` has `inherit_from_parent: true` and grants no `allowed_groups` or `allowed_users` of its own. The walk up the tree stops at any other folder:

- A folder with `inherit_from_parent: false` is isolated for access (see [Roles and access control](roles-and-access-control.md#inheritance)), so its parent's defaults do not flow into it.
- A folder that inherits but also grants groups or users of its own admits people the parent doesn't (access is the union of both), so its parent's defaults do not flow into it either. Otherwise a contractor added to `corp/partner` through `allowed_users` could connect with `corp`'s key.

The folder where the walk stops still applies its own `.defaults` to its entries and to subfolders that share its audience. A folder with no `.config`, or one written before the flag existed, counts as not inheriting, exactly as the access check treats it.

### Migration between stores

`mybastion storage migrate` copies every document, so each folder's `.defaults` travels with its `.config`. Deleting a folder removes its `.defaults` with it.

### Web entries: the password is visible to the user

A **web** entry with a default password has that password typed into the page by the login autofill, the same as a web entry with its own stored password. The user can read it from the page (a show-password toggle, the browser's developer tools, a form that echoes it). Treat a web default as shared with everyone who can connect through that folder, and prefer per-entry or per-user credentials (`$variables`) where the password must stay secret. SSH, RDP and VNC defaults are passed to guacd and never reach the browser.
