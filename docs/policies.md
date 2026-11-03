# Policies and approvals

Policies decide who may connect where: allow, deny, or wait for someone to
approve. They apply to every way of starting a session (the Connect buttons,
ad-hoc connections, quick-connect links and `POST /api/sessions`), to users
and to API keys alike. With no policies, every connect is allowed as before.

Manage them on the **Admin** page under **Policies**. Requests waiting for a
decision are on the **Approvals** page, which every signed-in user can open.

## Rules

A rule has:

| Part | Values |
|---|---|
| **Who** | `anyone`, a `user` (login email), a `group` (OIDC group), a `role` (exactly that role), or an `api_key` (by name) |
| **Target** | `anything`, a `folder` (and everything under it), or one `entry`, each in the `shared` or `instance` scope |
| **Action** | `connect`, or `ssh_command` (one command run through the bastion, see below). Clipboard and file transfer come in a later release |
| **Commands** | for `ssh_command`: regular expressions, matched anywhere in the command line; the rule applies to commands any of them matches (none: every command) |
| **Effect** | `allow`, `deny`, `require_approval`, or `allow_and_alert` |
| **Approvers** | for `require_approval`: `role:<role>` (that role or higher) and/or `group:<group>` |
| **Grant / timeout** | minutes an approval lets the requester in (default 60), and minutes a request waits before it expires (default 30) |

How a connect is decided:

1. A **deny** on any matching rule always wins.
2. Otherwise the **most specific** matching rule decides: an entry beats a
   folder, a deeper folder beats a shallower one, and a folder beats
   `anything`. Between rules with the same target, a user or API key beats a
   group, which beats a role, which beats `anyone`; then a command rule with
   patterns beats one without.
3. Between equally specific rules, the stricter effect wins.
4. If **no rule matches**, the connect is allowed.

Ad-hoc connections are matched only by rules whose target is `anything`.

## Command mode (`ssh_command`)

Instead of an interactive terminal, a user (operator or above) or an
automation can run **one command** on a saved SSH entry through the bastion:

```
POST /api/addressbook/folders/{scope}/{folder}/entries/{entry}/run
{"command": "systemctl status nginx", "timeout_secs": 60}
```

The command is checked against `ssh_command` policies before anything is
read or dialled, so a denied command never reaches the target. It then runs
over SSH with the entry's credentials (folder defaults and credential
variables apply), through its jump hosts if it has any, and the answer has
`stdout`, `stderr`, `exit_status`, `timed_out` and `truncated` (output is
kept to 1 MiB per stream; `timeout_secs` is 1–600, default 60). Without
jump hosts the target must be in `ssh_allowed_networks`, as for a session.

- A denied command answers **403** naming the policy.
- A command that needs approval answers **202** with the request, which
  shows the command to the approvers. The approval covers **that exact
  command** for the grant window; any other command needs its own.
- Every command that runs is in the policy audit log with its exit status
  (`command_run`; `command_failed` when it could not be run). Output is
  never logged.

Example rules: deny `rm\s+-rf\s+/(\s|;|$)` and `^\s*(shutdown|reboot)\b`
everywhere, and require approval for `^sudo\b` in `prod`.

**Patterns are a guard, not a sandbox.** A command can be written in many
ways (`bash -c`, variables, base64, a script on the target), so a list of
forbidden patterns stops mistakes, not a determined user. For real control
use an allowlist: a rule that requires approval for (or denies) every
command, plus allow rules for the exact commands people need. Commands are
one line; control characters are refused.

## Approvals

When a rule requires approval, the connect does not start a session. The
user sees **Approval required** with the policy and the target, can add a
reason for the approvers, and waits. Approvers see the request on the
**Approvals** page with the requester, the target, the policy and the
reason, and approve or deny it with an optional comment.

- **Nobody approves their own request**, whatever their role. API keys can
  request but never decide.
- An approval lets the requester connect to that target for the rule's grant
  window, so a dropped connection needs no new approval.
- A request nobody decides **expires** after the rule's timeout.
- Connecting again while a request waits reuses it rather than opening
  another. The requester can withdraw it.

## Audit log

The **Policy Audit Log** on the Admin page records every decision with the
requester and, where there is one, the approver: denials, new requests,
approvals and denials by an approver, expiry, withdrawal, use of an approval,
`allow_and_alert` connects, and every policy change.

## API

| Method | Path | Who | |
|---|---|---|---|
| GET, POST | `/api/admin/policies` | admin | list, create |
| PUT, DELETE | `/api/admin/policies/{id}` | admin | replace, delete |
| GET | `/api/admin/policy-audit?limit=N` | admin | newest first |
| GET | `/api/approvals` | anyone | `to_decide`, `mine`, and `recent` (admins) |
| GET | `/api/approvals/{id}` | requester, approvers, admins | one request |
| POST | `/api/approvals/{id}/reason` | requester | `{"reason": "..."}` |
| POST | `/api/approvals/{id}/approve`, `/deny` | approvers | `{"comment": "..."}` |
| POST | `/api/approvals/{id}/cancel` | requester | withdraw |
| POST | `/api/addressbook/folders/{scope}/{folder}/entries/{entry}/run` | operator+ | run one command (see Command mode) |

A connect held for approval answers **202** with
`{"approval_required": true, "approval": {...}}`; a denied one answers
**403** naming the policy. A quick-connect link held for approval redirects
to `/connections.html#approval=<id>`, which shows the request.

A policy, as the API takes it:

```json
{
  "name": "contractors to prod",
  "subject": { "kind": "group", "value": "contractors" },
  "target": { "kind": "folder", "scope": "shared", "path": "prod" },
  "action": "connect",
  "effect": "require_approval",
  "approvers": [{ "kind": "role", "value": "admin" }],
  "grant_minutes": 60,
  "timeout_minutes": 30,
  "enabled": true
}
```
