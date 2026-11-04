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
| **Who** | `anyone`, a `user` (login email), a `group` (OIDC group), a `role` (exactly that role), an `api_key` (by name), or an `ai_agent` (an MCP agent key by name, or `*` for every agent; see `docs/mcp.md`) |
| **Target** | `anything`, a `folder` (and everything under it), or one `entry`, each in the `shared` or `instance` scope |
| **Action** | `connect`; `ssh_command` (one command run through the bastion, see below); `clipboard` or `file_transfer` (in a session, see below); `input` (an AI agent's clicks, typing and keys over MCP, see `docs/mcp.md`); `db_query` (a statement through the database proxy, with statement **classes**, see `docs/database-proxy.md`) |
| **Direction** | for `clipboard` and `file_transfer`: `in` (paste, upload to the target), `out` (copy, download from it), or both (unset) |
| **Commands** | for `ssh_command`: regular expressions, matched anywhere in the command line; the rule applies to commands any of them matches (none: every command) |
| **Effect** | `allow`, `deny`, `require_approval`, or `allow_and_alert` |
| **Approvers** | for `require_approval`: `role:<role>` (that role or higher) and/or `group:<group>` |
| **Grant / timeout** | minutes an approval lets the requester in (default 60), and minutes a request waits before it expires (default 30) |
| **Web only** | for `require_approval` on high-risk targets: Telegram only notifies, and approvers decide on the Approvals page after a **fresh sign-in** (within the last 15 minutes; a token or API key never counts) |

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

## Interactive SSH command log

In an interactive SSH session, the WebSocket bridge rebuilds the lines the
user types from their keystrokes and logs each one (Admin page → **SSH
Command Log**, or `GET /api/admin/ssh-commands`), with the user, target and
session. guacd draws the terminal as images, so the bridge sees what is
typed, never what the shell shows: the log is **best-effort**, for review
and alerting, and never blocks anything.

- Line editing is followed: backspace, delete, cursor keys, Home/End,
  Ctrl+A/E/U/K/W/H, and Ctrl+C (the line is dropped). So are pastes
  (Ctrl+Shift+V, or the right or middle mouse button) of text the browser
  sent to the session's clipboard; such lines are marked **pasted**.
- Tab completion, history (Up/Down, Ctrl+R), Alt and Escape sequences change
  the line in ways only the shell knows: the line is marked **uncertain**.
  Full-screen programs (vi, less) are logged as typed.
- Password prompts have no echo and look like any other input. The
  one-word line typed within a minute after a command that usually prompts
  (`sudo`, `su`, `ssh`, `scp`, `mysql`, `psql`, `passwd`, `docker login`, …)
  is not stored: it is logged as **redacted**. Other prompts (a password
  typed into a script, say) are logged as typed: keep that in mind when
  granting access to the log.
- Read-only viewers (share links, shadowing) type nothing and are not
  logged; a viewer with input is logged under their own name.

Each line is also checked against the `ssh_command` rules, as if it were run
in command mode. A line a rule would **deny**, or **hold** by a command
pattern, or that an `allow_and_alert` rule matches, is flagged: an
`ssh_command_alert` row in the policy audit log, a warning in the server
log, and a Telegram message to the `chat_ids`. Rules without command
patterns that require approval do not flag every line; they are about
command mode. Users can hide what they run (aliases, scripts, `bash -c`,
base64), so for real control use command mode, connect approvals and
restrictions on the target.

`[ssh_log]` turns the log off (`enabled = false`) and sets how long lines
are kept (`retention_days`, default 90).

## Clipboard and file transfer

`clipboard` and `file_transfer` rules decide, when a session starts, what it
may do in each direction:

| | `in` (to the target) | `out` (from the target) |
|---|---|---|
| `clipboard` | paste | copy |
| `file_transfer` | upload (RDP drive, SFTP) | download |

Their effect is `allow`, `allow_and_alert` (allowed, and each transfer goes
to the audit log with its file name) or `deny`; they cannot wait for
approval. The usual rules pick the winner, and a rule for one direction
beats a rule for both. Example: deny `clipboard` `out` and `file_transfer`
`out` in `prod`, so nothing leaves it, and audit uploads.

A denied direction is enforced twice: guacd is started with its own switch
off (`disable-copy`, `disable-paste`, `disable-upload`, `disable-download`
and the SFTP equivalents), and the WebSocket bridge drops the instructions
that would carry it, answering the sender with `CLIENT_FORBIDDEN`. With both
upload and download denied, the file browser is hidden. Blocked attempts the
bridge sees are audited (`clipboard_paste_blocked`, `file_download_blocked`,
…); clipboard contents and file data never are.

The controls are fixed when the session starts: a policy change applies to
the next session.

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

## Break-glass

When a policy stops an admin in an emergency (a deny, or an approval nobody
is there to give), they can override it for themself: **Break glass** in the
connect dialog, with a reason.

- It needs the `admin` role, a person (not an API key or token) and a
  **fresh sign-in** on the web UI (within the last 15 minutes).
- The reason is mandatory (at least 10 characters).
- It grants that admin, and nobody else, that entry for **60 minutes**, a
  deny included. Their own requests still waiting for it are withdrawn.
- It is always alerted: a `break_glass` row in the audit log with the
  reason, every use (`allowed_by_break_glass`), a warning in the server log,
  and a Telegram message to the `chat_ids` and every other linked admin.

The API also takes `"action": "ssh_command"` with a `command`, to override a
command policy for that exact command.

## Telegram

With `[telegram]` enabled, a bot posts each approval request (who, the
target, the command if any, the policy and the reason) with **Approve** and
**Deny** buttons:

- to every chat in `chat_ids`, such as an approvers' group, where the edited
  messages double as a log;
- and, with `notify_approvers` (the default), to each linked approver who may
  decide that request.

The messages are edited as the request changes: the reason when the
requester adds one, then who approved or denied it, or that it expired or
was withdrawn. The bot long-polls Telegram, so no port is opened for it.

**Linking.** On the Approvals page an approver presses **Link Telegram** and
sends the one-time code to the bot (`/link CODE`, or the `t.me` link the page
shows) in a private chat. Codes last 10 minutes and work once. `/unlink` in
Telegram, or **Unlink** on the page, removes the link.

**Who can decide from Telegram.** A button press counts only from a linked
account, and only if that user may decide the request by the same rules as
the web UI: an approver, not disabled, and never for their own request.
Requests from a **web-only** policy are sent without buttons and a forged
press is refused. Decisions are in the audit log `via Telegram`.

**Setup.** Create a bot with @BotFather, store its token, and enable it:

```
mybastion secret put mybastion/telegram token=@/root/bot-token
```

```toml
[telegram]
enabled = true
bot_token_path = "mybastion/telegram"   # secret-store path, field "token"
chat_ids = [-1001234567890]             # optional group chats
notify_approvers = true
```

To find a group's chat id, add the bot to the group and read `chat.id` from
`https://api.telegram.org/bot<token>/getUpdates` before enabling My Bastion
(both read the same updates).

## Audit log

The **Policy Audit Log** on the Admin page records every decision with the
requester and, where there is one, the approver: denials, new requests,
approvals and denials by an approver (with `via Telegram` for button
presses), expiry, withdrawal, use of an approval, `allow_and_alert` connects,
Telegram links and unlinks, break-glass overrides and their use, audited or
blocked clipboard and file transfers, flagged interactive SSH commands
(`ssh_command_alert`), and every policy change.

## API

| Method | Path | Who | |
|---|---|---|---|
| GET, POST | `/api/admin/policies` | admin | list, create |
| PUT, DELETE | `/api/admin/policies/{id}` | admin | replace, delete |
| GET | `/api/admin/policy-audit?limit=N` | admin | newest first |
| GET | `/api/admin/ssh-commands` | admin | typed SSH lines, newest first; `session_id`, `q` (search), `alerts=true`, `limit` |
| GET | `/api/approvals` | anyone | `to_decide`, `mine`, and `recent` (admins) |
| GET | `/api/approvals/{id}` | requester, approvers, admins | one request |
| POST | `/api/approvals/{id}/reason` | requester | `{"reason": "..."}` |
| POST | `/api/approvals/{id}/approve`, `/deny` | approvers | `{"comment": "..."}` |
| POST | `/api/approvals/{id}/cancel` | requester | withdraw |
| POST | `/api/addressbook/folders/{scope}/{folder}/entries/{entry}/run` | operator+ | run one command (see Command mode) |
| GET | `/api/telegram` | signed-in users | `enabled`, `bot_username`, and the caller's `linked` account |
| POST, DELETE | `/api/telegram/link` | signed-in users | a new one-time link code (with a `t.me` `url`); unlink |
| POST | `/api/break-glass` | admins (fresh sign-in) | `{"scope", "folder", "entry", "reason"}`, optionally `"action": "ssh_command"` and `"command"` |

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
