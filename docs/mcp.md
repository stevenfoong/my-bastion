# AI agents (MCP)

My Bastion has an MCP endpoint at `/mcp` (Streamable HTTP) so AI agents can
use connections under the same policies, approvals and audit log as people.
It is **off** unless the config says otherwise:

```toml
[mcp]
enabled = true
```

## Agent keys

An unattended agent (a script, a scheduled job, Claude Code) gets its own
key and acts as `ai:<name>`:

```
mybastion add-ai-agent --name nightly-patch [--folders shared/lab,shared/dev] \
    [--allowed-ips 10.0.0.0/8] [--expires 2027-01-01]
```

or on the Admin page under **AI Agents**. The key (`mbai_…`) is shown once.
The agent sends it as `Authorization: Bearer <key>` on `/mcp`.

- An agent key works **only** on `/mcp`, and `/mcp` takes **only** agent
  keys: admin keys, user tokens and session cookies are refused there, and
  agent keys are refused on every REST and admin route.
- `--folders` narrows the agent to those folders (each with everything under
  it). Without it, the agent reaches every folder whose AI mode lets agents
  in.
- Keys are stored hashed, with optional IP allowlists and expiry. Disable or
  delete a key on the Admin page; it stops working at once.

## Folder AI mode

Each folder has an **AI agents** setting (folder dialog on the Connections
page; `ai_mode` in the folder API). Subfolders that leave it unset follow
their parent; the default at the top is `none`.

| Mode | Agents may |
|---|---|
| `none` | nothing: the folder does not exist for them |
| `observe` | list its connections (and, later, take screenshots) |
| `approve` | act, but every action waits for a person's approval |
| `auto` | act as far as the policies allow; everything is recorded |

In `approve` mode an action becomes an approval request (policy "AI approve
mode", approvers: admins) on the Approvals page and in Telegram. The
approval covers that exact action for an hour; the agent repeats it once
approved.

Policies apply to agents in every mode. A policy subject `ai_agent` matches
one agent by name, or every agent with `*`; `anyone` rules match agents too.
A deny still wins.

## Tools

| Tool | |
|---|---|
| `list_connections(folder?)` | Connections in the folders the agent reaches: id (`scope/folder/entry`), type, host, port, the folder's AI mode. Never credentials. |
| `run_ssh(connection, command, timeout_secs?)` | One command on an SSH connection, with the same checks as the REST `run` route: `ssh_command` policies, approvals, `ssh_allowed_networks`, jump hosts. Needs mode `approve` or `auto`. |
| `open_session(connection, width?, height?)` | Open an RDP, VNC or SSH session (default 1280×800). Connect policies and approvals apply; any mode but `none` may open one to look. Waits for the first frame; answers the `session_id` and screen size. |
| `screenshot(session_id, max_width?)` | The screen as a PNG, scaled down to `max_width` (default 1280), with the screen's and the image's size. |
| `wait(session_id, ms?)` | Returns when the screen next changes, or after `ms` (at most 10000). |
| `list_sessions()` | The agent's open sessions. |
| `close_session(session_id)` | Ends the session. |
| `click(session_id, x, y, button?, double?)` | Click at x, y in the coordinates of the agent's last screenshot of that session (mapped back to the screen). |
| `type_text(session_id, text)` | Types the text (up to 4000 characters; `\n` is Enter). |
| `key(session_id, combo)` | A key or combination: `enter`, `esc`, `f5`, `ctrl+c`, `alt+f4`, `win+r`, `ctrl+alt+del`, … |
| `scroll(session_id, x, y, dy)` | Turns the wheel at x, y; `dy` > 0 scrolls down. |

### Input

Every input is checked when it is sent, not when the session opened:

- The folder's AI mode must be `approve` or `auto` now: `observe` refuses
  input, and an admin who changes a folder's mode changes what agents
  already in a session may do.
- Policies with the action `input` apply (for example: deny `ai_agent *`
  input in `prod`, while still letting agents look).
- In `approve` mode each input becomes an approval request showing exactly
  what will be typed, clicked or pressed; the approval covers that exact
  input for an hour, and the agent sends it again once approved.
- Each input is in the policy audit log as `ai_input`: the kind, where it
  clicked, which keys, how many characters were typed, but not the text
  (`[mcp] log_typed_text = true` keeps it). The session recording shows
  everything.

## Safety

- **Recording** is always on for AI sessions, whatever the entry says.
- **Rate limits** per agent: input at 5 per second (bursts of 20),
  screenshots at 2 per second (bursts of 10).
- **Clipboard**: agents have none; the bastion never sends or reads the
  session clipboard for them.
- **Kill switch**: Admin page → AI Agents → *End all AI sessions*
  (`POST /api/admin/ai-sessions/kill`), optionally disabling every agent key
  too. It is audited (`ai_kill_switch`). `GET /api/admin/ai-sessions`
  lists what agents have open; the Sessions page marks their sessions
  **AI**, and admins can shadow or terminate them like any other.

### Sessions

The bastion is the session's Guacamole client: it takes the guacd connection
as the owner the moment the session is created, keeps the screen from
guacd's drawing instructions (images, rectangles, copies, layers), answers
its frame syncs, and draws a screenshot from that. Nothing on the screen
leaves the bastion except as a screenshot the agent asks for.

- A session is like any other: it shows on the Sessions page with
  `created_by` `ai:<name>`, admins can share, shadow or terminate it, it is
  recorded under `ai:<name>` when recording is on, and it ends with
  `close_session`, a terminate, or the remote side.
- Only the agent that opened a session can use it. An agent has at most 5
  sessions open; one left unused for 15 minutes is closed.
- The mouse pointer is not drawn in screenshots.

A refusal (policy, AI mode, unknown connection) or a wait for approval is a
tool error the model reads, with the reason. Everything is in the policy
audit log under `ai:<name>`: commands run (`command_run`), denials, approval
requests and decisions, and key changes (`ai_agent_created`, …).

## Connecting a client

Claude Code, for example:

```
claude mcp add --transport http mybastion https://bastion.example.com/mcp \
    --header "Authorization: Bearer mbai_..."
```
