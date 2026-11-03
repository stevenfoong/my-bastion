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

Desktop tools (open a session, screenshot, click, type) come next.

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
