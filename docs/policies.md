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
| **Action** | `connect` (clipboard, file transfer and SSH commands come in later releases) |
| **Effect** | `allow`, `deny`, `require_approval`, or `allow_and_alert` |
| **Approvers** | for `require_approval`: `role:<role>` (that role or higher) and/or `group:<group>` |
| **Grant / timeout** | minutes an approval lets the requester in (default 60), and minutes a request waits before it expires (default 30) |

How a connect is decided:

1. A **deny** on any matching rule always wins.
2. Otherwise the **most specific** matching rule decides: an entry beats a
   folder, a deeper folder beats a shallower one, and a folder beats
   `anything`. Between rules with the same target, a user or API key beats a
   group, which beats a role, which beats `anyone`.
3. Between equally specific rules, the stricter effect wins.
4. If **no rule matches**, the connect is allowed.

Ad-hoc connections are matched only by rules whose target is `anything`.

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
