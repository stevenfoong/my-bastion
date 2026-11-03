#!/usr/bin/env bash
#
# Live check of the policy and approval engine (Phase 2a): a policy
# "group contractors -> folder prod -> connect = require_approval(admin)"
# holds a contractor's connect until an admin approves it, an approval lets
# them in for the grant window, self-approval is refused, a deny rule wins,
# an undecided request expires, and every step is in the policy audit log.
#
# Uses user API tokens for the people involved, with OIDC groups written
# straight into the users table (no identity provider needed). A connect
# that passes the policy may still fail to reach guacd here; the check is
# only that the policy let it through (not 202, not 403).
#
# Usage: ./tests/test_policy_approval.sh   (PORT=18091 by default)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18091}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-policy.XXXXXX)
PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

mkdir -p "$W/rec"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/kek"
cat > "$W/config.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
db_path = "$W/mybastion.db"
static_path = "$PWD/static"
recording_path = "$W/rec"

[storage]
path = "$W/secrets.db"
kek_source = "file:$W/kek"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
for u in "contractor@example.com operator contractors" \
         "lead@example.com admin contractors" \
         "boss@example.com admin staff"; do
    set -- $u
    CLI add-user --email "$1" --role "$2" >/dev/null
done
python3 - "$W/mybastion.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
for email, groups in [("contractor@example.com", "contractors"),
                      ("lead@example.com", "contractors"),
                      ("boss@example.com", "staff")]:
    c.execute("UPDATE users SET oidc_groups = ? WHERE email = ?", (groups, email))
c.commit()
PY

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
token() {
    curl -s -H "$A" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"name\":\"policy-test\"}" "$U/api/admin/user-tokens" | json 'd["token"]'
}
C="Authorization: Bearer $(token contractor@example.com)"
L="Authorization: Bearer $(token lead@example.com)"
B="Authorization: Bearer $(token boss@example.com)"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
connect() { post "$1" "/api/addressbook/folders/shared/$2/entries/web01/connect" '{}'; }

# A folder tree and an entry in each folder.
for f in prod prod%2Fsecret lab; do
    name=$(python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "$f")
    post "$A" /api/addressbook/folders "{\"name\":\"$name\",\"allowed_groups\":[\"contractors\",\"staff\"],\"inherit_from_parent\":true}" >/dev/null
    post "$A" "/api/addressbook/folders/shared/$f/entries" '{"name":"web01","type":"ssh","hostname":"127.0.0.1","port":22}' >/dev/null
done

echo "== policies"
check "$(post "$A" /api/admin/policies '{"name":"contractors to prod","subject":{"kind":"group","value":"contractors"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"connect","effect":"require_approval","approvers":[{"kind":"role","value":"admin"}],"grant_minutes":60,"timeout_minutes":1,"enabled":true}')" 201 "create require-approval policy"
check "$(post "$A" /api/admin/policies '{"name":"nobody in prod/secret","subject":{"kind":"group","value":"contractors"},"target":{"kind":"folder","scope":"shared","path":"prod/secret"},"action":"connect","effect":"deny","approvers":[],"grant_minutes":60,"timeout_minutes":30,"enabled":true}')" 201 "create deny policy"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"role","value":"superuser"},"target":{"kind":"any"},"action":"connect","effect":"allow","approvers":[],"grant_minutes":60,"timeout_minutes":30,"enabled":true}')" 400 "invalid policy refused"

echo "== the connect is held for approval"
check "$(connect "$C" prod)" 202 "contractor connect to prod waits"
REQ=$(json 'd["approval"]["id"]' < "$W/out.json")
check "$(connect "$C" prod; json 'd["approval"]["id"]' < "$W/out.json")" "202$REQ" "a retry reuses the same request"
check "$(post "$C" "/api/approvals/$REQ/reason" '{"reason":"patching web01"}')" 204 "requester adds a reason"
check "$(connect "$C" lab)" "$(connect "$B" lab)" "outside prod the policy does not apply"
check "$(connect "$B" prod | grep -c 202)" 0 "staff are not held"
check "$(connect "$C" prod%2Fsecret)" 403 "deny rule wins below prod"

echo "== deciding"
check "$(post "$C" "/api/approvals/$REQ/approve")" 403 "requester cannot approve own request"
check "$(connect "$L" prod)" 202 "lead (admin, contractor) is held too"
LREQ=$(json 'd["approval"]["id"]' < "$W/out.json")
check "$(post "$L" "/api/approvals/$LREQ/approve"; json 'd["error"]' < "$W/out.json")" "403you cannot approve or deny your own request" "self-approval refused, even for an admin"
check "$(post "$A" "/api/approvals/$REQ/approve")" 403 "an API key cannot approve"
check "$(curl -s -H "$B" "$U/api/approvals" | json 'sorted(r["id"] for r in d["to_decide"]) == sorted(["'"$REQ"'","'"$LREQ"'"])')" True "approver sees both waiting requests"
check "$(post "$B" "/api/approvals/$REQ/approve" '{"comment":"ok for today"}'; json 'd["status"]' < "$W/out.json")" "200approved" "admin approves"
check "$(post "$B" "/api/approvals/$REQ/deny")" 409 "a decided request stays decided"
code=$(connect "$C" prod)
check "$([ "$code" != 202 ] && [ "$code" != 403 ] && echo through || echo "held ($code)")" through "approved contractor gets through"

echo "== quick connect redirects to the waiting request"
check "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "$L" "$U/api/connect?scope=shared&folder=prod&entry=web01" | sed "s#$U##")" "307 /connections.html#approval=$LREQ" "quick connect sends the browser to the request"

echo "== an undecided request expires"
for _ in $(seq 20); do
    st=$(curl -s -H "$L" "$U/api/approvals/$LREQ" | json 'd["status"]')
    [ "$st" = expired ] && break
    sleep 5
done
check "$st" expired "lead's request expired after its 1-minute timeout"

echo "== audit"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='requested' and r['requester']=='contractor@example.com'")" True "request is audited"
check "$(has "r['event']=='approved' and r['actor']=='boss@example.com' and r['requester']=='contractor@example.com'")" True "approval is audited with requester and approver"
check "$(has "r['event']=='allowed_by_grant' and r['requester']=='contractor@example.com'")" True "use of the grant is audited"
check "$(has "r['event']=='denied' and r['policy']=='nobody in prod/secret'")" True "deny is audited"
check "$(has "r['event']=='expired' and r['requester']=='lead@example.com'")" True "expiry is audited"

[ "$FAILED" = 0 ] && echo "PASS" || echo "FAILED"
exit "$FAILED"
