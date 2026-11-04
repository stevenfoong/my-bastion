#!/usr/bin/env bash
#
# Live check of Phase 3a: AI agents on /mcp.
#   - only AI agent keys work on /mcp, and they work nowhere else;
#   - list_connections shows the folders whose AI mode lets agents in (and
#     that the key's own folder list reaches), never credentials;
#   - run_ssh runs on the machine's own sshd in an `auto` folder, is refused
#     in `observe` and hidden folders, waits for a person's approval in
#     `approve` (and runs once approved), and policies with an ai_agent
#     subject apply; all of it is in the audit log as ai:<name>;
#   - agent keys from the CLI and the admin API; a disabled key is refused;
#   - saving a folder without ai_mode keeps its mode.
#
# Usage: ./tests/test_mcp_agent.sh   (PORT=18098)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18098}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-mcp.XXXXXX)
MARK="mybastion-mcp-test-$$"
PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -f ~/.ssh/authorized_keys ] && sed -i "/$MARK/d" ~/.ssh/authorized_keys
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

ssh-keygen -q -t ed25519 -N '' -C "$MARK" -f "$W/key"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat "$W/key.pub" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys

mkdir -p "$W/rec"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/kek"
cat > "$W/config.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
db_path = "$W/mybastion.db"
static_path = "$PWD/static"
recording_path = "$W/rec"
ssh_allowed_networks = ["127.0.0.0/8"]

[storage]
path = "$W/secrets.db"
kek_source = "file:$W/kek"

[mcp]
enabled = true
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email boss@example.com --role admin >/dev/null
CLI add-user --email op@example.com --role operator >/dev/null
AGENT=$(CLI add-ai-agent --name nightly | sed -n 's/^Agent Key: //p')
PRODONLY=$(CLI add-ai-agent --name prod-bot --folders shared/prod | sed -n 's/^Agent Key: //p')
check "${AGENT:0:5}" "mbai_" "the CLI prints an agent key"

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
BOSS="Authorization: Bearer $(curl -s -H "$A" -H 'Content-Type: application/json' \
    -d '{"email":"boss@example.com","name":"mcp-test"}' "$U/api/admin/user-tokens" | json 'd["token"]')"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -X "${4:-POST}" -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
mcp() { python3 tests/mcp_call.py "$U/mcp" "$@"; }
tool() {  # key, tool name, arguments JSON
    mcp "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"
}

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
for f in lab:auto prod:approve obs:observe secret:; do
    name=${f%%:*}; mode=${f##*:}
    post "$A" /api/addressbook/folders "{\"name\":\"$name\",\"allowed_groups\":[],\"ai_mode\":\"$mode\"}" >/dev/null
    post "$A" "/api/addressbook/folders/shared/$name/entries" "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null
done

echo "== who may use /mcp"
R=$(mcp "" initialize)
check "$(echo "$R" | json 'd["status"]')" 401 "no key: 401"
check "$(echo "$R" | json '"Bearer" in (d["www_authenticate"] or "")')" True "with WWW-Authenticate"
check "$(mcp "$ADMIN_KEY" initialize | json 'd["status"]')" 401 "an admin key is not an agent key"
check "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $AGENT" "$U/api/addressbook")" 401 "an agent key is refused on REST"
check "$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $AGENT" "$U/api/admin/policies")" 401 "and on admin routes"

echo "== tools"
R=$(mcp "$AGENT" initialize)
check "$(echo "$R" | json 'd["body"]["result"]["serverInfo"]["name"]')" mybastion "initialize"
check "$(mcp "$AGENT" tools/list | json '[t["name"] for t in d["body"]["result"]["tools"]]')" "['list_connections', 'run_ssh', 'open_session', 'screenshot', 'wait', 'list_sessions', 'close_session']" "tools/list"
L=$(tool "$AGENT" list_connections '{}')
conns() { echo "$1" | json 'sorted((c["id"], c["ai_mode"]) for c in __import__("json").loads(d["body"]["result"]["content"][0]["text"])["connections"])'; }
check "$(conns "$L")" "[('shared/lab/web01', 'auto'), ('shared/obs/web01', 'observe'), ('shared/prod/web01', 'approve')]" "list_connections: AI folders only"
check "$(echo "$L" | grep -c 'PRIVATE KEY\|private_key\|password')" 0 "no credentials in the listing"
check "$(conns "$(tool "$PRODONLY" list_connections '{}')")" "[('shared/prod/web01', 'approve')]" "a key's folder list narrows it"

echo "== run_ssh"
err() { echo "$1" | json '(d["body"]["result"].get("isError"), d["body"]["result"]["content"][0]["text"])'; }
R=$(tool "$AGENT" run_ssh "{\"connection\":\"shared/lab/web01\",\"command\":\"echo hello-$MARK\"}")
check "$(echo "$R" | json '__import__("json").loads(d["body"]["result"]["content"][0]["text"])["stdout"].strip()')" "hello-$MARK" "auto: the command runs"
check "$(err "$(tool "$AGENT" run_ssh '{"connection":"shared/obs/web01","command":"id"}')" | grep -c observe-only)" 1 "observe: refused"
check "$(err "$(tool "$AGENT" run_ssh '{"connection":"shared/secret/web01","command":"id"}')" | grep -c 'no such connection')" 1 "no AI mode: as if it did not exist"
check "$(err "$(tool "$PRODONLY" run_ssh '{"connection":"shared/lab/web01","command":"id"}')" | grep -c 'no such connection')" 1 "outside the key's folders: likewise"

R=$(tool "$AGENT" run_ssh '{"connection":"shared/prod/web01","command":"uptime"}')
check "$(err "$R" | grep -c 'Waiting for approval')" 1 "approve: the command waits"
REQ=$(curl -s -H "$BOSS" "$U/api/approvals" | json '[r["id"] for r in d["to_decide"] if r["requester"]=="ai:nightly"][0]')
check "$(post "$BOSS" "/api/approvals/$REQ/approve" '{"comment":"ok"}')" 200 "a person approves it"
R=$(tool "$AGENT" run_ssh '{"connection":"shared/prod/web01","command":"uptime"}')
check "$(echo "$R" | json '__import__("json").loads(d["body"]["result"]["content"][0]["text"])["exit_status"]')" 0 "then it runs"
check "$(err "$(tool "$AGENT" run_ssh '{"connection":"shared/prod/web01","command":"hostname"}')" | grep -c 'Waiting for approval')" 1 "the approval covers that command only"

check "$(post "$A" /api/admin/policies '{"name":"no rm for bots","subject":{"kind":"ai_agent","value":"*"},"target":{"kind":"any"},"action":"ssh_command","commands":["^rm\\b"],"effect":"deny"}')" 201 "a policy for every agent"
check "$(err "$(tool "$AGENT" run_ssh "{\"connection\":\"shared/lab/web01\",\"command\":\"rm -f /tmp/$MARK\"}")" | grep -c 'denied by policy')" 1 "applies to agents"

echo "== keys from the admin API"
check "$(post "$A" /api/admin/ai-agents '{"name":"from-api","folders":["shared/lab"]}')" 201 "create"
APIKEY=$(json 'd["key"]' < "$W/out.json")
check "$(conns "$(tool "$APIKEY" list_connections '{}')")" "[('shared/lab/web01', 'auto')]" "the new key works"
check "$(post "$A" /api/admin/ai-agents/from-api/disable)" 200 "disable"
check "$(mcp "$APIKEY" tools/list | json 'd["status"]')" 403 "a disabled key is refused"
OP="Authorization: Bearer $(curl -s -H "$A" -H 'Content-Type: application/json' \
    -d '{"email":"op@example.com","name":"mcp-test"}' "$U/api/admin/user-tokens" | json 'd["token"]')"
check "$(post "$OP" /api/admin/ai-agents '{"name":"x"}')" 403 "operators cannot create keys"
check "$(post "$BOSS" /api/admin/ai-agents '{"name":"x"}')" 201 "admin users can"
check "$(curl -s -H "$A" "$U/api/admin/ai-agents" | grep -c 'key_hash\|mbai_')" 0 "the list has no key material"

echo "== folders keep their AI mode"
post "$A" /api/addressbook/folders/shared/lab '{"allowed_groups":["ops"],"description":"edited"}' PUT >/dev/null
check "$(conns "$(tool "$AGENT" list_connections '{"folder":"shared/lab"}')")" "[('shared/lab/web01', 'auto')]" "a save without ai_mode keeps it"
check "$(post "$A" /api/addressbook/folders/shared/lab '{"allowed_groups":[],"ai_mode":"bogus"}' PUT)" 400 "an unknown mode is refused"

echo "== audit"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=200")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='command_run' and r['actor']=='ai:nightly' and 'hello-$MARK' in r['detail']")" True "the run is audited as ai:nightly"
check "$(has "r['event']=='requested' and r['requester']=='ai:nightly' and r['policy'].startswith('AI approve mode')")" True "the approve-mode request"
check "$(has "r['event']=='denied' and r['actor']=='ai:nightly' and r['policy']=='no rm for bots'")" True "the denial"
check "$(has "r['event']=='ai_agent_created' and r['target']=='ai:from-api'")" True "key changes"
check "$(grep -c "$AGENT" "$W/server.log")" 0 "keys never reach the server log"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; }
exit "$FAILED"
