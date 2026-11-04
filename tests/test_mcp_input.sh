#!/usr/bin/env bash
#
# Live check of Phase 3c: AI agents' input to sessions over MCP.
#   - type_text and key reach the target: typed into an SSH terminal the
#     bastion renders, a command creates a file on this machine;
#   - click and scroll change what the screen shows;
#   - observe folders refuse input; approve folders hold each input until a
#     person approves exactly that input; `input` policies apply;
#   - AI sessions are recorded even when the entry says not to;
#   - the audit log has each input without the typed text;
#   - rate limits; the kill switch ends every AI session (and can disable
#     every agent key).
#
# Usage: ./tests/test_mcp_input.sh   (PORT=18100, GUACD_PORT=14826)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18100}"
GUACD_PORT="${GUACD_PORT:-14826}"
GUACD="${GUACD:-/opt/mybastion/sbin/guacd}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-mcpin.XXXXXX)
MARK="mybastion-mcpin-test-$$"
PID=
GPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$GPID" ] && kill "$GPID" 2>/dev/null
    [ -f ~/.ssh/authorized_keys ] && sed -i "/$MARK/d" ~/.ssh/authorized_keys
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

[ -x "$GUACD" ] || { echo "SKIP: no guacd at $GUACD"; exit 1; }
LD_LIBRARY_PATH="$(dirname "$GUACD")/../lib" "$GUACD" -b 127.0.0.1 -l "$GUACD_PORT" -f -L warning >"$W.guacd.log" 2>&1 &
GPID=$!

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
guacd_addr = "127.0.0.1:$GUACD_PORT"

[storage]
path = "$W/secrets.db"
kek_source = "file:$W/kek"

[mcp]
enabled = true
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email boss@example.com --role admin >/dev/null
AGENT=$(CLI add-ai-agent --name nightly | sed -n 's/^Agent Key: //p')

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
BOSS="Authorization: Bearer $(curl -s -H "$A" -H 'Content-Type: application/json' \
    -d '{"email":"boss@example.com","name":"mcp-test"}' "$U/api/admin/user-tokens" | json 'd["token"]')"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -X "${4:-POST}" -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
tool() { python3 tests/mcp_call.py "$U/mcp" "$AGENT" tools/call "{\"name\":\"$1\",\"arguments\":$2}"; }
res() { json '__import__("json").loads(d["body"]["result"]["content"][0]["text"])'"$1"; }
err() { json 'd["body"]["result"]["content"][0]["text"] if d["body"]["result"].get("isError") else "no error"'; }
shot() {
    tool screenshot "{\"session_id\":\"$1\"}" > "$W/shot.json"
    python3 - "$W/shot.json" "$W/$2.png" <<'PY'
import base64, json, sys
d = json.load(open(sys.argv[1]))["body"]["result"]
img = [c for c in d["content"] if c["type"] == "image"]
open(sys.argv[2], "wb").write(base64.b64decode(img[0]["data"]) if img else b"")
PY
}
open_ssh() { tool open_session "{\"connection\":\"$1\"}" | res '["session_id"]'; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
for f in lab:auto prod:approve obs:observe; do
    name=${f%%:*}; mode=${f##*:}
    post "$A" /api/addressbook/folders "{\"name\":\"$name\",\"allowed_groups\":[],\"ai_mode\":\"$mode\"}" >/dev/null
    post "$A" "/api/addressbook/folders/shared/$name/entries" "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON,\"enable_recording\":false}" >/dev/null
done

echo "== typing into an SSH terminal (auto)"
SID=$(open_ssh shared/lab/web01)
sleep 2
R=$(tool type_text "{\"session_id\":\"$SID\",\"text\":\"touch $W/typed-$MARK\\n\"}")
check "$(echo "$R" | res '["done"]')" True "type_text"
for _ in $(seq 20); do [ -f "$W/typed-$MARK" ] && break; sleep 0.25; done
check "$([ -f "$W/typed-$MARK" ] && echo yes)" yes "the typed command ran on the target"
tool type_text "{\"session_id\":\"$SID\",\"text\":\"sleep 30; touch $W/not-$MARK\"}" >/dev/null
tool key "{\"session_id\":\"$SID\",\"combo\":\"enter\"}" >/dev/null
check "$(tool key "{\"session_id\":\"$SID\",\"combo\":\"ctrl+c\"}" | res '["done"]')" True "key ctrl+c"
sleep 1
tool type_text "{\"session_id\":\"$SID\",\"text\":\"touch $W/after-$MARK\\n\"}" >/dev/null
for _ in $(seq 20); do [ -f "$W/after-$MARK" ] && break; sleep 0.25; done
check "$([ -f "$W/after-$MARK" ] && [ ! -f "$W/not-$MARK" ] && echo interrupted)" interrupted "ctrl+c interrupted the sleep"
check "$(tool key "{\"session_id\":\"$SID\",\"combo\":\"hyper+q\"}" | err | grep -c 'unknown key')" 1 "an unknown key is refused"

tool type_text "{\"session_id\":\"$SID\",\"text\":\"clear; seq 1 300\\n\"}" >/dev/null
sleep 1
shot "$SID" before
sleep 1
shot "$SID" still
check "$(cmp -s "$W/before.png" "$W/still.png" && echo same || echo differs)" same "the screen is still before scrolling"
check "$(tool scroll "{\"session_id\":\"$SID\",\"x\":100,\"y\":100,\"dy\":-10}" | res '["done"]')" True "scroll"
tool wait "{\"session_id\":\"$SID\",\"ms\":2000}" >/dev/null
shot "$SID" after
check "$(cmp -s "$W/before.png" "$W/after.png" && echo same || echo differs)" differs "scrolling changes what the screen shows"
check "$(tool click "{\"session_id\":\"$SID\",\"x\":5000,\"y\":5}" | err | grep -c 'outside the screen')" 1 "a click outside the screenshot is refused"
check "$(tool click "{\"session_id\":\"$SID\",\"x\":40,\"y\":40,\"double\":true}" | res '["done"]')" True "click"

echo "== modes and policies"
OSID=$(open_ssh shared/obs/web01)
check "$(tool type_text "{\"session_id\":\"$OSID\",\"text\":\"id\"}" | err | grep -c 'observe-only')" 1 "observe: input refused"
PSID=$(open_ssh shared/prod/web01)
sleep 2
ARGS="{\"session_id\":\"$PSID\",\"text\":\"touch $W/approved-$MARK\\n\"}"
check "$(tool type_text "$ARGS" | err | grep -c 'Waiting for approval')" 1 "approve: the input waits"
check "$([ -f "$W/approved-$MARK" ] && echo ran || echo held)" held "nothing was typed yet"
REQ=$(curl -s -H "$BOSS" "$U/api/approvals" | json '[r for r in d["to_decide"] if r["requester"]=="ai:nightly"][0]')
check "$(echo "$REQ" | python3 -c "import ast,sys; r=ast.literal_eval(sys.stdin.read()); print(r['action'], 'approved-' in r['command'])")" "input True" "the approver sees the exact input"
RID=$(echo "$REQ" | python3 -c "import ast,sys; print(ast.literal_eval(sys.stdin.read())['id'])")
check "$(post "$BOSS" "/api/approvals/$RID/approve" '{"comment":"ok"}')" 200 "a person approves it"
check "$(tool type_text "$ARGS" | res '["done"]')" True "then it is typed"
for _ in $(seq 20); do [ -f "$W/approved-$MARK" ] && break; sleep 0.25; done
check "$([ -f "$W/approved-$MARK" ] && echo ran)" ran "and runs on the target"
check "$(tool key "{\"session_id\":\"$PSID\",\"combo\":\"enter\"}" | err | grep -c 'Waiting for approval')" 1 "other input needs its own approval"
check "$(post "$A" /api/admin/policies '{"name":"no bot typing in lab","subject":{"kind":"ai_agent","value":"nightly"},"target":{"kind":"folder","scope":"shared","path":"lab"},"action":"input","effect":"deny"}')" 201 "an input policy"
check "$(tool key "{\"session_id\":\"$SID\",\"combo\":\"enter\"}" | err | grep -c 'denied by policy')" 1 "denies input"

echo "== recording and audit"
check "$([ -s "$W/rec/$SID.guac" ] && echo yes)" yes "recorded although the entry says not to"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
check "$(echo "$AUDIT" | json "sum(1 for r in d if r['event']=='ai_input' and r['actor']=='ai:nightly')" | awk '{print ($1 >= 6) ? "many" : $1}')" many "each input is audited"
check "$(echo "$AUDIT" | json "any(r['event']=='ai_input' and '\"chars\"' in (r['detail'] or '') for r in d)")" True "with the number of characters typed"
check "$(echo "$AUDIT" | grep -c "typed-$MARK")" 0 "but not the text"
check "$(grep -c "typed-$MARK" "$W/server.log")" 0 "nor in the server log"

echo "== rate limits and the kill switch"
LIMITED=$(python3 - "$U/mcp" "$AGENT" "$OSID" <<'PY'
import json, sys, urllib.request
url, key, sid = sys.argv[1:]
n = 0
for i in range(45):
    body = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "screenshot", "arguments": {"session_id": sid}}}
    req = urllib.request.Request(url, json.dumps(body).encode(), {
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18", "Authorization": "Bearer " + key})
    r = json.loads(urllib.request.urlopen(req).read())["result"]
    n += "too many screenshots" in r["content"][0].get("text", "")
print(n > 0)
PY
)
check "$LIMITED" True "screenshots are rate limited"
check "$(curl -s -H "$A" "$U/api/admin/ai-sessions" | json 'len(d)')" 3 "admins see the AI sessions"
check "$(post "$A" /api/admin/ai-sessions/kill '{"disable_agents":true}')" 200 "the kill switch"
check "$(json '(d["sessions_ended"], d["agents_disabled"])' < "$W/out.json")" "(3, 1)" "ends every AI session and disables the keys"
check "$(curl -s -H "$A" "$U/api/sessions?all=true" | json "[s['status'] for s in d if s['created_by']=='ai:nightly' and s['status']=='active']")" "[]" "none is left active"
check "$(python3 tests/mcp_call.py "$U/mcp" "$AGENT" tools/list | json 'd["status"]')" 403 "the agent is locked out"
check "$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=50" | json "any(r['event']=='ai_kill_switch' for r in d)")" True "the kill switch is audited"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -30 "$W/server.log"; }
exit "$FAILED"
