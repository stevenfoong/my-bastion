#!/usr/bin/env bash
#
# Live check of Phase 3b: desktop sessions an AI agent opens over MCP,
# rendered by the bastion itself.
#   - open_session on a VNC desktop (a local Xvnc, through a plain guacd the
#     test starts) and on SSH; observe mode may look;
#   - screenshot matches what is on the screen, pixel for pixel (the root
#     window is painted a known colour), and follows a change after `wait`;
#     max_width scales it down;
#   - sessions belong to the agent that opened them, are recorded as
#     ai:<name>, count in /api/sessions, and end with close_session or an
#     admin's terminate;
#   - folders without an AI mode and connect policies still apply.
#
# Usage: ./tests/test_mcp_session.sh   (PORT=18099, GUACD_PORT=14825, DISPLAY_NUM=151)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18099}"
GUACD_PORT="${GUACD_PORT:-14825}"
DN="${DISPLAY_NUM:-151}"
VNC_PORT=$((5900 + DN))
GUACD="${GUACD:-/opt/mybastion/sbin/guacd}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-mcpsess.XXXXXX)
MARK="mybastion-mcpsess-test-$$"
PID=
GPID=
XPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$GPID" ] && kill "$GPID" 2>/dev/null
    [ -n "$XPID" ] && kill "$XPID" 2>/dev/null
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
command -v Xvnc >/dev/null || { echo "SKIP: no Xvnc"; exit 1; }
LD_LIBRARY_PATH="$(dirname "$GUACD")/../lib" "$GUACD" -b 127.0.0.1 -l "$GUACD_PORT" -f -L warning >"$W.guacd.log" 2>&1 &
GPID=$!
Xvnc ":$DN" -geometry 1024x768 -depth 24 -SecurityTypes None -localhost -rfbport "$VNC_PORT" >"$W/xvnc.log" 2>&1 &
XPID=$!
for _ in $(seq 50); do xsetroot -display ":$DN" -solid '#3366cc' 2>/dev/null && break; sleep 0.2; done

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
AGENT=$(CLI add-ai-agent --name nightly | sed -n 's/^Agent Key: //p')
OTHER=$(CLI add-ai-agent --name other | sed -n 's/^Agent Key: //p')

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -X "${4:-POST}" -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
tool() { python3 tests/mcp_call.py "$U/mcp" "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; }
text() { json '__import__("json").loads(d["body"]["result"]["content"][0]["text"])'"$1"; }
errtext() { json 'd["body"]["result"]["content"][0]["text"] if d["body"]["result"].get("isError") else "no error"'; }
# Save a screenshot's PNG to $W/$2.png.
shot() {
    tool "$AGENT" screenshot "$1" > "$W/shot.json"
    python3 - "$W/shot.json" "$W/$2.png" <<'PY'
import base64, json, sys
d = json.load(open(sys.argv[1]))["body"]["result"]
img = [c for c in d["content"] if c["type"] == "image"]
open(sys.argv[2], "wb").write(base64.b64decode(img[0]["data"]) if img else b"")
PY
}
px() { python3 tests/png_pixels.py "$W/$1.png" "${@:2}"; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
post "$A" /api/addressbook/folders '{"name":"lab","allowed_groups":[],"ai_mode":"observe"}' >/dev/null
post "$A" /api/addressbook/folders '{"name":"dark","allowed_groups":[]}' >/dev/null
for f in lab dark; do
    post "$A" "/api/addressbook/folders/shared/$f/entries" "{\"name\":\"desk\",\"type\":\"vnc\",\"hostname\":\"127.0.0.1\",\"port\":$VNC_PORT,\"password\":\"x\"}" >/dev/null
done
post "$A" /api/addressbook/folders/shared/lab/entries "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null

echo "== a VNC desktop"
R=$(tool "$AGENT" open_session '{"connection":"shared/lab/desk","width":1024,"height":768}')
SID=$(echo "$R" | text '["session_id"]')
check "$(echo "$R" | json 'tuple([__import__("json").loads(d["body"]["result"]["content"][0]["text"])[k] for k in ("ready", "width", "height", "type")])')" "(True, 1024, 768, 'vnc')" "observe mode opens it and the first frame arrives"
shot "{\"session_id\":\"$SID\"}" blue
check "$(px blue size)" "1024 768" "screenshot at full size"
check "$(px blue at 500 400)" "51 102 204" "it shows the screen exactly (the blue root window)"
( sleep 1; xsetroot -display ":$DN" -solid '#cc3333' ) &
PAINT=$!
check "$(tool "$AGENT" wait "{\"session_id\":\"$SID\",\"ms\":8000}" | text '["new_frame"]')" True "wait returns on the next frame"
wait "$PAINT"
shot "{\"session_id\":\"$SID\"}" red
check "$(px red at 10 10)" "204 51 51" "and the screenshot follows the change"
shot "{\"session_id\":\"$SID\",\"max_width\":512}" small
check "$(px small size)" "512 384" "max_width scales it down"

echo "== whose session"
check "$(tool "$AGENT" list_sessions '{}' | json '[(s["connection"], s["type"]) for s in __import__("json").loads(d["body"]["result"]["content"][0]["text"])["sessions"]]')" "[('shared/lab/desk', 'vnc')]" "list_sessions"
check "$(tool "$OTHER" screenshot "{\"session_id\":\"$SID\"}" | errtext)" "no such session for this agent" "another agent cannot look at it"
check "$(curl -s -H "$A" "$U/api/sessions?all=true" | json "[(s['created_by'], s['status']) for s in d if s['session_id']=='$SID']")" "[('ai:nightly', 'active')]" "it is an active session of ai:nightly"
check "$(tool "$AGENT" open_session '{"connection":"shared/dark/desk"}' | errtext)" "no such connection for this agent" "a folder without an AI mode stays hidden"

echo "== an SSH terminal"
R=$(tool "$AGENT" open_session '{"connection":"shared/lab/web01"}')
SSID=$(echo "$R" | text '["session_id"]')
sleep 2
shot "{\"session_id\":\"$SSID\"}" term
check "$([ "$(px term nonblack)" -gt 100 ] && echo drawn)" drawn "the terminal is drawn"
check "$(tool "$AGENT" close_session "{\"session_id\":\"$SSID\"}" | text '["closed"]')" "$SSID" "close_session"
check "$(tool "$AGENT" screenshot "{\"session_id\":\"$SSID\"}" | errtext)" "no such session for this agent" "a closed session is gone"

echo "== ending and recording"
check "$(post "$A" "/api/sessions/$SID" '' DELETE)" 204 "an admin terminates the desktop session"
sleep 1
check "$(tool "$AGENT" screenshot "{\"session_id\":\"$SID\"}" | errtext | grep -c 'session has ended')" 1 "the agent is told it ended"
check "$([ -s "$W/rec/$SID.guac" ] && echo yes)" yes "the session was recorded"
check "$(json 'd["user"]' < "$W/rec/$SID.meta")" "ai:nightly" "the recording belongs to ai:nightly"

echo "== policies"
check "$(post "$A" /api/admin/policies '{"name":"no bots on desk","subject":{"kind":"ai_agent","value":"*"},"target":{"kind":"entry","scope":"shared","folder":"lab","entry":"desk"},"action":"connect","effect":"deny"}')" 201 "deny AI agents the desk"
check "$(tool "$AGENT" open_session '{"connection":"shared/lab/desk"}' | errtext | grep -c 'denied by policy')" 1 "open_session is refused"
check "$(grep -c "$AGENT" "$W/server.log")" 0 "keys never reach the server log"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -30 "$W/server.log"; }
exit "$FAILED"
