#!/usr/bin/env bash
#
# Live check of Phase 2e: the interactive SSH command log.
#   - keystrokes typed into a real SSH session (through guacd) reach the
#     shell and are logged as lines, with line editing followed;
#   - a paste (clipboard + Ctrl+Shift+V) is logged as pasted;
#   - the one-word line after `sudo` is redacted and never stored;
#   - a line an `ssh_command` deny rule matches is flagged: policy audit log
#     and a Telegram alert to the chat_ids (fake Bot API);
#   - only admins can read the log.
#
# Sessions are SSH to this machine's own sshd through a plain-TCP guacd the
# test starts from the installed binary (GUACD=/opt/mybastion/sbin/guacd),
# with a throwaway key added to ~/.ssh/authorized_keys and removed on exit.
#
# Usage: ./tests/test_ssh_command_log.sh   (PORT=18096, GUACD_PORT=14824, TG_PORT=18097)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18096}"
GUACD_PORT="${GUACD_PORT:-14824}"
TG_PORT="${TG_PORT:-18097}"
GUACD="${GUACD:-/opt/mybastion/sbin/guacd}"
U="http://127.0.0.1:$PORT"
TOKEN="123456:test-token"
GROUP=-100888
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-sshlog.XXXXXX)
MARK="mybastion-sshlog-test-$$"
PID=
GPID=
TGPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$GPID" ] && kill "$GPID" 2>/dev/null
    [ -n "$TGPID" ] && kill "$TGPID" 2>/dev/null
    [ -f ~/.ssh/authorized_keys ] && sed -i "/$MARK/d" ~/.ssh/authorized_keys
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
# Guacamole instruction encoding (lengths in characters).
ins() { python3 -c "import sys; print(','.join(f'{len(a)}.{a}' for a in sys.argv[1:]) + ';', end='')" "$@"; }
# Key presses and releases. Arguments: text to type, or {Return},
# {BackSpace}, {Left}, {Paste} (Ctrl+Shift+V).
keys() {
    python3 - "$@" <<'PY'
import sys
special = {"{Return}": [0xff0d], "{BackSpace}": [0xff08], "{Left}": [0xff51]}
def key(k, p):
    a = [str(k), "1" if p else "0"]
    return "3.key," + ",".join(f"{len(x)}.{x}" for x in a) + ";"
out = []
for arg in sys.argv[1:]:
    if arg == "{Paste}":
        for k, p in [(0xffe3, 1), (0xffe1, 1), (ord("V"), 1), (ord("V"), 0), (0xffe1, 0), (0xffe3, 0)]:
            out.append(key(k, p))
        continue
    for k in special.get(arg) or [ord(c) if ord(c) < 0x100 else ord(c) + 0x1000000 for c in arg]:
        out.append(key(k, 1) + key(k, 0))
print("".join(out), end="")
PY
}

[ -x "$GUACD" ] || { echo "SKIP: no guacd at $GUACD"; exit 1; }
LD_LIBRARY_PATH="$(dirname "$GUACD")/../lib" "$GUACD" -b 127.0.0.1 -l "$GUACD_PORT" -f -L warning >"$W.guacd.log" 2>&1 &
GPID=$!
python3 tests/fake_telegram.py "$TG_PORT" "$TOKEN" &
TGPID=$!

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

[telegram]
enabled = true
chat_ids = [$GROUP]
api_url = "http://127.0.0.1:$TG_PORT"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email op@example.com --role operator >/dev/null
CLI secret put mybastion/telegram "token=$TOKEN" >/dev/null || echo "FAIL secret put"

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
OPTOKEN=$(curl -s -H "$A" -H 'Content-Type: application/json' \
    -d '{"email":"op@example.com","name":"sshlog-test"}' "$U/api/admin/user-tokens" | json 'd["token"]')
OP="Authorization: Bearer $OPTOKEN"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
post "$A" /api/addressbook/folders '{"name":"prod","allowed_groups":[],"allowed_users":["op@example.com"]}' >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null
check "$(post "$A" /api/admin/policies '{"name":"no rm -rf","subject":{"kind":"any"},"target":{"kind":"any"},"action":"ssh_command","commands":["rm\\s+-rf"],"effect":"deny"}')" 201 "command deny rule"

echo "== typing into a prod session"
post "$OP" /api/addressbook/folders/shared/prod/entries/web01/connect '{"width":800,"height":600}' >/dev/null
SID=$(json 'd["session_id"]' < "$W/out.json")
NOPE="/tmp/$MARK-does-not-exist"
CLIP=$(python3 -c "import base64; print(base64.b64encode(b'echo pasted-$$\n').decode())")
INPUT="$(keys "touch $W/typed-marker" "{Return}")"
INPUT+="$(keys "echo hello wod" "{Left}" "rl" "{Return}")"
INPUT+="$(keys "rm -rf $NOPE" "{Return}")"
INPUT+="$(keys "sudo -k" "{Return}" "hunter2" "{Return}")"
INPUT+="$(ins clipboard 9 text/plain)$(ins blob 9 "$CLIP")$(ins end 9)$(keys "{Paste}")"
WS_PROBE_DELAY=3 python3 tests/ws_probe.py "127.0.0.1:$PORT" "/ws/$SID" "$OP" 7 "$INPUT" > "$W/probe.out"
check "$(grep -q '4.sync,' "$W/probe.out" && echo live)" live "guacd session is live"
check "$([ -f "$W/typed-marker" ] && echo yes)" yes "the keystrokes reached the shell"
sleep 1

echo "== the log"
LOG=$(curl -s -H "$A" "$U/api/admin/ssh-commands?session_id=$SID")
lines() { echo "$LOG" | json "$1"; }
check "$(lines '[r["line"] for r in reversed(d)]')" \
    "['touch $W/typed-marker', 'echo hello world', 'rm -rf $NOPE', 'sudo -k', '', 'echo pasted-$$']" "lines rebuilt in order"
check "$(lines '[(r["redacted"], r["pasted"]) for r in reversed(d)][4:]')" "[(True, False), (False, True)]" "redacted and pasted flags"
check "$(lines '[r["policy"] for r in d if r["policy"]]')" "['no rm -rf']" "only the rm line is flagged"
check "$(lines 'set((r["actor"], r["target"]) for r in d)')" "{('op@example.com', 'shared/prod/web01')}" "who and where"
check "$(curl -s -o /dev/null -w '%{http_code}' -H "$OP" "$U/api/admin/ssh-commands")" 403 "operators cannot read the log"
check "$(curl -s -H "$A" "$U/api/admin/ssh-commands?q=hello" | json 'len(d)')" 1 "text search"
check "$(curl -s -H "$A" "$U/api/admin/ssh-commands?alerts=true" | json 'len(d)')" 1 "flagged only"

echo "== alerts"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=100")
check "$(echo "$AUDIT" | json "any(r['event']=='ssh_command_alert' and r['policy']=='no rm -rf' and '$NOPE' in r['detail'] for r in d)")" True "alert in the policy audit log"
for _ in $(seq 20); do
    CALLS=$(curl -s "http://127.0.0.1:$TG_PORT/test/calls")
    echo "$CALLS" | grep -q 'SSH command flagged' && break
    sleep 0.5
done
check "$(echo "$CALLS" | json "[c['body']['chat_id'] for c in d if c['method']=='sendMessage' and 'SSH command flagged' in c['body']['text'] and '$NOPE' in c['body']['text']]")" "[$GROUP]" "Telegram alert to the group"

echo "== nothing leaks the password"
check "$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"SELECT count(*) FROM ssh_command_log WHERE line LIKE '%hunter2%'\").fetchone()[0])" "$W/mybastion.db")" 0 "not in the database"
check "$(grep -c hunter2 "$W/server.log")" 0 "not in the server log"
check "$(echo "$CALLS" | grep -c hunter2)" 0 "not sent to Telegram"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; }
exit "$FAILED"
