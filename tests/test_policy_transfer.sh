#!/usr/bin/env bash
#
# Live check of Phase 2d: clipboard / file transfer policies and break-glass.
#   - a session started under "no paste into prod" has its pastes dropped on
#     the bridge (the browser gets an ack with CLIENT_FORBIDDEN) and audited;
#     an audited ("allow_and_alert") upload goes through and is logged;
#   - a session where no transfer rule applies passes everything;
#   - transfer rules refuse require_approval;
#   - break-glass: an admin with a fresh web sign-in and a reason overrides a
#     deny for themself only, for an hour; tokens, API keys, short reasons and
#     other users are refused; all of it is in the audit log.
#
# Sessions are SSH to this machine's own sshd through a plain-TCP guacd the
# test starts from the installed binary (GUACD=/opt/mybastion/sbin/guacd),
# with a throwaway key added to ~/.ssh/authorized_keys and removed on exit.
#
# Usage: ./tests/test_policy_transfer.sh   (PORT=18095, GUACD_PORT=14823)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18095}"
GUACD_PORT="${GUACD_PORT:-14823}"
GUACD="${GUACD:-/opt/mybastion/sbin/guacd}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-transfer.XXXXXX)
MARK="mybastion-transfer-test-$$"
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
# Guacamole instruction encoding (lengths in characters).
ins() { python3 -c "import sys; print(','.join(f'{len(a)}.{a}' for a in sys.argv[1:]) + ';')" "$@"; }

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
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email op@example.com --role operator >/dev/null
CLI add-user --email boss@example.com --role admin >/dev/null

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
token() {
    curl -s -H "$A" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"name\":\"transfer-test\"}" "$U/api/admin/user-tokens" | json 'd["token"]'
}
OP="Authorization: Bearer $(token op@example.com)"
BOSS="Authorization: Bearer $(token boss@example.com)"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
out() { json "$1" < "$W/out.json"; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
for f in prod lab; do
    post "$A" /api/addressbook/folders "{\"name\":\"$f\",\"allowed_groups\":[],\"allowed_users\":[\"op@example.com\",\"boss@example.com\"]}" >/dev/null
    for e in web01 db01; do
        post "$A" "/api/addressbook/folders/shared/$f/entries" "{\"name\":\"$e\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null
    done
done

echo "== policies"
check "$(post "$A" /api/admin/policies '{"name":"no paste into prod","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"clipboard","direction":"in","effect":"deny"}')" 201 "clipboard-in deny"
check "$(post "$A" /api/admin/policies '{"name":"watch prod files","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"file_transfer","effect":"allow_and_alert"}')" 201 "file transfer alert"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"any"},"target":{"kind":"any"},"action":"clipboard","effect":"require_approval","approvers":[{"kind":"role","value":"admin"}]}')" 400 "transfer rules cannot wait for approval"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"any"},"target":{"kind":"any"},"action":"connect","direction":"in","effect":"deny"}')" 400 "a direction only on transfer rules"
check "$(post "$A" /api/admin/policies '{"name":"db01 is closed","subject":{"kind":"any"},"target":{"kind":"entry","scope":"shared","folder":"prod","entry":"db01"},"action":"connect","effect":"deny"}')" 201 "connect deny on prod/db01"

# Start a session as op on folder/entry and run the probe on its tunnel.
probe() {  # folder, then instructions to send
    local f=$1; shift
    post "$OP" "/api/addressbook/folders/shared/$f/entries/web01/connect" '{"width":800,"height":600}' >/dev/null
    local sid
    sid=$(out 'd["session_id"]')
    python3 tests/ws_probe.py "127.0.0.1:$PORT" "/ws/$sid" "$OP" 4 "$@"
}
PASTE="$(ins clipboard 7 text/plain)$(ins blob 7 c2VjcmV0)$(ins end 7)"
UPLOAD="$(ins file 8 text/plain notes.txt)$(ins end 8)"
BLOCKED_ACK="$(ins ack 7 'Blocked by policy' 771)"

echo "== a prod session: paste blocked, upload audited"
probe prod "$PASTE" "$UPLOAD" > "$W/prod.out"
check "$(grep -q '4.sync,' "$W/prod.out" && echo live)" live "guacd session is live"
check "$(grep -cF "$BLOCKED_ACK" "$W/prod.out")" 1 "the paste is refused with CLIENT_FORBIDDEN"
check "$(grep -cF "$(ins ack 8 'Blocked by policy' 771)" "$W/prod.out")" 0 "the upload is not blocked"

echo "== a lab session: no transfer rule applies"
probe lab "$PASTE" > "$W/lab.out"
check "$(grep -q '4.sync,' "$W/lab.out" && echo live)" live "guacd session is live"
check "$(grep -cF "$BLOCKED_ACK" "$W/lab.out")" 0 "the paste goes through"

echo "== break-glass"
check "$(post "$OP" /api/addressbook/folders/shared/prod/entries/db01/connect)" 403 "op is denied db01"
check "$(post "$BOSS" /api/addressbook/folders/shared/prod/entries/db01/connect)" 403 "so is boss"
BG='{"scope":"shared","folder":"prod","entry":"db01","reason":"primary db is down, need a shell"}'
check "$(post "$A" /api/break-glass "$BG")" 403 "an API key cannot break the glass"
check "$(post "$OP" /api/break-glass "$BG")" 403 "an operator cannot"
check "$(post "$BOSS" /api/break-glass "$BG")" 403 "a token is not a fresh sign-in"
check "$(out 'd["fresh_signin_required"]')" True "says why"
python3 - "$W/mybastion.db" <<'PY'
import hashlib, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
uid = c.execute("SELECT id FROM users WHERE email = 'boss@example.com'").fetchone()[0]
c.execute("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at) "
          "VALUES (?, ?, datetime('now', '-1 minute'), datetime('now', '+1 day'))",
          (hashlib.sha256(b"fresh-session").hexdigest(), uid))
c.commit()
PY
cookie_post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "Cookie: mybastion_session=fresh-session" -H "Origin: $U" -H 'Content-Type: application/json' -d "$2" "$U$1"; }
check "$(cookie_post /api/break-glass '{"scope":"shared","folder":"prod","entry":"db01","reason":"too short"}')" 400 "a short reason is refused"
check "$(cookie_post /api/break-glass "$BG")" 200 "boss breaks the glass"
check "$(out '(d["approval"]["break_glass"], d["approval"]["status"], d["minutes"])')" "(True, 'approved', 60)" "an approved break-glass grant for an hour"
code=$(post "$BOSS" /api/addressbook/folders/shared/prod/entries/db01/connect)
check "$([ "$code" != 403 ] && echo through || echo "$code")" through "boss now gets past the deny"
check "$(post "$OP" /api/addressbook/folders/shared/prod/entries/db01/connect)" 403 "op is still denied"

echo "== audit"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='clipboard_paste_blocked' and r['actor']=='op@example.com' and r['target']=='shared/prod/web01'")" True "the blocked paste is audited"
check "$(has "r['event']=='file_upload' and 'notes.txt' in (r['detail'] or '')")" True "the audited upload is logged with its name"
check "$(has "r['event'].startswith('clipboard') and r['target']=='shared/lab/web01'")" False "nothing logged for the lab session"
check "$(has "r['event']=='break_glass' and r['actor']=='boss@example.com' and 'primary db is down' in (r['detail'] or '')")" True "break-glass is audited with its reason"
check "$(has "r['event']=='allowed_by_break_glass' and r['policy']=='db01 is closed'")" True "its use against the deny is audited"
check "$(grep -c 'c2VjcmV0' "$W/server.log")" 0 "clipboard data never reaches the log"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; }
exit "$FAILED"
