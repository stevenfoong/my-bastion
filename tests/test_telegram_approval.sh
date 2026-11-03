#!/usr/bin/env bash
#
# Live check of Telegram approvals (Phase 2c) against a fake Bot API
# (tests/fake_telegram.py), so no real bot or network is needed:
#   - an approver links their Telegram account with a one-time code;
#   - a held connect is posted to the group chat and to linked approvers,
#     with Approve / Deny buttons;
#   - buttons from unlinked accounts, the requester themself or a disabled
#     user don't count; an approver's does, and every message is edited to
#     show the decision;
#   - a web-only request has no buttons, a forged press is refused, and the
#     web UI needs a fresh sign-in to decide it;
#   - the audit log records links and decisions.
#
# Usage: ./tests/test_telegram_approval.sh   (PORT=18093, TG_PORT=18094)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18093}"
TG_PORT="${TG_PORT:-18094}"
U="http://127.0.0.1:$PORT"
T="http://127.0.0.1:$TG_PORT"
TOKEN="123456:test-token"
GROUP=-100777
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-telegram.XXXXXX)
PID=
TGPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$TGPID" ] && kill "$TGPID" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

python3 tests/fake_telegram.py "$TG_PORT" "$TOKEN" &
TGPID=$!

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

[telegram]
enabled = true
chat_ids = [$GROUP]
api_url = "$T"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email op@example.com --role operator >/dev/null
CLI add-user --email boss@example.com --role admin >/dev/null
CLI add-user --email gone@example.com --role admin >/dev/null
CLI secret put mybastion/telegram "token=$TOKEN" >/dev/null || echo "FAIL secret put"

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
token() {
    curl -s -H "$A" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"name\":\"telegram-test\"}" "$U/api/admin/user-tokens" | json 'd["token"]'
}
OP="Authorization: Bearer $(token op@example.com)"
BOSS="Authorization: Bearer $(token boss@example.com)"
GONE="Authorization: Bearer $(token gone@example.com)"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
out() { json "$1" < "$W/out.json"; }
calls() { curl -s "$T/test/calls" | json "$1"; }
# Wait (up to 10s) until the expression over the recorded calls is True.
wait_calls() {
    for _ in $(seq 50); do [ "$(calls "$1")" = True ] && { echo True; return; }; sleep 0.2; done
    echo False
}
update() { curl -s -o /dev/null -d "$1" "$T/test/update"; }
# A user sends the bot a private message.
say() { update "{\"message\":{\"message_id\":1,\"chat\":{\"id\":$1,\"type\":\"private\"},\"from\":{\"id\":$1,\"username\":\"$2\"},\"text\":\"$3\"}}"; }
# A user presses a button.
press() { update "{\"callback_query\":{\"id\":\"cq-$1-$RANDOM\",\"from\":{\"id\":$1},\"data\":\"$2\"}}"; }
answered() { wait_calls "any(c['method']=='answerCallbackQuery' and $1 in c['body'].get('text','') for c in d)"; }

post "$A" /api/addressbook/folders '{"name":"prod","allowed_groups":[],"allowed_users":["op@example.com"]}' >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries '{"name":"web01","type":"ssh","hostname":"127.0.0.1","port":22}' >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries '{"name":"db01","type":"ssh","hostname":"127.0.0.1","port":22}' >/dev/null
post "$A" /api/admin/policies '{"name":"prod needs approval","subject":{"kind":"any"},"target":{"kind":"entry","scope":"shared","folder":"prod","entry":"web01"},"action":"connect","effect":"require_approval","approvers":[{"kind":"role","value":"admin"}],"grant_minutes":10,"timeout_minutes":10}' >/dev/null
check "$(post "$A" /api/admin/policies '{"name":"db is web only","subject":{"kind":"any"},"target":{"kind":"entry","scope":"shared","folder":"prod","entry":"db01"},"action":"connect","effect":"require_approval","web_only":true,"approvers":[{"kind":"role","value":"admin"}],"grant_minutes":10,"timeout_minutes":10}')" 201 "web-only policy"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"any"},"target":{"kind":"any"},"action":"connect","effect":"deny","web_only":true}')" 400 "web only refused on a deny rule"

echo "== the bot starts and approvers link their accounts"
check "$(wait_calls "any(c['method']=='getMe' for c in d)")" True "bot read its token and called getMe"
for _ in $(seq 25); do curl -s -H "$BOSS" "$U/api/telegram" | grep -q test_bastion_bot && break; sleep 0.2; done
check "$(curl -s -H "$BOSS" "$U/api/telegram" | json '(d["enabled"], d["bot_username"], d["linked"])')" "(True, 'test_bastion_bot', None)" "status before linking"
check "$(post "$A" /api/telegram/link)" 403 "an API key cannot link"
post "$BOSS" /api/telegram/link >/dev/null
CODE=$(out 'd["code"]')
check "$(out 'd["url"]')" "https://t.me/test_bastion_bot?start=$CODE" "deep link to the bot"
say 1001 boss "/start $CODE"
check "$(wait_calls "any(c['method']=='sendMessage' and c['body']['chat_id']==1001 and 'Linked to boss@example.com' in c['body']['text'] for c in d)")" True "boss linked by /start"
check "$(curl -s -H "$BOSS" "$U/api/telegram" | json 'd["linked"]["telegram_username"]')" "@boss" "status shows the link"
say 1009 mallory "/link $CODE"
check "$(wait_calls "any(c['body'].get('chat_id')==1009 and 'unknown or expired' in c['body'].get('text','') for c in d)")" True "a used code links nothing"
post "$OP" /api/telegram/link >/dev/null; say 2002 op "/link $(out 'd["code"]')"
post "$GONE" /api/telegram/link >/dev/null; say 3003 gone "/link $(out 'd["code"]')"
check "$(wait_calls "sum(1 for c in d if c['method']=='sendMessage' and 'Linked to' in c['body']['text'])==3")" True "op and gone linked too"
python3 - "$W/mybastion.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE users SET disabled = 1 WHERE email = 'gone@example.com'")
c.commit()
PY

echo "== a held connect goes to the group and to linked approvers"
check "$(post "$OP" /api/addressbook/folders/shared/prod/entries/web01/connect)" 202 "op's connect waits"
REQ=$(out 'd["approval"]["id"]')
check "$(wait_calls "sum(1 for c in d if c['method']=='sendMessage' and '$REQ' in str(c['body']))==2")" True "two messages sent"
check "$(calls "sorted(c['body']['chat_id'] for c in d if c['method']=='sendMessage' and '$REQ' in str(c['body']))")" "[$GROUP, 1001]" "to the group and to boss (not op, not the disabled user)"
check "$(calls "[c['body']['reply_markup']['inline_keyboard'][0][0]['callback_data'] for c in d if c['method']=='sendMessage' and c['body']['chat_id']==1001 and '$REQ' in str(c['body'])][0]")" "ap:$REQ" "with an Approve button"
check "$(post "$OP" "/api/approvals/$REQ/reason" '{"reason":"deploy hotfix"}')" 204 "op adds a reason"
check "$(wait_calls "any(c['method']=='editMessageText' and 'deploy hotfix' in c['body']['text'] for c in d)")" True "the messages show the reason"

echo "== only an approver's button counts"
press 9999 "ap:$REQ"
check "$(answered "'Link your Telegram'")" True "unlinked account refused"
press 2002 "ap:$REQ"
check "$(answered "'own request'")" True "the requester cannot approve their own"
press 3003 "ap:$REQ"
check "$(answered "'disabled'")" True "a disabled user cannot approve"
check "$(curl -s -H "$OP" "$U/api/approvals/$REQ" | json 'd["status"]')" pending "still pending"
press 1001 "ap:$REQ"
check "$(answered "'Approved.'")" True "boss approves from Telegram"
check "$(curl -s -H "$OP" "$U/api/approvals/$REQ" | json '(d["status"], d["decided_by"])')" "('approved', 'boss@example.com')" "approved by boss"
check "$(wait_calls "set(c['body']['chat_id'] for c in d if c['method']=='editMessageText' and 'Approved by boss@example.com' in c['body']['text'] and c['body']['reply_markup']['inline_keyboard']==[])=={$GROUP, 1001}")" True "both messages edited to the decision, buttons gone"
press 1001 "dn:$REQ"
check "$(answered "'already approved'")" True "a second press changes nothing"

echo "== web-only requests"
check "$(post "$OP" /api/addressbook/folders/shared/prod/entries/db01/connect)" 202 "op's db connect waits"
WREQ=$(out 'd["approval"]["id"]')
check "$(wait_calls "any(c['method']=='sendMessage' and '$WREQ' not in str(c['body'].get('reply_markup')) and 'Web only' in c['body']['text'] for c in d)")" True "notified without buttons"
press 1001 "ap:$WREQ"
check "$(answered "'web UI'")" True "a forged button press is refused"
check "$(post "$BOSS" "/api/approvals/$WREQ/approve")" 403 "a token is not a fresh sign-in"
check "$(out 'd["fresh_signin_required"]')" True "says a fresh sign-in is needed"
# Web sessions as the OIDC login would make them: one old, one fresh.
python3 - "$W/mybastion.db" <<'PY'
import hashlib, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
uid = c.execute("SELECT id FROM users WHERE email = 'boss@example.com'").fetchone()[0]
for tok, age in [("old-session", "-1 hour"), ("fresh-session", "-1 minute")]:
    c.execute("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at) "
              "VALUES (?, ?, datetime('now', ?), datetime('now', '+1 day'))",
              (hashlib.sha256(tok.encode()).hexdigest(), uid, age))
c.commit()
PY
cookie_post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "Cookie: mybastion_session=$1" -H "Origin: $U" -H 'Content-Type: application/json' -d '{}' "$U$2"; }
check "$(cookie_post old-session "/api/approvals/$WREQ/approve")" 403 "an hour-old sign-in is not fresh"
check "$(cookie_post fresh-session "/api/approvals/$WREQ/approve")" 200 "a fresh sign-in approves"
check "$(wait_calls "any(c['method']=='editMessageText' and 'Approved by boss@example.com' in c['body']['text'] and c['body'].get('chat_id')==$GROUP for c in d)")" True "the group sees the web decision"

echo "== withdrawn requests and unlinking"
post "$A" /api/admin/policies '{"name":"prod folder needs approval","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"connect","effect":"require_approval","approvers":[{"kind":"role","value":"admin"}],"grant_minutes":10,"timeout_minutes":10}' >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries '{"name":"app01","type":"ssh","hostname":"127.0.0.1","port":22}' >/dev/null
post "$OP" /api/addressbook/folders/shared/prod/entries/app01/connect >/dev/null
CREQ=$(out 'd["approval"]["id"]')
wait_calls "any('$CREQ' in str(c['body']) for c in d)" >/dev/null
check "$(post "$OP" "/api/approvals/$CREQ/cancel")" 204 "op withdraws"
check "$(wait_calls "any(c['method']=='editMessageText' and 'Withdrawn' in c['body']['text'] for c in d)")" True "messages show it was withdrawn"
say 1001 boss "/unlink"
check "$(wait_calls "any(c['body'].get('chat_id')==1001 and 'Unlinked from boss@example.com' in c['body'].get('text','') for c in d)")" True "/unlink"
check "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$OP" "$U/api/telegram/link")" 204 "op unlinks on the web"

echo "== audit"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='telegram_linked' and r['actor']=='boss@example.com'")" True "the link is audited"
check "$(has "r['event']=='approved' and r['actor']=='boss@example.com' and r['approval_id']=='$REQ' and r['detail']=='via Telegram'")" True "the Telegram approval is audited as such"
check "$(has "r['event']=='approved' and r['approval_id']=='$WREQ' and (r['detail'] or '')==''")" True "the web approval is audited"
check "$(has "r['event']=='telegram_unlinked' and r['actor']=='op@example.com'")" True "unlinking is audited"
check "$(grep -c "$TOKEN" "$W/server.log")" 0 "the bot token never reaches the log"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; }
exit "$FAILED"
