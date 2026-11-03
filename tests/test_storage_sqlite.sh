#!/usr/bin/env bash
#
# Live check of the SQLite secret store with no Vault: starts mybastion with
# [storage] backend = "sqlite", creates a folder and an RDP entry over the
# REST API, restarts and reads them back, then exercises `secret put` and
# `rotate-kek`. Needs only cargo and curl.
#
# Usage: ./tests/test_storage_sqlite.sh
#   PORT=18089 by default.

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18089}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-sqlite.XXXXXX)
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
start() {
    "$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
    PID=$!
    for _ in $(seq 50); do curl -s -o /dev/null "$U/" && return; sleep 0.2; done
    echo "server did not start:"; tail "$W/server.log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null; PID=; }
entries() { curl -s -H "$H" "$U/api/addressbook/folders/shared/Prod/entries"; }

mkdir -p "$W/rec"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/kek" && chmod 400 "$W/kek"
cat > "$W/config.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
db_path = "$W/mybastion.db"
static_path = "$PWD/static"
recording_path = "$W/rec"

[storage]
backend = "sqlite"
path = "$W/secrets.db"
kek_source = "file:$W/kek"
EOF
KEY=$("$BIN" --config "$W/config.toml" add-admin --name e2e 2>/dev/null | sed -n 's/^API Key: //p')
H="X-API-Key: $KEY"

start
check "$(grep -c 'Secret store: SQLite' "$W/server.log")" 1 "server uses the SQLite store"
check "$(curl -s -o /dev/null -w '%{http_code}' -H "$H" -H 'Content-Type: application/json' \
    -d '{"name":"Prod","allowed_groups":["ops"],"description":"prod servers"}' \
    "$U/api/addressbook/folders")" 201 "create folder"
check "$(curl -s -o /dev/null -w '%{http_code}' -H "$H" -H 'Content-Type: application/json' \
    -d '{"name":"win01","type":"rdp","hostname":"10.0.0.5","port":3389,"username":"Administrator","password":"S3cret-e2e-pw"}' \
    "$U/api/addressbook/folders/shared/Prod/entries")" 201 "create RDP entry"
stop

start
check "$(curl -s -H "$H" "$U/api/addressbook/folders" | grep -o '"name":"Prod"' | head -1)" '"name":"Prod"' "folder listed after restart"
check "$(entries | grep -o '"hostname":"10.0.0.5"' | head -1)" '"hostname":"10.0.0.5"' "entry listed after restart"
check "$(entries | grep -c 'S3cret-e2e-pw')" 0 "password not in the API listing"
check "$(curl -s -H "$H" "$U/api/system/status" | grep -o '"configured":true' | head -1)" '"configured":true' "status says a secret store is configured"
stop

check "$(cat "$W"/secrets.db* | grep -c 'S3cret-e2e-pw')" 0 "password not in clear in secrets.db"
check "$(stat -c %a "$W/secrets.db")" 600 "secrets.db is mode 0600"

printf 'luks-key-material' > "$W/luks.key"
check "$("$BIN" --config "$W/config.toml" secret put mybastion/luks "key=@$W/luks.key" 2>/dev/null)" \
    "Wrote mybastion/luks on sqlite (version 1)" "secret put"
head -c 32 /dev/urandom | base64 > "$W/kek2" && chmod 400 "$W/kek2"
"$BIN" --config "$W/config.toml" rotate-kek --new-kek-source "file:$W/kek2" >/dev/null 2>&1
start
check "$(grep -c 'does not open' "$W/server.log")" 1 "old KEK refused after rotate-kek"
stop
sed -i "s#file:$W/kek\"#file:$W/kek2\"#" "$W/config.toml"
start
check "$(entries | grep -o '"hostname":"10.0.0.5"' | head -1)" '"hostname":"10.0.0.5"' "entry readable with the new KEK"
stop

[ "$FAILED" = 0 ] && echo "PASS" || echo "FAILED"
exit "$FAILED"
