#!/usr/bin/env bash
#
# Vault <-> SQLite migration against a real OpenBao, run in dev mode (in
# memory, gone on exit):
#   1. rustguac on OpenBao writes folders, entries and defaults over the
#      REST API; `storage put --backend vault` adds a user credential and a
#      LUKS key. Every document under secret/rustguac is dumped.
#   2. `storage migrate --from vault --to sqlite` (dry run first), then
#      rustguac serves the entries from SQLite.
#   3. A fresh, empty OpenBao; `storage migrate --from sqlite --to vault`.
#      The documents must match step 1 exactly, and a second migrate
#      without --overwrite must skip all of them.
# Needs cargo, curl, python3 and OpenBao's `bao` on PATH.
#
# Usage: ./tests/test_storage_openbao.sh
#   PORT=18090 and BAO_PORT=18200 by default.

set -uo pipefail

command -v bao >/dev/null || { echo "OpenBao's bao is not on PATH"; exit 1; }
cd "$(dirname "$0")/.."
PORT="${PORT:-18090}"
U="http://127.0.0.1:$PORT"
export BAO_ADDR="http://127.0.0.1:${BAO_PORT:-18200}" BAO_TOKEN="root-e2e"
cargo build -q || exit 1
BIN="$PWD/target/debug/rustguac"
W=$(mktemp -d /tmp/rustguac-openbao.XXXXXX)
PID=
BAO_PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$BAO_PID" ] && kill "$BAO_PID" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}

# A fresh dev OpenBao with an AppRole limited to secret/rustguac/*.
start_bao() {
    if [ -n "$BAO_PID" ]; then kill "$BAO_PID"; wait "$BAO_PID" 2>/dev/null; fi
    bao server -dev -dev-root-token-id="$BAO_TOKEN" -dev-listen-address="${BAO_ADDR#http://}" \
        >"$W/bao.log" 2>&1 &
    BAO_PID=$!
    for _ in $(seq 50); do bao status >/dev/null 2>&1 && break; sleep 0.2; done
    bao secrets list -format=json | python3 -c \
        'import json,sys; m=json.load(sys.stdin)["secret/"]; assert m["type"]=="kv" and m["options"]["version"]=="2"' \
        || { echo "dev OpenBao has no kv-v2 at secret/"; exit 1; }
    bao auth enable approle >/dev/null
    bao policy write rustguac - >/dev/null <<'P'
path "secret/data/rustguac/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/metadata/rustguac/*" { capabilities = ["read", "list", "delete"] }
P
    bao write auth/approle/role/rustguac token_policies=rustguac token_ttl=1h >/dev/null
    ROLE_ID=$(bao read -field=role_id auth/approle/role/rustguac/role-id)
    VAULT_SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/rustguac/secret-id)
    export VAULT_SECRET_ID
}

write_config() {  # $1: vault | sqlite
    cat > "$W/config.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
db_path = "$W/rustguac.db"
static_path = "$PWD/static"
recording_path = "$W/rec"

[vault]
addr = "$BAO_ADDR"
role_id = "$ROLE_ID"
instance_name = "node1"

[storage]
backend = "$1"
path = "$W/secrets.db"
kek_source = "file:$W/kek"
instance_name = "node1"
EOF
}

# Every document under secret/rustguac as sorted JSON, read with the root token.
dump() {
    python3 - <<'PY'
import json, os, urllib.error, urllib.request
addr, tok = os.environ["BAO_ADDR"], os.environ["BAO_TOKEN"]
def call(method, path):
    req = urllib.request.Request(addr + "/v1/" + path, method=method, headers={"X-Vault-Token": tok})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
out, dirs = {}, ["rustguac"]
while dirs:
    d = dirs.pop()
    for k in ((call("LIST", "secret/metadata/" + d) or {}).get("data") or {}).get("keys", []):
        if k.endswith("/"):
            dirs.append(d + "/" + k[:-1])
        else:
            out[d + "/" + k] = call("GET", "secret/data/" + d + "/" + k)["data"]["data"]
print(json.dumps(out, sort_keys=True, indent=1))
PY
}
count() { python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'; }

serve() {
    "$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
    PID=$!
    for _ in $(seq 50); do curl -s -o /dev/null "$U/" && return; sleep 0.2; done
    echo "server did not start:"; tail "$W/server.log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null; PID=; }
send() {  # path, JSON body, method (default POST) -> HTTP status
    curl -s -o /dev/null -w '%{http_code}' -H "$H" -H 'Content-Type: application/json' \
        -X "${3:-POST}" -d "$2" "$U$1"
}
migrate() { "$BIN" --config "$W/config.toml" storage migrate "$@" 2>/dev/null | tail -1; }

mkdir -p "$W/rec"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/kek" && chmod 400 "$W/kek"
start_bao
write_config vault
KEY=$("$BIN" --config "$W/config.toml" add-admin --name e2e 2>/dev/null | sed -n 's/^API Key: //p')
H="X-API-Key: $KEY"

echo "== rustguac on OpenBao"
serve
check "$(grep -c "Vault backend 'default' initialized" "$W/server.log")" 1 "server logged in to OpenBao"
check "$(send /api/addressbook/folders '{"name":"Prod","allowed_groups":["ops"],"description":"prod"}')" 201 "create folder Prod"
check "$(send /api/addressbook/folders '{"name":"Prod/Web","allowed_groups":[],"inherit_from_parent":true}')" 201 "create subfolder Prod/Web"
check "$(send /api/addressbook/folders '{"name":"Lab","allowed_groups":["lab"],"scope":"instance"}')" 201 "create instance folder Lab"
check "$(send /api/addressbook/folders/shared/Prod/entries \
    '{"name":"win01","type":"rdp","hostname":"10.0.0.5","port":3389,"username":"Administrator","password":"S3cret-bao-pw"}')" 201 "create RDP entry"
check "$(send /api/addressbook/folders/shared/Prod%2FWeb/entries \
    '{"name":"web01","type":"ssh","hostname":"10.0.1.1","port":22}')" 201 "create SSH entry in the subfolder"
check "$(send /api/addressbook/folders/instance/Lab/entries \
    '{"name":"vnc1","type":"vnc","hostname":"10.9.0.1","port":5900,"password":"vncpw"}')" 201 "create instance VNC entry"
check "$(send /api/addressbook/folders/shared/Prod/defaults '{"ssh":{"username":"deploy","password":"defpw"}}' PUT)" 200 "set folder defaults"
stop
"$BIN" --config "$W/config.toml" storage put --backend vault rustguac/users/a_at_b.c corp_pw=userpw >/dev/null 2>&1
printf 'luks-key-material' > "$W/luks.key"
"$BIN" --config "$W/config.toml" storage put --backend vault rustguac/luks "key=@$W/luks.key" >/dev/null 2>&1
check "$(bao kv get -field=hostname secret/rustguac/shared/Prod/win01)" 10.0.0.5 "entry is in OpenBao"
check "$(bao kv get -field=hostname secret/rustguac/instance/node1/Lab/vnc1)" 10.9.0.1 "instance entry is under instance/node1"
check "$(bao kv get -field=key secret/rustguac/luks)" luks-key-material "storage put wrote the LUKS key"
dump > "$W/A.json"
N=$(count < "$W/A.json")
check "$N" 9 "documents in OpenBao"

echo "== migrate vault -> sqlite"
check "$(migrate --from vault --to sqlite --dry-run 2>/dev/null; true)" "Re-run without --dry-run to perform the copy." "dry run"
check "$(python3 -c "import sqlite3; print(sqlite3.connect('$W/secrets.db').execute('select count(*) from secrets').fetchone()[0])")" 0 "dry run wrote nothing"
check "$(migrate --from vault --to sqlite)" "$N copied, 0 skipped (already in sqlite), 0 missing" "migrate to sqlite"

echo "== serve from SQLite"
write_config sqlite
serve
check "$(grep -c 'Secret store: SQLite' "$W/server.log")" 1 "server uses the SQLite store"
check "$(curl -s -H "$H" "$U/api/addressbook/folders/shared/Prod/entries" | grep -o '"hostname":"10.0.0.5"' | head -1)" \
    '"hostname":"10.0.0.5"' "RDP entry served from SQLite"
check "$(curl -s -H "$H" "$U/api/addressbook/folders/instance/Lab/entries" | grep -o '"hostname":"10.9.0.1"' | head -1)" \
    '"hostname":"10.9.0.1"' "instance entry served from SQLite"
check "$(curl -s -H "$H" "$U/api/addressbook/folders/shared/Prod/defaults" | grep -o '"username":"deploy"' | head -1)" \
    '"username":"deploy"' "folder defaults served from SQLite"
stop

echo "== fresh OpenBao, migrate sqlite -> vault"
start_bao
write_config vault
check "$(dump | count)" 0 "new OpenBao is empty"
check "$(migrate --from sqlite --to vault)" "$N copied, 0 skipped (already in vault), 0 missing" "migrate back to vault"
dump > "$W/B.json"
if diff -u "$W/A.json" "$W/B.json" > "$W/diff.txt"; then
    echo "ok   Vault -> SQLite -> Vault documents are identical"
else
    echo "FAIL round trip differs:"; head -40 "$W/diff.txt"; FAILED=1
fi
check "$(migrate --from sqlite --to vault)" "0 copied, $N skipped (already in vault), 0 missing" "second migrate skips everything"

[ "$FAILED" = 0 ] && echo "PASS" || echo "FAILED"
exit "$FAILED"
