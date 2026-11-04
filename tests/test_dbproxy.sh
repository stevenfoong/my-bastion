#!/usr/bin/env bash
#
# Live check of Phase 4a: the database proxy (dbproxy/) with a real
# PostgreSQL (a throwaway cluster) and psql as the client.
#   - psql through the proxy with a bastion DB token works; the database's
#     own password never reaches the user;
#   - a read-only user's INSERT is refused with a clear error;
#   - DELETE without WHERE is blocked; with WHERE on prod it waits for
#     approval, and runs once a person approves it;
#   - multi-statement strings, unparseable SQL and prepared statements
#     (extended protocol) are checked too; TLS and the token are required;
#   - every statement is in the core's audit log with the user and its
#     row count.
#
# Needs: go, PostgreSQL server binaries (initdb), psql.
# Usage: ./tests/test_dbproxy.sh   (PORT=18103, PG_PORT=15432, PROXY_PORT=15433)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18103}"
PG_PORT="${PG_PORT:-15432}"
PROXY_PORT="${PROXY_PORT:-15433}"
PGBIN="${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-db.XXXXXX)
PID=
PPID_=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$PPID_" ] && kill "$PPID_" 2>/dev/null
    [ -d "$W/pg" ] && "$PGBIN/pg_ctl" -D "$W/pg" -m immediate stop >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

[ -x "$PGBIN/initdb" ] || { echo "SKIP: no PostgreSQL server binaries"; exit 1; }
(cd dbproxy && go build -o "$W/dbproxy" .) || { echo "FAIL: dbproxy build"; exit 1; }

# A throwaway cluster with an app database and its own password.
echo postgres-pw > "$W/pgpw"
"$PGBIN/initdb" -D "$W/pg" -U postgres --auth-local=trust --auth-host=scram-sha-256 --pwfile="$W/pgpw" >/dev/null
mkdir -p "$W/sock"
"$PGBIN/pg_ctl" -D "$W/pg" -l "$W/pg.log" -o "-p $PG_PORT -k $W/sock -c listen_addresses=127.0.0.1" -w start >/dev/null
SQL() { psql -h "$W/sock" -p "$PG_PORT" -U postgres -qtA "$@"; }
SQL -c "CREATE ROLE app LOGIN PASSWORD 'app-db-pw-$$'" -c "CREATE DATABASE app OWNER app"
SQL -d app -c "SET ROLE app" -c "CREATE TABLE t (id int, v text)" -c "INSERT INTO t VALUES (1,'a'),(2,'b'),(3,'c')"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" -days 1 -subj "/CN=127.0.0.1" 2>/dev/null
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/secret"

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

[dbproxy]
enabled = true
shared_secret_file = "$W/secret"
address = "127.0.0.1:$PROXY_PORT"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
for u in op:operator ro:operator boss:admin; do CLI add-user --email "${u%%:*}@example.com" --role "${u##*:}" >/dev/null; done

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done
"$W/dbproxy" -listen "127.0.0.1:$PROXY_PORT" -core "$U" -secret-file "$W/secret" -tls-cert "$W/cert.pem" -tls-key "$W/key.pem" >>"$W/proxy.log" 2>&1 &
PPID_=$!
sleep 1

A="X-API-Key: $ADMIN_KEY"
token() {
    curl -s -H "$A" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1@example.com\",\"name\":\"db-test\"}" "$U/api/admin/user-tokens" | json 'd["token"]'
}
OP="Authorization: Bearer $(token op)"
RO="Authorization: Bearer $(token ro)"
BOSS="Authorization: Bearer $(token boss)"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }

for f in lab prod; do
    post "$A" /api/addressbook/folders "{\"name\":\"$f\",\"allowed_groups\":[],\"allowed_users\":[\"op@example.com\",\"ro@example.com\"]}" >/dev/null
    post "$A" "/api/addressbook/folders/shared/$f/entries" "{\"name\":\"pg\",\"type\":\"postgres\",\"hostname\":\"127.0.0.1\",\"port\":$PG_PORT,\"username\":\"app\",\"password\":\"app-db-pw-$$\",\"database\":\"app\"}" >/dev/null
done
pol() { check "$(post "$A" /api/admin/policies "$1")" 201 "policy: $2"; }
pol '{"name":"read-only for ro","subject":{"kind":"user","value":"ro@example.com"},"target":{"kind":"any"},"action":"db_query","classes":["write","ddl","admin","procedure"],"effect":"deny"}' "read-only for ro"
pol '{"name":"no unbounded writes","subject":{"kind":"any"},"target":{"kind":"any"},"action":"db_query","classes":["unbounded"],"effect":"deny"}' "no unbounded writes"
pol '{"name":"approve prod writes","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"db_query","classes":["write"],"effect":"require_approval","approvers":[{"kind":"role","value":"admin"}]}' "approve prod writes"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"any"},"target":{"kind":"any"},"action":"connect","classes":["read"],"effect":"deny"}')" 400 "classes only on db_query rules"

dbtoken() { post "$1" "/api/addressbook/folders/shared/$2/entries/pg/db-token" >/dev/null; json 'd["token"]' < "$W/out.json"; }
# psql through the proxy: token, user, then psql arguments.
pq() { local t=$1 u=$2; shift 2; PGPASSWORD="$t" psql "host=127.0.0.1 port=$PROXY_PORT dbname=app user=$u sslmode=require" -qtA "$@" 2>&1; }

echo "== psql through the proxy"
OPLAB=$(dbtoken "$OP" lab)
check "${OPLAB:0:5}" "mbdb_" "a DB token"
check "$(json 'd["psql"].startswith("PGPASSWORD=<token> psql")' < "$W/out.json")" True "with the psql command to use"
check "$(pq "$OPLAB" op -c "SELECT count(*) FROM t")" 3 "SELECT works"
check "$(pq "$OPLAB" op -c "SELECT current_user")" app "as the database's own user"
check "$(pq "$OPLAB" op -c "DELETE FROM t" | grep -c "denied by policy 'no unbounded writes'")" 1 "DELETE without WHERE is blocked"
check "$(pq "$OPLAB" op -c "SELECT count(*) FROM t")" 3 "and nothing was deleted"
check "$(pq "$OPLAB" op -c "UPDATE t SET v = 'z' WHERE id = 3" -c "SELECT v FROM t WHERE id = 3")" z "a bounded write in lab runs"
check "$(pq "$OPLAB" op -c "SELECT 1; DELETE FROM t" | grep -c "no unbounded writes")" 1 "a multi-statement string is checked statement by statement"
check "$(pq "$OPLAB" op -c "SELEC 1" | grep -c "could not be parsed")" 1 "unparseable SQL is refused"
check "$(printf 'DELETE FROM t \\bind \\g\n' | pq "$OPLAB" op | grep -c "no unbounded writes")" 1 "a prepared statement (extended protocol) is checked"
check "$(printf 'SELECT count(*) FROM t WHERE id > $1 \\bind 1 \\g\n' | pq "$OPLAB" op)" 2 "and an allowed one runs"

echo "== a read-only user"
ROLAB=$(dbtoken "$RO" lab)
check "$(pq "$ROLAB" ro -c "INSERT INTO t VALUES (9, 'x')" | grep -c "denied by policy 'read-only for ro'")" 1 "INSERT refused with a clear error"
check "$(pq "$ROLAB" ro -c "SELECT count(*) FROM t")" 3 "SELECT allowed"

echo "== prod writes wait for approval"
OPPROD=$(dbtoken "$OP" prod)
check "$(pq "$OPPROD" op -c "DELETE FROM t WHERE id = 1" | grep -c "held for approval")" 1 "DELETE with WHERE on prod waits"
REQ=$(curl -s -H "$BOSS" "$U/api/approvals" | json '[r["id"] for r in d["to_decide"] if r["requester"]=="op@example.com"][0]')
check "$(post "$BOSS" "/api/approvals/$REQ/approve" '{"comment":"ok"}')" 200 "a person approves it"
check "$(pq "$OPPROD" op -c "DELETE FROM t WHERE id = 1" -c "SELECT count(*) FROM t")" 2 "then it runs"
check "$(pq "$OPPROD" op -c "DELETE FROM t WHERE id = 2" | grep -c "held for approval")" 1 "another statement needs its own approval"

echo "== refusals"
check "$(pq "mbdb_nope" op -c "SELECT 1" | grep -c "invalid token")" 1 "a wrong token is refused"
check "$(PGPASSWORD="$OPLAB" psql "host=127.0.0.1 port=$PROXY_PORT dbname=app user=op sslmode=disable" -qtAc "SELECT 1" 2>&1 | grep -c "requires TLS")" 1 "TLS is required"
check "$(post "$A" /api/admin/policies '{"name":"no db for ro in prod","subject":{"kind":"user","value":"ro@example.com"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"connect","effect":"deny"}')" 201 "a connect deny"
check "$(post "$RO" /api/addressbook/folders/shared/prod/entries/pg/db-token)" 403 "no DB token where connecting is denied"

echo "== audit"
sleep 1
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='db_query' and r['actor']=='op@example.com' and 'SELECT count(*) FROM t' in r['detail']")" True "statements are audited with the user"
check "$(has "r['event']=='db_query' and 'DELETE FROM t WHERE id = 1' in r['detail'] and '\"rows\":1' in r['detail']")" True "with their row count"
check "$(has "r['event']=='db_query_blocked' and r['actor']=='ro@example.com' and 'INSERT' in r['detail']")" True "refusals too"
check "$(has "r['event']=='db_connect' and r['target']=='shared/prod/pg'")" True "and connections"
check "$(grep -c "app-db-pw-$$" "$W/server.log" "$W/proxy.log" | awk -F: '{s+=$2} END {print s}')" 0 "the database password is never logged"
check "$(grep -c "mbdb_" "$W/server.log" "$W/proxy.log" | awk -F: '{s+=$2} END {print s}')" 0 "nor the tokens"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; tail -20 "$W/proxy.log"; }
exit "$FAILED"
