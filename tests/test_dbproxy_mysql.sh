#!/usr/bin/env bash
#
# Live check of Phase 4c: the database proxy with a real MariaDB (a
# throwaway server) and the mariadb client.
#   - the mariadb client through the proxy with a bastion DB token works,
#     both ways it can send the token (caching_sha2_password full auth and
#     mysql_clear_password); the database's own password never reaches the
#     user;
#   - a read-only user's INSERT is refused with a clear error; DELETE
#     without WHERE is blocked; with WHERE on prod it waits for approval,
#     and runs once a person approves it;
#   - USE (COM_INIT_DB), prepared statements and multi-statement strings
#     (go-sql-driver/mysql, dbproxy/live_mysql_test.go) are checked too;
#   - TLS and the token are required; a PostgreSQL token is refused here;
#   - every statement is in the core's audit log with its row count.
#
# Needs: go, mariadb-server (mariadbd, mariadb-install-db), mariadb client.
# Usage: ./tests/test_dbproxy_mysql.sh   (PORT=18104, MY_PORT=13306, PROXY_PORT=13307)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18104}"
MY_PORT="${MY_PORT:-13306}"
PROXY_PORT="${PROXY_PORT:-13307}"
PG_PROXY_PORT="${PG_PROXY_PORT:-15434}"
U="http://127.0.0.1:$PORT"
MARIADBD=$(command -v mariadbd || echo /usr/sbin/mariadbd)
[ -x "$MARIADBD" ] && command -v mariadb-install-db >/dev/null && command -v mariadb >/dev/null \
    || { echo "SKIP: no MariaDB server/client"; exit 1; }
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-my.XXXXXX)
PID=
PPID_=
MYPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$PPID_" ] && kill "$PPID_" 2>/dev/null
    [ -n "$MYPID" ] && kill "$MYPID" 2>/dev/null && wait "$MYPID" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

(cd dbproxy && go build -o "$W/dbproxy" .) || { echo "FAIL: dbproxy build"; exit 1; }

# A throwaway server; this OS user is its admin (unix socket auth).
mariadb-install-db --no-defaults --datadir="$W/my" --auth-root-authentication-method=socket >"$W/install.log" 2>&1 \
    || { cat "$W/install.log"; exit 1; }
"$MARIADBD" --no-defaults --datadir="$W/my" --socket="$W/my.sock" --port="$MY_PORT" \
    --bind-address=127.0.0.1 --pid-file="$W/my.pid" --log-error="$W/my.log" &
MYPID=$!
for _ in $(seq 50); do [ -S "$W/my.sock" ] && break; sleep 0.2; done
SQL() { mariadb --no-defaults -S "$W/my.sock" -u "$(whoami)" -N -B "$@"; }
# (No anonymous users: ''@localhost would match before 'app'@'%'.)
SQL -e "DELETE FROM mysql.global_priv WHERE User = ''; FLUSH PRIVILEGES" || exit 1
SQL -e "CREATE DATABASE app; CREATE USER 'app'@'%' IDENTIFIED BY 'app-db-pw-$$'; GRANT ALL ON app.* TO 'app'@'%';
        CREATE TABLE app.t (id int, v text); INSERT INTO app.t VALUES (1,'a'),(2,'b'),(3,'c')" || exit 1

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
address = "127.0.0.1:$PG_PROXY_PORT"
mysql_address = "127.0.0.1:$PROXY_PORT"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
for u in op:operator ro:operator boss:admin; do CLI add-user --email "${u%%:*}@example.com" --role "${u##*:}" >/dev/null; done

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done
"$W/dbproxy" -listen "127.0.0.1:$PG_PROXY_PORT" -mysql-listen "127.0.0.1:$PROXY_PORT" -core "$U" -secret-file "$W/secret" \
    -tls-cert "$W/cert.pem" -tls-key "$W/key.pem" >>"$W/proxy.log" 2>&1 &
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
    post "$A" "/api/addressbook/folders/shared/$f/entries" "{\"name\":\"my\",\"type\":\"mysql\",\"hostname\":\"127.0.0.1\",\"port\":$MY_PORT,\"username\":\"app\",\"password\":\"app-db-pw-$$\",\"database\":\"app\"}" >/dev/null
done
post "$A" "/api/addressbook/folders/shared/lab/entries" "{\"name\":\"pg\",\"type\":\"postgres\",\"hostname\":\"127.0.0.1\",\"port\":5432,\"username\":\"x\",\"password\":\"y\"}" >/dev/null
pol() { check "$(post "$A" /api/admin/policies "$1")" 201 "policy: $2"; }
pol '{"name":"read-only for ro","subject":{"kind":"user","value":"ro@example.com"},"target":{"kind":"any"},"action":"db_query","classes":["write","ddl","admin","procedure"],"effect":"deny"}' "read-only for ro"
pol '{"name":"no unbounded writes","subject":{"kind":"any"},"target":{"kind":"any"},"action":"db_query","classes":["unbounded"],"effect":"deny"}' "no unbounded writes"
pol '{"name":"approve prod writes","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"db_query","classes":["write"],"effect":"require_approval","approvers":[{"kind":"role","value":"admin"}]}' "approve prod writes"
pol '{"name":"no other database","subject":{"kind":"any"},"target":{"kind":"any"},"action":"db_query","commands":["(?i)^USE `?mysql`?$"],"effect":"deny"}' "no USE mysql"

dbtoken() { post "$1" "/api/addressbook/folders/shared/$2/entries/${3:-my}/db-token" >/dev/null; json 'd["token"]' < "$W/out.json"; }
# The mariadb client through the proxy: token, then client arguments.
my() {
    local t=$1; shift
    MYSQL_PWD="$t" mariadb --no-defaults -h 127.0.0.1 -P "$PROXY_PORT" -u someone --ssl --skip-ssl-verify-server-cert -N -B "$@" 2>&1
}

echo "== the mariadb client through the proxy"
OPLAB=$(dbtoken "$OP" lab)
check "${OPLAB:0:5}" "mbdb_" "a DB token"
check "$(json 'd["protocol"] + " " + str(d["command"].startswith("MYSQL_PWD=<token> mysql -h 127.0.0.1 -P '"$PROXY_PORT"'"))' < "$W/out.json")" "mysql True" "with the mysql command to use"
check "$(my "$OPLAB" -e "SELECT count(*) FROM t")" 3 "SELECT works (in the entry's database)"
check "$(my "$OPLAB" -e "SELECT current_user()")" "app@%" "as the database's own user"
check "$(my "$OPLAB" --default-auth=mysql_native_password -e "SELECT 41+1")" 42 "the token also goes as a clear password (auth switch)"
check "$(my "$OPLAB" -e "DELETE FROM t" | grep -c "denied by policy 'no unbounded writes'")" 1 "DELETE without WHERE is blocked"
check "$(my "$OPLAB" -e "SELECT count(*) FROM t")" 3 "and nothing was deleted"
check "$(my "$OPLAB" -e "UPDATE t SET v = 'z' WHERE id = 3; SELECT v FROM t WHERE id = 3")" z "a bounded write in lab runs"
check "$(my "$OPLAB" -e "SELEC 1" | grep -c "could not be parsed")" 1 "unparseable SQL is refused"
check "$(my "$OPLAB" -e "SELECT 1 FROM DUAL WHERE 1 = 0; SHOW TABLES")" t "an empty result, then SHOW"
check "$(my "$OPLAB" -e "USE mysql" | grep -c "denied by policy 'no other database'")" 1 "USE (COM_INIT_DB) is checked"
check "$(my "$OPLAB" -e "SELECT REPEAT('x', 300000)" | wc -c)" 300001 "a large value comes through"
check "$(my "$OPLAB" -e "SELECT seq FROM seq_1_to_20000" | wc -l)" 20000 "many rows come through"

echo "== prepared statements and multi-statement strings (go-sql-driver/mysql)"
GOT=$(cd dbproxy && MYSQL_PROXY_DSN="someone:$OPLAB@tcp(127.0.0.1:$PROXY_PORT)/app?tls=skip-verify&allowCleartextPasswords=true" \
    go test -count=1 -tags live -run Live ./... 2>&1)
check "$(echo "$GOT" | grep -c '^ok')" 1 "prepared statements and multi-statements are checked"
echo "$GOT" | grep -v '^ok' | head -20

echo "== a read-only user"
ROLAB=$(dbtoken "$RO" lab)
check "$(my "$ROLAB" -e "INSERT INTO t VALUES (9, 'x')" | grep -c "denied by policy 'read-only for ro'")" 1 "INSERT refused with a clear error"
check "$(my "$ROLAB" -e "SELECT count(*) FROM t")" 3 "SELECT allowed"

echo "== prod writes wait for approval"
OPPROD=$(dbtoken "$OP" prod)
check "$(my "$OPPROD" -e "DELETE FROM t WHERE id = 1" | grep -c "held for approval")" 1 "DELETE with WHERE on prod waits"
REQ=$(curl -s -H "$BOSS" "$U/api/approvals" | json '[r["id"] for r in d["to_decide"] if r["requester"]=="op@example.com"][0]')
check "$(post "$BOSS" "/api/approvals/$REQ/approve" '{"comment":"ok"}')" 200 "a person approves it"
check "$(my "$OPPROD" -e "DELETE FROM t WHERE id = 1; SELECT count(*) FROM t")" 2 "then it runs"

echo "== refusals"
check "$(my "mbdb_nope" -e "SELECT 1" | grep -c "invalid token")" 1 "a wrong token is refused"
check "$(MYSQL_PWD="$OPLAB" mariadb --no-defaults -h 127.0.0.1 -P "$PROXY_PORT" -u x --skip-ssl -N -B -e "SELECT 1" 2>&1 | grep -c "TLS is required")" 1 "TLS is required"
PGTOK=$(dbtoken "$OP" lab pg)
check "$(my "$PGTOK" -e "SELECT 1" | grep -c "connect to the bastion's PostgreSQL port")" 1 "a PostgreSQL token is refused on the MySQL port"
post "$A" "/api/addressbook/folders/shared/lab/entries" "{\"name\":\"down\",\"type\":\"mysql\",\"hostname\":\"127.0.0.1\",\"port\":1,\"username\":\"app\",\"password\":\"x\"}" >/dev/null
check "$(my "$(dbtoken "$OP" lab down)" -e "SELECT 1" | grep -c "cannot connect to the database")" 1 "a database that cannot be reached says so"
check "$(my "$OPLAB" -e "LOAD DATA LOCAL INFILE '/etc/hostname' INTO TABLE t" 2>&1 | grep -ci "error")" 1 "LOAD DATA LOCAL does not work"

echo "== audit"
my "$OPLAB" -e "SELECT 'last-$$'" >/dev/null
for _ in $(seq 25); do
    curl -s -H "$A" "$U/api/admin/policy-audit?limit=50" | grep -q "last-$$" && break
    sleep 0.2
done
check "$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=50" | grep -c "last-$$")" 1 "the last statement before a disconnect is audited"
sleep 1
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='db_query' and r['actor']=='op@example.com' and 'SELECT count(*) FROM t' in r['detail']")" True "statements are audited with the user"
check "$(has "r['event']=='db_query' and 'DELETE FROM t WHERE id = 1' in r['detail'] and '\"rows\":1' in r['detail']")" True "with their row count"
check "$(has "r['event']=='db_query' and 'seq_1_to_20000' in r['detail'] and '\"rows\":20000' in r['detail']")" True "result sets with their row count"
check "$(has "r['event']=='db_query' and 'UPDATE t SET v = ? WHERE id = ?' in r['detail'] and '\"rows\":1' in r['detail']")" True "prepared statements when they run"
check "$(has "r['event']=='db_query_blocked' and r['actor']=='ro@example.com' and 'INSERT' in r['detail']")" True "refusals too"
check "$(has "r['event']=='db_connect' and r['target']=='shared/prod/my'")" True "and connections"
check "$(grep -c "app-db-pw-$$" "$W/server.log" "$W/proxy.log" | awk -F: '{s+=$2} END {print s}')" 0 "the database password is never logged"
check "$(grep -c "mbdb_" "$W/server.log" "$W/proxy.log" | awk -F: '{s+=$2} END {print s}')" 0 "nor the tokens"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -20 "$W/server.log"; tail -20 "$W/proxy.log"; }
exit "$FAILED"
