#!/usr/bin/env bash
#
# Live check of command mode (Phase 2b): commands run through the bastion on
# an SSH entry, checked against ssh_command policies first.
#   - an allowed command runs and returns stdout, stderr and its exit status;
#   - `rm -rf /` (and a command that has it in it) is refused before it
#     reaches the target: a marker file it would create never appears;
#   - a command that needs approval waits; the approval covers that exact
#     command and no other;
#   - timeouts, jump hosts, role and entry-type checks, and the audit log.
#
# The target is this machine's own sshd (127.0.0.1:22) as the current user,
# with a throwaway key added to ~/.ssh/authorized_keys and removed on exit.
#
# Usage: ./tests/test_policy_run_ssh.sh   (PORT=18092 by default)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18092}"
U="http://127.0.0.1:$PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-runssh.XXXXXX)
MARK="mybastion-run-ssh-test-$$"
MARKER="/tmp/$MARK-ran"
PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -f ~/.ssh/authorized_keys ] && sed -i "/$MARK/d" ~/.ssh/authorized_keys
    rm -f "$MARKER"
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

[storage]
path = "$W/secrets.db"
kek_source = "file:$W/kek"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')
CLI add-user --email op@example.com --role operator >/dev/null
CLI add-user --email boss@example.com --role admin >/dev/null
CLI add-user --email viewer@example.com --role viewer >/dev/null

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
token() {
    curl -s -H "$A" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"name\":\"run-ssh-test\"}" "$U/api/admin/user-tokens" | json 'd["token"]'
}
OP="Authorization: Bearer $(token op@example.com)"
BOSS="Authorization: Bearer $(token boss@example.com)"
VIEWER="Authorization: Bearer $(token viewer@example.com)"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -H "$1" -H 'Content-Type: application/json' -d "$3" "$U$2"; }
run() {  # who, entry, command [, timeout] -> HTTP status; body in $W/out.json
    local body
    body=$(python3 -c "import json,sys; print(json.dumps({'command': sys.argv[1], 'timeout_secs': int(sys.argv[2])}))" "$3" "${4:-30}")
    post "$1" "/api/addressbook/folders/shared/prod/entries/$2/run" "$body"
}
out() { json "$1" < "$W/out.json"; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
post "$A" /api/addressbook/folders '{"name":"prod","allowed_groups":[],"allowed_users":["op@example.com","viewer@example.com"]}' >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries "{\"name\":\"viajump\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON,\"jump_hosts\":[{\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}]}" >/dev/null
post "$A" /api/addressbook/folders/shared/prod/entries '{"name":"desk","type":"rdp","hostname":"127.0.0.1","port":3389}' >/dev/null

echo "== policies"
check "$(post "$A" /api/admin/policies '{"name":"never wipe /","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"ssh_command","effect":"deny","commands":["rm\\s+-rf\\s+/(\\s|;|$)"]}')" 201 "deny rule for rm -rf /"
check "$(post "$A" /api/admin/policies '{"name":"sudo needs approval","subject":{"kind":"any"},"target":{"kind":"folder","scope":"shared","path":"prod"},"action":"ssh_command","effect":"require_approval","approvers":[{"kind":"role","value":"admin"}],"commands":["^sudo\\b"],"grant_minutes":10,"timeout_minutes":10}')" 201 "approval rule for sudo"
check "$(post "$A" /api/admin/policies '{"name":"bad","subject":{"kind":"any"},"target":{"kind":"any"},"action":"connect","effect":"deny","commands":["x"]}')" 400 "patterns refused on a connect rule"

echo "== allowed commands run"
check "$(run "$OP" web01 'echo hello-from-bastion; id -un')" 200 "echo runs"
check "$(out 'd["stdout"].split()')" "['hello-from-bastion', '$USER']" "stdout comes back"
check "$(out 'd["exit_status"]')" 0 "exit status 0"
run "$OP" web01 'ls /nonexistent-mybastion-dir' >/dev/null
check "$(out '(d["exit_status"] != 0, "No such file" in d["stderr"])')" "(True, True)" "stderr and a failing exit status"
run "$OP" web01 'exit 7' >/dev/null
check "$(out 'd["exit_status"]')" 7 "the command's own exit code"
run "$OP" web01 'sleep 5' 1 >/dev/null
check "$(out '(d["timed_out"], d["exit_status"])')" "(True, None)" "timeout stops waiting"
check "$(run "$OP" viajump 'echo via-jump')" 200 "through a jump host"
check "$(out 'd["stdout"].strip()')" via-jump "jump-host output"

echo "== denied commands never reach the target"
check "$(run "$OP" web01 "rm -rf /; touch $MARKER")" 403 "rm -rf / refused"
check "$(out 'd["policy"]')" "never wipe /" "names the policy"
check "$(run "$OP" web01 "true && sudo rm -rf / --no-preserve-root; touch $MARKER")" 403 "rm -rf / inside a longer line refused"
sleep 1
check "$([ -e "$MARKER" ] && echo ran || echo 'not run')" "not run" "the target never ran the refused commands"
check "$(run "$OP" web01 'rm -rf /tmp/does-not-matter-xyz')" 200 "rm -rf on another path is not caught by that rule"

echo "== commands that need approval"
check "$(run "$OP" web01 'sudo -n true')" 202 "sudo waits for approval"
REQ=$(out 'd["approval"]["id"]')
check "$(out 'd["approval"]["command"]')" "sudo -n true" "the request carries the command"
check "$(post "$OP" "/api/approvals/$REQ/approve" '{}')" 403 "requester cannot approve"
check "$(post "$BOSS" "/api/approvals/$REQ/approve" '{"comment":"ok"}')" 200 "admin approves"
check "$(run "$OP" web01 'sudo -n true')" 200 "the approved command runs"
check "$(run "$OP" web01 'sudo -n id')" 202 "another sudo command needs its own approval"

echo "== who may run, and on what"
check "$(run "$VIEWER" web01 'echo hi')" 403 "viewer refused"
check "$(run "$OP" desk 'echo hi')" 400 "not on an RDP entry"
check "$(run "$OP" web01 $'echo a\necho b')" 400 "one line only"

echo "== audit"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=500")
has() { echo "$AUDIT" | json "any($1 for r in d)"; }
check "$(has "r['event']=='command_run' and 'hello-from-bastion' in (r['detail'] or '') and '\"exit_status\":0' in (r['detail'] or '') and r['requester']=='op@example.com'")" True "a run command is audited with its exit status"
check "$(has "r['event']=='denied' and r['policy']=='never wipe /' and r['action']=='ssh_command'")" True "the refusal is audited"
check "$(has "r['event']=='command_run' and 'rm -rf /;' in (r['detail'] or '')")" False "the refused command never ran"
check "$(has "r['event']=='approved' and r['actor']=='boss@example.com' and r['action']=='ssh_command'")" True "the approval is audited"

[ "$FAILED" = 0 ] && echo "PASS" || echo "FAILED"
exit "$FAILED"
