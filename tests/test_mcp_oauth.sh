#!/usr/bin/env bash
#
# Live check of Phase 3d: OAuth 2.1 for people using an AI client on /mcp,
# against a fake OIDC provider (tests/fake_oidc.py) and a scripted client
# and browser (tests/oauth_client.py).
#   - discovery from /mcp's 401, client registration, admin approval of a
#     client name, sign-in through the identity provider, consent, PKCE;
#   - the token acts as `user:<email> via ai:<client>` with the person's own
#     folder access, only in AI folders; scopes limit the tools;
#   - refresh tokens rotate; a reused one revokes the grant; the identity
#     provider is asked again on refresh: dropping the user from a group
#     cuts the folder off, and revoking them ends the grant;
#   - a disabled user, a denied client and a revoked grant lose access;
#   - bad PKCE and unregistered redirect URIs are refused.
#
# Usage: ./tests/test_mcp_oauth.sh   (PORT=18101, IDP_PORT=18102)

set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18101}"
IDP_PORT="${IDP_PORT:-18102}"
U="http://127.0.0.1:$PORT"
IDP="http://127.0.0.1:$IDP_PORT"
cargo build -q || exit 1
BIN="$PWD/target/debug/mybastion"
W=$(mktemp -d /tmp/mybastion-oauth.XXXXXX)
MARK="mybastion-oauth-test-$$"
PID=
IPID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    [ -n "$IPID" ] && kill "$IPID" 2>/dev/null
    [ -f ~/.ssh/authorized_keys ] && sed -i "/$MARK/d" ~/.ssh/authorized_keys
    rm -rf "$W"
}
trap cleanup EXIT

FAILED=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; FAILED=1; fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }

python3 tests/fake_oidc.py "$IDP_PORT" mybastion-test "$W" &
IPID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$IDP/jwks" && break; sleep 0.2; done

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

[oidc]
issuer_url = "$IDP"
client_id = "mybastion-test"
client_secret = "s3cret"
redirect_uri = "$U/auth/callback"
groups_claim = "groups"
default_role = "operator"

[mcp]
enabled = true

[mcp.oauth]
enabled = true
public_url = "$U"
EOF
CLI() { "$BIN" --config "$W/config.toml" "$@" 2>/dev/null; }
ADMIN_KEY=$(CLI add-admin --name e2e | sed -n 's/^API Key: //p')

"$BIN" --config "$W/config.toml" serve >>"$W/server.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$U/" && break; sleep 0.2; done

A="X-API-Key: $ADMIN_KEY"
post() { curl -s -o "$W/out.json" -w '%{http_code}' -X "${4:-POST}" -H "$1" -H 'Content-Type: application/json' -d "${3:-{\}}" "$U$2"; }
oc() { python3 tests/oauth_client.py "$@"; }
tool() { python3 tests/mcp_call.py "$U/mcp" "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; }
conns() { tool "$1" list_connections '{}' | json 'sorted(c["id"] for c in __import__("json").loads(d["body"]["result"]["content"][0]["text"])["connections"]) if not d["body"]["result"].get("isError") else d["body"]["result"]["content"][0]["text"]'; }
err() { json 'd["body"]["result"]["content"][0]["text"] if d["body"]["result"].get("isError") else "no error"'; }
idp_user() { curl -s -X POST -d "$1" "$IDP/test/user" >/dev/null; }

KEYJSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$W/key")
post "$A" /api/addressbook/folders '{"name":"lab","allowed_groups":["ops"],"ai_mode":"auto"}' >/dev/null
post "$A" /api/addressbook/folders '{"name":"prod","allowed_groups":["dba"],"ai_mode":"auto"}' >/dev/null
for f in lab prod; do
    post "$A" "/api/addressbook/folders/shared/$f/entries" "{\"name\":\"web01\",\"type\":\"ssh\",\"hostname\":\"127.0.0.1\",\"port\":22,\"username\":\"$USER\",\"private_key\":$KEYJSON}" >/dev/null
done

echo "== metadata"
PRM=$(curl -s "$U/.well-known/oauth-protected-resource")
check "$(echo "$PRM" | json '(d["resource"], d["authorization_servers"])')" "('$U/mcp', ['$U'])" "protected resource metadata"
check "$(curl -s "$U/.well-known/oauth-authorization-server" | json '(d["code_challenge_methods_supported"], d["grant_types_supported"])')" "(['S256'], ['authorization_code', 'refresh_token'])" "authorization server metadata"

echo "== a new client waits for an admin"
R=$(oc flow "$U" Claude)
check "$(echo "$R" | json '(d["challenge"], d["stage"])')" "(True, 'pending')" "discovered from the 401; Claude is pending"
check "$(curl -s -H "$A" "$U/api/admin/oauth-clients" | json '[(c["name"], c["status"]) for c in d]')" "[('Claude', 'pending')]" "admins see it waiting"
check "$(post "$A" /api/admin/oauth-clients/Claude/approve)" 200 "an admin approves Claude"

echo "== sign-in, consent, tokens"
R=$(oc flow "$U" Claude)
check "$(echo "$R" | json '(d["stage"], d["state_back"], d["iss"])')" "('tokens', 'st8', '$U')" "the flow ends with tokens"
check "$(echo "$R" | json '("shared/lab" in d["consent"], "shared/prod" in d["consent"], "alice@example.com" in d["consent"])')" "(True, False, True)" "the consent screen shows her AI folders only"
AT=$(echo "$R" | json 'd["tokens"]["access_token"]')
RT=$(echo "$R" | json 'd["tokens"]["refresh_token"]')
CID=$(echo "$R" | json 'd["client_id"]')
check "$(echo "$R" | json '(d["tokens"]["scope"], d["tokens"]["expires_in"])')" "('mcp:read mcp:act', 900)" "scopes and a 15-minute access token"
check "$(conns "$AT")" "['shared/lab/web01']" "she sees what she may reach (not prod)"
R2=$(tool "$AT" run_ssh "{\"connection\":\"shared/lab/web01\",\"command\":\"echo via-$MARK\"}")
check "$(echo "$R2" | json '__import__("json").loads(d["body"]["result"]["content"][0]["text"])["stdout"].strip()')" "via-$MARK" "run_ssh works as her"
check "$(tool "$AT" run_ssh '{"connection":"shared/prod/web01","command":"id"}' | err)" "no such connection for this agent" "not where she may not go"
AUDIT=$(curl -s -H "$A" "$U/api/admin/policy-audit?limit=200")
check "$(echo "$AUDIT" | json "any(r['event']=='command_run' and r['actor']=='user:alice@example.com via ai:Claude' for r in d)")" True "audited as user:alice via ai:Claude"
check "$(curl -s -H "$A" "$U/api/admin/ai-grants" | json '[(g["email"], g["client_name"], g["idp_linked"]) for g in d]')" "[('alice@example.com', 'Claude', True)]" "the grant keeps an identity provider link"

echo "== refresh"
F=$(oc refresh "$U" "$CID" "$RT")
check "$(echo "$F" | json 'd["status"]')" 200 "refresh"
check "$(curl -s "$IDP/test/calls" | json 'd.count("refresh_token")')" 1 "and the identity provider was asked"
RT2=$(echo "$F" | json 'd["body"]["refresh_token"]')
AT2=$(echo "$F" | json 'd["body"]["access_token"]')
check "$([ "$RT2" != "$RT" ] && echo rotated)" rotated "the refresh token rotates"
check "$(oc refresh "$U" "$CID" "$RT" | json '(d["status"], d["body"]["error"])')" "(400, 'invalid_grant')" "a reused refresh token is refused"
check "$(python3 tests/mcp_call.py "$U/mcp" "$AT2" tools/list | json 'd["status"]')" 401 "and the whole grant is revoked"

echo "== the identity provider decides"
R=$(oc flow "$U" Claude)
CID=$(echo "$R" | json 'd["client_id"]')
AT=$(echo "$R" | json 'd["tokens"]["access_token"]'); RT=$(echo "$R" | json 'd["tokens"]["refresh_token"]')
check "$(conns "$AT")" "['shared/lab/web01']" "a new grant"
idp_user '{"groups": []}'
F=$(oc refresh "$U" "$CID" "$RT")
AT=$(echo "$F" | json 'd["body"]["access_token"]'); RT=$(echo "$F" | json 'd["body"]["refresh_token"]')
check "$(conns "$AT")" "[]" "removed from ops at the provider: lab is gone after the refresh"
curl -s -X POST "$IDP/test/revoke" >/dev/null
check "$(oc refresh "$U" "$CID" "$RT" | json '(d["status"], d["body"]["error"])')" "(400, 'invalid_grant')" "revoked at the provider: the refresh fails"
check "$(python3 tests/mcp_call.py "$U/mcp" "$AT" tools/list | json 'd["status"]')" 401 "and the grant is gone"
idp_user '{"groups": ["ops"]}'

echo "== scopes, users, clients"
R=$(oc flow "$U" Claude mcp:read)
AT=$(echo "$R" | json 'd["tokens"]["access_token"]')
check "$(tool "$AT" run_ssh '{"connection":"shared/lab/web01","command":"id"}' | err)" "this token lacks the mcp:act scope" "a read-only token cannot act"
check "$(conns "$AT")" "['shared/lab/web01']" "but can list"
CLI disable-user --email alice@example.com >/dev/null
check "$(python3 tests/mcp_call.py "$U/mcp" "$AT" tools/list | json 'd["status"]')" 401 "a disabled user's token stops working"
"$BIN" --config "$W/config.toml" set-role --email alice@example.com --role operator >/dev/null 2>&1
python3 - "$W/mybastion.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1]); c.execute("UPDATE users SET disabled = 0"); c.commit()
PY
R=$(oc flow "$U" Claude)
AT=$(echo "$R" | json 'd["tokens"]["access_token"]')
check "$(conns "$AT")" "['shared/lab/web01']" "re-enabled, a new grant works"
check "$(post "$A" /api/admin/oauth-clients/Claude/deny)" 200 "an admin denies Claude"
check "$(python3 tests/mcp_call.py "$U/mcp" "$AT" tools/list | json 'd["status"]')" 401 "and its grants end"
check "$(oc flow "$U" Claude | json 'd["stage"], d.get("error")')" "('denied', 'access_denied')" "and it cannot sign anyone in again"
post "$A" /api/admin/oauth-clients/Claude/approve >/dev/null

echo "== refusals"
check "$(oc flow "$U" Claude "" --deny | json 'd["stage"], d.get("error")')" "('denied', 'access_denied')" "the person can deny consent"
check "$(oc flow "$U" Claude "" --bad-verifier | json 'd["token_status"], d["tokens"]["error"]')" "(400, 'invalid_grant')" "a wrong PKCE verifier is refused"
check "$(oc authorize "$U" "$CID" "https://evil.example/cb" | json 'd["status"], d["location"]')" "(400, None)" "an unregistered redirect URI is never redirected to"
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"client_name":"X","redirect_uris":["http://evil.example/cb"]}' "$U/oauth/register")" 400 "plain-http redirect URIs are refused at registration"
check "$(grep -c "mbat_\|mbrt_" "$W/server.log")" 0 "tokens never reach the server log"

[ "$FAILED" = 0 ] && echo "PASS" || { echo "FAILED"; tail -30 "$W/server.log"; }
exit "$FAILED"
