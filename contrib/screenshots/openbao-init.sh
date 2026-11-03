#!/bin/sh
# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# Prepare the OpenBao dev server for mybastion: the same policy and AppRole
# as contrib/vault-quickstart.sh, but with a fixed role ID and secret ID so
# that config.toml can name them. Dev mode only; the server keeps nothing.
set -eu

export BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
export BAO_TOKEN="${BAO_TOKEN:-root}"

for _ in $(seq 1 30); do
    bao status >/dev/null 2>&1 && break
    sleep 1
done
bao status >/dev/null

bao policy write mybastion - <<'EOF'
path "secret/data/mybastion/*" {
    capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/mybastion/*" {
    capabilities = ["list", "read", "delete"]
}
EOF

bao auth list | grep -q '^approle/' || bao auth enable approle
bao write auth/approle/role/mybastion \
    token_policies=mybastion token_ttl=1h token_max_ttl=4h secret_id_ttl=0
bao write auth/approle/role/mybastion/role-id role_id=screenshots-role
# Destroy first so that the script can run again against the same server.
bao write auth/approle/role/mybastion/secret-id/destroy secret_id=screenshots-secret
bao write auth/approle/role/mybastion/custom-secret-id secret_id=screenshots-secret

echo "OpenBao ready"
