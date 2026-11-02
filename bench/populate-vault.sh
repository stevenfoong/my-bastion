#!/bin/bash
# Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
# Populate Vault with address book entries for benchmarking.
# Usage: ./populate-vault.sh [total_entries] [folders] [vault_addr] [api_key] [mybastion_url]
#
# Defaults: 1000 entries across 20 folders.
# Uses the mybastion API (not Vault directly) so entries are properly formatted.
set -e

TOTAL=${1:-1000}
FOLDERS=${2:-20}
VAULT_ADDR=${3:-"http://127.0.0.1:8200"}
API_KEY=${4:-""}
MYBASTION_URL=${5:-"https://localhost:8089"}
ENTRIES_PER_FOLDER=$((TOTAL / FOLDERS))

if [ -z "$API_KEY" ]; then
    echo "Usage: $0 [entries] [folders] [vault_addr] [api_key] [mybastion_url]"
    echo "  api_key is required (admin API key for mybastion)"
    exit 1
fi

CURL="curl -sk -H X-API-Key:${API_KEY} -H Content-Type:application/json"

echo "Creating $TOTAL entries across $FOLDERS folders ($ENTRIES_PER_FOLDER per folder)"
echo "mybastion: $MYBASTION_URL"

for f in $(seq 1 $FOLDERS); do
    FOLDER="bench-folder-$(printf '%02d' $f)"

    # Create folder
    $CURL -X POST "$MYBASTION_URL/api/addressbook/folders" \
        -d "{\"name\":\"$FOLDER\",\"scope\":\"shared\",\"description\":\"Benchmark folder $f\",\"allowed_groups\":[]}" \
        -o /dev/null 2>/dev/null

    for e in $(seq 1 $ENTRIES_PER_FOLDER); do
        ENTRY="rdp-host-$(printf '%02d' $f)-$(printf '%03d' $e)"
        OCTET3=$((f % 256))
        OCTET4=$((e % 256))

        $CURL -X PUT "$MYBASTION_URL/api/addressbook/folders/shared/$FOLDER/entries/$ENTRY" \
            -d "{
                \"type\":\"rdp\",
                \"hostname\":\"10.99.${OCTET3}.${OCTET4}\",
                \"port\":3389,
                \"username\":\"bench$(printf '%02d' $e)\",
                \"password\":\"bench\",
                \"display_name\":\"RDP Host $f-$e\",
                \"ignore_cert\":true,
                \"security\":\"any\"
            }" -o /dev/null 2>/dev/null
    done
    echo "  $FOLDER: $ENTRIES_PER_FOLDER entries"
done

echo "Done: $TOTAL entries in $FOLDERS folders"
