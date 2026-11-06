#!/bin/sh

set -x
set -euo pipefail

status() { vault status -format=json 2>/dev/null || true; }

load_keys() {
    kubectl -n "$NS" get secret "$SECRET" \
    -o jsonpath='{.data.init\.json}' | base64 -d > /tmp/init.json
}

unseal() {
[ "$(status | jq -r .sealed)" = "false" ] && { echo "vault already unsealed"; return; }
echo "Unsealing vault"
n=0
while [ "$n" -lt "$THRESHOLD" ]; do
    KEY=$(jq -r ".unseal_keys_b64[$n]" /tmp/init.json)
    vault operator unseal "$KEY" >/dev/null
    n=$((n+1))
done
}

load_keys
unseal

echo "Done."
vault status