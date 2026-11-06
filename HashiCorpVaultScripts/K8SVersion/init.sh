#!/bin/sh

# Initializes vault and stores the init.json in a Kubernetes Secret.

set -x
set -euo pipefail

status() { vault status -format=json 2>/dev/null || true; }

# 1. Wait until vault-0 answers (sealed or not)
echo "Waiting for vault..."
until [ -n "$(status 0)" ]; do sleep 3; done

# 2. Initialize once, store output in a Secret
if ! kubectl -n "$NS" get secret "$SECRET" >/dev/null 2>&1; then
if [ "$(status 0 | jq -r .initialized)" = "true" ]; then
    echo "Vault is initialized but Secret $SECRET is missing. Aborting." >&2
    exit 1
fi

echo "Initializing Vault..."
vault operator init \
    -key-shares=$SHARES -key-threshold=$THRESHOLD -format=json > /tmp/init.json

kubectl -n "$NS" create secret generic "$SECRET" \
    --from-file=init.json=/tmp/init.json
fi