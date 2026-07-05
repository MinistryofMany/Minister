#!/usr/bin/env bash
# Stand up the local Signet test stack for Minister's crypto-core e2e/fixture
# runs (build plan Phase 3 item 2): build Signet + the fixture tool from the
# sibling Signet checkout, generate certs + the frozen-seed keystore into
# .stack/, boot Signet on 127.0.0.1:9443, and wait for readiness.
#
# Usage:   signet-e2e/up.sh            (from the Minister repo root)
# Then:    set -a; source signet-e2e/.stack/minister.env; set +a
#          MINISTER_SIGNET_FIXTURE=1 pnpm --filter @minister/app exec \
#            vitest run src/lib/nullifier/signet-live.fixture.test.ts
#   or:    pnpm --filter @minister/app test:e2e   (signet-backed dev server)
# Stop:    signet-e2e/down.sh
#
# Prereqs: a Rust toolchain (1.87+) and the Signet repo checked out as a
# sibling of Minister (the MinistryOfMany workspace layout). The docker path
# (ministry-dev compose, profile "signet") mounts the same .stack/ — see
# README.md.

set -euo pipefail
cd "$(dirname "$0")"

SIGNET_REPO="../../Signet"
STACK_DIR=".stack"
BIND="${SIGNET_E2E_BIND:-127.0.0.1:9443}"
URL="https://localhost:${BIND##*:}"

if [ ! -d "$SIGNET_REPO" ]; then
  echo "signet-e2e: Signet checkout not found at $SIGNET_REPO" >&2
  exit 1
fi

echo "signet-e2e: building signet + fixture tool (first build takes a while)..."
(cd "$SIGNET_REPO" && cargo build --release --bin signet)
(cd fixture && cargo build --release)

echo "signet-e2e: generating certs + frozen-seed keystore into $STACK_DIR/..."
./fixture/target/release/signet-e2e-fixture \
  "$STACK_DIR" ../apps/minister/src/lib/nullifier/prf-vectors.json "$URL"

if [ -f "$STACK_DIR/signet.pid" ] && kill -0 "$(cat "$STACK_DIR/signet.pid")" 2>/dev/null; then
  echo "signet-e2e: an old signet is still running; stopping it first"
  kill "$(cat "$STACK_DIR/signet.pid")" || true
  sleep 1
fi

echo "signet-e2e: starting signet on $BIND..."
set -a
# shellcheck source=/dev/null
source "$STACK_DIR/signet.env"
set +a
SIGNET_BIND="$BIND" \
SIGNET_DB="$STACK_DIR/db/signet.db" \
SIGNET_TLS_CERT="$STACK_DIR/certs/server.pem" \
SIGNET_TLS_KEY="$STACK_DIR/certs/server.key" \
SIGNET_CLIENT_CA="$STACK_DIR/certs/ca.pem" \
  "$SIGNET_REPO/target/release/signet" >"$STACK_DIR/signet.log" 2>&1 &
echo $! > "$STACK_DIR/signet.pid"

echo "signet-e2e: waiting for readiness..."
for i in $(seq 1 30); do
  if curl -sf --cacert "$STACK_DIR/certs/ca.pem" \
      --cert "$STACK_DIR/certs/client.pem" --key "$STACK_DIR/certs/client.key" \
      "$URL/healthz" >/dev/null 2>&1; then
    echo "signet-e2e: up at $URL (pid $(cat "$STACK_DIR/signet.pid"))"
    echo "signet-e2e: source $STACK_DIR/minister.env for the Minister side"
    exit 0
  fi
  sleep 1
done

echo "signet-e2e: signet did not become ready; log tail:" >&2
tail -20 "$STACK_DIR/signet.log" >&2
exit 1
