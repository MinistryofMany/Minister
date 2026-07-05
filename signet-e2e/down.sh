#!/usr/bin/env bash
# Stop the local Signet test stack started by up.sh.
set -euo pipefail
cd "$(dirname "$0")"
if [ -f .stack/signet.pid ]; then
  kill "$(cat .stack/signet.pid)" 2>/dev/null || true
  rm -f .stack/signet.pid
  echo "signet-e2e: stopped"
else
  echo "signet-e2e: not running"
fi
