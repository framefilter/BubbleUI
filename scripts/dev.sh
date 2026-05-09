#!/usr/bin/env bash
# scripts/dev.sh — start every BubbleUI daemon plus the Vite dev server
# in one shot. Each daemon writes to its own log under /tmp/bubble-dev/;
# Ctrl-C tears them all down.
#
# Daemons (default ports):
#   bubble-authd   :8765   /auth/* + /api/time/sync
#   bubble-vpnd    :8766   /vpn/*
#   bubble-netd    :8767   /net/*
#   bubble-hwd     :8768   /hw/*
#   pnpm dev       :5173   the SPA (Vite proxy points at the daemons)
#
# Mock-mode is on for everything by default — no router required.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGDIR="${BUBBLE_DEV_LOGS:-/tmp/bubble-dev}"
DBDIR="${BUBBLE_DEV_DBS:-/tmp/bubble-dev/db}"
mkdir -p "$LOGDIR" "$DBDIR"

# Kill anything from a previous run that's still bound to our ports.
for port in 8765 8766 8767 8768; do
  pids=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p { print $NF }' \
         | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  if [ -n "$pids" ]; then
    echo "killing stale bubble process(es) on :$port: $pids"
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
done

PIDS=()

cleanup() {
  echo
  echo "shutting down…"
  # shellcheck disable=SC2086
  kill ${PIDS[*]} 2>/dev/null || true
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

cd "$ROOT/backend"

echo "==> building all four daemons"
go build -o "$LOGDIR/bubble-authd" ./cmd/bubble-authd
go build -o "$LOGDIR/bubble-vpnd"  ./cmd/bubble-vpnd
go build -o "$LOGDIR/bubble-netd"  ./cmd/bubble-netd
go build -o "$LOGDIR/bubble-hwd"   ./cmd/bubble-hwd

# bubble-authd needs a provisioned credential to log in; the mock secret
# is auto-generated on first provision and persisted to a sidecar file.
if [ ! -s "$DBDIR/auth.db.mock-secret" ]; then
  echo "==> provisioning a mock YubiKey credential (first run only)"
  "$LOGDIR/bubble-authd" -db "$DBDIR/auth.db" -mock provision \
    | grep -E '^    [A-Za-z0-9-]+|saved' || true
fi

echo "==> launching daemons (logs in $LOGDIR)"
"$LOGDIR/bubble-authd" -db "$DBDIR/auth.db" -mock serve \
    -listen 127.0.0.1:8765 -insecure -rp-id localhost \
    > "$LOGDIR/authd.log" 2>&1 &
PIDS+=("$!")

"$LOGDIR/bubble-vpnd" -db "$DBDIR/vpn.db" -listen 127.0.0.1:8766 \
    > "$LOGDIR/vpnd.log" 2>&1 &
PIDS+=("$!")

"$LOGDIR/bubble-netd" -listen 127.0.0.1:8767 \
    > "$LOGDIR/netd.log" 2>&1 &
PIDS+=("$!")

"$LOGDIR/bubble-hwd" -listen 127.0.0.1:8768 -mock \
    > "$LOGDIR/hwd.log" 2>&1 &
PIDS+=("$!")

# Wait for each port to come up so the SPA's first requests don't 502.
for port in 8765 8766 8767 8768; do
  for _ in $(seq 1 50); do
    if curl -sf -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null \
       || curl -sf -o /dev/null "http://127.0.0.1:$port/auth/session/whoami" 2>/dev/null \
       || curl -sf -o /dev/null "http://127.0.0.1:$port/vpn/configs" 2>/dev/null \
       || curl -sf -o /dev/null "http://127.0.0.1:$port/net/signin/status" 2>/dev/null \
       || curl -sf -o /dev/null "http://127.0.0.1:$port/hw/led" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
done

echo
echo "  bubble-authd  :8765   tail -f $LOGDIR/authd.log"
echo "  bubble-vpnd   :8766   tail -f $LOGDIR/vpnd.log"
echo "  bubble-netd   :8767   tail -f $LOGDIR/netd.log"
echo "  bubble-hwd    :8768   tail -f $LOGDIR/hwd.log"
echo "  pnpm dev      :5173   (foreground)"
echo
echo "Ctrl-C to stop everything."
echo

cd "$ROOT/frontend"
exec pnpm dev
