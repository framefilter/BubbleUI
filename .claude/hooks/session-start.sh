#!/bin/bash
# Claude Code on the web — SessionStart hook.
#
# Installs frontend dependencies, fetches the Nerd Font binaries, and
# runs the Go test suite so cloud sessions catch backend regressions
# at resume time.
#
# Idempotent: safe to re-run. Skipped on local sessions to avoid
# touching a developer's working tree.

set -euo pipefail

# Local sessions: do nothing. Developers manage their own deps.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR/frontend"

echo "==> pnpm install"
pnpm install --prefer-offline

# The font fetch hits GitHub releases (~10 MB). It's optional for type
# checking but required for `pnpm dev` / `pnpm build` to render correctly.
# Skip silently if the network isn't reachable rather than failing the hook.
if [ ! -f public/fonts/CaskaydiaCoveMono-Regular.ttf ]; then
  echo "==> pnpm fonts"
  pnpm fonts || echo "!! font fetch failed; pnpm dev will fall back to system mono"
else
  echo "==> fonts already present, skipping"
fi

# Run the Go test suite when Go is available. Failures are surfaced but
# non-fatal — the hook's job is environment setup, not gating, and
# in-progress work might intentionally have failing tests.
if command -v go >/dev/null 2>&1; then
  echo "==> go test backend"
  ( cd "$CLAUDE_PROJECT_DIR/backend" && go test -count=1 ./... ) \
    || echo "!! backend tests failed; see output above"
else
  echo "==> go toolchain not found; skipping backend tests"
fi

echo "==> session-start hook done"
