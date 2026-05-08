#!/bin/bash
# Claude Code on the web — SessionStart hook.
#
# Installs frontend dependencies and fetches the Nerd Font binaries so
# `pnpm check`, `pnpm build`, and `pnpm dev` work out of the box in
# remote sessions.
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

echo "==> session-start hook done"
