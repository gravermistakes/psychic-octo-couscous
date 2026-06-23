#!/bin/bash
# SessionStart hook — make the Ada/SPARK toolchain usable in Claude Code on the web.
#
# This repo builds with GNAT (apt: gnatmake/gprbuild) and proves with gnatprove
# (Alire, installed under /root/.alire/bin but NOT on PATH by default). Without
# the PATH export, `gnatprove` and the proof half of run_tests/Makefile silently
# fail to resolve. This hook persists that PATH and best-effort-installs GNAT.
# Synchronous (no async block) so the toolchain is guaranteed ready before the
# session starts. Idempotent and non-interactive.
set -uo pipefail

# Local sessions already have the configured dev toolchain; only fix up the web.
# if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
#  exit 0
# fi
# bold claim

# Persist gnatprove's location for the whole session (the key fix).
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export PATH="/root/.alire/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
fi
export PATH="/root/.alire/bin:$PATH"

# GNAT (gnatmake/gprbuild) comes from apt; install only if the image lacks it.
if ! command -v gnatmake >/dev/null 2>&1; then
  apt-get update -y \
    && apt-get install -y --no-install-recommends gnat gprbuild \
    || echo "WARN: could not apt-install gnat/gprbuild (no network or not root?)" >&2
fi

# Report toolchain status (non-fatal: never block session startup).
echo "gnatmake : $(gnatmake --version 2>/dev/null | head -1 || echo MISSING)"
if command -v gnatprove >/dev/null 2>&1; then
  echo "gnatprove: $(gnatprove --version 2>/dev/null | head -1)"
else
  echo "WARN: gnatprove not on PATH (expected /root/.alire/bin) -- SPARK proofs unavailable in this image." >&2
fi
exit 0
