#!/usr/bin/env bash
#
# Self-hosted one-liner for ServerForge, served from your own domain via Caddy.
#   curl -fsSL https://mxm-bbv.dev/cli.sh | bash
#
# It downloads the binary for the host's architecture, verifies its SHA256
# against a checksum served next to it, runs the wizard, and cleans up. No
# `forge` binary is left installed.
#
set -euo pipefail

BASE="https://mxm-bbv.dev"          # <-- your domain

case "$(uname -m)" in
  x86_64|amd64)  A=amd64 ;;
  aarch64|arm64) A=arm64 ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

BIN_URL="$BASE/forge-linux-$A"
SUM_URL="$BASE/forge-linux-$A.sha256"

TMP="$(mktemp)"; SUM="$(mktemp)"
trap 'rm -f "$TMP" "$SUM"' EXIT

curl -fSL --progress-bar "$BIN_URL" -o "$TMP"

# Verify checksum — fail closed if it doesn't match or isn't published.
if curl -fsSL "$SUM_URL" -o "$SUM" 2>/dev/null; then
  EXPECTED="$(awk '{print $1}' "$SUM" | head -n1)"
  ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Checksum MISMATCH — aborting."
    echo "  expected: $EXPECTED"
    echo "  actual:   $ACTUAL"
    exit 1
  fi
  echo "Checksum verified: $ACTUAL"
else
  if [ "${FORGE_ALLOW_UNVERIFIED:-0}" != "1" ]; then
    echo "No checksum at $SUM_URL — refusing to run unverified binary."
    echo "Set FORGE_ALLOW_UNVERIFIED=1 to override (not recommended)."
    exit 1
  fi
  echo "WARNING: running UNVERIFIED binary."
fi

chmod +x "$TMP"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO=sudo
exec $SUDO "$TMP" < /dev/tty
