#!/usr/bin/env bash
#
# ServerForge installer — fetch the prebuilt binary and run the wizard.
#
#   curl -fsSL https://raw.githubusercontent.com/mxm-bbv/cli/main/install.sh | bash
#
# Env vars:
#   INSTALL_DIR   where to put the binary (default: /usr/local/bin)
#   FORGE_NO_RUN  set to 1 to install only, without launching the wizard
#   FORGE_VERSION release tag to install (default: latest)
#
set -euo pipefail

REPO="mxm-bbv/cli"
BIN="forge"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${FORGE_VERSION:-latest}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '\033[36m%s\033[0m\n' "$*"; }

# --- detect platform -------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
  red "ServerForge supports Linux only (detected: $OS)."; exit 1
fi
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) red "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

ASSET="${BIN}-linux-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

# --- download --------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { red "missing required tool: $1"; exit 1; }; }
need curl

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
info "Downloading ${ASSET} (${VERSION})…"
if ! curl -fSL --progress-bar "$URL" -o "$TMP"; then
  red "Download failed. Has a release been published yet?"
  red "  $URL"
  exit 1
fi
chmod +x "$TMP"

# --- install ---------------------------------------------------------------
SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    red "Need write access to $INSTALL_DIR (run as root or install sudo)."; exit 1
  fi
fi
$SUDO install -m 0755 "$TMP" "$INSTALL_DIR/$BIN"
ok "Installed $BIN -> $INSTALL_DIR/$BIN"

# --- run -------------------------------------------------------------------
# The wizard needs root and a terminal. forge opens /dev/tty itself, so this
# works even when this script is piped from curl.
if [ "${FORGE_NO_RUN:-0}" = "1" ]; then
  info "Run it any time with:  sudo $BIN"
  exit 0
fi

RUN_SUDO=""
if [ "$(id -u)" -ne 0 ]; then RUN_SUDO="sudo"; fi
info "Launching the wizard…"
exec $RUN_SUDO "$INSTALL_DIR/$BIN"
