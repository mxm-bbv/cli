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

# forge's minisign public key. If `minisign` is installed, the release's
# signature is verified against it; otherwise the SHA256 check below is the
# floor (and `forge update` later verifies the signature in-process).
FORGE_PUBKEY="RWSk3LOux6EkxZOpVER2fnvn2WKOHPBPG128iEhEy3JGztPOte98a+3C"

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

# forge provisions apt + systemd hosts: Ubuntu, Debian and their derivatives
# (Mint, Pop!_OS, Raspberry Pi OS, …). Fail here rather than after download.
# Read os-release in a subshell: it defines VERSION, NAME, ID… which would
# clobber this script's own variables.
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  OS_IDS="$(. /etc/os-release && echo " ${ID:-} ${ID_LIKE:-} ")"
  # shellcheck disable=SC1091
  OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-${ID:-unknown}}")"
  case "$OS_IDS" in
    *" debian "*|*" ubuntu "*) ;;
    *) red "Unsupported distribution: $OS_NAME — forge supports Ubuntu, Debian and derivatives."; exit 1 ;;
  esac
fi

ASSET="${BIN}-linux-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

# --- download --------------------------------------------------------------
# curl is preferred; minimal Debian installs often ship only wget.
if command -v curl >/dev/null 2>&1; then
  fetch()       { curl -fSL --progress-bar "$1" -o "$2"; }
  fetch_quiet() { curl -fsSL "$1" -o "$2" 2>/dev/null; }
elif command -v wget >/dev/null 2>&1; then
  fetch()       { wget -q --show-progress -O "$2" "$1"; }
  fetch_quiet() { wget -q -O "$2" "$1"; }
else
  red "Need curl or wget to download forge (apt-get install -y curl)."; exit 1
fi
command -v sha256sum >/dev/null 2>&1 || { red "missing required tool: sha256sum"; exit 1; }

TMP="$(mktemp)"
SUMS="$(mktemp)"
trap 'rm -f "$TMP" "$SUMS"' EXIT
info "Downloading ${ASSET} (${VERSION})…"
if ! fetch "$URL" "$TMP"; then
  red "Download failed. Has a release been published yet?"
  red "  $URL"
  exit 1
fi

# --- verify checksum (fail closed) -----------------------------------------
# checksums.txt is published alongside the binaries by the release workflow.
if [ "$VERSION" = "latest" ]; then
  SUMS_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"
else
  SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
fi
if fetch_quiet "$SUMS_URL" "$SUMS"; then
  # Opportunistic signature check: if minisign is present, verify checksums.txt
  # before trusting it. Fail closed only when a signature exists but is invalid.
  if command -v minisign >/dev/null 2>&1; then
    SIG="$(mktemp)"; trap 'rm -f "$TMP" "$SUMS" "$SIG"' EXIT
    if fetch_quiet "${SUMS_URL}.minisig" "$SIG"; then
      if minisign -Vm "$SUMS" -x "$SIG" -P "$FORGE_PUBKEY" >/dev/null 2>&1; then
        ok "Release signature verified (minisign)"
      else
        red "minisign signature verification FAILED for checksums.txt — aborting."; exit 1
      fi
    fi
  fi
  EXPECTED="$(awk -v f="$ASSET" '$2==f || $2=="*"f {print $1}' "$SUMS" | head -n1)"
  if [ -z "$EXPECTED" ]; then
    red "No checksum for ${ASSET} in checksums.txt — refusing to run."; exit 1
  fi
  ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    red "Checksum MISMATCH for ${ASSET} — aborting."
    red "  expected: $EXPECTED"
    red "  actual:   $ACTUAL"
    exit 1
  fi
  ok "Checksum verified (sha256: ${ACTUAL})"
else
  # No checksums file: warn loudly. Set FORGE_ALLOW_UNVERIFIED=1 to proceed.
  if [ "${FORGE_ALLOW_UNVERIFIED:-0}" != "1" ]; then
    red "checksums.txt not found — refusing to run unverified binary."
    red "Set FORGE_ALLOW_UNVERIFIED=1 to override (not recommended)."
    exit 1
  fi
  red "WARNING: proceeding with an UNVERIFIED binary (FORGE_ALLOW_UNVERIFIED=1)."
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
# The wizard needs root and a terminal. When piped from curl, stdin is the
# script itself — hand the wizard the real terminal instead.
if [ "${FORGE_NO_RUN:-0}" = "1" ]; then
  info "Run it any time with:  sudo $BIN"
  exit 0
fi

RUN_SUDO=""
if [ "$(id -u)" -ne 0 ]; then RUN_SUDO="sudo"; fi
info "Launching the wizard…"
if [ -t 0 ]; then
  exec $RUN_SUDO "$INSTALL_DIR/$BIN"
elif [ -r /dev/tty ]; then
  exec $RUN_SUDO "$INSTALL_DIR/$BIN" </dev/tty
else
  info "No terminal available — run it yourself with:  sudo $BIN"
fi
