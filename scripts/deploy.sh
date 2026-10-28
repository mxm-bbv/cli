#!/usr/bin/env bash
#
# Build forge for a server's architecture, copy it there over SSH, verify it
# arrived intact, install it as /usr/local/bin/forge and launch it with a real
# terminal. Usually called via `make deploy`.
#
#   scripts/deploy.sh root@203.0.113.10                 # run the wizard
#   scripts/deploy.sh ubuntu@srv --dry-run              # any forge args follow
#   SSH_PORT=2222 SSH_OPTS="-i ~/.ssh/id_vps" scripts/deploy.sh deploy@srv audit
#
# One SSH connection is shared by every step (ControlMaster), so a password or
# key passphrase is asked for once.
set -euo pipefail

red()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
info() { printf '\033[36m%s\033[0m\n' "$*"; }

HOST="${1:-}"
if [ -z "$HOST" ]; then
  red "usage: scripts/deploy.sh user@server [forge args…]"; exit 2
fi
shift

cd "$(dirname "$0")/.."

SSH_PORT="${SSH_PORT:-22}"
read -r -a EXTRA <<< "${SSH_OPTS:-}"
CTL="${TMPDIR:-/tmp}/forge-deploy-%C"
SSH_BASE=(-o ControlMaster=auto -o "ControlPath=$CTL" -o ControlPersist=120 "${EXTRA[@]}")

ssh_() { ssh -p "$SSH_PORT" "${SSH_BASE[@]}" "$@"; }
scp_() { scp -q -P "$SSH_PORT" "${SSH_BASE[@]}" "$@"; }
cleanup() { ssh -p "$SSH_PORT" "${SSH_BASE[@]}" -O exit "$HOST" >/dev/null 2>&1 || true; }
trap cleanup EXIT

info "Connecting to $HOST…"
if ! REMOTE_ARCH="$(ssh_ "$HOST" uname -m)"; then
  red "cannot connect to $HOST (port $SSH_PORT)."
  red "Many keys in your ssh-agent? Pick one: SSH_OPTS=\"-i ~/.ssh/key -o IdentitiesOnly=yes\""
  exit 1
fi
case "$REMOTE_ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) red "unsupported server architecture: $REMOTE_ARCH"; exit 1 ;;
esac

BIN="dist/forge-linux-$ARCH"
info "Building $BIN…"
make --no-print-directory "$BIN"
SUM="$(sha256sum "$BIN" | awk '{print $1}')"

REMOTE_TMP="$(ssh_ "$HOST" mktemp /tmp/forge.XXXXXX)"
info "Copying to $HOST…"
scp_ "$BIN" "$HOST:$REMOTE_TMP"

# Quote forge's arguments for the remote shell.
REMOTE_ARGS=""
for a in "$@"; do
  REMOTE_ARGS+=" '${a//\'/\'\\\'\'}'"
done

# Verify, install (sudo only when not root) and hand over the terminal. The
# sha256 check catches a truncated or tampered copy before it runs as root.
info "Installing and starting forge on $HOST…"
exec ssh -t -p "$SSH_PORT" "${SSH_BASE[@]}" "$HOST" "set -e
  S=''; [ \"\$(id -u)\" -eq 0 ] || S=sudo
  echo '$SUM  $REMOTE_TMP' | sha256sum -c --quiet - || { echo 'checksum mismatch — aborting' >&2; rm -f '$REMOTE_TMP'; exit 1; }
  \$S install -m 0755 '$REMOTE_TMP' /usr/local/bin/forge
  rm -f '$REMOTE_TMP'
  exec \$S /usr/local/bin/forge$REMOTE_ARGS"
