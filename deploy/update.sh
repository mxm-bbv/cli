#!/usr/bin/env bash
#
# Update the served forge binary on the server from CI-built artifacts.
# No compilation: it pulls the pre-built binary from the `dist` branch (produced
# by .github/workflows/build.yml) and drops it where Caddy serves it.
#
#   bash /srv/projects/cli/deploy/update.sh
#
set -euo pipefail

REPO_DIR="${REPO_DIR:-/srv/projects/cli}"
DIST_DIR="${DIST_DIR:-/srv/projects/cli-dist}"

cd "$REPO_DIR"
echo "Fetching latest CI build…"
git fetch -q origin dist

mkdir -p "$DIST_DIR"
for a in amd64 arm64; do
  if git cat-file -e "origin/dist:forge-linux-$a" 2>/dev/null; then
    git show "origin/dist:forge-linux-$a"        > "$DIST_DIR/forge-linux-$a"
    git show "origin/dist:forge-linux-$a.sha256" > "$DIST_DIR/forge-linux-$a.sha256"
    chmod 644 "$DIST_DIR/forge-linux-$a" "$DIST_DIR/forge-linux-$a.sha256"
    echo "  updated forge-linux-$a ($(cat "$DIST_DIR/forge-linux-$a.sha256"))"
  fi
done

echo "Done. Served from $DIST_DIR"
