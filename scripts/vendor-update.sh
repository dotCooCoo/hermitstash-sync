#!/usr/bin/env bash
# vendor-update.sh — Vendor a dependency for hermitstash-sync
#
# Usage:
#   ./scripts/vendor-update.sh <package-name> [version]
#   ./scripts/vendor-update.sh --check                 # check for updates
#   ./scripts/vendor-update.sh --diff <package-name>   # show changelog
#
# Examples:
#   ./scripts/vendor-update.sh ws                      # latest
#   ./scripts/vendor-update.sh ws 8.18.0               # specific version
#
# What it does:
#   1. Installs the package temporarily via npm
#   2. Bundles with esbuild into a single CJS file
#   3. Updates vendor/MANIFEST.json with version and date
#   4. Removes the npm package
#   5. Shows git diff of changed vendor files
#
# Zero npm runtime dependencies — vendor/ contains bundled code only.
# After running, verify with: node bin/hermitstash-sync.js version
# Then commit: git add vendor/ && git commit

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="vendor/MANIFEST.json"
DATE=$(date +%Y-%m-%d)

# Create MANIFEST if it doesn't exist
if [ ! -f "$MANIFEST" ]; then
  echo '{"note":"Vendored dependencies for hermitstash-sync. Zero npm runtime packages.","packages":{}}' > "$MANIFEST"
fi

# ---- Helper: get vendored version ----
get_vendored_ver() {
  node -e "try{var m=require('./$MANIFEST');var p=m.packages['$1'];console.log(p?p.version:'?')}catch(_){console.log('?')}"
}

# ---- Helper: show changelog ----
show_pkg_diff() {
  local pkg="$1"
  local vendored latest
  vendored=$(get_vendored_ver "$pkg")
  latest=$(npm view "$pkg" version 2>/dev/null || echo "?")

  if [ "$vendored" = "$latest" ]; then
    echo "$pkg: v$vendored — already up to date"
    return
  fi

  echo ""
  echo "━━━ $pkg: v$vendored → v$latest ━━━"
  echo ""
  echo "Published versions since v$vendored:"
  npm view "$pkg" versions --json 2>/dev/null | node -e "
    var versions = JSON.parse(require('fs').readFileSync(0,'utf8'));
    if (!Array.isArray(versions)) versions = [versions];
    var found = false;
    versions.forEach(function(v) {
      if (v === '$vendored') found = true;
      else if (found) console.log('  ' + v);
    });
  " 2>/dev/null || echo "  (could not fetch version list)"
  echo ""
}

# ---- Check mode ----
if [ "${1:-}" = "--check" ]; then
  echo "Checking vendored package versions..."
  echo ""
  # Read package names from MANIFEST
  packages=$(node -e "var m=require('./$MANIFEST');Object.keys(m.packages).forEach(function(p){console.log(p)})" 2>/dev/null)
  if [ -z "$packages" ]; then
    echo "No vendored packages. vendor/ is empty."
    exit 0
  fi
  printf "%-25s %-12s %-12s %-14s %s\n" "Package" "Vendored" "Latest" "Bundled" "Status"
  printf "%-25s %-12s %-12s %-14s %s\n" "-------" "--------" "------" "-------" "------"
  while IFS= read -r pkg; do
    vendored=$(get_vendored_ver "$pkg")
    bundled=$(node -e "var m=require('./$MANIFEST');var p=m.packages['$pkg'];console.log(p&&p.bundledAt?p.bundledAt:'?')")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" = "$latest" ]; then
      status="up to date"
    else
      status="UPDATE AVAILABLE"
    fi
    printf "%-25s %-12s %-12s %-14s %s\n" "$pkg" "$vendored" "$latest" "$bundled" "$status"
  done <<< "$packages"
  exit 0
fi

# ---- Diff mode ----
if [ "${1:-}" = "--diff" ]; then
  PKG="${2:?Usage: vendor-update.sh --diff <package-name>}"
  show_pkg_diff "$PKG"
  exit 0
fi

# ---- Update mode ----
PKG="${1:?Usage: vendor-update.sh <package-name> [version]}"
VER="${2:-latest}"

echo "=== Vendoring $PKG@$VER ==="

# Install temporarily
npm install "${PKG}@${VER}" --no-save --ignore-scripts 2>/dev/null
INSTALLED_VER=$(node -e "console.log(require('./node_modules/${PKG}/package.json').version)")
echo "Installed: $PKG@$INSTALLED_VER"

# Bundle based on package name
OUTFILE="vendor/${PKG//[@\/]/-}.cjs"

case "$PKG" in
  # Add specific bundling instructions per package here.
  # Example for 'ws' (if we ever need it):
  # "ws")
  #   echo "module.exports = require('ws');" > _entry.cjs
  #   npx esbuild _entry.cjs --bundle --format=cjs --platform=node --minify --outfile="$OUTFILE"
  #   rm _entry.cjs
  #   ;;

  *)
    # Generic bundling: CJS, minified, node platform
    echo "module.exports = require(\"$PKG\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --minify --outfile="$OUTFILE" --external:crypto --external:node:crypto --external:node:fs --external:node:path --external:node:os --external:node:child_process --external:node:events --external:node:net --external:node:tls --external:node:https --external:node:http --external:node:url --external:node:stream --external:node:sqlite
    rm _entry.cjs
    sed -i "1s|^|// $PKG v${INSTALLED_VER} — vendored for hermitstash-sync. License: see package.\n|" "$OUTFILE"
    ;;
esac

# Update MANIFEST.json
node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
m.packages['$PKG'] = {
  version: '$INSTALLED_VER',
  bundledAt: '$DATE',
  file: '$OUTFILE'
};
fs.writeFileSync('$MANIFEST', JSON.stringify(m, null, 2) + '\n');
console.log('Updated MANIFEST.json: $PKG → $INSTALLED_VER');
"

# Remove npm package
npm uninstall "$PKG" --no-save 2>/dev/null || true
rm -rf node_modules package-lock.json 2>/dev/null || true

# Verify bundle loads
echo ""
echo "=== Verifying bundle ==="
node -e "try{require('./$OUTFILE');console.log('  $OUTFILE: OK')}catch(e){console.log('  $OUTFILE: FAIL — '+e.message);process.exit(1)}" \
  || { echo "Bundle verification failed!"; exit 1; }

# Show size
echo ""
echo "=== Bundle size ==="
ls -lh "$OUTFILE" | awk '{print "  " $NF ": " $5}'

echo ""
echo "=== Git diff ==="
git diff --stat vendor/ 2>/dev/null || true

echo ""
echo "=== Done: $PKG v$INSTALLED_VER vendored ==="
echo ""
echo "Next steps:"
echo "  1. Review:  git diff vendor/"
echo "  2. Verify:  node bin/hermitstash-sync.js version"
echo "  3. Commit:  git add vendor/ && git commit -m 'Vendor $PKG@$INSTALLED_VER'"
