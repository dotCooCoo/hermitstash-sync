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
# vendor/ contains bundled (vendored) code only.
# After running, verify with: node bin/hermitstash-sync.js version
# Then commit: git add vendor/ && git commit

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="vendor/MANIFEST.json"
DATE=$(date +%Y-%m-%d)

# Create MANIFEST if it doesn't exist
if [ ! -f "$MANIFEST" ]; then
  echo '{"note":"Vendored dependencies for hermitstash-sync. blamejs is the single vendored upstream.","packages":{}}' > "$MANIFEST"
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

# ---- blamejs: a source tree, not an esbuild bundle ----
#
# The framework is vendored as its published source tree rather than bundled,
# because the boot-time integrity gate hashes individual consumed files. It is
# published as @blamejs/core — the bare name `blamejs` on npm belongs to an
# UNRELATED package and must never be installed.
#
# The refresh takes the published tarball rather than a clone: tar writes the
# bytes as published, so nothing rewrites line endings on the way in, and the
# archive holds only what actually runs. Cloning and copying instead is how
# line endings and stray paths get into the tree.
if [ "$PKG" = "blamejs" ]; then
  NPM_NAME="@blamejs/core"
  if [ "$VER" = "latest" ]; then
    INSTALLED_VER=$(npm view "$NPM_NAME" version 2>/dev/null)
    [ -n "$INSTALLED_VER" ] || { echo "ERROR: could not resolve the latest $NPM_NAME version."; exit 1; }
  else
    INSTALLED_VER="${VER#v}"
  fi
  TAG="v$INSTALLED_VER"
  echo "Resolved $NPM_NAME@$INSTALLED_VER (tag $TAG)"

  # Read the published digest BEFORE downloading, so the comparison is against
  # what the registry advertises rather than against the file just received.
  INTEGRITY=$(npm view "$NPM_NAME@$INSTALLED_VER" dist.integrity 2>/dev/null)
  [ -n "$INTEGRITY" ] || { echo "ERROR: no published integrity for $NPM_NAME@$INSTALLED_VER; refusing to vendor unverifiable bytes."; exit 1; }

  TMPPACK=".vendor-blamejs.tmp"
  _cleanup_pack() { node -e "try{require('fs').rmSync('$TMPPACK',{recursive:true,force:true,maxRetries:10,retryDelay:200})}catch(_e){}" 2>/dev/null || true; }
  trap _cleanup_pack EXIT
  _cleanup_pack
  mkdir -p "$TMPPACK"
  npm pack "$NPM_NAME@$INSTALLED_VER" --pack-destination "$TMPPACK" --silent >/dev/null 2>&1
  TARBALL=$(node -e "
    var fs=require('fs'),p=require('path'),d=process.argv[1];
    var f=fs.readdirSync(d).filter(function(n){return /\.tgz\$/.test(n);});
    if(f.length!==1){process.stderr.write('expected one tarball, found '+f.length+'\n');process.exit(1);}
    process.stdout.write(p.join(d,f[0]));
  " "$TMPPACK")
  [ -n "$TARBALL" ] && [ -f "$TARBALL" ] || { echo "ERROR: npm pack produced no tarball."; exit 1; }

  INTEGRITY="$INTEGRITY" TARBALL="$TARBALL" node -e '
    var fs=require("fs"), crypto=require("crypto");
    var want=process.env.INTEGRITY.trim();
    var m=/^sha(256|384|512)-(.+)$/.exec(want);
    if(!m){console.error("unrecognized integrity format: "+want);process.exit(1);}
    var got="sha"+m[1]+"-"+crypto.createHash("sha"+m[1]).update(fs.readFileSync(process.env.TARBALL)).digest("base64");
    if(got!==want){console.error("INTEGRITY MISMATCH\n  published: "+want+"\n  received:  "+got);process.exit(1);}
    console.log("Integrity verified: "+want.slice(0,24)+"…");
  '

  DEST="vendor/blamejs"
  # Empty the directory's CONTENTS rather than removing it: on this platform a
  # file-syncing agent can hold the directory handle open, so the final rmdir
  # fails even after every child is gone and leaves the tree half-removed.
  #
  # Leaving the TOP directory alone is not enough on its own — removing a child
  # directory recursively still ends in an rmdir of that child, so a lock one
  # level down (lib/) kills the run exactly the same way. _vendor-wipe.js falls
  # back to emptying a held directory instead of removing it, and fails loudly
  # if a FILE survives: extracting over leftover files would mix two releases,
  # which is worse than stopping.
  node scripts/_vendor-wipe.js "$DEST"
  tar -xzf "$TARBALL" -C "$DEST" --strip-components=1
  _cleanup_pack

  [ -f "$DEST/package.json" ] || { echo "ERROR: extract failed — $DEST/package.json missing."; exit 1; }
  node -e "var b=require('./$DEST');console.log('blamejs surface OK:',Object.keys(b).length,'primitives');"

  # Recompute the consumed-file hashes the boot gate checks. Without this the
  # tree and the manifest disagree and the client refuses to start.
  node scripts/vendor-hash.js

  INTEGRITY="$INTEGRITY" TAG="$TAG" INSTALLED_VER="$INSTALLED_VER" DATE="$DATE" MANIFEST="$MANIFEST" node -e '
    var fs=require("fs");
    var m=JSON.parse(fs.readFileSync(process.env.MANIFEST,"utf8"));
    var e=m.packages.blamejs=m.packages.blamejs||{};
    e.version=process.env.INSTALLED_VER;
    e.tag=process.env.TAG;
    e.bundledAt=process.env.DATE;
    // The CPE and purl carry the version too, and only these two were being
    // rewritten — so every refresh left the identifiers naming an older
    // release. Inventory and vulnerability tooling reads those, not the
    // version field, and would attribute the refreshed bytes to whatever
    // release the identifiers were last correct for. Rewrite the version
    // component in place rather than rebuilding the string, so the rest of the
    // identifier (and anything an operator has customised) survives.
    if (typeof e.cpe === "string") {
      e.cpe = e.cpe.replace(/^(cpe:2\.3:a:[^:]+:[^:]+:)[^:]+/, "$1" + process.env.INSTALLED_VER);
    }
    if (typeof e.purl === "string") {
      e.purl = e.purl.replace(/@.*$/, "@" + process.env.TAG);
    }
    // The registry-published digest of the exact tarball this tree came from,
    // so the vendored bytes stay traceable to a published artifact rather than
    // to a version number someone typed.
    e.integrity=process.env.INTEGRITY.trim();
    fs.writeFileSync(process.env.MANIFEST, JSON.stringify(m,null,2)+"\n");
    console.log("Updated MANIFEST.json: blamejs → "+process.env.INSTALLED_VER);
  '

  echo ""
  echo "=== Done: blamejs v$INSTALLED_VER vendored ($(find "$DEST" -type f | wc -l) files) ==="
  echo "Next: node tests/test-vendor-integrity.js && node bin/hermitstash-sync.js version"
  exit 0
fi

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
