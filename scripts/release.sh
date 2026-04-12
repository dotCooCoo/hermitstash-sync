#!/usr/bin/env bash
# release.sh — Automated release for HermitStash Sync
#
# Usage:
#   bash scripts/release.sh
#
# What it does:
#   1. Reads version from lib/constants.js
#   2. Builds the SEA binary for the current platform
#   3. Generates SHA-256 and SHA3-512 checksums
#   4. Signs the binary and checksums with GPG (if key available)
#   5. Creates a git tag
#   6. Pushes to GitHub
#   7. Creates a GitHub Release with all artifacts and release notes
#
# Prerequisites:
#   - gh CLI authenticated (gh auth login)
#   - gpg key (optional, for signing — run: gpg --full-generate-key)
#   - Node.js 22+ with esbuild and postject available via npx

set -euo pipefail
cd "$(dirname "$0")/.."

# ---- Read version ----
VERSION=$(node -e "console.log(require('./lib/constants').VERSION)")
TAG="v${VERSION}"
REPO="dotCooCoo/hermitstash-sync"

echo ""
echo "============================================"
echo "  HermitStash Sync — Release ${TAG}"
echo "============================================"
echo ""

# ---- Check for uncommitted changes ----
if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: Working directory has uncommitted changes."
  echo "Commit or stash them before releasing."
  exit 1
fi

# ---- Check tag doesn't already exist ----
if git rev-parse "${TAG}" >/dev/null 2>&1; then
  echo "ERROR: Tag ${TAG} already exists."
  echo "Bump the version in lib/constants.js and package.json first."
  exit 1
fi

# ---- Build SEA ----
echo "[1/7] Building SEA binary..."
node build/build-sea.js
echo ""

# Find the built binary
PLATFORM=$(node -e "var p=process.platform;console.log(p==='win32'?'win':p==='darwin'?'macos':'linux')")
ARCH=$(node -e "console.log(process.arch)")
EXT=$(node -e "console.log(process.platform==='win32'?'.exe':'')")
EXE_NAME="hermitstash-sync-${TAG}-${PLATFORM}-${ARCH}${EXT}"
EXE_PATH="build/${EXE_NAME}"

if [ ! -f "${EXE_PATH}" ]; then
  echo "ERROR: Expected binary not found: ${EXE_PATH}"
  exit 1
fi

# ---- Verify binary runs ----
echo "[2/7] Verifying binary..."
"${EXE_PATH}" version
echo ""

# ---- GPG signing (optional) ----
echo "[3/7] GPG signing..."
# Use Gpg4win on Windows if available, otherwise fall back to PATH gpg
if [ -x "/c/Program Files/GnuPG/bin/gpg.exe" ]; then
  GPG="/c/Program Files/GnuPG/bin/gpg.exe"
else
  GPG="gpg"
fi

GPG_KEY_ID=$("${GPG}" --list-secret-keys --keyid-format long 2>/dev/null | grep -E "^sec" | head -1 | awk '{print $2}' | cut -d'/' -f2 || true)

if [ -n "${GPG_KEY_ID}" ]; then
  echo "  Signing with GPG key: ${GPG_KEY_ID}"
  "${GPG}" --default-key "${GPG_KEY_ID}" --armor --detach-sign "${EXE_PATH}"
  "${GPG}" --default-key "${GPG_KEY_ID}" --armor --detach-sign "${EXE_PATH}.sha256"
  "${GPG}" --default-key "${GPG_KEY_ID}" --armor --detach-sign "${EXE_PATH}.sha3-512"
  echo "  Signatures created:"
  echo "    ${EXE_NAME}.asc"
  echo "    ${EXE_NAME}.sha256.asc"
  echo "    ${EXE_NAME}.sha3-512.asc"
else
  echo "  No GPG key found — skipping signatures."
  echo "  To set up: gpg --full-generate-key"
fi
echo ""

# ---- Git tag ----
echo "[4/7] Creating git tag ${TAG}..."
git tag "${TAG}"
echo ""

# ---- Push ----
echo "[5/7] Pushing to GitHub..."
git push
git push origin "${TAG}"
echo ""

# ---- Build release notes ----
echo "[6/7] Generating release notes..."

# Get commits since last tag
PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")
if [ -n "${PREV_TAG}" ]; then
  CHANGES=$(git log "${PREV_TAG}..HEAD" --oneline --no-decorate)
else
  CHANGES=$(git log --oneline --no-decorate -20)
fi

SHA256=$(cat "build/${EXE_NAME}.sha256" | awk '{print $1}')
SHA3=$(cat "build/${EXE_NAME}.sha3-512" | awk '{print $1}')

NOTES="## HermitStash Sync ${TAG}

### Downloads

| File | Description |
|------|-------------|
| \`${EXE_NAME}\` | Windows x64 binary (Node.js SEA) |
| \`${EXE_NAME}.sha256\` | SHA-256 checksum |
| \`${EXE_NAME}.sha3-512\` | SHA3-512 checksum |"

if [ -n "${GPG_KEY_ID}" ]; then
  NOTES="${NOTES}
| \`${EXE_NAME}.asc\` | GPG signature (binary) |
| \`${EXE_NAME}.sha256.asc\` | GPG signature (SHA-256) |
| \`${EXE_NAME}.sha3-512.asc\` | GPG signature (SHA3-512) |"
fi

NOTES="${NOTES}

### Verify integrity

\`\`\`bash
# SHA-256
echo \"${SHA256}  ${EXE_NAME}\" | sha256sum -c

# SHA3-512
echo \"${SHA3}  ${EXE_NAME}\" | sha3sum -c
\`\`\`"

if [ -n "${GPG_KEY_ID}" ]; then
  NOTES="${NOTES}

### Verify signature

\`\`\`bash
# Import the public key (first time only)
gpg --keyserver keyserver.ubuntu.com --recv-keys ${GPG_KEY_ID}

# Verify binary
gpg --verify ${EXE_NAME}.asc ${EXE_NAME}
\`\`\`"
fi

NOTES="${NOTES}

### Requirements

- HermitStash server v1.5.0+ with sync features enabled
- No Node.js installation needed (self-contained binary)

### Changes

\`\`\`
${CHANGES}
\`\`\`

### Build info

- Node.js: $(node --version)
- OpenSSL: $(node -e "console.log(process.versions.openssl)")
- Platform: ${PLATFORM} ${ARCH}
"

# ---- Create GitHub release ----
echo "[7/7] Creating GitHub Release..."

ARTIFACTS=("build/${EXE_NAME}" "build/${EXE_NAME}.sha256" "build/${EXE_NAME}.sha3-512")
if [ -f "build/${EXE_NAME}.asc" ]; then
  ARTIFACTS+=("build/${EXE_NAME}.asc" "build/${EXE_NAME}.sha256.asc" "build/${EXE_NAME}.sha3-512.asc")
fi

gh release create "${TAG}" \
  --repo "${REPO}" \
  --title "${TAG} — HermitStash Sync" \
  --notes "${NOTES}" \
  "${ARTIFACTS[@]}"

echo ""
echo "============================================"
echo "  Release ${TAG} published!"
echo "  https://github.com/${REPO}/releases/tag/${TAG}"
echo "============================================"
echo ""

# ---- Cleanup build artifacts ----
echo "Cleaning up build directory..."
rm -f build/hermitstash-sync-*
echo "Done."
