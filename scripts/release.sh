#!/usr/bin/env bash
# release.sh — Automated release for HermitStash Sync
#
# Usage:
#   bash scripts/release.sh
#
# What it does:
#   1. Reads version from lib/constants.js
#   2. Builds the SEA binary for the current platform
#   3. Verifies the binary runs
#   4. Windows Defender full scan (signature update + custom scan)
#   5. VirusTotal upload + scan (if API key configured)
#   6. GPG signs the binary and checksum files
#   7. Creates a git tag and pushes
#   8. Creates a GitHub Release with all artifacts and release notes
#
# Prerequisites:
#   - gh CLI authenticated (gh auth login)
#   - gpg key (optional — run: gpg --full-generate-key)
#   - Node.js 22+ with esbuild and postject via npx
#   - VIRUSTOTAL_API_KEY env var (optional — free key from virustotal.com)
#
# Environment:
#   VIRUSTOTAL_API_KEY  — VirusTotal API key for automated scanning
#   SKIP_VT             — set to 1 to skip VirusTotal upload

set -euo pipefail
cd "$(dirname "$0")/.."

# Load local release config (API keys, etc.) — not committed to repo.
# Parsed rather than sourced so ShellCheck can analyze statically and so
# arbitrary shell inside the file can't execute.
RELEASE_ENV="${HOME}/.hermitstash-sync/release.env"
if [ -f "${RELEASE_ENV}" ]; then
  while IFS='=' read -r _k _v; do
    case "${_k}" in
      ''|\#*) continue ;;
    esac
    # Strip optional surrounding single or double quotes from the value.
    case "${_v}" in
      \"*\") _v="${_v#\"}"; _v="${_v%\"}" ;;
      \'*\') _v="${_v#\'}"; _v="${_v%\'}" ;;
    esac
    export "${_k}=${_v}"
  done < "${RELEASE_ENV}"
  unset _k _v
fi

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

# ---- Step 1: Build SEA ----
echo "[1/8] Building SEA binary..."
node build/build-sea.js
echo ""

# Find the built binary
PLATFORM=$(node -e "var p=process.platform;console.log(p==='win32'?'win':p==='darwin'?'macos':'linux')")
ARCH=$(node -e "console.log(process.arch)")
EXT=$(node -e "console.log(process.platform==='win32'?'.exe':'')")
EXE_NAME="hermitstash-sync-${TAG}-${PLATFORM}-${ARCH}${EXT}"
EXE_PATH="build/${EXE_NAME}"
# Absolute path for Defender (needs Windows-style path)
EXE_ABS=$(cd build && pwd -W 2>/dev/null || pwd)/${EXE_NAME}

if [ ! -f "${EXE_PATH}" ]; then
  echo "ERROR: Expected binary not found: ${EXE_PATH}"
  exit 1
fi

# ---- Step 2: Verify binary runs ----
echo "[2/8] Verifying binary..."
"${EXE_PATH}" version
echo ""

# ---- Step 3: Security scan — Windows Defender ----
echo "[3/8] Security scan — Windows Defender..."
DEFENDER="/c/Program Files/Windows Defender/MpCmdRun.exe"
DEFENDER_RESULT="clean"

if [ -x "${DEFENDER}" ]; then
  echo "  Updating virus definitions..."
  "${DEFENDER}" -SignatureUpdate 2>&1 | grep -E "Version|finished" || true

  echo "  Running full custom scan..."
  # Convert to Windows path for Defender
  WIN_PATH=$(cygpath -w "${EXE_PATH}" 2>/dev/null || echo "${EXE_ABS}")
  SCAN_OUTPUT=$("${DEFENDER}" -Scan -ScanType 3 -File "${WIN_PATH}" -DisableRemediation 2>&1) || true
  echo "  ${SCAN_OUTPUT}" | tail -2

  if echo "${SCAN_OUTPUT}" | grep -qi "found no threats"; then
    DEFENDER_RESULT="clean"
    echo "  Result: CLEAN"
  elif echo "${SCAN_OUTPUT}" | grep -qi "threat"; then
    DEFENDER_RESULT="THREAT DETECTED"
    echo "  WARNING: Windows Defender found a threat!"
    echo "  Aborting release."
    exit 1
  else
    DEFENDER_RESULT="scan completed (check output)"
    echo "  Result: ${DEFENDER_RESULT}"
  fi
else
  DEFENDER_RESULT="not available"
  echo "  Windows Defender not found — skipping."
fi
echo ""

# ---- Step 4: Security scan — VirusTotal ----
echo "[4/8] Security scan — VirusTotal..."
VT_URL=""
VT_API_KEY="${VIRUSTOTAL_API_KEY:-}"

if [ -n "${VT_API_KEY}" ] && [ "${SKIP_VT:-}" != "1" ]; then
  FILE_SIZE=$(stat -c%s "${EXE_PATH}" 2>/dev/null || stat -f%z "${EXE_PATH}" 2>/dev/null || echo "0")

  if [ "${FILE_SIZE}" -gt 33554432 ]; then
    # Files >32MB need a special upload URL
    echo "  Requesting large file upload URL (${FILE_SIZE} bytes)..."
    UPLOAD_URL=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/files/upload_url" \
      --header "x-apikey: ${VT_API_KEY}" | node -e "var d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).data)}catch{console.log('')}})")

    if [ -z "${UPLOAD_URL}" ]; then
      echo "  Failed to get upload URL. Continuing without VirusTotal."
      VT_API_KEY=""
    else
      echo "  Uploading to VirusTotal (large file — may take several minutes)..."
      VT_RESPONSE=$(curl -s --request POST \
        --url "${UPLOAD_URL}" \
        --header "x-apikey: ${VT_API_KEY}" \
        --form "file=@${EXE_PATH}")
    fi
  else
    echo "  Uploading to VirusTotal..."
    VT_RESPONSE=$(curl -s --request POST \
      --url "https://www.virustotal.com/api/v3/files" \
      --header "x-apikey: ${VT_API_KEY}" \
      --form "file=@${EXE_PATH}")
  fi

  VT_ANALYSIS_ID=""
  if [ -n "${VT_API_KEY}" ]; then
  VT_ANALYSIS_ID=$(echo "${VT_RESPONSE}" | node -e "var d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).data.id)}catch{console.log('')}})")
  fi

  if [ -n "${VT_ANALYSIS_ID}" ]; then
    echo "  Upload complete. Analysis ID: ${VT_ANALYSIS_ID}"
    echo "  Waiting for scan to complete..."

    # Poll for results (max 5 minutes)
    for i in $(seq 1 30); do
      sleep 10
      VT_STATUS=$(curl -s \
        --url "https://www.virustotal.com/api/v3/analyses/${VT_ANALYSIS_ID}" \
        --header "x-apikey: ${VT_API_KEY}" | node -e "var d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{var r=JSON.parse(d);console.log(r.data.attributes.status+'|'+JSON.stringify(r.data.attributes.stats||{}))}catch{console.log('pending|{}')}})")

      STATUS=$(echo "${VT_STATUS}" | cut -d'|' -f1)
      STATS=$(echo "${VT_STATUS}" | cut -d'|' -f2)

      if [ "${STATUS}" = "completed" ]; then
        # Extract the file hash for the permalink
        VT_SHA256=$(cat "build/${EXE_NAME}.sha256" | awk '{print $1}')
        VT_URL="https://www.virustotal.com/gui/file/${VT_SHA256}"

        MALICIOUS=$(echo "${STATS}" | node -e "var d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).malicious||0)}catch{console.log('?')}})")
        UNDETECTED=$(echo "${STATS}" | node -e "var d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).undetected||0)}catch{console.log('?')}})")

        echo "  Scan complete: ${MALICIOUS} malicious, ${UNDETECTED} clean"
        echo "  Report: ${VT_URL}"

        if [ "${MALICIOUS}" != "0" ] && [ "${MALICIOUS}" != "?" ]; then
          echo ""
          echo "  WARNING: ${MALICIOUS} engine(s) flagged the binary!"
          echo "  Review the report before proceeding: ${VT_URL}"
          read -rp "  Continue with release? [y/N] " CONTINUE
          if [ "${CONTINUE}" != "y" ] && [ "${CONTINUE}" != "Y" ]; then
            echo "  Aborting."
            exit 1
          fi
        fi
        break
      fi
      printf "  Waiting... (%d/30)\r" "$i"
    done

    if [ "${STATUS}" != "completed" ]; then
      echo "  VirusTotal scan timed out. Check manually: ${VT_URL:-pending}"
    fi
  else
    echo "  Upload failed. Response: ${VT_RESPONSE}"
    echo "  Continuing without VirusTotal scan."
  fi
else
  if [ -z "${VT_API_KEY}" ]; then
    echo "  No VIRUSTOTAL_API_KEY set — skipping."
    echo "  Get a free key: https://www.virustotal.com/gui/my-apikey"
  else
    echo "  Skipped (SKIP_VT=1)."
  fi
fi
echo ""

# ---- Step 5: GPG signing ----
echo "[5/8] GPG signing..."
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
  echo "  Signed: binary + checksums"
else
  echo "  No GPG key found — skipping signatures."
fi

# ---- Auto-update ECDSA signing (separate from GPG) ----
# Signs the SHA3-512 digest with a P-384 key. This is the .sig that the
# daemon verifies with the pubkey embedded in lib/constants.js.
AUTOUPDATE_KEY="${AUTOUPDATE_SIGNING_KEY_FILE:-${HOME}/.hermitstash-sync/autoupdate-signing.key}"
if [ -f "${AUTOUPDATE_KEY}" ]; then
  echo "  Signing for auto-update with ${AUTOUPDATE_KEY}"
  node -e "
  const fs = require('node:fs');
  const crypto = require('node:crypto');
  const key = crypto.createPrivateKey(fs.readFileSync(process.argv[1], 'utf8'));
  const digest = crypto.createHash('sha3-512').update(fs.readFileSync(process.argv[2])).digest();
  const sig = crypto.sign('sha512', digest, { key, dsaEncoding: 'ieee-p1363' });
  fs.writeFileSync(process.argv[2] + '.sig', sig);
  console.log('  Wrote ' + process.argv[2] + '.sig (' + sig.length + ' bytes)');
  " "${AUTOUPDATE_KEY}" "${EXE_PATH}"
else
  echo "  No auto-update signing key at ${AUTOUPDATE_KEY} — skipping .sig."
  echo "  (Generate with: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ${AUTOUPDATE_KEY})"
fi
echo ""

# ---- Step 6: Git tag ----
echo "[6/8] Creating git tag ${TAG}..."
git tag "${TAG}"
echo ""

# ---- Step 7: Push ----
echo "[7/8] Pushing to GitHub..."
git push
git push origin "${TAG}"
echo ""

# ---- Step 8: Create GitHub Release ----
echo "[8/8] Creating GitHub Release..."

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
| \`${EXE_NAME}\` | ${PLATFORM} ${ARCH} binary (Node.js SEA) |
| \`${EXE_NAME}.sha256\` | SHA-256 checksum |
| \`${EXE_NAME}.sha3-512\` | SHA3-512 checksum |"

if [ -n "${GPG_KEY_ID:-}" ]; then
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

# SHA3-512 (matches HermitStash server's hash algorithm)
echo \"${SHA3}  ${EXE_NAME}\" | sha3sum -c
\`\`\`"

if [ -n "${GPG_KEY_ID:-}" ]; then
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

### Security scan results

| Scanner | Result |
|---------|--------|
| Windows Defender | ${DEFENDER_RESULT} |"

if [ -n "${VT_URL}" ]; then
  NOTES="${NOTES}
| VirusTotal (70+ engines) | [View full report](${VT_URL}) |"
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
- GPG Key: ${GPG_KEY_ID:-none}
"

# Collect artifacts
ARTIFACTS=("build/${EXE_NAME}" "build/${EXE_NAME}.sha256" "build/${EXE_NAME}.sha3-512")
if [ -f "build/${EXE_NAME}.sig" ]; then
  ARTIFACTS+=("build/${EXE_NAME}.sig")
fi
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
if [ -n "${VT_URL}" ]; then
  echo "  VirusTotal: ${VT_URL}"
fi
echo "============================================"
echo ""

# ---- Cleanup build artifacts ----
echo "Cleaning up build directory..."
rm -f build/hermitstash-sync-*
echo "Done."
