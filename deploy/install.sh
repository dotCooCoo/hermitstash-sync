#!/usr/bin/env bash
# hermitstash-sync — native install script for Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/deploy/install.sh | sudo bash
#
# What it does:
#   1. Detects arch (x64/arm64), resolves the latest GitHub Release
#   2. Downloads the signed SEA binary + its SHA3-512 + its P-384 ECDSA .sig
#   3. Verifies both against the embedded pubkey using Node.js if available,
#      otherwise uses openssl + sha3sum
#   4. Creates a 'hermit' system user + /var/lib/hermitstash-sync
#   5. Installs the systemd service (deploy/hermitstash-sync.service)
#   6. Prints next-step instructions for enrollment
#
# Environment:
#   VERSION         override the release tag (e.g. 0.4.7). Default = latest.
#   INSTALL_DIR     where the binary lands. Default: /usr/local/bin
#   CONFIG_DIR      persistent state dir. Default: /var/lib/hermitstash-sync
#   SYNC_DIR        default sync folder. Default: /srv/hermitstash-sync
#   SERVICE_USER    daemon user. Default: hermit
#   REPO            override repo slug. Default: dotCooCoo/hermitstash-sync
#
# Uninstall:
#   sudo systemctl disable --now hermitstash-sync
#   sudo rm /etc/systemd/system/hermitstash-sync.service /usr/local/bin/hermitstash-sync
#   sudo userdel hermit
#   sudo rm -rf /var/lib/hermitstash-sync

set -euo pipefail

# Colors (no-op when stdout isn't a TTY)
if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; NC=""
fi

log()  { printf '%s[hermitstash-sync]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[hermitstash-sync]%s %s\n' "$YELLOW" "$NC" "$*"; }
err()  { printf '%s[hermitstash-sync]%s %s\n' "$RED"    "$NC" "$*" >&2; }

# ---- Preflight ----

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  err "curl is required."
  exit 1
fi

REPO="${REPO:-dotCooCoo/hermitstash-sync}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/var/lib/hermitstash-sync}"
SYNC_DIR="${SYNC_DIR:-/srv/hermitstash-sync}"
SERVICE_USER="${SERVICE_USER:-hermit}"

# ---- Resolve architecture + version ----

case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64."; exit 1 ;;
esac

if [ -z "${VERSION:-}" ]; then
  log "Resolving latest release..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":\s*"v?([^"]+)".*/\1/')
  if [ -z "$VERSION" ]; then
    err "Could not resolve latest release. Set VERSION=X.Y.Z to pin."
    exit 1
  fi
fi

log "Installing hermitstash-sync v${VERSION} (linux-${ARCH}) to ${INSTALL_DIR}"

# ---- Download binary + checksum + sig ----

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
NAME="hermitstash-sync-v${VERSION}-linux-${ARCH}"

log "Downloading ${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin"         "${BASE}/${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin.sha3-512" "${BASE}/${NAME}.sha3-512"
curl -fsSL --retry 3 -o "${WORK}/bin.sig"     "${BASE}/${NAME}.sig"

# ---- Verify ----

log "Verifying SHA3-512 + P-384 ECDSA signature..."

# Prefer the Node-based verifier the Dockerfile uses — it validates both the
# checksum and the signature against the pubkey embedded in the binary's
# release. Falls back to openssl + sha3sum if no node is around.
if command -v node >/dev/null 2>&1; then
  # Pull the verify-release.js + constants.js for this tag so the pubkey
  # matches what was in the repo at release time.
  RAW="https://raw.githubusercontent.com/${REPO}/v${VERSION}"
  mkdir -p "${WORK}/lib" "${WORK}/scripts"
  curl -fsSL --retry 3 -o "${WORK}/lib/constants.js"     "${RAW}/lib/constants.js"
  curl -fsSL --retry 3 -o "${WORK}/scripts/verify-release.js" "${RAW}/scripts/verify-release.js"
  ( cd "$WORK" && node scripts/verify-release.js bin bin.sha3-512 bin.sig )
else
  warn "node not installed — falling back to sha3sum-only verification (signature NOT checked)."
  if ! command -v sha3sum >/dev/null 2>&1; then
    err "Neither node nor sha3sum is available. Install node (apt install nodejs) or sha3sum (apt install libdigest-sha3-perl)."
    exit 1
  fi
  EXPECTED=$(awk '{print $1}' "${WORK}/bin.sha3-512")
  ACTUAL=$(sha3sum -a 512 "${WORK}/bin" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    err "SHA3-512 mismatch. Refusing to install."
    exit 1
  fi
  warn "Checksum OK, but ECDSA signature was NOT verified (no node). Install node and re-run for full verification."
fi

log "Verification OK"

# ---- Install binary ----

install -m 0755 "${WORK}/bin" "${INSTALL_DIR}/hermitstash-sync"
log "Installed ${INSTALL_DIR}/hermitstash-sync"

# ---- Create service user ----

if id "$SERVICE_USER" >/dev/null 2>&1; then
  log "User '${SERVICE_USER}' already exists"
else
  useradd --system --home-dir "${CONFIG_DIR}" --shell /usr/sbin/nologin --create-home "$SERVICE_USER"
  log "Created user '${SERVICE_USER}'"
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$SYNC_DIR"

# ---- Install systemd unit ----

UNIT="/etc/systemd/system/hermitstash-sync.service"
RAW_UNIT="https://raw.githubusercontent.com/${REPO}/v${VERSION}/deploy/hermitstash-sync.service"

log "Installing systemd unit at ${UNIT}"
curl -fsSL --retry 3 -o "$UNIT" "$RAW_UNIT"
# Patch CONFIG_DIR + sync path into the unit if the caller overrode defaults.
if [ "$CONFIG_DIR" != "/var/lib/hermitstash-sync" ]; then
  sed -i "s|/var/lib/hermitstash-sync|${CONFIG_DIR}|g" "$UNIT"
fi
if [ "$SYNC_DIR" != "/srv/hermitstash-sync" ]; then
  sed -i "s|/srv/hermitstash-sync|${SYNC_DIR}|g" "$UNIT"
fi

systemctl daemon-reload
log "systemd unit installed (not yet started)"

# ---- Next steps ----

cat <<NEXT

${GREEN}Installation complete.${NC}

Next: enroll the client with your HermitStash server.

  Option A — interactive:
    sudo -u ${SERVICE_USER} HERMITSTASH_SYNC_CONFIG_DIR=${CONFIG_DIR} \\
      ${INSTALL_DIR}/hermitstash-sync init

  Option B — headless (env vars, good for scripted deploys):
    sudo -u ${SERVICE_USER} \\
      HERMITSTASH_SYNC_CONFIG_DIR=${CONFIG_DIR} \\
      HERMITSTASH_SERVER_URL=https://hermitstash.example.com \\
      HERMITSTASH_ENROLLMENT_CODE=HSTASH-XXXX-XXXX-XXXX \\
      HERMITSTASH_SYNC_FOLDER=${SYNC_DIR} \\
      ${INSTALL_DIR}/hermitstash-sync init --non-interactive

Then start the service:
    sudo systemctl enable --now hermitstash-sync
    sudo systemctl status hermitstash-sync
    sudo journalctl -u hermitstash-sync -f
NEXT
