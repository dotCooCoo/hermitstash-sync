#!/usr/bin/env bash
# hermitstash-sync — unattended updater for native (systemd) installs.
#
# Invoked via hermitstash-sync-update.timer, or manually:
#   sudo /usr/local/lib/hermitstash-sync/update.sh
#   sudo DRY_RUN=1 /usr/local/lib/hermitstash-sync/update.sh
#
# What it does:
#   1. Reads installed version from `hermitstash-sync version`
#   2. Fetches the newest release from GitHub that matches UPDATE_CHANNEL
#      and stays within the current major
#   3. Downloads the signed SEA binary + its SHA3-512 digest + its P-384
#      ECDSA signature; verifies both against the pubkey embedded in the
#      release's lib/constants.js via scripts/verify-release.js
#   4. Captures a rollback copy of the current binary
#   5. Atomically replaces the binary, restarts the systemd service
#   6. Waits for the daemon to report RUNNING status; on failure, restores
#      the rollback copy and restarts again
#   7. Never crosses a major version boundary on its own
#
# Environment (all optional):
#   UPDATE_CHANNEL    stable | off                 (default: stable)
#   VERSION           pin a specific version       (default: latest-stable)
#   INSTALL_DIR       where the binary lives       (default: /usr/local/bin)
#   LIB_DIR           where verify-release.js lives (default: /usr/local/lib/hermitstash-sync)
#   SERVICE_NAME      systemd unit name            (default: hermitstash-sync)
#   SERVICE_USER      uid whose status we check    (default: hermit)
#   CONFIG_DIR        daemon config dir            (default: /var/lib/hermitstash-sync)
#   HEALTH_TIMEOUT    seconds to wait after restart (default: 60)
#   GITHUB_REPO       upstream repo slug           (default: dotCooCoo/hermitstash-sync)
#   DRY_RUN           1 = preview only             (default: 0)
#   FORCE             1 = reinstall even if up to date (default: 0)
#
# Exit codes:
#   0   up to date OR update applied and healthy
#   10  update applied but unhealthy — rolled back
#   20  precondition failed (binary missing, non-root, etc.)
#   30  network / release-metadata fetch failed
#   40  signature verification failed
#   50  concurrent invocation (lock held)

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────

UPDATE_CHANNEL="${UPDATE_CHANNEL:-stable}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
LIB_DIR="${LIB_DIR:-/usr/local/lib/hermitstash-sync}"
SERVICE_NAME="${SERVICE_NAME:-hermitstash-sync}"
SERVICE_USER="${SERVICE_USER:-hermit}"
CONFIG_DIR="${CONFIG_DIR:-/var/lib/hermitstash-sync}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"
GITHUB_REPO="${GITHUB_REPO:-dotCooCoo/hermitstash-sync}"
DRY_RUN="${DRY_RUN:-0}"
FORCE="${FORCE:-0}"
PIN_VERSION="${VERSION:-}"

BIN="${INSTALL_DIR}/hermitstash-sync"
ROLLBACK="${INSTALL_DIR}/hermitstash-sync.prev"
LOCK_FILE="${LOCK_FILE:-/var/lock/hermitstash-sync-update.lock}"

# ─── Logging ─────────────────────────────────────────────────────────────

if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; NC=""
fi
log()  { printf '%s[hermitstash-sync-update]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[hermitstash-sync-update]%s %s\n' "$YELLOW" "$NC" "$*"; }
err()  { printf '%s[hermitstash-sync-update]%s %s\n' "$RED"    "$NC" "$*" >&2; }

# ─── Preflight ──────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
  err "This script must run as root (it manages the systemd unit + /usr/local/bin)."
  exit 20
fi

if [ ! -x "$BIN" ]; then
  err "No existing binary at $BIN. Run deploy/install.sh first."
  exit 20
fi

if ! command -v curl >/dev/null 2>&1; then
  err "curl is required."
  exit 20
fi

if ! command -v node >/dev/null 2>&1; then
  err "node is required for ECDSA signature verification. Install Node.js 20+."
  exit 20
fi

if [ ! -f "${LIB_DIR}/verify-release.js" ] || [ ! -f "${LIB_DIR}/constants.js" ]; then
  err "verify-release.js / constants.js not found under ${LIB_DIR}. Re-run deploy/install.sh."
  exit 20
fi

# ─── Concurrency guard ──────────────────────────────────────────────────

exec 9>"$LOCK_FILE" 2>/dev/null || { err "Cannot open $LOCK_FILE"; exit 20; }
if ! flock -n 9; then
  warn "Another update is running — skipping."
  exit 50
fi

# ─── Channel gate ───────────────────────────────────────────────────────

if [ "$UPDATE_CHANNEL" = "off" ]; then
  log "UPDATE_CHANNEL=off — auto-update disabled; exiting."
  exit 0
fi

# ─── Version helpers ────────────────────────────────────────────────────

read_current_version() {
  # The SEA prints a line like "hermitstash-sync v0.4.7" as first output.
  "$BIN" version 2>/dev/null | awk '/^hermitstash-sync v[0-9]/ {sub(/^v/, "", $2); print $2; exit}'
}

version_gt() {
  # shellcheck disable=SC2206
  local A=(${1//./ }) B=(${2//./ })
  for i in 0 1 2; do
    local a="${A[$i]:-0}" b="${B[$i]:-0}"
    if [ "$a" -gt "$b" ] 2>/dev/null; then return 0; fi
    if [ "$a" -lt "$b" ] 2>/dev/null; then return 1; fi
  done
  return 1
}

major_of() { echo "${1%%.*}"; }

fetch_latest_stable_tag() {
  local current_major="$1"
  curl -fsSL -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${GITHUB_REPO}/releases" \
    | grep -Eo '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"v?([^"]+)"$/\1/' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | while read -r ver; do
        if [ "$(major_of "$ver")" = "$current_major" ]; then
          echo "$ver"; break
        fi
      done
}

# ─── Arch detection ─────────────────────────────────────────────────────

case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "Unsupported architecture: $(uname -m)"; exit 20 ;;
esac

# ─── Decide target version ──────────────────────────────────────────────

CURRENT="$(read_current_version)"
if [ -z "$CURRENT" ]; then
  err "Could not read current version from $BIN"
  exit 20
fi

if [ -n "$PIN_VERSION" ]; then
  TARGET="$PIN_VERSION"
else
  TARGET="$(fetch_latest_stable_tag "$(major_of "$CURRENT")" || true)"
  if [ -z "$TARGET" ]; then
    err "Could not determine latest release from ${GITHUB_REPO}."
    exit 30
  fi
fi

log "Current: ${CURRENT}  Latest matching major: ${TARGET}"

if [ "$FORCE" != "1" ] && ! version_gt "$TARGET" "$CURRENT"; then
  log "Up to date — nothing to do."
  exit 0
fi

if [ "$DRY_RUN" = "1" ]; then
  log "DRY_RUN: would update ${CURRENT} → ${TARGET}"
  exit 0
fi

# ─── Download + verify ──────────────────────────────────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

BASE="https://github.com/${GITHUB_REPO}/releases/download/v${TARGET}"
NAME="hermitstash-sync-v${TARGET}-linux-${ARCH}"

log "Downloading ${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin"          "${BASE}/${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin.sha3-512"  "${BASE}/${NAME}.sha3-512"
curl -fsSL --retry 3 -o "${WORK}/bin.sig"      "${BASE}/${NAME}.sig"

log "Verifying SHA3-512 + P-384 ECDSA signature"
# Pull the verifier + constants.js for the TARGET version so the pubkey
# matches what was in the repo at release time.
RAW="https://raw.githubusercontent.com/${GITHUB_REPO}/v${TARGET}"
mkdir -p "${WORK}/lib" "${WORK}/scripts"
curl -fsSL --retry 3 -o "${WORK}/lib/constants.js"          "${RAW}/lib/constants.js"
curl -fsSL --retry 3 -o "${WORK}/scripts/verify-release.js" "${RAW}/scripts/verify-release.js"

if ! ( cd "$WORK" && node scripts/verify-release.js bin bin.sha3-512 bin.sig ); then
  err "Signature verification failed — refusing to install."
  exit 40
fi

# ─── Install atomically ─────────────────────────────────────────────────

log "Staging new binary"
install -m 0755 "${WORK}/bin" "${BIN}.new"

log "Capturing rollback copy"
cp -a "$BIN" "$ROLLBACK"

log "Swapping ${BIN}"
mv -f "${BIN}.new" "$BIN"

# Update the verify-release.js / constants.js cached under LIB_DIR so the
# NEXT update can verify against the newer pubkey if the release ever
# rotates it.
install -m 0644 "${WORK}/scripts/verify-release.js" "${LIB_DIR}/verify-release.js"
install -m 0644 "${WORK}/lib/constants.js"          "${LIB_DIR}/constants.js"

# ─── Restart + health probe ─────────────────────────────────────────────

log "Restarting ${SERVICE_NAME}"
systemctl restart "$SERVICE_NAME"

health_ok() {
  # `status` returns RUNNING when the daemon's PID file + state DB confirm
  # it's up and not in an ERROR state. We run it as the service user so
  # it reads the same CONFIG_DIR.
  if sudo -u "$SERVICE_USER" HERMITSTASH_SYNC_CONFIG_DIR="$CONFIG_DIR" \
       "$BIN" status 2>/dev/null | grep -q "Status: RUNNING"; then
    return 0
  fi
  return 1
}

DEADLINE=$(( $(date +%s) + HEALTH_TIMEOUT ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if health_ok; then
    log "Update complete — v${TARGET} is healthy."
    # Keep .prev around so the operator can roll back manually if something
    # regresses later. install.sh cleans it up on uninstall.
    exit 0
  fi
  sleep 2
done

# ─── Rollback ───────────────────────────────────────────────────────────

err "Health check failed after ${HEALTH_TIMEOUT}s — rolling back to ${CURRENT}"
mv -f "$ROLLBACK" "$BIN"
systemctl restart "$SERVICE_NAME"

DEADLINE=$(( $(date +%s) + HEALTH_TIMEOUT ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if health_ok; then
    warn "Rollback to ${CURRENT} restored health. Investigate v${TARGET} before retrying."
    exit 10
  fi
  sleep 2
done

err "Service still unhealthy after rollback — manual intervention required."
exit 10
