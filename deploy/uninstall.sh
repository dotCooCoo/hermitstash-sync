#!/usr/bin/env bash
# hermitstash-sync — native uninstaller
#
# Reverses deploy/install.sh. Stops + disables the service and update timer,
# removes systemd units + drop-ins + env files, removes the binary and the
# verify-release cache, deletes the hermit user (only if it owns the config
# dir — avoids clobbering an unrelated hermit user), and — with --purge —
# also removes the config and sync directories.
#
# Usage:
#   sudo bash /usr/local/lib/hermitstash-sync/uninstall.sh
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/deploy/uninstall.sh | sudo bash
#
# DATA IS PRESERVED BY DEFAULT. Pass --purge to also delete:
#   $CONFIG_DIR (API key, mTLS certs, state DB, logs)
#   $SYNC_DIR   (the actual synced files)
#
# Flags:
#   --purge   Delete config + synced files (irreversible)
#   --yes     Non-interactive; assume yes for all prompts
#   --help    Show this message
#
# Environment overrides (match the install-time overrides):
#   INSTALL_DIR, CONFIG_DIR, SYNC_DIR, LIB_DIR, SERVICE_USER

set -euo pipefail

if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; NC=""
fi
log()  { printf '%s[hermitstash-sync]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[hermitstash-sync]%s %s\n' "$YELLOW" "$NC" "$*"; }
err()  { printf '%s[hermitstash-sync]%s %s\n' "$RED"    "$NC" "$*" >&2; }

# ─── Args ───────────────────────────────────────────────────────────────

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h) sed -n '2,24p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) err "Unknown argument: $arg"; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  err "This script must run as root (sudo)."
  exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
LIB_DIR="${LIB_DIR:-/usr/local/lib/hermitstash-sync}"
CONFIG_DIR="${CONFIG_DIR:-/var/lib/hermitstash-sync}"
SYNC_DIR="${SYNC_DIR:-/srv/hermitstash-sync}"
SERVICE_USER="${SERVICE_USER:-hermit}"
SERVICE_FILE="/etc/systemd/system/hermitstash-sync.service"
UPDATE_SERVICE="/etc/systemd/system/hermitstash-sync-update.service"
UPDATE_TIMER="/etc/systemd/system/hermitstash-sync-update.timer"
ENV_FILE="/etc/default/hermitstash-sync"
UPDATE_ENV="/etc/default/hermitstash-sync-update"
DROPIN_DIR="/etc/systemd/system/hermitstash-sync.service.d"

confirm() {
  if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
  local prompt="$1"
  printf "%s [y/N] " "$prompt"
  read -r reply </dev/tty || return 1
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

log "Uninstalling hermitstash-sync"
echo ""

# ─── Step 1: Stop + disable services ────────────────────────────────────
# Stop the update timer FIRST so it can't fire a new install mid-uninstall.

if systemctl list-unit-files hermitstash-sync-update.timer >/dev/null 2>&1; then
  log "Stopping hermitstash-sync-update timer"
  systemctl disable --now hermitstash-sync-update.timer 2>/dev/null || true
fi
if systemctl list-unit-files hermitstash-sync-update.service >/dev/null 2>&1; then
  systemctl stop hermitstash-sync-update.service 2>/dev/null || true
fi

if systemctl list-unit-files hermitstash-sync.service >/dev/null 2>&1; then
  log "Stopping hermitstash-sync service"
  systemctl disable --now hermitstash-sync 2>/dev/null || true
else
  warn "hermitstash-sync.service not registered — skipping"
fi

# ─── Step 2: Remove units + env files + drop-ins ────────────────────────

for f in "$SERVICE_FILE" "$UPDATE_SERVICE" "$UPDATE_TIMER" "$ENV_FILE" "$UPDATE_ENV"; do
  if [ -f "$f" ]; then
    log "Removing $(basename "$f")"
    rm -f "$f"
  fi
done

if [ -d "$DROPIN_DIR" ]; then
  log "Removing systemd drop-in directory"
  rm -rf "$DROPIN_DIR"
fi

if [ -f /var/lock/hermitstash-sync-update.lock ]; then
  rm -f /var/lock/hermitstash-sync-update.lock
fi

systemctl daemon-reload
systemctl reset-failed hermitstash-sync 2>/dev/null || true
systemctl reset-failed hermitstash-sync-update 2>/dev/null || true

# ─── Step 3: Remove binary + verify-release cache ───────────────────────

for f in "${INSTALL_DIR}/hermitstash-sync" "${INSTALL_DIR}/hermitstash-sync.prev"; do
  if [ -f "$f" ]; then
    log "Removing $f"
    rm -f "$f"
  fi
done

if [ -d "$LIB_DIR" ]; then
  log "Removing $LIB_DIR"
  rm -rf "$LIB_DIR"
fi

# ─── Step 4: Remove system user (only if it owns the config dir) ────────

if id "$SERVICE_USER" >/dev/null 2>&1; then
  OWNER="$(stat -c '%U' "$CONFIG_DIR" 2>/dev/null || echo "")"
  if [ "$OWNER" = "$SERVICE_USER" ]; then
    log "Removing system user '${SERVICE_USER}'"
    userdel "$SERVICE_USER" 2>/dev/null || warn "Could not delete user ${SERVICE_USER}"
  else
    warn "User '${SERVICE_USER}' does not own ${CONFIG_DIR} — leaving it alone"
  fi
fi

# ─── Step 5: Optionally purge data ──────────────────────────────────────

if [ "$PURGE" -eq 1 ]; then
  warn "--purge requested: this will delete:"
  warn "  ${CONFIG_DIR}  (API key, mTLS certs, state DB)"
  warn "  ${SYNC_DIR}    (the synced files)"
  if confirm "Really delete both directories?"; then
    rm -rf "$CONFIG_DIR" "$SYNC_DIR"
    log "Config + sync data removed."
  else
    warn "Skipped — data preserved at ${CONFIG_DIR} and ${SYNC_DIR}"
  fi
else
  if [ -d "$CONFIG_DIR" ] || [ -d "$SYNC_DIR" ]; then
    log "Data preserved:"
    [ -d "$CONFIG_DIR" ] && echo "  ${CONFIG_DIR}"
    [ -d "$SYNC_DIR" ]   && echo "  ${SYNC_DIR}"
    echo "  Remove with: sudo rm -rf ${CONFIG_DIR} ${SYNC_DIR}"
  fi
fi

echo ""
log "Uninstall complete."
