#!/usr/bin/env bash
# hermitstash-sync — native install script for Linux (systemd)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/deploy/install.sh | sudo bash
#
#   # opt-in: auto-update daily via a systemd timer + update.sh
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/deploy/install.sh \
#     | sudo HERMITSTASH_AUTO_UPDATE=yes bash
#
# What it does:
#   1. Detects arch (x64/arm64), resolves the latest GitHub Release
#   2. Downloads the signed SEA binary + its SHA3-512 + its P-384 ECDSA .sig
#   3. Verifies both against the pubkey embedded in lib/autoupdate-pubkey.js
#      for that release (requires node; refuses to install without it unless
#      HERMITSTASH_ALLOW_UNVERIFIED=1 forces a weaker checksum-only path)
#   4. Creates a 'hermit' system user + /var/lib/hermitstash-sync
#   5. Installs checked-in systemd units (from the same release) — hardened
#      daemon unit + opt-in update timer + matching env files
#   6. Caches verify-release.js under /usr/local/lib/hermitstash-sync for
#      the update timer + uninstall script to use
#   7. Enables the auto-update timer if HERMITSTASH_AUTO_UPDATE=yes
#   8. On re-run: refreshes units and restarts the service (idempotent)
#
# Environment (all optional):
#   VERSION                  override release tag     (default: latest)
#   INSTALL_DIR              binary destination       (default: /usr/local/bin)
#   LIB_DIR                  lib cache                (default: /usr/local/lib/hermitstash-sync)
#   CONFIG_DIR               persistent state        (default: /var/lib/hermitstash-sync)
#   SYNC_DIR                 default sync folder     (default: /srv/hermitstash-sync)
#   SERVICE_USER             daemon user             (default: hermit)
#   REPO                     repo slug               (default: dotCooCoo/hermitstash-sync)
#   HERMITSTASH_AUTO_UPDATE  "yes" to enable timer   (default: unset = off)
#   HERMITSTASH_ALLOW_UNVERIFIED  "1" to install without the ECDSA signature
#                            gate when node is absent (checksum-only, weaker;
#                            default refuses)
#
# Uninstall:
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/deploy/uninstall.sh | sudo bash
#   # or, from the cached copy:
#   sudo bash /usr/local/lib/hermitstash-sync/uninstall.sh

set -euo pipefail

if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; NC=""
fi
log()  { printf '%s[hermitstash-sync]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[hermitstash-sync]%s %s\n' "$YELLOW" "$NC" "$*"; }
err()  { printf '%s[hermitstash-sync]%s %s\n' "$RED"    "$NC" "$*" >&2; }

# ─── Preflight ──────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  err "curl is required."
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  err "systemctl is required — this script targets systemd distros."
  exit 1
fi

REPO="${REPO:-dotCooCoo/hermitstash-sync}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
LIB_DIR="${LIB_DIR:-/usr/local/lib/hermitstash-sync}"
CONFIG_DIR="${CONFIG_DIR:-/var/lib/hermitstash-sync}"
SYNC_DIR="${SYNC_DIR:-/srv/hermitstash-sync}"
SERVICE_USER="${SERVICE_USER:-hermit}"
WANT_AUTO_UPDATE="${HERMITSTASH_AUTO_UPDATE:-no}"

# ─── Resolve arch + version ─────────────────────────────────────────────

case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64."; exit 1 ;;
esac

if [ -z "${VERSION:-}" ]; then
  log "Resolving latest release..."
  # `|| true` so a failed resolve (GitHub API 403 rate-limit on an unauthenticated
  # host, a network blip, or a pipefail on curl) does NOT abort under `set -e`
  # before the empty-check below — otherwise the actionable "Set VERSION=X.Y.Z to
  # pin" hint is never printed and the operator sees only an opaque non-zero exit.
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/') || true
  if [ -z "$VERSION" ]; then
    err "Could not resolve latest release. Set VERSION=X.Y.Z to pin."
    exit 1
  fi
fi

log "Installing hermitstash-sync v${VERSION} (linux-${ARCH})"

# ─── Download binary + checksum + sig ───────────────────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
NAME="hermitstash-sync-v${VERSION}-linux-${ARCH}"
RAW="https://raw.githubusercontent.com/${REPO}/v${VERSION}"

log "Downloading ${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin"           "${BASE}/${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin.sha3-512"   "${BASE}/${NAME}.sha3-512"
curl -fsSL --retry 3 -o "${WORK}/bin.sig"       "${BASE}/${NAME}.sig"

# Also pull the in-tree verify trio for this tag so the next update run
# can re-verify against the same pubkey + verifier that were in the repo
# at release time. The three files use only Node built-ins:
#   lib/autoupdate-pubkey.js     — P-384 verify key (operator-owned)
#   scripts/standalone-verifier.js — b.selfUpdate.standaloneVerifier copy
#   scripts/verify-release.js    — CLI shim wiring the two together
log "Fetching verify trio for v${VERSION}"
mkdir -p "${WORK}/lib" "${WORK}/scripts" "${WORK}/deploy"
curl -fsSL --retry 3 -o "${WORK}/lib/autoupdate-pubkey.js"       "${RAW}/lib/autoupdate-pubkey.js"
curl -fsSL --retry 3 -o "${WORK}/scripts/standalone-verifier.js" "${RAW}/scripts/standalone-verifier.js"
curl -fsSL --retry 3 -o "${WORK}/scripts/verify-release.js"      "${RAW}/scripts/verify-release.js"

# And the checked-in systemd units / env files / updater / uninstaller.
for f in hermitstash-sync.service hermitstash-sync-update.service hermitstash-sync-update.timer \
         hermitstash-sync-update.env update.sh uninstall.sh; do
  curl -fsSL --retry 3 -o "${WORK}/deploy/${f}" "${RAW}/deploy/${f}"
done

# ─── Verify ─────────────────────────────────────────────────────────────

log "Verifying SHA3-512 + P-384 ECDSA signature"

if command -v node >/dev/null 2>&1; then
  ( cd "$WORK" && node scripts/verify-release.js bin bin.sha3-512 bin.sig )
  log "Verification OK"
elif [ "${HERMITSTASH_ALLOW_UNVERIFIED:-0}" = "1" ]; then
  # Explicit operator opt-out of the signature gate. The .sha3-512 sidecar
  # travels over the same channel as the binary, so a checksum match is NOT
  # an integrity substitute for the detached ECDSA signature — an attacker
  # who can serve a modified binary can serve a matching checksum too. This
  # path exists only for hosts that genuinely cannot run Node; it is never
  # the default.
  warn "HERMITSTASH_ALLOW_UNVERIFIED=1 — skipping ECDSA signature, checksum-only."
  if ! command -v sha3sum >/dev/null 2>&1; then
    err "Neither node nor sha3sum is available. Install Node.js (apt install nodejs) for full"
    err "signature verification, or sha3sum (libdigest-sha3-perl) for the checksum-only path."
    exit 1
  fi
  EXPECTED=$(awk '{print $1}' "${WORK}/bin.sha3-512")
  ACTUAL=$(sha3sum -a 512 "${WORK}/bin" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    err "SHA3-512 mismatch. Refusing to install."
    exit 1
  fi
  warn "Checksum matched, but the ECDSA signature was NOT verified. This is weaker than the"
  warn "default install — install Node.js and re-run for the full signature gate."
else
  err "node is required to verify the release signature before installing."
  err "Install Node.js 24+ and re-run (apt install nodejs / dnf install nodejs / brew install node),"
  err "or use the signed container image (ghcr.io/dotcoocoo/hermitstash-sync)."
  err "To install without the signature gate (checksum-only, weaker — same-channel checksum is"
  err "not an integrity substitute), re-run with HERMITSTASH_ALLOW_UNVERIFIED=1."
  exit 1
fi

# ─── Install binary + lib cache ─────────────────────────────────────────

install -d -m 0755 "$LIB_DIR"
install -m 0755 "${WORK}/bin"                            "${INSTALL_DIR}/hermitstash-sync"
install -m 0644 "${WORK}/lib/autoupdate-pubkey.js"       "${LIB_DIR}/autoupdate-pubkey.js"
install -m 0644 "${WORK}/scripts/standalone-verifier.js" "${LIB_DIR}/standalone-verifier.js"
install -m 0644 "${WORK}/scripts/verify-release.js"      "${LIB_DIR}/verify-release.js"
install -m 0755 "${WORK}/deploy/update.sh"          "${LIB_DIR}/update.sh"
install -m 0755 "${WORK}/deploy/uninstall.sh"       "${LIB_DIR}/uninstall.sh"
log "Installed binary: ${INSTALL_DIR}/hermitstash-sync"
log "Installed lib cache: ${LIB_DIR}"

# ─── Create service user + dirs ─────────────────────────────────────────

if id "$SERVICE_USER" >/dev/null 2>&1; then
  log "User '${SERVICE_USER}' already exists"
else
  useradd --system --home-dir "${CONFIG_DIR}" --shell /usr/sbin/nologin --create-home "$SERVICE_USER"
  log "Created user '${SERVICE_USER}'"
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$SYNC_DIR"

# ─── Install systemd units ──────────────────────────────────────────────
# We install the CHECKED-IN units from this release (not downloaded-inline
# heredoc) so the running system matches the repo tag — if you audit the
# unit on disk against deploy/hermitstash-sync.service@v${VERSION} they'll
# byte-match.

install -m 0644 "${WORK}/deploy/hermitstash-sync.service"          /etc/systemd/system/hermitstash-sync.service
install -m 0644 "${WORK}/deploy/hermitstash-sync-update.service"   /etc/systemd/system/hermitstash-sync-update.service
install -m 0644 "${WORK}/deploy/hermitstash-sync-update.timer"     /etc/systemd/system/hermitstash-sync-update.timer
# The env file is OPERATOR config, not a checked-in unit — a re-run must NOT
# reset it to the all-commented default (that would silently discard an explicit
# HERMITSTASH_AUTO_UPDATE pause or other edits; `install -b` still overwrites the
# live file, only keeping a backup). Install it only when absent; on an upgrade
# with existing config, drop the shipped template beside it as `.new` so an
# operator can diff for newly-added options.
if [ ! -f /etc/default/hermitstash-sync-update ]; then
  install -m 0644 "${WORK}/deploy/hermitstash-sync-update.env"     /etc/default/hermitstash-sync-update
else
  install -m 0644 "${WORK}/deploy/hermitstash-sync-update.env"     /etc/default/hermitstash-sync-update.new
  log "Kept existing /etc/default/hermitstash-sync-update; shipped template written to .new — diff it for new options."
fi

# Patch non-default paths into the daemon unit via a drop-in (cleaner than
# sed'ing the upstream file — operators can diff the drop-in to see exactly
# what's been customized for this host).
if [ "$CONFIG_DIR" != "/var/lib/hermitstash-sync" ] || [ "$SYNC_DIR" != "/srv/hermitstash-sync" ]; then
  install -d -m 0755 /etc/systemd/system/hermitstash-sync.service.d
  cat > /etc/systemd/system/hermitstash-sync.service.d/local-paths.conf <<EOF
# Generated by deploy/install.sh — override default paths without touching
# the upstream unit file.
[Service]
Environment=HERMITSTASH_SYNC_CONFIG_DIR=${CONFIG_DIR}
ReadWritePaths=
ReadWritePaths=${CONFIG_DIR}
ReadWritePaths=${SYNC_DIR}
EOF
  log "Installed drop-in for custom paths"
fi

systemctl daemon-reload
log "Installed systemd units"

# ─── Opt-in auto-update timer ───────────────────────────────────────────

if [ "$WANT_AUTO_UPDATE" = "yes" ]; then
  log "HERMITSTASH_AUTO_UPDATE=yes — enabling update timer"
  systemctl enable --now hermitstash-sync-update.timer
else
  log "Auto-update timer installed but not enabled (pass HERMITSTASH_AUTO_UPDATE=yes to opt in)"
fi

# ─── Idempotent re-run: restart existing service ────────────────────────

if systemctl is-active --quiet hermitstash-sync.service; then
  log "Service already running — restarting with new binary"
  systemctl restart hermitstash-sync.service
fi

# ─── Next steps ─────────────────────────────────────────────────────────

cat <<NEXT

${GREEN}Installation complete (v${VERSION}).${NC}

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

Auto-update:
    sudo systemctl enable --now hermitstash-sync-update.timer   # turn on
    sudo systemctl disable --now hermitstash-sync-update.timer  # turn off
    sudo systemctl start hermitstash-sync-update.service         # run once
    sudo DRY_RUN=1 ${LIB_DIR}/update.sh                          # preview

Uninstall:
    sudo bash ${LIB_DIR}/uninstall.sh
    sudo bash ${LIB_DIR}/uninstall.sh --purge   # also delete data
NEXT
