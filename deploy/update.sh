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
#      ECDSA signature; verifies them against the install-time pinned
#      verify trio cached under LIB_DIR (autoupdate-pubkey.js +
#      standalone-verifier.js + verify-release.js) — never a key fetched
#      from the release being installed
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
  err "node is required for ECDSA signature verification. Install Node.js 24+."
  exit 20
fi

# The pinned verify trio is the install-time trust root: the binary is
# verified against THESE files, not a copy fetched from the release. All
# three must be present, or we cannot establish that the new binary was
# signed by the operator-trusted key.
for pinned in verify-release.js standalone-verifier.js autoupdate-pubkey.js; do
  if [ ! -f "${LIB_DIR}/${pinned}" ]; then
    err "${pinned} not found under ${LIB_DIR}. Re-run deploy/install.sh to restore the pinned verify key."
    exit 20
  fi
done

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
  # Select the HIGHEST-semver stable release whose major matches the running
  # binary. The /releases feed returns prereleases and drafts too, and it is
  # ordered newest-PUBLISHED-first, not highest-version-first — so a backport
  # patch to an older minor can be published after a newer minor. Parse the
  # JSON properly (node is already a hard dependency of this script): drop
  # prerelease + draft entries, keep clean X.Y.Z tags on the current major,
  # and fold to the maximum version rather than the first one seen.
  local current_major="$1"
  curl -fsSL -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=100" \
    | HS_CURRENT_MAJOR="$current_major" node -e '
      const major = process.env.HS_CURRENT_MAJOR;
      let raw = "";
      process.stdin.on("data", (c) => { raw += c; });
      process.stdin.on("end", () => {
        let releases;
        try { releases = JSON.parse(raw); } catch { process.exit(0); }
        if (!Array.isArray(releases)) process.exit(0);
        const cmp = (a, b) => {
          const x = a.split("."), y = b.split(".");
          for (let i = 0; i < 3; i++) {
            const d = (Number(x[i]) || 0) - (Number(y[i]) || 0);
            if (d) return d;
          }
          return 0;
        };
        let best = null;
        for (const r of releases) {
          if (!r || r.prerelease || r.draft) continue;
          const tag = String(r.tag_name || "").replace(/^v/, "");
          if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(tag)) continue;
          if (tag.split(".")[0] !== major) continue;
          if (best === null || cmp(tag, best) > 0) best = tag;
        }
        if (best) process.stdout.write(best + "\n");
      });
    '
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
# Clean the scratch dir AND a stale "${BIN}.new" left by a swap interrupted
# between `install ... "${BIN}.new"` and `mv -f "${BIN}.new" "$BIN"` — otherwise
# an aborted update leaks a half-written binary next to the live one (uninstall
# also sweeps it). ${BIN:-} keeps this safe under `set -u` before BIN is set;
# rm -f never fails, so the trap can't itself abort.
trap 'rm -rf "$WORK"; rm -f "${BIN:-}.new"' EXIT

BASE="https://github.com/${GITHUB_REPO}/releases/download/v${TARGET}"
NAME="hermitstash-sync-v${TARGET}-linux-${ARCH}"

log "Downloading ${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin"          "${BASE}/${NAME}"
curl -fsSL --retry 3 -o "${WORK}/bin.sha3-512"  "${BASE}/${NAME}.sha3-512"
curl -fsSL --retry 3 -o "${WORK}/bin.sig"      "${BASE}/${NAME}.sig"

log "Verifying SHA3-512 + P-384 ECDSA signature"
# Verify the downloaded binary against the LOCALLY-PINNED verify trio that
# install.sh wrote to ${LIB_DIR} — never against a copy fetched from the
# release being installed. Downloading the pubkey alongside the binary it is
# meant to authenticate is self-referential: whoever controls the release
# controls both the binary and the key it would be checked against, so a
# tampered or attacker-published release would verify trivially. Pinning to
# the install-time key is the trust-on-first-use root.
#
# verify-release.js resolves its dependencies by relative path
# (./standalone-verifier and ../lib/autoupdate-pubkey), so stage the pinned
# files into the checkout-shaped layout it expects before invoking it.
mkdir -p "${WORK}/lib" "${WORK}/scripts"
cp -f "${LIB_DIR}/verify-release.js"      "${WORK}/scripts/verify-release.js"
cp -f "${LIB_DIR}/standalone-verifier.js" "${WORK}/scripts/standalone-verifier.js"
cp -f "${LIB_DIR}/autoupdate-pubkey.js"   "${WORK}/lib/autoupdate-pubkey.js"

if ! ( cd "$WORK" && node scripts/verify-release.js bin bin.sha3-512 bin.sig ); then
  err "Signature verification failed against the pinned release key — refusing to install."
  err "If the project rotated its signing key, re-run deploy/install.sh to adopt the new pinned key."
  exit 40
fi

# ─── Install atomically ─────────────────────────────────────────────────

log "Staging new binary"
install -m 0755 "${WORK}/bin" "${BIN}.new"

log "Capturing rollback copy"
cp -a "$BIN" "$ROLLBACK"

log "Swapping ${BIN}"
mv -f "${BIN}.new" "$BIN"

# The pinned verify trio under ${LIB_DIR} is the trust root and is left
# untouched here. The updater never silently adopts a signing key shipped by
# the release it just installed — that would defeat the install-time pin. Key
# rotation is an explicit operator action: re-run deploy/install.sh to fetch
# and pin the new key. Leaving the cache unchanged also keeps it consistent
# with the running binary after a rollback.

# ─── Restart + health probe ─────────────────────────────────────────────

log "Restarting ${SERVICE_NAME}"
# Don't let a non-zero restart abort the script under `set -e`. The unit is
# Type=notify with TimeoutStartSec, so `systemctl restart` returns non-zero when
# the freshly-swapped binary crash-loops or never signals READY=1 — which is the
# exact failure the rollback below exists to handle. Swallow the status (warn
# returns 0) and let the health probe be the single source of truth: an unhealthy
# service falls through to the rollback instead of exiting here with the broken
# binary still installed and the daemon down.
systemctl restart "$SERVICE_NAME" || warn "systemctl restart returned non-zero — the health probe decides success/failure"

health_ok() {
  # `status` reports RUNNING when the daemon's PID file confirms it's up and
  # not in an ERROR state. Run it AS THE SERVICE USER: cmdStatus opens the
  # state DB read-write (it re-asserts journal_mode=WAL), so running it as root
  # could, in a narrow restart-window race, leave root-owned WAL/SHM sidecars
  # in the service user's CONFIG_DIR that the daemon then cannot write. runuser
  # performs a privilege DROP (root -> service user), which NoNewPrivileges=yes
  # permits — NNP blocks GAINING privileges, not dropping them — unlike `sudo`,
  # which NNP refuses to run at all (a sudo probe would fail every healthy
  # update and force a needless rollback). If runuser or the service user is
  # unavailable, fall back to a direct probe so a missing tool never forces a
  # rollback on its own.
  if command -v runuser >/dev/null 2>&1 && id "$SERVICE_USER" >/dev/null 2>&1; then
    runuser -u "$SERVICE_USER" -- env "HERMITSTASH_SYNC_CONFIG_DIR=$CONFIG_DIR" \
      "$BIN" status 2>/dev/null | grep -q "Status: RUNNING"
  else
    HERMITSTASH_SYNC_CONFIG_DIR="$CONFIG_DIR" \
      "$BIN" status 2>/dev/null | grep -q "Status: RUNNING"
  fi
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
# Same errexit guard as the forward restart: a non-zero rollback restart must not
# abort before the final health probe + the "manual intervention required" exit.
systemctl restart "$SERVICE_NAME" || warn "rollback restart returned non-zero — the final health probe decides"

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
