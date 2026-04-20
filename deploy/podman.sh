#!/usr/bin/env bash
# hermitstash-sync — Podman deployment script
#
# Podman is the default container runtime on RHEL, Fedora, Rocky Linux, and
# Alma Linux. It's daemonless and rootless by default.
#
# Usage (rootless):
#   bash podman.sh
#
# Usage (rootful, for systemd integration):
#   sudo bash podman.sh
#
# Environment variables (all optional):
#   VERSION          image tag to run            (default: latest)
#   DATA_DIR         host sync folder            (default: ./hermitstash-sync-data)
#   CONFIG_VOL       Podman named volume         (default: hermitstash-sync-config)
#   SERVER_URL       HermitStash server URL      (required on first start)
#   ENROLL_CODE      enrollment code             (required on first start)
#   LOG_LEVEL        debug|info|warn|error       (default: info)
#   GENERATE_SYSTEMD create user/system unit     (default: true)

set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "Error: podman not found." >&2
  echo "" >&2
  echo "Install it for your distro:" >&2
  echo "  Fedora / RHEL / Rocky / Alma: sudo dnf install podman" >&2
  echo "  Debian / Ubuntu:              sudo apt install podman" >&2
  echo "  Arch:                         sudo pacman -S podman" >&2
  echo "  openSUSE:                     sudo zypper install podman" >&2
  exit 1
fi

VERSION="${VERSION:-latest}"
DATA_DIR="${DATA_DIR:-./hermitstash-sync-data}"
CONFIG_VOL="${CONFIG_VOL:-hermitstash-sync-config}"
SERVER_URL="${SERVER_URL:-}"
ENROLL_CODE="${ENROLL_CODE:-}"
LOG_LEVEL="${LOG_LEVEL:-info}"
GENERATE_SYSTEMD="${GENERATE_SYSTEMD:-true}"
IMAGE="ghcr.io/dotcoocoo/hermitstash-sync:${VERSION}"
CONTAINER_NAME="hermitstash-sync"

echo "=== hermitstash-sync Podman Installer ==="
echo ""
echo "Image:      ${IMAGE}"
echo "Data:       $(readlink -f -- "${DATA_DIR}" 2>/dev/null || echo "${DATA_DIR}")"
echo "Config:     podman volume ${CONFIG_VOL}"
if [ "$(id -u)" -eq 0 ]; then
  echo "Mode:       rootful"
else
  echo "Mode:       rootless"
fi
echo ""

# ---- First-run detection: check for existing config volume ----

FIRST_RUN=false
if ! podman volume inspect "$CONFIG_VOL" >/dev/null 2>&1; then
  FIRST_RUN=true
fi

if $FIRST_RUN; then
  if [ -z "$SERVER_URL" ] || [ -z "$ENROLL_CODE" ]; then
    echo "First-time setup needs SERVER_URL and ENROLL_CODE:" >&2
    echo "" >&2
    echo "  SERVER_URL=https://hermitstash.example.com \\" >&2
    echo "  ENROLL_CODE=HSTASH-XXXX-XXXX-XXXX \\" >&2
    echo "  bash podman.sh" >&2
    exit 1
  fi
  echo "First run detected — will enroll and persist credentials to ${CONFIG_VOL}."
fi

mkdir -p "${DATA_DIR}"

# ---- Pull image ----

echo ""
echo "Pulling ${IMAGE}..."
podman pull "${IMAGE}"

# ---- Remove any stale container ----

if podman container exists "${CONTAINER_NAME}"; then
  echo "Removing stale container ${CONTAINER_NAME}..."
  podman rm -f "${CONTAINER_NAME}" >/dev/null
fi

# ---- Run ----

echo ""
echo "Starting container..."

RUN_ARGS=(
  --name "${CONTAINER_NAME}"
  --detach
  --restart=unless-stopped
  --cap-drop=ALL
  --security-opt=no-new-privileges:true
  # podman-auto-update checks the registry for a newer digest on the
  # currently-used tag. Enable with: sudo systemctl enable --now
  # podman-auto-update.timer (or the --user variant for rootless).
  --label "io.containers.autoupdate=registry"
  -v "${CONFIG_VOL}:/config:Z"
  -v "${DATA_DIR}:/data:Z"
  -e "HERMITSTASH_LOG_LEVEL=${LOG_LEVEL}"
)

if $FIRST_RUN; then
  RUN_ARGS+=(
    -e "HERMITSTASH_SERVER_URL=${SERVER_URL}"
    -e "HERMITSTASH_ENROLLMENT_CODE=${ENROLL_CODE}"
  )
fi

podman run "${RUN_ARGS[@]}" "${IMAGE}"

echo ""
echo "Container started."
echo "  podman logs -f ${CONTAINER_NAME}"
echo "  podman exec ${CONTAINER_NAME} hermitstash-sync status"
echo ""
echo "Auto-update: image carries the podman-auto-update label. Enable the"
echo "system or user timer to have the registry digest checked on a schedule:"
if [ "$(id -u)" -eq 0 ]; then
  echo "  sudo systemctl enable --now podman-auto-update.timer"
else
  echo "  systemctl --user enable --now podman-auto-update.timer"
fi
echo ""

# ---- systemd unit generation ----

if [ "${GENERATE_SYSTEMD}" = "true" ]; then
  echo "Generating systemd unit for automatic restart..."
  if [ "$(id -u)" -eq 0 ]; then
    UNIT_DIR="/etc/systemd/system"
  else
    UNIT_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${UNIT_DIR}"
  fi

  UNIT_FILE="${UNIT_DIR}/container-${CONTAINER_NAME}.service"
  podman generate systemd --name "${CONTAINER_NAME}" --files --new --restart-policy=always > "${UNIT_FILE}.tmp"
  # podman generate writes to ./container-<name>.service — move it into place.
  GENERATED="./container-${CONTAINER_NAME}.service"
  if [ -f "${GENERATED}" ]; then
    mv "${GENERATED}" "${UNIT_FILE}"
    rm -f "${UNIT_FILE}.tmp"
  fi

  if [ "$(id -u)" -eq 0 ]; then
    systemctl daemon-reload
    systemctl enable "container-${CONTAINER_NAME}.service"
    echo "Rootful systemd unit installed at ${UNIT_FILE}"
    echo "  sudo systemctl start container-${CONTAINER_NAME}"
  else
    systemctl --user daemon-reload
    systemctl --user enable "container-${CONTAINER_NAME}.service"
    # Survive logout (requires linger)
    loginctl enable-linger "$(whoami)" 2>/dev/null || true
    echo "Rootless user-systemd unit installed at ${UNIT_FILE}"
    echo "  systemctl --user start container-${CONTAINER_NAME}"
  fi
fi

echo ""
echo "Done."
