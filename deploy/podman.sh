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

# Podman major version. Quadlet (.container files) is the supported path on
# Podman >= 4.4; `podman generate systemd` is deprecated there and removed on
# 5.x, where it writes no side-effect file into the cwd — so a move-and-enable
# approach leaves no unit behind and then aborts on `systemctl enable`. Pick the
# mechanism by version.
podman_major() {
  podman version --format '{{.Client.Version}}' 2>/dev/null \
    | sed -E 's/^([0-9]+)\..*/\1/' \
    | grep -E '^[0-9]+$' || echo 0
}

if [ "${GENERATE_SYSTEMD}" = "true" ]; then
  PODMAN_MAJOR="$(podman_major)"

  if [ "${PODMAN_MAJOR}" -ge 4 ]; then
    # ---- Quadlet (.container) — Podman >= 4.4 / 5.x ----
    echo "Installing Quadlet unit for automatic restart..."
    if [ "$(id -u)" -eq 0 ]; then
      QUADLET_DIR="/etc/containers/systemd"
      WANTED_BY="multi-user.target"
      SYSTEMCTL=(systemctl)
    else
      QUADLET_DIR="${HOME}/.config/containers/systemd"
      WANTED_BY="default.target"
      SYSTEMCTL=(systemctl --user)
    fi
    mkdir -p "${QUADLET_DIR}"

    QUADLET_FILE="${QUADLET_DIR}/${CONTAINER_NAME}.container"
    {
      echo "# Generated by deploy/podman.sh — Quadlet unit for hermitstash-sync."
      echo "[Unit]"
      echo "Description=hermitstash-sync container"
      echo ""
      echo "[Container]"
      echo "Image=${IMAGE}"
      echo "ContainerName=${CONTAINER_NAME}"
      echo "AutoUpdate=registry"
      echo "DropCapability=ALL"
      echo "NoNewPrivileges=true"
      echo "Volume=${CONFIG_VOL}:/config:Z"
      echo "Volume=$(readlink -f -- "${DATA_DIR}" 2>/dev/null || echo "${DATA_DIR}"):/data:Z"
      echo "Environment=HERMITSTASH_LOG_LEVEL=${LOG_LEVEL}"
      echo ""
      echo "[Service]"
      echo "Restart=always"
      echo ""
      echo "[Install]"
      echo "WantedBy=${WANTED_BY}"
    } > "${QUADLET_FILE}"

    # First-run race guard: enrollment runs INSIDE the container started above
    # (with SERVER_URL / ENROLL_CODE) and writes config.json to the /config
    # volume. The Quadlet unit that replaces it carries NO enrollment env, so
    # swapping before enrollment has persisted config.json makes the Quadlet
    # container crash-loop "not configured". Wait (bounded, ~60s) for config.json
    # to land on the volume — or for the bootstrap container to exit early (a
    # failed enroll: bad code / unreachable server) — before handing off. The
    # file persists on the named volume across the container removal below.
    _cfg_seen=false
    _tries=0
    while [ "${_tries}" -lt 30 ]; do
      if podman exec "${CONTAINER_NAME}" test -f /config/config.json >/dev/null 2>&1; then
        _cfg_seen=true; break
      fi
      if [ "$(podman inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null)" != "true" ]; then
        break  # bootstrap container stopped before enrolling — surface it below
      fi
      _tries=$((_tries + 1))
      sleep 2
    done
    if [ "${_cfg_seen}" != "true" ]; then
      echo "WARNING: enrollment did not persist /config/config.json in ~60s — the Quadlet unit may crash-loop until you enroll. Check: podman logs ${CONTAINER_NAME}" >&2
    fi

    # Quadlet owns the container lifecycle; remove the one we started above so
    # the generated unit can create it without a name clash.
    podman rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

    "${SYSTEMCTL[@]}" daemon-reload
    if [ "$(id -u)" -ne 0 ]; then
      loginctl enable-linger "$(whoami)" 2>/dev/null || true
    fi
    # Quadlet-generated units are transient and cannot be `enable`d directly;
    # the [Install] section above wires them at daemon-reload. Start it now.
    if "${SYSTEMCTL[@]}" start "${CONTAINER_NAME}.service"; then
      echo "Quadlet unit installed at ${QUADLET_FILE}"
      if [ "$(id -u)" -eq 0 ]; then
        echo "  sudo systemctl status ${CONTAINER_NAME}.service"
      else
        echo "  systemctl --user status ${CONTAINER_NAME}.service"
      fi
    else
      echo "WARNING: systemd could not start ${CONTAINER_NAME}.service from the Quadlet unit." >&2
      echo "The container is not running under systemd. Inspect with:" >&2
      if [ "$(id -u)" -eq 0 ]; then
        echo "  systemctl status ${CONTAINER_NAME}.service" >&2
      else
        echo "  systemctl --user status ${CONTAINER_NAME}.service" >&2
      fi
    fi

  else
    # ---- podman generate systemd — Podman < 4.4 (no Quadlet) ----
    echo "Generating systemd unit for automatic restart..."
    if [ "$(id -u)" -eq 0 ]; then
      UNIT_DIR="/etc/systemd/system"
      SYSTEMCTL=(systemctl)
    else
      UNIT_DIR="${HOME}/.config/systemd/user"
      mkdir -p "${UNIT_DIR}"
      SYSTEMCTL=(systemctl --user)
    fi

    UNIT_FILE="${UNIT_DIR}/container-${CONTAINER_NAME}.service"
    # Capture the unit on stdout (no --files, so no cwd side-effect to chase)
    # and validate it materialized before installing + enabling it.
    GEN_DIR="$(mktemp -d)"
    if podman generate systemd --name "${CONTAINER_NAME}" --new \
         --restart-policy=always > "${GEN_DIR}/container-${CONTAINER_NAME}.service" 2>/dev/null \
         && [ -s "${GEN_DIR}/container-${CONTAINER_NAME}.service" ]; then
      install -m 0644 "${GEN_DIR}/container-${CONTAINER_NAME}.service" "${UNIT_FILE}"
      rm -rf "${GEN_DIR}"
      "${SYSTEMCTL[@]}" daemon-reload
      "${SYSTEMCTL[@]}" enable "container-${CONTAINER_NAME}.service"
      if [ "$(id -u)" -ne 0 ]; then
        loginctl enable-linger "$(whoami)" 2>/dev/null || true
      fi
      echo "systemd unit installed at ${UNIT_FILE}"
      if [ "$(id -u)" -eq 0 ]; then
        echo "  sudo systemctl start container-${CONTAINER_NAME}"
      else
        echo "  systemctl --user start container-${CONTAINER_NAME}"
      fi
    else
      rm -rf "${GEN_DIR}"
      echo "WARNING: 'podman generate systemd' did not produce a unit on this Podman." >&2
      echo "The container is running with --restart=unless-stopped but is NOT managed by" >&2
      echo "systemd. Upgrade to Podman 4.4+ for Quadlet support, or create a unit manually." >&2
    fi
  fi
fi

echo ""
echo "Done."
