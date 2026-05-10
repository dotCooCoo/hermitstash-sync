#!/usr/bin/env bash
# hermitstash-sync container entrypoint.
#
# On first start (no config.json in $HERMITSTASH_SYNC_CONFIG_DIR) this runs
# the non-interactive init flow using env vars. On subsequent starts the
# config is already persisted on the /config volume, so we go straight to
# `hermitstash-sync start` and the daemon honours any existing API key +
# mTLS certs.
#
# Required on first start:
#   HERMITSTASH_SERVER_URL         server base URL (https://...)
#   HERMITSTASH_ENROLLMENT_CODE    HSTASH-XXXX-XXXX-XXXX
# Optional:
#   HERMITSTASH_SYNC_FOLDER        defaults to /data
#   HERMITSTASH_AUTO_UPDATE        "false" to disable binary self-replace.
#                                  Forced false in this script regardless —
#                                  containers must be updated by pulling a
#                                  new image tag, not by the daemon writing
#                                  over its own /usr/local/bin/... inode.

set -euo pipefail

CONFIG_DIR="${HERMITSTASH_SYNC_CONFIG_DIR:-/config}"
CONFIG_FILE="${CONFIG_DIR}/config.json"

# Never allow the daemon's binary self-replace inside a container image.
export HERMITSTASH_AUTO_UPDATE=false

# Default the file watcher to polling mode in containers. Bind-mounted
# /data on Docker Desktop (Windows / macOS hosts via gRPC-FUSE /
# VirtioFS) and on NFS / SMB / FUSE mounts does not propagate kernel
# inotify events into the container — fs.watch goes silent and
# host-written files never trigger upload. Polling sidesteps the
# event-bridge entirely. Operators who know their bind-mount fires
# inotify (Linux host + native bind mount, no FS virtualization) can
# override with HERMITSTASH_WATCHER_MODE=fs in the container env.
export HERMITSTASH_WATCHER_MODE="${HERMITSTASH_WATCHER_MODE:-poll}"

if [ ! -f "${CONFIG_FILE}" ]; then
  if [ -z "${HERMITSTASH_ENROLLMENT_CODE:-}" ] || [ -z "${HERMITSTASH_SERVER_URL:-}" ]; then
    cat >&2 <<MSG
[entrypoint] hermitstash-sync is not configured yet.

First-time setup needs two env vars:
  HERMITSTASH_SERVER_URL      e.g. https://hermitstash.example.com
  HERMITSTASH_ENROLLMENT_CODE e.g. HSTASH-XXXX-XXXX-XXXX

Example:
  docker run -d \\
    -e HERMITSTASH_SERVER_URL=https://hermitstash.example.com \\
    -e HERMITSTASH_ENROLLMENT_CODE=HSTASH-XXXX-XXXX-XXXX \\
    -v hermitstash-sync-config:${CONFIG_DIR} \\
    -v /path/on/host:/data \\
    ghcr.io/dotcoocoo/hermitstash-sync:latest

Once enrolled, ${CONFIG_DIR} persists the API key and mTLS certs so this
step only runs once per installation.
MSG
    exit 1
  fi
  echo "[entrypoint] Running first-time enrollment against ${HERMITSTASH_SERVER_URL}"
  hermitstash-sync init --non-interactive
fi

exec hermitstash-sync "$@"
