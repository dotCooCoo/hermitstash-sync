#!/usr/bin/env bash
# docker-smoke.sh — shared packaging checks for the hermitstash-sync image.
#
# Used by:
#   .github/workflows/docker-e2e.yml      (against a fresh local build)
#   .github/workflows/docker-publish.yml  (against the just-published image,
#                                          referenced by digest for immutability)
#
# Runs only checks that don't need a real HermitStash server: OCI label
# presence, non-root user, declared volumes, env defaults, the status command
# as invokable, the entrypoint error path when enrollment env is missing, and
# that the binary gets far enough to hit the enrollment step against an
# unreachable stub URL. Full sync e2e is in tests/test-docker-e2e.js locally.
#
# Usage:
#   bash scripts/docker-smoke.sh <image-ref>
# Examples:
#   bash scripts/docker-smoke.sh hermitstash-sync-e2e:ci
#   bash scripts/docker-smoke.sh ghcr.io/dotcoocoo/hermitstash-sync@sha256:...

set -euo pipefail

IMAGE="${1:?usage: docker-smoke.sh <image-ref>}"

log()  { printf '[smoke] %s\n' "$*"; }
fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

log "Image under test: ${IMAGE}"

# ── OCI labels ──────────────────────────────────────────────────────────
log "Checking OCI labels"
INSPECT=$(docker inspect "$IMAGE")
for label in title description version source licenses vendor; do
  if ! echo "$INSPECT" | grep -q "\"org.opencontainers.image.${label}\""; then
    fail "missing OCI label: ${label}"
  fi
done
# podman-auto-update label — sync-client-specific requirement
if ! echo "$INSPECT" | grep -q '"io.containers.autoupdate"'; then
  fail "missing io.containers.autoupdate label (podman auto-update)"
fi

# ── Non-root user + volumes ─────────────────────────────────────────────
log "Checking user + volumes"
USER_FIELD=$(docker inspect -f '{{.Config.User}}' "$IMAGE")
if [ "$USER_FIELD" != "hermit" ]; then
  fail "expected User=hermit, got ${USER_FIELD}"
fi
VOLS=$(docker inspect -f '{{range $k,$v := .Config.Volumes}}{{$k}} {{end}}' "$IMAGE")
for v in /config /data; do
  case " $VOLS " in *" $v "*) : ;; *) fail "missing volume: $v" ;; esac
done

# ── Env defaults ────────────────────────────────────────────────────────
log "Checking env defaults"
ENV_DUMP=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE")
echo "$ENV_DUMP" | grep -q '^HERMITSTASH_SYNC_CONFIG_DIR=/config$' || fail "missing HERMITSTASH_SYNC_CONFIG_DIR=/config"
echo "$ENV_DUMP" | grep -q '^HERMITSTASH_SYNC_FOLDER=/data$'      || fail "missing HERMITSTASH_SYNC_FOLDER=/data"
echo "$ENV_DUMP" | grep -q '^HERMITSTASH_AUTO_UPDATE=false$'      || fail "missing HERMITSTASH_AUTO_UPDATE=false"

# ── Entrypoint error path (missing enrollment env) ──────────────────────
log "Checking entrypoint error path (missing env)"
set +e
OUT=$(docker run --rm "$IMAGE" 2>&1)
CODE=$?
set -e
if [ "$CODE" -eq 0 ]; then
  echo "$OUT"
  fail "expected nonzero exit when enrollment env missing, got 0"
fi
echo "$OUT" | grep -q "not configured yet" || { echo "$OUT"; fail "missing 'not configured yet' message"; }

# ── Binary reaches enrollment step ──────────────────────────────────────
log "Checking binary reaches enrollment step"
set +e
OUT=$(timeout 30 docker run --rm \
  -e HERMITSTASH_SERVER_URL=https://127.0.0.1:9/ \
  -e HERMITSTASH_ENROLLMENT_CODE=HSTASH-TEST-TEST-TEST \
  "$IMAGE" 2>&1)
CODE=$?
set -e
if [ "$CODE" -eq 0 ]; then
  echo "$OUT"
  fail "expected nonzero exit on unreachable server"
fi
if ! echo "$OUT" | grep -qE "(\[init\] Enrolling with https://127\.0\.0\.1:9/|Running first-time enrollment)"; then
  echo "$OUT"
  fail "entrypoint didn't reach init step — binary likely broken"
fi

# ── status command ──────────────────────────────────────────────────────
log "Checking status command"
set +e
OUT=$(docker run --rm --entrypoint /usr/local/bin/hermitstash-sync "$IMAGE" status 2>&1)
set -e
echo "$OUT" | grep -qE "Status: (STOPPED|RUNNING)" || { echo "$OUT"; fail "status command output unexpected"; }

# ── version command ─────────────────────────────────────────────────────
log "Checking version command"
set +e
OUT=$(docker run --rm --entrypoint /usr/local/bin/hermitstash-sync "$IMAGE" version 2>&1)
set -e
echo "$OUT" | grep -qE "hermitstash-sync v[0-9]+\.[0-9]+\.[0-9]+" || { echo "$OUT"; fail "version command output unexpected"; }

log "All packaging checks passed for ${IMAGE}"
