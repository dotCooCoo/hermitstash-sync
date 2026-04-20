# syntax=docker/dockerfile:1.7
#
# hermitstash-sync — Docker image
#
# Two-stage build. Stage 1 downloads the signed SEA binary from the matching
# GitHub Release and verifies it (SHA3-512 + P-384 ECDSA) before letting it
# enter the runtime image. Stage 2 is debian-slim with only ca-certificates,
# the verified binary, and a small entrypoint.
#
# Build:
#   docker buildx build --build-arg VERSION=0.4.7 \
#     --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/dotcoocoo/hermitstash-sync:0.4.7 .
#
# Runtime is non-root. /config holds persistent state (config.json, mTLS
# certs, state.db, logs). /data is the sync folder.

ARG VERSION
ARG NODE_VERSION=24.8.0-slim
# Runtime base: Chainguard wolfi-base — glibc-dynamic, apk-based, rebuilt
# continuously by Chainguard when upstream CVE fixes land. Typical CVE
# count at any given digest is near zero; chosen over debian-slim to avoid
# the unfixed systemd/ncurses/util-linux base-image noise flagged by Trivy.
ARG RUNTIME_BASE=cgr.dev/chainguard/wolfi-base:latest

# ---------- Stage 1: download + verify the signed binary ----------
FROM node:${NODE_VERSION} AS verify
ARG VERSION
ARG TARGETARCH
WORKDIR /build

# ca-certificates: needed for TLS verification when curl hits github.com.
# curl: pulls the signed binary + its checksum + its .sig.
# xxd: not needed; verification happens in Node.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the parts of the repo the verifier needs (and only those — smaller
# build context, clearer layer).
COPY lib/constants.js /build/lib/constants.js
COPY scripts/verify-release.js /build/scripts/verify-release.js

RUN set -eux; \
    if [ -z "${VERSION}" ]; then echo "VERSION build-arg is required" >&2; exit 1; fi; \
    case "${TARGETARCH}" in \
      amd64) ARCH=x64 ;; \
      arm64) ARCH=arm64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    BASE="https://github.com/dotCooCoo/hermitstash-sync/releases/download/v${VERSION}"; \
    NAME="hermitstash-sync-v${VERSION}-linux-${ARCH}"; \
    curl -fsSL --retry 3 -o /build/hermitstash-sync         "${BASE}/${NAME}"; \
    curl -fsSL --retry 3 -o /build/hermitstash-sync.sha3-512 "${BASE}/${NAME}.sha3-512"; \
    curl -fsSL --retry 3 -o /build/hermitstash-sync.sig     "${BASE}/${NAME}.sig"; \
    node /build/scripts/verify-release.js \
      /build/hermitstash-sync \
      /build/hermitstash-sync.sha3-512 \
      /build/hermitstash-sync.sig; \
    chmod 0755 /build/hermitstash-sync

# ---------- Stage 2: runtime ----------
FROM ${RUNTIME_BASE} AS runtime

ARG VERSION
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="hermitstash-sync" \
      org.opencontainers.image.description="Post-quantum encrypted file sync client for HermitStash" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/dotCooCoo/hermitstash-sync" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="dotCooCoo" \
      io.containers.autoupdate="registry"
# io.containers.autoupdate=registry lets `podman auto-update` pull the
# newest image digest for the currently-used tag on a schedule — the
# Podman equivalent of the systemd timer path in deploy/update.sh.

# Packages:
#   ca-certificates-bundle — TLS roots for outbound HTTPS to the server
#   tini                   — PID 1 signal forwarding + zombie reaping
#   bash                   — docker/entrypoint.sh uses `set -euo pipefail`
#   shadow                 — provides groupadd/useradd on wolfi (busybox
#                             ships addgroup/adduser with a different flag
#                             surface; easier to keep the Debian-style
#                             invocations consistent with install.sh)
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates-bundle tini bash shadow \
    && groupadd --system --gid 1000 hermit \
    && useradd  --system --uid 1000 --gid 1000 --home-dir /config --shell /sbin/nologin hermit \
    && mkdir -p /data /config \
    && chown hermit:hermit /data /config

COPY --from=verify /build/hermitstash-sync /usr/local/bin/hermitstash-sync
COPY docker/entrypoint.sh /usr/local/bin/hermitstash-sync-entrypoint
RUN chmod 0755 /usr/local/bin/hermitstash-sync /usr/local/bin/hermitstash-sync-entrypoint

ENV HERMITSTASH_SYNC_CONFIG_DIR=/config \
    HERMITSTASH_SYNC_FOLDER=/data \
    HERMITSTASH_AUTO_UPDATE=false

USER hermit
WORKDIR /data
VOLUME ["/config", "/data"]

# status exits 0 when the daemon's PID file resolves to a live process.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD hermitstash-sync status 2>&1 | grep -q "Status: RUNNING" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/hermitstash-sync-entrypoint"]
CMD ["start"]
