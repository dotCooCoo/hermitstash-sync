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
# Verify-stage base — DIGEST-PINNED for the same reason RUNTIME_BASE is. The
# stage-1 `verify` image both RUNS the SHA3-512 + ECDSA signature check and
# materializes the binary COPY'd into the runtime image, so a tag-republish of
# node:24.19.0-slim (Docker Official Images re-point version tags on base-OS
# rebuilds; a registry compromise is the same class the RUNTIME_BASE pin
# defends) could force the check to pass on any bytes or swap the binary after
# it — shipping a backdoored binary that is then cosign-signed + SLSA-attested.
# Pinning the toolchain base closes that half of the build. Refresh the digest
# deliberately on each Node bump (resolve via
#   docker buildx imagetools inspect node:24.19.0-slim
# and copy the index Digest), updating the trailing date, on the same cadence
# as RUNTIME_BASE and the GitHub Action pins.
ARG NODE_VERSION=24.19.0-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03  # node 24.19.0-slim 2026-08-07
# Runtime base: Chainguard wolfi-base — glibc-dynamic, apk-based, rebuilt
# continuously by Chainguard when upstream CVE fixes land. Typical CVE
# count at any given digest is near zero; chosen over debian-slim to avoid
# the unfixed systemd/ncurses/util-linux base-image noise flagged by Trivy.
#
# Pinned to an immutable manifest-list digest (not the floating :latest
# tag) so two builds of the same VERSION embed byte-identical base layers
# and a tag-republish / registry compromise cannot inject a poisoned base
# into a cosign-signed, SLSA-attested image. The digest is the multi-arch
# OCI index, so linux/amd64 and linux/arm64 still resolve from one pin.
#
# Tradeoff: a digest pin freezes the base at the layer current when the
# digest was captured, so it does NOT auto-pick-up newer Chainguard CVE
# rebuilds. Refresh the digest deliberately on each base bump (resolve via
#   docker buildx imagetools inspect cgr.dev/chainguard/wolfi-base:latest
# and copy the index Digest) on the same cadence as the GitHub Action pins,
# updating the trailing date comment. The release Trivy gate still blocks
# any fixable CRITICAL/HIGH that ages into a stale pin, so a forgotten
# refresh surfaces as a failed build rather than a silently-vulnerable
# image. RUNTIME_BASE stays a build-arg so a refresh is visible in the diff
# and an operator can override it for a local rebuild against a newer base.
ARG RUNTIME_BASE=cgr.dev/chainguard/wolfi-base@sha256:a31344ab2cb8618db84f535eec56f76f6178b142cb92cb2e48676cc2dcebea72  # wolfi-base 2026-08-22

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
# build context, clearer layer). The trio:
#   lib/autoupdate-pubkey.js     — zero-dep module carrying the P-384 pubkey
#   scripts/standalone-verifier.js — zero-dep verifier (b.selfUpdate.standaloneVerifier)
#   scripts/verify-release.js    — CLI shim that wires the above two together
# The full lib/constants.js depends transitively on vendor/blamejs which
# we don't ship into the verify stage.
COPY lib/autoupdate-pubkey.js       /build/lib/autoupdate-pubkey.js
COPY scripts/standalone-verifier.js /build/scripts/standalone-verifier.js
COPY scripts/verify-release.js      /build/scripts/verify-release.js

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
#   libstdc++              — Node.js SEA binary is dynamically linked
#                             against libstdc++.so.6 (V8's C++ runtime).
#                             Wolfi-base doesn't ship it by default; the
#                             Debian slim images we replaced happened to
#                             have it pulled in by apt's base set. Without
#                             it `hermitstash-sync` fails at load time with
#                             "cannot open shared object file".
#   libatomic              — same story on a different Node major: a binary
#                             built on Node 26 links libatomic.so.1, where a
#                             Node 24 build does not. A missing libatomic
#                             fails identically at load time, so the container
#                             never reaches the entrypoint. The Node that
#                             builds the binary is pinned exactly in
#                             .github/workflows/release.yml, so this should not
#                             move on its own; libatomic stays installed as
#                             insurance because the cost is a few KB and the
#                             failure mode is a container that cannot start.
#                             Re-check this list on any Node bump — the SEA's
#                             shared-library set is a property of the Node
#                             build, not of this project's code.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates-bundle tini bash shadow libstdc++ libatomic \
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

# `-e 143` remaps the SEA Node bug exit code to 0. Node 24 SEA binaries exit
# with signal-default code 143 (128 + SIGTERM) when process.exit(0) is called
# from inside a SIGTERM handler, even though the handler ran and the daemon
# completed a graceful shutdown. v0.8.15 → v0.8.19 bisected this to a SEA-
# specific quirk (plain `node:24-alpine` + tini honors process.exit(0)
# correctly; the SEA-packaged Node does not). lib/daemon.js still runs the
# real engine.stop + pidfile teardown — this just translates the OS-reported
# exit code to match the shutdown reality so `docker stop` reports 0 to
# orchestrators that gate on it.
ENTRYPOINT ["/usr/bin/tini", "-e", "143", "--", "/usr/local/bin/hermitstash-sync-entrypoint"]
CMD ["start"]
