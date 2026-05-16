<p align="center">
  <img src="public/img/logos/green.svg" alt="HermitStash Sync" width="120" />
</p>

<h1 align="center">HermitStash Sync</h1>

<p align="center">
  Desktop file sync client for <a href="https://github.com/dotCooCoo/hermitstash">HermitStash</a> — post-quantum encrypted, self-hosted file sync.
</p>

<p align="center">
  <a href="LICENSE">AGPL-3.0</a> · <a href="SECURITY.md">Security Policy</a> · <a href="https://ko-fi.com/dotcoocoo">Support on Ko-fi</a>
</p>

---

### A quick note

HermitStash Sync is the companion to [HermitStash](https://github.com/dotCooCoo/hermitstash) — same author, same philosophy, same caveats. If you haven't read the note at the top of the main repo, the short version is: this is a personal project, built by someone who is not a cryptographer, and it hasn't been audited.

This client inherits its security posture from HermitStash and from Node.js's OpenSSL 3.5 — I'm not rolling my own TLS or inventing key exchanges. But a sync client introduces its own surface area (file watching, state tracking, daemon lifecycle), and those parts are entirely my own work. I've tried to be careful, but "tried to be careful" is not a substitute for a professional review.

If you're already running HermitStash and you want your files to show up on the other end without dragging them there yourself — this is for that. If you're evaluating it for something where reliability and security truly matter, please factor in that it's one person, spare time, and zero formal review.

— .CooCoo ([@dotCooCoo](https://github.com/dotCooCoo))

> **Status:** Personal project · Not audited · API may change · Use at your own risk

---

## Built on [blamejs](https://github.com/blamejs/blamejs)

<p align="center">
  <a href="https://github.com/blamejs/blamejs">
    <img src="https://raw.githubusercontent.com/blamejs/blamejs/main/assets/BlameJS_Logo.svg" alt="blamejs" width="120" />
  </a>
</p>

<p align="center">
  <strong><em>The Node framework that owns its stack.</em></strong>
</p>

HermitStash Sync vendors [**blamejs**](https://github.com/blamejs/blamejs) — a single, audit-able framework that bundles its own crypto, transports, validation, and process-lifecycle primitives instead of pulling them from forty transitive npm packages. That's how this client ships with **zero npm runtime dependencies** while still getting:

- **PQC TLS 1.3 agent** (`b.pqcAgent`) — `SecP384r1MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768` posture pinned for both the mTLS sync transport and the auto-update GitHub-release downloader
- **Hardened HTTP client** (`b.httpClient.request`) — SSRF gate with DNS pinning that closes the resolve-vs-connect TOCTOU window, AbortSignal, idle-vs-wall-clock timeout split, permanent-vs-transient classifier, h2 via ALPN
- **Hardened WebSocket client** (`b.wsClient`) — RFC 6455 with decompression-bomb defence, UTF-8 fatal validation, ≤125-byte control-frame cap, RSV1-on-continuation rejection, permanent-error classifier
- **Per-session encryption envelope** (`b.middleware.apiEncrypt` / `b.httpClient.encrypted`) — ML-KEM-1024 + ECDH P-384 + SHAKE256 + XChaCha20-Poly1305, identity-agile 4-byte version header
- **Daemon lifecycle** (`b.daemon`, `b.appShutdown.pidLock`) — atomic-create pidfile, SIGTERM→SIGKILL escalation, phase-ordered graceful shutdown
- **Cross-platform file watcher** (`b.watcher`) — fs.watch + event coalescing + symlink-skip + debounce on real kernels, polling fallback for bind mounts and FUSE filesystems
- **Self-update lifecycle** (`b.selfUpdate.{poll,verify,swap,rollback}`) — semver-aware GitHub Releases poll, ECDSA P-384 detached-signature verify, atomic backup-and-rename swap with rollback
- **Validation primitives** (`b.safeJson`, `b.safeUrl`, `b.atomicFile`, `b.retry`, `b.safeAsync.repeating`) — depth/size/prototype caps, atomic-rename + fsync, full-jitter exponential backoff, error-swallowing recurring timers
- **Vendored ML-KEM-1024 + XChaCha20-Poly1305** via blamejs's own pinned `noble-post-quantum` / `noble-ciphers` cjs bundles

The client sits as a thin specialization on top — sync engine, file watcher integration, state DB, and CLI surface — while the wire layer, crypto layer, and process layer are blamejs's responsibility. Every refresh of `vendor/blamejs/` carries upstream security backports across all of those primitives at once.

If you're building something else and find yourself reaching for this same set of primitives, give blamejs a look: <https://github.com/blamejs/blamejs>.

---

## What it does

Watches a local folder and keeps it in sync with a HermitStash server:

- **New files** are uploaded automatically
- **Modified files** are re-uploaded (server detects and replaces)
- **Renamed/moved files** are detected by checksum matching — server updates the path without re-uploading the file
- **Deleted files** are removed from the server
- **Server-side changes** are downloaded in real-time via WebSocket
- **Conflict resolution** is last-write-wins — if both sides change a file, the most recent write takes priority

All connections use PQC TLS with TLS 1.3 minimum and a three-tier hybrid group list (`SecP384r1MLKEM1024` → `X25519MLKEM768` → `SecP256r1MLKEM768`, Level 5 preferred) plus optional mTLS client certificates. Client certs auto-renew on startup when within 60 days of expiry — no admin action needed.

## Requirements

- Node.js 24.14.1+ (vendored blamejs's effective floor; also covers `node:sqlite` and OpenSSL 3.5+ PQC support)
- HermitStash server v1.9.19+ with sync features enabled. v1.9.19 ships blamejs v0.8.43+ which emits 0xE2-magic envelopes; this client (on blamejs v0.9.54) requires that posture. Servers below v1.9.19 still on the 0xE1 envelope are not compatible.

## Install

```bash
# From source
git clone https://github.com/dotCooCoo/hermitstash-sync.git
cd hermitstash-sync

# Or use pre-built binary (no Node.js required)
# Download from Releases for your platform

# Or run in Docker (see below)
docker pull ghcr.io/dotcoocoo/hermitstash-sync:latest
```

## Docker

The image pulls the signed SEA binary from the matching GitHub Release during build, verifies its SHA3-512 checksum and P-384 ECDSA signature before installing, and runs non-root with a minimal Debian-slim base. Two volumes: `/config` holds persistent state (API key, mTLS certs, state DB, logs), `/data` is the sync folder.

```bash
# First run — enrolls and starts syncing
docker run -d \
  --name hermitstash-sync \
  -e HERMITSTASH_SERVER_URL=https://hermitstash.example.com \
  -e HERMITSTASH_ENROLLMENT_CODE=HSTASH-XXXX-XXXX-XXXX \
  -v hermitstash-sync-config:/config \
  -v /path/on/host:/data \
  --restart unless-stopped \
  ghcr.io/dotcoocoo/hermitstash-sync:latest
```

Subsequent restarts skip enrollment — the API key and mTLS certs persist on the `hermitstash-sync-config` volume. A Compose file is available at `docker-compose.example.yml`.

Auto-update is always disabled inside the container (binary self-replace would violate the immutable-image model — pull a new image tag to upgrade). All other features (mTLS cert auto-renewal, PQC TLS, SHA3-512 checksums, sync bundle semantics) work identically to the native binary.

**Testing:** PRs touching `Dockerfile`, `docker/`, or `scripts/verify-release.js` trigger `.github/workflows/docker-e2e.yml`, which builds the image against the latest published release and runs packaging checks (OCI labels, non-root user, volumes, env defaults, entrypoint error paths). Full container-to-server e2e (enrollment, bidirectional sync, restart persistence, graceful shutdown) runs locally via `node tests/run-all.js` when Docker is available on the dev machine.

## Other deployment platforms

In addition to the Docker image, the repo ships reference configs for running the daemon natively or on common orchestration platforms. Each is self-contained and shows the sync-client-specific shape: outbound-only, two volumes (`/config` + `/data`), enrollment via env vars on first run.

| Platform | File | Notes |
| --- | --- | --- |
| **Unraid** | `unraid-template.xml` | Community Apps template. Point the template URL at `https://raw.githubusercontent.com/dotCooCoo/hermitstash-sync/main/unraid-template.xml` to install. |
| **systemd (native Linux)** | `deploy/install.sh` + `deploy/hermitstash-sync.service` | `curl | sudo bash` one-liner: downloads the signed SEA binary, verifies SHA3-512 + P-384 ECDSA, installs under `/usr/local/bin/hermitstash-sync`, creates a `hermit` system user, and lays down a hardened systemd unit. Pair with `deploy/update.sh` + timer for unattended updates. Uninstall via `deploy/uninstall.sh`. |
| **Podman** | `deploy/podman.sh` | Rootless by default (RHEL/Fedora/Alma/Rocky idiomatic). Also generates a user or system systemd unit for auto-restart. Image carries the `io.containers.autoupdate=registry` label so `podman-auto-update.timer` can refresh it. |
| **Kubernetes** | `deploy/kubernetes.yml` | Namespace + 2 PVCs + Deployment (replicas=1, strategy=Recreate) + Secret for enrollment. No Service — the client is outbound-only. `runAsNonRoot`, `readOnlyRootFilesystem`, dropped capabilities. |

For fleet deployment, use `deploy/install.sh` inside Ansible / SaltStack / your config-management tool of choice — it's idempotent and respects the standard `VERSION`, `INSTALL_DIR`, `CONFIG_DIR`, `SYNC_DIR`, `SERVICE_USER` env overrides.

### Update mechanisms

Each deployment shape has its own update path. The in-binary self-replace only runs when the daemon has write access to its own executable — otherwise an external updater handles it.

| Deployment | Update path | Enabled by default |
| --- | --- | --- |
| **Bare binary** (no systemd) | In-daemon: polls GitHub every 6h, verifies SHA3-512 + ECDSA, renames current → `.prev`, spawns new, 60s probation + auto-rollback on crash. | Yes — config `"autoUpdate": true` |
| **systemd** (via `install.sh`) | External: `hermitstash-sync-update.timer` fires daily + 4h random delay; `update.sh` downloads + verifies + atomic swap + `systemctl restart`, rolls back if the daemon doesn't report RUNNING within 60s. In-daemon path is disabled (can't cross the root/hermit permission boundary under `ProtectSystem=strict`). | Opt-in — install with `HERMITSTASH_AUTO_UPDATE=yes` to enable the timer |
| **Docker** | Pull a new image tag manually (`docker pull ... && docker restart ...`). In-daemon self-replace is hard-disabled — mutating `/usr/local/bin` inside a running image violates the immutable-image model. | No |
| **Podman** | `podman auto-update` reads the image's `io.containers.autoupdate=registry` label and pulls the newest digest for the current tag. Enable `podman-auto-update.timer` (system or `--user`) to run on a schedule. | Opt-in via timer |
| **Kubernetes** | Bump the image tag in your manifest and `kubectl apply`. `imagePullPolicy: IfNotPresent` means you need to delete the pod or roll the Deployment to pick up a floating tag. Consider a pinned digest + a GitOps flow for production. | No |

## Quick start

```bash
# 1. Set up the connection
hermitstash-sync init

# 2. Start syncing (foreground)
hermitstash-sync start

# 3. Or run as a background daemon
hermitstash-sync start --daemon

# 4. Check status
hermitstash-sync status

# 5. Stop the daemon
hermitstash-sync stop
```

## Commands

| Command | Description |
| --- | --- |
| `init` | Interactive setup — enrollment code or API key, server URL, sync folder |
| `init --non-interactive` | Headless enrollment from env vars (`HERMITSTASH_SERVER_URL`, `HERMITSTASH_ENROLLMENT_CODE`, `HERMITSTASH_SYNC_FOLDER`, `HERMITSTASH_AUTO_UPDATE`) — intended for Docker/CI |
| `start` | Start sync in foreground |
| `start --daemon` | Start sync as background daemon |
| `start --no-autoupdate` | Start without polling GitHub Releases for new binaries |
| `status` | Show sync status, file count, last sync time, errors |
| `stats` | Print daemon telemetry — uploads/downloads/retries, WS reconnects, upload circuit-breaker state. Reads `$CONFIG_DIR/stats.json` (refreshed every 15s by the daemon). `--json` for machine-readable output, `--prometheus` for textfile-collector exposition. |
| `stop` | Stop the background daemon |
| `log` | Show last 50 log lines |
| `log --follow`, `-f` | Tail the log file in real-time |
| `resync` | Force a full re-sync from scratch |
| `repair` | Re-provision mTLS certificate using an admin-issued enrollment code (run this if your cert is revoked or the daemon can't connect after a certificate reissue) |
| `version` | Show version and OpenSSL info |
| `--help`, `-h` | Show usage information |

## Configuration

Config file: `~/.hermitstash-sync/config.json` (or `$HERMITSTASH_SYNC_CONFIG_DIR/config.json` — useful for containers, where `/config` is a common mount point).

```json
{
  "server": "https://hermitstash.com",
  "bundleId": "your-sync-bundle-id",
  "shareId": "your-share-id",
  "syncFolder": "/home/user/Documents/synced",
  "mtls": {
    "cert": "/path/to/client.crt",
    "key": "/path/to/client.key",
    "ca": "/path/to/ca.crt"
  },
  "ignore": ["*.log", "build/**"],
  "logLevel": "info",
  "autoUpdate": true
}
```

### Ignore patterns

The following patterns are always excluded from sync:

| Pattern | Reason |
| --- | --- |
| `.DS_Store`, `.Spotlight-V100/**`, `.Trashes/**` | macOS system files |
| `Thumbs.db`, `ehthumbs.db`, `desktop.ini` | Windows system files |
| `.git/**`, `.svn/**` | Version control |
| `node_modules/**`, `__pycache__/**` | Package/build artifacts |
| `*.tmp`, `*.swp`, `*.swo`, `*~` | Editor temp files |
| `.hermitstash-sync/**` | Client config directory |

Add custom patterns in:

- `config.json` → `ignore` array
- `.hermitstash-ignore` file in the sync folder root (one pattern per line, `#` comments supported)

Supported pattern syntax: exact filename (`file.txt`), extension (`*.log`), and directory recursion (`build/**`).

### API key storage

The API key is stored in your OS keychain:

- **macOS:** Keychain Access
- **Linux:** GNOME Keyring / KDE Wallet (via `secret-tool`)
- **Windows:** Windows Credential Manager

Falls back to `~/.hermitstash-sync/credentials` (permissions `0600`) on headless systems.

### Auto-update

Binary (SEA) installs poll GitHub Releases every 6 hours. When a newer version exists, the daemon downloads the binary for its platform and verifies a P-384 ECDSA signature (DER) over the binary bytes against a public key embedded at build time. Only after the signature verifies does it copy the current binary to `.prev`, atomically rename the new one in place, and spawn itself. If the new binary crashes within 60 seconds of first start, the next launch restores `.prev`.

The verify path runs through `b.selfUpdate.verify` (auto-detects the algorithm from the embedded public key) and the swap runs through `b.selfUpdate.swap` (atomic rename with cross-device fallback and rollback on failure). Releases v0.6.13 and earlier signed the SHA3-512 digest with raw `ieee-p1363` encoding; v0.6.14 → v0.7.6 signed the binary directly with the curve-default SHA-384 + DER. **v0.7.7+ signs with SHA3-512 + DER** to match `b.selfUpdate.standaloneVerifier`'s hardcoded hash so the install-side (`deploy/install.sh`, Dockerfile verify stage) and the daemon-side auto-update path share one signature shape end-to-end. Existing v0.6.x and v0.7.0 → v0.7.6 binaries cannot auto-update across the v0.7.7 boundary — the signature-hash mismatch will be reported as a verification failure and the install refused. **Manually reinstall v0.7.7+ once** to bridge the gap (re-run `deploy/install.sh`, `docker pull`, or download the new binary from the GitHub Release page).

Source installs (running from `git clone`) do not self-replace — the daemon logs a notice when a new version is out and expects you to `git pull` yourself.

Disable per-invocation with `start --no-autoupdate`, or globally by setting `"autoUpdate": false` in `config.json`.

The signing key is held only by the release pipeline; the daemon cannot install a binary signed by anything else. If no pubkey is embedded in this build, auto-update is disabled and logged at startup.

### Windows SmartScreen on first launch

Windows binaries are not Authenticode-signed. The first time you run `hermitstash-sync.exe`, Windows Defender SmartScreen may show a "Windows protected your PC" dialog and require you to click **More info → Run anyway**. This is a reputation-based warning for unsigned executables; it goes away as more users download and run the same binary.

If you want to verify authenticity before running:

```bash
# SHA3-512 checksum
sha3sum -a 512 -c hermitstash-sync-vX.Y.Z-win-x64.exe.sha3-512

# GPG signature (import the public key once, then verify)
gpg --import gpg-public-key.asc
gpg --verify hermitstash-sync-vX.Y.Z-win-x64.exe.asc hermitstash-sync-vX.Y.Z-win-x64.exe
```

Both files are attached to every release. The GPG key fingerprint and the ECDSA auto-update pubkey are both baked into the binary itself, so once the first release is trusted, subsequent auto-updates verify against those keys without any further ceremony.

## How sync works

1. On startup, if an mTLS client certificate is configured and within 60 days of expiring, the daemon silently calls `POST /sync/renew-cert` to rotate it using the current API key. No admin action needed unless the cert has already been revoked (use `repair` for that).
2. On first connection with a `shareId` configured, the client fetches the bundle manifest and downloads all existing files from the server, then uploads any local files not yet on the server. Existing local files are verified against server checksums using parallel SHA3-512 hashing across the worker thread pool.
3. After initial sync, the client enters a real-time loop: a WebSocket receives change events (`file_added`, `file_replaced`, `file_removed`, `file_renamed`) and a file watcher detects local changes. Changes are debounced (500 ms) to avoid redundant uploads during active writes. All checksum computations are dispatched to the worker pool to keep the main thread responsive.
4. If the connection drops, the client reconnects with exponential backoff (1s, 2s, 4s, 8s, 16s, 32s, 60s, 120s, 300s). On reconnect, it sends the last known sequence number so the server can replay missed events.
5. The server sends a heartbeat every 30 seconds. If no message arrives within 90 seconds, the client treats the connection as dead and reconnects.
6. Failed uploads are retried up to 3 times with full-jitter exponential backoff (base 5s). After 5 consecutive uploads exhaust their retries, a per-target circuit breaker opens for 30 seconds and new uploads fast-fail without dialling the server. The breaker probes after the cooldown; 2 consecutive successful probes close it. This keeps the daemon from hammering a flapping server while the retry loop would otherwise happily keep firing.
7. `hermitstash-sync stats` reads a JSON snapshot the daemon writes every 15 seconds (`$CONFIG_DIR/stats.json`) — uploads/downloads (ok/error/retries), WebSocket reconnects, upload circuit-breaker state, and last applied sequence number. Use `--json` for machine-readable output or `--prometheus` for textfile-collector-friendly exposition.

### Sync states

The `status` command shows which state the daemon is in:

| State | Meaning |
| --- | --- |
| `DISCONNECTED` | Not connected to server |
| `CONNECTING` | Establishing WebSocket connection |
| `CATCHING_UP` | Downloading changes missed while offline |
| `SYNCED` | Fully synchronized, watching for changes |
| `UPLOADING` | Actively uploading files |
| `DOWNLOADING` | Actively downloading files |
| `RECONNECTING` | Connection lost, waiting to retry |
| `ERROR` | Something went wrong (check logs) |

## Security

- **PQC TLS** on every connection — three-tier hybrid group list `SecP384r1MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768` (NIST Level 5 preferred, Level 3 and Level 1 fallback for broad server compatibility). Both `ecdhCurve` and `groups` are set so Node negotiates the hybrid group even on older OpenSSL builds.
- **TLS 1.3 minimum** — connections below TLS 1.3 are rejected
- **mTLS** client certificates for server authentication (optional, certs cached in memory). Certificates auto-renew on startup when within 60 days of expiry — no admin intervention required.
- **Per-session PQC envelope** on encryption-grade JSON POSTs (`/drop/init`, `/drop/finalize/:bundleId`, `/sync/rename`) — ML-KEM-1024 + ECDH P-384 + SHAKE256 + XChaCha20-Poly1305, server keypair fetched once from `/.well-known/blamejs-pubkey` and cached. Strict-monotonic counter on the wire blocks replay. Other Bearer-authed sync calls send plain JSON over the PQC TLS + mTLS layer — transport encryption is the floor; no Bearer-authed sync call ever sends plaintext on the wire.
- **SHA3-512** checksums verified before file rename — mismatched downloads never appear in sync folder
- **Path traversal protection** — all server-provided paths validated against sync folder boundary
- **Symlink protection** — symlinks skipped during directory walk and file watching (prevents escape)
- **API key** in OS keychain, never in plaintext config or log files
- **Atomic writes** — downloads write to `.tmp` file, verify checksum, then rename
- **Stale temp cleanup** — orphaned `.tmp` files from interrupted downloads removed on startup
- **Download suppression** — files written by the sync engine don't trigger re-upload
- **Disk space guard** — downloads pause if free space drops below 100 MB
- **PID file locking** — exclusive create prevents two daemon instances from racing
- **State DB integrity** — SQLite integrity check on startup with auto-recovery on corruption
- **Filename sanitization** — multipart upload headers strip injection characters
- **Response body limiting** — error responses capped at 64 KB to prevent memory exhaustion
- **HTTP timeouts** — all requests time out after 30 seconds to prevent hangs
- **Log rotation** — log file rotated at 10 MB to prevent disk exhaustion
- **Log symlink protection** — log path checked for symlinks before opening
- **Worker thread pool** — SHA3-512 checksums computed in parallel across CPU cores, keeping the main thread responsive to WebSocket heartbeats during bulk sync
- **Hardened wire layer via blamejs primitives** — the WebSocket client (`b.wsClient`) inherits decompression-bomb defence, UTF-8 fatal validation on text + close-reason, control-frame ≤125-byte cap with FIN=1 enforcement, RSV1-on-continuation rejection, permanent-vs-transient error classifier (no auth-failure hammering); the HTTP client (`b.httpClient.request`) adds an SSRF gate with DNS pinning that closes the resolve-vs-connect TOCTOU window on the configured server, AbortSignal cancellation, and an idle vs wall-clock timeout split; the auto-update GitHub-release fetcher inherits the same posture with the SSRF gate left fully closed in production so a hijacked release index can't pivot the download to an internal target
- **safeJson on every untrusted parse** — server response bodies, the user-edited `config.json`, and the enrollment response all run through `b.safeJson.parse`'s depth + size + prototype-pollution caps, so a malformed or hostile JSON document can't mutate `Object.prototype` or exhaust the heap
- **Atomic config + cert writes** — `config.json` and the enrolled mTLS client/cert/key/CA trio are written via `b.atomicFile.writeSync` (temp file, fsync, rename, parent-dir fsync) so a crash mid-write leaves the previous good copy intact instead of a torn file
- **Phase-ordered graceful shutdown** — SIGTERM/SIGINT routes through `b.appShutdown` with per-phase time budgets and idempotent semantics, so a double signal during drain doesn't kick off a parallel teardown
- **Crypto-strength retry jitter** — upload retries use `b.retry.withRetry`'s full-jitter exponential backoff sourced from `crypto.randomInt`, so retry timing isn't predictable from `Math.random`
- **Boot-time wall-clock gate** — `hermitstash-sync start` runs an SNTPv4 drift check (`b.ntpCheck.bootCheck`) against `pool.ntp.org` before opening the engine. The cert-renewal threshold and the auto-update probation window both depend on `Date.now()` being roughly correct; a laptop resuming from a long sleep, a container without an RTC, or a system whose NTP daemon died can drift far enough to mis-renew certs or false-clear probation. Default thresholds: warn at 5 min, fatal at 1 hr. Unreachable NTP is non-fatal so offline boots still work. Override with `HERMITSTASH_NTP_DISABLE=1` (skip) or `HERMITSTASH_NTP_STRICT=1` (refuse to boot if unreachable).
- **CSAF 2.1 VEX disclosures on releases** — when transitive CVEs surface in the vendored runtime that don't reach a vulnerable code path here, an OASIS CSAF 2.1 VEX document (`hermitstash-sync-vX.Y.Z.vex.json`) is published alongside the binaries. CSAF-aware scanners (e.g. `trivy --vex`, `grype --vex`) can consume it to suppress alerts on declared `known_not_affected` findings with a justification. Generated via `b.vex` from the assessments committed at `vex/statements.json`.
- **Zero npm dependencies** — entire codebase is auditable

## Logging

Logs are written to `~/.hermitstash-sync/hermitstash-sync.log` in JSON format — one object per line with `ts`, `level`, and `msg` fields.

Log levels: `debug`, `info`, `warn`, `error`.

The log file is rotated at 10 MB. The current log is renamed to `.log.1` and a fresh file is started. Only one rotated copy is kept.

## Platform notes

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Keychain | Keychain Access | GNOME Keyring / KDE Wallet | Credential Manager |
| Daemon | `start --daemon` | `start --daemon` | `start --daemon` |
| Resync signal | `SIGHUP` | `SIGHUP` | Not supported — restart daemon |
| Auto-start | launchd | systemd | Task Scheduler |

## Auto-start (optional)

### Linux (systemd)

```ini
# ~/.config/systemd/user/hermitstash-sync.service
[Unit]
Description=HermitStash Sync
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hermitstash-sync start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable hermitstash-sync
systemctl --user start hermitstash-sync
```

### macOS (launchd)

```xml
<!-- ~/Library/LaunchAgents/com.hermitstash.sync.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.hermitstash.sync</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/hermitstash-sync</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

## File structure

```
bin/hermitstash-sync.js       CLI entry point
lib/cli.js                    Command parser and dispatcher
lib/config.js                 Config file management
lib/constants.js              All constants, message types, defaults
lib/checksum.js               SHA3-512 hashing (single + worker pool)
lib/daemon.js                 Daemonization, PID file, signal handlers
lib/http-client.js            HTTP client with PQC agent + blamejs apiEncrypt for write paths
lib/keychain.js               OS keychain for API key storage
lib/logger.js                 Structured JSON logger with rotation
lib/state-db.js               Local SQLite state database (node:sqlite)
lib/sync-engine.js            Core sync loop orchestrator
lib/watcher.js                fs.watch with debounce and ignore patterns
lib/worker-pool.js            Generic worker thread pool
lib/workers/checksum-worker.js  SHA3-512 hashing worker thread
lib/ws-client.js              Minimal WebSocket client with PQC TLS
```

## Deployment

### Platform: Node.js SEA (Single Executable Application)

The sync client ships as a standalone binary — no Node.js installation required on the target machine.

| | |
|---|---|
| **Runtime** | Node.js SEA binary (Node.js + app bundled into a single executable) |
| **Build** | GitHub Actions on tag push (`v*`) — automated via `.github/workflows/release.yml` |
| **Platforms** | Windows x64, Linux x64, Linux ARM64, macOS ARM64 (Intel Macs: use the ARM64 binary under Rosetta 2) |
| **Artifacts** | `hermitstash-sync-vX.Y.Z-{win,linux,macos}-{x64,arm64}[.exe]` + SHA3-512 checksum + GPG signature, per platform |
| **Signing** | GPG (P-384) for humans + P-384 ECDSA (DER) over the binary bytes for the auto-update channel (verified via `b.selfUpdate.verify`). No Authenticode — see Windows note below. |
| **TLS** | PQC hybrid: `SecP384r1MLKEM1024 > X25519MLKEM768 > SecP256r1MLKEM768` (Level 5 preferred) |
| **Dependencies** | Zero npm runtime packages — all vendored |

### Release workflow

```
git tag vX.Y.Z && git push origin vX.Y.Z
```

GitHub Actions automatically:
1. Builds the SEA binary for Windows x64, Linux x64, Linux ARM64, and macOS ARM64
2. Generates a SHA3-512 checksum per binary (matches the server's hash algorithm)
3. Scans the Windows binary with Windows Defender (updated definitions)
4. GPG-signs each binary + checksum (`secrets.GPG_PRIVATE_KEY`)
5. Creates a GitHub Release attaching every platform's binary, checksum, and signature

Download the latest release from the [Releases page](https://github.com/dotCooCoo/hermitstash-sync/releases).

### Building locally

```bash
# Requires Node.js 24.14.1+ and postject
node --experimental-sea-config build/sea-config.json
cp $(which node) build/hermitstash-sync
npx postject build/hermitstash-sync NODE_SEA_BLOB build/hermitstash-sync.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
```

Or use the local release script: `bash scripts/release.sh` (builds + signs + optional VirusTotal scan).

## Contributing

I want to be straightforward about this: I'm not currently accepting code contributions, and I want to explain why rather than just saying no.

HermitStash Sync is a security-focused project maintained by one person. Reviewing external code contributions to a cryptographic system is something I don't feel I can do responsibly right now — I'm still learning, and I'd rather not merge code I can't fully evaluate myself. Accepting PRs would mean either rubber-stamping changes I don't understand (bad) or asking contributors to wait indefinitely while I figure it out (also bad). The honest answer is that I'm not set up for it yet.

That said, there are a lot of ways to help that I genuinely welcome:

- **Bug reports.** If something doesn't work, or works in a way that surprises you, please open an issue. Steps to reproduce help a lot.
- **Security findings.** If you spot a cryptographic issue, a misuse of a primitive, or anything that contradicts a security claim in the README, please report it privately — see [SECURITY.md](SECURITY.md) for how.
- **Feature requests.** Open an issue describing the use case. I can't promise I'll build it, but I want to hear what people would find useful.
- **Documentation feedback.** If something in the README is unclear, wrong, or missing, an issue is great. Documentation issues are some of the most useful kinds of feedback I get.
- **Questions.** If you're trying to use HermitStash Sync and something isn't clear, asking is welcome.

If you've built something on top of HermitStash, or you're running it somewhere interesting, I'd love to hear about that too — feel free to open an issue just to say hi.

This may change in the future. If HermitStash Sync grows to a point where I can responsibly review external code, I'll update this section. Until then: thank you for understanding, and thank you for being interested enough to consider contributing in the first place.

## License

[AGPL-3.0-or-later](LICENSE)

---

### A final note

If you've read this far — thank you. Building and sharing HermitStash has been one of the most rewarding things I've worked on, and the fact that you took the time to look at it means a lot.

If HermitStash has been useful to you and you'd like to buy me a coffee, you can do so at [ko-fi.com/dotcoocoo](https://ko-fi.com/dotcoocoo). It's never expected, always appreciated.
