'use strict';

const nodePath = require('node:path');
const nodeOs = require('node:os');
const b = require('../vendor/blamejs');

const C = b.constants;

const VERSION = '1.0.13';
const LICENSE = 'AGPL-3.0-or-later';

// AUTOUPDATE_PUBKEY_PEM is re-exported from ./autoupdate-pubkey for
// in-tree callers (lib/updater.js) so they keep importing it via
// require('./constants') unchanged. The pubkey itself lives in a tiny
// node:-builtins-only module so scripts/verify-release.js can require it from
// contexts that don't ship vendor/blamejs (Docker verify stage,
// install.sh, update.sh).
const { AUTOUPDATE_PUBKEY_PEM } = require('./autoupdate-pubkey');

// CONFIG_DIR holds all persistent state: config.json, state.db, credentials,
// PID/log files, mTLS certs, update-pending marker. Override with
// HERMITSTASH_SYNC_CONFIG_DIR when running in a container or other environment
// where $HOME isn't a good default (e.g., Docker uses /config).
const CONFIG_DIR = b.safeEnv.readVar('HERMITSTASH_SYNC_CONFIG_DIR', { type: 'string', default: '' })
  || nodePath.join(nodeOs.homedir(), '.hermitstash-sync');
const CONFIG_FILE = nodePath.join(CONFIG_DIR, 'config.json');
const STATE_DB_FILE = nodePath.join(CONFIG_DIR, 'state.db');
const PID_FILE = nodePath.join(CONFIG_DIR, 'hermitstash-sync.pid');
const LOG_FILE = nodePath.join(CONFIG_DIR, 'hermitstash-sync.log');
const CREDENTIALS_FILE = nodePath.join(CONFIG_DIR, 'credentials');
// Periodic metrics snapshot the running daemon writes for `hermitstash-sync
// stats`. JSON object with counters/gauges + a writtenAt timestamp so the
// stats command can flag a stale file.
const STATS_FILE = nodePath.join(CONFIG_DIR, 'stats.json');
// Sidecar Prometheus 0.0.4 exposition the daemon writes alongside stats.json.
// Carries full histogram bucket counts (P50/P95/P99 territory) which the
// flat snapshot can't represent. `stats --prometheus` reads it directly.
const STATS_PROM_FILE = nodePath.join(CONFIG_DIR, 'stats.prom');
// Stable identifier for THIS installation, generated once and kept alongside the
// rest of the daemon's state. Sent on the sync WebSocket upgrade so the server
// can drop this client's own stale connection when it reconnects, instead of
// counting the not-yet-reaped socket against the per-key connection ceiling.
// Persisted rather than per-process so a restarted daemon still supersedes the
// connections its previous run left behind. It identifies, it does not
// authenticate — the API key and client certificate do that.
const INSTANCE_ID_FILE = nodePath.join(CONFIG_DIR, 'instance-id');

// WebSocket message types — must match server's lib/sync-emitter.js
const MSG = {
  // Server → Client
  FILE_ADDED: 'file_added',
  FILE_REPLACED: 'file_replaced',
  FILE_REMOVED: 'file_removed',
  FILE_RENAMED: 'file_renamed',
  HEARTBEAT: 'heartbeat',
  // CA rotation: server pushes when the mTLS CA is regenerated (admin
  // Danger Zone → Regenerate mTLS CA). Payload:
  //   { newCaPem: string, newCertPem: string, newKeyPem: string, restartInMs: number }
  // Client must atomically persist all three files, refresh its in-memory
  // TLS cache, and send CA_ROTATION_ACK before the server restarts.
  CA_ROTATION: 'ca:rotation',

  // Client → Server
  ACK: 'ack',
  PING: 'ping',
  CATCH_UP: 'catch_up',
  BATCH_SYNC_REQUEST: 'batch_sync_request',
  CA_ROTATION_ACK: 'ca:rotation-ack',
};

// File status in local state DB
const FILE_STATUS = {
  SYNCED: 'synced',
  PENDING_UPLOAD: 'pending_upload',
  PENDING_DOWNLOAD: 'pending_download',
  // A local delete whose server DELETE failed transiently. Distinct from ERROR
  // so the reconcile sweep re-drives the DELETE instead of the download
  // recovery resurrecting the file (ERROR conflates "re-download this" with
  // "the user deleted this"). `status` is a free-text column — no migration.
  PENDING_DELETE: 'pending_delete',
  UPLOADING: 'uploading',
  DOWNLOADING: 'downloading',
  CONFLICT: 'conflict',
  ERROR: 'error',
};

// Sync engine states
const SYNC_STATE = {
  DISCONNECTED: 'DISCONNECTED',
  CONNECTING: 'CONNECTING',
  CATCHING_UP: 'CATCHING_UP',
  SYNCED: 'SYNCED',
  UPLOADING: 'UPLOADING',
  DOWNLOADING: 'DOWNLOADING',
  ERROR: 'ERROR',
  RECONNECTING: 'RECONNECTING',
};

// PQC TLS configuration
const TLS_GROUPS = 'SecP384r1MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768:X25519';
const TLS_MIN_VERSION = 'TLSv1.3';

// Default ignore patterns (always applied)
const DEFAULT_IGNORES = [
  '.DS_Store',
  'Thumbs.db',
  'desktop.ini',
  '*.tmp',
  '*.swp',
  '*.swo',
  '*~',
  '.hermitstash-sync/**',
  '.git/**',
  '.svn/**',
  'node_modules/**',
  '__pycache__/**',
  '.Spotlight-V100/**',
  '.Trashes/**',
  'ehthumbs.db',
];

// Reconnection backoff (1s, 2s, 4s, 8s, 16s, 32s, 1m, 2m, 5m)
const RECONNECT_DELAYS = [
  C.TIME.seconds(1),
  C.TIME.seconds(2),
  C.TIME.seconds(4),
  C.TIME.seconds(8),
  C.TIME.seconds(16),
  C.TIME.seconds(32),
  C.TIME.minutes(1),
  C.TIME.minutes(2),
  C.TIME.minutes(5),
];

// File watcher debounce
const WATCHER_DEBOUNCE_MS = 500; // allow:raw-byte-literal — sub-second debounce, < TIME.seconds(1) granularity

// Heartbeat timeout — if no heartbeat in this many seconds, reconnect.
// Server sends heartbeat every 30s, so 90s = 3 missed heartbeats.
const HEARTBEAT_TIMEOUT_MS = C.TIME.seconds(90);

// Upload retry
const UPLOAD_MAX_RETRIES = 3;
const UPLOAD_RETRY_DELAY_MS = C.TIME.seconds(5);

// Upload pool concurrency. The HTTPS agent's maxSockets is the wire-
// level cap; this gates the JS-side promise queue so a bulk
// `cp -r 10000 files` doesn't materialize 10000 in-flight promises
// queueing for sockets. Operators override via config.uploadConcurrency
// (clamped 1..16 inside the engine).
const UPLOAD_DEFAULT_CONCURRENCY = 4;

// Upload circuit breaker. After UPLOAD_CB_FAILURES consecutive upload
// failures the breaker opens for UPLOAD_CB_COOLDOWN_MS — new uploads
// fast-fail with `retry/circuit-open` without dialling the server, then
// one probe is allowed. UPLOAD_CB_SUCCESSES probe successes close the
// breaker. Stops the daemon from hammering a flapping server while the
// b.retry.withRetry inner loop is otherwise happy to keep trying.
const UPLOAD_CB_FAILURES = 5;
const UPLOAD_CB_COOLDOWN_MS = C.TIME.seconds(30);
const UPLOAD_CB_SUCCESSES = 2;

// How often the daemon dumps its metrics + sync-state snapshot to
// STATS_FILE for `hermitstash-sync stats` to read.
const STATS_WRITE_INTERVAL_MS = C.TIME.seconds(15);

// Minimum free disk space before pausing downloads
const MIN_FREE_DISK_BYTES = C.BYTES.mib(100);

// Per-file ceiling for local checksum hashing. Sync-folder content is
// operator-owned local data, not untrusted network input, so the small
// DoS cap blamejs's hashFilesParallel defaults to (1 GiB) does not
// apply here — a legitimate 4 GiB archive must still hash and reconcile.
// Both the single-file (hashFile) and batch (hashFilesParallel) paths in
// lib/checksum.js read this constant so they can never disagree on which
// files are too large to sync. Operators raise it for archive-heavy
// folders via HERMITSTASH_MAX_FILE_BYTES; the default is large enough
// that no ordinary file trips it. A value <= 0 or unparsable falls back
// to the default.
const DEFAULT_MAX_SYNC_FILE_BYTES = C.BYTES.gib(256);
const MAX_SYNC_FILE_BYTES = (() => {
  // readVar with type:'number' rejects a unit-suffixed value ('256GB' → throw)
  // that the old parseInt silently truncated to 256 bytes, which would reject
  // essentially every real file. Number.isInteger also refuses float/Infinity.
  // A present-but-garbage value falls back to the default rather than crashing
  // module load.
  let raw;
  try { raw = b.safeEnv.readVar('HERMITSTASH_MAX_FILE_BYTES', { type: 'number', default: DEFAULT_MAX_SYNC_FILE_BYTES }); }
  catch { return DEFAULT_MAX_SYNC_FILE_BYTES; }
  return (Number.isInteger(raw) && raw > 0) ? raw : DEFAULT_MAX_SYNC_FILE_BYTES;
})();

// ---- Auto-update ----
// The daemon polls GitHub Releases every AUTOUPDATE_POLL_MS. When a newer
// version is found it downloads the binary, SHA3-512 checksum, and .sig,
// verifies both, then swaps itself out (SEA only — source installs log a
// notice). AUTOUPDATE_PUBKEY_PEM is the P-384 verify key embedded at build
// time; the corresponding private key lives in GitHub secret
// AUTOUPDATE_SIGNING_KEY (CI) and/or ~/.hermitstash-sync/autoupdate-signing.key
// (local release). If AUTOUPDATE_PUBKEY_PEM is null, auto-update is disabled
// and the daemon logs that verification is not possible.
const AUTOUPDATE_REPO = 'dotCooCoo/hermitstash-sync';
const AUTOUPDATE_POLL_MS = C.TIME.hours(6);
const AUTOUPDATE_PROBATION_MS = C.TIME.minutes(1); // roll back if crash within 1m
// AUTOUPDATE_PUBKEY_PEM is sourced above from ./autoupdate-pubkey.

// Single home for SEA (Single Executable Application) detection. Node inserts
// process.execPath at argv[1] in a SEA binary, so any code that builds a child
// argv or interprets its own argv must branch on this. Kept here (zero-dep,
// required by every module) so daemon/updater/CLI don't each grow their own
// copy that can drift.
function isSeaBinary() {
  try { return require('node:sea').isSea(); } catch { return false; }
}

module.exports = {
  VERSION,
  LICENSE,
  CONFIG_DIR,
  CONFIG_FILE,
  STATE_DB_FILE,
  PID_FILE,
  LOG_FILE,
  CREDENTIALS_FILE,
  STATS_FILE,
  STATS_PROM_FILE,
  INSTANCE_ID_FILE,
  MSG,
  FILE_STATUS,
  SYNC_STATE,
  TLS_GROUPS,
  TLS_MIN_VERSION,
  DEFAULT_IGNORES,
  RECONNECT_DELAYS,
  WATCHER_DEBOUNCE_MS,
  HEARTBEAT_TIMEOUT_MS,
  UPLOAD_MAX_RETRIES,
  UPLOAD_RETRY_DELAY_MS,
  UPLOAD_DEFAULT_CONCURRENCY,
  UPLOAD_CB_FAILURES,
  UPLOAD_CB_COOLDOWN_MS,
  UPLOAD_CB_SUCCESSES,
  STATS_WRITE_INTERVAL_MS,
  MIN_FREE_DISK_BYTES,
  MAX_SYNC_FILE_BYTES,
  AUTOUPDATE_REPO,
  AUTOUPDATE_POLL_MS,
  AUTOUPDATE_PROBATION_MS,
  AUTOUPDATE_PUBKEY_PEM,
  isSeaBinary,
};
