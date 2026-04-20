'use strict';

const path = require('node:path');
const os = require('node:os');

const VERSION = '0.4.8';
const LICENSE = 'AGPL-3.0-or-later';

// CONFIG_DIR holds all persistent state: config.json, state.db, credentials,
// PID/log files, mTLS certs, update-pending marker. Override with
// HERMITSTASH_SYNC_CONFIG_DIR when running in a container or other environment
// where $HOME isn't a good default (e.g., Docker uses /config).
const CONFIG_DIR = process.env.HERMITSTASH_SYNC_CONFIG_DIR
  || path.join(os.homedir(), '.hermitstash-sync');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const STATE_DB_FILE = path.join(CONFIG_DIR, 'state.db');
const PID_FILE = path.join(CONFIG_DIR, 'hermitstash-sync.pid');
const LOG_FILE = path.join(CONFIG_DIR, 'hermitstash-sync.log');
const CREDENTIALS_FILE = path.join(CONFIG_DIR, 'credentials');

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
const TLS_GROUPS = 'SecP384r1MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768';
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

// Reconnection backoff
const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 16000, 32000, 60000, 120000, 300000];

// File watcher debounce
const WATCHER_DEBOUNCE_MS = 500;

// Heartbeat timeout — if no heartbeat in this many ms, reconnect
const HEARTBEAT_TIMEOUT_MS = 90000; // 90 seconds (server sends every 30s)

// Upload retry
const UPLOAD_MAX_RETRIES = 3;
const UPLOAD_RETRY_DELAY_MS = 5000;

// Minimum free disk space before pausing downloads
const MIN_FREE_DISK_BYTES = 100 * 1024 * 1024; // 100 MB

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
const AUTOUPDATE_POLL_MS = 6 * 60 * 60 * 1000; // 6 hours
const AUTOUPDATE_PROBATION_MS = 60 * 1000;     // roll back if crash within 60s
const AUTOUPDATE_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPv6OpIP57gy2rXXUc99SSN6PeA1IEHgA
MhqhMR12ZsMsEYut9841eSWmzdmt4ZzrIqqJjmPqJOmmqJcubl7hblwguKcZtHAL
WT3boCQiZjVskjAa9eJsJPT7pSLpKGgH
-----END PUBLIC KEY-----
`;

module.exports = {
  VERSION,
  LICENSE,
  CONFIG_DIR,
  CONFIG_FILE,
  STATE_DB_FILE,
  PID_FILE,
  LOG_FILE,
  CREDENTIALS_FILE,
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
  MIN_FREE_DISK_BYTES,
  AUTOUPDATE_REPO,
  AUTOUPDATE_POLL_MS,
  AUTOUPDATE_PROBATION_MS,
  AUTOUPDATE_PUBKEY_PEM,
};
