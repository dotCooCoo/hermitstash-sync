'use strict';

const path = require('node:path');
const os = require('node:os');

const VERSION = '0.4.3';
const LICENSE = 'AGPL-3.0-or-later';

const CONFIG_DIR = path.join(os.homedir(), '.hermitstash-sync');
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

  // Client → Server
  ACK: 'ack',
  PING: 'ping',
  CATCH_UP: 'catch_up',
  BATCH_SYNC_REQUEST: 'batch_sync_request',
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
};
