'use strict';

// In-process telemetry for the running daemon. Wraps `b.metrics.create` so
// every counter / gauge / histogram lives on a single Prometheus-shaped
// registry, and periodically dumps a snapshot to STATS_FILE so the
// `hermitstash-sync stats` CLI (running in a separate process) can read
// it without an IPC or HTTP listener.
//
// Two surfaces:
//   - record.*(): hot-path taps wired into sync-engine, ws-client, updater.
//   - snapshot(): returns a plain object suitable for JSON.stringify, used
//     both by the periodic writer and by `cmdStats` for the running daemon
//     itself (covers `hermitstash-sync stats` invoked inside the daemon
//     process, though in practice the CLI runs out-of-process and reads
//     STATS_FILE).

const b = require('../vendor/blamejs');
const { STATS_FILE, STATS_WRITE_INTERVAL_MS } = require('./constants');

const C = b.constants;

let _registry = null;
let _counters = null;
let _gauges = null;
let _writer = null;
let _startedAt = 0;

// Gauges that don't have a natural increment cadence — sync state, file
// counts, last-seq — are mirrored here so snapshot() can read them back
// without parsing Prometheus exposition. b.metrics gauges only expose
// .set/.inc/.dec; they don't surface a .value() reader.
const _gaugeShadow = {
  sync_state: 'DISCONNECTED',
  file_count: 0,
  active_ops: 0,
  last_seq: 0,
  circuit_state_upload: 'closed',
};

// Counter shadow — same reason. Prometheus exposition is the source of
// truth on the wire; the shadow is what `stats` displays as plain
// integers without rendering + re-parsing exposition text.
const _counterShadow = {
  uploads_ok: 0,
  uploads_error: 0,
  upload_retries: 0,
  circuit_opens_upload: 0,
  downloads_ok: 0,
  downloads_error: 0,
  ws_reconnects: 0,
  ws_auth_errors: 0,
};

function init() {
  if (_registry) return _registry;
  _startedAt = Date.now();
  _registry = b.metrics.create({
    namespace:     'hermitstash_sync',
    defaultLabels: {},
  });

  _counters = {
    uploads: _registry.counter('uploads_total', {
      help: 'File uploads by outcome', labelNames: ['outcome'],
    }),
    uploadRetries: _registry.counter('upload_retries_total', {
      help: 'Retry attempts inside b.retry.withRetry on the upload path',
    }),
    circuitOpens: _registry.counter('circuit_opens_total', {
      help: 'Circuit breaker open events', labelNames: ['target'],
    }),
    downloads: _registry.counter('downloads_total', {
      help: 'File downloads by outcome', labelNames: ['outcome'],
    }),
    wsReconnects: _registry.counter('ws_reconnects_total', {
      help: 'WebSocket reconnect attempts',
    }),
    wsAuthErrors: _registry.counter('ws_auth_errors_total', {
      help: 'WebSocket handshake auth failures (401/403)',
    }),
  };

  // String-valued gauges (sync state, circuit state) aren't a natural fit
  // for Prometheus — they live in _gaugeShadow only. Numeric gauges get
  // real registry entries so `b.metrics.exposition()` exports them.
  _gauges = {
    fileCount: _registry.gauge('files_total', { help: 'Files tracked in state DB' }),
    activeOps: _registry.gauge('active_ops', { help: 'Active upload + download operations' }),
    lastSeq: _registry.gauge('last_seq', { help: 'Last applied server sequence number' }),
  };

  return _registry;
}

const record = {
  upload(ok) {
    if (!_counters) return;
    _counters.uploads.inc({ outcome: ok ? 'ok' : 'error' });
    if (ok) _counterShadow.uploads_ok += 1; else _counterShadow.uploads_error += 1;
  },
  uploadAttempt() {
    if (!_counters) return;
    _counters.uploadRetries.inc();
    _counterShadow.upload_retries += 1;
  },
  download(ok) {
    if (!_counters) return;
    _counters.downloads.inc({ outcome: ok ? 'ok' : 'error' });
    if (ok) _counterShadow.downloads_ok += 1; else _counterShadow.downloads_error += 1;
  },
  reconnect() {
    if (!_counters) return;
    _counters.wsReconnects.inc();
    _counterShadow.ws_reconnects += 1;
  },
  authError() {
    if (!_counters) return;
    _counters.wsAuthErrors.inc();
    _counterShadow.ws_auth_errors += 1;
  },
  circuitOpen(target) {
    if (!_counters) return;
    _counters.circuitOpens.inc({ target: target || 'upload' });
    _counterShadow.circuit_opens_upload += 1;
  },
};

function setSyncState(state) {
  _gaugeShadow.sync_state = state;
}
function setFileCount(n) {
  _gaugeShadow.file_count = n;
  if (_gauges) _gauges.fileCount.set(n);
}
function setActiveOps(n) {
  _gaugeShadow.active_ops = n;
  if (_gauges) _gauges.activeOps.set(n);
}
function setLastSeq(n) {
  _gaugeShadow.last_seq = n;
  if (_gauges) _gauges.lastSeq.set(n);
}
function setCircuitState(target, state) {
  if (target === 'upload') _gaugeShadow.circuit_state_upload = state;
}

function snapshot() {
  return {
    writtenAt: new Date().toISOString(),
    startedAt: _startedAt ? new Date(_startedAt).toISOString() : null,
    uptimeSec: _startedAt ? Math.floor((Date.now() - _startedAt) / C.TIME.seconds(1)) : 0,
    gauges: Object.assign({}, _gaugeShadow),
    counters: Object.assign({}, _counterShadow),
  };
}

// Render Prometheus exposition for callers that want to scrape the
// registry directly (e.g. piping into a textfile collector). The
// `stats` CLI uses snapshot() for display, not this.
function exposition() {
  if (!_registry) return '';
  return _registry.exposition();
}

function writeSnapshot() {
  try {
    const body = JSON.stringify(snapshot(), null, 2);
    b.atomicFile.writeSync(STATS_FILE, body, { mode: 0o600 });
  } catch (_e) {
    // Best-effort — telemetry must never crash the daemon.
  }
}

// Start the periodic snapshot writer. Returns a stop handle from
// b.safeAsync.repeating so the daemon shutdown orchestrator can halt it
// before tearing down the engine.
function startWriter() {
  if (_writer) return _writer;
  _writer = b.safeAsync.repeating(writeSnapshot, STATS_WRITE_INTERVAL_MS, {
    onError: () => { /* best-effort */ },
  });
  return _writer;
}

function stopWriter() {
  if (_writer) {
    try { _writer.stop(); } catch (_e) {} // allow:silent-catch — repeater stop is idempotent; a double-stop on shutdown is fine
    _writer = null;
  }
}

module.exports = {
  init,
  record,
  setSyncState,
  setFileCount,
  setActiveOps,
  setLastSeq,
  setCircuitState,
  snapshot,
  exposition,
  writeSnapshot,
  startWriter,
  stopWriter,
};
