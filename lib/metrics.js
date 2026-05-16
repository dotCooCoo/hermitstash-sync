'use strict';

// In-process telemetry for the running daemon. Wraps `b.metrics.create` so
// every counter / gauge / histogram lives on a single Prometheus-shaped
// registry, and routes the periodic disk snapshot through
// `b.metrics.snapshot.startWriter` so `hermitstash-sync stats` (running in
// a separate process) can read it via `b.metrics.snapshot.read` without an
// IPC or HTTP listener.
//
// Two surfaces:
//   - record.*(): hot-path taps wired into sync-engine, ws-client, updater.
//   - snapshotFields(): callback consumed by b.metrics.snapshot.startWriter.
//     Returns a flat object — sync state, file count, active ops, last
//     seq, circuit state, plus counter shadows. `b.metrics.snapshot.render`
//     emits Prometheus for the numeric subset directly.

const b = require('../vendor/blamejs');
const { STATS_FILE, STATS_WRITE_INTERVAL_MS } = require('./constants');

const C = b.constants;

let _registry = null;
let _counters = null;
let _gauges = null;
let _stopWriter = null;
let _startedAt = 0;

// Shadow values for string-typed state fields the framework's Prometheus
// gauge model doesn't carry natively (sync_state, circuit_state_*). Also
// mirrors numeric gauges + counters so snapshotFields() can produce a
// flat object without parsing exposition text.
const _shadow = {
  sync_state: 'DISCONNECTED',
  file_count: 0,
  active_ops: 0,
  last_seq: 0,
  circuit_state_upload: 'closed',
  uploads_ok: 0,
  uploads_error: 0,
  upload_retries: 0,
  circuit_opens_upload: 0,
  downloads_ok: 0,
  downloads_error: 0,
  ws_reconnects: 0,
  ws_auth_errors: 0,
};

// Counter overrides for b.metrics.snapshot.render's prometheus mode.
// Upstream v0.9.47+ auto-detects `_total`-suffixed fields as counters
// and everything else as gauges; our field names predate that
// convention (uploads_ok / ws_reconnects / etc. without the suffix),
// so we explicitly opt the 8 counter-shaped fields into the counter
// type. Gauges + string-valued state (sync_state / circuit_state_upload)
// fall through to the auto-default (gauge for numerics, skipped for
// non-numerics).
const FIELD_TYPES = {
  uploads_ok:           'counter',
  uploads_error:        'counter',
  upload_retries:       'counter',
  circuit_opens_upload: 'counter',
  downloads_ok:         'counter',
  downloads_error:      'counter',
  ws_reconnects:        'counter',
  ws_auth_errors:       'counter',
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

  // Numeric gauges only — string-valued state lives in _shadow.
  _gauges = {
    fileCount: _registry.gauge('files_total', { help: 'Files tracked in state DB' }),
    activeOps: _registry.gauge('active_ops', { help: 'Active upload + download operations' }),
    lastSeq:   _registry.gauge('last_seq',   { help: 'Last applied server sequence number' }),
  };

  return _registry;
}

const record = {
  upload(ok) {
    if (!_counters) return;
    _counters.uploads.inc({ outcome: ok ? 'ok' : 'error' });
    if (ok) _shadow.uploads_ok += 1; else _shadow.uploads_error += 1;
  },
  uploadAttempt() {
    if (!_counters) return;
    _counters.uploadRetries.inc();
    _shadow.upload_retries += 1;
  },
  download(ok) {
    if (!_counters) return;
    _counters.downloads.inc({ outcome: ok ? 'ok' : 'error' });
    if (ok) _shadow.downloads_ok += 1; else _shadow.downloads_error += 1;
  },
  reconnect() {
    if (!_counters) return;
    _counters.wsReconnects.inc();
    _shadow.ws_reconnects += 1;
  },
  authError() {
    if (!_counters) return;
    _counters.wsAuthErrors.inc();
    _shadow.ws_auth_errors += 1;
  },
  circuitOpen(target) {
    if (!_counters) return;
    _counters.circuitOpens.inc({ target: target || 'upload' });
    _shadow.circuit_opens_upload += 1;
  },
};

function setSyncState(state) {
  _shadow.sync_state = state;
}
function setFileCount(n) {
  _shadow.file_count = n;
  if (_gauges) _gauges.fileCount.set(n);
}
function setActiveOps(n) {
  _shadow.active_ops = n;
  if (_gauges) _gauges.activeOps.set(n);
}
function setLastSeq(n) {
  _shadow.last_seq = n;
  if (_gauges) _gauges.lastSeq.set(n);
}
function setCircuitState(target, state) {
  if (target === 'upload') _shadow.circuit_state_upload = state;
}

// Snapshot callback consumed by b.metrics.snapshot.startWriter. Returns a
// flat object — b.metrics.snapshot wraps it in { writtenAt, fields } and
// writes atomically. cmdStats reads via b.metrics.snapshot.read and uses
// either its own grouped text rendering or b.metrics.snapshot.render's
// Prometheus exposition for --prometheus.
function snapshotFields() {
  return Object.assign({
    startedAt: _startedAt ? new Date(_startedAt).toISOString() : null,
    uptimeSec: _startedAt ? Math.floor((Date.now() - _startedAt) / C.TIME.seconds(1)) : 0,
  }, _shadow);
}

// Prometheus exposition of the live registry — gauges/counters with
// labels intact, used by anything that wants the full label surface
// instead of the flat snapshot file.
function exposition() {
  if (!_registry) return '';
  return _registry.exposition();
}

// Render a snapshot's flat fields as Prometheus 0.0.4 text exposition.
// Thin wrapper around `b.metrics.snapshot.render` (v0.9.47+) that
// pre-fills the `fieldTypes` override map so our 8 counter-shaped
// fields render with `# TYPE … counter` instead of the default gauge.
// Was a hand-rolled 25-line shim before v0.9.47 added the opt; now
// upstream owns the render and we just provide the type hints.
function renderPrometheus(snap, opts) {
  opts = opts || {};
  return b.metrics.snapshot.render(snap, {
    format:     'prometheus',
    prefix:     opts.prefix || 'hermitstash_sync',
    fieldTypes: FIELD_TYPES,
  });
}

function startWriter() {
  if (_stopWriter) return _stopWriter;
  _stopWriter = b.metrics.snapshot.startWriter({
    path:       STATS_FILE,
    intervalMs: STATS_WRITE_INTERVAL_MS,
    fields:     snapshotFields,
  });
  return _stopWriter;
}

function stopWriter() {
  if (_stopWriter) {
    try { _stopWriter(); } catch (_e) {} // allow:silent-catch — stop is idempotent + final-flushes; a double-stop on shutdown is fine
    _stopWriter = null;
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
  snapshotFields,
  exposition,
  renderPrometheus,
  FIELD_TYPES,
  startWriter,
  stopWriter,
};
