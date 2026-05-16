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

// Field-type metadata — drives our local Prometheus renderer so counters
// emit `# TYPE … counter` and gauges emit `# TYPE … gauge`. b.metrics.
// snapshot.render flattens everything to `gauge` (it has no field-type
// hint to consult); operators scraping the snapshot for `rate()` queries
// need the counter distinction. Open upstream feature-request to accept
// a fieldTypes map on the snapshot writer; until then we render locally.
const FIELD_TYPES = {
  sync_state:           'info',     // string-valued — skipped by Prom render
  circuit_state_upload: 'info',     // string-valued — skipped by Prom render
  startedAt:            'info',     // ISO string  — skipped by Prom render
  uptimeSec:            'gauge',
  file_count:           'gauge',
  active_ops:           'gauge',
  last_seq:             'gauge',
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

// Render a snapshot's flat fields as Prometheus 0.0.4 text exposition,
// emitting `# TYPE … counter` for counter-shaped fields and
// `# TYPE … gauge` for gauge-shaped fields per the FIELD_TYPES map.
// Replacement for `b.metrics.snapshot.render(snap, { format: 'prometheus' })`,
// which always emits `gauge` regardless of source-type — that breaks
// `rate()` queries on counters in operator dashboards.
function renderPrometheus(snap, opts) {
  opts = opts || {};
  if (!snap || typeof snap !== 'object' || !snap.fields) return '';
  var prefix = opts.prefix || 'hermitstash_sync';
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(prefix)) return '';
  var out = [];
  var keys = Object.keys(snap.fields).sort(); // allow:bare-canonicalize-walk — stable Prometheus output ordering, not canonicalize-for-hashing
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = snap.fields[k];
    if (typeof v !== 'number' || !isFinite(v)) continue;
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(k)) continue;
    var type = FIELD_TYPES[k] === 'counter' ? 'counter' : 'gauge';
    var metric = prefix + '_' + k;
    out.push('# TYPE ' + metric + ' ' + type);
    out.push(metric + ' ' + v);
  }
  return out.join('\n') + '\n';
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
