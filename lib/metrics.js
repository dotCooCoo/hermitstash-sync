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
const { STATS_FILE, STATS_PROM_FILE, STATS_WRITE_INTERVAL_MS } = require('./constants');

const C = b.constants;

let _registry = null;
let _counters = null;
let _gauges = null;
let _histograms = null;
let _stopWriter = null;
let _startedAt = 0;

// Standard Prometheus-style latency buckets in seconds. The bottom
// half captures fast control-plane operations; the upper half captures
// large-file streaming uploads / downloads that run for many seconds
// on a slow link. Endpoints that exceed 10s are still counted in the
// +Inf bucket — the histogram's `_sum` + `_count` produce an accurate
// average regardless.
const LATENCY_BUCKETS_SECONDS = Object.freeze([
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
]);

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
  conflicts: 0,
  upload_pool_inflight: 0,
  upload_pool_queue: 0,
  upload_duration_sum_sec: 0,
  upload_duration_count: 0,
  download_duration_sum_sec: 0,
  download_duration_count: 0,
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
  conflicts:            'counter',
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
    conflicts: _registry.counter('conflicts_total', {
      help: 'Local files renamed to conflict copies before server-side overwrite',
    }),
  };

  // Numeric gauges only — string-valued state lives in _shadow.
  _gauges = {
    fileCount: _registry.gauge('files_total', { help: 'Files tracked in state DB' }),
    activeOps: _registry.gauge('active_ops', { help: 'Active upload + download operations' }),
    lastSeq:   _registry.gauge('last_seq',   { help: 'Last applied server sequence number' }),
  };

  // Latency histograms feed `histogram_quantile()` in Prometheus for
  // P50/P95/P99. The flat snapshot file (used by `stats` text mode)
  // doesn't carry buckets — operators wanting tail latency reach for
  // the `--prometheus` exposition. The `_sum` + `_count` shadow into
  // the snapshot so average upload/download duration is still visible
  // in the text output.
  _histograms = {
    uploadDuration:   _registry.histogram('upload_duration_seconds', {
      help: 'End-to-end upload duration (includes multipart write + server response). Excludes time spent waiting in the upload pool / circuit breaker.',
      buckets: LATENCY_BUCKETS_SECONDS,
    }),
    downloadDuration: _registry.histogram('download_duration_seconds', {
      help: 'End-to-end download duration (includes streamed body + SHA3-512 verify + atomic rename).',
      buckets: LATENCY_BUCKETS_SECONDS,
    }),
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
  conflict() {
    if (!_counters) return;
    _counters.conflicts.inc();
    _shadow.conflicts += 1;
  },
  uploadDuration(seconds) {
    if (!_histograms || typeof seconds !== 'number' || !isFinite(seconds) || seconds < 0) return;
    _histograms.uploadDuration.observe(seconds);
    _shadow.upload_duration_sum_sec += seconds;
    _shadow.upload_duration_count   += 1;
  },
  downloadDuration(seconds) {
    if (!_histograms || typeof seconds !== 'number' || !isFinite(seconds) || seconds < 0) return;
    _histograms.downloadDuration.observe(seconds);
    _shadow.download_duration_sum_sec += seconds;
    _shadow.download_duration_count   += 1;
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
function setUploadPool(inflight, queueDepth) {
  _shadow.upload_pool_inflight = inflight;
  _shadow.upload_pool_queue = queueDepth;
}

// Push-pull bridge for live-changing values the engine owns. The
// snapshot writer pulls a fresh sample each interval — cheaper than
// having the engine fire setUploadPool on every dispatch.
let _poolStatsProvider = null;
function registerPoolStatsProvider(fn) {
  _poolStatsProvider = (typeof fn === 'function') ? fn : null;
}

// Snapshot callback consumed by b.metrics.snapshot.startWriter. Returns a
// flat object — b.metrics.snapshot wraps it in { writtenAt, fields } and
// writes atomically. cmdStats reads via b.metrics.snapshot.read and uses
// either its own grouped text rendering or b.metrics.snapshot.render's
// Prometheus exposition for --prometheus.
function snapshotFields() {
  if (_poolStatsProvider) {
    try {
      const sample = _poolStatsProvider();
      if (sample) {
        if (typeof sample.inflight === 'number') _shadow.upload_pool_inflight = sample.inflight;
        if (typeof sample.queueDepth === 'number') _shadow.upload_pool_queue = sample.queueDepth;
      }
    } catch { /* allow:silent-catch — best-effort provider tap; never abort the snapshot */ }
  }
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
// Thin wrapper around `b.metrics.snapshot.render` that pre-fills the
// `fieldTypes` override map so the 8 counter-shaped fields render
// with `# TYPE … counter` instead of the default `gauge` (which
// `b.metrics.snapshot.render` infers from the `_total` suffix, which
// our field names predate).
function renderPrometheus(snap, opts) {
  opts = opts || {};
  return b.metrics.snapshot.render(snap, {
    format:     'prometheus',
    prefix:     opts.prefix || 'hermitstash_sync',
    fieldTypes: FIELD_TYPES,
  });
}

function _flushPromSidecar() {
  if (!_registry) return;
  try {
    b.atomicFile.writeSync(STATS_PROM_FILE, _registry.exposition(), { fileMode: 0o600 });
  } catch (_e) { /* allow:silent-catch — best-effort sidecar; snapshot.json is the source of truth for the human-readable surface */ }
}

function startWriter() {
  if (_stopWriter) return _stopWriter;
  const stopSnapshot = b.metrics.snapshot.startWriter({
    path:       STATS_FILE,
    intervalMs: STATS_WRITE_INTERVAL_MS,
    fields:     snapshotFields,
  });

  // Sidecar Prometheus exposition with histogram buckets. The flat
  // snapshot can't represent histograms (KV only), so `stats
  // --prometheus` falls back to the sidecar when it exists. Written
  // best-effort at the same cadence as the snapshot. Atomic write via
  // temp + rename so a concurrent scrape never sees a torn file.
  const promTimer = setInterval(_flushPromSidecar, STATS_WRITE_INTERVAL_MS);
  promTimer.unref();

  _stopWriter = () => {
    try { stopSnapshot(); } catch (_e) { /* allow:silent-catch — idempotent */ }
    try { clearInterval(promTimer); } catch (_e) { /* allow:silent-catch — idempotent */ }
    // Final flush of the prom sidecar so the historical snapshot has
    // matching latency buckets at shutdown.
    _flushPromSidecar();
  };
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
  setUploadPool,
  registerPoolStatsProvider,
  snapshotFields,
  exposition,
  renderPrometheus,
  FIELD_TYPES,
  startWriter,
  stopWriter,
};
