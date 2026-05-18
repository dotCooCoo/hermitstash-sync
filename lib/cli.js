'use strict';

// codebase-patterns:allow-file console-direct — CLI surface; operator-visible stdout/stderr is the literal output contract of every command. The structured logger ships through ./logger separately for daemon-mode file logs.
// codebase-patterns:allow-file process-exit — CLI commands return through process.exit(code) to surface sysexits-style status to shells and orchestrators.
// codebase-patterns:allow-file inline-require — interactive commands cold-load heavy modules (state-db, vendor/blamejs) only on demand so `hermitstash-sync help` / `version` stay fast and don't open the SQLite handle.
// codebase-patterns:allow-file raw-process-env — env-driven entry points read documented HERMITSTASH_* names by hand; the values are the user contract of Docker/systemd entrypoints, not internal toggles.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeReadline = require('node:readline');
const b = require('../vendor/blamejs');
const { VERSION, LOG_FILE, CONFIG_DIR, CONFIG_FILE, STATS_FILE } = require('./constants');
const config = require('./config');
const keychain = require('./keychain');
const daemon = require('./daemon');
const log = require('./logger');
const metrics = require('./metrics');
const SyncEngine = require('./sync-engine');
const updater = require('./updater');

const C = b.constants;

// Print an error and exit 1. Used in command entry points where there's no
// cleanup to perform — inside try/catch blocks that own resources (readline,
// PID file, engine) the handler stays explicit so ordering is clear.
function die(msg) {
  console.error(msg);
  process.exit(1);
}

async function run(args) {
  const command = args[0] || 'help';

  switch (command) {
    case 'init':     return cmdInit(args);
    case 'start':    return cmdStart(args);
    case 'status':   return cmdStatus();
    case 'stats':    return cmdStats(args);
    case 'stop':     return cmdStop();
    case 'log':      return cmdLog(args);
    case 'resync':   return cmdResync();
    case 'repair':   return cmdRepair();
    case 'diagnose': return cmdDiagnose(args);
    case 'version':  return cmdVersion();
    case 'help':
    case '--help':
    case '-h':       return cmdHelp();
    default:
      console.error(`Unknown command: ${command}`);
      cmdHelp();
      process.exit(1);
  }
}

// --- Shared enrollment helpers ---

/**
 * POST /sync/enroll to exchange an enrollment code for an API key + mTLS
 * certs. Returns the server response data. Throws on non-200 or bad JSON.
 */
async function exchangeEnrollmentCode(serverUrl, code) {
  const nodeHttps = require('node:https');

  // Local error class so 4xx/5xx surface as `err.statusCode` instead of
  // requiring a string-parse of the FrameworkError message.
  const EnrollHttpError = b.frameworkError.defineClass('EnrollHttpError', { withStatusCode: true });

  const parsedUrl = b.safeUrl.parse(serverUrl, { allow: b.safeUrl.ALLOW_HTTP_ALL });
  const enrollUrl = `${parsedUrl.protocol}//${parsedUrl.host}/sync/enroll`;
  const body = b.safeJson.stringify({ code: code.trim().toUpperCase() });
  const responseCap = C.BYTES.kib(256);

  let resp;
  try {
    resp = await b.httpClient.request({
      url: enrollUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: Buffer.from(body, 'utf8'),
      // Self-signed certs are common on first enrollment — accept them at
      // this stage; the server-issued client cert + CA pin take over for
      // every subsequent request.
      agent: new nodeHttps.Agent({ rejectUnauthorized: false }),
      // User-supplied URL may be a same-network HermitStash instance.
      allowInternal: true,
      timeoutMs: C.TIME.seconds(15),
      maxResponseBytes: responseCap,
      errorClass: EnrollHttpError,
    });
  } catch (err) {
    if (err instanceof EnrollHttpError && err.statusCode) {
      const headerPrefix = 'HTTP ' + err.statusCode + ': ';
      const errBody = err.message.startsWith(headerPrefix) ? err.message.slice(headerPrefix.length) : '';
      const parsed = b.safeJson.parseOrDefault(errBody, null, { maxBytes: responseCap });
      const errMsg = (parsed && parsed.error) || `Server returned status ${err.statusCode}`;
      throw new Error(errMsg);
    }
    throw err;
  }

  let data;
  try {
    data = b.safeJson.parse(
      Buffer.isBuffer(resp.body) ? resp.body.toString('utf8') : String(resp.body || ''),
      { maxBytes: responseCap },
    );
  } catch (_e) {
    throw new Error('Invalid response from server');
  }

  if (resp.statusCode !== 200 || !data.success) {
    throw new Error(data.error || `Server returned status ${resp.statusCode}`);
  }
  return data;
}

/**
 * Write mTLS certs to CONFIG_DIR/certs and return their paths, or null if
 * no certs were provided.
 */
function saveMtlsCerts(enrollData) {
  if (!enrollData.clientCert || !enrollData.clientKey || !enrollData.caCert) return null;
  const certsDir = nodePath.join(CONFIG_DIR, 'certs');
  nodeFs.mkdirSync(certsDir, { recursive: true });
  const cert = nodePath.join(certsDir, 'client.crt');
  const key = nodePath.join(certsDir, 'client.key');
  const ca = nodePath.join(certsDir, 'ca.crt');
  // b.atomicFile.writeSync: write-temp + fsync + rename + parent-dir-fsync.
  // A crash mid-enrollment leaves either the previous trio intact OR the
  // complete new trio — never a torn key paired with the old cert (which
  // would silently fail TLS handshake on the next start).
  // Ensure each PEM ends with a newline so operators bundling extra
  // trust anchors via `cat extra.pem >> ca.crt` get a parseable result
  // — without the trailing newline, the appended cert begins on the
  // same line as `-----END CERTIFICATE-----` and OpenSSL / Node TLS
  // reject the whole bundle.
  const ensureNewline = pem => (pem && !pem.endsWith('\n')) ? pem + '\n' : pem;
  b.atomicFile.writeSync(cert, ensureNewline(enrollData.clientCert), { mode: 0o644 });
  b.atomicFile.writeSync(key,  ensureNewline(enrollData.clientKey),  { mode: 0o600 });
  b.atomicFile.writeSync(ca,   ensureNewline(enrollData.caCert),     { mode: 0o644 });
  return { cert, key, ca };
}

/**
 * Persist config and API key to disk. Returns the saved config object.
 * Throws with a combined message if validation fails.
 */
async function saveSyncConfig({ server, bundleId, shareId, syncFolder, apiKey, mtls, autoUpdate }) {
  const resolvedFolder = nodePath.resolve(syncFolder);
  if (!nodeFs.existsSync(resolvedFolder)) {
    nodeFs.mkdirSync(resolvedFolder, { recursive: true });
  }
  const storage = await keychain.store(apiKey);
  const cfg = {
    server,
    bundleId: bundleId || '',
    shareId: shareId || '',
    syncFolder: resolvedFolder,
    apiKeyRef: storage === 'keychain' ? 'keychain:hermitstash-sync' : 'file',
    mtls: mtls || null,
    ignore: [],
    logLevel: 'info',
  };
  if (autoUpdate === false) cfg.autoUpdate = false;
  const errors = config.validate(cfg);
  if (errors.length > 0) {
    throw new Error('Configuration errors:\n  - ' + errors.join('\n  - '));
  }
  config.save(cfg);
  return { cfg, storage, resolvedFolder };
}

// --- Commands ---

async function cmdInit(args = []) {
  const nonInteractive = args.includes('--non-interactive') || args.includes('--ni');
  if (nonInteractive) return cmdInitFromEnv();

  console.log('HermitStash Sync — Setup\n');

  const rl = nodeReadline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(resolve => rl.question(q, resolve));

  try {
    const server = await ask('Server URL (e.g. https://hermitstash.com): ');
    const syncFolder = await ask('Local folder to sync: ');
    const authMethod = await ask('Setup method — (1) Enrollment code or (2) Manual API key? [1]: ');

    let apiKey = null;
    let mtls = null;
    let bundleId = '';
    let shareId = '';

    if (authMethod === '2') {
      apiKey = await ask('API key or sync token: ');
      bundleId = await ask('Bundle ID: ');
      shareId = await ask('Share ID (for metadata access): ');

      const useMtls = (await ask('Use mTLS client certificate? (y/N): ')).toLowerCase() === 'y';
      if (useMtls) {
        const cert = await ask('  Client cert path (.crt): ');
        const key = await ask('  Client key path (.key): ');
        const ca = await ask('  CA cert path (.crt): ');
        mtls = { cert, key, ca };
      }
    } else {
      const code = await ask('Enrollment code (e.g. HSTASH-XXXX-XXXX-XXXX): ');
      rl.close();

      console.log('\nExchanging enrollment code...');
      const ed = await exchangeEnrollmentCode(server, code);
      apiKey = ed.apiKey;
      console.log('  API key received');

      mtls = saveMtlsCerts(ed);
      if (mtls) console.log('  mTLS certificates saved to ' + nodePath.dirname(mtls.cert));

      if (ed.stashId) console.log('  Stash-scoped token');
      if (ed.bundleId) bundleId = ed.bundleId;
      // Server-issued shareId — hermitstash v1.11.2+ returns it in the
      // enrollment response so the daemon can drive initial-sync
      // metadata fetch (GET /b/:shareId) immediately, instead of
      // requiring the operator to look it up and paste it in. Older
      // servers omit the field; we keep the typed-in fallback above.
      if (ed.shareId) shareId = ed.shareId;
      console.log('  Enrollment complete!');
    }

    if (rl.terminal !== undefined) try { rl.close(); } catch (_e) {} // allow:silent-catch — best-effort TTY close before the success path; the readline handle is dead after this branch

    const { resolvedFolder, storage } = await saveSyncConfig({
      server, bundleId, shareId, syncFolder, apiKey, mtls,
    });
    console.log(`Created sync folder: ${resolvedFolder}`);
    console.log(`API key stored in: ${storage}`);
    console.log(`\nConfig saved to ${CONFIG_DIR}/config.json`);
    console.log('Run "hermitstash-sync start" to begin syncing.');
  } catch (err) {
    try { rl.close(); } catch (_e) {} // allow:silent-catch — error path tearing down the prompt; rl may already be closed if the question was interrupted
    console.error(`Init failed: ${err.message}`);
    process.exit(1);
  }
}

/**
 * Non-interactive init — reads all inputs from env vars. Intended for Docker
 * entrypoints and other headless contexts. Required:
 *   HERMITSTASH_SERVER_URL        — server base URL
 *   HERMITSTASH_ENROLLMENT_CODE   — code from admin UI
 * Optional:
 *   HERMITSTASH_SYNC_FOLDER       — defaults to /data in a container,
 *                                   $HOME/hermitstash-sync otherwise
 *   HERMITSTASH_AUTO_UPDATE       — 'false' to disable binary self-replace
 *                                   (default true on bare-metal, forced
 *                                   false in container entrypoints).
 */
async function cmdInitFromEnv() {
  try {
    const server = process.env.HERMITSTASH_SERVER_URL;
    const code = process.env.HERMITSTASH_ENROLLMENT_CODE;
    const syncFolder = process.env.HERMITSTASH_SYNC_FOLDER
      || (process.env.HERMITSTASH_SYNC_CONFIG_DIR ? '/data' : nodePath.join(require('node:os').homedir(), 'hermitstash-sync'));
    const autoUpdate = process.env.HERMITSTASH_AUTO_UPDATE === 'false' ? false : undefined;

    const missing = [];
    if (!server) missing.push('HERMITSTASH_SERVER_URL');
    if (!code) missing.push('HERMITSTASH_ENROLLMENT_CODE');
    if (missing.length > 0) {
      throw new Error(`Missing required env vars: ${missing.join(', ')}`);
    }

    console.log(`[init] Enrolling with ${server}`);
    const ed = await exchangeEnrollmentCode(server, code);
    const mtls = saveMtlsCerts(ed);
    if (mtls) console.log(`[init] mTLS certs saved to ${nodePath.dirname(mtls.cert)}`);

    const { resolvedFolder, storage } = await saveSyncConfig({
      server,
      bundleId: ed.bundleId || '',
      shareId: ed.shareId || '',
      syncFolder,
      apiKey: ed.apiKey,
      mtls,
      autoUpdate,
    });
    console.log(`[init] Sync folder: ${resolvedFolder}`);
    console.log(`[init] API key stored in: ${storage}`);
    console.log(`[init] Config saved to ${CONFIG_DIR}/config.json`);
  } catch (err) {
    console.error(`[init] Failed: ${err.message}`);
    process.exit(1);
  }
}

// Wall-clock skew gate run at daemon start. Wraps b.ntpCheck.bootCheck
// behind the HERMITSTASH_NTP_* env contract — opt-out + opt-in-strict.
// On fatal drift (>= 1h) the daemon refuses to start; on warning-band
// drift it logs and continues; on unreachable NTP it logs and continues
// unless strict mode is on.
async function _ntpBootGate() {
  if (b.safeEnv.readVar('HERMITSTASH_NTP_DISABLE', { type: 'string', default: '' }) === '1') {
    log.debug('NTP boot check disabled (HERMITSTASH_NTP_DISABLE=1)');
    return;
  }
  const strict = b.safeEnv.readVar('HERMITSTASH_NTP_STRICT', { type: 'string', default: '' }) === '1';
  let r;
  try {
    r = await b.ntpCheck.bootCheck({});
  } catch (err) {
    // bootCheck shouldn't normally throw — checkDrift wraps network
    // errors and returns a result with driftMs=null. Treat a real throw
    // as unreachable so the daemon doesn't crash on a misconfigured DNS.
    log.warn('NTP boot check threw', { err: err.message });
    if (strict) die('NTP boot check failed and HERMITSTASH_NTP_STRICT=1');
    return;
  }
  if (r.severity === 'fatal') {
    log.error('NTP boot check: ' + r.message, { driftMs: r.driftMs, server: r.server });
    die('Refusing to start: ' + r.message + '. Resync the system clock and retry, or set HERMITSTASH_NTP_DISABLE=1 to bypass (cert renewal + auto-update probation will be unreliable).');
  }
  if (r.severity === 'warning') {
    if (r.driftMs === null && strict) {
      die('NTP unreachable and HERMITSTASH_NTP_STRICT=1: ' + r.message);
    }
    log.warn('NTP boot check: ' + r.message, { driftMs: r.driftMs, server: r.server });
    return;
  }
  log.info('NTP boot check: ' + r.message, { driftMs: r.driftMs, server: r.server });
}

async function cmdStart(args) {
  const isDaemon = args.includes('--daemon');
  const isChild = process.env.HERMITSTASH_SYNC_DAEMON === '1';
  const noAutoUpdate = args.includes('--no-autoupdate');

  // Check if already running
  const running = daemon.isRunning();
  if (running) die(`Daemon already running (PID ${running})`);

  // Fork to background if --daemon and not already the child
  if (isDaemon && !isChild) {
    daemon.daemonize();
    return; // daemonize() calls process.exit()
  }

  // Load config
  const cfg = config.load();

  // Initialize logger
  log.init({
    level: cfg.logLevel,
    stdout: !isChild,  // No stdout in daemon mode
  });

  // Auto-update rollback check. If the previous start crashed during
  // probation, this spawns the restored binary and exits the current one.
  await updater.checkRollback();

  // Boot-time NTP drift gate. Two paths in the daemon depend on the
  // wall clock being roughly correct: the auto-update probation
  // (60s window after install — premature `Date.now()` advance can
  // false-clear; large reverse skew can keep us in probation forever)
  // and the cert auto-renewal threshold (`daysLeft > 60` math against
  // `endDate.getTime()` — a clock stuck weeks in the past renews
  // certs needlessly; a clock weeks in the future fails to renew an
  // expiring cert). A laptop that resumed from sleep, a container
  // without an RTC, or a system whose NTP daemon died can all drift
  // far enough to corrupt those decisions silently.
  //
  // `b.ntpCheck.bootCheck` does one SNTPv4 query (UDP/123) against the
  // configured server list and classifies the drift. Defaults: warn at
  // 5 min, fatal at 1 hr. NTP unreachable is non-fatal — the daemon
  // proceeds with a warning so offline / air-gapped installs aren't
  // broken. Operators can:
  //
  //   HERMITSTASH_NTP_DISABLE=1   skip the check entirely
  //   HERMITSTASH_NTP_STRICT=1    treat unreachable NTP as fatal
  //
  // The check runs once at start (boot-time gate, not a monitor) and
  // adds ~50-200ms to startup on a reachable network; offline boxes
  // pay the UDP query timeout (default 2s) before continuing.
  await _ntpBootGate();

  // Retrieve API key
  const apiKey = await keychain.retrieve();
  if (!apiKey) {
    log.error('No API key found. Run "hermitstash-sync init" first.');
    process.exit(1);
  }

  // Get ignore patterns
  const ignorePatterns = config.getIgnorePatterns(cfg);
  const includePatterns = config.getIncludePatterns(cfg);

  // Initialize in-process metrics registry BEFORE the engine so the engine
  // constructor's circuit-breaker `onStateChange` taps land on a registered
  // counter. The periodic writer dumps a snapshot to STATS_FILE so
  // `hermitstash-sync stats` can read it from a separate process.
  metrics.init();
  metrics.startWriter();

  // Create and start sync engine
  const engine = new SyncEngine(cfg, apiKey);

  // Write PID and install signal handlers
  daemon.writePid();
  daemon.installSignalHandlers(
    async () => {
      // sd_notify STOPPING=1 — fires FIRST so systemd marks the unit
      // as deactivating before we tear anything down. Best-effort;
      // missing systemd-notify just no-ops.
      try {
        const systemdNotify = require('./systemd-notify');                          // allow:inline-require — shutdown path; cold-load
        await systemdNotify.stopping('Sync engine stopping');
      } catch { /* allow:silent-catch — never block shutdown on notify */ }
      // metrics.stopWriter() calls b.metrics.snapshot.startWriter's
      // stop() handle, which performs one final flush before clearing
      // the timer. No separate writeSnapshot() needed afterwards.
      metrics.stopWriter();
      await engine.stop();
      await log.close();
    },
    () => engine.resync(),
    // SIGHUP reload callback — re-reads config.json + .hermitstash-
    // ignore + .hermitstash-include from disk and pushes the merged
    // pattern arrays to the engine. Lets operators edit selective-
    // sync or ignore rules and SIGHUP to apply them without
    // restarting the daemon.
    async () => {
      const freshCfg = config.load();
      engine.updatePatterns(
        config.getIgnorePatterns(freshCfg),
        config.getIncludePatterns(freshCfg),
      );
    },
  );

  engine.on('state', (state) => {
    log.info(`Sync state: ${state}`);
  });

  engine.on('auth_error', () => {
    log.error('Authentication failed. Check your API key and try "hermitstash-sync init".');
    daemon.removePid();
    process.exit(1);
  });

  try {
    await engine.start(ignorePatterns, includePatterns);
    log.info('Sync engine running');

    // sd_notify READY=1 — tells systemd the daemon is up so Type=notify
    // unit files unblock systemctl-start. No-op when $NOTIFY_SOCKET is
    // absent (Docker, Windows, dev runs).
    const systemdNotify = require('./systemd-notify');                              // allow:inline-require — cold path; only invoked once per daemon
    systemdNotify.ready('Sync engine running').catch(() => { /* allow:silent-catch — best-effort notify */ });

    // WATCHDOG ping every 60s while the daemon is up. Pairs with a unit
    // file WatchdogSec=120 — systemd auto-restarts the service if two
    // consecutive watchdog windows are missed (engine hang, deadlock).
    // Cheap: ~1 process spawn per minute, exits when env var absent.
    const watchdogTimer = setInterval(() => {
      systemdNotify.watchdog().catch(() => { /* allow:silent-catch — best-effort */ });
    }, 60_000);                                                                  // allow:raw-byte-literal — 60s watchdog cadence; sub-second granularity not meaningful here
    watchdogTimer.unref();                                                       // don't keep the event loop alive on shutdown

    if (!isChild) {
      console.log('Syncing... Press Ctrl+C to stop.');
    }
  } catch (err) {
    log.error('Failed to start sync engine', err);
    daemon.removePid();
    process.exit(1);
  }

  // Start auto-update polling after the engine is running. When a verified
  // update is ready, gracefully stop the engine, swap the binary, and exit
  // so the new detached child takes over. HERMITSTASH_AUTO_UPDATE=false at
  // runtime is a hard disable — the container entrypoint exports it so the
  // daemon can't self-replace its binary inside an immutable image.
  const envDisable = process.env.HERMITSTASH_AUTO_UPDATE === 'false';
  if (cfg.autoUpdate !== false && !noAutoUpdate && !envDisable) {
    // Build a channel-aware updater instance when the operator opts
    // into the beta channel; otherwise use the default module-level
    // stable instance. createUpdater() carries the cost of fetching
    // the GitHub-Releases-list URL pattern, so we only spin a fresh
    // one when the channel diverges from default.
    const updaterInstance = (cfg.autoUpdateChannel === 'beta')
      ? updater.createUpdater({ channel: 'beta' })
      : updater;
    if (cfg.autoUpdateChannel === 'beta') {
      log.info('Auto-update channel: beta — prereleases will be applied');
    }
    updaterInstance.start(async (install) => {
      log.info('Stopping engine to install update');
      try { await engine.stop(); } catch (err) { log.warn('engine.stop failed: ' + err.message); }
      try { install(); } catch (err) {
        log.error('Install failed, staying on current version: ' + err.message);
        return;
      }
      daemon.removePid();
      await log.close();
      process.exit(0);
    });
  } else {
    log.info('Auto-update disabled (config or --no-autoupdate)');
  }
}

function cmdStatus() {
  const running = daemon.isRunning();

  if (!running) {
    console.log('Status: STOPPED');

    if (config.exists()) {
      const cfg = config.load();
      console.log(`Server: ${cfg.server}`);
      console.log(`Folder: ${cfg.syncFolder}`);
    } else {
      console.log('Not configured. Run "hermitstash-sync init".');
    }
    return;
  }

  console.log(`Status: RUNNING (PID ${running})`);

  if (config.exists()) {
    const cfg = config.load();
    console.log(`Server:  ${cfg.server}`);
    console.log(`Folder:  ${cfg.syncFolder}`);
    console.log(`Bundle:  ${cfg.bundleId}`);

    // Try to read state DB for more info
    try {
      const stateDb = require('./state-db'); // allow:inline-require — lazy load: status/resync don't open the DB unless invoked
      stateDb.open();
      const lastSync = stateDb.getMeta('last_sync_time');
      const lastSeq = stateDb.getLastSeq();
      const files = stateDb.getAllFiles();
      const errors = stateDb.getFilesByStatus('error');
      stateDb.close();

      console.log(`Files:   ${files.length}`);
      console.log(`Seq:     ${lastSeq}`);
      console.log(`Last sync: ${lastSync || 'never'}`);
      if (errors.length > 0) {
        console.log(`Errors:  ${errors.length}`);
        errors.slice(0, 5).forEach(f => console.log(`  - ${f.relativePath}`));
        if (errors.length > 5) console.log(`  ... and ${errors.length - 5} more`);
      }
    } catch (err) {
      console.error(`  (Could not read state: ${err.message})`);
    }
  }
}

function cmdStats(args = []) {
  const asJson = args.includes('--json');
  const asProm = args.includes('--prometheus');

  // The stats file is written by the running daemon every
  // STATS_WRITE_INTERVAL_MS via b.metrics.snapshot.startWriter. If it's
  // missing or stale, fall back to the state DB so `stats` works while
  // the daemon is stopped — it just can't surface in-process counters
  // then. b.metrics.snapshot.read validates the file shape; we catch
  // the framework's MetricsError and treat it as "no snapshot".
  let snap = null;
  if (nodeFs.existsSync(STATS_FILE)) {
    try {
      snap = b.metrics.snapshot.read(STATS_FILE);
    } catch (err) {
      console.error(`Could not read ${STATS_FILE}: ${err.message}`);
    }
  }

  const running = daemon.isRunning();
  const stateDb = require('./state-db'); // allow:inline-require — stats path stays cheap when the DB isn't needed
  let dbInfo = null;
  if (config.exists()) {
    try {
      stateDb.open();
      dbInfo = {
        files:    stateDb.getAllFiles().length,
        errors:   stateDb.getFilesByStatus('error').length,
        lastSeq:  stateDb.getLastSeq(),
        lastSync: stateDb.getMeta('last_sync_time'),
      };
      stateDb.close();
    } catch (err) {
      console.error(`Could not read state DB: ${err.message}`);
    }
  }

  if (asJson) {
    console.log(b.safeJson.stringify({
      running:  running ? { pid: running } : null,
      snapshot: snap,
      stateDb:  dbInfo,
    }, null, 2));
    return;
  }
  if (asProm) {
    if (!snap) {
      console.error('No stats file found. Start the daemon first.');
      process.exit(1);
    }
    // b.metrics.snapshot.render emits Prometheus 0.0.4 for every numeric
    // top-level field. String-valued state fields (sync_state,
    // circuit_state_upload) are skipped automatically. Counter-vs-gauge
    // distinction comes from lib/metrics.js#FIELD_TYPES — `b.metrics.
    // snapshot.render` emits everything as `gauge`, which breaks `rate()`
    // queries on the counter-shaped fields (uploads_ok, ws_reconnects,
    // …). Until upstream accepts a fieldTypes hint on render, we emit
    // locally via metrics.renderPrometheus.
    process.stdout.write(metrics.renderPrometheus(snap, {
      prefix: 'hermitstash_sync',
    }));
    return;
  }

  // Human-readable summary — flat snapshot under snap.fields, grouped by
  // hand here for operator readability.
  if (running) {
    console.log(`Daemon:    RUNNING (PID ${running})`);
  } else {
    console.log('Daemon:    STOPPED');
  }
  if (snap) {
    const f = snap.fields;
    const ageSec = Math.floor((Date.now() - new Date(snap.writtenAt).getTime()) / C.TIME.seconds(1));
    // Three buckets: live snapshot (daemon running + fresh), stalled
    // snapshot (daemon running but writer hasn't ticked recently — engine
    // hang or filesystem freeze), historical snapshot (daemon stopped —
    // values describe the previous run, not "now"). The historical case
    // used to display Uptime / State / Pool as if they were live; that's
    // misleading. Now we explicitly frame those as last-known values
    // and route the operator to the state DB section for current truth.
    const live    = running && ageSec <= _SEC_PER_MIN;
    const stalled = running && ageSec > _SEC_PER_MIN;
    const historical = !running;
    const label = historical
      ? '  (historical — daemon stopped)'
      : stalled
        ? `  (stale — last write ${_fmtDuration(ageSec)} ago)`
        : '';
    console.log(`Snapshot:  ${snap.writtenAt}${label}`);
    if (historical) {
      console.log('');
      console.log('Last known state before the daemon stopped:');
      console.log(`  Started:        ${f.startedAt || '—'}`);
      console.log(`  Ran for:        ${_fmtDuration(f.uptimeSec)}`);
      console.log(`  Final state:    ${f.sync_state}`);
      console.log(`  Files tracked:  ${f.file_count}`);
      console.log(`  Last seq:       ${f.last_seq}`);
      console.log('');
      console.log('Counters at last write:');
      console.log(`  Uploads:        ok=${f.uploads_ok} error=${f.uploads_error} retries=${f.upload_retries}`);
      console.log(`  Downloads:      ok=${f.downloads_ok} error=${f.downloads_error}`);
      console.log(`  Conflicts:      ${f.conflicts || 0}`);
      console.log(`  WS reconnects:  ${f.ws_reconnects}`);
      console.log(`  Auth errors:    ${f.ws_auth_errors}`);
      console.log(`  Circuit opens:  upload=${f.circuit_opens_upload}`);
      console.log('');
      console.log('Current truth is in the State DB section below.');
    } else {
      // live or stalled — the values are still meaningful as "current"
      // because the writer is the same daemon process and the snapshot
      // is at most STATS_WRITE_INTERVAL_MS old (or stalled but still
      // alive).
      console.log(`Started:   ${f.startedAt || '—'}`);
      console.log(`Uptime:    ${_fmtDuration(f.uptimeSec)}`);
      console.log('');
      console.log(`State:     ${f.sync_state}`);
      console.log(`Files:     ${f.file_count}`);
      console.log(`Active:    ${f.active_ops} operation(s)`);
      console.log(`Last seq:  ${f.last_seq}`);
      console.log(`Circuit:   upload=${f.circuit_state_upload}`);
      if (f.upload_pool_inflight !== undefined || f.upload_pool_queue !== undefined) {
        console.log(`Pool:      upload inflight=${f.upload_pool_inflight || 0} queued=${f.upload_pool_queue || 0}`);
      }
      console.log('');
      console.log('Counters since start:');
      console.log(`  Uploads:        ok=${f.uploads_ok} error=${f.uploads_error} retries=${f.upload_retries}`);
      console.log(`  Downloads:      ok=${f.downloads_ok} error=${f.downloads_error}`);
      console.log(`  Conflicts:      ${f.conflicts || 0}`);
      console.log(`  WS reconnects:  ${f.ws_reconnects}`);
      console.log(`  Auth errors:    ${f.ws_auth_errors}`);
      console.log(`  Circuit opens:  upload=${f.circuit_opens_upload}`);
    }
  } else if (running) {
    console.log('No snapshot yet — wait a few seconds for the first write.');
  }
  if (dbInfo) {
    console.log('');
    console.log('State DB:');
    console.log(`  Files:      ${dbInfo.files}`);
    console.log(`  Errors:     ${dbInfo.errors}`);
    console.log(`  Last seq:   ${dbInfo.lastSeq}`);
    console.log(`  Last sync:  ${dbInfo.lastSync || 'never'}`);
  }
}

// Seconds-per-{day,hour,minute} divisors for the duration formatter below —
// not millisecond TIME values, so the b.constants.TIME helpers don't apply.
const _SEC_PER_DAY  = 86400; // allow:raw-byte-literal allow:raw-time-literal — seconds/day divisor
const _SEC_PER_HOUR = 3600;  // allow:raw-byte-literal allow:raw-time-literal — seconds/hour divisor
const _SEC_PER_MIN  = 60;    // allow:raw-byte-literal allow:raw-time-literal — seconds/minute divisor
function _fmtDuration(sec) {
  if (!sec || sec < 0) return '0s';
  const d = Math.floor(sec / _SEC_PER_DAY);
  const h = Math.floor((sec % _SEC_PER_DAY) / _SEC_PER_HOUR);
  const m = Math.floor((sec % _SEC_PER_HOUR) / _SEC_PER_MIN);
  const s = sec % _SEC_PER_MIN;
  const parts = [];
  if (d) parts.push(d + 'd');
  if (h) parts.push(h + 'h');
  if (m) parts.push(m + 'm');
  if (s || parts.length === 0) parts.push(s + 's');
  return parts.join(' ');
}

async function cmdStop() {
  await daemon.stop();
}

function cmdLog(args) {
  const follow = args.includes('--follow') || args.includes('-f');

  if (!nodeFs.existsSync(LOG_FILE)) {
    console.log('No log file found.');
    return;
  }

  if (follow) {
    // Cross-platform log follower (no dependency on `tail`). b.safeAsync.
    // repeating gives us automatic Promise/throw swallowing via onError so
    // a transient stat/open/read failure doesn't crash the follower; the
    // empty catch block from the previous setInterval shape is now the
    // explicit onError handler with a debug-level log on persistent issues.
    let pos = 0;
    try { pos = nodeFs.statSync(LOG_FILE).size; } catch {}
    const repeater = b.safeAsync.repeating(() => {
      const stat = nodeFs.statSync(LOG_FILE);
      if (stat.size > pos) {
        const fd = nodeFs.openSync(LOG_FILE, 'r');
        try {
          const buf = Buffer.alloc(stat.size - pos);
          nodeFs.readSync(fd, buf, 0, buf.length, pos);
          process.stdout.write(buf);
          pos = stat.size;
        } finally {
          nodeFs.closeSync(fd);
        }
      }
    }, 500, { onError: () => { /* transient stat/read errors are best-effort for a follower */ } });
    process.on('SIGINT', () => { repeater.stop(); process.exit(0); });
  } else {
    // Last 50 lines
    const content = nodeFs.readFileSync(LOG_FILE, 'utf8');
    const lines = content.trim().split('\n');
    const last50 = lines.slice(-50);
    console.log(last50.join('\n'));
  }
}

async function cmdResync() {
  const running = daemon.isRunning();
  if (running) {
    // L9: SIGHUP is not available on Windows
    if (process.platform === 'win32') {
      console.error('Resync signal not supported on Windows. Stop and restart the daemon.');
      return;
    }
    // Send SIGHUP to trigger resync in the daemon
    try {
      process.kill(running, 'SIGHUP');
      console.log(`Sent resync signal to daemon (PID ${running})`);
    } catch (err) {
      console.error(`Failed to signal daemon: ${err.message}`);
    }
    return;
  }

  console.log('No daemon running. Starting full resync...');

  const cfg = config.load();
  log.init({ level: cfg.logLevel });

  const stateDb = require('./state-db');
  stateDb.open();
  stateDb.clearAll();
  stateDb.close();

  console.log('State cleared. Start the daemon to begin full resync.');
}

async function cmdRepair() {
  if (!nodeFs.existsSync(CONFIG_FILE)) {
    die('No config found. Run "hermitstash-sync init" first.');
  }

  const cfg = b.safeJson.parse(nodeFs.readFileSync(CONFIG_FILE, 'utf8'), { maxBytes: C.BYTES.mib(1) });
  console.log('Repair — re-provision mTLS certificates from enrollment code');
  console.log('Server: ' + cfg.server);
  console.log('');
  console.log('Get a repair code from your admin:');
  console.log('  Admin > Customers > [stash] > Reissue Certificate');
  console.log('');

  const rl = nodeReadline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(resolve => rl.question(q, resolve));

  try {
    const code = await ask('Enrollment code: ');
    if (!code.trim()) die('Code required.');

    console.log('\nExchanging enrollment code...');
    const ed = await exchangeEnrollmentCode(cfg.server, code);

    if (ed.apiKey) {
      await keychain.store(ed.apiKey);
      console.log('  API key updated');
    } else {
      console.log('  API key unchanged (cert-only reissue)');
    }

    const mtls = saveMtlsCerts(ed);
    if (mtls) console.log('  mTLS certificates updated at ' + nodePath.dirname(mtls.cert));

    console.log('\nRepair complete. Restart the daemon to reconnect.');
  } catch (err) {
    die(`Repair failed: ${err.message}`);
  } finally {
    try { rl.close(); } catch (_e) {} // allow:silent-catch — finally-block readline teardown; close is idempotent and an already-closed handle is fine
  }
}

function cmdVersion() {
  console.log(`hermitstash-sync v${VERSION}`);
  console.log(`License: ${require('./constants').LICENSE}`); // allow:inline-require — version path stays lean; LICENSE alone avoids destructuring import friction
  console.log(`Node.js ${process.version}`);
  console.log(`OpenSSL ${process.versions.openssl}`);
}

// Bundle non-secret operational state into a .zip for support handoff.
// Includes redacted config, state DB schema (no rows), parsed cert
// info, version banner, stats snapshot, and rotated log files. Never
// includes the credentials file or the mTLS private key.
function cmdDiagnose(args) {
  const diagnose = require('./diagnose');                                       // allow:inline-require — cold path; pulls b.archive + b.redact only when invoked
  let outPath = diagnose.defaultOutPath();
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--out' && args[i + 1]) {
      outPath = nodePath.resolve(args[++i]);
    }
  }
  try {
    const result = diagnose.buildBundle(outPath);
    console.log(`Diagnose bundle written: ${result.path}`);
    console.log(`  ${result.entryCount} entries, ${(result.sizeBytes / 1024).toFixed(1)} KiB`);
    console.log('');
    console.log('Includes: redacted config, state DB schema (no rows), cert subject,');
    console.log('log rotations, stats snapshot, version banner.');
    console.log('Excludes: credentials, mTLS private key, sync-folder contents, DB rows.');
    console.log('');
    console.log('Inspect with: unzip -l ' + result.path);
  } catch (err) {
    die(`Diagnose failed: ${err.message}`);
  }
}

function cmdHelp() {
  console.log(`
hermitstash-sync v${VERSION} — HermitStash file sync daemon

Usage: hermitstash-sync <command> [options]

Commands:
  init              Interactive setup (server URL, API key, sync folder)
  init --non-interactive
                    Headless setup from env vars (for Docker/CI):
                    HERMITSTASH_SERVER_URL, HERMITSTASH_ENROLLMENT_CODE,
                    HERMITSTASH_SYNC_FOLDER, HERMITSTASH_AUTO_UPDATE
  start             Start sync in foreground
  start --daemon    Start sync as background daemon
  start --no-autoupdate
                    Start without auto-updating the binary
  status            Show sync status
  stats             Show daemon telemetry (uploads/downloads/circuit breaker)
  stats --json      Same, as a JSON object
  stats --prometheus
                    Same, as Prometheus exposition (textfile-collector friendly)
  stop              Stop the daemon
  log               Show last 50 log lines
  log --follow      Follow the log in real time
  resync            Force a full re-sync
  repair            Re-provision mTLS certificates from a repair code
  diagnose          Bundle non-secret state + logs into a .zip for support
  diagnose --out <path>
                    Write the bundle to <path> instead of the cwd default
  version           Show version info
  help              Show this help

Environment overrides:
  HERMITSTASH_AUTO_UPDATE=false   Disable in-binary self-replace (Docker/systemd)
  HERMITSTASH_NTP_DISABLE=1       Skip the SNTPv4 boot-time clock-drift gate
  HERMITSTASH_NTP_STRICT=1        Refuse to start if NTP is unreachable
  HERMITSTASH_WATCHER_MODE        auto (default) | fs | poll — file watcher.
                                  auto detects Docker bind-mounts + non-inotify
                                  fstypes (fuse/virtiofs/nfs/cifs) and falls
                                  back to poll; fs / poll force the choice.

Configuration: ${CONFIG_DIR}/config.json
Log file:      ${LOG_FILE}
  `.trim());
}

module.exports = { run };
