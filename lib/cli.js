'use strict';

// codebase-patterns:allow-file console-direct — CLI surface; operator-visible stdout/stderr is the literal output contract of every command. The structured logger ships through ./logger separately for daemon-mode file logs.
// codebase-patterns:allow-file process-exit — CLI commands return through process.exit(code) to surface sysexits-style status to shells and orchestrators.
// codebase-patterns:allow-file inline-require — interactive commands cold-load heavy modules (state-db, vendor/blamejs) only on demand so `hermitstash-sync help` / `version` stay fast and don't open the SQLite handle.
// codebase-patterns:allow-file raw-process-env — env-driven entry points read documented HERMITSTASH_* names by hand; the values are the user contract of Docker/systemd entrypoints, not internal toggles.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeReadline = require('node:readline');
const b = require('../vendor/blamejs');
const { VERSION, LOG_FILE, CONFIG_DIR, CONFIG_FILE, STATS_FILE, TLS_GROUPS, TLS_MIN_VERSION } = require('./constants');
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
  // Redact at the central fatal-error sink: a die() message routinely
  // interpolates config-derived paths (CONFIG_FILE / LOG_FILE, which resolve
  // from the HERMITSTASH_SYNC_CONFIG_DIR environment value) and the occasional
  // upstream error text, so masking secret-shaped substrings here keeps an
  // accidental token out of stderr and routes the env-derived value through the
  // framework's redaction boundary before it is printed. A plain path or message
  // is unchanged (nothing secret-shaped to mask).
  console.error(b.redact.redact(msg));
  process.exit(1);
}

// Validate + normalize a configured/env-supplied server URL into a safe display
// label (scheme + host[:port]) before it reaches any console/log sink. Two jobs:
// (1) security — b.safeUrl.parse refuses a non-http(s) or malformed entry and
// refuses a user:pass@host authority outright (safe-url/userinfo-disallowed), so
// an embedded credential can never reach a log line; the rebuilt label is then
// run through b.redact.redact so any residual secret-shaped substring is masked
// at the boundary. (2) The label is reconstructed from the parsed origin rather
// than echoing the raw configuration string, so an env-sourced server value is
// never logged verbatim. On a malformed value it returns an actionable
// placeholder instead of throwing, so a status/diagnostic line still renders.
// Shared by status / repair / init so the masking is applied in exactly one
// audited place.
function safeServerLabel(raw) {
  try {
    const u = b.safeUrl.parse(raw, { allowedProtocols: ['http:', 'https:'] });
    return b.redact.redact(`${u.protocol}//${u.host}`);
  } catch {
    return '(invalid server URL — run "hermitstash-sync init")';
  }
}

// Load config with an actionable message on failure. config.load() already
// throws a fully-actionable message for the not-found case; this wraps the
// corrupt-JSON / unreadable cases so a hand-broken config.json surfaces as a
// clear instruction instead of a raw parse stack. Exit semantics match the
// rest of the CLI (die() → exit 1).
function loadConfigOrDie() {
  try {
    return config.load();
  } catch (err) {
    die(`Could not read config at ${CONFIG_FILE}: ${err.message}\n` +
        'Fix the JSON, or run "hermitstash-sync init" to recreate it.');
  }
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
 * First-contact TLS agent for enrollment. Self-signed certs are common at this
 * stage (rejectUnauthorized:false) — the server-issued client cert + CA pin
 * take over for every subsequent request. The agent still advertises the PQC
 * group preference and pins TLS 1.3 so the ClientHello passes a server that
 * enforces the PQC posture; a bare https.Agent negotiates Node's default
 * non-PQC curves over TLS 1.2 and is rejected at the gate.
 */
function buildEnrollmentAgent() {
  const agent = b.pqcAgent.create({ keepAlive: false });
  agent.options.ecdhCurve = TLS_GROUPS;
  agent.options.groups = TLS_GROUPS;
  agent.options.minVersion = TLS_MIN_VERSION;
  agent.options.rejectUnauthorized = false;
  return agent;
}

/**
 * POST /sync/enroll to exchange an enrollment code for an API key + mTLS
 * certs. Returns the server response data. Throws on non-2xx (the transport
 * rejects those before we reach the success check) or an unsuccessful body.
 */
async function exchangeEnrollmentCode(serverUrl, code) {
  // Local error class so 4xx/5xx surface as `err.statusCode` instead of
  // requiring a string-parse of the FrameworkError message.
  const EnrollHttpError = b.frameworkError.defineClass('EnrollHttpError', { withStatusCode: true });

  const parsedUrl = b.safeUrl.parse(serverUrl, { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL });
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
      agent: buildEnrollmentAgent(),
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
      const errMsg = (parsed && (parsed.detail || parsed.error)) || `Server returned status ${err.statusCode}`;
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

  // The transport already rejected every non-2xx (handled in the catch above),
  // so resp.statusCode is always in the success range here — any 2xx (200/201/
  // 202) is accepted. Success keys off the server-asserted `success` flag.
  if (!data || !data.success) {
    throw new Error((data && (data.detail || data.error)) || 'Enrollment failed');
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
  // 0o700 so the dir holding client.crt/client.key/ca.crt is not
  // world-traversable, matching the CONFIG_DIR parent's posture (the key
  // itself is written 0o600 below). ensureDir also tightens a dir an older
  // version created at the umask default.
  b.atomicFile.ensureDir(certsDir, 0o700);
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
  // b.atomicFile.writeSync reads the permission bits from opts.fileMode (not
  // opts.mode). With the wrong key the public cert + CA silently land at the
  // 0o600 default, which is over-restrictive for material an operator expects
  // to read/bundle as their own user. The private key stays 0o600.
  b.atomicFile.writeSync(cert, ensureNewline(enrollData.clientCert), { fileMode: 0o644 });
  b.atomicFile.writeSync(key,  ensureNewline(enrollData.clientKey),  { fileMode: 0o600 });
  b.atomicFile.writeSync(ca,   ensureNewline(enrollData.caCert),     { fileMode: 0o644 });
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
  // Anchor any mTLS paths to absolute so the stored config is cwd-independent
  // — catches the manual init branch, cmdInitFromEnv, and any future caller.
  // Enrollment-issued certs are already absolute (joined under CONFIG_DIR), so
  // this is a no-op for them.
  const mtlsResolved = mtls
    ? { cert: nodePath.resolve(mtls.cert), key: nodePath.resolve(mtls.key), ca: nodePath.resolve(mtls.ca) }
    : null;
  const cfg = {
    server,
    bundleId: bundleId || '',
    shareId: shareId || '',
    syncFolder: resolvedFolder,
    apiKeyRef: storage === 'keychain' ? 'keychain:hermitstash-sync' : 'file',
    mtls: mtlsResolved,
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
        // Resolve against the init cwd now so the persisted config holds
        // absolute paths. A relative path would break once the daemon runs
        // under a different working directory (systemd, Docker, `start
        // --daemon` re-spawn) where the cwd no longer anchors it.
        mtls = {
          cert: nodePath.resolve(cert.trim()),
          key:  nodePath.resolve(key.trim()),
          ca:   nodePath.resolve(ca.trim()),
        };
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

    try { rl.close(); } catch (_e) {} // allow:silent-catch — release stdin before the success path; close is idempotent so the enrollment branch's earlier close is harmless

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

    console.log(`[init] Enrolling with ${safeServerLabel(server)}`);
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
  // The re-spawned daemon worker carries both the env marker (set by
  // daemonize() before the detached spawn) and an explicit --child arg
  // (visible in `ps`). Either is sufficient; we check both so neither path
  // can silently rot.
  const isChild = process.env.HERMITSTASH_SYNC_DAEMON === '1' || args.includes('--child');
  const noAutoUpdate = args.includes('--no-autoupdate');

  // Check if already running. During an auto-update self-replace (or rollback
  // restore) the freshly-spawned successor briefly overlaps the predecessor,
  // which still holds the pidfile until it finishes exiting. Tolerate that
  // transient overlap rather than dying on first sight: wait for the
  // predecessor to release the pidfile, then continue. A genuine
  // already-running daemon (no self-replace marker) still fails fast.
  let running = daemon.isRunning();
  if (running && process.env.HERMITSTASH_SELF_REPLACE === '1') {
    const handoffDeadline = Date.now() + b.constants.TIME.seconds(10);
    while (running && Date.now() < handoffDeadline) {
      await b.safeAsync.sleep(b.constants.TIME.seconds(0.2));
      running = daemon.isRunning();
    }
  }
  delete process.env.HERMITSTASH_SELF_REPLACE;
  if (running) die(`Daemon already running (PID ${running})`);

  // Fork to background if --daemon and not already the child
  if (isDaemon && !isChild) {
    daemon.daemonize();
    return; // daemonize() calls process.exit()
  }

  // Load config and validate it before the engine touches any of these
  // values. The use-site guards in sync-engine/http-client clamp out-of-range
  // numbers, but a bad env override (HERMITSTASH_UPLOAD_CONCURRENCY=-5) or a
  // hand-edited config should fail fast with the actionable message here
  // rather than silently degrading at runtime.
  const cfg = loadConfigOrDie();
  const cfgErrors = config.validate(cfg);
  if (cfgErrors.length > 0) {
    die('Configuration errors:\n  - ' + cfgErrors.join('\n  - '));
  }

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

  // Retrieve API key, honoring config.apiKeyRef (which backend / service the
  // key lives in). retrieveDetailed distinguishes "the OS keychain is
  // unreachable" from "there is genuinely no key" so we don't tell the
  // operator to re-enroll when their existing key is simply behind a
  // credential store that's currently down.
  const keyResult = await keychain.retrieveDetailed(cfg.apiKeyRef);
  if (!keyResult.found) {
    if (keyResult.backendUnreachable) {
      log.error(
        'Your API key is stored in the OS keychain but the credential store is currently unreachable. ' +
        'On Linux: install `secret-tool` (libsecret) and ensure a running keyring agent / D-Bus session; ' +
        'on macOS: ensure the login keychain is unlocked; on Windows: ensure PowerShell is on PATH. ' +
        'Do NOT run "hermitstash-sync init" unless you intend to re-enroll a new key.');
    } else {
      log.error('No API key found. Run "hermitstash-sync init" first.');
    }
    process.exit(1);
  }
  const apiKey = keyResult.apiKey;

  // Get ignore patterns
  const ignorePatterns = config.getIgnorePatterns(cfg);
  const includePatterns = config.getIncludePatterns(cfg);

  // Warn on any pattern shape the matcher silently no-ops on. An unsupported
  // ignore would upload a file class the operator meant to exclude; an
  // unsupported include would drop one they meant to keep. Warnings only —
  // the grammar is documented and a stray pattern shouldn't fail-fast a boot.
  config.warnUnsupportedPatterns(ignorePatterns, 'ignore', log);
  config.warnUnsupportedPatterns(includePatterns, 'include', log);

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
  // Hoisted so the shutdown + auto-update closures can stop the watchdog the
  // moment teardown begins (assigned once the engine is up, below).
  let watchdogTimer = null;
  daemon.installSignalHandlers(
    async () => {
      // sd_notify STOPPING=1 — fires FIRST so systemd marks the unit
      // as deactivating before we tear anything down. Best-effort;
      // missing systemd-notify just no-ops.
      try {
        await b.sdNotify.stopping({ status: 'Sync engine stopping' });
      } catch { /* allow:silent-catch — never block shutdown on notify */ }
      // Stop the watchdog ping as soon as teardown starts — STOPPING=1 has
      // already told systemd the unit is deactivating, so a trailing WATCHDOG=1
      // during the drain is noise. clearInterval is idempotent (null-guarded).
      if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
      // metrics.stopWriter() calls b.metrics.snapshot.startWriter's
      // stop() handle, which performs one final flush before clearing
      // the timer. No separate writeSnapshot() needed afterwards.
      metrics.stopWriter();
      await engine.stop();
      // Record a clean exit for auto-update probation: a SIGTERM/SIGINT-handled
      // shutdown during the probation window means this freshly-installed binary
      // ran and was intentionally stopped (reboot / systemd Restart= / operator
      // stop), not crashed — so the next boot past the window completes
      // probation instead of spuriously rolling back. A crash never reaches
      // here. No-op unless a self-update is on probation.
      updater.markGracefulShutdown();
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
      // Surface a bad live edit rather than silently applying it. We only
      // push the pattern arrays here, so a bad value isn't acted on, but the
      // operator should hear about it so the next restart doesn't fail-fast
      // unexpectedly.
      const reloadErrors = config.validate(freshCfg);
      if (reloadErrors.length > 0) {
        log.warn('Reloaded config has errors; applying pattern changes only', { errors: reloadErrors });
      }
      const reloadIgnore = config.getIgnorePatterns(freshCfg);
      const reloadInclude = config.getIncludePatterns(freshCfg);
      // Re-warn on a freshly-edited pattern that the matcher will silently
      // no-op — the operator just edited config and SIGHUP'd; tell them now
      // rather than letting a typo silently change what syncs.
      config.warnUnsupportedPatterns(reloadIgnore, 'ignore', log);
      config.warnUnsupportedPatterns(reloadInclude, 'include', log);
      engine.updatePatterns(reloadIgnore, reloadInclude);
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
    b.sdNotify.ready({ status: 'Sync engine running' }).catch(() => { /* allow:silent-catch — best-effort notify */ });

    // WATCHDOG ping every 60s while the daemon is up. Pairs with a unit
    // file WatchdogSec=120 — systemd auto-restarts the service if two
    // consecutive watchdog windows are missed (engine hang, deadlock).
    watchdogTimer = setInterval(() => {
      b.sdNotify.watchdog().catch(() => { /* allow:silent-catch — best-effort */ });
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
      // Silence the watchdog before the self-replace path tears the engine
      // down (same rationale as the graceful-shutdown closure above).
      if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
      try { await engine.stop(); } catch (err) { log.warn('engine.stop failed: ' + err.message); }
      // Await the install so the binary swap + detached-child spawn finish
      // before this process exits — otherwise process.exit() races the swap
      // and a rejection escapes as an unhandledRejection after the PID file
      // is already gone. On failure we stay on the current version.
      try {
        await install();
      } catch (err) {
        log.error('Auto-update install failed, staying on current version: ' + err.message);
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

// Exit code for `status` when the daemon is not running. Follows the LSB
// init-script convention (3 = "program is not running") so a health probe —
// Docker HEALTHCHECK, Kubernetes liveness exec, systemd, or a plain
// `hermitstash-sync status && ...` — detects a dead daemon by exit code alone
// instead of grepping the human-readable banner. RUNNING/healthy stays exit 0.
// The stdout output is unchanged for interactive use.
const STATUS_EXIT_STOPPED = 3; // LSB init-script convention: "program is not running"

function cmdStatus() {
  const running = daemon.isRunning();

  if (!running) {
    // Signal "not running" by exit code without aborting — process.exitCode
    // (not process.exit) lets the human-readable lines below flush and the
    // run() promise resolve normally; the code is honoured at natural exit.
    process.exitCode = STATUS_EXIT_STOPPED;
    console.log('Status: STOPPED');

    if (config.exists()) {
      const cfg = loadConfigOrDie();
      console.log(`Server: ${safeServerLabel(cfg.server)}`);
      console.log(`Folder: ${cfg.syncFolder}`);
    } else {
      console.log('Not configured. Run "hermitstash-sync init".');
    }
    return;
  }

  console.log(`Status: RUNNING (PID ${running})`);

  if (config.exists()) {
    const cfg = loadConfigOrDie();
    console.log(`Server:  ${safeServerLabel(cfg.server)}`);
    console.log(`Folder:  ${cfg.syncFolder}`);
    console.log(`Bundle:  ${cfg.bundleId}`);

    // Try to read state DB for more info
    try {
      const stateDb = require('./state-db'); // allow:inline-require — lazy load: status/resync don't open the DB unless invoked
      // Read-only consumer: refuse corruption recovery so this short-lived
      // command can never rename-and-recreate the DB the live daemon (the
      // RUNNING branch reaches here precisely when the daemon is writing it)
      // still holds open under WAL.
      stateDb.open(undefined, { recovery: 'refuse' });
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
      // Read-only consumer: refuse corruption recovery so this stats command
      // never rename-and-recreates the live daemon's DB (mirrors diagnose).
      stateDb.open(undefined, { recovery: 'refuse' });
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
    }, { indent: 2 }));
    return;
  }
  if (asProm) {
    // Prefer the sidecar exposition the daemon writes to STATS_PROM_FILE
    // — it carries full histogram buckets (P50/P95/P99 territory) that
    // the flat snapshot can't represent. Falls back to the flat-snapshot
    // render when the sidecar is absent (older daemon, or before the
    // first sidecar tick after a fresh start).
    const STATS_PROM_FILE = require('./constants').STATS_PROM_FILE;             // allow:inline-require — cold path; avoids pulling the constants binding into the warm stats text path
    if (nodeFs.existsSync(STATS_PROM_FILE)) {
      try {
        // O_NOFOLLOW: refuse a symlink swapped in at the sidecar path rather
        // than reading through it; readFileSync(fd) leaves the fd to the finally.
        const fd = b.atomicFile.openNoFollowSync(STATS_PROM_FILE);
        try {
          process.stdout.write(nodeFs.readFileSync(fd));
        } finally {
          nodeFs.closeSync(fd);
        }
        return;
      } catch (err) {
        console.error(`Could not read ${STATS_PROM_FILE}: ${err.message}`);
      }
    }
    if (!snap) {
      console.error('No stats file found. Start the daemon first.');
      process.exit(1);
    }
    // Flat-snapshot fallback. b.metrics.snapshot.render emits Prometheus
    // 0.0.4 for every numeric top-level field; string-valued state
    // fields (sync_state, circuit_state_upload) are skipped. Counter-vs-
    // gauge distinction comes from lib/metrics.js#FIELD_TYPES. Histogram
    // bucket counts are absent on this path — operators wanting tail
    // latency wait for the sidecar (within STATS_WRITE_INTERVAL_MS of
    // daemon start) or use the histogram_count + _sum gauges here.
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
      if (f.upload_duration_count > 0 || f.download_duration_count > 0) {
        const ulAvg = f.upload_duration_count > 0
          ? (f.upload_duration_sum_sec / f.upload_duration_count).toFixed(3) + 's'
          : 'n/a';
        const dlAvg = f.download_duration_count > 0
          ? (f.download_duration_sum_sec / f.download_duration_count).toFixed(3) + 's'
          : 'n/a';
        console.log(`  Avg latency:    upload=${ulAvg} (n=${f.upload_duration_count}) ` +
                    `download=${dlAvg} (n=${f.download_duration_count})`);
        console.log('  (P50/P95/P99 buckets exposed via `stats --prometheus`)');
      }
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
        // O_NOFOLLOW: a symlink swapped in at the log path is refused (ELOOP,
        // swallowed by onError) rather than read through to an off-dir target.
        const fd = b.atomicFile.openNoFollowSync(LOG_FILE);
        try {
          const buf = Buffer.alloc(stat.size - pos);
          nodeFs.readSync(fd, buf, 0, buf.length, pos);
          process.stdout.write(buf);
          pos = stat.size;
        } finally {
          nodeFs.closeSync(fd);
        }
      }
    }, 500, { unref: false, onError: () => { /* transient stat/read errors are best-effort for a follower */ } });
    // allow:sea-sigterm-bug — `logs --follow` is interactive (operator Ctrl-C); the foreground caller sees the tty 143 from the SEA Node bug but immediately re-prompts. Not a container path. tini-remapped exit 0 doesn't apply here.
    process.on('SIGINT', () => { repeater.stop(); process.exit(0); });
  } else {
    // Last 50 lines. Open O_NOFOLLOW so a symlink planted at the log path is
    // refused rather than read through to an attacker-chosen target (CWE-59);
    // readFileSync(fd) does not close the fd, so the finally owns it.
    let content;
    let fd;
    try {
      fd = b.atomicFile.openNoFollowSync(LOG_FILE);
      content = nodeFs.readFileSync(fd, 'utf8');
    } catch (err) {
      if (err && err.code === 'ELOOP') {
        die(`Refusing to read logs through a symlink at ${LOG_FILE}. Remove it and ensure only the daemon owner can write that directory.`);
      }
      throw err;
    } finally {
      if (fd !== undefined) nodeFs.closeSync(fd);
    }
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

  const cfg = loadConfigOrDie();
  log.init({ level: cfg.logLevel });

  const stateDb = require('./state-db');
  stateDb.open();
  stateDb.clearAll();
  stateDb.close();

  console.log('State cleared. Start the daemon to begin full resync.');
}

async function cmdRepair() {
  // Route through the single config entry point so the byte cap, DEFAULTS
  // merge, and env overlay match every other consumer — no hand-rolled
  // re-parse that can drift from config.js's CONFIG_MAX_BYTES. loadConfigOrDie
  // re-checks existence internally and dies with an actionable message when the
  // config is missing or unreadable.
  const cfg = loadConfigOrDie();
  // Validate the configured server up front so a malformed entry dies here with
  // a clear URL error before the enrollment exchange below uses it. The result
  // is discarded — the display goes through safeServerLabel (validate + mask),
  // the single audited place server URLs are rendered, mirroring the wire layer
  // (lib/ws-client.js / lib/http-client.js) which routes config.server through
  // b.safeUrl.parse rather than emitting the raw config string.
  b.safeUrl.parse(cfg.server, { allowedProtocols: ['http:', 'https:'] });
  console.log('Repair — re-provision mTLS certificates from enrollment code');
  console.log(`Server: ${safeServerLabel(cfg.server)}`);
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
      // Re-store under the backend/service the operator's config already
      // points at (config.apiKeyRef) rather than always defaulting, so a
      // non-default keychain service survives a repair.
      await keychain.store(ed.apiKey, cfg.apiKeyRef);
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

module.exports = { run, buildEnrollmentAgent, exchangeEnrollmentCode, safeServerLabel };
