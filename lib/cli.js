'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { VERSION, LOG_FILE, CONFIG_DIR } = require('./constants');
const config = require('./config');
const keychain = require('./keychain');
const daemon = require('./daemon');
const log = require('./logger');
const SyncEngine = require('./sync-engine');
const updater = require('./updater');

async function run(args) {
  const command = args[0] || 'help';

  switch (command) {
    case 'init':     return cmdInit(args);
    case 'start':    return cmdStart(args);
    case 'status':   return cmdStatus();
    case 'stop':     return cmdStop();
    case 'log':      return cmdLog(args);
    case 'resync':   return cmdResync();
    case 'repair':   return cmdRepair();
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
  const http = require('node:http');
  const https = require('node:https');
  const url = new URL(serverUrl);
  const mod = url.protocol === 'https:' ? https : http;
  const body = JSON.stringify({ code: code.trim().toUpperCase() });

  const result = await new Promise((resolve, reject) => {
    const req = mod.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: '/sync/enroll',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      rejectUnauthorized: false,
    }, res => {
      let buf = '';
      res.on('data', c => { buf += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(buf) }); }
        catch (_e) { reject(new Error('Invalid response from server')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(new Error('Request timeout')); });
    req.write(body);
    req.end();
  });

  if (result.status !== 200 || !result.data.success) {
    throw new Error(result.data.error || `Server returned status ${result.status}`);
  }
  return result.data;
}

/**
 * Write mTLS certs to CONFIG_DIR/certs and return their paths, or null if
 * no certs were provided.
 */
function saveMtlsCerts(enrollData) {
  if (!enrollData.clientCert || !enrollData.clientKey || !enrollData.caCert) return null;
  const certsDir = path.join(CONFIG_DIR, 'certs');
  fs.mkdirSync(certsDir, { recursive: true });
  const cert = path.join(certsDir, 'client.crt');
  const key = path.join(certsDir, 'client.key');
  const ca = path.join(certsDir, 'ca.crt');
  fs.writeFileSync(cert, enrollData.clientCert, { mode: 0o644 });
  fs.writeFileSync(key, enrollData.clientKey, { mode: 0o600 });
  fs.writeFileSync(ca, enrollData.caCert, { mode: 0o644 });
  return { cert, key, ca };
}

/**
 * Persist config and API key to disk. Returns the saved config object.
 * Throws with a combined message if validation fails.
 */
function saveSyncConfig({ server, bundleId, shareId, syncFolder, apiKey, mtls, autoUpdate }) {
  const resolvedFolder = path.resolve(syncFolder);
  if (!fs.existsSync(resolvedFolder)) {
    fs.mkdirSync(resolvedFolder, { recursive: true });
  }
  const storage = keychain.store(apiKey);
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

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
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
      if (mtls) console.log('  mTLS certificates saved to ' + path.dirname(mtls.cert));

      if (ed.stashId) console.log('  Stash-scoped token');
      if (ed.bundleId) bundleId = ed.bundleId;
      console.log('  Enrollment complete!');
    }

    if (rl.terminal !== undefined) try { rl.close(); } catch (_e) {}

    const { resolvedFolder, storage } = saveSyncConfig({
      server, bundleId, shareId, syncFolder, apiKey, mtls,
    });
    console.log(`Created sync folder: ${resolvedFolder}`);
    console.log(`API key stored in: ${storage}`);
    console.log(`\nConfig saved to ${CONFIG_DIR}/config.json`);
    console.log('Run "hermitstash-sync start" to begin syncing.');
  } catch (err) {
    try { rl.close(); } catch (_e) {}
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
      || (process.env.HERMITSTASH_SYNC_CONFIG_DIR ? '/data' : path.join(require('node:os').homedir(), 'hermitstash-sync'));
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
    if (mtls) console.log(`[init] mTLS certs saved to ${path.dirname(mtls.cert)}`);

    const { resolvedFolder, storage } = saveSyncConfig({
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

async function cmdStart(args) {
  const isDaemon = args.includes('--daemon');
  const isChild = process.env.HERMITSTASH_SYNC_DAEMON === '1';
  const noAutoUpdate = args.includes('--no-autoupdate');

  // Check if already running
  const running = daemon.isRunning();
  if (running) {
    console.error(`Daemon already running (PID ${running})`);
    process.exit(1);
  }

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
  updater.checkRollback();

  // Retrieve API key
  const apiKey = keychain.retrieve();
  if (!apiKey) {
    log.error('No API key found. Run "hermitstash-sync init" first.');
    process.exit(1);
  }

  // Get ignore patterns
  const ignorePatterns = config.getIgnorePatterns(cfg);

  // Create and start sync engine
  const engine = new SyncEngine(cfg, apiKey);

  // Write PID and install signal handlers
  daemon.writePid();
  daemon.installSignalHandlers(
    async () => {
      await engine.stop();
      log.close();
    },
    () => engine.resync(),
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
    await engine.start(ignorePatterns);
    log.info('Sync engine running');

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
    updater.start(async (install) => {
      log.info('Stopping engine to install update');
      try { await engine.stop(); } catch (err) { log.warn('engine.stop failed: ' + err.message); }
      try { install(); } catch (err) {
        log.error('Install failed, staying on current version: ' + err.message);
        return;
      }
      daemon.removePid();
      log.close();
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
      const stateDb = require('./state-db');
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

function cmdStop() {
  daemon.stop();
}

function cmdLog(args) {
  const follow = args.includes('--follow') || args.includes('-f');

  if (!fs.existsSync(LOG_FILE)) {
    console.log('No log file found.');
    return;
  }

  if (follow) {
    // M1: Cross-platform log follower (no dependency on `tail`)
    let pos = 0;
    try { pos = fs.statSync(LOG_FILE).size; } catch {}
    const interval = setInterval(() => {
      try {
        const stat = fs.statSync(LOG_FILE);
        if (stat.size > pos) {
          const fd = fs.openSync(LOG_FILE, 'r');
          const buf = Buffer.alloc(stat.size - pos);
          fs.readSync(fd, buf, 0, buf.length, pos);
          fs.closeSync(fd);
          process.stdout.write(buf);
          pos = stat.size;
        }
      } catch {}
    }, 500);
    process.on('SIGINT', () => { clearInterval(interval); process.exit(0); });
  } else {
    // Last 50 lines
    const content = fs.readFileSync(LOG_FILE, 'utf8');
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
  const configPath = path.join(CONFIG_DIR, 'config.json');
  if (!fs.existsSync(configPath)) {
    console.error('No config found. Run "hermitstash-sync init" first.');
    process.exit(1);
  }

  const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  console.log('Repair — re-provision mTLS certificates from enrollment code');
  console.log('Server: ' + cfg.server);
  console.log('');
  console.log('Get a repair code from your admin:');
  console.log('  Admin > Customers > [stash] > Reissue Certificate');
  console.log('');

  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  function ask(q) { return new Promise(resolve => rl.question(q, resolve)); }

  const code = await ask('Enrollment code: ');
  if (!code.trim()) { console.error('Code required.'); process.exit(1); }

  console.log('\nExchanging enrollment code...');
  const enrollBody = JSON.stringify({ code: code.trim().toUpperCase() });

  const https = require('https');
  const http = require('http');
  const url = new URL(cfg.server);
  const mod = url.protocol === 'https:' ? https : http;

  const enrollResult = await new Promise((resolve, reject) => {
    const req = mod.request({
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: '/sync/enroll', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(enrollBody) },
      rejectUnauthorized: false,
    }, res => {
      let body = ''; res.on('data', c => body += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(body) }); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(enrollBody);
    req.end();
  });

  if (enrollResult.status !== 200 || !enrollResult.data.success) {
    console.error('Enrollment failed: ' + (enrollResult.data.error || 'Unknown error'));
    process.exit(1);
  }

  const ed = enrollResult.data;

  // Update API key if provided (full re-enrollment, not just cert reissue)
  if (ed.apiKey) {
    const keychain = require('./keychain');
    keychain.store(ed.apiKey);
    console.log('  API key updated');
  } else {
    console.log('  API key unchanged (cert-only reissue)');
  }

  // Save mTLS certs
  if (ed.clientCert && ed.clientKey && ed.caCert) {
    const certsDir = path.join(CONFIG_DIR, 'certs');
    fs.mkdirSync(certsDir, { recursive: true });
    fs.writeFileSync(path.join(certsDir, 'client.crt'), ed.clientCert, { mode: 0o644 });
    fs.writeFileSync(path.join(certsDir, 'client.key'), ed.clientKey, { mode: 0o600 });
    fs.writeFileSync(path.join(certsDir, 'ca.crt'), ed.caCert, { mode: 0o644 });
    console.log('  mTLS certificates updated');
  }

  if (rl.terminal !== undefined) try { rl.close(); } catch (_e) {}
  console.log('\nRepair complete. Restart the daemon to reconnect.');
}

function cmdVersion() {
  console.log(`hermitstash-sync v${VERSION}`);
  console.log(`License: ${require('./constants').LICENSE}`);
  console.log(`Node.js ${process.version}`);
  console.log(`OpenSSL ${process.versions.openssl}`);
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
  stop              Stop the daemon
  log               Show last 50 log lines
  log --follow      Follow the log in real time
  resync            Force a full re-sync
  repair            Re-provision mTLS certificates from a repair code
  version           Show version info
  help              Show this help

Configuration: ${CONFIG_DIR}/config.json
Log file:      ${LOG_FILE}
  `.trim());
}

module.exports = { run };
