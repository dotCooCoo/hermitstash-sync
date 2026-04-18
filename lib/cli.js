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

async function run(args) {
  const command = args[0] || 'help';

  switch (command) {
    case 'init':     return cmdInit();
    case 'start':    return cmdStart(args);
    case 'status':   return cmdStatus();
    case 'stop':     return cmdStop();
    case 'log':      return cmdLog(args);
    case 'resync':   return cmdResync();
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

// --- Commands ---

async function cmdInit() {
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
      // Manual setup — user provides API key and optional mTLS cert paths
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
      // Enrollment code — exchange code for API key + mTLS certs
      const code = await ask('Enrollment code (e.g. HSTASH-XXXX-XXXX-XXXX): ');
      rl.close();

      console.log('\nExchanging enrollment code...');
      const http = require('node:http');
      const https = require('node:https');
      const serverUrl = new URL(server);
      const mod = serverUrl.protocol === 'https:' ? https : http;

      const enrollBody = JSON.stringify({ code: code.trim().toUpperCase() });
      const enrollResult = await new Promise((resolve, reject) => {
        const req = mod.request({
          hostname: serverUrl.hostname,
          port: serverUrl.port || (serverUrl.protocol === 'https:' ? 443 : 80),
          path: '/sync/enroll',
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(enrollBody) },
          rejectUnauthorized: false,
        }, res => {
          let body = '';
          res.on('data', c => { body += c; });
          res.on('end', () => {
            try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
            catch (_e) { reject(new Error('Invalid response from server')); }
          });
        });
        req.on('error', reject);
        req.setTimeout(15000, () => { req.destroy(new Error('Request timeout')); });
        req.write(enrollBody);
        req.end();
      });

      if (enrollResult.status !== 200 || !enrollResult.data.success) {
        console.error('Enrollment failed: ' + (enrollResult.data.error || 'Unknown error'));
        process.exit(1);
      }

      const ed = enrollResult.data;
      apiKey = ed.apiKey;
      console.log('  API key received');

      // Save mTLS certs if provided
      if (ed.clientCert && ed.clientKey && ed.caCert) {
        const certsDir = path.join(CONFIG_DIR, 'certs');
        fs.mkdirSync(certsDir, { recursive: true });
        const certPath = path.join(certsDir, 'client.crt');
        const keyPath = path.join(certsDir, 'client.key');
        const caPath = path.join(certsDir, 'ca.crt');
        fs.writeFileSync(certPath, ed.clientCert, { mode: 0o644 });
        fs.writeFileSync(keyPath, ed.clientKey, { mode: 0o600 });
        fs.writeFileSync(caPath, ed.caCert, { mode: 0o644 });
        mtls = { cert: certPath, key: keyPath, ca: caPath };
        console.log('  mTLS certificates saved to ' + certsDir);
      }

      if (ed.stashId) console.log('  Stash-scoped token');
      if (ed.bundleId) bundleId = ed.bundleId;

      console.log('  Enrollment complete!');
    }

    if (rl.terminal !== undefined) try { rl.close(); } catch (_e) {}

    // Resolve sync folder to absolute path
    const resolvedFolder = path.resolve(syncFolder);

    // Create sync folder if it doesn't exist
    if (!fs.existsSync(resolvedFolder)) {
      fs.mkdirSync(resolvedFolder, { recursive: true });
      console.log(`Created sync folder: ${resolvedFolder}`);
    }

    // Store API key in keychain
    const storage = keychain.store(apiKey);
    console.log(`API key stored in: ${storage}`);

    // Save config
    const cfg = {
      server,
      bundleId,
      shareId,
      syncFolder: resolvedFolder,
      apiKeyRef: storage === 'keychain' ? 'keychain:hermitstash-sync' : 'file',
      mtls,
      ignore: [],
      logLevel: 'info',
    };

    const errors = config.validate(cfg);
    if (errors.length > 0) {
      console.error('\nConfiguration errors:');
      errors.forEach(e => console.error(`  - ${e}`));
      process.exit(1);
    }

    config.save(cfg);
    console.log(`\nConfig saved to ${CONFIG_DIR}/config.json`);
    console.log('Run "hermitstash-sync start" to begin syncing.');
  } catch (err) {
    try { rl.close(); } catch (_e) {}
    console.error(`Init failed: ${err.message}`);
    process.exit(1);
  }
}

async function cmdStart(args) {
  const isDaemon = args.includes('--daemon');
  const isChild = process.env.HERMITSTASH_SYNC_DAEMON === '1';

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
  start             Start sync in foreground
  start --daemon    Start sync as background daemon
  status            Show sync status
  stop              Stop the daemon
  log               Show last 50 log lines
  log --follow      Follow the log in real time
  resync            Force a full re-sync
  version           Show version info
  help              Show this help

Configuration: ${CONFIG_DIR}/config.json
Log file:      ${LOG_FILE}
  `.trim());
}

module.exports = { run };
