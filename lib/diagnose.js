'use strict';

// Diagnose bundle — collects non-secret operational state into a
// single .zip for support handoff. Composed over b.archive.zip,
// b.redact, b.atomicFile, and node:crypto X509Certificate.
//
// What goes in:
//   config.json          — redacted via b.redact (apiKeyRef and any
//                           field b.redact's defaults flag are masked)
//   state-db-schema.json — CREATE TABLE / index DDL + per-table row
//                           counts. No actual rows (file table holds
//                           user paths — those don't leave the host).
//   stats.json           — last metrics snapshot, if present
//   log/*                — current log + retained rotations as-is
//   update-pending.json  — present iff the daemon is mid-update
//   cert-info.json       — parsed subject + validity window of the
//                           mTLS client cert (cert is public material;
//                           the key file is NEVER included)
//   info.json            — version banner, platform, blamejs vendored
//                           version, keychain backend in use
//
// What's explicitly out:
//   - credentials file
//   - mTLS private key
//   - state.db raw bytes (the file table holds user paths)
//   - any field b.redact's defaults mask (apiKey*, password*, secret*,
//     token*, cookie, authorization, etc.)

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const b = require('../vendor/blamejs');
const {
  VERSION,
  CONFIG_DIR,
  CONFIG_FILE,
  STATE_DB_FILE,
  STATS_FILE,
  LOG_FILE,
} = require('./constants');
const stateDb = require('./state-db');

const C = b.constants;

function _readJsonIfPresent(path, capBytes) {
  if (!nodeFs.existsSync(path)) return null;
  try {
    const raw = nodeFs.readFileSync(path, 'utf8');
    return b.safeJson.parse(raw, { maxBytes: capBytes || C.BYTES.mib(1) });
  } catch (err) {
    return { _diagnose_read_error: err.message };
  }
}

function _redactedConfig() {
  const cfg = _readJsonIfPresent(CONFIG_FILE);
  if (!cfg) return { _absent: true, path: CONFIG_FILE };
  return b.redact.redact(cfg);
}

function _certInfo(cfg) {
  if (!cfg || !cfg.mtls || !cfg.mtls.cert) return { _absent: true };
  const certPath = cfg.mtls.cert;
  if (!nodeFs.existsSync(certPath)) return { _absent: true, path: certPath };
  try {
    const pem = nodeFs.readFileSync(certPath, 'utf8');
    const x = new nodeCrypto.X509Certificate(pem);
    // SPKI pin for the cert's public key, in the `sha256/<base64>`
    // shape that config.pinnedServerSpki accepts. The pin is computed
    // from the public-key bytes (not the whole cert) so cert rotation
    // that reuses the same keypair preserves the pin. Operators can
    // copy this into config.pinnedServerSpki to enable opt-in cert
    // pinning against the same server identity.
    const spkiDer = x.publicKey.export({ format: 'der', type: 'spki' });
    const spkiPin = 'sha256/' + nodeCrypto.createHash('sha256').update(spkiDer).digest('base64');
    return {
      subject:        x.subject,
      issuer:         x.issuer,
      validFrom:      x.validFrom,
      validTo:        x.validTo,
      serialNumber:   x.serialNumber,
      fingerprint256: x.fingerprint256,
      spkiPin:        spkiPin,
    };
  } catch (err) {
    return { _parse_error: err.message };
  }
}

function _vendoredBlamejsVersion() {
  try {
    const manifestPath = nodePath.resolve(__dirname, '..', 'vendor', 'MANIFEST.json');
    const m = _readJsonIfPresent(manifestPath);
    if (!m || !m.packages || !m.packages.blamejs) return null;
    return m.packages.blamejs.version || null;
  } catch {
    return null;
  }
}

function _logFiles() {
  // The b.logStream local sink rotates as <prefix>.log + <prefix>.<n>.log.gz.
  // Pick up everything matching the base prefix that lives in CONFIG_DIR.
  const out = [];
  try {
    const dir = nodePath.dirname(LOG_FILE);
    const base = nodePath.basename(LOG_FILE, nodePath.extname(LOG_FILE));
    const entries = nodeFs.readdirSync(dir);
    for (const name of entries) {
      if (!name.startsWith(base)) continue;
      const abs = nodePath.join(dir, name);
      try {
        const stat = nodeFs.statSync(abs);
        if (!stat.isFile()) continue;
        out.push({ name, abs, size: stat.size, mtime: stat.mtime.toISOString() });
      } catch { /* allow:silent-catch — best-effort enumeration */ }
    }
  } catch { /* allow:silent-catch — missing log dir is fine */ }
  return out;
}

function _info() {
  return {
    version:                   VERSION,
    node:                      process.version,
    platform:                  process.platform,
    arch:                      process.arch,
    pid:                       process.pid,
    cwd:                       process.cwd(),
    configDir:                 CONFIG_DIR,
    blamejsVendoredVersion:    _vendoredBlamejsVersion(),
    sea:                       Boolean(process.execArgv.length === 0 && /hermitstash-sync/.test(process.execPath)),
    generatedAt:               new Date().toISOString(),
  };
}

function _stateDbSchema() {
  // Open read-only if not already open; close after if we were the one
  // to open it. The CLI command runs against the live daemon's DB
  // through a separate handle.
  let opened = false;
  try {
    if (!nodeFs.existsSync(STATE_DB_FILE)) return { _absent: true, path: STATE_DB_FILE };
    try { stateDb.db(); } catch { stateDb.open(); opened = true; }
    return stateDb.dumpSchema();
  } catch (err) {
    return { error: err.message };
  } finally {
    if (opened) try { stateDb.close(); } catch { /* allow:silent-catch — idempotent teardown */ }
  }
}

/**
 * Build the diagnose archive and write it to `outPath`. Returns
 * { path, entryCount, sizeBytes }.
 */
function buildBundle(outPath) {
  const zip = b.archive.zip();

  const info = _info();
  zip.addFile('info.json', Buffer.from(JSON.stringify(info, null, 2), 'utf8'));

  const cfg = _redactedConfig();
  zip.addFile('config.redacted.json', Buffer.from(JSON.stringify(cfg, null, 2), 'utf8'));

  const rawCfg = _readJsonIfPresent(CONFIG_FILE);
  const certInfo = _certInfo(rawCfg);
  zip.addFile('cert-info.json', Buffer.from(JSON.stringify(certInfo, null, 2), 'utf8'));

  const schema = _stateDbSchema();
  zip.addFile('state-db-schema.json', Buffer.from(JSON.stringify(schema, null, 2), 'utf8'));

  const stats = _readJsonIfPresent(STATS_FILE);
  if (stats) {
    zip.addFile('stats.json', Buffer.from(JSON.stringify(stats, null, 2), 'utf8'));
  }

  const updateMarker = _readJsonIfPresent(nodePath.join(CONFIG_DIR, 'update-pending.json'));
  if (updateMarker) {
    zip.addFile('update-pending.json', Buffer.from(JSON.stringify(updateMarker, null, 2), 'utf8'));
  }

  const logCap = C.BYTES.mib(50);
  for (const entry of _logFiles()) {
    if (entry.size > logCap) continue; // skip pathological log files
    try {
      const buf = nodeFs.readFileSync(entry.abs);
      zip.addFile('log/' + entry.name, buf);
    } catch { /* allow:silent-catch — best-effort log inclusion */ }
  }

  const buf = zip.toBuffer();
  nodeFs.writeFileSync(outPath, buf, { mode: 0o600 });
  return { path: outPath, entryCount: zip.entryCount, sizeBytes: buf.length };
}

function defaultOutPath() {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, 'Z');
  return nodePath.join(process.cwd(), `hermitstash-sync-diagnose-${ts}.zip`);
}

module.exports = { buildBundle, defaultOutPath };
