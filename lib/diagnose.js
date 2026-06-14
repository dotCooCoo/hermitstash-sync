'use strict';

// Diagnose bundle — collects non-secret operational state into a
// single .zip for support handoff. Composed over b.archive.zip,
// b.redact, b.atomicFile, and node:crypto X509Certificate.
//
// What goes in:
//   config.json          — an explicit allowlist projection of the
//                           config (see CONFIG_ALLOWLIST below), with
//                           home-dir paths reduced to basename/booleans
//                           so the OS username and folder layout never
//                           leave the host, then run through b.redact as
//                           defense-in-depth. A field NOT on the
//                           allowlist is dropped entirely.
//   state-db-schema.json — CREATE TABLE / index DDL + per-table row
//                           counts. No actual rows (file table holds
//                           user paths — those don't leave the host).
//   stats.json           — last metrics snapshot, if present
//   log/*                — current log + retained rotations, re-redacted
//                           at bundle time. The framework redacts at emit
//                           time, but a message string already on disk
//                           (a user file path, a token in a URL) was
//                           written before any rule that would catch it,
//                           so we re-run b.redact over the bytes here.
//   update-pending.json  — present iff the daemon is mid-update
//   cert-info.json       — validity window + serial + fingerprint + SPKI
//                           pin of the mTLS client cert, plus the subject
//                           and issuer reduced to CN only. The full DN +
//                           any subjectAltName are NOT emitted — an
//                           enrollment-embedded email/hostname stays on
//                           the host. The key file is NEVER included.
//   info.json            — version banner, platform, blamejs vendored
//                           version, keychain backend in use
//
// What's explicitly out:
//   - credentials file
//   - mTLS private key
//   - state.db raw bytes (the file table holds user paths)
//   - absolute paths carrying the OS username / home-dir layout
//   - any config field not on CONFIG_ALLOWLIST
//   - any field b.redact's defaults mask (apiKey*, password*, secret*,
//     token*, cookie, authorization, etc.)
//
// Allowlist contract: config inclusion is allowlist-projected, not
// denylist-redacted. Adding a config field to the bundle is a deliberate
// opt-in — extend CONFIG_ALLOWLIST below — rather than a silent
// pass-through of whatever the operator's config.json happens to hold.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');
const nodeZlib = require('node:zlib');
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

// The only config fields permitted into the bundle. Anything not listed is
// dropped — adding a field here is the deliberate opt-in the allowlist
// contract (see module header) requires. Identifying / path-bearing fields
// (server, syncFolder, mtls paths, bundleId/shareId, ignore/include patterns)
// are reduced below to a non-identifying form before they land in the bundle.
const CONFIG_ALLOWLIST = [
  'logLevel',
  'autoUpdate',
  'autoUpdateChannel',
  'maxFileSize',
  'uploadConcurrency',
  'uploadBytesPerSec',
  'downloadBytesPerSec',
];

// Reduce a configured filesystem path to its basename so the OS username and
// home-dir layout never leave the host. `null` for an absent value.
function _basenameOrNull(p) {
  if (typeof p !== 'string' || p.length === 0) return null;
  try { return nodePath.basename(p); } catch { return null; }
}

function _redactedConfig() {
  const cfg = _readJsonIfPresent(CONFIG_FILE);
  if (!cfg) return { _absent: true, path: CONFIG_FILE };

  // Allowlist projection — pass through only the non-identifying tuning knobs
  // verbatim; everything else is either dropped or reduced to a non-
  // identifying form. A denylist-redact would silently leak any future field
  // that happens not to match a redact rule (a home-dir path, a hostname);
  // an allowlist makes every new field a deliberate opt-in.
  const out = {};
  for (const key of CONFIG_ALLOWLIST) {
    if (cfg[key] !== undefined) out[key] = cfg[key];
  }

  // server → host:port only, with userinfo stripped defensively. b.safeUrl
  // refuses a credentialed authority, so a server URL that somehow carried
  // user:pass@ surfaces as the safe `_invalid` marker rather than leaking it.
  if (typeof cfg.server === 'string' && cfg.server.length > 0) {
    try {
      out.server = b.safeUrl.parse(cfg.server, { allowedProtocols: ['http:', 'https:'] }).origin;
    } catch {
      out.server = { _invalid: true };
    }
  }

  // Path-bearing fields → basename only (drops the OS username + home-dir
  // layout). The cert's identity + validity is surfaced separately and safely
  // via cert-info.json; here we only confirm the paths are configured.
  out.syncFolder = _basenameOrNull(cfg.syncFolder);
  if (cfg.mtls && typeof cfg.mtls === 'object') {
    out.mtls = {
      cert: _basenameOrNull(cfg.mtls.cert),
      key:  _basenameOrNull(cfg.mtls.key),
      ca:   _basenameOrNull(cfg.mtls.ca),
    };
  } else {
    out.mtls = null;
  }

  // bundleId/shareId → presence only (the values are share secrets / handles).
  out.bundleConfigured = Boolean(cfg.bundleId);
  out.shareConfigured = Boolean(cfg.shareId);

  // Defense-in-depth: run b.redact over the projection so a field added to the
  // allowlist that happens to carry a secret is still masked. This is the
  // backstop, not the primary control — the allowlist + path reduction above
  // is what keeps identifying data out.
  const redacted = b.redact.redact(out);

  // Provably-non-secret integer counts are applied AFTER the redact pass so
  // they survive verbatim. b.redact masks any field whose name contains a
  // sensitive substring ('pin' inside 'pinnedSpki...'), which would otherwise
  // blank a count that carries no secret. The values here are plain integers
  // derived from array lengths — nothing to leak.
  redacted.pinnedServerSpkiCount = Array.isArray(cfg.pinnedServerSpki) ? cfg.pinnedServerSpki.length : 0;
  // ignore/include → counts only. The patterns can embed user paths
  // ('src/secret-project/**'), so ship how many rules exist, not the rules.
  redacted.ignoreCount = Array.isArray(cfg.ignore) ? cfg.ignore.length : 0;
  redacted.includeCount = Array.isArray(cfg.include) ? cfg.include.length : 0;

  return redacted;
}

// Pull the CN out of a node:crypto X509 DN string. `x.subject` / `x.issuer`
// are newline-separated `<attr>=<value>` lines; we want only the CN so an
// enrollment-embedded O / OU / emailAddress never ships. Returns null when no
// CN line is present.
function _cnOf(dn) {
  if (typeof dn !== 'string') return null;
  for (const line of dn.split('\n')) {
    const m = /^CN=(.*)$/.exec(line.trim());
    if (m) return m[1];
  }
  return null;
}

function _certInfo(cfg) {
  if (!cfg || !cfg.mtls || !cfg.mtls.cert) return { _absent: true };
  const certPath = cfg.mtls.cert;
  if (!nodeFs.existsSync(certPath)) return { _absent: true, path: nodePath.basename(certPath) };
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
    // Emit the CN only, not the full DN, and drop subjectAltName entirely.
    // Enrollment embeds the operator's email / hostname into the SAN (and
    // sometimes the O / emailAddress DN attributes); the CN plus the
    // serial / fingerprint / SPKI pin is enough to identify the cert for
    // support without shipping that PII into a handoff bundle.
    return {
      subjectCN:      _cnOf(x.subject),
      issuerCN:       _cnOf(x.issuer),
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
  // The b.logStream local sink keeps the active file as <prefix>.log and
  // rotates to <prefix>-<UTC-timestamp>.log.gz. Pick up everything matching
  // the base prefix that lives in CONFIG_DIR — the startsWith(base) match
  // below already enumerates both the active file and the timestamped
  // rotations.
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

// Shortest config value treated as a scrubbable secret literal. A floor keeps
// a short/empty value (e.g. a one-char placeholder) from blank-replacing
// unrelated bytes across the whole log.
const MIN_SECRET_LITERAL_LEN = 'aaaaaaaa'.length; // eight-char floor

// Secret literals known from the operator's config.json — the raw apiKey and
// apiKeyRef. These are scrubbed verbatim from log content at bundle time as a
// targeted backstop: b.redact masks sensitive-named FIELDS and whole-URL
// tokens, but a secret pasted into a free-form log message (a debug line, an
// error from a third-party lib) is plain text b.redact won't recognise. We
// know these exact values, so we can guarantee they don't survive into the
// bundle regardless of how they appear.
function _knownSecretLiterals() {
  const out = [];
  try {
    const cfg = _readJsonIfPresent(CONFIG_FILE);
    if (cfg) {
      for (const v of [cfg.apiKey, cfg.apiKeyRef, cfg.token, cfg.password]) {
        if (typeof v === 'string' && v.length >= MIN_SECRET_LITERAL_LEN && !out.includes(v)) out.push(v);
      }
    }
  } catch { /* allow:silent-catch — no readable config means no literals to scrub */ }
  return out;
}

// Re-redact a UTF-8 log line. The framework redacts at EMIT time, but a value
// already on disk was written before any rule that would catch it, so we
// re-run b.redact over the bytes at bundle time. Each line is a JSON record
// ({ts,level,message,meta}); we re-redact the structured object (field-based —
// catches a sensitive-named meta field) and the free-form `message` value
// (value-based — catches a whole-URL token), then scrub any known config
// secret literal. A line that doesn't parse as JSON falls back to a plain
// string redact + literal scrub.
function _redactLogLine(line, secretLiterals) {
  let redacted;
  let obj = null;
  try { obj = b.safeJson.parse(line, { maxBytes: C.BYTES.mib(2) }); } catch { obj = null; }
  if (obj && typeof obj === 'object') {
    const r = b.redact.redact(obj);
    if (r && typeof r.message === 'string') r.message = b.redact.redact(r.message);
    redacted = JSON.stringify(r);
  } else {
    redacted = b.redact.redact(line);
  }
  for (const lit of secretLiterals) {
    if (redacted.includes(lit)) redacted = redacted.split(lit).join('[REDACTED]');
  }
  return redacted;
}

// Re-redact an entire log file's bytes. Transparently handles the gzipped
// rotations the framework writes (<prefix>-<ts>.log.gz): decompress, redact
// line-by-line, recompress so the bundle entry stays the same shape it would
// have without redaction. A decode/decompress failure returns null so the
// caller skips the file rather than shipping un-redacted bytes.
function _redactLogBuffer(buf, isGzip, secretLiterals) {
  let text;
  try {
    const raw = isGzip ? nodeZlib.gunzipSync(buf) : buf;
    text = raw.toString('utf8');
  } catch { return null; }
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length === 0) continue; // preserve the trailing blank line
    lines[i] = _redactLogLine(lines[i], secretLiterals);
  }
  const outText = lines.join('\n');
  const outBuf = Buffer.from(outText, 'utf8');
  return isGzip ? nodeZlib.gzipSync(outBuf) : outBuf;
}

function _info() {
  return {
    version:                   VERSION,
    node:                      process.version,
    platform:                  process.platform,
    arch:                      process.arch,
    pid:                       process.pid,
    // Basename only — the full cwd / configDir carry the OS username and
    // home-dir layout the bundle contract lists as out-of-scope.
    cwd:                       _basenameOrNull(process.cwd()),
    configDir:                 _basenameOrNull(CONFIG_DIR),
    blamejsVendoredVersion:    _vendoredBlamejsVersion(),
    sea:                       Boolean(process.execArgv.length === 0 && /hermitstash-sync/.test(process.execPath)),
    generatedAt:               new Date().toISOString(),
  };
}

function _stateDbSchema() {
  // Reuse the live daemon's handle if one is already open in this
  // process; otherwise open our own with recovery: 'refuse'. The support
  // tool must never rename-and-recreate the DB it is collecting — the
  // daemon may still hold it open, and a corrupt file is itself the
  // diagnostic signal the operator needs to attach to the ticket. With
  // 'refuse', a corrupt DB throws localdb-thin/corrupt, the catch below
  // records it as { error } in state-db-schema.json, and the file on
  // disk is left untouched. Close our handle after if we were the opener.
  let opened = false;
  try {
    if (!nodeFs.existsSync(STATE_DB_FILE)) return { _absent: true, path: STATE_DB_FILE };
    try { stateDb.db(); } catch { stateDb.open(undefined, { recovery: 'refuse' }); opened = true; }
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

  // Re-redact log content at bundle time. Emit-time redaction can't catch a
  // value that was written to disk before a matching rule existed, so we
  // re-run b.redact over every included line (and scrub any known config
  // secret literal) before the bytes land in the bundle. A file that fails to
  // decode/decompress is skipped rather than shipped un-redacted.
  const secretLiterals = _knownSecretLiterals();
  const logCap = C.BYTES.mib(50);
  for (const entry of _logFiles()) {
    if (entry.size > logCap) continue; // skip pathological log files
    try {
      const raw = nodeFs.readFileSync(entry.abs);
      const isGzip = entry.name.endsWith('.gz');
      const redacted = _redactLogBuffer(raw, isGzip, secretLiterals);
      if (redacted === null) continue; // undecodable → drop rather than leak
      zip.addFile('log/' + entry.name, redacted);
    } catch { /* allow:silent-catch — best-effort log inclusion */ }
  }

  const buf = zip.toBuffer();
  nodeFs.writeFileSync(outPath, buf, { mode: 0o600 });
  return { path: outPath, entryCount: zip.entryCount, sizeBytes: buf.length };
}

function defaultOutPath() {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  return nodePath.join(process.cwd(), `hermitstash-sync-diagnose-${ts}.zip`);
}

module.exports = { buildBundle, defaultOutPath };
