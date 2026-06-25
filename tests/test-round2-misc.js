'use strict';

// Server-independent regression tests for the round-2 hardening:
//   - path-filter: a path-qualified directory pattern WITHOUT a trailing '/**'
//     must exclude its whole subtree (not just the directory inode), and an
//     out-of-grammar pattern must be flagged so config can WARN rather than
//     silently no-op (which would let data through).
//   - diagnose: a secret planted into config.json + the log stream must NOT
//     survive into the built support bundle (the bundle re-redacts at build
//     time and projects config through an allowlist).
//
// path-filter runs in-process. The diagnose test spawns a child with
// HERMITSTASH_SYNC_CONFIG_DIR pointed at a throwaway dir so constants resolve
// CONFIG_FILE / LOG_FILE / STATE_DB_FILE into the temp dir (mirrors
// test-observability.js's isolated-config-dir pattern). No server harness, so
// it joins the parallel pool by filename convention.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const pathFilter = require(path.join(REPO_ROOT, 'lib', 'path-filter.js'));
const config = require(path.join(REPO_ROOT, 'lib', 'config.js'));
const BLAMEJS = path.join(REPO_ROOT, 'vendor', 'blamejs');

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hs-r2-${label}-`));
}

function rmrf(dir) {
  for (let i = 0; i < 5; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true }); return; }
    catch (_e) { const until = Date.now() + 100; while (Date.now() < until) { /* spin */ } }
  }
}

describe('path-filter — path-qualified directory excludes its subtree (R21)', () => {
  it('a path-qualified dir pattern without /** matches the dir AND everything under it', () => {
    const pat = ['src/node_modules'];
    // The directory inode itself.
    assert.equal(pathFilter.isIgnored('src/node_modules', pat), true);
    // Files nested arbitrarily deep under it — the real data-not-excluded bug.
    assert.equal(pathFilter.isIgnored('src/node_modules/left-pad/index.js', pat), true);
    assert.equal(pathFilter.isIgnored('src/node_modules/a/b/c/d.js', pat), true);
  });

  it('only matches at a path-segment boundary (no sibling false positives)', () => {
    const pat = ['src/node_modules'];
    // A sibling file sharing the prefix must NOT be excluded.
    assert.equal(pathFilter.isIgnored('src/node_modules.txt', pat), false);
    assert.equal(pathFilter.isIgnored('src/node_modules-backup/x', pat), false);
  });

  it('does not regress the existing supported shapes', () => {
    assert.equal(pathFilter.isIgnored('a/b/.DS_Store', ['.DS_Store']), true); // basename
    assert.equal(pathFilter.isIgnored('a/b/x.tmp', ['*.tmp']), true);          // ext
    assert.equal(pathFilter.isIgnored('a/b/draft~', ['*~']), true);            // tilde
    assert.equal(pathFilter.isIgnored('node_modules/x/y', ['node_modules/**']), true); // recursive
    assert.equal(pathFilter.isIgnored('a/b/c', ['a/b/c']), true);              // exact
    assert.equal(pathFilter.isIgnored('a/b/keep.txt', ['*.tmp']), false);      // non-match
  });
});

describe('path-filter — classifyPattern flags out-of-grammar shapes (R22)', () => {
  it('classifies the supported grammar branches', () => {
    assert.equal(pathFilter.classifyPattern('.DS_Store'), 'basename');
    assert.equal(pathFilter.classifyPattern('*.tmp'), 'ext');
    assert.equal(pathFilter.classifyPattern('*~'), 'tilde');
    assert.equal(pathFilter.classifyPattern('node_modules/**'), 'recursive-dir');
    assert.equal(pathFilter.classifyPattern('src/node_modules'), 'path-qualified');
  });

  it('flags the silent-no-op set as unsupported', () => {
    for (const p of ['/work/**', 'build/', '*.[oa]', 'file?.txt', '!*.keep', 'work/**/cache', 'temp*', '*', 'a*b']) {
      assert.equal(pathFilter.classifyPattern(p), 'unsupported', `expected '${p}' to be unsupported`);
    }
  });
});

describe('config — warnUnsupportedPatterns WARNs (never throws) on bad shapes (R22)', () => {
  it('warns per unsupported entry with the fail direction, and stays silent on supported ones', () => {
    const warned = [];
    const logStub = { warn: (m) => warned.push(m) };

    const ignoreUnsupported = config.warnUnsupportedPatterns(['build/', '*.tmp', 'node_modules/**'], 'ignore', logStub);
    assert.deepEqual(ignoreUnsupported, ['build/'], 'only the bad ignore pattern is returned');
    assert.equal(warned.length, 1);
    assert.match(warned[0], /build\//);
    assert.match(warned[0], /UPLOADED/, 'an unsupported ignore must warn that the file class will be uploaded');

    warned.length = 0;
    const includeUnsupported = config.warnUnsupportedPatterns(['temp*', 'src/**'], 'include', logStub);
    assert.deepEqual(includeUnsupported, ['temp*']);
    assert.equal(warned.length, 1);
    assert.match(warned[0], /NOT be synced/, 'an unsupported include must warn that files will not sync');
  });

  it('gives shape-specific remediation', () => {
    const warned = [];
    const logStub = { warn: (m) => warned.push(m) };
    config.warnUnsupportedPatterns(['/work/**'], 'ignore', logStub);
    assert.match(warned[0], /drop the leading slash/);
    warned.length = 0;
    config.warnUnsupportedPatterns(['build/'], 'ignore', logStub);
    assert.match(warned[0], /build\/\*\*/, 'trailing-slash dir should suggest the /\\*\\* form');
  });

  it('never throws on a fully-unsupported batch', () => {
    assert.doesNotThrow(() => config.warnUnsupportedPatterns(['/a', 'b/', 'c?', '!d', 'e/**/f'], 'ignore', { warn() {} }));
  });

  it('never throws on a NON-STRING entry, flags it, and keeps processing the batch', () => {
    const warned = [];
    const logStub = { warn: (m) => warned.push(m) };
    let out;
    // A hand-edited config.json `ignore: ["*.log", 123, null, {}]` reaches here
    // via the SIGHUP reload (validate only warns, doesn't strip). classifyPattern
    // reports each non-string as 'unsupported'; _unsupportedPatternHelp must not
    // call a string method on it (the pre-fix TypeError aborted the whole reload).
    assert.doesNotThrow(() => {
      out = config.warnUnsupportedPatterns(['*.log', 123, null, 'node_modules/**'], 'ignore', logStub);
    });
    assert.ok(out.includes(123) && out.includes(null), 'non-string entries are returned as unsupported');
    assert.ok(!out.includes('node_modules/**'), 'a supported pattern after a non-string is still processed (no early abort)');
    assert.ok(warned.some(m => /not a string/i.test(m)), 'a non-string warns with a clear "not a string" message');
  });
});

describe('config — non-boolean autoUpdate is rejected at validate (v0.9.19)', () => {
  // server/syncFolder/bundleId are the required fields; REPO_ROOT is a real dir.
  const base = () => ({ server: 'https://h.example', syncFolder: REPO_ROOT, bundleId: 'b1' });

  it('a quoted "false" / 0 / 1 / null is a load-time error, not a silent self-update-still-on', () => {
    for (const bad of ['false', 0, 1, null]) {
      const errs = config.validate(Object.assign(base(), { autoUpdate: bad }));
      assert.ok(
        errs.some(e => /autoUpdate/i.test(e) && /boolean/i.test(e)),
        `autoUpdate: ${JSON.stringify(bad)} must be rejected with a boolean-type error`
      );
    }
  });

  it('a real boolean (or omission) produces no autoUpdate error', () => {
    for (const ok of [true, false, undefined]) {
      const cfg = base();
      if (ok !== undefined) cfg.autoUpdate = ok;
      const errs = config.validate(cfg);
      assert.ok(!errs.some(e => /autoUpdate\b/i.test(e)), `autoUpdate: ${JSON.stringify(ok)} must not error`);
    }
  });
});

describe('config — getIgnorePatterns/getIncludePatterns drop non-string entries (v0.9.19)', () => {
  it('a non-string ignore entry is dropped so it never reaches the matcher', () => {
    const ig = config.getIgnorePatterns({ ignore: ['*.log', 123, 'foo/**', null] });
    assert.ok(ig.every(p => typeof p === 'string'), 'every returned ignore pattern is a string');
    assert.ok(ig.includes('*.log') && ig.includes('foo/**'), 'valid string patterns survive');
    assert.ok(!ig.includes(123), 'the number entry is dropped');
  });

  it('a non-string include entry is dropped', () => {
    const inc = config.getIncludePatterns({ include: ['Work/**', 42] });
    assert.ok(inc.every(p => typeof p === 'string'), 'every returned include pattern is a string');
    assert.ok(inc.includes('Work/**') && !inc.includes(42), 'string kept, number dropped');
  });
});

// --- diagnose: planted secrets must not survive into the bundle (R26) ---

const DIAGNOSE_CHILD = `
  const fs = require('node:fs');
  const path = require('node:path');
  const b = require(${JSON.stringify(BLAMEJS)});
  const dir = process.env.HERMITSTASH_SYNC_CONFIG_DIR;
  const SECRET = process.env.PLANT_SECRET;
  const APIREF = process.env.PLANT_APIREF;
  const HOMEPATH = process.env.PLANT_HOMEPATH;
  const KEYBYTES = process.env.PLANT_KEYBYTES;

  // 1. config.json with a planted high-entropy apiKey, an apiKeyRef, and
  //    mtls paths under a planted home-dir path.
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
    server: 'https://example.com:8443',
    syncFolder: path.join(HOMEPATH, 'sync'),
    bundleId: 'bundle-abc',
    apiKey: SECRET,
    apiKeyRef: APIREF,
    mtls: { cert: path.join(HOMEPATH, '.hermit', 'client.pem'),
            key:  path.join(HOMEPATH, '.hermit', 'client.key'),
            ca:   path.join(HOMEPATH, '.hermit', 'ca.pem') },
    ignore: ['*.tmp'], include: [], pinnedServerSpki: [], logLevel: 'info',
  }));

  // Plant the mTLS private-key FILE on disk (never to be included).
  fs.mkdirSync(path.join(HOMEPATH, '.hermit'), { recursive: true });
  fs.writeFileSync(path.join(HOMEPATH, '.hermit', 'client.key'), KEYBYTES);

  // 2. Emit log lines through the REAL logger → b.logStream path: the secret
  //    and the planted user path, both as free-form msg AND as metadata.
  const logger = require(${JSON.stringify(path.join(REPO_ROOT, 'lib', 'logger.js'))});
  logger.init({ level: 'info', stdout: false, file: path.join(dir, 'hermitstash-sync.log') });
  logger.info('fetched https://h/x?token=' + SECRET + ' into ' + HOMEPATH, { path: HOMEPATH, apiKey: SECRET });
  logger.warn('free-form secret ' + SECRET + ' and ref ' + APIREF);

  (async () => {
    await logger.close();

    // 4. Build the bundle.
    const diagnose = require(${JSON.stringify(path.join(REPO_ROOT, 'lib', 'diagnose.js'))});
    const zipPath = path.join(dir, 'bundle.zip');
    diagnose.buildBundle(zipPath);

    // 5. Unzip every entry and scan the bytes.
    const reader = b.archive.read.zip(b.archive.adapters.buffer(fs.readFileSync(zipPath)));
    const entries = {};
    for await (const e of reader.extractEntries()) { entries[e.name] = e.bytes; }
    const names = Object.keys(entries);
    let allBytes = Buffer.concat(names.map(n => entries[n]));
    const all = allBytes.toString('latin1');

    const assert = require('node:assert/strict');
    // 5. No planted secret / apiKeyRef anywhere in the bundle.
    assert.equal(all.includes(SECRET), false, 'planted secret token must not survive into any bundle entry');
    assert.equal(all.includes(APIREF), false, 'apiKeyRef must not survive into any bundle entry');
    // 6. The mTLS private-key FILE bytes must never appear.
    assert.equal(all.includes(KEYBYTES), false, 'mTLS private-key bytes must never be in the bundle');
    // The planted home-dir path (OS username / layout) must not leak via config.
    const cfgRedacted = entries['config.redacted.json'].toString('utf8');
    assert.equal(cfgRedacted.includes(HOMEPATH), false, 'home-dir path must not be in config.redacted.json');

    // 7. Pin the contract: cert-info carries DN/SPKI fields but no key material;
    //    config.redacted carries the server but no apiKey; schema has DDL only.
    assert.ok(names.includes('config.redacted.json'));
    assert.ok(names.includes('cert-info.json'));
    assert.ok(names.includes('state-db-schema.json'));
    const certInfo = entries['cert-info.json'].toString('utf8');
    assert.equal(certInfo.includes('PRIVATE KEY'), false, 'cert-info must never carry key material');
    assert.equal(certInfo.includes(KEYBYTES), false);
    // config.redacted ships the server host:port but never the raw apiKey field.
    const parsedCfg = JSON.parse(cfgRedacted);
    assert.equal('apiKey' in parsedCfg, false, 'raw apiKey field must not be projected into the bundle');
    assert.ok(typeof parsedCfg.server === 'string' && parsedCfg.server.includes('example.com'));
    // state-db-schema must be DDL/counts only — no file-table relativePath rows.
    const schema = entries['state-db-schema.json'].toString('utf8');
    assert.equal(schema.includes(HOMEPATH), false, 'state-db schema dump must not contain data rows with user paths');

    console.log('CHILD_OK names=' + names.join(','));
  })().catch(e => { console.error(e && e.stack ? e.stack : e); process.exit(1); });
`;

describe('diagnose — planted secrets do not survive into the bundle (R26)', () => {
  it('builds a bundle free of the planted secret, apiKeyRef, key bytes, and home-dir path', () => {
    const dir = tmpDir('diag');
    const home = path.join(dir, 'home', 'PLANTED-USER');
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(path.join(home, 'sync'), { recursive: true });
    const secret = 'PLANTED-SECRET-' + crypto.randomBytes(20).toString('hex');
    const apiref = 'keychain:planted-' + crypto.randomBytes(8).toString('hex');
    const keyBytes = '-----BEGIN PRIVATE KEY-----\nPLANTED-KEY-' + crypto.randomBytes(24).toString('hex') + '\n-----END PRIVATE KEY-----';
    try {
      const out = execFileSync(process.execPath, ['-e', DIAGNOSE_CHILD], {
        env: Object.assign({}, process.env, {
          HERMITSTASH_SYNC_CONFIG_DIR: dir,
          PLANT_SECRET: secret,
          PLANT_APIREF: apiref,
          PLANT_HOMEPATH: home,
          PLANT_KEYBYTES: keyBytes,
        }),
        encoding: 'utf8',
      });
      assert.match(out, /CHILD_OK/);
    } finally {
      rmrf(dir);
    }
  });
});
