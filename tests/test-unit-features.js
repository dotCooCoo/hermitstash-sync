'use strict';

// Unit regression tests for library features that don't need the server
// harness: config validation, path matcher, SPKI pin shape, env-overlay,
// recursive temp-file cleanup, and the sync-cursor advance on dropped
// (path-traversal) server events. Server-driven paths (parallel uploads
// against multipart endpoints, SIGHUP reload over a running engine) live in
// the integration suites.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');

const pathFilter = require('../lib/path-filter');
const config = require('../lib/config');
const SyncEngine = require('../lib/sync-engine');
const logger = require('../lib/logger');
const b = require('../vendor/blamejs');

// Quiet the engine's structured logger (its server-event handlers log) so unit
// runs don't spew to the console; mirrors the harness's logger setup.
logger.init({ level: 'error', stdout: false, file: nodePath.join(nodeOs.tmpdir(), 'hs-unit-' + process.pid + '.log') });

describe('Selective sync — path-filter', () => {
  it('empty include = sync everything', () => {
    assert.equal(pathFilter.shouldSync('any/path.txt', {}), true);
    assert.equal(pathFilter.shouldSync('deeply/nested/file.bin', {}), true);
  });

  it('include=[work/**] gates correctly', () => {
    const o = { include: ['work/**'] };
    assert.equal(pathFilter.shouldSync('work/x.txt', o), true);
    assert.equal(pathFilter.shouldSync('work/sub/y.txt', o), true);
    assert.equal(pathFilter.shouldSync('photos/x.txt', o), false);
    assert.equal(pathFilter.shouldSync('work', o), true);
  });

  it('ignore takes precedence over include', () => {
    const o = { include: ['work/**'], ignore: ['*.log'] };
    assert.equal(pathFilter.shouldSync('work/x.txt', o), true);
    assert.equal(pathFilter.shouldSync('work/x.log', o), false);
  });

  it('basename-anywhere ignore (e.g. .DS_Store)', () => {
    const o = { ignore: ['.DS_Store'] };
    assert.equal(pathFilter.shouldSync('.DS_Store', o), false);
    assert.equal(pathFilter.shouldSync('foo/bar/.DS_Store', o), false);
    assert.equal(pathFilter.shouldSync('foo/.DS_Storef', o), true);
  });

  it('windows backslash paths normalize', () => {
    const o = { include: ['work/**'] };
    assert.equal(pathFilter.shouldSync('work\\sub\\x.txt', o), true);
  });
});

describe('Conflict-path builder (b.atomicFile.conflictPath)', () => {
  it('preserves extension', () => {
    const p = b.atomicFile.conflictPath('/tmp/notes.md');
    assert.ok(p.endsWith('.md'), `expected .md suffix, got ${p}`);
    assert.ok(p.includes('.conflict-'), `expected '.conflict-' marker, got ${p}`);
  });

  it('Windows-safe timestamp (no colons in filename)', () => {
    const p = b.atomicFile.conflictPath('/tmp/file.txt');
    const filename = nodePath.basename(p);
    assert.ok(!filename.includes(':'), `colon in filename: ${filename}`);
  });
});

describe('Promise pool (b.promisePool)', () => {
  it('concurrency cap holds under burst', async () => {
    const pool = b.promisePool.create({ concurrency: 4 });
    let inFlight = 0, peak = 0;
    const tasks = Array.from({ length: 30 }, () =>
      pool.run(async () => {
        inFlight++; peak = Math.max(peak, inFlight);
        await new Promise(r => setTimeout(r, 10));
        inFlight--;
      })
    );
    await Promise.all(tasks);
    assert.equal(peak, 4, `expected peak concurrency 4, got ${peak}`);
  });

  it('drain waits for in-flight', async () => {
    const pool = b.promisePool.create({ concurrency: 2 });
    let done = 0;
    pool.run(async () => { await new Promise(r => setTimeout(r, 30)); done++; });
    pool.run(async () => { await new Promise(r => setTimeout(r, 30)); done++; });
    await pool.drain();
    assert.equal(done, 2);
    assert.equal(pool.inFlight(), 0);
  });
});

describe('Stream throttle (b.streamThrottle)', () => {
  it('shares budget across concurrent consumers', async () => {
    const { Readable, PassThrough } = require('node:stream');
    // burstBytes default = bytesPerSec, so the bucket gives a 1-second
    // freebie on first hit. To prove SHARED behaviour rather than
    // burst behaviour, push 4× the rate through 2 streams: 8 KB total
    // at 2 KB/s shared should take ~3s (1s burst absorbs first 2 KB,
    // remaining 6 KB at 2 KB/s = 3s). Per-stream-rate would give ~1.5s.
    const t = b.streamThrottle.create({ bytesPerSec: 2048 });
    const t0 = Date.now();
    const pipeOne = () => new Promise(r => {
      const src = Readable.from([Buffer.alloc(4096)]);
      const sink = new PassThrough();
      sink.resume();
      src.pipe(t.transform({ allowOversize: true })).pipe(sink).on('finish', r);
    });
    await Promise.all([pipeOne(), pipeOne()]);
    const elapsed = Date.now() - t0;
    // 8 KB total, 1 KB burst, 6 KB / (2 KB/s) = 3s. Guard a 2.5s floor
    // (regression to per-stream rate would land near 1.5s).
    assert.ok(elapsed > 2500, `expected ~3000ms for shared budget, got ${elapsed}ms`);
  });
});

describe('Config validation', () => {
  function _baseCfg(overrides) {
    const tmp = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-cfg-'));
    return Object.assign({
      server:     'https://localhost:3443',
      bundleId:   'abc123',
      shareId:    '',
      syncFolder: tmp,
      mtls:       null,
    }, overrides || {});
  }

  it('clean config produces no errors', () => {
    const errs = config.validate(_baseCfg());
    assert.deepEqual(errs, []);
  });

  it('uploadConcurrency must be non-negative integer', () => {
    assert.ok(config.validate(_baseCfg({ uploadConcurrency: -1 })).some(e => e.includes('uploadConcurrency')));
    assert.ok(config.validate(_baseCfg({ uploadConcurrency: 'four' })).some(e => e.includes('uploadConcurrency')));
    assert.deepEqual(config.validate(_baseCfg({ uploadConcurrency: 0 })), []);
    assert.deepEqual(config.validate(_baseCfg({ uploadConcurrency: 16 })), []);
  });

  it('uploadBytesPerSec + downloadBytesPerSec ditto', () => {
    assert.ok(config.validate(_baseCfg({ uploadBytesPerSec: -100 })).some(e => e.includes('uploadBytesPerSec')));
    assert.ok(config.validate(_baseCfg({ downloadBytesPerSec: 1.5 })).some(e => e.includes('downloadBytesPerSec')));
    assert.deepEqual(config.validate(_baseCfg({ uploadBytesPerSec: 0 })), []);
    assert.deepEqual(config.validate(_baseCfg({ downloadBytesPerSec: 1048576 })), []);
  });

  it('autoUpdateChannel must be stable | beta', () => {
    assert.ok(config.validate(_baseCfg({ autoUpdateChannel: 'nightly' })).some(e => e.includes('autoUpdateChannel')));
    assert.deepEqual(config.validate(_baseCfg({ autoUpdateChannel: 'stable' })), []);
    assert.deepEqual(config.validate(_baseCfg({ autoUpdateChannel: 'beta' })), []);
  });

  it('include / ignore must be arrays of strings', () => {
    assert.ok(config.validate(_baseCfg({ include: 'work/**' })).some(e => e.includes('include')));
    assert.ok(config.validate(_baseCfg({ ignore: ['*.log', 42] })).some(e => e.includes('ignore[1]')));
    assert.deepEqual(config.validate(_baseCfg({ include: ['work/**'], ignore: ['*.log'] })), []);
  });

  it('pinnedServerSpki must match sha256/<43-char-base64>= shape', () => {
    assert.ok(config.validate(_baseCfg({ pinnedServerSpki: ['sha1/badhash'] })).some(e => e.includes('pinnedServerSpki')));
    assert.ok(config.validate(_baseCfg({ pinnedServerSpki: 'sha256/abc=' })).some(e => e.includes('pinnedServerSpki')));
    // 43-char base64 = 256 bits, the SHA-256 length
    const validPin = 'sha256/' + 'a'.repeat(43) + '=';
    assert.deepEqual(config.validate(_baseCfg({ pinnedServerSpki: [validPin] })), []);
  });

  it('logLevel must be one of debug/info/warn/error', () => {
    assert.ok(config.validate(_baseCfg({ logLevel: 'verbose' })).some(e => e.includes('logLevel')));
    assert.deepEqual(config.validate(_baseCfg({ logLevel: 'debug' })), []);
  });

  it('server URL must validate', () => {
    assert.ok(config.validate(_baseCfg({ server: 'not-a-url' })).some(e => e.includes('not a valid URL')));
  });

  it('bundleId OR shareId required', () => {
    assert.ok(config.validate(_baseCfg({ bundleId: '', shareId: '' })).some(e => e.includes('bundleId or shareId')));
  });
});

describe('SPKI pin computation (from a real cert)', () => {
  it('computes a sha256/<base64> pin from a self-signed cert', () => {
    // Generate a one-off P-256 key + cert pair via openssl, compute
    // the pin via our code path, verify the shape.
    const { execFileSync } = require('node:child_process');                       // allow:inline-require — test-only, openssl is the lingua franca for cert ops
    const tmp = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-spki-'));
    const keyPath  = nodePath.join(tmp, 'k.pem');
    const certPath = nodePath.join(tmp, 'c.pem');
    try {
      execFileSync('openssl', ['ecparam', '-genkey', '-name', 'secp256r1', '-noout', '-out', keyPath], { stdio: 'pipe' });
      execFileSync('openssl', ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '3650', '-subj', '/CN=test'], { stdio: 'pipe' });
    } catch {
      // openssl not available — skip rather than fail. Test farms
      // without it (rare) still pass.
      return;
    }
    const nodeCrypto = require('node:crypto');                                    // allow:inline-require — test-only
    const x = new nodeCrypto.X509Certificate(nodeFs.readFileSync(certPath));
    const spkiDer = x.publicKey.export({ format: 'der', type: 'spki' });
    const pin = 'sha256/' + nodeCrypto.createHash('sha256').update(spkiDer).digest('base64');
    assert.match(pin, /^sha256\/[A-Za-z0-9+/]{43}=$/, `pin shape: ${pin}`);
    // And the pin should validate through our config check.
    assert.deepEqual(config.validate({
      server: 'https://x', bundleId: 'a', syncFolder: tmp,
      pinnedServerSpki: [pin],
    }), []);
  });
});

describe('Recursive temp-file cleanup', () => {
  function withEngine(fn) {
    const tmp = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-tmpclean-'));
    try { fn(new SyncEngine({ syncFolder: tmp }, 'k'), tmp); }
    finally { nodeFs.rmSync(tmp, { recursive: true, force: true }); }
  }

  it('removes .tmp.<hex> files at any depth, keeps real files and decoys', () => {
    withEngine((engine, tmp) => {
      nodeFs.mkdirSync(nodePath.join(tmp, 'sub', 'deep'), { recursive: true });
      const mk = (p) => nodeFs.writeFileSync(nodePath.join(tmp, p), 'x');
      mk('a.txt');                   // keep — real file
      mk('b.tmp.deadbeef');          // delete — root temp
      mk('sub/c.txt');               // keep
      mk('sub/d.tmp.12345678');      // delete — nested temp
      mk('sub/e.tmp.nothexxx');      // keep — suffix not all-hex
      mk('sub/deep/f.tmp.aabbccdd'); // delete — deep temp
      mk('report.tmp.final');        // keep — decoy ("final" is not all-hex)

      engine._cleanupTempFiles();

      const has = (p) => nodeFs.existsSync(nodePath.join(tmp, p));
      assert.equal(has('a.txt'), true);
      assert.equal(has('b.tmp.deadbeef'), false);
      assert.equal(has('sub/c.txt'), true);
      assert.equal(has('sub/d.tmp.12345678'), false);
      assert.equal(has('sub/e.tmp.nothexxx'), true);
      assert.equal(has('sub/deep/f.tmp.aabbccdd'), false);
      assert.equal(has('report.tmp.final'), true);
    });
  });

  it('does not throw when the sync folder is missing', () => {
    const gone = nodePath.join(nodeOs.tmpdir(), 'hs-absent-' + process.pid);
    const engine = new SyncEngine({ syncFolder: gone }, 'k');
    assert.doesNotThrow(() => engine._cleanupTempFiles());
  });
});

describe('Sync cursor advances on dropped (path-traversal) server events', () => {
  function tinyEngine() {
    const tmp = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-wedge-'));
    const engine = new SyncEngine({ syncFolder: tmp }, 'k');
    let advanced = null;
    engine._updateSeq = (s) => { advanced = s; }; // spy: avoids touching the state DB
    return { engine, tmp, seqOf: () => advanced };
  }

  it('file_added with a traversal path still advances seq', async () => {
    const { engine, tmp, seqOf } = tinyEngine();
    await engine._handleFileAdded({ relativePath: '../escape.txt', seq: 7, fileId: 'f', checksum: 'c', size: 1 });
    assert.equal(seqOf(), 7);
    nodeFs.rmSync(tmp, { recursive: true, force: true });
  });

  it('file_replaced with a traversal path still advances seq', async () => {
    const { engine, tmp, seqOf } = tinyEngine();
    await engine._handleFileReplaced({ relativePath: '../escape.txt', seq: 8, fileId: 'f', checksum: 'c', size: 1 });
    assert.equal(seqOf(), 8);
    nodeFs.rmSync(tmp, { recursive: true, force: true });
  });

  it('file_removed with a traversal path still advances seq', async () => {
    const { engine, tmp, seqOf } = tinyEngine();
    await engine._handleFileRemoved({ relativePath: '../escape.txt', seq: 9 });
    assert.equal(seqOf(), 9);
    nodeFs.rmSync(tmp, { recursive: true, force: true });
  });

  it('file_renamed with a traversal path still advances seq', async () => {
    const { engine, tmp, seqOf } = tinyEngine();
    await engine._handleFileRenamed({ oldRelativePath: '../evil.txt', relativePath: 'ok.txt', seq: 10, fileId: 'f', checksum: 'c', size: 1 });
    assert.equal(seqOf(), 10);
    nodeFs.rmSync(tmp, { recursive: true, force: true });
  });
});
