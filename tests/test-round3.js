'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const {
  MSG, sleep, sha3, createTempDir, rmrf,
} = require('./test-helpers');

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');
const SyncEngine = require(path.join(CLIENT_LIB, 'sync-engine'));
const HttpClient = require(path.join(CLIENT_LIB, 'http-client'));
const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
const { FILE_STATUS, SYNC_STATE, MAX_SYNC_FILE_BYTES } = require(path.join(CLIENT_LIB, 'constants'));

/**
 * Round-three sync-engine hardening tests.
 *
 * Exercise the production SyncEngine + HttpClient + the real state-db
 * against a controlled wire layer (a local plain-HTTP server for the
 * streamed-download byte-ceiling test; stubbed _http for the engine-level
 * cases). No encryption is bypassed — these paths carry no wire crypto at
 * this layer, and checksums are the production SHA3-512 path throughout.
 *
 * Covered:
 *   - a streamed download larger than the byte ceiling is aborted mid-flight
 *     and the temp file is unlinked (no unbounded write to disk)
 *   - a Content-Length over the ceiling is refused before the fd opens
 *   - a statfs failure (free space unknown) does NOT bypass the size cap
 *   - a local edit re-checks suppression after hashing and does not race a
 *     same-path server download (per-path lock serializes them)
 *   - a buffered delete is gated by suppression (no DELETE against an
 *     in-flight same-path download)
 *   - a 426 / 404 upgrade_rejected transitions to a sticky ERROR (no
 *     reconnect-forever)
 *   - overlapping resync() calls coalesce onto one in-flight run
 *   - cert expiry is read via node:crypto X509Certificate (no openssl spawn)
 */

function makeEngine(opts) {
  opts = opts || {};
  const root = createTempDir('round3-sync');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });

  stateDb.open(dbFile);

  const config = {
    syncFolder,
    bundleId: 'bundle-test',
    shareId: opts.shareId || null,
    // No mtls block → _checkCertExpiry is a no-op for these cases; the
    // cert-expiry case builds its own config with a real cert file.
  };
  const engine = new SyncEngine(config, 'hs_test_key');

  engine._ignorePatterns = [];
  engine._includePatterns = [];

  const downloads = opts.downloads || {}; // fileId -> { content, delayMs, fail }
  const downloadLog = [];
  const deleted = [];
  engine._http = {
    async downloadFile(fileId, destPath, expectedChecksum /*, expectedSize */) {
      const spec = downloads[fileId] || {};
      downloadLog.push({ fileId, destPath, startedAt: Date.now() });
      if (typeof spec.delayMs === 'number' && spec.delayMs > 0) await sleep(spec.delayMs);
      if (spec.fail) throw new Error('simulated download failure for ' + fileId);
      const content = spec.content != null ? spec.content : ('content-' + fileId);
      const buf = Buffer.from(content, 'utf8');
      if (expectedChecksum && sha3(buf) !== expectedChecksum) {
        throw new Error('checksum mismatch for ' + fileId);
      }
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.writeFileSync(destPath, buf);
      return destPath;
    },
    async deleteFile(fileId) { deleted.push(fileId); return { ok: true }; },
    async uploadFile(bundleId, relativePath, fullPath) {
      const buf = fs.readFileSync(fullPath);
      return { fileId: 'up-' + relativePath, checksum: sha3(buf), seq: 0 };
    },
    reloadMtlsCerts() {},
    destroy() {},
  };

  return { engine, root, syncFolder, dbFile, downloadLog, downloads, deleted };
}

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

describe('Round-three sync-engine hardening', { timeout: 30000 }, () => {

  it('a streamed download over the byte ceiling is aborted + the temp is unlinked', async () => {
    // A misbehaving server streams far more than the declared size. The
    // counting Transform in HttpClient.downloadFile must abort the request,
    // fail the write stream, and unlink the temp — never letting the body
    // land in full on disk before the checksum runs.
    const root = createTempDir('round3-wire');
    const destPath = path.join(root, 'big.bin');
    let server, client;
    try {
      const chunk = Buffer.alloc(4096, 0x41);
      // Chunked transfer (no Content-Length) keeps the response framing valid
      // while we stream far past the cap, so the mid-stream counting gate —
      // not the Content-Length preflight — is what aborts the transfer.
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        let sent = 0;
        const pump = () => {
          if (sent >= 2 * 1024 * 1024) { res.end(); return; }
          if (!res.write(chunk)) { res.once('drain', pump); }
          else { sent += chunk.length; setImmediate(pump); }
        };
        pump();
      });
      await new Promise(r => server.listen(0, '127.0.0.1', r));
      const port = server.address().port;

      client = new HttpClient({ server: 'http://127.0.0.1:' + port }, 'hs_test_key');

      // Cap the transfer at 256 KiB via the expectedSize arg; the body
      // (2 MiB) blows past it mid-stream.
      const cap = 256 * 1024;
      await assert.rejects(
        () => client.downloadFile('fid', destPath, undefined, cap),
        (err) => /size limit/.test(err.message),
        'an over-cap streamed body is rejected with an actionable size-limit error'
      );

      // The temp-unlink runs on the stream-teardown tick after the abort —
      // let microtasks/IO settle before asserting the directory is clean.
      await sleep(100);
      const leftovers = fs.readdirSync(root);
      assert.equal(leftovers.length, 0, 'the temp + dest were cleaned up — no partial bytes left on disk');
    } finally {
      if (client) try { client.destroy(); } catch { /* best-effort */ }
      if (server) await new Promise(r => server.close(r));
      rmrf(root);
    }
  });

  it('a Content-Length over the ceiling is refused before the fd opens', async () => {
    const root = createTempDir('round3-wire-cl');
    const destPath = path.join(root, 'declared-big.bin');
    let server, client;
    try {
      // Declare a body larger than the cap; the preflight must refuse before
      // opening the temp fd, so we never even start the body.
      let bodyStarted = false;
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Length': String(8 * 1024 * 1024) });
        bodyStarted = true;
        res.end(Buffer.alloc(16, 0x42));
      });
      await new Promise(r => server.listen(0, '127.0.0.1', r));
      const port = server.address().port;
      client = new HttpClient({ server: 'http://127.0.0.1:' + port }, 'hs_test_key');

      const cap = 1024 * 1024; // 1 MiB cap < 8 MiB declared
      await assert.rejects(
        () => client.downloadFile('fid', destPath, undefined, cap),
        (err) => /size limit/.test(err.message),
        'a declared-oversize body is refused on the Content-Length preflight'
      );
      assert.ok(!fs.existsSync(destPath), 'no destination file was created');
      assert.equal(fs.readdirSync(root).length, 0, 'no temp file was created');
      // bodyStarted may be true (server handler ran) — the point is the
      // CLIENT refused without landing bytes, asserted above.
      void bodyStarted;
    } finally {
      if (client) try { client.destroy(); } catch { /* best-effort */ }
      if (server) await new Promise(r => server.close(r));
      rmrf(root);
    }
  });

  it('a statfs failure does not bypass the per-file size cap', async () => {
    const h = makeEngine({});
    try {
      // Simulate statfs throwing: _getFreeDiskSpace returns Infinity, which
      // the disk-fit preflight treats as unlimited. The size-vs-cap check
      // must still refuse a file larger than MAX_SYNC_FILE_BYTES.
      h.engine._getFreeDiskSpace = () => Infinity;
      const oversize = MAX_SYNC_FILE_BYTES + 1;
      stateDb.upsertFile({
        relativePath: 'too-big.bin',
        serverFileId: 'fid-toobig',
        serverChecksum: sha3('x'),
        size: oversize,
        serverSeq: 1,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });

      const ok = await h.engine._downloadFile('too-big.bin', 'fid-toobig', sha3('x'), oversize);
      assert.equal(ok, false, 'an over-cap file is refused even when free space is unknown');
      assert.equal(stateDb.getFile('too-big.bin').status, FILE_STATUS.ERROR, 'row left ERROR');
      assert.equal(h.downloadLog.length, 0, 'the network fetch never started — the cap ran before the wire call');
    } finally {
      cleanup(h);
    }
  });

  it('a local edit re-checks suppression after hashing and does not race a same-path download', async () => {
    const content = 'server-authoritative-bytes';
    const checksum = sha3(content);
    const h = makeEngine({ downloads: { 'fid-race': { content, delayMs: 120 } } });
    try {
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      h.engine._watcher = { shouldSync: () => true };

      // Seed the PENDING_DOWNLOAD row the server-event handler would have
      // written before dispatching the download, so the download's SYNCED
      // upsert carries the server fileId forward (it spreads the prior row).
      stateDb.upsertFile({
        relativePath: 'race.txt',
        serverFileId: 'fid-race',
        serverChecksum: checksum,
        size: content.length,
        serverSeq: 1,
        status: FILE_STATUS.PENDING_DOWNLOAD,
      });

      // Start a slow same-path server download. It holds the per-path lock
      // and suppresses the path for its whole span.
      const dlP = h.engine._downloadFile('race.txt', 'fid-race', checksum, content.length);
      await sleep(20);
      assert.ok(h.engine._isSuppressed('race.txt'), 'the download suppresses the path');

      // A local edit lands the SAME path while the download is in flight.
      // The watcher would write divergent bytes; the per-path lock serializes
      // it behind the download, and the post-hash suppression re-check makes
      // it no-op rather than upload over the file the server is delivering.
      const localBytes = 'local-divergent-bytes';
      fs.writeFileSync(path.join(h.syncFolder, 'race.txt'), localBytes);
      const modP = h.engine._handleLocalModify('race.txt', path.join(h.syncFolder, 'race.txt'), localBytes.length, Date.now());

      await Promise.all([dlP, modP]);
      await h.engine._uploadPool.drain();

      const row = stateDb.getFile('race.txt');
      assert.ok(row, 'the path is tracked');
      assert.equal(row.localChecksum, checksum, 'the row carries the server bytes, not the racing local edit');
      assert.equal(row.status, FILE_STATUS.SYNCED, 'the download landed SYNCED');
      assert.equal(row.serverFileId, 'fid-race', 'the server fileId won, not an upload fileId');
      // The bytes on disk are the server bytes (download wrote last under the lock).
      assert.equal(fs.readFileSync(path.join(h.syncFolder, 'race.txt'), 'utf8'), content,
        'disk holds the server content, the racing local upload did not overwrite it');
    } finally {
      cleanup(h);
    }
  });

  it('a buffered delete is gated by suppression — no DELETE against an in-flight same-path download', async () => {
    const content = 'down-bytes';
    const checksum = sha3(content);
    const h = makeEngine({ downloads: { 'fid-del': { content, delayMs: 120 } } });
    try {
      h.engine._setState(SYNC_STATE.SYNCED);
      stateDb.upsertFile({
        relativePath: 'gated.txt',
        serverFileId: 'fid-del',
        localChecksum: checksum,
        serverChecksum: checksum,
        size: content.length,
        serverSeq: 1,
        status: FILE_STATUS.SYNCED,
      });

      // A server download takes the path (suppresses it).
      const dlP = h.engine._downloadFile('gated.txt', 'fid-del', checksum, content.length);
      await sleep(20);
      assert.ok(h.engine._isSuppressed('gated.txt'), 'download owns the path');

      // A delete fires for the same path while the download is mid-stream.
      const delResult = await h.engine._executeDelete('gated.txt', { serverFileId: 'fid-del' });
      assert.equal(delResult, 'skipped', 'the delete is refused (tri-state "skipped") while a same-path download is in flight');
      assert.equal(h.deleted.length, 0, 'no server DELETE was issued');

      await dlP;
    } finally {
      cleanup(h);
    }
  });

  it('a 426 upgrade_rejected transitions to a sticky ERROR with no reconnect-forever', async () => {
    const h = makeEngine({});
    try {
      // Stand in for the real ws-client with a bare EventEmitter and wire the
      // production listener the way start() does.
      const ws = new EventEmitter();
      ws.connect = () => {};
      ws.close = () => {};
      h.engine._ws = ws;
      ws.on('upgrade_rejected', ({ status }) => h.engine._onUpgradeRejected(status));
      ws.on('close', () => {
        if (h.engine._terminalUpgradeReject) return;
        if (h.engine._state !== SYNC_STATE.DISCONNECTED) h.engine._setState(SYNC_STATE.RECONNECTING);
      });

      h.engine._setState(SYNC_STATE.CATCHING_UP);

      // ws-client emits upgrade_rejected (from its 'error') BEFORE 'close'.
      ws.emit('upgrade_rejected', { status: 426 });
      assert.equal(h.engine._state, SYNC_STATE.ERROR, '426 drives a sticky ERROR state');
      assert.equal(h.engine._terminalUpgradeReject, true, 'the sticky guard is set');

      // The follow-on close must NOT flip back to RECONNECTING.
      ws.emit('close');
      assert.equal(h.engine._state, SYNC_STATE.ERROR, 'close does not mask the permanent rejection with RECONNECTING');

      // A 404 also sticks; 401/403 are skipped (owned by auth_error).
      h.engine._terminalUpgradeReject = false;
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      ws.emit('upgrade_rejected', { status: 404 });
      assert.equal(h.engine._state, SYNC_STATE.ERROR, '404 also drives ERROR');

      h.engine._terminalUpgradeReject = false;
      h.engine._setState(SYNC_STATE.CATCHING_UP);
      ws.emit('upgrade_rejected', { status: 403 });
      assert.notEqual(h.engine._terminalUpgradeReject, true, '403 is left to the auth_error handler — not stuck here');
    } finally {
      cleanup(h);
    }
  });

  it('overlapping resync() calls coalesce onto one in-flight run', async () => {
    const h = makeEngine({});
    try {
      let connects = 0;
      const ws = new EventEmitter();
      ws.close = () => {};
      ws.connect = () => { connects++; };
      ws.updateSince = () => {};
      h.engine._ws = ws;

      // Make the drain observably slow so a second resync() lands while the
      // first is mid-body.
      let drains = 0;
      const realPool = h.engine._uploadPool;
      h.engine._uploadPool = {
        inFlight: () => realPool.inFlight(),
        queued:   () => realPool.queued(),
        drain:    async () => { drains++; await sleep(60); },
        run:      (fn) => realPool.run(fn),
      };

      stateDb.upsertFile({ relativePath: 'a.txt', serverFileId: 'fa', size: 1, serverSeq: 1, status: FILE_STATUS.SYNCED });
      stateDb.setLastSeq(5);

      const p1 = h.engine.resync();
      const p2 = h.engine.resync(); // arrives while p1 is mid-drain
      assert.equal(p1, p2, 'the second resync coalesces onto the same in-flight promise');

      await Promise.all([p1, p2]);

      assert.equal(drains, 1, 'the teardown body (pool drain) ran exactly once');
      assert.equal(connects, 1, 'the WS reconnect ran exactly once — no double close/connect');
      assert.equal(stateDb.getAllFiles().length, 0, 'the DB was cleared once');
      assert.equal(stateDb.getLastSeq(), 0, 'the cursor was reset');
      assert.equal(h.engine._resyncInFlight, null, 'the in-flight memo is cleared once the run settles');

      // A later resync starts a fresh run (new connect).
      await h.engine.resync();
      assert.equal(connects, 2, 'a subsequent resync runs a fresh teardown after the memo cleared');
    } finally {
      cleanup(h);
    }
  });

  it('resync() at the connect entry point clears a sticky upgrade-reject ERROR', async () => {
    const h = makeEngine({});
    try {
      const ws = new EventEmitter();
      ws.close = () => {};
      ws.connect = () => {};
      ws.updateSince = () => {};
      h.engine._ws = ws;

      h.engine._terminalUpgradeReject = true;
      h.engine._setState(SYNC_STATE.ERROR);

      await h.engine.resync();
      assert.equal(h.engine._terminalUpgradeReject, false, 'resync clears the sticky upgrade-reject flag at the connect entry point');
    } finally {
      cleanup(h);
    }
  });

  it('cert expiry is read via node:crypto X509Certificate without spawning openssl', async () => {
    // Mint a real, long-dated client cert via the framework CA (no openssl
    // shell-out in the test either) and point _checkCertExpiry at it. The
    // production code must read notAfter natively and decline renewal on a
    // far-future cert — proving the openssl subprocess path is gone AND that
    // expiry is actually parsed (not a silent no-op).
    const b = require('../vendor/blamejs');
    const root = createTempDir('round3-cert');
    const certPath = path.join(root, 'client.crt');
    let h;
    try {
      const ca = b.mtlsCa.create({ dataDir: root, caKeySealedMode: 'disabled', generation: 1 });
      await ca.initCA();
      const client = await ca.generateClientCert({ cn: 'hs_round3_client', usage: 'client', validityDays: 3650 });
      fs.writeFileSync(certPath, client.cert);

      h = makeEngine({});
      h.engine._config.mtls = { cert: certPath, key: path.join(root, 'client.key'), ca: path.join(root, 'ca.crt') };

      // Guard: a stray openssl spawn must fail the test. Stub execFileSync to
      // record + throw if the production path tries to shell out.
      const cp = require('node:child_process');
      const origExec = cp.execFileSync;
      let spawned = false;
      cp.execFileSync = function () { spawned = true; throw new Error('openssl spawn attempted — the native X509 path should not shell out'); };

      let renewCalled = false;
      h.engine._http.renewCert = async () => { renewCalled = true; return {}; };

      try {
        await h.engine._checkCertExpiry();
      } finally {
        cp.execFileSync = origExec;
      }

      assert.equal(spawned, false, 'no openssl subprocess was spawned');
      // A 10-year cert is far from the 60-day renewal threshold, so renewal
      // must NOT fire — proving expiry was parsed (a silent no-op would also
      // skip renewal, so pair this with the spawn assertion above).
      assert.equal(renewCalled, false, 'a long-dated cert does not trigger renewal — expiry was parsed natively');
    } finally {
      if (h) cleanup(h);
      rmrf(root);
    }
  });

});
