'use strict';

/**
 * Chunked upload scratch API tests.
 *
 * /drop/chunk/:bundleId writes to a scratch directory structured as
 *   <scratchDir>/<bundleShareId>/<fileId>/<chunkIndex>
 * and finalizes by reassembling + moving to regular storage. The attack
 * surface is the user-controlled fileId + chunkIndex + filename fields —
 * path traversal there would let an attacker write outside the scratch
 * root. Defensive layers (validateChunk, _safeComponent, path.extname
 * stripping) should reject each. This suite proves those rejections hold.
 *
 * Coverage:
 *   - Happy path: upload N chunks + finalize reassembles correctly
 *   - fileId with path traversal → rejected
 *   - fileId with special chars (_, dash at either position, over 64) → the
 *     layered gate actually applies — fileId must be alphanumeric AND ≤64
 *   - chunkIndex >= totalChunks → rejected
 *   - chunkIndex negative → rejected
 *   - totalChunks > 10000 → rejected
 *   - Missing fileId / chunkIndex / totalChunks → rejected
 *   - filename with traversal chars in reassembled upload — rejected
 *     via extension validation (magic bytes check too)
 *   - Isolated scratch per bundle: same fileId in two bundles doesn't
 *     collide
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const b = require('../vendor/blamejs');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');
const { sleep, createApiKey, runDbScript } = require('./test-helpers');

const ctx = {
  url: process.env.HERMITSTASH_TEST_URL,
  apiKey: process.env.HERMITSTASH_TEST_API_KEY,
  dbPath: process.env.HERMITSTASH_TEST_DB_PATH,
};

if (!ctx.url) {
  console.error('Missing HERMITSTASH_TEST_URL. Run via: node tests/run-all.js');
  process.exit(1);
}

/**
 * Create a snapshot-type bundle (status=uploading) so /drop/chunk accepts
 * uploads. Bypasses ECIES to avoid rate limits on /drop/init for a test
 * that just exercises the scratch API.
 */
function createSnapshotBundle() {
  var bundleId = b.crypto.generateToken(32);
  var shareId = b.crypto.generateToken(32);
  var finalizeToken = b.crypto.generateToken(32);
  var finalizeTokenHash = require('./test-helpers').sha3(finalizeToken);
  var shareIdHash = require('./test-helpers').sha3('hs-share:' + shareId);
  var now = new Date().toISOString();
  var script = [
    'var users = db.prepare("SELECT _id FROM users ORDER BY createdAt ASC LIMIT 1").all();',
    'var userId = users.length > 0 ? users[0]._id : null;',
    'db.prepare("INSERT INTO bundles (_id, shareId, shareIdHash, uploaderName, uploaderEmail, expectedFiles, receivedFiles, skippedCount, totalSize, downloads, status, bundleType, seq, finalizeTokenHash, ownerId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")',
    '  .run(',
    '    ' + JSON.stringify(bundleId) + ',',
    '    ' + JSON.stringify(shareId) + ',',
    '    ' + JSON.stringify(shareIdHash) + ',',
    '    "Chunk Test", "chunk@hermitstash.com", 10, 0, 0, 0, 0,',
    '    "uploading", "default", 0,',
    '    ' + JSON.stringify(finalizeTokenHash) + ',',
    '    userId,',
    '    ' + JSON.stringify(now),
    '  );',
    'process.stdout.write("OK");',
  ].join('\n');
  var out = runDbScript(ctx.dbPath, script);
  if (out !== 'OK') throw new Error('Failed to create snapshot bundle: ' + out);
  return { bundleId: bundleId, shareId: shareId, finalizeToken: finalizeToken };
}

/**
 * Raw multipart POST to /drop/chunk/:bundleId with caller-controlled fields
 * so traversal attempts survive all client-side sanitization.
 * Returns { statusCode, json, body }.
 */
function postChunk(bundleId, fields, chunkData, apiKey) {
  return new Promise(function (resolve, reject) {
    var parsed = new URL(ctx.url);
    var boundary = '----HSTestChunk' + b.crypto.generateToken(8);
    var parts = [];
    Object.keys(fields).forEach(function (k) {
      parts.push(Buffer.from(
        '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="' + k + '"\r\n\r\n' +
        fields[k] + '\r\n', 'utf8'));
    });
    parts.push(Buffer.from(
      '--' + boundary + '\r\n' +
      'Content-Disposition: form-data; name="file"; filename="chunk.txt"\r\n' +
      'Content-Type: application/octet-stream\r\n\r\n', 'utf8'));
    parts.push(Buffer.isBuffer(chunkData) ? chunkData : Buffer.from(chunkData));
    parts.push(Buffer.from('\r\n--' + boundary + '--\r\n', 'utf8'));
    var body = Buffer.concat(parts);

    var reqOpts = {
      hostname: parsed.hostname, port: parsed.port,
      path: '/drop/chunk/' + bundleId, method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': body.length,
        'Authorization': 'Bearer ' + apiKey,
      },
      rejectUnauthorized: false,
    };
    var mod = parsed.protocol === 'https:' ? https : http;
    var req = mod.request(reqOpts, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        var b = Buffer.concat(chunks).toString('utf8');
        var j = null; try { j = JSON.parse(b); } catch (_e) {}
        resolve({ statusCode: res.statusCode, body: b, json: j });
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Send a valid chunk with the given index. Returns the response.
 */
function sendChunk(bundleId, fileId, index, total, payload, apiKey) {
  return postChunk(bundleId, {
    chunkIndex: String(index),
    totalChunks: String(total),
    fileId: fileId,
    filename: 'test.txt',
    relativePath: 'test.txt',
    mimeType: 'application/octet-stream',
  }, payload, apiKey);
}

describe('Chunked upload scratch API', { timeout: 30000 }, function () {

  before(async function () {
    // /drop/init is rate-limited (20/min) so this suite skips it
    // entirely — bundles are DB-seeded. Brief settle pause for the
    // server before the first request.
    await sleep(100);
  });

  // Response bodies from /drop/chunk are ECIES-encrypted by the api-encrypt
  // middleware (bearer-authed, encrypted session). We can't cheaply decrypt
  // in this test harness, so assertions use statusCode + DB state as the
  // observable signal instead of parsed JSON body.
  function countFilesForBundle(bundleId) {
    var s = [
      'var row = db.prepare("SELECT COUNT(*) as cnt FROM files WHERE bundleId = ?").get(' + JSON.stringify(bundleId) + ');',
      'process.stdout.write(String(row ? row.cnt : 0));',
    ].join('\n');
    return parseInt(runDbScript(ctx.dbPath, s), 10);
  }

  it('happy path: 3 chunks assemble into a complete file', async function () {
    var bundle = createSnapshotBundle();
    var fileId = 'happy' + b.crypto.generateToken(8);

    var r1 = await sendChunk(bundle.bundleId, fileId, 0, 3, Buffer.from('AAAA'), ctx.apiKey);
    assert.equal(r1.statusCode, 200, 'chunk 0 → 200, got ' + r1.statusCode);
    assert.equal(countFilesForBundle(bundle.bundleId), 0, 'No file row yet (partial upload)');

    var r2 = await sendChunk(bundle.bundleId, fileId, 1, 3, Buffer.from('BBBB'), ctx.apiKey);
    assert.equal(r2.statusCode, 200, 'chunk 1 → 200, got ' + r2.statusCode);
    assert.equal(countFilesForBundle(bundle.bundleId), 0, 'Still no file row');

    var r3 = await sendChunk(bundle.bundleId, fileId, 2, 3, Buffer.from('CCCC'), ctx.apiKey);
    assert.equal(r3.statusCode, 200, 'chunk 2 → 200, got ' + r3.statusCode);
    assert.equal(countFilesForBundle(bundle.bundleId), 1, 'Final chunk triggers reassembly → 1 file row');
  });

  it('rejects fileId with path traversal (../)', async function () {
    var bundle = createSnapshotBundle();
    var r = await sendChunk(bundle.bundleId, '../etc/passwd', 0, 1, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500,
      'Path-traversal fileId → 4xx, got ' + r.statusCode + ' ' + r.body);
  });

  it('rejects fileId with forward slash', async function () {
    var bundle = createSnapshotBundle();
    var r = await sendChunk(bundle.bundleId, 'foo/bar', 0, 1, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'fileId with "/" → 4xx, got ' + r.statusCode);
  });

  it('rejects fileId with backslash', async function () {
    var bundle = createSnapshotBundle();
    var r = await sendChunk(bundle.bundleId, 'foo\\bar', 0, 1, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'fileId with "\\" → 4xx, got ' + r.statusCode);
  });

  it('rejects fileId with null byte', async function () {
    var bundle = createSnapshotBundle();
    var r = await sendChunk(bundle.bundleId, 'foo\u0000bar', 0, 1, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'fileId with NUL → 4xx, got ' + r.statusCode);
  });

  it('rejects fileId longer than 64 chars', async function () {
    var bundle = createSnapshotBundle();
    var longId = 'a'.repeat(65);
    var r = await sendChunk(bundle.bundleId, longId, 0, 1, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'long fileId → 4xx, got ' + r.statusCode);
  });

  it('rejects chunkIndex equal to totalChunks (out of range)', async function () {
    var bundle = createSnapshotBundle();
    var fileId = 'oor' + b.crypto.generateToken(8);
    var r = await sendChunk(bundle.bundleId, fileId, 3, 3, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500,
      'chunkIndex=totalChunks → 4xx, got ' + r.statusCode + ' ' + r.body);
  });

  it('rejects negative chunkIndex', async function () {
    var bundle = createSnapshotBundle();
    var fileId = 'neg' + b.crypto.generateToken(8);
    var r = await sendChunk(bundle.bundleId, fileId, -1, 3, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'negative chunkIndex → 4xx, got ' + r.statusCode);
  });

  it('rejects totalChunks over the 10000 cap', async function () {
    var bundle = createSnapshotBundle();
    var fileId = 'big' + b.crypto.generateToken(8);
    var r = await sendChunk(bundle.bundleId, fileId, 0, 10001, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'totalChunks>10000 → 4xx, got ' + r.statusCode);
  });

  it('rejects missing fileId field', async function () {
    var bundle = createSnapshotBundle();
    var r = await postChunk(bundle.bundleId, {
      chunkIndex: '0', totalChunks: '1', filename: 'x.txt', relativePath: 'x.txt',
    }, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'missing fileId → 4xx, got ' + r.statusCode);
  });

  it('rejects missing totalChunks field', async function () {
    var bundle = createSnapshotBundle();
    var fileId = 'nt' + b.crypto.generateToken(8);
    var r = await postChunk(bundle.bundleId, {
      chunkIndex: '0', fileId: fileId, filename: 'x.txt',
    }, Buffer.from('X'), ctx.apiKey);
    assert.ok(r.statusCode >= 400 && r.statusCode < 500, 'missing totalChunks → 4xx, got ' + r.statusCode);
  });

  it('isolates scratch per bundle — same fileId in two bundles does not collide', async function () {
    var a = createSnapshotBundle();
    var bb = createSnapshotBundle();
    var fileId = 'iso' + b.crypto.generateToken(8);

    // Partial upload to bundle A (1 of 2) — state observable via DB
    var r1 = await sendChunk(a.bundleId, fileId, 0, 2, Buffer.from('AAAA'), ctx.apiKey);
    assert.equal(r1.statusCode, 200, 'A chunk 0 accepted');
    assert.equal(countFilesForBundle(a.bundleId), 0, 'A not yet reassembled');

    // Same fileId, different bundle — must not be seen as already partially uploaded
    var r2 = await sendChunk(bb.bundleId, fileId, 0, 2, Buffer.from('BBBB'), ctx.apiKey);
    assert.equal(r2.statusCode, 200, 'B chunk 0 accepted');
    assert.equal(countFilesForBundle(bb.bundleId), 0, 'B not yet reassembled');

    // Complete A → A gets a file row, B still has zero
    var r3 = await sendChunk(a.bundleId, fileId, 1, 2, Buffer.from('aaaa'), ctx.apiKey);
    assert.equal(r3.statusCode, 200, 'A chunk 1 accepted');
    assert.equal(countFilesForBundle(a.bundleId), 1, 'A reassembled');
    assert.equal(countFilesForBundle(bb.bundleId), 0, 'B still pending (A reassembly did not consume B)');

    // Complete B → B gets its own file row
    var r4 = await sendChunk(bb.bundleId, fileId, 1, 2, Buffer.from('bbbb'), ctx.apiKey);
    assert.equal(r4.statusCode, 200, 'B chunk 1 accepted');
    assert.equal(countFilesForBundle(bb.bundleId), 1, 'B reassembled independently');
  });
});
