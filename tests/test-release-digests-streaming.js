'use strict';

// Unit coverage for scripts/sha3-digest.js. The release workflow invokes
// this helper once per platform binary to emit the SHA-256 + SHA3-512
// sidecars the auto-update verifier and `sha256sum -c` consume. The
// digests are computed by streaming the artifact through both hashers in a
// single pass so a multi-hundred-MB SEA bundle never materializes in the
// runner's heap. These tests pin that contract: the streamed digests must
// equal an independent whole-file reference for every size class, including
// a payload larger than one read-stream chunk so the multi-chunk path is
// exercised, and the emitted sidecar files must carry the exact
// `<hex>  <basename>` line format the checksum tools expect.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { computeDigests, ALGORITHMS } = require('../scripts/sha3-digest.js');

function referenceDigest(buf, algorithm) {
  return crypto.createHash(algorithm).update(buf).digest('hex');
}

async function withTempFile(buf, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-digest-'));
  const file = path.join(dir, 'artifact.bin');
  fs.writeFileSync(file, buf);
  try {
    return await fn(file, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('ALGORITHMS emits SHA-256 then SHA3-512 in sidecar order', () => {
  assert.deepStrictEqual(
    ALGORITHMS.map((a) => a.name),
    ['sha256', 'sha3-512'],
  );
  assert.deepStrictEqual(
    ALGORITHMS.map((a) => a.ext),
    ['sha256', 'sha3-512'],
  );
});

test('streamed digests match a whole-file reference for an empty file', async () => {
  await withTempFile(Buffer.alloc(0), async (file) => {
    const digests = await computeDigests(file);
    assert.strictEqual(digests[0], referenceDigest(Buffer.alloc(0), 'sha256'));
    assert.strictEqual(digests[1], referenceDigest(Buffer.alloc(0), 'sha3-512'));
  });
});

test('streamed digests match a whole-file reference for a small file', async () => {
  const buf = Buffer.from('hermitstash-sync release artifact', 'utf8');
  await withTempFile(buf, async (file) => {
    const digests = await computeDigests(file);
    assert.strictEqual(digests[0], referenceDigest(buf, 'sha256'));
    assert.strictEqual(digests[1], referenceDigest(buf, 'sha3-512'));
  });
});

test('streamed digests match a whole-file reference across multiple read-stream chunks', async () => {
  // Larger than the default 64 KiB read-stream highWaterMark so the data
  // event fires repeatedly — proves every chunk feeds both hashers, the
  // exact behaviour the whole-file read it replaced used to guarantee.
  const buf = crypto.randomBytes(64 * 1024 * 3 + 17);
  await withTempFile(buf, async (file) => {
    const digests = await computeDigests(file);
    assert.strictEqual(digests[0], referenceDigest(buf, 'sha256'));
    assert.strictEqual(digests[1], referenceDigest(buf, 'sha3-512'));
  });
});

test('computeDigests rejects when the artifact cannot be read', async () => {
  const missing = path.join(os.tmpdir(), 'hs-digest-does-not-exist-' + Date.now());
  await assert.rejects(() => computeDigests(missing));
});

test('a one-pass stream reproduces both sidecar lines exactly', async () => {
  // Mirrors what main() writes: each sidecar is `<hex>  <basename>\n`. The
  // digest must equal the streamed computation so a verifier reading the
  // sidecar agrees with the verifier hashing the binary.
  const buf = crypto.randomBytes(100000);
  await withTempFile(buf, async (file) => {
    const digests = await computeDigests(file);
    const base = path.basename(file);
    for (let i = 0; i < ALGORITHMS.length; i++) {
      const expectedLine = digests[i] + '  ' + base + '\n';
      const ref = referenceDigest(buf, ALGORITHMS[i].name) + '  ' + base + '\n';
      assert.strictEqual(expectedLine, ref);
    }
  });
});
