'use strict';

// Unit tests for lib/checksum.js. Server-independent — exercises the
// production hashing wrapper directly against temp files.
//
// Two concerns:
//   1. Windows long-path prefixing applies at the syscall boundary so
//      files in deep (>260 char) trees still hash. The prefixing is a
//      no-op off Windows, so the cross-platform assertion is "a deep
//      path hashes to the same digest as the same bytes at a short
//      path"; the Windows-only assertion checks the `\\?\` form directly.
//   2. The batch path tolerates one un-hashable file (missing, special,
//      or oversize) — it returns a null-checksum row in that slot and
//      still hashes the rest, in input order, so a single bad file never
//      aborts the whole reconciliation. The per-file size ceiling is
//      shared with the single-file streaming path so they can't drift.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const checksum = require('../lib/checksum');
const { longPath } = require('../lib/long-path');

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hs-checksum-${label}-`));
}

// Reference SHA3-512 of the same bytes via node:crypto, independent of
// the production path, so we're comparing against ground truth.
function refSha3(buf) {
  return crypto.createHash('sha3-512').update(buf).digest('hex');
}

describe('checksum — hashFile', () => {
  it('matches a node:crypto SHA3-512 of the same bytes', async () => {
    const dir = tmpDir('hf');
    const file = path.join(dir, 'a.bin');
    const bytes = crypto.randomBytes(4096);
    fs.writeFileSync(file, bytes);
    const got = await checksum.hashFile(file);
    assert.equal(got, refSha3(bytes));
  });

  it('hashes a deep path identically to the same bytes at a short path', async () => {
    const bytes = crypto.randomBytes(2048);
    const expected = refSha3(bytes);

    const shortDir = tmpDir('short');
    const shortFile = path.join(shortDir, 'f.bin');
    fs.writeFileSync(shortFile, bytes);

    // Build a path comfortably past the Windows MAX_PATH (260) limit so
    // the long-path prefix is the thing that lets the open succeed.
    const deepDir = tmpDir('deep');
    let cur = deepDir;
    const segment = 'segment-' + 'x'.repeat(20);
    while (cur.length < 300) {
      cur = path.join(cur, segment);
    }
    fs.mkdirSync(longPath(cur), { recursive: true });
    const deepFile = path.join(cur, 'f.bin');
    fs.writeFileSync(longPath(deepFile), bytes);
    assert.ok(deepFile.length > 260, `deep path should exceed MAX_PATH, was ${deepFile.length}`);

    const shortHash = await checksum.hashFile(shortFile);
    const deepHash = await checksum.hashFile(deepFile);
    assert.equal(shortHash, expected);
    assert.equal(deepHash, expected, 'deep-path file must hash to the same digest');
  });
});

describe('checksum — longPath prefixing', () => {
  it('long-prefixes a >248-char path on Windows; passes short paths through', () => {
    const long = 'C:\\' + 'a'.repeat(300) + '\\file.bin';
    const prefixed = longPath(long);
    if (process.platform === 'win32') {
      assert.ok(prefixed.startsWith('\\\\?\\'), 'long Windows path should be \\\\?\\-prefixed');
    } else {
      assert.equal(prefixed, long, 'longPath is a no-op off Windows');
    }
    // Short paths are never prefixed, on any platform.
    assert.equal(longPath('/tmp/x'), '/tmp/x');
  });
});

describe('checksum — hashFilesParallel batch tolerance', () => {
  it('returns one row per input in input order', async () => {
    const dir = tmpDir('order');
    const files = [];
    const expected = [];
    for (let i = 0; i < 5; i++) {
      const f = path.join(dir, `f${i}.bin`);
      const bytes = crypto.randomBytes(1024 + i);
      fs.writeFileSync(f, bytes);
      files.push(f);
      expected.push(refSha3(bytes));
    }
    const rows = await checksum.hashFilesParallel(files);
    assert.equal(rows.length, files.length);
    for (let i = 0; i < files.length; i++) {
      assert.equal(rows[i].filePath, files[i], `row ${i} path must stay aligned`);
      assert.equal(rows[i].checksum, expected[i]);
    }
  });

  it('degrades one un-hashable file to a null-checksum row, hashes the rest', async () => {
    const dir = tmpDir('mixed');
    const good1 = path.join(dir, 'good1.bin');
    const good2 = path.join(dir, 'good2.bin');
    const missing = path.join(dir, 'does-not-exist.bin');
    const subdir = path.join(dir, 'a-directory'); // special: not a regular file
    const g1 = crypto.randomBytes(512);
    const g2 = crypto.randomBytes(512);
    fs.writeFileSync(good1, g1);
    fs.writeFileSync(good2, g2);
    fs.mkdirSync(subdir);

    const input = [good1, missing, good2, subdir];
    const rows = await checksum.hashFilesParallel(input);

    assert.equal(rows.length, 4, 'one row per input, none dropped');
    assert.equal(rows[0].checksum, refSha3(g1));
    assert.equal(rows[1].checksum, null, 'missing file must degrade to null, not throw');
    assert.equal(rows[2].checksum, refSha3(g2), 'good file after the bad one still hashes');
    assert.equal(rows[3].checksum, null, 'directory (special file) must degrade to null');
    // Positional alignment is the contract the upload scan depends on.
    assert.deepEqual(rows.map(r => r.filePath), input);
  });

  it('empty input returns an empty array', async () => {
    assert.deepEqual(await checksum.hashFilesParallel([]), []);
  });
});

describe('checksum — size ceiling consistency (child process for env override)', () => {
  it('a file over HERMITSTASH_MAX_FILE_BYTES degrades the batch but spares its siblings', () => {
    // The ceiling is read at module load, so drive a child process with a
    // tiny HERMITSTASH_MAX_FILE_BYTES. A sparse file is allocated past the
    // cap; the small sibling must still hash while the oversize one comes
    // back null. This also confirms the single-file streaming path rejects
    // the oversize file with an actionable message rather than hashing it.
    const dir = tmpDir('cap');
    const big = path.join(dir, 'big.bin');
    const small = path.join(dir, 'small.bin');
    const smallBytes = crypto.randomBytes(256);
    fs.writeFileSync(small, smallBytes);
    // Sparse allocation: a 4 MiB file without writing 4 MiB of data.
    const fd = fs.openSync(big, 'w');
    fs.ftruncateSync(fd, 4 * 1024 * 1024);
    fs.closeSync(fd);

    const script = `
      const assert = require('node:assert/strict');
      const checksum = require(${JSON.stringify(path.resolve(__dirname, '../lib/checksum.js'))});
      (async () => {
        const big = ${JSON.stringify(big)};
        const small = ${JSON.stringify(small)};
        // Cap is well below the 4 MiB sparse file.
        assert.ok(checksum.MAX_BYTES_PER_FILE < 4 * 1024 * 1024, 'env cap should be small');

        const rows = await checksum.hashFilesParallel([small, big]);
        assert.equal(rows.length, 2);
        assert.ok(rows[0].checksum, 'small sibling must still hash');
        assert.equal(rows[1].checksum, null, 'oversize file must degrade to null');

        // Single-file streaming path enforces the same ceiling.
        await assert.rejects(checksum.hashFile(big), /sync size limit|HERMITSTASH_MAX_FILE_BYTES/);
        const ok = await checksum.hashFile(small);
        assert.equal(typeof ok, 'string');
        console.log('CHILD_OK');
      })().catch(e => { console.error(e); process.exit(1); });
    `;
    const out = execFileSync(process.execPath, ['-e', script], {
      env: Object.assign({}, process.env, { HERMITSTASH_MAX_FILE_BYTES: String(64 * 1024) }),
      encoding: 'utf8',
    });
    assert.match(out, /CHILD_OK/);
  });
});
