'use strict';

/**
 * Hardened mTLS-material read tests for lib/http-client.js buildTlsOptions.
 *
 * The mTLS trio (cert, the 0o600 private key, CA) lives in CONFIG_DIR's certs/
 * dir and is written exclusively via b.atomicFile.writeSync, so a symlink at
 * any of these paths is never legitimate — it is exactly the swap an attacker
 * with parent-dir write plants to redirect the secret read at a victim file.
 * buildTlsOptions now reads each path via b.atomicFile.fdSafeReadSync with
 * refuseSymlink + inodeCheck, so a symlinked key/cert/CA is refused with an
 * actionable error instead of being silently followed.
 *
 * NODE_EXTRA_CA_CERTS (an arbitrary operator-pointed trust-root path) is also
 * read with refuseSymlink (no inodeCheck) — a symlink there is skipped rather
 * than fatal, since a broken operator-chosen path just means no extra roots.
 *
 * Symlink creation needs privilege on Windows (Developer Mode / admin). When
 * it throws EPERM/EACCES the symlink-specific assertions skip; the
 * regular-file happy path still runs everywhere.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const { createTempDir, rmrf } = require('./test-helpers');

const HttpClient = require('../lib/http-client');
const buildTlsOptions = HttpClient.buildTlsOptions;

// Try to create a symlink; return false if the platform/privilege refuses it.
function trySymlink(target, linkPath) {
  try {
    nodeFs.symlinkSync(target, linkPath);
    return true;
  } catch (e) {
    if (e && (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOSYS')) return false;
    throw e;
  }
}

describe('buildTlsOptions mTLS material read', () => {
  let dir = null;
  let certPath, keyPath, caPath;

  before(() => {
    dir = createTempDir('mtls-read');
    certPath = nodePath.join(dir, 'client.crt');
    keyPath  = nodePath.join(dir, 'client.key');
    caPath   = nodePath.join(dir, 'ca.crt');
    // The bytes need not be valid PEM for this test — buildTlsOptions only
    // reads them; TLS validation happens later at handshake. We assert on the
    // read posture (symlink refusal / inode binding), not on cert parsing.
    nodeFs.writeFileSync(certPath, 'CERT-BYTES', { mode: 0o600 });
    nodeFs.writeFileSync(keyPath, 'KEY-BYTES', { mode: 0o600 });
    nodeFs.writeFileSync(caPath, 'CA-BYTES', { mode: 0o600 });
  });

  after(() => { if (dir) rmrf(dir); });

  it('reads regular files into Buffers (byte-compatible with the TLS layer)', () => {
    const opts = buildTlsOptions({ cert: certPath, key: keyPath, ca: caPath });
    assert.ok(Buffer.isBuffer(opts.cert), 'cert should be a Buffer');
    assert.strictEqual(opts.cert.toString('utf8'), 'CERT-BYTES');
    assert.ok(Buffer.isBuffer(opts.key), 'key should be a Buffer');
    assert.strictEqual(opts.key.toString('utf8'), 'KEY-BYTES');
    // ca runs through _buildCaBundle -> an array including the system roots.
    assert.ok(Array.isArray(opts.ca));
    assert.ok(opts.ca.some((c) => String(c) === 'CA-BYTES'),
      'the enrollment CA must be appended to the trust bundle');
  });

  it('passes pre-loaded Buffers through verbatim (no file read)', () => {
    const opts = buildTlsOptions({
      cert: Buffer.from('B-CERT'), key: Buffer.from('B-KEY'), ca: Buffer.from('B-CA'),
    });
    assert.strictEqual(opts.cert.toString('utf8'), 'B-CERT');
    assert.strictEqual(opts.key.toString('utf8'), 'B-KEY');
  });

  it('refuses a symlinked private key with an actionable error', (t) => {
    const victim = nodePath.join(dir, 'victim-secret');
    nodeFs.writeFileSync(victim, 'VICTIM-PRIVATE-KEY');
    const linkKey = nodePath.join(dir, 'client.symlink.key');
    if (!trySymlink(victim, linkKey)) {
      return t.skip('symlink creation unavailable (Windows without Developer Mode / admin)');
    }
    try {
      assert.throws(
        () => buildTlsOptions({ cert: certPath, key: linkKey, ca: caPath }),
        (err) => {
          assert.match(err.message, /could not be read safely/);
          assert.match(err.message, /re-enroll with "hermitstash-sync init"/);
          return true;
        },
        'a symlinked private key must be refused, not silently followed',
      );
    } finally {
      try { nodeFs.unlinkSync(linkKey); } catch {}
    }
  });

  it('refuses a symlinked cert and a symlinked CA too', (t) => {
    const victim = nodePath.join(dir, 'victim-2');
    nodeFs.writeFileSync(victim, 'VICTIM');
    const linkCert = nodePath.join(dir, 'client.symlink.crt');
    const linkCa = nodePath.join(dir, 'ca.symlink.crt');
    if (!trySymlink(victim, linkCert)) {
      return t.skip('symlink creation unavailable');
    }
    trySymlink(victim, linkCa);
    try {
      assert.throws(() => buildTlsOptions({ cert: linkCert, key: keyPath, ca: caPath }),
        /could not be read safely/);
      assert.throws(() => buildTlsOptions({ cert: certPath, key: keyPath, ca: linkCa }),
        /could not be read safely/);
    } finally {
      try { nodeFs.unlinkSync(linkCert); } catch {}
      try { nodeFs.unlinkSync(linkCa); } catch {}
    }
  });

  it('a missing mTLS path throws a clear error naming the path', () => {
    // Under refuseSymlink, fdSafeReadSync lstat's the path first and a missing
    // file surfaces a raw ENOENT from that lstat (the caller's errorFor is only
    // consulted for the open()-stage ENOENT, not the lstat stage). Either way
    // the failure is loud and names the path — never a silent fall-through.
    const missing = nodePath.join(dir, 'does-not-exist.key');
    assert.throws(
      () => buildTlsOptions({ cert: certPath, key: missing, ca: caPath }),
      (err) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes('does-not-exist.key'),
          'the error must name the missing path: ' + err.message);
        return true;
      },
    );
  });
});

describe('NODE_EXTRA_CA_CERTS read posture', () => {
  let dir = null;
  let savedExtra;

  before(() => {
    dir = createTempDir('extra-ca');
    savedExtra = process.env.NODE_EXTRA_CA_CERTS;
  });

  after(() => {
    if (savedExtra === undefined) delete process.env.NODE_EXTRA_CA_CERTS;
    else process.env.NODE_EXTRA_CA_CERTS = savedExtra;
    if (dir) rmrf(dir);
  });

  it('appends a regular-file extra CA to the bundle', () => {
    const extra = nodePath.join(dir, 'extra-root.pem');
    nodeFs.writeFileSync(extra, 'EXTRA-ROOT');
    process.env.NODE_EXTRA_CA_CERTS = extra;
    const bundle = HttpClient.buildCaBundle(null);
    assert.ok(bundle.some((c) => String(c) === 'EXTRA-ROOT'),
      'a regular-file NODE_EXTRA_CA_CERTS must be appended');
  });

  it('skips (does not throw on) a symlinked extra CA — broken operator path is non-fatal', (t) => {
    const victim = nodePath.join(dir, 'victim-root.pem');
    nodeFs.writeFileSync(victim, 'VICTIM-ROOT');
    const link = nodePath.join(dir, 'extra-root.symlink.pem');
    if (!trySymlink(victim, link)) {
      return t.skip('symlink creation unavailable');
    }
    process.env.NODE_EXTRA_CA_CERTS = link;
    try {
      let bundle;
      assert.doesNotThrow(() => { bundle = HttpClient.buildCaBundle(null); },
        'a symlinked NODE_EXTRA_CA_CERTS is skipped, not fatal');
      assert.ok(!bundle.some((c) => String(c) === 'VICTIM-ROOT'),
        'the symlink target must NOT have been read into the trust bundle');
    } finally {
      try { nodeFs.unlinkSync(link); } catch {}
    }
  });
});
