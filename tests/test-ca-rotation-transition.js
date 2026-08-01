'use strict';

/**
 * End-to-end coverage of the mTLS CA-rotation TRANSITION — the client-side
 * capability preflight that keeps a future signature-algorithm upgrade smooth.
 *
 * These drive the production SyncEngine._handleCaRotation directly against real
 * on-disk cert files and real ephemeral trios minted by b.mtlsEngine. Nothing
 * is faked below the wire: validation runs the real b.x509Chain issuer test,
 * the capability probe runs a real in-process TLS 1.3 mutual handshake, and the
 * commit runs the real stage -> validate -> probe -> backup -> swap -> ack path
 * with real atomic file writes. No live HTTPS server is needed — a CA rotation
 * is a client-local operation triggered by one WS message, so the transition is
 * exercised end to end here.
 *
 * The four outcomes that matter for a smooth future upgrade:
 *   1. ACCEPT           — an algorithm THIS runtime can handshake is committed.
 *   2. CAPABILITY DECLINE — an algorithm it cannot handshake (a future CA on an
 *                         un-upgraded client) is refused with the live identity
 *                         left untouched and NOT acked (server retries later).
 *   3. SECURITY REJECT  — a structurally invalid trio is refused before the
 *                         probe and NOT acked.
 *   4. The probe itself accepts a usable trio and rejects an unusable one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { MSG, createTempDir, rmrf } = require('./test-helpers');

const CLIENT_LIB = path.resolve(__dirname, '..', 'lib');
const SyncEngine = require(path.join(CLIENT_LIB, 'sync-engine'));
const stateDb = require(path.join(CLIENT_LIB, 'state-db'));
const b = require(path.resolve(__dirname, '..', 'vendor', 'blamejs'));

// Mint an independent CA + client leaf. With no `algorithm` the process PQC
// default (ML-DSA-87) is used, so the ACCEPT path proves the real migration
// target handshakes on this runtime.
async function genTrio(cn, algorithm) {
  const caArgs = { generation: 1 };
  if (algorithm) caArgs.algorithm = algorithm;
  const ca = await b.mtlsEngine.generateCa(caArgs);
  const leafArgs = { cn, usage: 'client', caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem };
  if (algorithm) leafArgs.algorithm = algorithm;
  const leaf = await b.mtlsEngine.signClientCert(leafArgs);
  return { caPem: ca.caCertPem, certPem: leaf.cert, keyPem: leaf.key };
}

function withNl(pem) { return pem.endsWith('\n') ? pem : pem + '\n'; }

function makeEngine() {
  const root = createTempDir('ca-rotation-transition');
  const syncFolder = path.join(root, 'sync');
  const dbFile = path.join(root, 'state.db');
  fs.mkdirSync(syncFolder, { recursive: true });
  stateDb.open(dbFile);

  const config = { syncFolder, bundleId: 'bundle-test', shareId: 'share-test' };
  const engine = new SyncEngine(config, 'hs_test_key');

  const acks = [];
  let reloads = 0;
  engine._ws = {
    send: (m) => { acks.push(m); return true; },
    updateSince() {}, close() {}, connect() {},
    reloadMtlsCerts() { reloads++; },
  };
  engine._http = { reloadMtlsCerts() { reloads++; }, destroy() {} };
  engine._ignorePatterns = [];
  engine._includePatterns = [];

  const mtlsDir = path.join(root, 'mtls');
  fs.mkdirSync(mtlsDir, { recursive: true });
  const mtls = {
    cert: path.join(mtlsDir, 'client.crt'),
    key: path.join(mtlsDir, 'client.key'),
    ca: path.join(mtlsDir, 'ca.crt'),
  };
  engine._config.mtls = mtls;

  return { engine, root, mtls, acks, getReloads: () => reloads };
}

function seedLive(mtls, trio) {
  fs.writeFileSync(mtls.cert, withNl(trio.certPem));
  fs.writeFileSync(mtls.key, withNl(trio.keyPem));
  fs.writeFileSync(mtls.ca, withNl(trio.caPem));
}

function acked(h) { return h.acks.some((m) => m && m.type === MSG.CA_ROTATION_ACK); }

function cleanup(h) {
  try { stateDb.close(); } catch { /* best-effort teardown */ }
  rmrf(h.root);
}

describe('mTLS CA-rotation transition — capability preflight', { timeout: 60000 }, () => {

  it('the capability probe accepts a trio this runtime can handshake', async () => {
    const h = makeEngine();
    try {
      const trio = await genTrio('probe-ok');
      const ok = await h.engine._probeMtlsTlsCapability(trio.certPem, trio.keyPem, trio.caPem);
      assert.equal(ok, true, 'a well-formed, runtime-supported trio probes true');
    } finally { cleanup(h); }
  });

  it('the capability probe rejects a trio whose key does not match the cert (no handshake possible)', async () => {
    const h = makeEngine();
    try {
      const a = await genTrio('probe-a');
      const c = await genTrio('probe-b');
      // Cert from A, key from B → the secure context cannot form → no handshake.
      const ok = await h.engine._probeMtlsTlsCapability(a.certPem, c.keyPem, a.caPem);
      assert.equal(ok, false, 'a mismatched key/cert probes false');
    } finally { cleanup(h); }
  });

  it('_deriveCaAlgorithmLabel prefers the server hint, else the CA key type, else a generic label', async () => {
    const h = makeEngine();
    try {
      const trio = await genTrio('label');
      assert.equal(h.engine._deriveCaAlgorithmLabel(trio.caPem, 'ML-DSA-87'), 'ML-DSA-87', 'hint wins');
      const derived = h.engine._deriveCaAlgorithmLabel(trio.caPem, undefined);
      assert.equal(typeof derived, 'string');
      assert.ok(derived.length > 0, 'derives a non-empty label from the CA cert');
      assert.equal(
        h.engine._deriveCaAlgorithmLabel('not a pem', undefined),
        'the new signature algorithm',
        'generic fallback on an unparseable CA',
      );
    } finally { cleanup(h); }
  });

  it('ACCEPT: a rotation whose algorithm the runtime supports is validated, probed, swapped, and acked', async (t) => {
    const h = makeEngine();
    try {
      const live = await genTrio('live-identity');
      seedLive(h.mtls, live);
      const next = await genTrio('rotated-identity');

      // The runtime must be able to handshake the new algorithm for the accept
      // path to be meaningful. If it can't, the very condition the decline path
      // guards holds — skip rather than assert a false negative.
      const canDo = await h.engine._probeMtlsTlsCapability(next.certPem, next.keyPem, next.caPem);
      if (!canDo) { t.skip('runtime cannot handshake the default PQC algorithm — the decline test covers this'); return; }

      const liveCertBefore = fs.readFileSync(h.mtls.cert, 'utf8');
      await h.engine._handleCaRotation({
        newCaPem: next.caPem, newCertPem: next.certPem, newKeyPem: next.keyPem, dryRun: false,
      });

      assert.notEqual(fs.readFileSync(h.mtls.cert, 'utf8'), liveCertBefore, 'live cert changed');
      assert.ok(fs.readFileSync(h.mtls.cert, 'utf8').includes(next.certPem.trim()), 'live cert now holds the rotated leaf');
      assert.ok(fs.readFileSync(h.mtls.ca, 'utf8').includes(next.caPem.trim()), 'live CA now holds the rotated CA');
      assert.ok(fs.existsSync(h.mtls.cert + '.prev'), 'pre-rotation backup written for boot recovery');
      assert.ok(!fs.existsSync(h.mtls.cert + '.next'), 'no staging left behind');
      assert.ok(h.getReloads() >= 2, 'ws + http cert caches reloaded after commit');
      assert.ok(acked(h), 'rotation acked after a committed swap');
    } finally { cleanup(h); }
  });

  it('CAPABILITY DECLINE: a rotation the runtime cannot handshake keeps the current identity and is NOT acked', async () => {
    const h = makeEngine();
    try {
      const live = await genTrio('live-identity');
      seedLive(h.mtls, live);
      const next = await genTrio('future-algo');   // structurally valid, chains fine

      // Simulate a signature algorithm newer than this client's runtime: the
      // trio validates (parse + key-match + chain) but the runtime cannot drive
      // it through TLS — exactly how a real future-algorithm CA looks to an
      // un-upgraded client.
      h.engine._probeMtlsTlsCapability = async () => false;

      const certBefore = fs.readFileSync(h.mtls.cert, 'utf8');
      const keyBefore = fs.readFileSync(h.mtls.key, 'utf8');
      const caBefore = fs.readFileSync(h.mtls.ca, 'utf8');

      await h.engine._handleCaRotation({
        newCaPem: next.caPem, newCertPem: next.certPem, newKeyPem: next.keyPem, dryRun: false,
        caAlgorithm: 'a-future-pqc-signature',
      });

      assert.equal(fs.readFileSync(h.mtls.cert, 'utf8'), certBefore, 'live cert untouched');
      assert.equal(fs.readFileSync(h.mtls.key, 'utf8'), keyBefore, 'live key untouched');
      assert.equal(fs.readFileSync(h.mtls.ca, 'utf8'), caBefore, 'live CA untouched');
      assert.ok(!fs.existsSync(h.mtls.cert + '.next'), 'staging cleaned on decline');
      assert.ok(!fs.existsSync(h.mtls.cert + '.prev'), 'no backup taken — the live identity was never at risk');
      assert.equal(acked(h), false, 'a capability decline is NOT acked — the server retries after the client is upgraded');
    } finally { cleanup(h); }
  });

  it('SECURITY REJECT: a trio that does not chain to the supplied CA is refused before the probe and NOT acked', async () => {
    const h = makeEngine();
    try {
      const live = await genTrio('live-identity');
      seedLive(h.mtls, live);
      const other = await genTrio('other-ca');

      let probed = false;
      h.engine._probeMtlsTlsCapability = async () => { probed = true; return true; };

      // live's leaf/key (they match) presented under other's CA → the chain
      // check fails, so validation throws before the capability probe runs.
      await h.engine._handleCaRotation({
        newCaPem: other.caPem, newCertPem: live.certPem, newKeyPem: live.keyPem, dryRun: false,
      });

      assert.equal(probed, false, 'the probe is never reached — validation rejects first');
      assert.equal(fs.readFileSync(h.mtls.cert, 'utf8'), withNl(live.certPem), 'live cert untouched');
      assert.ok(!fs.existsSync(h.mtls.cert + '.next'), 'no staging left behind');
      assert.equal(acked(h), false, 'a security reject is NOT acked');
    } finally { cleanup(h); }
  });
});
