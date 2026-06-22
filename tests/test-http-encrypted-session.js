'use strict';

/**
 * Recovery-branch tests for the per-session encrypted request path
 * (lib/http-client.js _encryptedRequest / _encryptedRequestOnce).
 *
 * The encrypted metadata routes (/sync/rename, /drop/init, /drop/finalize)
 * run over a blamejs apiEncrypt per-session envelope with a strict-monotonic
 * replay counter. _encryptedRequestOnce carries four recovery paths that keep
 * the sync client functional across server keypair rotation / session expiry /
 * restart:
 *
 *   (a) a client-side sid/ctr mismatch (CLIENT_RESPONSE_SID /
 *       CLIENT_RESPONSE_REPLAY) -> reset the session + retry once;
 *   (b) a 401 with a session-* body -> rebuild + retry once;
 *   (c) a 400 encrypted-payload-rejected (sealed to a rotated pubkey) ->
 *       re-fetch the pubkey + retry once;
 *   (d) the single-slot _encChain lock that serializes overlapping encrypted
 *       requests so their counters never interleave.
 *
 * Plus the client-side wall-clock cap (_withWallClock): the blamejs encrypted
 * wrapper forwards only idleTimeoutMs and exposes no abort handle, so a request
 * that never settles must still reject at the wall-clock ceiling rather than
 * wedging the serialized _encChain queue.
 *
 * These run without a server: _getEncClient is stubbed to return a scripted
 * fake enc client and _resetEncClient is spied. Self-contained — runnable via
 * `node --test tests/test-http-encrypted-session.js`.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const HttpClient = require('../lib/http-client');

// Build a client without standing up TLS/agents we don't need; an http URL
// keeps _isHttps false so the constructor builds a plain http agent.
function makeClient() {
  return new HttpClient({ server: 'http://127.0.0.1:9/' }, 'test_api_key');
}

// Install a scripted enc client. `script` is an array of step descriptors,
// consumed one per enc.request() call:
//   { throw: <Error> }       -> the request promise rejects with that error
//   { resp: <responseObj> }  -> resolves with { statusCode, body, ... }
//   { hang: true }           -> never settles (drives the wall-clock cap)
// Returns a controller exposing the recorded call count and reset count.
function installScript(client, script) {
  let callIndex = 0;
  let resetCount = 0;
  const calls = [];

  const fakeEnc = {
    request(opts) {
      const step = script[callIndex++];
      calls.push(opts);
      if (!step) return Promise.reject(new Error('script exhausted at call ' + callIndex));
      if (step.hang) return new Promise(() => {});
      if (step.throw) return Promise.reject(step.throw);
      return Promise.resolve(step.resp);
    },
  };

  // _getEncClient hands back the same scripted client; a "rebuild" just resolves
  // to it again (the script controls behaviour, not the identity).
  client._getEncClient = () => Promise.resolve(fakeEnc);

  const realReset = client._resetEncClient.bind(client);
  client._resetEncClient = () => { resetCount++; realReset(); };

  return {
    get callCount() { return callIndex; },
    get resetCount() { return resetCount; },
    calls,
  };
}

describe('encrypted-session recovery branches', () => {
  it('CLIENT_RESPONSE_REPLAY -> reset + retry once -> success', async () => {
    const client = makeClient();
    const replay = new Error('replay'); replay.code = 'CLIENT_RESPONSE_REPLAY';
    const ctl = installScript(client, [
      { throw: replay },
      { resp: { statusCode: 200, body: { ok: true } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 1 });
    assert.strictEqual(resp.statusCode, 200);
    assert.strictEqual(ctl.callCount, 2, 'exactly one retry');
    assert.strictEqual(ctl.resetCount, 1, 'exactly one session reset');
    client.destroy();
  });

  it('CLIENT_RESPONSE_SID retry is terminal — a second failure propagates, no infinite loop', async () => {
    const client = makeClient();
    const sid1 = new Error('sid1'); sid1.code = 'CLIENT_RESPONSE_SID';
    const sid2 = new Error('sid2'); sid2.code = 'CLIENT_RESPONSE_SID';
    const ctl = installScript(client, [
      { throw: sid1 },
      { throw: sid2 },
    ]);
    await assert.rejects(
      client._encryptedRequest('POST', '/sync/rename', { a: 1 }),
      (e) => e.code === 'CLIENT_RESPONSE_SID',
    );
    assert.strictEqual(ctl.callCount, 2, 'retried exactly once then gave up');
    assert.strictEqual(ctl.resetCount, 1, 'reset once on the first failure only');
    client.destroy();
  });

  it('401 session-expired -> rebuild + retry once -> success', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { resp: { statusCode: 401, body: { error: 'session-expired' } } },
      { resp: { statusCode: 200, body: { ok: true } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/drop/init', { a: 1 });
    assert.strictEqual(resp.statusCode, 200);
    assert.strictEqual(ctl.callCount, 2);
    assert.strictEqual(ctl.resetCount, 1);
    client.destroy();
  });

  it('401 session-rotation-required -> rebuild + retry once', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { resp: { statusCode: 401, body: { error: 'session-rotation-required' } } },
      { resp: { statusCode: 200, body: { ok: true } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 1 });
    assert.strictEqual(resp.statusCode, 200);
    assert.strictEqual(ctl.callCount, 2);
    assert.strictEqual(ctl.resetCount, 1);
    client.destroy();
  });

  it('401 with an UNRECOGNIZED body does not retry — surfaces the 401', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { resp: { statusCode: 401, body: { error: 'bad-bearer-token' } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 1 });
    assert.strictEqual(resp.statusCode, 401);
    assert.strictEqual(ctl.callCount, 1, 'no retry for an unrelated 401');
    assert.strictEqual(ctl.resetCount, 0, 'no session reset');
    client.destroy();
  });

  it('400 encrypted-payload-rejected -> re-fetch pubkey + retry once', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { resp: { statusCode: 400, body: { error: 'encrypted-payload-rejected' } } },
      { resp: { statusCode: 200, body: { ok: true } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 1 });
    assert.strictEqual(resp.statusCode, 200);
    assert.strictEqual(ctl.callCount, 2);
    assert.strictEqual(ctl.resetCount, 1, 'reset forces _getEncClient to re-fetch the pubkey');
    client.destroy();
  });

  it('400 encrypted-payload-rejected retry is terminal — a second 400 surfaces, no loop', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { resp: { statusCode: 400, body: { error: 'encrypted-payload-rejected' } } },
      { resp: { statusCode: 400, body: { error: 'encrypted-payload-rejected' } } },
    ]);
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 1 });
    assert.strictEqual(resp.statusCode, 400);
    assert.strictEqual(ctl.callCount, 2, 'one retry then terminal');
    assert.strictEqual(ctl.resetCount, 1);
    client.destroy();
  });

  it('a non-session error propagates without retry', async () => {
    const client = makeClient();
    const netErr = new Error('ECONNRESET'); netErr.code = 'ECONNRESET';
    const ctl = installScript(client, [
      { throw: netErr },
    ]);
    await assert.rejects(
      client._encryptedRequest('POST', '/sync/rename', { a: 1 }),
      (e) => e.code === 'ECONNRESET',
    );
    assert.strictEqual(ctl.callCount, 1, 'network errors are not session-loss; no retry');
    assert.strictEqual(ctl.resetCount, 0);
    client.destroy();
  });
});

describe('encrypted-request serialization (_encChain)', () => {
  it('overlapping encrypted requests are serialized — the second starts only after the first settles', async () => {
    const client = makeClient();

    // Track when each request enters and leaves the underlying enc.request().
    const order = [];
    let releaseFirst;
    const firstGate = new Promise((res) => { releaseFirst = res; });
    let n = 0;

    const fakeEnc = {
      request() {
        const id = ++n;
        order.push('enter-' + id);
        if (id === 1) {
          // Hold the first request open until the test releases it.
          return firstGate.then(() => {
            order.push('leave-1');
            return { statusCode: 200, body: { id: 1 } };
          });
        }
        order.push('leave-2');
        return Promise.resolve({ statusCode: 200, body: { id: 2 } });
      },
    };
    client._getEncClient = () => Promise.resolve(fakeEnc);

    const p1 = client._encryptedRequest('POST', '/sync/rename', { which: 1 });
    const p2 = client._encryptedRequest('POST', '/sync/rename', { which: 2 });

    // Give the microtask queue a chance — the second must NOT have entered yet,
    // because the chain is still waiting on the first.
    await new Promise((r) => setTimeout(r, 20));
    assert.deepStrictEqual(order, ['enter-1'], 'second request must wait for the first');

    releaseFirst();
    const [r1, r2] = await Promise.all([p1, p2]);
    assert.strictEqual(r1.body.id, 1);
    assert.strictEqual(r2.body.id, 2);
    // Strict ordering: first fully settles before the second enters.
    assert.deepStrictEqual(order, ['enter-1', 'leave-1', 'enter-2', 'leave-2']);
    client.destroy();
  });

  it('a failed request does not wedge the chain — the next request still runs', async () => {
    const client = makeClient();
    const boom = new Error('boom'); boom.code = 'ECONNRESET';
    const ctl = installScript(client, [
      { throw: boom },
      { resp: { statusCode: 200, body: { ok: true } } },
    ]);
    await assert.rejects(client._encryptedRequest('POST', '/sync/rename', { a: 1 }));
    const resp = await client._encryptedRequest('POST', '/sync/rename', { a: 2 });
    assert.strictEqual(resp.statusCode, 200, 'chain recovered after a rejection');
    assert.strictEqual(ctl.callCount, 2);
    client.destroy();
  });
});

describe('encrypted-request wall-clock cap (_withWallClock)', () => {
  it('a request that never settles rejects at the wall-clock ceiling, not hangs forever', async () => {
    const client = makeClient();
    const ctl = installScript(client, [
      { hang: true },
    ]);
    // Shrink the ceiling so the test is fast; the production constant is 60s.
    const start = Date.now();
    await assert.rejects(
      client._withWallClock(client._getEncClient().then((e) => e.request({})), 60, 'POST /sync/rename'),
      (e) => e.code === 'ENC_WALL_CLOCK_TIMEOUT' && e.permanent === false,
    );
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, 'rejected promptly at the cap, elapsed=' + elapsed + 'ms');
    assert.ok(ctl.callCount >= 1, 'the underlying request was issued');
    client.destroy();
  });

  it('a fast request resolves through the wall-clock wrapper unchanged', async () => {
    const client = makeClient();
    const v = await client._withWallClock(Promise.resolve({ statusCode: 200 }), 1000, 'POST /x');
    assert.strictEqual(v.statusCode, 200);
    client.destroy();
  });

  it('the timeout error is actionable and transient (translated, not the raw primitive code)', async () => {
    const client = makeClient();
    await assert.rejects(
      client._withWallClock(new Promise(() => {}), 10, 'POST /sync/rename'),
      (e) => {
        // The hardened primitive raises async/timeout; _withWallClock must
        // translate it to the HermitStash-specific contract callers depend on,
        // not leak the framework code.
        assert.strictEqual(e.code, 'ENC_WALL_CLOCK_TIMEOUT');
        assert.strictEqual(e.permanent, false);
        assert.match(e.message, /wall-clock limit/);
        assert.match(e.message, /POST \/sync\/rename/);
        assert.match(e.message, /Retry/);
        return true;
      },
    );
    client.destroy();
  });

  it('a non-timeout rejection passes through the wall-clock wrapper untranslated', async () => {
    const client = makeClient();
    const orig = new Error('decrypt failed'); orig.code = 'CLIENT_RESPONSE_NOT_JSON';
    await assert.rejects(
      client._withWallClock(Promise.reject(orig), 1000, 'POST /x'),
      (e) => e === orig && e.code === 'CLIENT_RESPONSE_NOT_JSON',
    );
    client.destroy();
  });
});
