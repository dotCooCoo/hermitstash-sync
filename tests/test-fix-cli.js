'use strict';

// Pure-unit regression tests for the lib/cli.js audit fixes. No server harness,
// no network: enrollment-status acceptance is exercised by stubbing
// b.httpClient.request on the shared framework singleton; the timer-lifetime /
// readline-close / watchdog-teardown fixes are verified through the real
// b.safeAsync primitive plus source-level guards against the exact prior bug.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');

const b = require('../vendor/blamejs');
const cli = require('../lib/cli');

const CLI_SRC = nodeFs.readFileSync(nodePath.join(__dirname, '..', 'lib', 'cli.js'), 'utf8');

// cli+daemon+bin#15 — exchangeEnrollmentCode accepts the full 2xx range and
// keys success off the parsed body, not a brittle statusCode===200 equality.
describe('cli+daemon+bin#15 — enrollment accepts any 2xx success', () => {
  const realRequest = b.httpClient.request;

  function stubResponse(statusCode, bodyObj) {
    b.httpClient.request = async () => ({
      statusCode,
      body: Buffer.from(JSON.stringify(bodyObj), 'utf8'),
    });
  }

  before(() => { /* each test sets its own stub */ });
  after(() => { b.httpClient.request = realRequest; });

  it('accepts a 200 with { success: true }', async () => {
    stubResponse(200, { success: true, apiKey: 'k-200' });
    const data = await cli.exchangeEnrollmentCode('https://example.test', 'HSTASH-AAAA-BBBB-CCCC');
    assert.equal(data.apiKey, 'k-200');
  });

  it('accepts a 201 success (regression: old code rejected non-200 2xx)', async () => {
    stubResponse(201, { success: true, apiKey: 'k-201' });
    const data = await cli.exchangeEnrollmentCode('https://example.test', 'HSTASH-AAAA-BBBB-CCCC');
    assert.equal(data.apiKey, 'k-201', '201 Created must be accepted, not rejected as a status error');
  });

  it('accepts a 202 success', async () => {
    stubResponse(202, { success: true, apiKey: 'k-202' });
    const data = await cli.exchangeEnrollmentCode('https://example.test', 'HSTASH-AAAA-BBBB-CCCC');
    assert.equal(data.apiKey, 'k-202');
  });

  it('rejects a 2xx body without success, surfacing detail/error', async () => {
    stubResponse(200, { success: false, detail: 'code expired' });
    await assert.rejects(
      cli.exchangeEnrollmentCode('https://example.test', 'HSTASH-AAAA-BBBB-CCCC'),
      /code expired/);
  });

  it('rejects a 2xx body with no fields without throwing on null access', async () => {
    // success absent → treated as failure with the generic message; the null
    // guard (`!data || !data.success`) must not NPE on a sparse body.
    stubResponse(200, {});
    await assert.rejects(
      cli.exchangeEnrollmentCode('https://example.test', 'HSTASH-AAAA-BBBB-CCCC'),
      /Enrollment failed/);
  });

  it('source no longer gates success on statusCode !== 200', () => {
    assert.ok(!/resp\.statusCode\s*!==\s*200/.test(CLI_SRC),
      'the dead/unreachable statusCode !== 200 success clause must be gone');
    assert.ok(/!data\s*\|\|\s*!data\.success/.test(CLI_SRC),
      'success must key off a null-guarded data.success');
  });
});

// cli+daemon+bin#13 — `log --follow` must hold the event loop open. The fix
// passes { unref: false } to b.safeAsync.repeating. Verify the primitive
// behavior the fix depends on, and that the follow branch opts into it.
describe('cli+daemon+bin#13 — log --follow keeps the loop alive (ref\'d timer)', () => {
  it('b.safeAsync.repeating({unref:false}) returns a live handle that ticks', async () => {
    let ticks = 0;
    const r = b.safeAsync.repeating(() => { ticks += 1; }, 20, { unref: false });
    try {
      // Generous window so a loaded CI box still fires the interval at least
      // once; the point is the repeater is live, not its exact cadence.
      await b.safeAsync.sleep(300);
      assert.ok(ticks >= 1, `expected the repeater to tick at least once, got ${ticks}`);
    } finally {
      r.stop();
    }
  });

  it('default (no unref opt) is unref\'d — the prior bug shape', () => {
    // Documents WHY the fix is needed: the framework default does not keep the
    // loop alive, so the follow branch must explicitly pass unref:false.
    let ticks = 0;
    const r = b.safeAsync.repeating(() => { ticks += 1; }, 20);
    r.stop();
    assert.equal(ticks, 0);
  });

  it('follow branch passes unref:false to the repeater', () => {
    assert.ok(/}, 500, \{ unref: false,/.test(CLI_SRC),
      'the log --follow repeater must pass { unref: false } so the tail does not exit immediately');
  });
});

// cli+daemon+bin#14 — cmdRepair routes config reads through the single entry
// point (loadConfigOrDie / config.load), not a hand-rolled re-parse.
describe('cli+daemon+bin#14 — cmdRepair uses the central config loader', () => {
  it('cmdRepair no longer hand-parses CONFIG_FILE', () => {
    const repairStart = CLI_SRC.indexOf('async function cmdRepair()');
    assert.ok(repairStart >= 0, 'cmdRepair must exist');
    const repairBody = CLI_SRC.slice(repairStart, CLI_SRC.indexOf('\n}', repairStart) + 2);
    assert.ok(!/b\.safeJson\.parse\(nodeFs\.readFileSync\(CONFIG_FILE/.test(repairBody),
      'cmdRepair must not re-parse CONFIG_FILE by hand');
    assert.ok(/loadConfigOrDie\(\)/.test(repairBody) || /config\.load\(\)/.test(repairBody),
      'cmdRepair must load config through the centralised loader');
  });
});

// cli+daemon+bin#16 — the always-true `rl.terminal !== undefined` guard is
// removed; the success-path close is unconditional.
describe('cli+daemon+bin#16 — readline close is unconditional', () => {
  it('rl.terminal !== undefined guard is gone', () => {
    assert.ok(!/rl\.terminal\s*!==\s*undefined/.test(CLI_SRC),
      'the dead rl.terminal !== undefined guard must be removed');
  });

  it('readline.Interface.terminal is in fact always a boolean (never undefined)', () => {
    const nodeReadline = require('node:readline');
    // A non-TTY input — proves the old guard was constant-true.
    const rl = nodeReadline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    try {
      assert.equal(typeof rl.terminal, 'boolean');
      assert.notEqual(rl.terminal, undefined);
    } finally {
      rl.close();
    }
  });
});

// cli+daemon+bin#17 — the watchdog interval is cleared on shutdown (graceful
// and self-update paths), and is hoisted so those closures can see it.
describe('cli+daemon+bin#17 — watchdog timer is cleared on shutdown', () => {
  it('watchdogTimer is hoisted as a reassignable binding', () => {
    assert.ok(/let watchdogTimer = null;/.test(CLI_SRC),
      'watchdogTimer must be hoisted (let) so the shutdown closures can clear it');
    assert.ok(!/const watchdogTimer = setInterval/.test(CLI_SRC),
      'watchdogTimer must not be a const local that the shutdown path cannot reach');
  });

  it('both teardown paths clear the watchdog interval', () => {
    const clears = (CLI_SRC.match(/clearInterval\(watchdogTimer\)/g) || []).length;
    assert.ok(clears >= 2,
      `expected the watchdog cleared in both the shutdown and self-update closures, found ${clears}`);
  });
});
