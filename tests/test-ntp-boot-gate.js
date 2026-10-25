'use strict';

// The startup clock check when no time server answers: it continues with a
// warning by default, refuses under HERMITSTASH_NTP_STRICT=1, and refuses
// under BLAMEJS_NTP_REQUIRE_REACHABLE=1, which the framework itself acts on.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const b = require('../vendor/blamejs');
const { _ntpBootGate } = require('../lib/cli');

const UNREACHABLE = {
  ok: true, severity: 'warning', driftMs: null, server: 'time.cloudflare.com',
  unreachableReason: 'time.cloudflare.com: getaddrinfo EAI_AGAIN time.cloudflare.com',
  message: 'NTP unreachable: time.cloudflare.com: getaddrinfo EAI_AGAIN time.cloudflare.com (continuing; set BLAMEJS_NTP_REQUIRE_REACHABLE=1 to refuse the boot instead)',
};

describe('NTP boot gate when no time server answers', () => {
  let realBootCheck, realExit, realError, realStrict, died;

  beforeEach(() => {
    realBootCheck = b.ntpCheck.bootCheck;
    realExit = process.exit;
    realError = console.error;
    realStrict = process.env.HERMITSTASH_NTP_STRICT;
    delete process.env.HERMITSTASH_NTP_STRICT;
    died = null;
    console.error = (msg) => { died = String(msg); };
    process.exit = (code) => { throw Object.assign(new Error('exit ' + code), { exitCode: code }); };
  });

  afterEach(() => {
    b.ntpCheck.bootCheck = realBootCheck;
    process.exit = realExit;
    console.error = realError;
    if (realStrict === undefined) delete process.env.HERMITSTASH_NTP_STRICT;
    else process.env.HERMITSTASH_NTP_STRICT = realStrict;
  });

  it('continues by default', async () => {
    b.ntpCheck.bootCheck = async () => UNREACHABLE;
    await _ntpBootGate();
    assert.equal(died, null);
  });

  it('refuses under HERMITSTASH_NTP_STRICT=1 and names the reason without the framework advice', async () => {
    process.env.HERMITSTASH_NTP_STRICT = '1';
    b.ntpCheck.bootCheck = async () => UNREACHABLE;
    await assert.rejects(_ntpBootGate(), { exitCode: 1 });
    assert.equal(died, 'NTP unreachable: time.cloudflare.com: getaddrinfo EAI_AGAIN time.cloudflare.com. Refusing to start because HERMITSTASH_NTP_STRICT=1.');
  });

  it('refuses under BLAMEJS_NTP_REQUIRE_REACHABLE=1 and names that variable, not a clock resync', async () => {
    b.ntpCheck.bootCheck = async () => Object.assign({}, UNREACHABLE, {
      ok: false, severity: 'fatal',
      message: 'NTP unreachable: time.cloudflare.com: getaddrinfo EAI_AGAIN time.cloudflare.com (BLAMEJS_NTP_REQUIRE_REACHABLE=1 refuses the boot rather than run on an unverified clock)',
    });
    await assert.rejects(_ntpBootGate(), { exitCode: 1 });
    assert.match(died, /^NTP unreachable: time\.cloudflare\.com: getaddrinfo EAI_AGAIN time\.cloudflare\.com\. Refusing to start because BLAMEJS_NTP_REQUIRE_REACHABLE=1\./);
    assert.doesNotMatch(died, /Resync the system clock/);
  });
});
