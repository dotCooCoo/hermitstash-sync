'use strict';

// Tests for the server-URL display masking that backs the CodeQL
// js/clear-text-logging fix. lib/cli.js routes every configured/env-supplied
// server URL through safeServerLabel before it reaches a console sink (status,
// repair, init), so:
//   1. an embedded user:pass@host credential can NEVER appear in a log line
//      (b.safeUrl.parse refuses userinfo outright),
//   2. only the validated, normalized scheme + host[:port] is shown (path,
//      query, fragment dropped),
//   3. a malformed value yields an actionable placeholder, never a throw.
// Server-independent — exercises the real production helper, no reimplementation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { safeServerLabel } = require('../lib/cli');

describe('safeServerLabel — server URL display masking', () => {
  it('returns scheme + host[:port] and drops path/query/fragment', () => {
    assert.equal(safeServerLabel('https://example.com:8443/sync?x=1#f'), 'https://example.com:8443');
    assert.equal(safeServerLabel('https://example.com/'), 'https://example.com');
    assert.equal(safeServerLabel('http://10.0.0.5:9000'), 'http://10.0.0.5:9000');
  });

  it('NEVER leaks user:pass@ credentials embedded in the authority', () => {
    const withCreds = 'https://alice:s3cr3tP@ss@example.com:8443/x';
    const label = safeServerLabel(withCreds);
    assert.ok(!label.includes('alice'), `label must not contain the username: ${label}`);
    assert.ok(!label.includes('s3cr3tP'), `label must not contain the password: ${label}`);
    // A userinfo-bearing URL is refused by b.safeUrl.parse, so it falls to the
    // actionable placeholder rather than a partially-masked credential string.
    assert.ok(/invalid server URL/.test(label), `expected the invalid-URL placeholder, got: ${label}`);
  });

  it('returns an actionable placeholder for a malformed value instead of throwing', () => {
    for (const bad of ['not a url', '', 'ftp://example.com', 'javascript:alert(1)', '   ']) {
      const label = safeServerLabel(bad);
      assert.equal(label, '(invalid server URL — run "hermitstash-sync init")',
        `unexpected label for ${JSON.stringify(bad)}: ${label}`);
    }
  });

  it('refuses a non-http(s) scheme even if otherwise well-formed', () => {
    assert.ok(/invalid server URL/.test(safeServerLabel('file:///etc/passwd')));
    assert.ok(/invalid server URL/.test(safeServerLabel('ws://example.com')));
  });
});
