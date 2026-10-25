'use strict';
// The boot-time vendor precheck in bin/hermitstash-sync.js refuses to start when
// a vendor/MANIFEST.json entry has no recorded hash: an entry it cannot verify
// counts as a mismatch, as it does in the framework's own check.
//
// A --require preload hands the precheck a manifest with one hash removed; the
// manifest on disk is not touched. Needs no HermitStash server.
//
// Run standalone:
//   node --test tests/test-vendor-precheck.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'hermitstash-sync.js');

test('the boot precheck refuses a manifest entry that has no recorded hash', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'vendor', 'MANIFEST.json'), 'utf8'));
  const kinds = Object.keys(manifest.packages.blamejs.hashes);
  assert.ok(kinds.length > 0, 'the manifest records consumed-file hashes');
  const dropped = kinds[0];
  delete manifest.packages.blamejs.hashes[dropped];

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-vendor-precheck-'));
  try {
    const altered = path.join(dir, 'MANIFEST.json');
    fs.writeFileSync(altered, JSON.stringify(manifest));
    const preload = path.join(dir, 'swap-manifest.js');
    fs.writeFileSync(preload, [
      "'use strict';",
      "const fs = require('node:fs');",
      'const target = ' + JSON.stringify(path.join(ROOT, 'vendor', 'MANIFEST.json')) + ';',
      'const altered = ' + JSON.stringify(altered) + ';',
      'const read = fs.readFileSync;',
      'fs.readFileSync = function (p) {',
      '  if (typeof p === "string" && require("node:path").resolve(p) === require("node:path").resolve(target)) {',
      '    return read.apply(this, [altered].concat(Array.prototype.slice.call(arguments, 1)));',
      '  }',
      '  return read.apply(this, arguments);',
      '};',
      '',
    ].join('\n'));

    const r = spawnSync(process.execPath, ['--require', preload, BIN, 'version'], { encoding: 'utf8', timeout: 60_000 }); // allow:raw-byte-literal — test ceiling
    assert.equal(r.status, 70, 'the precheck exits with EX_SOFTWARE:\n' + r.stdout + r.stderr);
    assert.match(r.stderr, /do not match the recorded SHA256/);
    assert.ok(r.stderr.includes(manifest.packages.blamejs.files[dropped]), 'names the entry it could not verify:\n' + r.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
