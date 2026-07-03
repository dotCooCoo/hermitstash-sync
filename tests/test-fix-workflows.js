'use strict';

// Static supply-chain invariants for the CI/release workflows.
//
// These four findings are workflow-only (no runtime code path), so the test
// asserts the hardened shape of the committed YAML directly rather than
// exercising a server. Each assertion pins the exact regression the fix closed:
//
//   workflows#43  code-scan.yml   osv-scanner pulled from mutable releases/latest
//                                 and run unverified in a security-events:write job
//   workflows#44  docker-publish  lint/build/smoke checkouts pinned the mutable
//                                 tag name instead of the resolved immutable SHA
//   workflows#45  release.yml     provenance job granted contents:write to a
//                                 tag-pinned reusable workflow that needs read
//   workflows#47  ci.yml          pull-requests:write scoped to the untrusted-code
//                                 lint job; PR comment 403s + reds fork-PR CI

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

var WF = path.join(__dirname, '..', '.github', 'workflows');

function readWf(name) {
  return fs.readFileSync(path.join(WF, name), 'utf8');
}

// Slice a single 2-space-indented job block out of a workflow, from `  <name>:`
// up to the next 2-space job key (or EOF). Bounds a job so a permission check
// can't leak across into a sibling job.
function jobBlock(text, name) {
  var re = new RegExp('\\n  ' + name + ':\\n([\\s\\S]*?)(?=\\n  [A-Za-z_][\\w-]*:\\n|$)');
  var m = re.exec(text);
  assert.ok(m, 'expected a job named "' + name + '"');
  return m[1];
}

// Everything before `\njobs:\n` — the workflow-level header (name/on/permissions/env).
function header(text) {
  var idx = text.indexOf('\njobs:');
  assert.ok(idx > -1, 'workflow has a jobs: section');
  return text.slice(0, idx);
}

// ── workflows#43 — code-scan.yml: osv-scanner pin + checksum verify ──────────
test('code-scan.yml: osv-scanner is version-pinned, not fetched from releases/latest', function () {
  var text = readWf('code-scan.yml');
  assert.ok(
    !/releases\/latest\/download\/osv-scanner/.test(text),
    'osv-scanner must not be downloaded from the mutable releases/latest path'
  );
  assert.ok(
    /releases\/download\/\$\{OSV_VERSION\}\/osv-scanner_linux_amd64/.test(text),
    'osv-scanner download must target a pinned release tag (OSV_VERSION)'
  );
  assert.ok(/OSV_VERSION:\s*v\d+\.\d+\.\d+/.test(text), 'a concrete OSV_VERSION must be pinned');
});

test('code-scan.yml: osv-scanner asset is SHA-256 verified before chmod/exec', function () {
  var text = readWf('code-scan.yml');
  var m = /OSV_SHA256:\s*([0-9a-f]{64})\b/.exec(text);
  assert.ok(m, 'a committed 64-hex SHA-256 (OSV_SHA256) must be present');
  assert.ok(/sha256sum -c -/.test(text), 'the downloaded binary must be checksum-verified');

  // The verify must gate the exec: `sha256sum -c` appears before `chmod +x`,
  // and a mismatch hard-fails (exit 1) rather than silently running/skipping.
  var verifyIdx = text.indexOf('sha256sum -c -');
  var chmodIdx = text.indexOf('chmod +x "${RUNNER_TEMP}/osv-scanner"');
  assert.ok(verifyIdx > -1 && chmodIdx > -1, 'both the verify and chmod steps exist');
  assert.ok(verifyIdx < chmodIdx, 'checksum verification must precede chmod +x');
  assert.ok(
    /checksum mismatch; refusing to execute[\s\S]*?exit 1/.test(text),
    'a checksum mismatch must fail loudly (exit 1)'
  );
});

test('code-scan.yml: pipx security scanners are version-pinned', function () {
  var text = readWf('code-scan.yml');
  assert.ok(/pipx install zizmor==\d/.test(text), 'zizmor must be pinned to a version');
  assert.ok(/pipx install semgrep==\d/.test(text), 'semgrep must be pinned to a version');
  assert.ok(!/pipx install zizmor\s*$/m.test(text), 'zizmor must not float to latest');
  assert.ok(!/pipx install semgrep\s*$/m.test(text), 'semgrep must not float to latest');
});

// ── workflows#44 — docker-publish.yml: checkout the resolved SHA ─────────────
test('docker-publish.yml: all code checkouts pin the resolved immutable SHA', function () {
  var text = readWf('docker-publish.yml');
  assert.ok(
    !/ref:\s*\$\{\{\s*needs\.resolve-tag\.outputs\.tag\s*\}\}/.test(text),
    'no checkout may bind ref: to the mutable tag NAME'
  );
  var shaRefs = (text.match(/ref:\s*\$\{\{\s*needs\.resolve-tag\.outputs\.sha\s*\}\}/g) || []).length;
  assert.strictEqual(shaRefs, 3, 'lint + build-and-push + smoke-test checkouts all use outputs.sha');

  // The provenance label + build-arg still consume the same resolved SHA, so
  // built bytes and stamped commit stay identical.
  assert.ok(/org\.opencontainers\.image\.revision=\$\{\{\s*needs\.resolve-tag\.outputs\.sha/.test(text));
  assert.ok(/COMMIT_SHA=\$\{\{\s*needs\.resolve-tag\.outputs\.sha/.test(text));
});

// ── release.yml: provenance job grants the SLSA reusable workflow contents:write
// GitHub validates a caller against the permissions a called reusable workflow
// DECLARES: the SLSA generator (generator_generic_slsa3.yml) declares
// contents:write in its own permissions block, so a caller that grants less
// fails the ENTIRE run at startup (startup_failure), before any job runs —
// regardless of upload-assets:false. The write must be present.
test('release.yml: provenance job grants the SLSA reusable workflow contents:write', function () {
  var text = readWf('release.yml');
  var block = jobBlock(text, 'provenance');
  assert.ok(/contents:\s+write/.test(block), 'provenance MUST grant contents:write — the SLSA reusable workflow declares it and GitHub startup-fails a caller that under-grants');
  assert.ok(!/contents:\s+read/.test(block), 'provenance must not down-grant contents to read (fails the run at startup)');
  assert.ok(/id-token:\s+write/.test(block), 'id-token:write is required for Sigstore-keyless');
  assert.ok(/actions:\s+read/.test(block), 'actions:read is required to introspect the run');

  // The write that attaches the release lives on `publish`.
  var publish = jobBlock(text, 'publish');
  assert.ok(/contents:\s+write/.test(publish), 'publish job retains contents:write for gh release create');
});

// ── workflows#47 — ci.yml: PR-comment write scoped off the lint job ──────────
test('ci.yml: workflow default and lint job are read-only (no pull-requests:write)', function () {
  var text = readWf('ci.yml');
  assert.ok(
    !/pull-requests:\s+write/.test(header(text)),
    'the workflow-level default must not grant pull-requests:write'
  );
  var lint = jobBlock(text, 'lint');
  assert.ok(
    !/pull-requests:\s+write/.test(lint),
    'the lint job (runs untrusted PR code) must not hold pull-requests:write'
  );
  assert.ok(/outputs:\s*\n\s*summary_body:/.test(lint), 'lint exposes summary_body as a job output');
});

test('ci.yml: PR comment is an isolated job with write, guarded to same-repo PRs', function () {
  var text = readWf('ci.yml');
  var comment = jobBlock(text, 'comment');
  assert.ok(/pull-requests:\s+write/.test(comment), 'the comment job holds pull-requests:write');
  assert.ok(/needs:\s*lint/.test(comment), 'the comment job depends on lint');
  assert.ok(
    /github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository/.test(comment),
    'the comment job is gated to same-repo PRs so fork PRs do not 403 the check'
  );
  assert.ok(
    /needs\.lint\.outputs\.summary_body/.test(comment),
    'the comment job consumes the summary via job output, not a fresh checkout'
  );
  // The comment job must not check out the (untrusted) PR code.
  assert.ok(!/actions\/checkout/.test(comment), 'the write-capable comment job must not check out PR code');
});
