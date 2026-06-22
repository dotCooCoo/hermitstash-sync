'use strict';

// Unit coverage for the test runner's pass/fail tally (tests/run-all.js).
//
// The runner reports a file as failed from the child process exit code as the
// source of truth — not by scraping per-test glyphs from stdout. These tests
// pin that contract: a clean run tallies from the canonical TAP summary, and a
// child that crashes after its first assertion (non-zero exit, missing or
// zero-fail summary) is still counted as a failure so the human tally can never
// read green on a crash.
//
// Pure unit test — no server. Run standalone:
//   node --test tests/test-run-all-tally.js

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseTapSummary, tallyAndPrint } = require('./run-all');

// A representative passing TAP tail from `node --test --test-reporter=tap`.
const PASS_TAP = [
  'TAP version 13',
  '# Subtest: a passes',
  'ok 1 - a passes',
  '1..2',
  '# tests 2',
  '# suites 0',
  '# pass 2',
  '# fail 0',
  '# cancelled 0',
  '# skipped 0',
  '# todo 0',
  '# duration_ms 52.4',
].join('\n');

const FAIL_TAP = [
  'TAP version 13',
  'not ok 1 - a fails',
  '1..2',
  '# tests 2',
  '# pass 1',
  '# fail 1',
  '# duration_ms 60.1',
].join('\n');

function freshTotals() {
  return { pass: 0, fail: 0, failures: [] };
}

test('parseTapSummary reads the canonical summary block', () => {
  const s = parseTapSummary(PASS_TAP);
  assert.equal(s.hasSummary, true);
  assert.equal(s.pass, 2);
  assert.equal(s.fail, 0);
});

test('parseTapSummary ignores inline glyphs and per-test result lines', () => {
  // A passing run whose assertion output happens to embed ✔/✖ glyphs and a
  // unicode filename must not inflate the counts — only the # pass / # fail
  // summary lines drive the tally.
  const noisy = [
    'TAP version 13',
    'ok 1 - uploads ✔ file ✓✓✓',
    '# expected: "rénamed-✖.txt"',
    'not ok-looking text that is not a summary line',
    '1..1',
    '# tests 1',
    '# pass 1',
    '# fail 0',
    '# duration_ms 10.0',
  ].join('\n');
  const s = parseTapSummary(noisy);
  assert.equal(s.pass, 1, 'glyphs in assertion text must not be counted as passes');
  assert.equal(s.fail, 0, 'glyphs in assertion text must not be counted as fails');
});

test('parseTapSummary reports no summary when the block is absent', () => {
  const s = parseTapSummary('TAP version 13\n# Subtest: a\nok 1 - a\n');
  assert.equal(s.hasSummary, false);
  assert.equal(s.pass, 0);
  assert.equal(s.fail, 0);
});

test('tallyAndPrint counts a clean pass from the summary', () => {
  const totals = freshTotals();
  tallyAndPrint({ file: 'test-x.js', output: PASS_TAP, status: 0, durationMs: 10 }, totals);
  assert.equal(totals.pass, 2);
  assert.equal(totals.fail, 0);
  assert.equal(totals.failures.length, 0);
});

test('tallyAndPrint records a reported failure (non-zero exit + # fail)', () => {
  const totals = freshTotals();
  tallyAndPrint({ file: 'test-x.js', output: FAIL_TAP, status: 1, durationMs: 10 }, totals);
  assert.equal(totals.pass, 1);
  assert.equal(totals.fail, 1);
  assert.equal(totals.failures.length, 1);
  assert.equal(totals.failures[0].file, 'test-x.js');
  assert.equal(totals.failures[0].crashed, undefined);
});

test('tallyAndPrint counts a crash-after-first-assertion as a failure', () => {
  // The child printed a partial stream with no TAP summary (timeout SIGKILL,
  // OOM, hard crash) and exited non-zero. The parsed fail count is 0 but the
  // file MUST register as failed — exit code is the source of truth.
  const partial = 'TAP version 13\n# Subtest: a passes\nok 1 - a passes\n';
  const totals = freshTotals();
  tallyAndPrint({ file: 'test-crash.js', output: partial, status: 137, durationMs: 10 }, totals);
  assert.equal(totals.fail, 1, 'a non-zero exit with no summary must count as a failure');
  assert.equal(totals.failures.length, 1);
  assert.equal(totals.failures[0].crashed, true);
  assert.equal(totals.failures[0].status, 137);
});

test('tallyAndPrint flags a non-zero exit whose summary claims zero failures', () => {
  // Pathological: a file reports "# fail 0" yet the process exits non-zero
  // (e.g. an unhandled rejection escaping after the summary). Trust the exit
  // code and mark it failed rather than letting it read green.
  const zeroFailSummary = [
    'TAP version 13',
    'ok 1 - a',
    '1..1',
    '# tests 1',
    '# pass 1',
    '# fail 0',
    '# duration_ms 5.0',
  ].join('\n');
  const totals = freshTotals();
  tallyAndPrint({ file: 'test-late-crash.js', output: zeroFailSummary, status: 1, durationMs: 5 }, totals);
  assert.equal(totals.fail, 1);
  assert.equal(totals.failures.length, 1);
  assert.equal(totals.failures[0].crashed, true);
});

test('tallyAndPrint does not double-count: pass total reflects summary only', () => {
  const totals = freshTotals();
  // Two clean files: 2 + 1 passes, no fails.
  tallyAndPrint({ file: 'a.js', output: PASS_TAP, status: 0, durationMs: 1 }, totals);
  const oneOk = [
    'TAP version 13',
    'ok 1 - solo',
    '1..1',
    '# tests 1',
    '# pass 1',
    '# fail 0',
    '# duration_ms 1.0',
  ].join('\n');
  tallyAndPrint({ file: 'b.js', output: oneOk, status: 0, durationMs: 1 }, totals);
  assert.equal(totals.pass, 3);
  assert.equal(totals.fail, 0);
  assert.equal(totals.failures.length, 0);
});
