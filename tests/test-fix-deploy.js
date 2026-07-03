'use strict';

// Regression guards for the deploy-surface hardening fixes. These are static
// assertions over the checked-in deploy artifacts (no server needed), so a
// future edit can't silently reintroduce a fixed defect.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

test('Dockerfile: BOTH the verify-stage and runtime base images are digest-pinned', () => {
  const df = read('Dockerfile');
  const nodeArg = df.match(/^ARG NODE_VERSION=(\S+)/m);
  const baseArg = df.match(/^ARG RUNTIME_BASE=(\S+)/m);
  assert.ok(nodeArg, 'NODE_VERSION ARG present');
  assert.ok(baseArg, 'RUNTIME_BASE ARG present');
  // The verify stage runs the crypto check AND produces the shipped binary, so
  // a mutable-tag base there defeats the whole signed-binary trust model.
  assert.match(nodeArg[1], /@sha256:[0-9a-f]{64}$/, 'NODE_VERSION (verify base) must be digest-pinned, not a mutable tag');
  assert.match(baseArg[1], /@sha256:[0-9a-f]{64}$/, 'RUNTIME_BASE must be digest-pinned');
});

test('deploy/update.sh: systemctl restart cannot abort before the rollback under set -e', () => {
  const s = read('deploy/update.sh');
  // Every `systemctl restart` must be guarded so a non-zero (crash-looping /
  // never-ready binary) restart falls through to the health probe + rollback
  // instead of aborting the script with the broken binary installed.
  const restarts = s.split('\n').filter((l) => /^\s*systemctl restart /.test(l));
  assert.ok(restarts.length >= 2, 'expected the forward + rollback restart calls');
  for (const line of restarts) {
    assert.match(line, /\|\|\s*warn /, `unguarded restart would abort under set -e: ${line.trim()}`);
  }
  assert.match(s, /rm -f "\$\{BIN:-\}\.new"/, 'the EXIT trap must also clean a stale ${BIN}.new');
});

test('deploy/install.sh: latest-release resolve stays reachable + operator env is not clobbered', () => {
  const s = read('deploy/install.sh');
  // The VERSION resolve must not abort under set -e before the actionable hint.
  assert.match(s, /releases\/latest[\s\S]*?\|\| true/, 'VERSION resolve must be `|| true` so the empty-check hint is reachable');
  // A re-run must not reset the operator-edited updater env to the default.
  assert.match(s, /if \[ ! -f \/etc\/default\/hermitstash-sync-update \]; then/, 'env install must be gated on absence, not an unconditional overwrite');
});

test('deploy/uninstall.sh: the binary removal loop also sweeps a stale .new', () => {
  const s = read('deploy/uninstall.sh');
  assert.match(s, /hermitstash-sync\.new/, 'uninstall must remove an interrupted-update .new binary');
});

test('deploy/podman.sh: first-run waits for enrollment before handing off to Quadlet', () => {
  const s = read('deploy/podman.sh');
  // lastIndexOf: the FIRST `podman rm -f` is a pre-run cleanup before `podman
  // run`; the LAST is the Quadlet handoff swap the wait must precede.
  const swapIdx = s.lastIndexOf('podman rm -f "${CONTAINER_NAME}"');
  const waitIdx = s.indexOf('/config/config.json');
  assert.ok(waitIdx !== -1, 'must poll for the persisted config.json');
  assert.ok(swapIdx !== -1 && waitIdx < swapIdx, 'the enrollment wait must precede the Quadlet container swap');
});

test('deploy/kubernetes.yml: SA token opt-out + Always pull for the mutable tag', () => {
  const s = read('deploy/kubernetes.yml');
  assert.match(s, /automountServiceAccountToken:\s*false/, 'outbound-only pod must opt out of the default SA token');
  assert.match(s, /imagePullPolicy:\s*Always/, ':latest must use Always so security rebuilds are re-pulled');
  assert.doesNotMatch(s, /imagePullPolicy:\s*IfNotPresent/, 'IfNotPresent pins the node to a stale cached :latest');
});

test('unraid-template.xml: no misleading PUID/PGID vars (image is fixed uid 1000)', () => {
  const s = read('unraid-template.xml');
  assert.doesNotMatch(s, /Target="PUID"/, 'PUID is silently ignored by the fixed-uid image — must not be advertised');
  assert.doesNotMatch(s, /Target="PGID"/, 'PGID is silently ignored by the fixed-uid image — must not be advertised');
});
