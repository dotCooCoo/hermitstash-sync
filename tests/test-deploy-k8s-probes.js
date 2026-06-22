'use strict';

// Verifies the Kubernetes manifest's liveness/readiness probes detect a dead
// daemon via the `status` exit-code contract (0 = RUNNING, 3 = STOPPED).
//
// The probe must be a bare exec of `hermitstash-sync status` so the kubelet
// sees the non-zero exit and restarts the pod. A shell wrapper (sh -c ...,
// grep, ||, ;) would swallow or mask the exit code and is rejected here.
//
// No YAML library is available (zero npm deps), so this parses the small,
// well-known probe blocks structurally from the manifest text.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const MANIFEST = path.join(__dirname, '..', 'deploy', 'kubernetes.yml');

function readManifest() {
  return fs.readFileSync(MANIFEST, 'utf8');
}

// Pull the indented block belonging to a probe key up to the next sibling key
// at the same indentation (or end of file). Returns the block text.
function probeBlock(src, probeKey) {
  const lines = src.split(/\r?\n/);
  const startIdx = lines.findIndex((l) => new RegExp('^(\\s+)' + probeKey + ':\\s*$').test(l));
  assert.notStrictEqual(startIdx, -1, `${probeKey}: not found in manifest`);
  const indent = lines[startIdx].match(/^(\s+)/)[1].length;
  const out = [lines[startIdx]];
  for (let i = startIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') { out.push(line); continue; }
    const lead = line.match(/^(\s*)/)[1].length;
    // A line at the same or lower indent that is a key ends the block.
    if (lead <= indent && /^\s*[A-Za-z]/.test(line)) break;
    out.push(line);
  }
  return out.join('\n');
}

for (const probeKey of ['livenessProbe', 'readinessProbe']) {
  test(`${probeKey} uses a bare exec of status (exit-code contract)`, () => {
    const src = readManifest();
    const block = probeBlock(src, probeKey);

    // exec, not httpGet/tcpSocket/grpc — only exec consults the exit code we own.
    assert.match(block, /\bexec:/, `${probeKey} must use an exec probe`);
    assert.doesNotMatch(block, /\bhttpGet:/, `${probeKey} must not use httpGet`);
    assert.doesNotMatch(block, /\btcpSocket:/, `${probeKey} must not use tcpSocket`);

    // The command must invoke `status` directly.
    assert.match(
      block,
      /command:\s*\[\s*hermitstash-sync\s*,\s*status\s*\]/,
      `${probeKey} command must be [hermitstash-sync, status]`,
    );
  });

  test(`${probeKey} does not shell-wrap the exit code away`, () => {
    const block = probeBlock(readManifest(), probeKey);
    // A shell wrapper or pipeline can mask the non-zero exit (e.g. `sh -c`,
    // `grep`, `||`, `;`). The whole point of this finding's fix is that the
    // raw exit code reaches the kubelet, so reject those forms.
    assert.doesNotMatch(block, /\/bin\/sh/, `${probeKey} must not wrap status in a shell`);
    assert.doesNotMatch(block, /\bgrep\b/, `${probeKey} must not pipe status through grep`);
    assert.doesNotMatch(block, /\|\|/, `${probeKey} must not mask status exit with ||`);
  });
}

test('the manifest still defines a Deployment with a single container', () => {
  const src = readManifest();
  assert.match(src, /kind:\s*Deployment/, 'Deployment kind missing');
  assert.match(src, /name:\s*hermitstash-sync/, 'container/Deployment name missing');
});
