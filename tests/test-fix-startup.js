'use strict';

// Regression tests for the startup-lane audit fixes (cli#19, cli#20, cli#21).
//
// These exercise the REAL production entry points — the actual bin/
// hermitstash-sync.js boot gate and the real lib/cli.js cmdInit/cmdStart — with
// no test-only reimplementation:
//   * cli#19 drives the real Node-floor IIFE in bin/hermitstash-sync.js by
//     spawning it with a forced process.versions.node value and asserting the
//     real process.exit(78) fires below the floor (and does not fire at/above it
//     or on a genuinely-unparseable string).
//   * cli#20 asserts the boot ordering in cmdStart: the NTP wall-clock gate must
//     run before the Date.now()-dependent auto-update rollback decision.
//   * cli#21 drives the real interactive `init` enrollment branch with an empty
//     code and asserts the local "Enrollment code required." guard fires before
//     any network round-trip (no config is written).
//
// None of these touch the shared HTTPS/mTLS test server, shared settings, the
// session table, or a shared rate-limit window — each spawns an isolated child
// with its own HERMITSTASH_SYNC_CONFIG_DIR — so this file does NOT belong in the
// run-all.js SEQUENTIAL stage.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const nodeCp = require('node:child_process');

const REPO_ROOT = nodePath.join(__dirname, '..');
const BIN_PATH = nodePath.join(REPO_ROOT, 'bin', 'hermitstash-sync.js');
const CLI_PATH = nodePath.join(REPO_ROOT, 'lib', 'cli.js');
const BIN_SRC = nodeFs.readFileSync(BIN_PATH, 'utf8');
const CLI_SRC = nodeFs.readFileSync(CLI_PATH, 'utf8');

// ---------------------------------------------------------------------------
// cli#19 — the Node.js runtime floor gate must actually enforce 24.18.0.
//
// The prior regex was anchored to a literal 'v' (`/^v(\d+)...`) but parsed
// process.versions.node, which is the BARE triple ("24.18.0", no 'v'). The
// match always returned null, the `if (!m) return;` branch let every version
// through, and the floor was never enforced on any Node version.
// ---------------------------------------------------------------------------
describe('cli#19 — Node-floor boot gate enforces 24.18.0', () => {
  // Spawn the REAL bin with process.versions.node forced to `nodeVer`. The
  // Node-floor IIFE is the first thing bin/hermitstash-sync.js runs, so a
  // below-floor value exits 78 before any other boot work; an at/above-floor
  // (or unparseable) value lets boot continue into `version`, which exits 0.
  function driveBinWithNodeVersion(nodeVer) {
    const driver =
      'Object.defineProperty(process.versions,"node",' +
      '{value:' + JSON.stringify(nodeVer) + ',configurable:true,writable:true});' +
      'process.argv=[process.execPath,' + JSON.stringify(BIN_PATH) + ',"version"];' +
      'require(' + JSON.stringify(BIN_PATH) + ');';
    return nodeCp.spawnSync(process.execPath, ['-e', driver], { encoding: 'utf8' });
  }

  it('exits 78 (EX_CONFIG) when the runtime is below the floor', () => {
    for (const ver of ['24.17.9', '24.4.0', '23.99.99', '10.0.0']) {
      const r = driveBinWithNodeVersion(ver);
      assert.equal(r.status, 78,
        `Node ${ver} is below the 24.18.0 floor and must be refused with exit 78 (got ${r.status})`);
      assert.match(r.stderr || '', /requires Node\.js 24\.18\.0 or newer/,
        `Node ${ver} must surface the actionable floor error`);
    }
  });

  it('does NOT exit 78 at or above the floor', () => {
    for (const ver of ['24.18.0', '24.19.0', '25.0.0', '30.1.2']) {
      const r = driveBinWithNodeVersion(ver);
      assert.notEqual(r.status, 78,
        `Node ${ver} is at/above the 24.18.0 floor and must be allowed (got exit ${r.status}, stderr: ${r.stderr})`);
      assert.equal(r.status, 0,
        `Node ${ver} should boot through to the version command and exit 0 (got ${r.status})`);
    }
  });

  it('parses the at-floor prerelease/nightly triple and allows it', () => {
    // Unanchored tail ignores the "-nightly..." suffix; 24.18.0 == floor passes.
    const r = driveBinWithNodeVersion('24.18.0-nightly20250101abcdef');
    assert.equal(r.status, 0,
      `an at-floor prerelease build must be allowed (got ${r.status}, stderr: ${r.stderr})`);
  });

  it('treats a genuinely-unparseable version as "let it through" (fail-open, documented)', () => {
    for (const ver of ['garbage', '', 'v.notaversion']) {
      const r = driveBinWithNodeVersion(ver);
      assert.notEqual(r.status, 78,
        `an unparseable version (${JSON.stringify(ver)}) must not be rejected by the floor gate`);
    }
  });

  it('source: the gate reads process.versions.node with an optional-v prefix (dead anchored regex removed)', () => {
    assert.ok(
      BIN_SRC.includes('/^v?(\\d+)\\.(\\d+)\\.(\\d+)/.exec(process.versions.node)'),
      'the floor gate must parse process.versions.node with an OPTIONAL v prefix');
    assert.ok(
      !BIN_SRC.includes('/^v(\\d+)\\.(\\d+)\\.(\\d+)/.exec(process.versions.node)'),
      'the dead mandatory-v regex against process.versions.node must be gone');
  });
});

// ---------------------------------------------------------------------------
// cli#20 — the NTP wall-clock boot gate must run BEFORE updater.checkRollback().
//
// checkRollback makes an irreversible, Date.now()-based probation/rollback
// decision (rename the running exe, restore/prune .prev, respawn). It must not
// act on a clock the gate has not yet validated, so _ntpBootGate() has to come
// first. Both calls appear exactly once in the file, so a simple ordered index
// comparison is an unambiguous regression guard.
// ---------------------------------------------------------------------------
describe('cli#20 — clock gate precedes the auto-update rollback decision', () => {
  it('_ntpBootGate() runs before updater.checkRollback() in cmdStart', () => {
    const ntpCalls = (CLI_SRC.match(/await _ntpBootGate\(\);/g) || []).length;
    const rollbackCalls = (CLI_SRC.match(/await updater\.checkRollback\(\);/g) || []).length;
    assert.equal(ntpCalls, 1, 'expected exactly one _ntpBootGate() call site');
    assert.equal(rollbackCalls, 1, 'expected exactly one updater.checkRollback() call site');

    const iNtp = CLI_SRC.indexOf('await _ntpBootGate();');
    const iRollback = CLI_SRC.indexOf('await updater.checkRollback();');
    const iLogInit = CLI_SRC.indexOf('await log.init(');
    assert.ok(iLogInit > 0 && iNtp > 0 && iRollback > 0, 'all three call sites must exist');
    assert.ok(iLogInit < iNtp, 'the NTP gate must run after logger init');
    assert.ok(iNtp < iRollback,
      'the NTP wall-clock gate must run BEFORE the Date.now()-dependent rollback check');
  });

  it('both call sites are inside cmdStart', () => {
    const startIdx = CLI_SRC.indexOf('async function cmdStart(');
    assert.ok(startIdx >= 0, 'cmdStart must exist');
    // The next top-level `async function ` after cmdStart bounds its body.
    const nextFn = CLI_SRC.indexOf('\nasync function ', startIdx + 1);
    const body = CLI_SRC.slice(startIdx, nextFn > 0 ? nextFn : CLI_SRC.length);
    assert.ok(/await _ntpBootGate\(\);/.test(body), 'the NTP gate call must live in cmdStart');
    assert.ok(/await updater\.checkRollback\(\);/.test(body), 'the rollback call must live in cmdStart');
  });
});

// ---------------------------------------------------------------------------
// cli#21 — the interactive `init` enrollment branch must reject an empty code
// locally, matching cmdRepair's "Code required." short-circuit, instead of
// POSTing {code:''} and surfacing a generic server-side "Init failed".
// ---------------------------------------------------------------------------
describe('cli#21 — init rejects an empty enrollment code before any network call', () => {
  // Drive the REAL cmdInit through run(['init']) in a child process, answering
  // each prompt as it appears (prompt-driven so readline never races the feed).
  // The enrollment code is left EMPTY. Resolves with the child's exit code,
  // stderr, and whether a config.json was written.
  function driveInitWithEmptyCode() {
    return new Promise((resolve) => {
      const tmp = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'hs-init-'));
      const driver =
        'const cli=require(' + JSON.stringify(CLI_PATH) + ');' +
        'cli.run(["init"]).catch(e=>{process.stderr.write(String(e&&e.message||e)+"\\n");process.exit(1);});';
      const child = nodeCp.spawn(process.execPath, ['-e', driver], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: Object.assign({}, process.env, { HERMITSTASH_SYNC_CONFIG_DIR: tmp }),
      });
      let out = '';
      let err = '';
      const steps = [
        { match: /Server URL/, send: 'https://example.test\n' },
        { match: /Local folder to sync/, send: tmp.replace(/\\/g, '/') + '/sync\n' },
        { match: /Setup method/, send: '\n' },     // blank => enrollment (the default)
        { match: /Enrollment code/, send: '\n' },  // EMPTY => the guard must fire
      ];
      let step = 0;
      child.stdout.on('data', (d) => {
        out += d;
        while (step < steps.length && steps[step].match.test(out)) {
          const s = steps[step];
          step += 1;
          try { child.stdin.write(s.send); } catch (_e) { /* child may have exited */ }
        }
      });
      child.stderr.on('data', (d) => { err += d; });
      const killTimer = setTimeout(() => { try { child.kill(); } catch (_e) {} }, 25000);
      child.on('exit', (code) => {
        clearTimeout(killTimer);
        const configExists = nodeFs.existsSync(nodePath.join(tmp, 'config.json'));
        try { nodeFs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) {}
        resolve({ code, err: err.trim(), configExists });
      });
    });
  }

  it('exits 1 with the local "Enrollment code required." error and writes no config', async () => {
    const r = await driveInitWithEmptyCode();
    assert.equal(r.code, 1, 'an empty enrollment code must fail fast with exit 1');
    assert.match(r.err, /Enrollment code required\./,
      'the local presence guard must surface "Enrollment code required."');
    assert.doesNotMatch(r.err, /Init failed/,
      'the guard must fire locally — an empty code must NOT reach the enrollment exchange');
    assert.equal(r.configExists, false, 'no config may be written when enrollment is refused');
  });

  it('source: the enrollment branch guards the empty code before exchangeEnrollmentCode', () => {
    const elseIdx = CLI_SRC.indexOf("const code = await ask('Enrollment code");
    assert.ok(elseIdx >= 0, 'the interactive enrollment-code prompt must exist');
    const exchangeIdx = CLI_SRC.indexOf('exchangeEnrollmentCode(server, code)', elseIdx);
    assert.ok(exchangeIdx > elseIdx, 'the enrollment exchange must follow the prompt');
    const between = CLI_SRC.slice(elseIdx, exchangeIdx);
    assert.match(between, /if \(!code\.trim\(\)\) die\('Enrollment code required\.'\);/,
      'the empty-code guard must sit between the prompt and the enrollment exchange');
  });
});
