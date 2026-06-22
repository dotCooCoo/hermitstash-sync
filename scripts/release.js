#!/usr/bin/env node
'use strict';
/**
 * release.js — orchestrate the LOCAL release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints what
 * it did, and exits with a code that's safe to script against.
 *
 * Usage:
 *   node scripts/release.js prepare [--minor]  # bump VERSION + regen CHANGELOG + static gates
 *   node scripts/release.js regen              # re-regen CHANGELOG after release-notes edits
 *   node scripts/release.js test               # full suite (node tests/run-all.js)
 *   node scripts/release.js commit             # signed release commit on main
 *   node scripts/release.js tag                # signed tag + push main + push tag (fires release.yml)
 *   node scripts/release.js watch              # watch release.yml + docker-publish.yml runs
 *   node scripts/release.js all [--minor]      # prepare -> test -> commit -> tag (stops before watch)
 *   node scripts/release.js status             # branch + dual-version + release-notes + last CI run
 *   node scripts/release.js help               # this banner
 *
 * The heavy build/sign/publish is owned by .github/workflows/release.yml on a
 * signed-tag push (SEA binaries x4 platforms, SBOM/VEX, SLSA L3, cosign,
 * ML-DSA-65, GPG, P-384 ECDSA). This script drives only the human-side local
 * prep, then `tag` pushes the tag and prints the URLs to watch. `watch` is a
 * separate observability step so the operator isn't blocked for ~11 minutes.
 *
 * Pre-conditions:
 *   - release-notes/v<next>.json MUST exist before `prepare` (refuses with a
 *     printed stub otherwise — headline/summary/sections need human judgment).
 *   - VERSION must match in BOTH lib/constants.js and package.json — this
 *     script reads/writes both; release.yml's matrix gate enforces it at CI.
 *   - Git signing configured (SSH + allowed_signers + commit/tag.gpgsign).
 *
 * scripts/release.sh remains the offline single-platform local-build fallback.
 * release.js never builds the SEA.
 */

var fs = require('node:fs');
var path = require('node:path');
var childProcess = require('node:child_process');
var b = require('../vendor/blamejs');

var ROOT = path.resolve(__dirname, '..');
var CONSTANTS_PATH = path.join(ROOT, 'lib', 'constants.js');
var PACKAGE_PATH = path.join(ROOT, 'package.json');

// ---- Helpers -------------------------------------------------------------

// Every tool this script spawns (node, git, gh) is a native .exe on every
// platform — no npm/npx .cmd shims — so shell stays OFF. That sidesteps Node's
// DEP0190 (args-array + shell:true) deprecation and the arg-quoting hazard, and
// a repo path containing a space ("Dropbox (Personal)") is passed via the cwd
// option, never on a command line.
function _run(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  var rv = childProcess.spawnSync(cmd, args, {
    cwd:   opts.cwd || ROOT,
    stdio: opts.stdio || 'inherit',
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: false,
  });
  if (rv.error) {
    throw new Error('release: failed to spawn ' + cmd + ': ' + rv.error.message);
  }
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error('release: ' + cmd + ' ' + args.join(' ') + ' failed with status ' + rv.status);
  }
  return rv;
}

function _capture(cmd, args, opts) {
  opts = opts || {};
  var rv = childProcess.spawnSync(cmd, args || [], {
    cwd:   opts.cwd || ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: false,
  });
  return {
    status: rv.status,
    stdout: (rv.stdout || '').toString().trim(),
    stderr: (rv.stderr || '').toString().trim(),
  };
}

function _gitClean() {
  return _capture('git', ['status', '--porcelain']).stdout === '';
}

function _gitBranch() {
  return _capture('git', ['rev-parse', '--abbrev-ref', 'HEAD']).stdout;
}

function _gitOnMain() {
  return _gitBranch() === 'main';
}

function _requireMain(phase) {
  if (!_gitOnMain()) {
    throw new Error('release: ' + phase + ' must run on main (currently on ' + _gitBranch() +
      '). Fast-forward your working branch into main first, then re-run.');
  }
}

function _bumpPatch(version) {
  var parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + '.' + parts[1] + '.' + (parts[2] + 1);
}

function _bumpMinor(version) {
  var parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + '.' + (parts[1] + 1) + '.0';
}

// Read the version from BOTH sources of truth and assert they match. The
// matrix tag-gate in release.yml only catches a mismatch AFTER the tag is
// pushed; surfacing it locally turns a pushed-but-unbuildable tag into an
// early, fixable error. Reads from disk (not require) to stay cache-free.
function _readVersion() {
  var pkg = JSON.parse(fs.readFileSync(PACKAGE_PATH, 'utf8'));
  var constSrc = fs.readFileSync(CONSTANTS_PATH, 'utf8');
  var m = constSrc.match(/const VERSION = '([^']+)'/);
  if (!m) {
    throw new Error("release: could not find `const VERSION = '...'` in lib/constants.js");
  }
  if (pkg.version !== m[1]) {
    throw new Error('release: version mismatch — package.json=' + pkg.version +
      ' lib/constants.js=' + m[1] + ' (they MUST match; fix before releasing)');
  }
  return pkg.version;
}

// Rewrite the version in BOTH files and assert each write changed content. A
// silent regex miss on either file would ship a tag whose VERSION constant
// diverges from package.json — the single highest-risk release footgun.
//
// Both replacement buffers are computed (and validated to differ) BEFORE
// either file is touched, so a regex miss aborts with neither file changed.
// Each write goes through b.atomicFile.writeSync (temp + fsync + atomic
// rename), so a single file is never left half-written. The remaining
// failure mode — package.json renamed to the new version, then the
// constants.js write throws (ENOSPC, an AV lock on Windows, a kill) — is
// made self-healing: the first file is restored from its in-memory
// original before the error propagates, so the two never diverge.
function _writeVersion(next) {
  var pkgSrc = fs.readFileSync(PACKAGE_PATH, 'utf8');
  var pkgNext = pkgSrc.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (pkgNext === pkgSrc) {
    throw new Error('release: failed to rewrite package.json version line');
  }
  var constSrc = fs.readFileSync(CONSTANTS_PATH, 'utf8');
  var constNext = constSrc.replace(/const VERSION = '[^']+'/, "const VERSION = '" + next + "'");
  if (constNext === constSrc) {
    throw new Error('release: failed to rewrite lib/constants.js VERSION line');
  }
  // 0o644: package.json and lib/constants.js are world-readable tracked
  // source; the atomic primitive defaults to 0o600, which would silently
  // tighten their mode on every release.
  b.atomicFile.writeSync(PACKAGE_PATH, pkgNext, { fileMode: 0o644 });
  try {
    b.atomicFile.writeSync(CONSTANTS_PATH, constNext, { fileMode: 0o644 });
  } catch (e) {
    // Second write failed AFTER the first landed — roll package.json back to
    // its pre-bump content so the two version sources never diverge. The
    // restore is itself atomic; if it also fails, surface both faults.
    try {
      b.atomicFile.writeSync(PACKAGE_PATH, pkgSrc, { fileMode: 0o644 });
    } catch (restoreErr) {
      throw new Error('release: lib/constants.js write failed (' + (e && e.message || e) +
        ') AND the package.json rollback ALSO failed (' + (restoreErr && restoreErr.message || restoreErr) +
        ') — package.json now advertises ' + next + ' while lib/constants.js does not; ' +
        'restore package.json by hand before re-running.');
    }
    throw new Error('release: lib/constants.js version write failed (' + (e && e.message || e) +
      '); rolled package.json back to ' + JSON.parse(pkgSrc).version + ' so the two stay in lockstep — re-run prepare.');
  }
}

function _releaseNotesPath(version) {
  return path.join(ROOT, 'release-notes', 'v' + version + '.json');
}

function _ensureReleaseNotes(version) {
  var p = _releaseNotesPath(version);
  if (!fs.existsSync(p)) {
    var stub = {
      version:  version,
      date:     '<YYYY-MM-DD>',
      headline: '<one-line operator-facing summary, capital-first, no trailing punctuation>',
      summary:  '<one-paragraph why-it-matters, ends in sentence punctuation>',
      sections: [
        {
          heading: 'Fixed',
          items: [
            { title: '<short title, no trailing punctuation>', body: '<one-paragraph body ending in . ! or ?>' },
          ],
        },
      ],
    };
    console.error('');
    console.error('release: missing ' + path.relative(ROOT, p));
    console.error('');
    console.error('Author that file before re-running (headline/summary/sections need judgment). Stub:');
    console.error('');
    console.error(JSON.stringify(stub, null, 2));
    console.error('');
    process.exit(2);
  }
  return p;
}

function _section(title) {
  console.log('\n=== ' + title + ' ===');
}

function _ok(msg) {
  console.log('ok: ' + msg);
}

// github.com/<owner>/<repo> derived from the origin remote, for the URLs the
// project memory rule requires surfacing after a tag push.
function _repoSlug() {
  var url = _capture('git', ['remote', 'get-url', 'origin']).stdout;
  var m = url.match(/github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/);
  return m ? m[1] : null;
}

// Shared artifact regeneration. Called by `prepare` after the bump and by
// `regen` standalone after release-notes edits. Idempotent. The api-snapshot
// pair from the upstream flow is intentionally dropped — this is a CLI daemon
// with no public-API surface to snapshot.
function _regenArtifacts(opts) {
  opts = opts || {};
  if (opts.rollupOnMinor) {
    _run('node', ['scripts/consolidate-release-notes.js', '--prune']);
    _ok("prior minor's release-notes rolled up");
  }
  _run('node', ['scripts/generate-changelog-entry.js', '--rebuild']);
  _run('node', ['scripts/check-changelog-extract.js']);
  _ok('CHANGELOG regenerated + drift-checked');
}

function _verifyCommitSignature(label) {
  var verify = _capture('git', ['verify-commit', 'HEAD']);
  if (verify.status !== 0) {
    var hint = 'release: ' + label + ' commit signature is not Good — check signing setup ' +
      '(commit.gpgsign=true + gpg.format=ssh + gpg.ssh.allowedSignersFile populated).';
    if (verify.stderr) hint += '\n' + verify.stderr;
    throw new Error(hint);
  }
  var sig = _capture('git', ['log', '-1', '--pretty=%h %G? %GS']);
  console.log('signature: ' + (sig.stdout || '(captured empty — verify-commit reports Good)'));
  _ok(label + ' commit signature verified');
}

// ---- Subcommands ---------------------------------------------------------

function cmdPrepare(opts) {
  _section('prepare');
  _requireMain('prepare');
  if (!_gitClean()) {
    throw new Error('release: prepare requires a clean working tree');
  }

  var current = _readVersion();
  var next = opts.minor ? _bumpMinor(current) : _bumpPatch(current);
  console.log('current version: ' + current);
  console.log('next version:    ' + next + ' (' + (opts.minor ? 'minor' : 'patch') + ')');

  _ensureReleaseNotes(next);

  _writeVersion(next);
  _ok('bumped lib/constants.js + package.json -> ' + next);

  _section('regen artifacts');
  var minorRotated = current.split('.')[1] !== next.split('.')[1];
  _regenArtifacts({ rollupOnMinor: minorRotated });

  _section('static gates');
  // node:test files run ZERO tests without --test — the gate MUST be invoked
  // with --test (this is the canonical CI invocation, ci.yml).
  _run('node', ['--test', 'scripts/test-codebase-patterns.js']);
  _ok('codebase-patterns clean');

  _section('vendor currency');
  // Advisory: a transient network/API error must not block the cut. A real
  // "vendored blamejs is stale" failure is surfaced as a warning to act on.
  var freshness = _run('node', ['scripts/check-blamejs-version.js'], { allowFail: true });
  if (freshness.status !== 0) {
    console.warn('warning: check-blamejs-version reported non-zero (stale vendor or network blip) — review before tagging');
  } else {
    _ok('vendored blamejs current');
  }

  console.log('\nESLint, ShellCheck, and Hadolint run in CI (ci.yml), not locally.');
  console.log('next: node scripts/release.js test');
}

function cmdRegen() {
  _section('regen');
  // Re-run the artifact pipeline after editing release-notes/v<next>.json,
  // without re-bumping. Safe from any branch.
  var next = _readVersion();
  _ensureReleaseNotes(next);
  _regenArtifacts();
  console.log('\nnext: re-run the phase you were on (test / commit / tag).');
}

function cmdTest() {
  _section('test');
  // Full suite — spins up the HermitStash server from ../hermitstash (or
  // HERMITSTASH_SERVER_DIR); run-all.js throws an actionable error if the
  // server source is absent, which propagates here.
  _run('node', ['tests/run-all.js']);
  _ok('full test suite passed');
  console.log('\nnext: node scripts/release.js commit');
}

function cmdCommit() {
  _section('commit');
  _requireMain('commit');
  var next = _readVersion();

  // Resume: if HEAD already carries this release commit (re-run after a
  // signature/hook failure resolved out-of-band), verify and move on.
  var headSubject = _capture('git', ['log', '-1', '--pretty=%s']).stdout;
  if (headSubject.indexOf('release: v' + next + ' ') === 0) {
    _ok('HEAD already carries the v' + next + ' release commit (resume mode)');
    _verifyCommitSignature('existing');
    console.log('\nnext: node scripts/release.js tag');
    return;
  }

  if (_gitClean()) {
    throw new Error('release: nothing staged to commit — did `prepare` run? (working tree is clean)');
  }

  // Compose the commit body from the release-notes JSON, mirroring the
  // CHANGELOG entry shape. Operators can amend post-commit.
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), 'utf8'));
  var lines = ['release: v' + next + ' — ' + rn.headline, '', rn.summary];
  if (Array.isArray(rn.sections)) {
    rn.sections.forEach(function (s) {
      if (!Array.isArray(s.items) || s.items.length === 0) return;
      lines.push('', s.heading + ':');
      s.items.forEach(function (it) { lines.push('  - ' + it.title); });
    });
  }
  var msgPath = path.join(ROOT, '.scratch', 'release-commit-msg.txt');
  try { fs.mkdirSync(path.dirname(msgPath), { recursive: true }); } catch (_e) { /* ignore */ }
  fs.writeFileSync(msgPath, lines.join('\n') + '\n');

  // Stage ONLY the files a release produces — never `git add -A`. `commit` is
  // an independently-dispatchable subcommand, so an operator can reach it with
  // unrelated edits in the tree; a broad add would fold those into the signed,
  // pushed release commit silently (the signature is over whatever happened to
  // be staged). The version bump touches package.json + lib/constants.js; the
  // regen rewrites CHANGELOG.md; and the whole release-notes/ tree is release
  // output (the per-patch v<next>.json plus, on a minor rotation, the deleted
  // per-patch files and the new/extended consolidated rollup). Stage that exact
  // set with -A pathspecs so deletions from the rollup are captured too.
  _run('git', ['add', '--',
    'package.json',
    'lib/constants.js',
    'CHANGELOG.md',
    'release-notes',
  ]);

  // Refuse to proceed if anything OUTSIDE that set is still dirty. A surviving
  // unstaged/untracked change means the tree carried edits the release doesn't
  // own — surface it as an error rather than committing a partial or sweeping
  // it in on a later broad add. Ignored paths (e.g. .scratch/) never appear in
  // --porcelain, so the commit-message file is not flagged.
  var stray = _capture('git', ['status', '--porcelain', '--untracked-files=all']).stdout
    .split('\n')
    .filter(function (l) { return l.length > 0; })
    .filter(function (l) {
      // --porcelain line: XY<space>path. A staged-and-clean release file shows
      // as e.g. "M  package.json" (no worktree-side flag); anything with a
      // worktree change (second column non-space) or an unstaged/untracked file
      // is outside the release set.
      var worktreeFlag = l.charAt(1);
      return worktreeFlag !== ' ';
    });
  if (stray.length > 0) {
    throw new Error('release: working tree has changes outside the release set after staging ' +
      'package.json / lib/constants.js / CHANGELOG.md / release-notes/:\n' +
      stray.join('\n') +
      '\nStash or revert those before committing — the release commit must contain only release output.');
  }

  _run('git', ['commit', '-F', msgPath]);
  _ok('signed release commit');

  _verifyCommitSignature('new');
  console.log('\nnext: node scripts/release.js tag');
}

function cmdTag() {
  _section('tag');
  _requireMain('tag');
  if (!_gitClean()) {
    throw new Error('release: tag requires a clean working tree (commit first)');
  }
  var next = _readVersion();
  var tag = 'v' + next;

  if (_capture('git', ['tag', '-l', tag]).stdout === tag) {
    throw new Error('release: tag ' + tag + ' already exists locally');
  }

  // Push the commit to main first so the tag's commit is on the branch, then
  // the signed tag — the tag push is what triggers release.yml.
  _run('git', ['push', 'origin', 'main']);
  _run('git', ['tag', '-s', tag, '-m', tag]);
  _run('git', ['push', 'origin', tag]);
  _ok('pushed main + tagged ' + tag);

  var verify = _capture('git', ['tag', '-v', tag]);
  if (verify.stderr.indexOf('Good') === -1 && verify.stdout.indexOf('Good') === -1) {
    console.error('warning: `git tag -v ' + tag + '` did not report a Good signature:');
    console.error(verify.stderr || verify.stdout);
  } else {
    _ok('tag signature: Good');
  }

  var slug = _repoSlug();
  console.log('');
  if (slug) {
    console.log('release.yml run:  https://github.com/' + slug + '/actions/workflows/release.yml');
    console.log('release page:     https://github.com/' + slug + '/releases/tag/' + tag);
  }
  console.log('\nnext: node scripts/release.js watch   (release.yml ~5-8 min, then docker-publish.yml ~3 min)');
}

function _pollForRun(workflow, branch) {
  // gh run list can lag the push; poll until the run for this tag appears.
  for (var attempt = 0; attempt < 30; attempt++) {
    var rv = _capture('gh', ['run', 'list', '--workflow=' + workflow, '--branch', branch,
      '--limit', '1', '--json', 'databaseId', '--jq', '.[0].databaseId']);
    if (rv.stdout) return rv.stdout;
    _run('node', ['-e', 'setTimeout(function(){}, 10000)'], { stdio: 'ignore' });
  }
  return null;
}

function cmdWatch() {
  _section('watch');
  var tag = 'v' + _readVersion();

  _section('release.yml');
  var releaseRun = _pollForRun('release.yml', tag);
  if (!releaseRun) {
    throw new Error('release: release.yml run for ' + tag + ' did not appear — check `gh run list`');
  }
  console.log('release.yml run: ' + releaseRun);
  _run('gh', ['run', 'watch', releaseRun, '--exit-status'], { allowFail: true });

  // docker-publish.yml is workflow_run-triggered: it only appears AFTER
  // release.yml succeeds, so watch it second, not concurrently.
  _section('docker-publish.yml');
  var dockerRun = _pollForRun('docker-publish.yml', 'main');
  if (dockerRun) {
    console.log('docker-publish.yml run: ' + dockerRun);
    _run('gh', ['run', 'watch', dockerRun, '--exit-status'], { allowFail: true });
  } else {
    console.log('docker-publish.yml run not found yet (it chains off release.yml success).');
  }

  var slug = _repoSlug();
  if (slug) {
    console.log('\nrelease page: https://github.com/' + slug + '/releases/tag/' + tag);
  }
}

function cmdAll(opts) {
  // Stops after `tag` — the ship event is the tag push, and `tag` already
  // printed the URLs. `watch` is a separate ~11-minute observability step.
  cmdPrepare(opts);
  cmdTest();
  cmdCommit();
  cmdTag();
  _section('all');
  _ok('prepared, tested, committed, and tagged — release.yml is now building');
  console.log('next: node scripts/release.js watch   (optional — watch CI to completion)');
}

function cmdStatus() {
  _section('status');
  console.log('branch:          ' + _gitBranch());
  console.log('clean:           ' + _gitClean());
  var versionLine;
  try {
    versionLine = _readVersion() + ' (constants.js + package.json match)';
  } catch (e) {
    versionLine = 'MISMATCH — ' + e.message;
  }
  console.log('version:         ' + versionLine);
  var pkg = JSON.parse(fs.readFileSync(PACKAGE_PATH, 'utf8'));
  console.log('release-notes:   ' + (fs.existsSync(_releaseNotesPath(pkg.version)) ? 'present for v' + pkg.version : 'missing for v' + pkg.version));
  var run = _capture('gh', ['run', 'list', '--workflow=release.yml', '--limit', '1',
    '--json', 'headBranch,status,conclusion', '--jq', '.[0]']);
  console.log('last release.yml: ' + (run.stdout || '(unable to query gh)'));
}

function cmdHelp() {
  console.log('release.js — orchestrated local release flow for hermitstash-sync');
  console.log('');
  console.log('Usage:');
  console.log('  node scripts/release.js prepare [--minor]  # bump VERSION (both files) + regen CHANGELOG + gates');
  console.log('  node scripts/release.js regen              # re-regen CHANGELOG after release-notes edits');
  console.log('  node scripts/release.js test               # full suite (node tests/run-all.js)');
  console.log('  node scripts/release.js commit             # signed release commit on main');
  console.log('  node scripts/release.js tag                # signed tag + push (fires release.yml)');
  console.log('  node scripts/release.js watch              # watch release.yml + docker-publish.yml');
  console.log('  node scripts/release.js all [--minor]      # prepare -> test -> commit -> tag');
  console.log('  node scripts/release.js status             # branch + dual-version + last CI run');
  console.log('  node scripts/release.js help               # this banner');
  console.log('');
  console.log('Pre-req: author release-notes/v<next>.json before `prepare`. Run on main.');
  console.log('scripts/release.sh is the offline single-platform local-build fallback.');
}

// ---- Dispatch ------------------------------------------------------------

var sub = process.argv[2] || 'help';
var args = process.argv.slice(3);
var opts = { minor: args.indexOf('--minor') !== -1 };

try {
  switch (sub) {
    case 'prepare': cmdPrepare(opts); break;
    case 'regen':   cmdRegen();       break;
    case 'test':    cmdTest();        break;
    case 'commit':  cmdCommit();      break;
    case 'tag':     cmdTag();         break;
    case 'watch':   cmdWatch();       break;
    case 'all':     cmdAll(opts);     break;
    case 'status':  cmdStatus();      break;
    case 'help':
    case '--help':
    case '-h':      cmdHelp();        break;
    default:
      console.error("release: unknown subcommand '" + sub + "'");
      cmdHelp();
      process.exit(1);
  }
} catch (e) {
  console.error('\nrelease: FAIL — ' + (e.message || e));
  process.exit(1);
}
