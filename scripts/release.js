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
var LOCK_PATH = path.join(ROOT, 'package-lock.json');

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

// Synchronous bounded sleep without spawning a subprocess. Atomics.wait on a
// throwaway shared buffer blocks the calling thread for `ms`; falls back to a
// spin if SharedArrayBuffer is somehow unavailable (it is present on the Node
// runtime floor, so the fallback is belt-and-suspenders). Mirrors blamejs's
// internal idiom (vendor/blamejs/lib/atomic-file.js#_sleepSync) without
// reaching into a non-exported symbol.
function _sleepSync(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); return; }
  catch (_e) { /* fall through to spin */ }
  var end = Date.now() + ms;
  while (Date.now() < end) { /* spin */ }
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

// _capture returns the exit status alongside the output, and reading only the
// output throws that away: git writes its failures to stderr, so a status that
// did not run leaves stdout empty and `=== ''` reports a clean tree. `prepare`
// and `tag` both gate on this, and both read "clean" as permission to proceed —
// so a lookup that failed would let `tag` sign an immutable tag over a tree it
// could not read. Refuse instead; a release gate has to have an answer, not a
// default.
function _gitClean() {
  var rv = _capture('git', ['status', '--porcelain']);
  if (rv.status !== 0) {
    throw new Error('release: could not read the working tree (git status exited '
      + rv.status + ') — refusing rather than assuming it is clean'
      + (rv.stderr ? ': ' + rv.stderr : ''));
  }
  return rv.stdout === '';
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
  var pkg = b.safeJson.parse(fs.readFileSync(PACKAGE_PATH, 'utf8'), { maxBytes: b.constants.BYTES.mib(1) });
  var constSrc = fs.readFileSync(CONSTANTS_PATH, 'utf8');
  var m = constSrc.match(/const VERSION = '([^']+)'/);
  if (!m) {
    throw new Error("release: could not find `const VERSION = '...'` in lib/constants.js");
  }
  if (pkg.version !== m[1]) {
    throw new Error('release: version mismatch — package.json=' + pkg.version +
      ' lib/constants.js=' + m[1] + ' (they MUST match; fix before releasing)');
  }

  // The lockfile is checked here too, not only where prepare writes it. `commit`
  // is independently dispatchable and stages package-lock.json as release
  // output, so without this a stale or hand-edited lockfile rides into a signed,
  // pushed release advertising a different version. Both fields npm keeps equal
  // to package.json are compared; nothing else gates them, which is how this one
  // sat a release behind while the other two moved together.
  // Absence is a failure, not a skip. `commit` stages package-lock.json as
  // release output with an -A pathspec, so a deleted lockfile would be committed
  // AS a deletion and ship a release whose `npm ci` no longer resolves. Skipping
  // the check when the file is gone makes deleting it the way around the check.
  if (!fs.existsSync(LOCK_PATH)) {
    throw new Error('release: package-lock.json is missing. It pins the dev toolchain ' +
      '(eslint, c8 and their transitives) and is part of the release set, so a cut ' +
      'without it ships a tree `npm ci` cannot install. Restore it before releasing.');
  }
  var lock = b.safeJson.parse(fs.readFileSync(LOCK_PATH, 'utf8'), { maxBytes: b.constants.BYTES.mib(8) });
  var lockRoot = lock && lock.version;
  var lockSelf = lock && lock.packages && lock.packages[''] && lock.packages[''].version;
  if (lockRoot !== pkg.version || lockSelf !== pkg.version) {
    throw new Error('release: version mismatch — package.json=' + pkg.version +
      ' package-lock.json root=' + lockRoot + ' packages[""]=' + lockSelf +
      ' (all MUST match; `npm install --package-lock-only` or fix by hand before releasing)');
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
// package-lock.json states the version twice: on the root object and again on
// `packages[""]`, which npm keeps equal to package.json. Both sit ahead of the
// first `"node_modules/` key, so the rewrite is bounded to that header region
// and cannot reach a dependency that happens to share the version string.
//
// Exactly two occurrences are required. Finding another count means the file
// is not the shape this assumes, and guessing which to rewrite is how a
// lockfile ends up describing a package that does not exist.
function _lockVersionRewrite(src, current, next) {
  var boundary = src.indexOf('"node_modules/');
  var head = boundary === -1 ? src : src.slice(0, boundary);
  var tail = boundary === -1 ? '' : src.slice(boundary);

  var needle = '"version": "' + current + '"';
  var parts = head.split(needle);
  if (parts.length - 1 !== 2) {
    throw new Error('release: package-lock.json carries ' + (parts.length - 1) +
      ' occurrence(s) of ' + needle + ' before the first dependency, expected 2 ' +
      '(the root object and packages[""]). Refusing to guess which to rewrite — ' +
      'check the lockfile by hand.');
  }
  return parts.join('"version": "' + next + '"') + tail;
}

function _writeVersion(next) {
  var current = _readVersion();

  // Every file carrying the version, written as one unit. package.json and
  // lib/constants.js are what release.yml's tag gate compares; package-lock.json
  // is gated nowhere, which is exactly how it sat a release behind while the
  // other two moved, and an SBOM or an auditor reads it as this package's
  // version all the same.
  var targets = [
    {
      path: PACKAGE_PATH, label: 'package.json',
      rewrite: function (src) {
        return src.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
      },
    },
    {
      path: CONSTANTS_PATH, label: 'lib/constants.js',
      rewrite: function (src) {
        return src.replace(/const VERSION = '[^']+'/, "const VERSION = '" + next + "'");
      },
    },
    {
      path: LOCK_PATH, label: 'package-lock.json',
      rewrite: function (src) { return _lockVersionRewrite(src, current, next); },
    },
  ];

  // Read and rewrite everything BEFORE writing anything, so a file that cannot
  // be rewritten fails with nothing on disk changed.
  targets.forEach(function (t) {
    t.src = fs.readFileSync(t.path, 'utf8');
    t.next = t.rewrite(t.src);
    if (t.next === t.src) {
      throw new Error('release: failed to rewrite the version in ' + t.label);
    }
  });

  // 0o644: these are world-readable tracked source, and the atomic primitive
  // defaults to 0o600, which would silently tighten their mode every release.
  var written = [];
  try {
    targets.forEach(function (t) {
      b.atomicFile.writeSync(t.path, t.next, { fileMode: 0o644 });
      written.push(t);
    });
  } catch (e) {
    // A write landed and a later one threw (ENOSPC, an AV lock on Windows, a
    // kill). Restore what already changed from its in-memory original so the
    // version sources never diverge; each restore is itself atomic.
    var failedRestores = [];
    written.forEach(function (t) {
      try { b.atomicFile.writeSync(t.path, t.src, { fileMode: 0o644 }); }
      catch (restoreErr) { failedRestores.push(t.label + ' (' + (restoreErr && restoreErr.message || restoreErr) + ')'); }
    });
    if (failedRestores.length) {
      throw new Error('release: a version write failed (' + (e && e.message || e) +
        ') AND rolling back ALSO failed for: ' + failedRestores.join(', ') +
        ' — those files now advertise ' + next + ' while the rest do not; ' +
        'restore them by hand before re-running.');
    }
    throw new Error('release: a version write failed (' + (e && e.message || e) +
      '); rolled the others back to ' + current + ' so they stay in lockstep — re-run prepare.');
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
  // Vendored transitive surface (packages.blamejs.transitive) must match
  // blamejs's own authoritative manifest. The projection is populated
  // mechanically at the vendor step (scripts/vendor-hash.js); here we only
  // gate drift, so a blamejs refresh that skipped vendor-hash or a hand-edit
  // fails prepare loud instead of shipping a stale SBOM — mirroring the
  // changelog drift gate above.
  _run('node', ['scripts/project-transitive-manifest.js', '--check']);
  _ok('vendored transitive SBOM projection drift-checked');
  // Hand-typed version references in the operator-facing docs (the vendored
  // blamejs version, its minor line, the Node floor) must match their source of
  // truth — vendor-hash.js syncs them on a refresh; here we gate drift so a
  // vendor bump that skipped vendor-hash, or a hand-edit, fails prepare loud
  // instead of shipping a stale version in the README.
  _run('node', ['scripts/check-doc-versions.js', '--check']);
  _ok('operator-facing doc versions drift-checked');
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
  _ok('bumped lib/constants.js + package.json + package-lock.json -> ' + next);

  _section('regen artifacts');
  var minorRotated = current.split('.')[1] !== next.split('.')[1];
  _regenArtifacts({ rollupOnMinor: minorRotated });

  _section('static gates');
  // node:test files run ZERO tests without --test — the gate MUST be invoked
  // with --test (this is the canonical CI invocation, ci.yml).
  _run('node', ['--test', 'scripts/test-codebase-patterns.js']);
  _ok('codebase-patterns clean');

  _section('vendor currency');
  // HARD GATE on a genuinely stale vendor, and this is the right place for it:
  // `prepare` runs before the release commit exists and long before any tag, so
  // failing here costs nothing but a re-run. (ci.yml deliberately keeps its copy
  // advisory — there it would only fire on the push that already carries an
  // immutable tag, punishing a cut it cannot prevent.)
  //
  // Severity is GRADED off the script's own exit codes:
  // 1 = actually behind upstream (a release blocker),
  // 2 = could not reach the API at all (a network blip must not block a cut).
  var freshness = _run('node', ['scripts/check-blamejs-version.js'], { allowFail: true });
  if (freshness.status === 0) {
    _ok('vendored blamejs current');
  } else if (freshness.status === 2) {
    console.warn('warning: could not reach the GitHub API to check vendored blamejs currency — ' +
      'unverified, not known-stale. Re-run `prepare` when connectivity returns if you want the proof.');
  } else if (opts && opts.vendorStaleReason) {
    // Audited override for the real race: blamejs ships often, so upstream can
    // publish mid-cut and strand an otherwise-finished release. Overriding is
    // allowed but never silent — the reason is echoed here and belongs in the
    // release discussion.
    console.warn('warning: vendored blamejs is STALE and the gate was overridden.');
    console.warn('         reason: ' + opts.vendorStaleReason);
  } else {
    throw new Error(
      'vendored blamejs is behind the latest upstream release (see the report above). Refresh it before ' +
      'cutting — a release should not ship a vendored framework that is knowingly behind. If upstream ' +
      'published mid-cut and you are deliberately shipping the older pin, re-run with ' +
      '--vendor-stale-reason="why" to record that decision.');
  }

  _section('base image currency');
  // Digest drift only WARNS. Both bases here are rebuilt continuously upstream,
  // so failing on drift would block nearly every cut, and the pressure that
  // creates is to bump the pin blindly to quiet the gate — worse than the
  // staleness it was meant to surface. Drift is also just a proxy; the harm is
  // shipping a fixable CRITICAL/HIGH, and Trivy already hard-gates that.
  //
  // A non-zero exit means something else: the pinned digest no longer resolves,
  // a base carries no digest at all, or a Dockerfile could not be parsed. Those
  // are a broken build or a broken check, and both block.
  var baseCurrency = _run('node', ['scripts/check-base-currency.js'], { allowFail: true });
  if (baseCurrency.status === 0) {
    _ok('base image pins checked');
  } else {
    throw new Error(
      'base-image currency check failed (see the report above). Either a pinned digest no longer ' +
      'resolves, a base image is not digest-pinned, or a Dockerfile could not be parsed — each is a ' +
      'release blocker. Digest drift alone does NOT reach here; it warns above.');
  }

  _section('actions currency');
  // A stale action pin FAILS, unlike base-image drift above. An action release
  // is a deliberate upstream act rather than a continuous rebuild, so "behind"
  // is a real statement here, and there is no Trivy step downstream to catch
  // the consequence the way there is for a base image.
  //
  // Graded the same way as the vendored-framework gate:
  // 1 = a pin is behind its action's latest release (a blocker),
  // 2 = the GitHub API could not be reached (unverified, not known-stale).
  var actionsCurrency = _run('node', ['scripts/check-actions-currency.js'], { allowFail: true });
  if (actionsCurrency.status === 0) {
    _ok('action pins current');
  } else if (actionsCurrency.status === 2) {
    console.warn('warning: could not reach the GitHub API to check action-pin currency — ' +
      'unverified, not known-stale. Re-run `prepare` when connectivity returns if you want the proof.');
  } else {
    throw new Error(
      'a GitHub Actions pin is behind its latest release (see the report above). These workflows build ' +
      'the SEA binary auto-update fetches and the image operators pull, so a stale pin here is the one ' +
      'that reaches a user. Paste the pin the report prints, then re-run.');
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

  // Re-run the leak-vocabulary + CHANGELOG-drift gate before composing the
  // signed commit body. `commit` is an independently-dispatchable subcommand,
  // so the release-notes JSON may have been hand-edited AFTER `prepare`
  // validated it (or `prepare` may have been skipped). The commit message is
  // operator-facing and is built from that JSON below, so validate it here with
  // the same gate `prepare` runs — this renders + validates the current
  // version's release-notes (leak-vocabulary sweep over the whole tree) and
  // confirms CHANGELOG.md is in sync — rather than trusting a prior, possibly
  // stale validation. The normal prepare -> test -> commit flow is unaffected
  // since prepare already left the tree validated (this is a read-only re-check).
  _run('node', ['scripts/check-changelog-extract.js']);
  _ok('release-notes + CHANGELOG re-validated before composing the commit message');

  // Compose the commit body from the release-notes JSON, mirroring the
  // CHANGELOG entry shape. Operators can amend post-commit.
  var rn = b.safeJson.parse(fs.readFileSync(_releaseNotesPath(next), 'utf8'), { maxBytes: b.constants.BYTES.mib(1) });
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
  // be staged). The version bump touches package.json, lib/constants.js and
  // package-lock.json; the regen rewrites CHANGELOG.md; and the whole
  // release-notes/ tree is release output (the per-patch v<next>.json plus, on
  // a minor rotation, the deleted per-patch files and the new/extended
  // consolidated rollup). Stage that exact set with -A pathspecs so deletions
  // from the rollup are captured too.
  _run('git', ['add', '--',
    'package.json',
    'package-lock.json',
    'lib/constants.js',
    'CHANGELOG.md',
    'release-notes',
  ]);

  // Refuse to proceed if the git INDEX carries anything outside the release
  // set. The worktree scan below only inspects the worktree column of
  // `git status`, so a file the operator staged BEFORE running `commit` (an
  // index change with a clean worktree — e.g. `git add lib/foo.js` then
  // `commit`) shows as "M " (index flag set, worktree flag a space) and slips
  // past that scan, getting folded into the signed, pushed release commit.
  // Enumerate the staged paths directly and refuse any outside the allowlist.
  // `git diff --cached --name-only` prints repo-root-relative, forward-slashed
  // paths; a path with unusual bytes may be quoted, which only ever fails the
  // allowlist (the safe direction) — the release files are plain ASCII.
  var stagedRv = _capture('git', ['diff', '--cached', '--name-only']);
  if (stagedRv.status !== 0) {
    throw new Error('release: could not list the staged files (git diff --cached exited '
      + stagedRv.status + ') — refusing rather than assuming nothing extra is staged'
      + (stagedRv.stderr ? ': ' + stagedRv.stderr : ''));
  }
  var stagedStray = stagedRv.stdout
    .split('\n')
    .map(function (p) { return p.trim(); })
    .filter(function (p) { return p.length > 0; })
    .filter(function (p) {
      return p !== 'package.json' &&
        p !== 'package-lock.json' &&
        p !== 'lib/constants.js' &&
        p !== 'CHANGELOG.md' &&
        p !== 'release-notes' &&
        p.indexOf('release-notes/') !== 0;
    });
  if (stagedStray.length > 0) {
    throw new Error('release: the git index has staged changes outside the release set ' +
      '(package.json / package-lock.json / lib/constants.js / CHANGELOG.md / release-notes/):\n' +
      stagedStray.join('\n') +
      '\nUnstage them with `git restore --staged <path>` before committing — the ' +
      'signed release commit must contain only release output.');
  }

  // Refuse to proceed if anything OUTSIDE that set is still dirty. A surviving
  // unstaged/untracked change means the tree carried edits the release doesn't
  // own — surface it as an error rather than committing a partial or sweeping
  // it in on a later broad add. Ignored paths (e.g. .scratch/) never appear in
  // --porcelain, so the commit-message file is not flagged.
  var strayRv = _capture('git', ['status', '--porcelain', '--untracked-files=all']);
  if (strayRv.status !== 0) {
    throw new Error('release: could not list the working tree (git status exited '
      + strayRv.status + ') — refusing rather than assuming nothing is stray'
      + (strayRv.stderr ? ': ' + strayRv.stderr : ''));
  }
  var stray = strayRv.stdout
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
      'package.json / package-lock.json / lib/constants.js / CHANGELOG.md / release-notes/:\n' +
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

  var existing = _capture('git', ['tag', '-l', tag]);
  if (existing.status !== 0) {
    throw new Error('release: could not check whether ' + tag + ' already exists (git tag -l exited '
      + existing.status + ') — refusing rather than assuming it does not'
      + (existing.stderr ? ': ' + existing.stderr : ''));
  }
  if (existing.stdout === tag) {
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
    _sleepSync(10000);
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
  // status is a read-only report, so an unreadable tree is shown as unreadable
  // rather than ending the command the way it ends a gate.
  var cleanLine;
  try { cleanLine = String(_gitClean()); }
  catch (e) { cleanLine = 'unreadable — ' + e.message; }
  console.log('clean:           ' + cleanLine);
  var versionLine;
  try {
    versionLine = _readVersion() + ' (constants.js + package.json + package-lock.json match)';
  } catch (e) {
    versionLine = 'MISMATCH — ' + e.message;
  }
  console.log('version:         ' + versionLine);
  var pkg = b.safeJson.parse(fs.readFileSync(PACKAGE_PATH, 'utf8'), { maxBytes: b.constants.BYTES.mib(1) });
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
  console.log('        --vendor-stale-reason="why"          # ship despite a stale vendored blamejs (recorded, not silent)');
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
// --vendor-stale-reason="…" — audited override for the vendor-currency gate in
// `prepare`. Requires a non-empty reason: an override that records nothing is
// indistinguishable from not having the gate.
var _reasonArg = args.filter(function (a) { return a.indexOf('--vendor-stale-reason') === 0; })[0];
if (_reasonArg) {
  var _eq = _reasonArg.indexOf('=');
  opts.vendorStaleReason = _eq === -1 ? '' : _reasonArg.slice(_eq + 1).trim();
  if (!opts.vendorStaleReason) {
    console.error('release: --vendor-stale-reason needs a value, e.g. ' +
      '--vendor-stale-reason="upstream published 0.18.15 mid-cut; shipping .14, refresh next patch"');
    process.exit(1);
  }
}

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
