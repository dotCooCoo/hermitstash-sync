'use strict';

// Auto-update for the sync daemon — built on b.selfUpdate primitives.
//
// Lifecycle:
//   1. b.selfUpdate.poll → fetches the GitHub /releases/latest feed,
//      semver-compares the latest tag to the running version, and
//      surfaces { available, asset, signature } when a newer build
//      exists. The poll itself handles SSRF posture (allowedHosts) and
//      response-size caps.
//   2. Download asset + signature to temp files via b.httpClient.request
//      (PQC TLS posture inherited from b.pqcAgent). Allowlist the same
//      GitHub-release host set on every fetch — a hostile redirect
//      cannot pivot us at a private IP.
//   3. b.selfUpdate.standaloneVerifier → ECDSA P-384 signature over the
//      asset bytes (DER, SHA3-512) verified against the pubkey embedded
//      in lib/autoupdate-pubkey.js. The standalone verifier is
//      SHA3-512-pinned, matching release.yml's signer; b.selfUpdate.verify
//      cannot be used here because its underlying crypto.verify(null, …)
//      call infers SHA-384 from the P-384 key and silently rejects our
//      SHA3-512-signed assets (latent v0.7.7+ bug — fixed at v0.7.9).
//   4. b.selfUpdate.swap → atomic copy-current-to-prev + rename
//      new-to-current with cross-device fallback. Probation marker
//      written by us, not the framework — it's the hermitstash-specific
//      contract that lets the next boot detect a crash-during-warmup.
//   5. Spawn detached child of the new binary, parent exits.
//
// Probation + rollback (next-boot path):
//   - checkRollback() reads ~/.hermitstash-sync/update-pending.json on
//     every startup. If marker is fresh (age < probationMs) we're
//     in-probation — arm a timer to clear the marker on success.
//   - If marker is stale (we're past probation but the marker is still
//     there → previous boot crashed) → b.selfUpdate.rollback restores
//     .prev → spawn restored binary → exit.
//
// Source installs (not SEA): poll + log a notice, never swap.

// codebase-patterns:allow-file process-exit — updater.exitFn defaults to process.exit so post-swap the parent terminates and the detached child takes over (tests inject a stub).

const nodeFs = require('node:fs');
const nodeFsPromises = require('node:fs/promises');
const nodePath = require('node:path');
const nodeOs = require('node:os');
const log = require('./logger');
const b = require('../vendor/blamejs');
// Standalone verifier (SHA3-512-pinned), consumed via the vendored surface.
// Bypasses b.selfUpdate.verify's SHA-384 inference that would silently reject
// our SHA3-512-signed assets — see verify-call-site below for context. The
// byte-identical module also ships as scripts/standalone-verifier.js for the
// vendor-free contexts (Dockerfile verify stage, install.sh, update.sh),
// mechanically re-copied by scripts/vendor-hash.js; the daemon consumes the
// vendored original so its signature-verification path can never drift from
// the framework between vendor refreshes.
const standaloneVerifier = b.selfUpdate.standaloneVerifier;
// Reused only for its negotiated-group observer. The updater's TLS path is
// OBSERVE-ONLY: api.github.com / the *.githubusercontent.com release CDN don't
// offer the ML-KEM hybrid groups, so a hard-fail would brick self-update. We log a
// WARN on a classical negotiation but never destroy the socket — separate
// agent from http-client's, so http-client's hard-fail can't bleed onto it.
const { assertNegotiatedGroupPqc } = require('./http-client');
const {
  VERSION,
  AUTOUPDATE_REPO,
  AUTOUPDATE_POLL_MS,
  AUTOUPDATE_PROBATION_MS,
  AUTOUPDATE_PUBKEY_PEM,
  CONFIG_DIR,
  TLS_GROUPS,
  // Aliased: createUpdater has a per-instance `isSeaBinary` (test-injectable)
  // whose default delegates to this shared detector.
  isSeaBinary: constantsIsSeaBinary,
} = require('./constants');

const C = b.constants;

const DEFAULT_INITIAL_CHECK_DELAY_MS = C.TIME.minutes(1);
const MAX_ASSET_BYTES = C.BYTES.mib(256);
// The detached P-384 ECDSA auto-update sidecar is a raw r||s pair (~96 bytes);
// the standalone verifier refuses any signature file over 64 KiB. Cap the
// signature download at that same ceiling rather than reusing the 256 MiB asset
// cap, so a hostile / TLS-MITM'd release CDN can't stream a giant body to the
// temp dir for a leg whose legitimate size is under a hundred bytes.
const MAX_SIGNATURE_BYTES = C.BYTES.kib(64);

function defaultIsSeaBinary() {
  return constantsIsSeaBinary();
}

function platformTag() {
  const p = process.platform;
  return p === 'win32' ? 'win' : p === 'darwin' ? 'macos' : 'linux';
}

function assetName(version) {
  const ext = process.platform === 'win32' ? '.exe' : '';
  return `hermitstash-sync-v${version}-${platformTag()}-${process.arch}${ext}`;
}

// Delegates to b.selfUpdate.compareTags (v0.9.47+ public-surface
// exposure of the internal _compareTags). Kept as a local re-export so
// existing tests that import `compareVersions` from `lib/updater` don't
// have to be rewritten. Same -1 / 0 / +1 semantics; same leading-`v`
// stripping; full SemVer prefix handling (`1.10.0` > `1.9.0`).
function compareVersions(a, c) {
  return b.selfUpdate.compareTags(a, c);
}

function createUpdater(opts = {}) {
  const currentVersion = opts.currentVersion || VERSION;
  const repo = opts.repo || AUTOUPDATE_REPO;
  const apiBase = opts.apiBase || 'https://api.github.com';
  const pubkeyPem = opts.pubkeyPem !== undefined ? opts.pubkeyPem : AUTOUPDATE_PUBKEY_PEM;
  const pollMs = opts.pollMs || AUTOUPDATE_POLL_MS;
  const probationMs = opts.probationMs || AUTOUPDATE_PROBATION_MS;
  const initialDelayMs = opts.initialDelayMs != null ? opts.initialDelayMs : DEFAULT_INITIAL_CHECK_DELAY_MS;
  const markerPath = opts.markerPath || nodePath.join(CONFIG_DIR, 'update-pending.json');
  const getExecPath = opts.getExecPath || (() => process.execPath);
  const getArgv = opts.getArgv || (() => process.argv.slice(2));
  const isSeaBinary = opts.isSeaBinary || defaultIsSeaBinary;
  const exitFn = opts.exitFn || ((code) => process.exit(code));
  const spawnFn = opts.spawnFn || b.processSpawn.spawn;
  // Injectable platform (defaults to the real one) so tests can exercise the
  // win32/POSIX swap+rollback branches WITHOUT mutating the global
  // process.platform — an Object.defineProperty stub restored in `finally`
  // clobbers concurrently-running tests' view of the platform.
  const platform = opts.platform || process.platform;
  const userAgent = `hermitstash-sync/${currentVersion}`;

  // Auto-update channel — "stable" (default) pins to /releases/latest
  // which by GitHub's contract excludes prereleases. "beta" lists
  // /releases and lets b.selfUpdate.poll pick the highest by tag
  // (semver-aware), so a v0.9.0-beta.1 prerelease beats a v0.8.5
  // stable. Operators set config.autoUpdateChannel; the cmdStart
  // path passes it through here.
  const channel = (opts.channel === 'beta') ? 'beta' : 'stable';
  const releasesUrl = channel === 'beta'
    ? `${apiBase}/repos/${repo}/releases?per_page=10`                          // allow:raw-byte-literal — page size (count, not bytes)
    : `${apiBase}/repos/${repo}/releases/latest`;

  // Tests inject httpsAgent + isTestEnv; production builds the PQC agent.
  let httpsAgent = opts.httpsAgent;
  const isTestEnv = !!opts.httpsAgent;
  if (!httpsAgent) {
    // ecdhCurve through create() for typed per-group validation;
    // allowOperatorGroups keeps the trailing classical X25519 accepted if a
    // future vendor bump narrows the default preference. create() now mirrors
    // ecdhCurve into options.groups verbatim (blamejs v0.17.13+), so the explicit
    // set below is a belt-and-suspenders assertion that BOTH keys are set (Node
    // versions differ on which one OpenSSL honours), pinned even if a future
    // vendor bump changes create()'s mirroring. minVersion TLSv1.3 is pinned by
    // create().
    httpsAgent = b.pqcAgent.create({
      keepAlive: true,
      maxSockets: 4,
      ecdhCurve: TLS_GROUPS,
      allowOperatorGroups: true,
    });
    httpsAgent.options.groups = TLS_GROUPS;
    // Observe-only post-quantum check on the self-update TLS path. The
    // GitHub release CDN legitimately speaks no ML-KEM hybrid, so a classical
    // negotiation here is expected, not an attack — log it (so the PQC posture
    // is visible) but never fail. enforce:false routes through the same logger
    // line the enforced sync transport uses without destroying the socket.
    // This is a DIFFERENT agent from http-client's, so the sync transport's
    // hard-fail cannot reach the updater.
    const _origCreateConnection = httpsAgent.createConnection.bind(httpsAgent);
    httpsAgent.createConnection = function (options, cb) {
      const socket = _origCreateConnection(options, cb);
      if (socket && typeof socket.once === 'function') {
        const host = (options && (options.servername || options.host)) || 'github release CDN';
        socket.once('secureConnect', function () {
          assertNegotiatedGroupPqc(socket, host, { enforce: false });
        });
      }
      return socket;
    };
  }
  const allowInternal = isTestEnv;

  // Production-only egress allowlist. Tests bypass via isTestEnv.
  // A release-asset download 302-redirects from github.com to GitHub's signed
  // content CDN, and the allowlist is re-checked at every redirect hop — so the
  // CDN host must be allowed or the download fails closed (HOST_DISALLOWED) and
  // self-update silently never installs. GitHub moved that CDN from
  // objects.githubusercontent.com to release-assets.githubusercontent.com, so a
  // single hardcoded host goes stale on a CDN rename. The leading-dot entry is
  // a SUFFIX match (host.endsWith('.githubusercontent.com')) covering both the
  // old and current hosts and any future subdomain, anchored at a label
  // boundary so it can't match a look-alike like evilgithubusercontent.com. The
  // P-384 ECDSA + SHA3-512 signature verified before any swap is the real
  // integrity gate; this allowlist is egress/SSRF defense-in-depth.
  const allowedHosts = isTestEnv ? undefined : ['api.github.com', 'github.com', '.githubusercontent.com'];

  function platformAssetPattern() {
    const ext = platform === 'win32' ? '\\.exe$' : '$';
    // `[-0-9A-Za-z.+]{0,64}` is the optional SemVer prerelease/build tail
    // (`-beta.1`, `-rc.2`, `+build.7`) as a BARE bounded char class rather than a
    // `(?:[-+]…+)?` group: b.selfUpdate now runs the assetPattern through
    // b.guardRegex.sanitize, which refuses a quantifier-inside-a-quantified-group
    // shape (the `(a+)+` ReDoS class) — even a `?`-wrapped one. The bounded char
    // class is guardRegex-safe (linear, no nested quantifier) and the {0,64} cap
    // hardens against a hostile feed asset name. `-` is first in the class so it is
    // a literal. Stable assets (empty tail) match byte-for-byte; the end-anchored
    // `-<platformTag>-<arch><ext>$` still fails wrong-arch and the `.mldsa.sig`
    // sidecar.
    // allow:dynamic-regex — pattern built from local platform / arch / extension only (no operator input); the runtime values come from process.platform and process.arch.
    return new RegExp(
      'hermitstash-sync-v\\d+\\.\\d+\\.\\d+[-0-9A-Za-z.+]{0,64}-' +
      platformTag() + '-' + process.arch + ext
    );
  }

  // The P-384 ECDSA auto-update sidecar for THIS platform's binary only.
  // Anchored to platform/arch/ext exactly like platformAssetPattern, then a
  // literal ".sig" end — so it matches <binary>.sig but NOT the ML-DSA
  // sidecar <binary>.mldsa.sig (which also ends in ".sig"), nor any other
  // platform's signature. A loose /\.sig$/ matches every platform's .sig AND
  // every .mldsa.sig; b.selfUpdate.poll then claims the first feed match,
  // so every platform would fetch the wrong-platform / wrong-algorithm
  // signature and verification would fail-closed — silently disabling
  // self-update on all platforms.
  function platformSignaturePattern() {
    const ext = platform === 'win32' ? '\\.exe\\.sig$' : '\\.sig$';
    // Same bare bounded prerelease/build char class as platformAssetPattern (see
    // there for why it is not a `(?:…)?` group — b.guardRegex.sanitize refuses a
    // quantified group) so a `...-v0.9.0-beta.1-<platform>-<arch><ext>.sig` sidecar
    // matches on the beta channel. The `\.exe\.sig$`/`\.sig$` anchor plus the
    // `<arch>` prefix still excludes the ML-DSA sidecar `.mldsa.sig` and every
    // other platform's sig.
    // allow:dynamic-regex — pattern built from local platform / arch / extension only (no operator input); the runtime values come from process.platform and process.arch.
    return new RegExp(
      'hermitstash-sync-v\\d+\\.\\d+\\.\\d+[-0-9A-Za-z.+]{0,64}-' +
      platformTag() + '-' + process.arch + ext
    );
  }

  // GitHub release-asset URLs 302 to a signed *.githubusercontent.com location
  // (release-assets.githubusercontent.com today),
  // and b.httpClient.downloadStream composes through request()'s
  // no-follow default — it throws on a 3xx rather than chasing it. So we
  // resolve the final landing URL first: a stream-mode request that follows
  // up to 5 hops and records each Location via the onRedirect hook. The
  // last `to` is the resolved URL; the response body is drained + destroyed
  // immediately since we only wanted the URL. A direct 200 (no redirect)
  // leaves resolved === url.
  async function resolveFinalUrl(url) {
    let resolved = url;
    let resp;
    try {
      resp = await b.httpClient.request({
        url, method: 'GET',
        headers: { 'User-Agent': userAgent },
        agent: httpsAgent,
        allowInternal,
        allowedHosts,
        responseMode: 'stream',
        maxRedirects: 5,
        timeoutMs: C.TIME.minutes(2),
        idleTimeoutMs: C.TIME.minutes(1),
        onRedirect: (e) => { if (e && e.to) resolved = e.to; },
      });
    } catch (err) {
      if (err && err.code === 'HTTP_ERROR' && err.statusCode) {
        throw new Error(`HTTP ${err.statusCode} from ${url}`);
      }
      throw err;
    }
    // We have the resolved URL — discard the body without buffering it.
    const body = resp && resp.body;
    if (body && typeof body.destroy === 'function') {
      try { body.destroy(); } catch { /* best-effort teardown */ }
    } else if (body && typeof body.resume === 'function') {
      body.resume();
    }
    return resolved;
  }

  // Stream an asset to disk instead of buffering it into memory. Routes
  // through the same b.httpClient + b.pqcAgent the rest of the client uses
  // (SSRF / TLS / allowedHosts posture unchanged), hashes the bytes in
  // flight, and atomically renames into place — the on-disk file is then
  // re-verified by the SHA3-512-pinned standalone verifier before any swap.
  // The resolved URL is computed first so downloadStream never sees the
  // GitHub 302 it would refuse.
  //
  // GitHub's release-asset 302 lands on a short-lived signed
  // release-assets.githubusercontent.com URL (X-Amz-Expires, minutes). If the
  // signed URL has expired between resolveFinalUrl() and the download leg,
  // S3 answers 403 (AccessDenied) / 410 (Gone). Re-running resolveFinalUrl
  // mints a fresh signed URL, so retry the WHOLE resolve+download as a unit
  // on exactly those two statuses. The retry classifier gates on statusCode
  // only, and only the download leg surfaces an err.statusCode (the resolve
  // leg's HTTP_ERROR is remapped to a plain message above), so an auth/404
  // failure on the resolve leg is never spun. A small attempt cap suffices —
  // the standalone verifier and the 6h poll cadence are the outer resilience.
  async function downloadTo(url, destPath, maxBytes) {
    // Size the byte cap to the artifact class: the binary asset legitimately
    // runs to hundreds of MiB, but the detached signature is under a hundred
    // bytes — so the signature leg passes MAX_SIGNATURE_BYTES and only the
    // asset leg carries the 256 MiB ceiling. Default to the asset cap so an
    // unspecified caller is never LESS bounded than before.
    const byteCap = typeof maxBytes === 'number' ? maxBytes : MAX_ASSET_BYTES;
    return b.retry.withRetry(async () => {
      const resolvedUrl = await resolveFinalUrl(url);
      try {
        await b.httpClient.downloadStream({
          url: resolvedUrl,
          dest: destPath,
          agent: httpsAgent,
          allowInternal,
          allowedHosts,
          headers: { 'User-Agent': userAgent },
          hash: 'sha3-512',
          maxBytes: byteCap,
          timeoutMs: C.TIME.minutes(2),
          idleTimeoutMs: C.TIME.minutes(1),
        });
      } catch (err) {
        if (err && err.statusCode) {
          // Preserve statusCode on the rethrown Error so the retry classifier
          // below can see it (a bare message-only Error would never match).
          const e = new Error(`HTTP ${err.statusCode} from ${resolvedUrl}`);
          e.statusCode = err.statusCode;
          throw e;
        }
        throw err;
      }
      return destPath;
    }, {
      maxAttempts: 3,
      baseDelayMs: 250,
      // 403 AccessDenied / 410 Gone are the S3 responses to an expired signed URL.
      isRetryable: (e) => !!(e && (e.statusCode === 403 || e.statusCode === 410)),
    });
  }

  function writeMarker(newVersion, prevBinaryPath, extra) {
    const data = Object.assign({ newVersion, prevBinaryPath, installedAt: Date.now() }, extra || {});
    // Atomic write: temp + fsync + rename + parent-dir fsync, with the
    // Windows transient-lock retry on the rename, and the parent dir
    // created internally. A crash in the swap window can never leave a
    // torn JSON that readMarker() would silently treat as "no pending
    // update", abandoning rollback. fileMode keeps the marker world-
    // readable (it carries no secret — only version + prev-binary path).
    b.atomicFile.writeSync(markerPath, JSON.stringify(data), { fileMode: 0o644 });
  }

  // Read the rollback marker through a symlink-refusing, fd-bound read.
  // The marker drives destructive decisions — its prevBinaryPath is fed
  // to unlinkSync and copied onto the running executable on rollback — so
  // a symlink planted at the marker path (the daemon writes it 0o644 via
  // b.atomicFile.writeSync, so a link there is never legitimate) must be
  // refused rather than followed to an attacker-chosen file. fdSafeReadSync
  // opens O_NOFOLLOW + caps the size; the parsed JSON still runs through
  // b.safeJson for prototype-pollution defense. Any failure — symlink,
  // missing file, oversize, malformed JSON — collapses to null so the
  // caller treats it as "no pending update".
  function readMarker() {
    try {
      const raw = b.atomicFile.fdSafeReadSync(markerPath, {
        refuseSymlink: true,
        maxBytes: C.BYTES.kib(64),
        encoding: 'utf8',
      });
      return b.safeJson.parse(raw, { maxBytes: C.BYTES.kib(64) });
    } catch { return null; }
  }

  function deleteMarker() {
    try { nodeFs.unlinkSync(markerPath); } catch {}
  }

  // Durable clean-exit signal for probation. The daemon calls this from its
  // graceful-shutdown handler (SIGTERM/SIGINT). A clean, signal-handled exit
  // during probation means the new binary RAN and was intentionally stopped
  // (reboot, systemd Restart=, operator stop/start, container restart) — it did
  // NOT crash. It stamps `gracefulAt` into the marker (atomic rewrite,
  // preserving installedAt + prevBinaryPath) so a restart that straddles the
  // window is recognised as a healthy restart and never downgraded. A crash —
  // an uncaught throw, a hang killed by SIGKILL, or any exit that bypasses the
  // shutdown handler — leaves no gracefulAt, so the past-window branch rolls
  // back. (This deliberately does NOT key off reaching engine.start(): a binary
  // that boots then crashes seconds later would stamp health on that single
  // start and escape rollback while its predecessor's binary is being deleted —
  // engine.start() returning is not proof the build stays alive.) Idempotent +
  // best-effort: a missing/foreign/already-stamped marker is a no-op, and a
  // write failure is swallowed so it can never block shutdown.
  function markGracefulShutdown() {
    try {
      const marker = readMarker();
      if (!marker || marker.newVersion !== currentVersion || marker.gracefulAt) return;
      writeMarker(currentVersion, marker.prevBinaryPath, {
        installedAt: marker.installedAt,
        gracefulAt: Date.now(),
        expectedHash: marker.expectedHash, // preserve the probationary-binary digest
      });
    } catch { /* best-effort; the probation timer + past-window branch still guard */ }
  }

  function prevPathFor(currentPath) {
    const ext = nodePath.extname(currentPath);
    const base = currentPath.slice(0, currentPath.length - ext.length);
    return `${base}.prev${ext}`;
  }

  // Windows holds an exclusive lock on a running image, so renaming the
  // NEW binary ONTO the running .exe (what b.selfUpdate.swap does) fails
  // with EBUSY/EPERM. Windows does, however, permit renaming the running
  // image away from its own path. The backup of the current binary is
  // therefore that rename target — `<exec>.old` — which stays locked
  // until this process exits and is unlinked on the next boot.
  function oldPathFor(currentPath) {
    const ext = nodePath.extname(currentPath);
    const base = currentPath.slice(0, currentPath.length - ext.length);
    return `${base}.old${ext}`;
  }

  // win32 in-use rollback: rename the running (new, crashed) image away,
  // then move `<exec>.old` (the backup recorded at install) back to the
  // original path. The `.new-failed` rename target stays locked until this
  // process exits; the next boot's stale-marker / probation cleanup leaves
  // it for the operator (or a later install's unlink) — it never blocks
  // the restore. Throws an actionable error if even the rename-away fails.
  function _windowsRollback(currentPath, backupPath) {
    const failedPath = `${currentPath}.new-failed`;
    try { nodeFs.unlinkSync(failedPath); } catch { /* no stale failed image */ }
    try {
      nodeFs.renameSync(currentPath, failedPath);
    } catch (err) {
      if (err && (err.code === 'EPERM' || err.code === 'EACCES' || err.code === 'EBUSY')) {
        throw new Error(
          `Windows blocked renaming the running executable (${err.code}) — ` +
          `manual recovery required: restore ${backupPath} to ${currentPath}.`
        );
      }
      throw err;
    }
    try {
      nodeFs.renameSync(backupPath, currentPath);
    } catch (mvErr) {
      if (mvErr && mvErr.code === 'EXDEV') {
        // backupPath comes from marker.prevBinaryPath — disk-sourced state
        // with no structural same-volume guarantee (an operator can relocate
        // the install between the crashed boot and this restore), so the
        // cross-device copy fallback is load-bearing, not dead code.
        try {
          nodeFs.copyFileSync(backupPath, currentPath);
        } catch (cpErr) {
          // Copy failed mid-restore — currentPath may now hold a truncated
          // partial. Clear it, put the running image back so the exec path
          // isn't left empty/corrupt, and surface the ORIGINAL copy error
          // (not any restore error) so checkRollback reports the root cause.
          try { nodeFs.unlinkSync(currentPath); } catch { /* nothing partial to clear */ }
          try { nodeFs.renameSync(failedPath, currentPath); } catch { /* best-effort */ }
          throw cpErr;
        }
        try { nodeFs.unlinkSync(backupPath); } catch { /* backup leak — operator-cleanable */ }
      } else {
        // Restore failed — put the running image back so we aren't left
        // with no binary at currentPath, then surface the error.
        try { nodeFs.renameSync(failedPath, currentPath); } catch { /* best-effort */ }
        throw mvErr;
      }
    }
  }

  // `expectedHash` is the SHA3-512 hex the standalone verifier returned for
  // `assetPath` (verifyResult.sha3_512). It is REQUIRED on the POSIX path —
  // b.selfUpdate.swap now mandates it and re-hashes the source from memory to
  // bind the installed bytes to the signature-verified bytes — and the win32
  // path re-checks the same digest before installing. checkOnce always threads
  // the verified digest through; never recompute it here (a fresh recompute
  // would reopen the verify->install TOCTOU window the binding exists to close).
  async function performInstall(version, assetPath, expectedHash) {
    const currentPath = getExecPath();
    const prevPath = platform === 'win32'
      ? oldPathFor(currentPath)
      : prevPathFor(currentPath);

    // Marker BEFORE the swap. If the marker write fails (ENOSPC / EACCES on
    // CONFIG_DIR) nothing has touched the binary yet, so "install failed"
    // is true on disk as well as in the process. The reverse order installed
    // the new binary with NO marker on a marker-write failure — no probation,
    // no crash-rollback, an orphaned backup — and the next poll's stale-backup
    // unlink then destroyed the only genuine old-binary copy before re-backing
    // up the already-new bytes. A marker whose swap subsequently fails is
    // harmless: the next boot of the OLD binary hits checkRollback's
    // version-mismatch branch and clears it, and the rollback branch's
    // existsSync guard covers a prevBinaryPath the failed swap never created.
    // Stamp the SHA3-512 the standalone verifier signed off on so a later
    // crash-rollback can confirm the on-disk binary is still THIS probationary
    // build before restoring .prev over it (mirrors b.selfUpdate.evaluateOnBoot's
    // installed-binary-not-probationary guard).
    writeMarker(version, prevPath, { expectedHash });

    // Install the verified bytes over the running image via b.selfUpdate.swap.
    // The primitive moves the outgoing binary aside to `prevPath` (a rename,
    // which frees the path even for a locked/running Windows image — the OS
    // refuses an in-place replace of a mapped executable but allows the move),
    // re-hashes `from` against the SHA3-512 the standalone verifier signed off
    // on (O_NOFOLLOW, from memory — no verify->install TOCTOU), installs the
    // verified in-memory bytes at the freed path, and restores the backup if the
    // install write fails. The move-aside is what makes it Windows-safe, so both
    // platforms route through the one primitive; the hand-rolled _windowsSwap it
    // used to need was retired once swap() gained the move-aside (blamejs
    // v0.17.13). (rollback is NOT symmetric — b.selfUpdate.rollback copies OVER
    // `to`, which fails on a locked Windows image, so _windowsRollback stays.)
    try { nodeFs.unlinkSync(prevPath); } catch {} // clear a stale backup at prevPath
    try {
      await b.selfUpdate.swap({
        from:         assetPath,
        to:           currentPath,
        backupTo:     prevPath,
        expectedHash,
        // Match the swap-side integrity re-read cap to the download cap rather
        // than riding the primitive's 1 GiB default.
        maxBytes:     MAX_ASSET_BYTES,
      });
    } catch (err) {
      const code = err && err.code;
      // Map the primitive's typed errors back to the actionable operator
      // guidance the hand-rolled swap emitted, rather than an opaque framework
      // code. A move-aside refused on Windows (locked-down ACLs / an AV scanner
      // holding a handle) means even the rename-away is blocked.
      if (code === 'selfupdate/backup-failed' && platform === 'win32') {
        throw new Error(
          `Auto-update: in-daemon self-replace is not supported here — Windows blocked ` +
          `moving the running executable aside (${(err && err.message) || String(err)}). Re-run the ` +
          `installer manually, or run the external updater / "docker pull" for your deployment to upgrade.`);
      }
      if (code === 'selfupdate/swap-hash-mismatch' || code === 'selfupdate/swap-read-failed') {
        throw new Error(
          `Auto-update: the downloaded binary failed its pre-install integrity re-check ` +
          `(${(err && err.message) || String(err)}) — refusing to install. Re-run the update, or use ` +
          `the external updater / "docker pull" for your deployment to upgrade.`);
      }
      throw err;
    }
    // Restore the executable bit on POSIX (Windows ignores it). swap preserves
    // the SOURCE asset's mode, which the streamed download may not have left at 0o755.
    if (platform !== 'win32') { try { nodeFs.chmodSync(currentPath, 0o755); } catch {} }

    // Mark the successor so its cmdStart tolerates THIS still-exiting process's
    // pidfile during the brief handoff window instead of die()-ing on it.
    const child = spawnFn(currentPath, getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, HERMITSTASH_SELF_REPLACE: '1' },
    });
    // Wait for the successor to actually spawn before the caller proceeds to
    // exit. A spawn failure (EACCES from a blocked chmod, AV interference) is
    // delivered as an async 'error' event; unhandled, it surfaced as an
    // uncaughtException that killed the parent with NO successor running
    // while the probation marker kept ticking — a manual restart more than
    // probationMs later then spuriously rolled back a correctly-installed
    // build. On spawn failure delete the marker so the next boot of the
    // (already-installed) new binary starts clean; forfeiting crash-rollback
    // for that one boot beats a guaranteed spurious downgrade. The typeof
    // guards match unref's — tests inject plain-object spawnFn stubs.
    if (child && typeof child.once === 'function') {
      await new Promise((resolve) => {
        let settled = false;
        const done = () => { if (!settled) { settled = true; resolve(); } };
        child.once('spawn', done);
        child.once('error', (e) => {
          log.error(
            `Auto-update: installed v${version} but failed to spawn the new binary ` +
            `(${(e && (e.code || e.message)) || String(e)}) — restart hermitstash-sync manually; ` +
            `the new binary is already in place.`);
          deleteMarker();
          done();
        });
      });
    }
    if (child && typeof child.unref === 'function') child.unref();
    return { currentPath, prevPath };
  }

  // Last-seen ETag for poll's If-None-Match fast path (memory-only,
  // per-instance). RFC 9110 etags are per-resource; a channel switch builds a
  // fresh createUpdater instance with a different releasesUrl, so the cache
  // can never pin a stale etag against the wrong resource.
  let lastEtag = null;

  async function checkOnce(onUpdateReady) {
    if (!pubkeyPem) {
      log.debug('Auto-update: no pubkey embedded, skipping check');
      return { status: 'disabled' };
    }
    let pollResult;
    try {
      pollResult = await b.selfUpdate.poll({
        releasesUrl,
        currentVersion,
        assetPattern:     platformAssetPattern(),
        signaturePattern: platformSignaturePattern(),
        allowedHosts,
        allowInternal,
        etag:             lastEtag || undefined,
        timeoutMs:        C.TIME.seconds(15),
        headers:          { 'User-Agent': userAgent, 'Accept': 'application/vnd.github+json' },
      });
    } catch (err) {
      log.warn(`Auto-update poll failed: ${err.message}`);
      return { status: 'error', error: err };
    }
    if (pollResult.etag) lastEtag = pollResult.etag;

    if (!pollResult.available) {
      // Covers both a genuine same-version response and the If-None-Match
      // 304 fast path (statusCode 304, etagHit) — either way nothing changed.
      log.debug(`Auto-update: on latest (${currentVersion})`);
      return { status: 'up-to-date', version: pollResult.latestTag };
    }

    const newVersion = String(pollResult.latestTag || '').replace(/^v/, '');
    if (!isSeaBinary()) {
      log.warn(`Auto-update: v${newVersion} available — running from source, update manually with "git pull"`);
      return { status: 'source-notify', version: newVersion };
    }

    if (!pollResult.asset || !pollResult.signature) {
      const err = new Error(`Missing asset or signature for ${assetName(newVersion)} (asset=${!!pollResult.asset} sig=${!!pollResult.signature})`);
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }

    // Defence in depth behind platformSignaturePattern(): the selected
    // signature must be exactly <asset>.sig. If the poll ever pairs the
    // binary with a foreign or wrong-algorithm sidecar (e.g. .mldsa.sig),
    // refuse rather than download + fail an opaque verification.
    const expectedSig = `${pollResult.asset.name}.sig`;
    if (pollResult.signature.name !== expectedSig) {
      const err = new Error(`Auto-update signature/asset mismatch: picked ${pollResult.signature.name} for ${pollResult.asset.name} (expected ${expectedSig})`);
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }

    // Guarded like every other failure leg: checkOnce's contract is to never
    // reject (callers treat any rejection as a bug), and mkdtemp was the one
    // remaining await outside a try — a full tmpdir surfaced as a misrouted
    // generic unhandled-rejection log instead of the check-failed warn.
    let tmp;
    try {
      tmp = await nodeFsPromises.mkdtemp(nodePath.join(nodeOs.tmpdir(), 'hs-update-'));
    } catch (err) {
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }
    const cleanup = async () => {
      try { await nodeFsPromises.rm(tmp, { recursive: true, force: true }); } catch {}
    };

    try {
      log.info(`Auto-update: v${newVersion} available (running ${currentVersion}) — downloading + verifying`);
      const assetPath = nodePath.join(tmp, pollResult.asset.name);
      const sigPath   = nodePath.join(tmp, pollResult.signature.name);
      await downloadTo(pollResult.asset.url, assetPath, MAX_ASSET_BYTES);
      await downloadTo(pollResult.signature.url, sigPath, MAX_SIGNATURE_BYTES);

      // Verify via the SHA3-512-pinned standalone verifier — matches the
      // release.yml signer's hash choice. b.selfUpdate.verify would
      // wrongly reject SHA3-512 sigs because it goes through
      // crypto.verify(null, …) which infers SHA-384 from the curve.
      let verifyResult;
      try {
        verifyResult = standaloneVerifier.verify(assetPath, sigPath, pubkeyPem);
      } catch (vErr) {
        throw new Error(`Auto-update: signature verification failed for v${newVersion}: ${vErr.message}`);
      }
      log.info(`Auto-update: v${newVersion} verified (sha3-512=${verifyResult.sha3_512.slice(0, 16)}…, alg=${verifyResult.alg}), handing off for install`);

      if (onUpdateReady) {
        await onUpdateReady(async () => {
          try {
            // Thread the VERIFIED SHA3-512 (not a fresh recompute) into the
            // install so the swap binds the installed bytes to the
            // signature-verified bytes, closing the verify->install window.
            return await performInstall(newVersion, assetPath, verifyResult.sha3_512);
          } finally {
            await cleanup();
          }
        });
      } else {
        await cleanup();
      }
      return { status: 'ready', version: newVersion };
    } catch (err) {
      await cleanup();
      log.warn(`Auto-update check failed: ${err.message}`);
      return { status: 'error', error: err };
    }
  }

  function start(onUpdateReady) {
    if (!pubkeyPem) {
      log.info('Auto-update disabled: no pubkey embedded in this build');
      return () => {};
    }
    if (!isSeaBinary()) {
      log.info('Auto-update: source install — will notify on new versions but not self-replace');
    }

    let running = false;
    const runCheck = async () => {
      if (running) return;
      running = true;
      try { await checkOnce(onUpdateReady); } finally { running = false; }
    };

    const kickoff = setTimeout(runCheck, initialDelayMs);
    if (kickoff && typeof kickoff.unref === 'function') kickoff.unref();

    const repeater = b.safeAsync.repeating(runCheck, pollMs, {
      onError: function (err) {
        log.warn('Auto-update poll failed: ' + (err && err.message ? err.message : String(err)));
      },
    });

    return () => { clearTimeout(kickoff); repeater.stop(); };
  }

  // Returns one of: 'no-marker', 'stale-cleared', 'probation',
  // 'probation-complete', 'rolled-back', 'rollback-failed'.
  // 'probation-complete' is the healthy past-window path: a prior boot of
  // this version exited cleanly during probation (gracefulAt stamped), so
  // the update is kept and the backup is pruned without a downgrade. The
  // caller (cli.js cmdStart) must not continue startup when 'rolled-back'
  // is returned — exitFn fires.
  async function checkRollback() {
    const marker = readMarker();
    if (!marker) return 'no-marker';

    if (marker.newVersion !== currentVersion) {
      log.warn(`Auto-update: stale marker (newVersion=${marker.newVersion}, running=${currentVersion}) — clearing`);
      deleteMarker();
      return 'stale-cleared';
    }

    // Harden the age math: a missing / zero / non-numeric installedAt would
    // turn `Date.now() - installedAt` into a huge value that forces an
    // immediate spurious rollback. Treat a marker with no valid install time
    // as corrupt and clear it rather than acting on it.
    const installedAt = Number(marker.installedAt);
    if (!Number.isFinite(installedAt) || installedAt <= 0) {
      log.warn('Auto-update: update marker has no valid install time — clearing');
      deleteMarker();
      return 'stale-cleared';
    }

    const age = Date.now() - installedAt;

    if (age < probationMs) {
      log.info(`Auto-update: v${currentVersion} in probation (${Math.round(age/1000)}s / ${Math.round(probationMs/1000)}s)`);
      const remaining = probationMs - age;
      const timer = setTimeout(() => {
        // Re-read the marker so cleanup acts on the CURRENT on-disk state, not
        // the snapshot captured when the timer was armed (markGracefulShutdown
        // can rewrite the marker during the window). Guard the destructive
        // unlink on the marker still being for this version: if it has been
        // rewritten for a different version, skip the unlink (worst case a
        // leaked backup the next boot prunes, never a wrong-file unlink) and
        // still clear any stale marker. A concurrently-deleted marker (m null)
        // skips the unlink and deleteMarker is a no-op. readMarker stays the
        // single read path so its O_NOFOLLOW + size-cap + proto-pollution
        // defenses still apply inside the timer.
        const m = readMarker();
        if (m && m.newVersion === currentVersion && m.prevBinaryPath) {
          try { nodeFs.unlinkSync(m.prevBinaryPath); } catch {}
        }
        deleteMarker();
        log.info(`Auto-update: v${currentVersion} completed probation`);
      }, remaining);
      if (timer && typeof timer.unref === 'function') timer.unref();
      return 'probation';
    }

    // Past the probation window. If a prior boot of this version exited
    // CLEANLY during probation (markGracefulShutdown stamped gracefulAt from
    // the SIGTERM/SIGINT handler), the binary ran and was intentionally stopped
    // — a reboot or operator/systemd restart that straddled the window, not a
    // crash — so complete probation and never downgrade. Roll back only when
    // there is NO clean-exit evidence: the new binary never survived to a
    // graceful stop within the window, the genuine botched-update crash signal
    // (an uncaught throw, a hang killed by SIGKILL, or an error-path
    // process.exit that bypassed the shutdown handler).
    if (marker.gracefulAt) {
      log.info(`Auto-update: v${currentVersion} completed probation (clean restart past the window)`);
      if (marker.prevBinaryPath) {
        try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {}
      }
      deleteMarker();
      return 'probation-complete';
    }

    // Before restoring .prev, re-verify the on-disk binary is actually THIS
    // probationary build. If some other mechanism replaced getExecPath() at the
    // same version between the crashed boot and now (an external updater, a
    // manual reinstall), rolling back would clobber it with the stale .prev.
    // Mirror b.selfUpdate.evaluateOnBoot's installed-binary-not-probationary
    // guard: when the marker recorded the installed digest and the current
    // binary no longer matches it, KEEP the current binary and clear the marker
    // instead of rolling back. Only enforced when expectedHash is present (a
    // marker written before this shipped, or after markGracefulShutdown, falls
    // through unchanged); an unreadable binary also falls through — rolling back
    // a binary we can't even hash is the safer default. Hashed with the
    // MAX_ASSET_BYTES cap the swap uses: the SEA binary exceeds hashFile's
    // sync-file ceiling.
    if (marker.expectedHash) {
      let currentHash = null;
      try {
        const rows = await b.crypto.hashFilesParallel([getExecPath()], {
          algorithms: ['sha3-512'],
          maxBytesPerFile: MAX_ASSET_BYTES,
        });
        currentHash = rows[0] && rows[0].sha3_512;
      } catch (e) {
        log.warn(`Auto-update: could not re-hash the current binary before rollback (${(e && e.message) || String(e)}) — proceeding with rollback`);
      }
      if (currentHash && currentHash !== marker.expectedHash) {
        log.info(`Auto-update: the binary at ${getExecPath()} is not the probationary v${currentVersion} build (digest mismatch) — something else replaced it; keeping it and clearing the marker instead of rolling back`);
        if (marker.prevBinaryPath) { try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {} }
        deleteMarker();
        return 'probation-complete';
      }
    }

    log.error(`Auto-update: v${currentVersion} did not survive to a clean stop within probation — rolling back`);
    try {
      if (!marker.prevBinaryPath || !nodeFs.existsSync(marker.prevBinaryPath)) {
        throw new Error(`prev binary not found at ${marker.prevBinaryPath}`);
      }
      if (platform === 'win32') {
        // Symmetric in-use restore: copying the backup ONTO the running
        // (new, crashed) image fails with EPERM, so rename the running
        // image away to `<exec>.new-failed`, then rename `<exec>.old`
        // back to the original path. The stranded `.new-failed` stays
        // locked until this process exits and is cleared next boot.
        _windowsRollback(getExecPath(), marker.prevBinaryPath);
      } else {
        // POSIX in-place restore. Do NOT route through b.selfUpdate.rollback:
        // it copies via atomicFile.copy whose read is capped at a 64 MiB default
        // with NO override, and the .prev backup is a prior Node SEA binary
        // (~110+ MiB, well over that cap) — so it would fail 'too-large' and
        // silently defeat auto-rollback on Linux/macOS. Restore in-process with
        // the same MAX_ASSET_BYTES ceiling the download + swap already use (this
        // mirrors b.selfUpdate.evaluateOnBoot, which reads with a GiB cap for
        // exactly this reason): read the SHA3-512-verified prev binary with
        // O_NOFOLLOW (a symlink planted at the backup path is refused, not
        // followed) and write it atomically over the running exec — POSIX
        // permits replacing a running binary's inode. b.selfUpdate.rollback has
        // no maxBytes knob; that gap is filed upstream against blamejs.
        const prevBytes = b.atomicFile.fdSafeReadSync(marker.prevBinaryPath, {
          maxBytes: MAX_ASSET_BYTES,
          refuseSymlink: true,
        });
        await b.atomicFile.write(getExecPath(), prevBytes, { fileMode: 0o755, overwrite: true });
        try { nodeFs.unlinkSync(marker.prevBinaryPath); } catch {}
      }
    } catch (err) {
      log.error(`Auto-update: rollback failed: ${err.message} — manual recovery required`);
      deleteMarker();
      return 'rollback-failed';
    }

    deleteMarker();

    // Same self-replace handoff as performInstall: the restored binary's
    // cmdStart must tolerate this exiting process's pidfile during the window.
    const child = spawnFn(getExecPath(), getArgv(), {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, HERMITSTASH_SELF_REPLACE: '1' },
    });
    // Wait for 'spawn'/'error' before exitFn: process.exit runs synchronously
    // and would preempt the nextTick 'error' emission, turning a failed
    // respawn into a silent exit-0 with no successor and no log line. The
    // marker is already deleted above, so there is nothing to unwind — just
    // make the failure durable and actionable.
    if (child && typeof child.once === 'function') {
      await new Promise((resolve) => {
        let settled = false;
        const done = () => { if (!settled) { settled = true; resolve(); } };
        child.once('spawn', done);
        child.once('error', (e) => {
          log.error(
            `Auto-update: rolled back to the previous binary but failed to respawn it ` +
            `(${(e && (e.code || e.message)) || String(e)}) — start hermitstash-sync manually.`);
          done();
        });
      });
    }
    if (child && typeof child.unref === 'function') child.unref();
    exitFn(0);
    return 'rolled-back';
  }

  return {
    start,
    checkRollback,
    markGracefulShutdown,
    checkOnce,
    isSeaBinary,
    _internals: { performInstall, downloadTo, compareVersions, assetName, prevPathFor, readMarker, writeMarker, deleteMarker, platformAssetPattern, platformSignaturePattern, resolveFinalUrl, allowedHosts },
  };
}

const _default = createUpdater();

module.exports = {
  start: _default.start,
  checkRollback: _default.checkRollback,
  markGracefulShutdown: _default.markGracefulShutdown,
  checkOnce: _default.checkOnce,
  isSeaBinary: _default.isSeaBinary,
  createUpdater,
  assetName,
  compareVersions,
};
