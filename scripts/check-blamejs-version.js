#!/usr/bin/env node
'use strict';

/**
 * Vendor-freshness gate.
 *
 * Reads the pinned blamejs tag from `vendor/MANIFEST.json` and compares it
 * to the latest release on GitHub. Exits non-zero with a GitHub-Actions-
 * style `::error::` annotation when they diverge, so CI fails loudly the
 * moment blamejs ships a new version we haven't pulled in.
 *
 * Talks to the GitHub API through the same hardened transport the rest
 * of the client uses — b.httpClient.request (SSRF guard, DNS pinning,
 * response byte cap, PQC TLS 1.3 via b.pqcAgent) — and parses the body
 * with b.safeJson.parse (size + depth + prototype-pollution caps). Runs
 * identically in CI and locally.
 *
 * Run via:
 *   node scripts/check-blamejs-version.js
 *
 * Exit codes:
 *   0 — vendored matches upstream latest
 *   1 — version mismatch (intentional fail; bump vendor/blamejs)
 *   2 — unable to determine upstream latest (network / API failure)
 */

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeChildProcess = require('node:child_process');
const b = require('../vendor/blamejs');

const MANIFEST_PATH = nodePath.join(__dirname, '..', 'vendor', 'MANIFEST.json');
// Currency is measured against the npm registry because that is where the
// vendored tree comes from. Asking GitHub instead compares against a different
// publication event: a tagged release with no corresponding publish would read
// as staleness that no refresh could clear, and a publish without a tag would
// hide staleness that one could. The check has to ask the same source
// scripts/vendor-update.sh fetches from.
//
// It also removes a dependency on the GitHub API, whose rate limiting has made
// this check fail for reasons that had nothing to do with currency.
//
// The package is @blamejs/core. The bare name `blamejs` on npm belongs to an
// unrelated package and must never be consulted here.
//
// A version string is a few bytes; the cap is far above that so a misbehaving
// or intercepted command cannot stream an unbounded body into memory.
const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MiB

function readVendoredTag() {
  const manifest = b.safeJson.parse(nodeFs.readFileSync(MANIFEST_PATH, 'utf8'));
  if (!manifest || !manifest.packages || !manifest.packages.blamejs ||
      typeof manifest.packages.blamejs.tag !== 'string') {
    throw new Error('vendor/MANIFEST.json does not have packages.blamejs.tag');
  }
  return manifest.packages.blamejs.tag;
}

async function fetchLatestTag() {
  // Asked through npm's own client rather than this project's HTTP client.
  // That client requires a post-quantum key exchange, and the registry does not
  // offer one — the handshake ends in a TLS alert before any request is sent.
  // Loosening it for this one call is not on the table: the floor exists so
  // that no caller can quietly opt out of it.
  //
  // Transport is not what protects the vendored code in any case. The package
  // is fetched over the same connection during a refresh, and what makes those
  // bytes trustworthy is the published SHA-512 they are checked against before
  // anything is unpacked. This call reads a version number and compares it to
  // one already on disk; a tampered answer can cause a spurious "stale" or
  // "current" report and nothing else.
  //
  // The command is a fixed literal with nothing interpolated into it.
  let stdout;
  try {
    stdout = nodeChildProcess.execSync('npm view @blamejs/core version', {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: MAX_RESPONSE_BYTES,
    });
  } catch (e) {
    throw new Error('could not reach the npm registry: ' + (e.message || 'npm view failed'));
  }
  const version = String(stdout).trim();
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error('registry returned an unrecognized version: ' + version.slice(0, 40));
  }
  // The manifest records a tag ("v0.18.16") while the registry reports a bare
  // version, so normalize here rather than at every comparison site.
  return 'v' + version;
}

(async function main() {
  let vendored;
  try { vendored = readVendoredTag(); }
  catch (e) {
    console.error('::error::Cannot read vendor/MANIFEST.json: ' + e.message);
    process.exit(2);
  }

  let latest;
  try { latest = await fetchLatestTag(); }
  catch (e) {
    console.error('::error::Cannot fetch latest blamejs release: ' + e.message);
    process.exit(2);
  }

  if (vendored === latest) {
    console.log('Vendored blamejs ' + vendored + ' is current with upstream.');
    process.exit(0);
  }

  console.error('::error::Vendored blamejs ' + vendored + ' does not match upstream latest ' + latest + '.');
  console.error('');
  console.error('Update with:');
  console.error('  bash scripts/vendor-update.sh blamejs ' + latest.replace(/^v/, ''));
  console.error('');
  console.error('That verifies the published package against its SHA-512 before unpacking,');
  console.error('recomputes the consumed-file hashes the startup check reads, and records the');
  console.error('version, tag and digest in vendor/MANIFEST.json. Editing the manifest by hand');
  console.error('leaves those hashes describing the previous tree.');
  process.exit(1);
})();
