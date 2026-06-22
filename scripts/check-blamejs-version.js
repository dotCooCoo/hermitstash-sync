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
const b = require('../vendor/blamejs');

const MANIFEST_PATH = nodePath.join(__dirname, '..', 'vendor', 'MANIFEST.json');
const API_URL = 'https://api.github.com/repos/blamejs/blamejs/releases/latest';
// The releases/latest payload is a few KiB; cap the response well above
// that so a compromised / MITM'd transport can't stream an unbounded
// body into memory.
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
  const headers = {
    'User-Agent': 'hermitstash-sync-vendor-check',
    'Accept':     'application/vnd.github+json',
  };
  // GitHub Actions provides GITHUB_TOKEN as the standard auth handle;
  // unauthenticated requests are rate-limited to 60/hour shared across
  // the runner's IP. Use the token when present so the check survives
  // a noisy CI day.
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = 'Bearer ' + process.env.GITHUB_TOKEN;
  }

  const res = await b.httpClient.request({
    method:           'GET',
    url:              API_URL,
    headers:          headers,
    timeoutMs:        15000,
    maxResponseBytes: MAX_RESPONSE_BYTES,
  });
  if (res.statusCode !== 200) {
    throw new Error('GitHub API returned HTTP ' + res.statusCode);
  }
  let parsed;
  try { parsed = b.safeJson.parse(res.body, { maxBytes: MAX_RESPONSE_BYTES }); }
  catch (e) { throw new Error('GitHub API response not JSON: ' + e.message); }
  if (typeof parsed.tag_name !== 'string' || parsed.tag_name.length === 0) {
    throw new Error('GitHub API response missing tag_name');
  }
  return parsed.tag_name;
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
  console.error('  rm -rf vendor/blamejs');
  console.error('  git clone --depth 1 --branch ' + latest + ' https://github.com/blamejs/blamejs vendor/blamejs');
  console.error('  rm -rf vendor/blamejs/.git');
  console.error('');
  console.error('Then edit vendor/MANIFEST.json:');
  console.error('  "version": "' + latest.replace(/^v/, '') + '",');
  console.error('  "tag":     "' + latest + '"');
  process.exit(1);
})();
