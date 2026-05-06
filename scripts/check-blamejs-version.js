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
 * Zero dependencies (node:https + node:fs + node:path only) so the check
 * runs identically in CI and locally — same code path the auto-updater
 * uses to talk to the GitHub API.
 *
 * Run via:
 *   node scripts/check-blamejs-version.js
 *
 * Exit codes:
 *   0 — vendored matches upstream latest
 *   1 — version mismatch (intentional fail; bump vendor/blamejs)
 *   2 — unable to determine upstream latest (network / API failure)
 */

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');

const MANIFEST_PATH = path.join(__dirname, '..', 'vendor', 'MANIFEST.json');
const API_URL = 'https://api.github.com/repos/blamejs/blamejs/releases/latest';

function readVendoredTag() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  if (!manifest || !manifest.packages || !manifest.packages.blamejs ||
      typeof manifest.packages.blamejs.tag !== 'string') {
    throw new Error('vendor/MANIFEST.json does not have packages.blamejs.tag');
  }
  return manifest.packages.blamejs.tag;
}

function fetchLatestTag() {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        'User-Agent': 'hermitstash-sync-vendor-check',
        'Accept':     'application/vnd.github+json',
      },
    };
    // GitHub Actions provides GITHUB_TOKEN as the standard auth handle;
    // unauthenticated requests are rate-limited to 60/hour shared across
    // the runner's IP. Use the token when present so the check survives
    // a noisy CI day.
    if (process.env.GITHUB_TOKEN) {
      opts.headers['Authorization'] = 'Bearer ' + process.env.GITHUB_TOKEN;
    }
    const req = https.get(API_URL, opts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error('GitHub API returned HTTP ' + res.statusCode));
          return;
        }
        let parsed;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch (e) { reject(new Error('GitHub API response not JSON: ' + e.message)); return; }
        if (typeof parsed.tag_name !== 'string' || parsed.tag_name.length === 0) {
          reject(new Error('GitHub API response missing tag_name'));
          return;
        }
        resolve(parsed.tag_name);
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('GitHub API request timed out')));
  });
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
