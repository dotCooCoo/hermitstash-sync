'use strict';

/**
 * E2E test runner for hermitstash-sync.
 *
 * Usage:   node tests/run-all.js
 *
 * Env:
 *   HS_ONLY=test-a.js,test-b.js  Run only these files (sequential, in order).
 *   HS_PARALLEL=0                Force fully-sequential mode (debug order bugs).
 *   HS_CONCURRENCY=N             Override parallel-pool size (default min(4, cpus)).
 *
 * Execution model:
 *   1. Start one shared HermitStash server.
 *   2. Stage A (sequential): run global-state mutators one at a time.
 *   3. Stage B (parallel):   run bundle-scoped tests in a worker pool.
 *   4. Stop server.
 *
 * Test files are classified via SEQUENTIAL below. Anything not listed runs in
 * the parallel pool. When adding a new test file that mutates global server
 * state (admin settings, session table, rate-limit windows shared across
 * tests), add it to SEQUENTIAL.
 */

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startServer, stopServer, httpRequest, sleep } = require('./test-helpers');

// Load tests/.env (gitignored) into process.env before tests spawn.
// Covers S3_TEST_* / BACKUP_TEST_* credentials for the S3-backed
// suites. Parsed line-by-line (not sourced) so arbitrary shell can't
// execute and the file format stays predictable: KEY=VALUE, # comments,
// optional single or double quotes around the value.
function loadDotEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return 0;
  let loaded = 0;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    // Don't overwrite values already set by the caller's shell — caller
    // always wins, matching the dotenv convention.
    if (process.env[key] === undefined) {
      process.env[key] = value;
      loaded++;
    }
  }
  return loaded;
}

const loadedCount = loadDotEnv();
if (loadedCount > 0) {
  console.log(`[runner] Loaded ${loadedCount} var(s) from tests/.env`);
}

// Files that mutate global server state and must run alone and in order.
const SEQUENTIAL = new Set([
  'test-admin-ops.js',          // session purge, user suspend/delete, settings writes
  'test-settings-validation.js', // rewrites settings repeatedly
  'test-cert-renewal.js',        // 5/5min rate limit on /sync/renew-cert
  'test-ca-regen.js',            // drives /admin/api/mtls-ca/regenerate — mutates CA state if skipRestart is omitted
  'test-server-fixes.js',        // some fixtures touch global config
  'test-s3-storage.js',          // external S3 I/O — keep serial to avoid flaky cloud noise
  'test-backup-restore-roundtrip.js', // drives /admin/backup + /admin/restore, needs S3 bucket
  'test-bundle-ownership.js',    // seeds users/keys/bundles; keep ordered to avoid user-sequence races
  'test-chunked-upload-scratch.js', // drives /drop/init rate limits + creates bundles via DB
  'test-enrollment-reissue.js',  // /admin/stash/:id/reissue-cert has 5/5min rate limit — sequential avoids sharing budget
  'test-cert-fingerprint-binding.js', // mutates api_keys.certFingerprint — isolate
  'test-orphan-cleanup.js',      // seeds files under uploads/ and exercises scheduled cleanup
  'test-sync-rename-idor.js',    // seeds multiple bundles/files, races with parallel sync tests
]);

const ONLY = (process.env.HS_ONLY || '').split(',').map(s => s.trim()).filter(Boolean);
const FORCE_SEQUENTIAL = process.env.HS_PARALLEL === '0';
const CONCURRENCY = Math.max(1, parseInt(process.env.HS_CONCURRENCY, 10)
  || Math.min(4, os.availableParallelism ? os.availableParallelism() : os.cpus().length));

const ALL_FILES = fs.readdirSync(__dirname)
  .filter(f => f.startsWith('test-') && f.endsWith('.js') && f !== 'test-helpers.js')
  .filter(f => ONLY.length === 0 || ONLY.includes(f))
  .sort();

function classify(files) {
  if (ONLY.length > 0 || FORCE_SEQUENTIAL) {
    return { sequential: files, parallel: [] };
  }
  return {
    sequential: files.filter(f => SEQUENTIAL.has(f)),
    parallel: files.filter(f => !SEQUENTIAL.has(f)),
  };
}

function buildEnv(ctx) {
  return {
    ...process.env,
    HERMITSTASH_TEST_URL: ctx.url,
    HERMITSTASH_TEST_API_KEY: ctx.apiKey,
    HERMITSTASH_TEST_DB_PATH: ctx.dbPath,
    HERMITSTASH_TEST_SYNC_DIR: ctx.syncDir,
    HERMITSTASH_TEST_DATA_DIR: ctx.dataDir,
    HERMITSTASH_TEST_PORT: String(ctx.port),
    HERMITSTASH_TEST_CLIENT_CERT: ctx.certs ? ctx.certs.clientCertPath : '',
    HERMITSTASH_TEST_CLIENT_KEY: ctx.certs ? ctx.certs.clientKeyPath : '',
    HERMITSTASH_TEST_CA_CERT: ctx.certs ? ctx.certs.caCertPath : '',
  };
}

// Per-file runtime ceilings. Defaults to 120s; suites that exercise
// real Docker / container builds need a longer ceiling because the
// image build alone runs 30-60s before the first test starts. Without
// the override, docker-e2e times out before its inner suite (image
// build + 60s enroll wait + 20s sync waits + restart + SIGTERM)
// finishes — every run reports 3 spurious failures even though every
// test inside passes.
const FILE_TIMEOUTS_MS = {
  'test-docker-e2e.js': 600000,
};
const DEFAULT_FILE_TIMEOUT_MS = 120000;

/**
 * Spawn `node --test <file>` and buffer stdout+stderr until exit.
 * Returns { file, output, status, durationMs }. Never throws.
 */
function runOne(file, env) {
  return new Promise(resolve => {
    const started = Date.now();
    const filePath = path.join(__dirname, file);
    const child = spawn(process.execPath, ['--test', filePath], { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', c => { stdout += c.toString('utf8'); });
    child.stderr.on('data', c => { stderr += c.toString('utf8'); });

    const fileTimeoutMs = FILE_TIMEOUTS_MS[file] || DEFAULT_FILE_TIMEOUT_MS;
    const killTimer = setTimeout(() => {
      child.kill('SIGKILL');
      stderr += `\n[runner] killed after ${Math.round(fileTimeoutMs/1000)}s timeout`;
    }, fileTimeoutMs);

    child.on('close', code => {
      clearTimeout(killTimer);
      resolve({
        file,
        output: stdout + stderr,
        status: code,
        durationMs: Date.now() - started,
      });
    });
    child.on('error', err => {
      clearTimeout(killTimer);
      resolve({
        file,
        output: stdout + stderr + '\n[runner] spawn error: ' + err.message,
        status: -1,
        durationMs: Date.now() - started,
      });
    });
  });
}

function tallyAndPrint(result, totals) {
  const { file, output, status, durationMs } = result;
  const passCount = (output.match(/✔|# pass/g) || []).length;
  const failCount = (output.match(/✖|# fail [1-9][0-9]*/g) || []).length;

  console.log('-'.repeat(60));
  console.log(`  ${file}   (${(durationMs / 1000).toFixed(2)}s)`);
  console.log('-'.repeat(60));
  console.log(output);

  totals.pass += passCount;
  totals.fail += failCount;
  if (failCount > 0 || status !== 0) {
    totals.failures.push({ file, status });
  }
}

async function runSequential(files, env, totals) {
  for (const file of files) {
    await sleep(200);
    const result = await runOne(file, env);
    tallyAndPrint(result, totals);
  }
}

async function runParallel(files, env, totals, concurrency) {
  if (files.length === 0) return;
  console.log('');
  console.log('='.repeat(60));
  console.log(`  Parallel stage (${files.length} files, ${concurrency} workers)`);
  console.log('='.repeat(60));
  console.log('');

  const queue = files.slice();
  // Sort longest-first in a follow-up; for now, shuffle deterministically by name
  // so long-runners don't all land on the same worker.
  queue.sort();

  const workers = [];
  for (let w = 0; w < concurrency; w++) {
    workers.push((async () => {
      while (queue.length > 0) {
        const file = queue.shift();
        if (!file) break;
        const result = await runOne(file, env);
        tallyAndPrint(result, totals);
      }
    })());
  }
  await Promise.all(workers);
}

async function healthCheck(ctx, label) {
  try {
    const res = await httpRequest(`${ctx.url}/health`);
    if (res.statusCode !== 200) {
      console.error(`[runner] Server unhealthy (HTTP ${res.statusCode}) ${label}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error(`[runner] Server unreachable ${label}: ${err.message}`);
    console.error(`[runner] Server stderr tail:\n${(ctx.stderr() || '').slice(-2000)}`);
    return false;
  }
}

async function main() {
  const startTime = Date.now();
  console.log('');
  console.log('='.repeat(60));
  console.log('  HermitStash Sync -- E2E Test Suite');
  console.log('='.repeat(60));
  console.log('');

  console.log('[runner] Starting HermitStash server...');
  let ctx;
  try {
    ctx = await startServer();
    console.log(`[runner] Server running at ${ctx.url}`);
    console.log(`[runner] API key: ${ctx.apiKey.substring(0, 10)}...`);
    console.log(`[runner] Data dir: ${ctx.dataDir}`);
  } catch (err) {
    console.error('[runner] FATAL: Failed to start server');
    console.error(err.message);
    process.exit(1);
  }

  const { sequential, parallel } = classify(ALL_FILES);
  console.log(`[runner] Sequential stage: ${sequential.length} file(s)`);
  console.log(`[runner] Parallel stage:   ${parallel.length} file(s) at concurrency=${CONCURRENCY}`);
  console.log('');

  const env = buildEnv(ctx);
  const totals = { pass: 0, fail: 0, failures: [] };

  if (!(await healthCheck(ctx, 'before test run'))) {
    totals.fail++;
    totals.failures.push({ file: '(pre-flight)', status: -1 });
  } else {
    // Stage A — sequential, global-state mutators
    if (sequential.length > 0) {
      console.log('='.repeat(60));
      console.log(`  Sequential stage (${sequential.length} files)`);
      console.log('='.repeat(60));
      console.log('');
      await runSequential(sequential, env, totals);
    }

    // Re-check server health before releasing the parallel pool
    if (parallel.length > 0 && !(await healthCheck(ctx, 'before parallel stage'))) {
      totals.fail++;
      totals.failures.push({ file: '(parallel-preflight)', status: -1 });
    } else {
      await runParallel(parallel, env, totals, CONCURRENCY);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log('');
  console.log('='.repeat(60));
  console.log('  Results');
  console.log('='.repeat(60));
  console.log(`  Passed:  ${totals.pass}`);
  console.log(`  Failed:  ${totals.fail}`);
  console.log(`  Time:    ${elapsed}s`);
  console.log('');

  if (totals.failures.length > 0) {
    console.log('  Failed files:');
    for (const f of totals.failures) {
      console.log(`    - ${f.file}`);
    }
    console.log('');
  }

  console.log('[runner] Stopping server and cleaning up...');
  try {
    await stopServer(ctx);
    console.log('[runner] Done.');
  } catch (err) {
    console.error('[runner] Cleanup error:', err.message);
  }

  console.log('');
  if (totals.fail > 0) {
    process.exit(1);
  } else {
    console.log(`  All tests passed.`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error('[runner] Unhandled error:', err);
  process.exit(1);
});
