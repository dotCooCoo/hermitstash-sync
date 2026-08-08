# Test suite

End-to-end tests for hermitstash-sync. Each `test-*.js` file runs against a real `HermitStash` server spawned as a child process — no mocks at the transport layer.

## Quick start

```sh
node tests/run-all.js
```

`run-all.js` boots one shared server, runs global-state mutators sequentially, then runs bundle-scoped suites in a parallel pool (`min(4, cpus)` workers).

## Requirements

| | |
|---|---|
| Node.js | ≥ 24.19.0 (same floor as the sync client) |
| `openssl` on PATH | for the per-run test-CA + cert generation |
| `docker` on PATH | only `test-docker-e2e.js` requires it; suite skips when absent |
| Sibling checkout of the server repo | required for any test that uses `startServer()` — see below |

### Server source location

The test runner spawns `node server.js` from the server repo. By default it looks for a sibling checkout at `../hermitstash/` (i.e. `dotCooCoo/hermitstash` cloned next to this repo). Override the path with:

```sh
HERMITSTASH_SERVER_DIR=/path/to/server node tests/run-all.js
```

Tests fail fast with an actionable error if the server source isn't found.

## Local-only files

The following stay gitignored even though the rest of `tests/` ships:

| File | Purpose |
|---|---|
| `tests/.env` | S3 + backup test credentials. Format: `KEY=value` per line, `#` comments, optional `"…"` or `'…'` quotes around values. Parsed (not sourced) by `loadDotEnv()` in `run-all.js` so arbitrary shell can't execute. |
| `tests/autoupdate-signing.key` | P-384 private key for the auto-update signature test. Generate once with `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out tests/autoupdate-signing.key`. `test-autoupdate.js` skips itself if missing. |
| `tests/certs/` | Per-run test CA + server cert + client cert generated at startup by `generateTestCerts()`. Excluded as defense-in-depth in case a stale run leaves keys on disk. |

### `tests/.env` example

```env
S3_TEST_BUCKET=my-test-bucket
S3_TEST_REGION=us-west-1
S3_TEST_ACCESS_KEY=AKIA...
S3_TEST_SECRET_KEY=...
S3_TEST_ENDPOINT=                       # optional, non-AWS providers
BACKUP_TEST_BUCKET=my-backup-bucket
```

S3-backed suites (`test-s3-storage.js`, `test-backup-restore-roundtrip.js`) self-skip when these aren't set.

## Runner options

| Env var | Effect |
|---|---|
| `HS_ONLY=test-a.js,test-b.js` | Run only the listed files, sequentially. Useful for debugging one suite in isolation. |
| `HS_PARALLEL=0` | Force fully-sequential execution across every file. Useful for bisecting order-dependent flakes. |
| `HS_CONCURRENCY=N` | Override the default `min(4, cpus)` parallel-pool size. |
| `HERMITSTASH_SERVER_DIR=/path` | Point at a non-default server checkout (see above). |

## Test classification

`SEQUENTIAL` in `run-all.js` lists files that mutate process-global server state — admin settings, the session table, user suspend/delete, or per-IP rate-limit windows shared across tests. Those run one at a time. Everything else runs in the parallel pool.

When adding a new test file that touches any of those globals, add it to `SEQUENTIAL`.

## Codebase patterns

`tests/test-codebase-patterns.js` is a thin shim that re-exports `scripts/test-codebase-patterns.js` — the canonical suite. Edit the `scripts/` copy. The shim exists so `run-all.js` auto-discovery still picks it up.
