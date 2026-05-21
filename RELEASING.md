# Releasing hermitstash-sync

This document is the procedure for cutting a release. It complements `SECURITY.md` (which covers what operators verify against a downloaded release) and `CHANGELOG.md` (the generated history of past releases).

Releases are automated end-to-end via GitHub Actions. The operator-side workflow is:

1. **Verify version match.** `VERSION` in `lib/constants.js` and `"version"` in `package.json` must match. The first matrix step of `.github/workflows/release.yml` is a tag-vs-VERSION gate and refuses to build if they diverge.

2. **Author the release notes.** Create `release-notes/vX.Y.Z.json` for the new release. The current minor line stays as per-patch files (one per release); historical minor lines collapse to a single `release-notes/vX.Y.x.json` via `node scripts/consolidate-release-notes.js --prune`, which is a maintainer-side step run between releases.

   The JSON shape is enforced by `scripts/generate-changelog-entry.js`. A minimal valid entry:

   ```jsonc
   {
     "version":  "0.8.24",
     "date":     "YYYY-MM-DD",
     "headline": "Short summary; capital-first; no trailing punctuation",
     "summary":  "Optional paragraph. Must end with sentence punctuation when present.",
     "sections": [
       {
         "heading": "Fixed",
         "items":   [
           { "title": "Short title", "body": "Body must be at least 16 chars and end with . ! or ?" }
         ]
       }
     ]
   }
   ```

   Section headings come from a fixed allowlist: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`, `Supply chain`, `Migration`. The generator sorts to a canonical order at render time, so authoring order does not matter.

3. **Regenerate the changelog.** Run `node scripts/generate-changelog-entry.js --rebuild` to rewrite `CHANGELOG.md` from the full `release-notes/` tree. The file is generated; do not hand-edit it.

4. **Run the local gates.** Two checks gate every commit on the release path:

   - `node scripts/check-changelog-extract.js` — refuses to pass if either (a) the current `VERSION`'s release-notes JSON is missing, or (b) `CHANGELOG.md` drifts from the JSON tree. The release workflow runs the same render step at tag time, so any mismatch surfaces locally rather than in CI.
   - `node --test scripts/test-codebase-patterns.js` — the codebase-patterns suite includes three operator-facing-doc detectors that interface with the changelog pipeline. See "Operator-facing doc gates" below.

5. **Update `README.md`** if anything user-visible changed — commands, requirements, attached artifacts, security claims.

6. **Commit and push to `main`.** Tag protection on `main` blocks force-push; `--force-with-lease` works only when no one else has pushed.

7. **Tag and push.** Tags are SSH-signed via the repo's `tag.gpgsign=true` config:

   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

8. **Wait for `release.yml` to complete** (typically 5–8 minutes), then `docker-publish.yml` (~3 minutes). Both URLs appear in the workflow run output and the GitHub Releases page.

## Semver convention (pre-1.0)

- **Patch bump** (`0.X.Y` → `0.X.(Y+1)`) for bugfixes, feature additions, and platform-floor raises that only break from-source installs (SEA users carry the embedded Node with them).
- **Minor bump** (`0.X` → `0.(X+1)`) when signalling a larger behavioural break.

## What `release.yml` produces

The matrix `build` job runs in parallel on four runners and emits, per platform:

- the SEA binary
- `.sha256` + `.sha3-512` content checksums
- `.asc` armored GPG detached signature on the binary, the SHA-256 sidecar, and the SHA3-512 sidecar (three `.asc` files per binary)
- `.sig` raw P-384 ECDSA signature over the SHA3-512 digest (DER), used by the daemon's in-binary auto-update path

The `prepare-release` job fans in all matrix artifacts and then emits:

- `hermitstash-sync-vX.Y.Z.cdx.json` — CycloneDX 1.6 SBOM
- `hermitstash-sync-vX.Y.Z.vex.json` — CSAF 2.1 VEX document (only when `vex/statements.json` has entries)
- `<binary>.mldsa.sig` per platform — ML-DSA-65 (FIPS 204) signature sidecar
- `*.cdx.json.sigstore` + `*.vex.json.sigstore` — Sigstore-keyless cosign sign-blob bundles

The `provenance` job calls `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0` (tag-pinned by SLSA constraint) and produces `hermitstash-sync-vX.Y.Z.intoto.jsonl` — the SLSA L3 provenance attestation covering every platform binary plus the SBOM and (when present) the VEX.

The `publish` job creates the GitHub release atomically with every artifact attached at creation time.

## Required GitHub Actions secrets

| Secret                       | Used by                                           | Effect if missing                                                                 |
|------------------------------|---------------------------------------------------|------------------------------------------------------------------------------------|
| `GPG_PRIVATE_KEY`            | GPG sign step (matrix build)                      | `.asc` files skipped; release ships unsigned by GPG.                              |
| `GPG_PASSPHRASE`             | GPG sign step                                     | Same as above.                                                                    |
| `AUTOUPDATE_SIGNING_KEY`     | ECDSA sign step (matrix build)                    | `.sig` skipped; daemon's auto-update refuses to upgrade until a valid `.sig` lands. |
| `RELEASE_PQC_SIGNING_KEY`    | `scripts/sign-release-artifact.js` (prepare job)  | `.mldsa.sig` skipped (logged as a `::warning::`); every other artifact still ships. |

`VIRUSTOTAL_API_KEY` is an optional repo variable consumed only by the local `scripts/release.sh` alternative.

## ML-DSA-65 release-signing key

The release-signing pubkey lives in-tree at `keys/release-pqc-pub.json`. Its SHA3-512 fingerprint is recorded in `SECURITY.md` for out-of-band verification — operators compare the in-tree value against the published fingerprint after `git clone` to detect tree tampering.

### Initial setup

```bash
node scripts/generate-release-signing-key.js
# Writes keys/release-pqc-pub.json; prints the secret key to stdout.
```

Push the printed secret as the `RELEASE_PQC_SIGNING_KEY` repository secret. Add the fingerprint (also printed) to `SECURITY.md`. Commit `keys/release-pqc-pub.json` together with the `SECURITY.md` update.

### Rotation

Re-running `node scripts/generate-release-signing-key.js` rotates the key: it overwrites `keys/release-pqc-pub.json` and emits a new secret. Update the `RELEASE_PQC_SIGNING_KEY` secret, refresh the fingerprint in `SECURITY.md`, and commit. Past releases remain verifiable against the historical pubkey via `git log keys/release-pqc-pub.json`; document the boundary version in `SECURITY.md` so operators following a single fingerprint know which range each pubkey covers.

The signer in `scripts/sign-release-artifact.js` self-verifies every signature against the in-tree pubkey before writing the `.sig` file, so a stale secret produces no output rather than an un-verifiable artifact.

## Release-checklist summary

```
1. Verify VERSION (lib/constants.js) matches package.json "version".
2. Author release-notes/vX.Y.Z.json.
3. node scripts/generate-changelog-entry.js --rebuild
4. node scripts/check-changelog-extract.js
5. node --test scripts/test-codebase-patterns.js
6. Update README.md if anything user-visible changed.
7. git commit && git push origin main
8. git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
9. Watch release.yml + docker-publish.yml; share both URLs.
```

## Local release alternative

`bash scripts/release.sh` runs the same build end-to-end locally and uploads to the GitHub release using `gh` CLI credentials. Loads API keys from `~/.hermitstash-sync/release.env`. The local path produces the same artifacts as the workflow except for the SLSA L3 attestation (which requires the workflow's OIDC token to sign via Sigstore-keyless) and the cosign bundles. Use the local path only as a backup when the workflow runner is unavailable.

## Operator-facing doc gates

`scripts/test-codebase-patterns.js` includes three detectors that scan the operator-facing doc set (`README.md`, `SECURITY.md`, `RELEASING.md`, `CHANGELOG.md`) for content that would either rot on the next release or signal a hygiene issue. The structured `release-notes/*.json` tree already runs through the validator's leak-vocabulary sweep at `--rebuild` / `--check` time; the gates below extend the same discipline to adjacent hand-written prose.

| Detector                  | Scope                                                 | What it refuses                                                                                                                                                              |
|---------------------------|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `docs-leak-vocab`         | README, SECURITY, RELEASING, CHANGELOG                | Internal-process numbering (phase / sweep / tier / batch / slice / pass + digit); AI-tooling vocab; conversation residue; tautological pass/green claims; references to the internal maintainer-config file.        |
| `current-version-stamp`   | README, SECURITY, RELEASING (CHANGELOG excluded)      | The current `VERSION` from `lib/constants.js` baked literally into doc prose. Use `vX.Y.Z` placeholder for command examples; historical-boundary references (`v0.6.13`) are exempt because they describe fixed past state. |
| `docs-secret-shape`       | README, SECURITY, RELEASING, CHANGELOG                | JWT compact serialisations (`eyJ…{20,}`) and Stripe live keys (`sk_live_…{20,}`) — fundamental secret shapes that CI gitleaks-style scans flag regardless of context.       |

All three gates accept an inline `allow:<class>` marker on the offending line when the prose is genuinely intentional (e.g. an `allow:current-version-stamp` marker on a `SECURITY.md` line pinning a fingerprint to the live release).

## What is not in scope here

- **Container image release.** `docker-publish.yml` chains off `release.yml` automatically; it pulls the just-published signed SEA, verifies SHA3-512 + ECDSA before copying it into the runtime stage, and pushes a cosign-signed multi-arch image to `ghcr.io/dotcoocoo/hermitstash-sync`. No separate operator step.
- **Authenticode signing for Windows.** Not pursued — Certum's USB-token model is operationally too heavy and SignPath Foundation requires community traction the project does not yet have. Windows binaries ship unsigned; SmartScreen warm-up over time is the acceptance path. Authenticity is established via the GPG `.asc` + SHA3-512 checksum pair.
- **CHANGELOG hand-edits.** `CHANGELOG.md` is generated from `release-notes/`. Edit the JSON; regenerate. The `--check` gate refuses commits that drift.
