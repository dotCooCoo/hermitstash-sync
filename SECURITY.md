# Security Policy

## A note up front

HermitStash Sync is a personal project maintained by one person in their spare time. It inherits its cryptographic posture from HermitStash and from Node.js's OpenSSL 3.5 — I'm not rolling my own TLS or inventing key exchanges. But a sync client introduces its own surface area (file watching, state tracking, daemon lifecycle), and those parts are entirely my own work. The code has not been professionally audited.

If you're evaluating HermitStash Sync for a use case where the consequences of a security flaw matter — legal, medical, financial, journalistic, or anything else where being wrong has real stakes — please factor this into your decision.

## Reporting a vulnerability

If you find a security issue, **please do not open a public GitHub issue**. Public disclosure before a fix is in place puts users at risk.

Instead, please email me directly:

**security@hermitstash.com**

### What to include

A useful report usually has:

- A clear description of the issue
- Steps to reproduce, or a proof of concept
- The version or commit hash you tested against
- Your assessment of the impact (what could an attacker actually do?)
- Any suggested fix, if you have one

Don't worry about formatting it perfectly. I'd rather get a rough report than no report.

## What to expect from me

I want to be honest about response times: this is a side project, and I can't promise the kind of turnaround a funded security team would offer. Realistically:

- **Acknowledgment:** within a few days, usually faster
- **Initial assessment:** within a week or two
- **Fix and disclosure:** depends on severity and complexity

For critical issues (anything that breaks the core security promises — confidentiality of synced files, integrity of data in transit, authentication bypass, TLS downgrade), I'll prioritize and try to ship a fix as quickly as I reasonably can. For lower-severity issues, it may take longer.

I'll keep you updated as I work on it, and I'll credit you in the fix commit and release notes unless you'd prefer to stay anonymous.

## Scope

Things I consider in scope:

- Cryptographic flaws (TLS misconfiguration, checksum bypass, PQC downgrade)
- Authentication and session bypass
- Authorization issues (accessing files or bundles you shouldn't)
- Data exposure (file contents, API keys, or paths leaking somewhere they shouldn't)
- Path traversal or symlink escape from the sync folder
- Daemon lifecycle issues (PID file races, signal handling flaws)
- Anything that contradicts a security claim made in the README

Things that are probably out of scope:

- Issues in dependencies that are already publicly known and have updates available — please open a normal issue for these
- Theoretical attacks that require capabilities beyond a realistic threat model
- Self-XSS or social engineering attacks against the user
- Anything that requires already-compromised admin credentials

For issues in the HermitStash server itself, please report to the [main repository](https://github.com/dotCooCoo/hermitstash).

If you're not sure whether something is in scope, just send it. I'd rather decide together than have you not report something that matters.

## Verifying release authenticity

Every release attaches the following per-binary verification artifacts:

| Artifact                   | What it is                                                                                  |
|----------------------------|---------------------------------------------------------------------------------------------|
| `<binary>.sha256`          | Conventional SHA-256 checksum (`sha256sum -c`).                                             |
| `<binary>.sha3-512`        | PQC-first SHA3-512 checksum — the same digest the auto-update verifier hashes against.      |
| `<binary>.sig`             | Raw P-384 ECDSA signature over the SHA3-512 digest (DER). Verified by the in-binary updater. |
| `<binary>.asc`             | Armored GPG detached signature (for `gpg --verify`).                                        |
| `<binary>.mldsa.sig`       | Raw ML-DSA-65 (FIPS 204) signature over the binary bytes. Optional, additive PQC sidecar.   |

Releases also attach a CycloneDX 1.6 SBOM (`*.cdx.json`), a Sigstore-keyless cosign bundle over it (`*.cdx.json.sigstore`), a SLSA L3 provenance attestation (`*.intoto.jsonl`), and — when `vex/statements.json` has entries — a CSAF 2.1 VEX document with matching cosign bundle.

### Post-quantum release key (ML-DSA-65)

The release-signing public key lives in-tree at `keys/release-pqc-pub.json`. Its SHA3-512 fingerprint is:

```text
cec87f784b3dfd6ee72ead8f0ee66d9d739035f8ea1374b7bd46637a4163d9c1b2940c4621e921852287af0ee8a9efbd23882c2fd5cdbc42bd12533c85116dbb
```

After `git clone`, compare the value above against `(Get-Content keys/release-pqc-pub.json | ConvertFrom-Json).fingerprint_sha3_512` (or the equivalent shell pipe). A mismatch means the file was tampered with between commit-time and your local checkout — refuse the working tree.

To verify a downloaded binary against the in-tree pubkey (Node 24+, zero external deps; works because blamejs is vendored):

```bash
node -e "
var b = require('./vendor/blamejs'), fs = require('node:fs');
var pub = JSON.parse(fs.readFileSync('keys/release-pqc-pub.json','utf8'));
var pubBytes = new Uint8Array(Buffer.from(pub.publicKey, 'base64url'));
var binary   = new Uint8Array(fs.readFileSync(process.argv[1]));
var sig      = new Uint8Array(fs.readFileSync(process.argv[1] + '.mldsa.sig'));
process.exit(b.pqcSoftware.ml_dsa_65.verify(sig, binary, pubBytes) ? 0 : 1);
" hermitstash-sync-vX.Y.Z-linux-x64
```

The ML-DSA-65 sidecar is independent of the in-binary P-384 ECDSA signature (`.sig`) that the daemon's auto-update path uses — the daemon stays on ECDSA so it can verify with `node:crypto` alone, and the ML-DSA-65 sidecar is there for operators who want a PQC-only verification posture.

### Rotation

Re-running `node scripts/generate-release-signing-key.js` rotates the key and rewrites `keys/release-pqc-pub.json`. Past releases remain verifiable against the historical pubkey via `git log keys/release-pqc-pub.json`; the fingerprint above always corresponds to whatever is currently committed. After a rotation, this file is updated in the same commit that lands the new pubkey.

## What I can't offer

To set expectations honestly:

- No bug bounty. I can't pay for findings — this is a personal project with no budget. I can offer credit, gratitude, and a genuine attempt to fix what you find.
- No service-level agreement. I'll do my best, but I can't guarantee response times.
- No guarantees about backwards compatibility while I'm fixing things. If a fix requires breaking changes, I'll make them.

## Thank you

Security research is real work, and reporting issues responsibly takes time and care. If you take the time to look at HermitStash Sync and tell me what you find, you have my genuine thanks — even if the finding turns out to be a false alarm or out of scope.
