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

- Cryptographic flaws (TLS misconfiguration, checksum bypass, PQC downgrade, etc.)
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

## What I can't offer

To set expectations honestly:

- No bug bounty. I can't pay for findings — this is a personal project with no budget. I can offer credit, gratitude, and a genuine attempt to fix what you find.
- No SLA. I'll do my best, but I can't guarantee response times.
- No guarantees about backwards compatibility while I'm fixing things. If a fix requires breaking changes, I'll make them.

## Thank you

Security research is real work, and reporting issues responsibly takes time and care. If you take the time to look at HermitStash Sync and tell me what you find, you have my genuine thanks — even if the finding turns out to be a false alarm or out of scope.
