'use strict';

// Auto-update verification key, isolated in its own node:-builtins-only module so the
// release verifier (`scripts/verify-release.js`) can require it from
// contexts where the full b.* surface (vendor/blamejs/) isn't present —
// the Dockerfile's verify stage, deploy/install.sh, deploy/update.sh. All
// three fetch only the files they need from the public release and run
// the signature check before letting the binary near anything else.
//
// P-384 ECDSA public key. The matching private key lives in:
//   - GitHub secret AUTOUPDATE_SIGNING_KEY (CI release workflow)
//   - ~/.hermitstash-sync/autoupdate-signing.key (local releases via
//     scripts/release.sh)
//
// Rotate by generating a new keypair, updating this constant + the
// secrets, then republishing — every consumer pulls the new pubkey via
// auto-update or fresh install. The constant is also re-exported from
// lib/constants.js for in-tree callers that already read it there
// (lib/updater.js).
const AUTOUPDATE_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPv6OpIP57gy2rXXUc99SSN6PeA1IEHgA
MhqhMR12ZsMsEYut9841eSWmzdmt4ZzrIqqJjmPqJOmmqJcubl7hblwguKcZtHAL
WT3boCQiZjVskjAa9eJsJPT7pSLpKGgH
-----END PUBLIC KEY-----
`;

module.exports = { AUTOUPDATE_PUBKEY_PEM };
