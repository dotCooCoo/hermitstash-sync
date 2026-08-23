#!/usr/bin/env node
"use strict";

/**
 * GitHub Actions pin currency.
 *
 * Every `uses:` in this repository names an action by the full 40-character
 * commit SHA of one of its releases, with the version beside it as a comment.
 * The SHA is what makes the pin a pin: a tag can be moved to point at different
 * code, and these workflows build the SEA binary auto-update fetches and the
 * image operators pull, so a moved tag on any transitive action lands chosen
 * code on every user's machine carrying valid GPG and cosign signatures.
 *
 * The cost is the same one the base-image pins carry: a SHA does not pick up
 * upstream fixes on its own, and nothing else in the release path looks at it.
 * The vendored-dependency gate covers `vendor/`, base-currency covers `FROM`
 * lines, and neither says anything about actions. Before this existed the pins
 * here drifted five releases behind and were only found by reading them.
 *
 * Structure and approach follow the equivalent gate in blamejs, which is where
 * the useful details came from: resolving over plain https rather than shelling
 * out to `gh` so the check runs in CI unchanged, honouring GITHUB_TOKEN for the
 * authenticated rate limit, a --fix that rewrites the pins, and reporting what
 * was actually CHECKED rather than what was assumed.
 *
 * WHAT FAILS AND WHAT WARNS
 *
 * A pin behind its action's latest release FAILS. Unlike a base image an action
 * is not rebuilt continuously — a release is a deliberate upstream act, so
 * "behind" is a real statement rather than a proxy for someone else's build
 * schedule, and there is no Trivy step downstream to catch the consequence.
 *
 * Not reaching the GitHub API WARNS (exit 2), which scripts/release.js grades
 * as unverified rather than stale. Set HERMITSTASH_ACTIONS_CURRENCY_STRICT=1 to
 * make it a hard failure. What this will never do is report success it did not
 * establish: an unauthenticated run hits the 60/hour per-IP limit, every lookup
 * comes back 403, and "every action is current" would then be a claim about a
 * comparison that never happened.
 *
 * Anything meaning the check itself is broken fails: an unreadable workflow, or
 * finding no `uses:` at all, which means the scanner and the tree drifted apart.
 *
 * TWO PIN CLASSES
 *
 * Ordinary actions are SHA-pinned, and a tag or branch there is a failure.
 *
 * A reusable workflow (`owner/repo/.github/workflows/x.yml@ref`) must stay
 * TAG-pinned: the SLSA generator refuses to run from a SHA, which is why
 * release.yml pins it to a tag deliberately. For those the check is that the
 * tag is current, and a SHA is the failure. Collecting only SHA-shaped pins
 * would make this the one pin that can silently fall behind while the gate
 * reports green (blamejs/blamejs#621).
 *
 * GitHub's "latest release" marker is not always an action's newest version.
 * github/codeql-action publishes versioned releases (v4.37.8) and CodeQL bundle
 * releases (codeql-bundle-v2.26.3) from one repository, and the marker has sat
 * on a bundle tag older than the newest v4. Following it argues for pinning a
 * security-scanning action backwards and then reports the correct pin as stale.
 * A non-semver marker is therefore not trusted.
 *
 * Usage:
 *   node scripts/check-actions-currency.js           # report; exit 0/1/2
 *   node scripts/check-actions-currency.js --json    # structured output
 *   node scripts/check-actions-currency.js --warn    # print only, exit 0
 *   node scripts/check-actions-currency.js --fix     # rewrite stale pins
 */

var fs    = require("node:fs");
var path  = require("node:path");
var https = require("node:https");
var cp    = require("node:child_process");

var ROOT           = path.resolve(__dirname, "..");
var WORKFLOWS_DIR  = path.join(ROOT, ".github", "workflows");
var TIMEOUT_MS     = 10000;

var JSON_OUT  = process.argv.indexOf("--json") !== -1;
var WARN_ONLY = process.argv.indexOf("--warn") !== -1;
var DO_FIX    = process.argv.indexOf("--fix")  !== -1;
var STRICT    = process.env.HERMITSTASH_ACTIONS_CURRENCY_STRICT === "1";

// Per-action overrides, keyed by "owner/repo":
//   { type: "hold-major", major: N, reason } — flag stale only WITHIN that
//        major, so an intentional hold on an unadopted new major is not a
//        recurring argument with the gate.
//   { type: "skip", reason }                 — never flag.
var SPECIAL_MAP = {
  // (none — every pin here tracks upstream latest)
};

// ---- github -------------------------------------------------------------

// Resolved once. GITHUB_TOKEN is what Actions provides; GH_TOKEN is the common
// local name. Falling back to `gh auth token` matters more than it looks: an
// unauthenticated run gets 60 requests an hour per IP, which this check exhausts
// partway through, so without it a local `release.js prepare` almost always
// degrades to "currency UNKNOWN" and the gate stops being one. The gh CLI stays
// optional — its absence costs the fallback, not the check.
var _token;
function githubToken() {
  if (_token !== undefined) return _token;
  _token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
  if (!_token) {
    try {
      var out = cp.execFileSync("gh", ["auth", "token"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      var t = String(out).trim();
      if (t) _token = t;
    } catch (_e) { /* no gh, or not logged in — proceed unauthenticated */ }
  }
  return _token;
}

function githubGet(apiPath) {
  return new Promise(function (resolve, reject) {
    var headers = {
      "User-Agent": "hermitstash-sync-actions-currency/1",
      "Accept":     "application/vnd.github+json",
    };
    // Moves the budget from 60/hour per IP to 5000/hour.
    var token = githubToken();
    if (token) headers.Authorization = "Bearer " + token;

    var req = https.get("https://api.github.com" + apiPath,
      { timeout: TIMEOUT_MS, headers: headers }, function (res) {
        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () {
          if (res.statusCode !== 200) {
            return reject(new Error("github " + apiPath + " status " + res.statusCode));
          }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch (e) { reject(e); }
        });
      });
    req.on("timeout", function () {
      req.destroy(new Error("github " + apiPath + " timed out after " + TIMEOUT_MS + "ms"));
    });
    req.on("error", reject);
  });
}

// ---- semver -------------------------------------------------------------

// Accept a partial tag (v4 / v4.1) by treating the missing segments as 0.
// Returns [major, minor, patch] or null when the string does not start with a
// version at all, which is how a non-semver release marker is rejected.
//
// Walked rather than matched, for the reason given above parseUsesLine: the
// natural pattern here nests optional quantified groups and ESLint's
// security/detect-unsafe-regex refuses it, and a linear walk is the answer this
// project reaches for rather than a suppression.
function semverParse(v) {
  var s = String(v);
  // Lowercase "v" only. Accepting "V3.1.4" as well would be a wider reading
  // than the pattern this replaced, and a version parser that accepts more is
  // what lets a non-semver "latest" marker through the check above.
  if (s.charAt(0) === "v") s = s.slice(1);

  var parts = [0, 0, 0];
  var seg = 0;
  var sawDigit = false;

  for (var i = 0; i < s.length && seg < 3; i++) {
    var ch = s.charAt(i);
    if (ch >= "0" && ch <= "9") {
      parts[seg] = parts[seg] * 10 + (ch.charCodeAt(0) - 48);
      sawDigit = true;
    } else if (ch === "." && sawDigit) {
      seg++;
    } else {
      break;   // a prerelease suffix, a build tag, or a non-version string
    }
  }

  return sawDigit ? parts : null;
}

// True only for exactly `X.Y.Z` or `vX.Y.Z`, with nothing after it.
//
// semverParse deliberately reads a PREFIX, so it turns "v8.0.0-beta.1" into
// [8,0,0]. That is right for a version comment and wrong for deciding which
// upstream tag is latest, or whether a pinned ref is that tag: a prerelease
// would out-rank the current stable, and "@v2.1.0junk" would compare equal to
// v2.1.0 and pass. Both are the same fail-open, so selection and ref validation
// both use this rather than semverParse alone.
//
// Build metadata is refused too, rather than accepted-and-ignored. SemVer
// ignores it for precedence, so "v1.2.3+a" and "v1.2.3+b" are one version and
// two different git tags — accepting it lets a ref that does not resolve
// upstream read as current. No action pinned here tags that way, and one that
// did would be reported as uncheckable rather than silently approved.
function isStableSemverTag(name) {
  var s = String(name);
  if (s.charAt(0) === "v") s = s.slice(1);

  var dots = 0, digits = 0;
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (ch >= "0" && ch <= "9") { digits++; continue; }
    if (ch === "." && digits > 0 && dots < 2) { dots++; digits = 0; continue; }
    return false;               // a "-prerelease", "+build", or trailing text
  }
  return dots === 2 && digits > 0;
}

function semverCompare(a, b) {
  // Refuse a null rather than treating it as equal. Returning 0 for "could not
  // parse" is how a pin that is not a version at all — `@main`, a branch, a
  // typo — reads as up to date: the comparison says "not behind" and the check
  // records no problem. A currency gate failing open is the one outcome worth
  // throwing over.
  if (!a || !b) {
    throw new Error("semverCompare: unparseable version (" +
      JSON.stringify(a) + ", " + JSON.stringify(b) + ")");
  }
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

// ---- workflow parsing ---------------------------------------------------

var SHA40_RE = /^[0-9a-f]{40}$/i;

function isReusableWorkflow(fullPath) {
  return /\/\.github\/workflows\/[^/]+\.ya?ml$/.test(fullPath);
}

// Parse one line into { pathPart, ref, comment }, or null if it is not a pin.
//
// Deliberately no regular expression over the line. The obvious pattern for
// this puts a lazy group in front of a trailing anchor, which is the
// polynomial-backtracking shape the release gates exist to keep out of the
// tree, and it is the shape ESLint's security/detect-unsafe-regex flags.
// Walking the string is linear and makes the quoted form easier to see.
function parseUsesLine(line) {
  var s = line.trim();
  if (s.charAt(0) === "-") s = s.slice(1).trim();     // a YAML list item
  if (s.slice(0, 5) !== "uses:") return null;

  var rest = s.slice(5).trim();
  if (!rest) return null;

  var value, comment = "";
  var q = rest.charAt(0);
  if (q === '"' || q === "'") {
    // Quoted: find the closing quote first, so a "#" inside the value is not
    // mistaken for the start of a comment.
    var close = rest.indexOf(q, 1);
    if (close === -1) return null;
    value = rest.slice(1, close);
    var after = rest.slice(close + 1);
    var h = after.indexOf("#");
    if (h !== -1) comment = after.slice(h + 1).trim();
  } else {
    var h2 = rest.indexOf("#");
    if (h2 === -1) {
      value = rest;
    } else {
      value = rest.slice(0, h2).trim();
      comment = rest.slice(h2 + 1).trim();
    }
  }

  // A ref never contains "@", so the LAST one separates it from the path.
  var at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) return null;
  return { pathPart: value.slice(0, at), ref: value.slice(at + 1), comment: comment };
}

// Returns [{ ownerRepo, fullPath, ref, comment, reusable, file, line }]
function collectPins() {
  var pins = [];
  if (!fs.existsSync(WORKFLOWS_DIR)) return pins;
  var files = fs.readdirSync(WORKFLOWS_DIR)
    .filter(function (f) { return /\.ya?ml$/.test(f); })
    .sort();

  files.forEach(function (f) {
    var lines = fs.readFileSync(path.join(WORKFLOWS_DIR, f), "utf8").split(/\r?\n/);
    lines.forEach(function (line, i) {
      var p = parseUsesLine(line);
      if (!p) return;
      // A local composite action and a container image are not pinned upstream.
      if (p.pathPart.indexOf("./") === 0 || p.pathPart.indexOf("docker://") === 0) return;
      var segs = p.pathPart.split("/");
      if (segs.length < 2) return;
      pins.push({
        ownerRepo: segs[0] + "/" + segs[1],
        fullPath:  p.pathPart,
        ref:       p.ref,
        comment:   p.comment,
        reusable:  isReusableWorkflow(p.pathPart),
        file:      ".github/workflows/" + f,
        line:      i + 1,
      });
    });
  });
  return pins;
}

// ---- latest-release resolution ------------------------------------------

async function resolveSha(ownerRepo, ref) {
  // The commits endpoint dereferences an annotated tag to its commit, which is
  // what a pin names.
  var c = await githubGet("/repos/" + ownerRepo + "/commits/" + encodeURIComponent(ref));
  if (!c || typeof c.sha !== "string") {
    throw new Error("could not resolve a sha for " + ownerRepo + "@" + ref);
  }
  return c.sha;
}

async function latestVersion(ownerRepo) {
  var tag = null;

  // The RELEASES LIST is authoritative, and the "latest" marker is not consulted
  // first. Two separate reasons, both of which produce a false green:
  //
  // A repository can publish two channels from one repo. github/codeql-action
  // ships versioned action releases (v4.37.8) alongside CodeQL bundle releases
  // (codeql-bundle-v2.26.3), and the marker has sat on a bundle tag older than
  // the newest v4 — following it argues for pinning a security-scanning action
  // backwards, then reports the correct pin as stale.
  //
  // And the marker is a maintainer's choice rather than a computed maximum:
  // GitHub allows designating an OLDER release as latest. Trusting it there
  // reports a pin current while a newer stable release exists, which is the one
  // thing this gate is for.
  //
  // Scanning the list and taking the greatest stable semver answers both.
  var best = null;
  try {
    var rels = await githubGet("/repos/" + ownerRepo + "/releases?per_page=100");
    if (Array.isArray(rels)) {
      rels.forEach(function (r) {
        if (!r || typeof r.tag_name !== "string") return;
        if (r.draft) return;                        // not published
        if (r.prerelease) return;                   // flagged, whatever it is named
        if (!isStableSemverTag(r.tag_name)) return;
        var p = semverParse(r.tag_name);
        if (p && (!best || semverCompare(p, best.parsed) > 0)) {
          best = { name: r.tag_name, parsed: p };
        }
      });
    }
  } catch (_e) { /* fall through */ }
  if (best) tag = best.name;

  // Only if the list gave nothing: a repository with a single release, or one
  // whose list request failed while this one succeeds.
  if (!tag) {
    try {
      var rel = await githubGet("/repos/" + ownerRepo + "/releases/latest");
      if (rel && typeof rel.tag_name === "string" && isStableSemverTag(rel.tag_name)) {
        tag = rel.tag_name;
      }
    } catch (_e) { /* fall through to the tag list */ }
  }

  // Last resort: an action that ships tags without GitHub Releases at all.
  if (!tag) {
    var tags = await githubGet("/repos/" + ownerRepo + "/tags?per_page=100");
    if (!Array.isArray(tags) || tags.length === 0) {
      throw new Error("no releases or tags for " + ownerRepo);
    }
    var bestTag = null;
    for (var i = 0; i < tags.length; i++) {
      if (!isStableSemverTag(tags[i].name)) continue;
      var tp = semverParse(tags[i].name);
      if (tp && (!bestTag || semverCompare(tp, bestTag.parsed) > 0)) {
        bestTag = { name: tags[i].name, parsed: tp };
      }
    }
    if (!bestTag) throw new Error("no stable semver tag for " + ownerRepo);
    tag = bestTag.name;
  }
  return { tag: tag, sha: await resolveSha(ownerRepo, tag) };
}

// Supply-chain review material for a bump: what actually changed between the
// pinned SHA and the new one, plus the release body. Printed before --fix
// applies anything, so a compromised release surfaces as an unexpected commit
// or author rather than being pinned sight-unseen.
async function bumpReview(ownerRepo, oldRef, newTag, newSha) {
  var out = {
    compareUrl: "https://github.com/" + ownerRepo + "/compare/" + oldRef + "..." + newSha,
    commits: [], files: [], body: "", error: null,
  };
  try {
    var cmp = await githubGet("/repos/" + ownerRepo + "/compare/" + oldRef + "..." + newSha);
    if (cmp && cmp.html_url) out.compareUrl = cmp.html_url;
    if (cmp && Array.isArray(cmp.commits)) {
      out.commits = cmp.commits.map(function (c) {
        var msg = ((c.commit && c.commit.message) || "").split("\n")[0];
        var who = (c.author && c.author.login)
          || (c.commit && c.commit.author && c.commit.author.name) || "?";
        return (c.sha || "").slice(0, 10) + "  " + who + "  " + msg;
      });
    }
    if (cmp && Array.isArray(cmp.files)) {
      out.files = cmp.files.map(function (f) {
        return { name: f.filename, status: f.status, add: f.additions, del: f.deletions };
      });
    }
  } catch (e) { out.error = (e && e.message) || String(e); }
  try {
    var rel = await githubGet("/repos/" + ownerRepo + "/releases/tags/" + encodeURIComponent(newTag));
    if (rel && typeof rel.body === "string") out.body = rel.body;
  } catch (_e) { /* an action may ship tags with no release body */ }
  return out;
}

// Human-readable output. Silent under --json so the only thing on stdout is the
// document: a trailing summary line after it makes the whole stream unparseable,
// which defeats the flag entirely.
var _write = process.stdout.write.bind(process.stdout);
function say(s) {
  if (!JSON_OUT) _write(s);
}

// ---- the check ----------------------------------------------------------

async function checkAction(ownerRepo, pins) {
  var special = SPECIAL_MAP[ownerRepo];
  if (special && special.type === "skip") {
    return { action: ownerRepo, status: "skipped", reason: special.reason, pins: pins };
  }

  var info;
  try {
    info = await latestVersion(ownerRepo);
  } catch (e) {
    return { action: ownerRepo, status: "api-error", error: (e && e.message) || String(e), pins: pins };
  }

  var latestParsed = semverParse(info.tag);
  var problems = [];

  pins.forEach(function (p) {
    if (p.reusable) {
      if (SHA40_RE.test(p.ref)) {
        problems.push({ pin: p, why: "reusable workflow is SHA-pinned, and it must carry a semver tag" });
      } else if (!isStableSemverTag(p.ref)) {
        // The STRICT predicate, not semverParse. semverParse reads a prefix, so
        // `@v2.1.0-rc.1` and `@v2.1.0junk` both truncate to [2,1,0] and compare
        // equal to a stable v2.1.0, reporting a prerelease or a typo as current.
        // This also rejects a branch (`@main`) and a moving major tag (`@v4`),
        // both of which can change under the pin without the ref changing.
        problems.push({ pin: p, why: "reusable workflow is pinned to `" + p.ref +
          "`, which is not a stable semver tag, so it cannot be checked for currency" });
      } else {
        // Equality, not "not behind". A ref AHEAD of the latest release does
        // not exist upstream — an accidental @v20.1.0 against a latest of
        // v2.1.0 — and GitHub fails the workflow at run time rather than here.
        // The SHA path below already demands an exact match; this is the same
        // rule for the pin style that cannot use one.
        var cmp = semverCompare(semverParse(p.ref), latestParsed);
        if (cmp < 0) {
          problems.push({ pin: p, why: "tag " + p.ref + " is behind latest " + info.tag });
        } else if (cmp > 0) {
          problems.push({ pin: p, why: "tag " + p.ref + " is ahead of the latest release " +
            info.tag + ", so it does not exist upstream" });
        }
      }
      return;
    }

    if (!SHA40_RE.test(p.ref)) {
      problems.push({ pin: p, why: "pinned to " + p.ref + ", which is not a commit SHA" });
      return;
    }

    if (p.ref.toLowerCase() !== info.sha.toLowerCase()) {
      problems.push({ pin: p, why: "SHA " + p.ref.slice(0, 12) + "... is not latest " + info.tag });
      return;
    }

    // The FIRST token of the comment is the version; anything after it is a
    // linter directive and none of this gate's business. A comment that does
    // not START with a version is a finding rather than a pass — the reason the
    // pin carries a comment at all is so a reader can see which release the SHA
    // is, and `# latest` or a bare directive does not tell them.
    if (!p.comment) {
      problems.push({ pin: p, why: "pinned correctly but carries no version comment" });
    } else {
      var firstTok = p.comment.split(/\s+/)[0];
      var commentVer = semverParse(firstTok);
      if (!commentVer) {
        problems.push({ pin: p, why: "comment `" + p.comment + "` does not begin with a version" });
      } else if (latestParsed && semverCompare(commentVer, latestParsed) !== 0) {
        problems.push({ pin: p, why: "comment `" + firstTok + "` does not name latest " + info.tag });
      }
    }
  });

  // An intentional hold on an older major is not an argument to have every run.
  if (special && special.type === "hold-major" && latestParsed && latestParsed[0] > special.major) {
    return { action: ownerRepo, status: "held", reason: special.reason, latest: info.tag, pins: pins };
  }

  return {
    action: ownerRepo,
    status: problems.length ? "stale" : "current",
    latest: info.tag,
    latestSha: info.sha,
    problems: problems,
    pins: pins,
  };
}

function applyFix(results) {
  var byFile = {};
  var rewritten = 0;

  results.filter(function (r) { return r.status === "stale" && r.latestSha; }).forEach(function (r) {
    var tag = /^v/.test(r.latest) ? r.latest : "v" + r.latest;
    r.problems.forEach(function (pr) {
      var p = pr.pin;
      var abs = path.join(ROOT, p.file);
      if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8").split(/\r?\n/);
      var lines = byFile[abs];
      var idx = p.line - 1;
      if (idx < 0 || idx >= lines.length) return;

      // Rebuild the line rather than pattern-replacing inside it: the pin's
      // exact position is already known, and a reusable workflow keeps a TAG
      // where an action takes the SHA. Rewriting a reusable pin to a SHA would
      // break the build this gate exists to keep working.
      // The ref is the EXACT tag upstream published. `tag` above adds a leading
      // "v" where one is missing, which is right for the comment a human reads
      // and wrong for a ref: an action whose releases are tagged "2.1.0" has no
      // "v2.1.0", so the normalised form would swap a stale pin for a broken one.
      var newRef = p.reusable ? r.latest : r.latestSha;
      var indent = lines[idx].slice(0, lines[idx].length - lines[idx].trimStart().length);
      var dash = lines[idx].trimStart().charAt(0) === "-" ? "- " : "";

      // Carry over anything in the comment that is not the version token. A
      // workflow-linter directive lives there (`# v7.0.0 # zizmor: ignore[...]`),
      // and a fix that rebuilds the line from the pin alone deletes it, turning
      // a routine bump into a lint failure nobody connects to this script.
      var extra = "";
      if (p.comment) {
        var c = p.comment.trim();
        var sp = c.search(/\s/);
        var firstTok = sp === -1 ? c : c.slice(0, sp);
        if (semverParse(firstTok)) extra = sp === -1 ? "" : c.slice(sp).trim();
        else extra = c;                       // no version token — keep it all
      }

      // One space before the "#", which is what every pin in this tree uses.
      var suffix;
      if (p.reusable) suffix = extra ? " # " + extra : "";
      else suffix = " # " + tag + (extra ? " " + extra : "");

      lines[idx] = indent + dash + "uses: " + p.fullPath + "@" + newRef + suffix;
      rewritten++;
    });
  });

  Object.keys(byFile).forEach(function (abs) {
    fs.writeFileSync(abs, byFile[abs].join("\n"));
  });
  return { rewritten: rewritten, files: Object.keys(byFile).length };
}

async function main() {
  var pins = collectPins();
  if (pins.length === 0) {
    say("[actions-currency] FAIL — no `uses:` found under .github/workflows/.\n");
    say("  Either this tree has no workflows or the scanner no longer matches them.\n");
    return 1;
  }

  var byAction = {};
  pins.forEach(function (p) { (byAction[p.ownerRepo] = byAction[p.ownerRepo] || []).push(p); });
  var names = Object.keys(byAction).sort();

  var results = [];
  // Sequential and polite: the action count is small, and serial requests stay
  // well inside the budget on a shared CI address.
  for (var i = 0; i < names.length; i++) {
    results.push(await checkAction(names[i], byAction[names[i]]));
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "api-error"; });

  if (JSON_OUT) {
    _write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    say("[actions-currency] " + names.length + " action(s) across " +
      pins.length + " pin site(s)\n");
    results.forEach(function (r) {
      var label = r.status === "current" ? "OK"
        : r.status === "stale"     ? "STALE"
        : r.status === "api-error" ? "ERR"
        : r.status === "held"      ? "held"
        : r.status === "skipped"   ? "skip"
        : r.status;
      var line = "  [" + label + "] " + r.action;
      if (r.latest) line += "  latest " + r.latest;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (api: " + r.error + ")";
      say(line + "\n");
      (r.problems || []).forEach(function (pr) {
        say("        " + pr.why + "\n");
        say("        at " + pr.pin.file + ":" + pr.pin.line + "\n");
        var pin = pr.pin.reusable
          ? pr.pin.fullPath + "@" + r.latest + "    (reusable workflow: tag, not SHA)"
          : pr.pin.fullPath + "@" + r.latestSha + "  # " + r.latest;
        say("        pin: " + pin + "\n");
      });
    });
  }

  if (DO_FIX) {
    for (var f = 0; f < stale.length; f++) {
      var r = stale[f];
      if (!r.latestSha) continue;
      var first = r.problems[0] && r.problems[0].pin;
      if (!first) continue;
      var review = await bumpReview(r.action, first.ref, r.latest, r.latestSha);
      say("\n=== " + r.action + " -> " + r.latest + " ===\n");
      say("  compare: " + review.compareUrl + "\n");
      if (review.commits.length) {
        say("  commits (" + review.commits.length + ") [sha  author  subject]:\n");
        review.commits.forEach(function (c) { say("    " + c + "\n"); });
      } else if (review.error) {
        say("  commits: (compare unavailable: " + review.error + ")\n");
      }
      if (review.files.length) {
        say("  changed files (" + review.files.length + "):\n");
        review.files.forEach(function (sf) {
          say("    [" + sf.status + " +" + sf.add + "/-" + sf.del + "] " + sf.name + "\n");
        });
      }
      if (review.body) {
        var bl = review.body.split("\n");
        say("  release notes for " + r.latest + ":\n");
        bl.slice(0, 40).forEach(function (l) { say("    " + l + "\n"); });
        if (bl.length > 40) {
          say("    ... (" + (bl.length - 40) + " more line(s) — see the compare URL)\n");
        }
      }
    }
    var applied = applyFix(results);
    say("\n[actions-currency] --fix rewrote " + applied.rewritten +
      " pin site(s) across " + applied.files + " workflow file(s).\n");
    say("  Read the commits and release notes above before committing, then " +
      "re-run without --fix to verify.\n");
    // Rewriting what could be resolved does not make the rest verified. An
    // action whose lookup failed was never compared, and returning 0 here would
    // tell a caller the tree is current when part of it was never checked —
    // the same false success the non-fix path refuses to report.
    if (errored.length > 0) {
      say("  " + errored.length + " action(s) could not be reached and were left " +
        "untouched; their currency is still UNKNOWN.\n");
      return STRICT ? 1 : 2;
    }
    return 0;
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length) {
      say("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored — exit 0 anyway\n");
    }
    return 0;
  }

  if (stale.length > 0) {
    say("\n[actions-currency] FAIL — " + stale.length + " action(s) behind latest.\n");
    say("  These workflows build the binary auto-update fetches and the image\n");
    say("  operators pull, so a stale pin here is the one that reaches a user.\n");
    say("  `--fix` rewrites them after printing what changed upstream.\n");
    return 1;
  }

  if (errored.length > 0) {
    // Say what was checked, not what was assumed. Unauthenticated runs hit the
    // 60/hour per-IP limit and every lookup returns 403; claiming currency then
    // describes a comparison that never ran.
    say("\n[actions-currency] " + (results.length - errored.length) + " of " +
      results.length + " action(s) match latest; " + errored.length +
      " could not be reached, so their currency is UNKNOWN.\n");
    say("  Set GITHUB_TOKEN for the authenticated rate limit.\n");
    return STRICT ? 1 : 2;
  }

  say("\n[actions-currency] OK — every pin matches its action's latest release\n");
  return 0;
}

main().then(function (code) { process.exit(code); }, function (err) {
  process.stderr.write("[actions-currency] crashed: " + ((err && err.stack) || err) + "\n");
  process.exit(1);
});
