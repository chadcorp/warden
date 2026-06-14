# Warden — Phase 0 Build Report

**Date:** 2026-06-13 · **Version:** 0.1.0 · **Verdict:** ✅ Phase 0 GREEN / shippable

This is an independent, cold record of what was built and what was *verified*
(not merely intended). It follows the plan's Execution-Readiness Gate: Phase 0
is GREEN now; Phase 1+ stays GATED behind the cheap test.

## What was built (the plan's Phase 0, in full)

1. **The Agent Skill Trust Spec** ([`TRUST_SPEC.md`](TRUST_SPEC.md)) — the
   signed / scanned / pinned / sandboxed / behaviorally-scored / transparency-
   logged standard, written to the OWASP Agentic Skills Top 10, with conformance
   levels and exact algorithms. Backed by [`THREAT_MODEL.md`](THREAT_MODEL.md).
2. **The curated hardened skill-pack scaffold** ([`skills/`](skills/)) — manifest
   format, deny-by-default capability model, sandbox profiles, the signed
   `scan_allow` waiver mechanism, and **5 real curated skills** across 3 packs,
   each signed + tested, plus an intentionally-poisoned fixture.
3. **A reference local node** ([`warden/`](warden/)) — a working MCP server over
   stdio that verifies every skill cold and serves it with provenance. Pure
   Python standard library, **zero third-party runtime dependencies**, 2,742 LOC
   across 16 modules.

## Verification evidence (run cold, trusting no build claim)

| Check | Result |
|-------|--------|
| Self-test (`py -m warden selftest`) | **47/47 PASS** |
| Ed25519 is real RFC 8032 (interop vs `cryptography`) | pubkey + signature **byte-identical** |
| All curated skills cold-verify (`verify-all`) | **5/5 VERIFIED, 11/11 checks each** |
| Schema conformance (jsonschema vs `schema/*.json`) | **all manifests, signatures, log entries valid** |
| **Rug-pull catch** (live: tamper a signed skill) | pristine→VERIFIED, tampered→**FAILED**, restored→VERIFIED |
| Bad-signature / foreign-curator-key | **rejected** (in self-test) |
| Poisoned sample (`scan _samples/poisoned-weather`) | **verdict=reject** [CRITICAL:5, HIGH:6], rc=1 |
| Scanner precision (curated skills) | 4× clean `pass`, secret-sentinel `pass [ACK:1]` (waived) |
| Transparency log integrity + Merkle root | **OK**, deterministic root `sha256:491104b0…` |
| Magic-moment end-to-end (`examples/mcp_client_smoke.py`) | initialize→tools/list→call+provenance→audit, **clean** |
| CLI robustness when piped/redirected | hardened to UTF-8; **no crash** on the ✓ badge |
| Curator private seed | **gitignored** (`keys/curator.seed`) |

### The honest trust gradient (no vanity scores)

```
research-brain/idea-scout      A/100        research-brain/fact-gate   A/100
build-brain/ship-gate          A/100        build-brain/build-product  PROVISIONAL A/99
compliance-brain/secret-sentinel  PROVISIONAL C/79  ← security skill with a signed, logged waiver
```

`build-product` is A/99 *provisional* (still accruing the clean-observation
window). `secret-sentinel` is C/79 because it must *name* attack indicators and
ships an honest `scan_allow` waiver that visibly costs trust. These are the
behavioral score working as designed — not bugs.

## Bugs found and fixed during the build (cold-caught)

- **Windows console encoding (cp1252) crash on the `✓` badge** when CLI output is
  piped or written to a non-UTF-8 sink. Fixed: UTF-8 hardening at every entry
  point + an encoding-proof `_logline`. Re-verified piped (`selftest 47/47`,
  `list`, `trust`, `audit` all clean through a pipe).
- **`py` launcher honored a `#!/usr/bin/env python` shebang** in the smoke
  client → resolved bare `python` (a broken Store alias) → "Python was not
  found." Fixed: removed the shebang; documented `py`-not-`python` everywhere.

## Honest scope & residuals (named, not hidden)

- **Instruction packs, not code execution.** The Phase 0 node serves *verified
  instructions + provenance*; the agent's model follows them. Sandboxed
  execution of `kind:"code"` skills is **Phase 1** — the same `policy.py` engine
  is what that sandbox will consult.
- **The scanner is heuristic**, tuned for precision on the auto-reject path.
  Softer risks are *flagged for a curator*, not auto-blocked. A novel zero-day
  pattern can still pass a static scan — mitigated, not eliminated, by
  deny-by-default + the provisional cap.
- **Pure-Python Ed25519 is not constant-time.** Production curators should sign
  offline with an HSM/hardware key.
- **The plan's market statistics** (Snyk ToxicSkills, ClawHavoc, OWASP Agentic
  Skills Top 10, the 8k-server scan, registry/memory-vendor figures) are dated
  after this build's knowledge cutoff and are **attributed to their sources, not
  asserted** as independently verified. Warden's engineering value does not
  depend on any specific number.
- **The three structural residuals** (Anthropic commoditizes signing; devs don't
  pay; infra-vs-our-model) are carried forward consciously — see
  [`docs/BUILD_PATH.md`](docs/BUILD_PATH.md).

## Execution-readiness gate

- **GREEN now:** Phase 0 (this repo). Pure artifact/content — zero infra, zero
  PII, and it *is* the cheap test.
- **GATED:** Phase 1+ unlocks only on the cheap-test pass (150 GitHub stars OR
  75 waitlist signups + 5 devs who connect an agent, within 3 weeks) **and**
  conscious acceptance of the three residuals.

## Update — Phases 1–4 built as reference implementations (v0.2.0)

The phase capabilities were subsequently built locally and verified (the owner
chose to build the technical capability ahead of the original launch gate). All
remain pure standard library, zero third-party runtime dependencies.

| Phase | Capability | Module(s) | Verified |
|-------|-----------|-----------|----------|
| 1 | Sandboxed execution of `kind:"code"` skills | `sandbox.py`, `_sandbox_runner.py` | runs word-count; **blocks network / shell / secret-env / out-of-sandbox fs** |
| 1 | Private encrypted memory | `memory.py`, `chacha.py` | ChaCha20-Poly1305 **matches RFC 8439 + byte-identical to `cryptography`**; encrypted at rest; wrong-key rejected |
| 1 | Signed knowledge packs | `kpack.py` | sign/verify, tamper-caught, path-traversal blocked |
| 2 | Safe auto-update gate | `update.py` | **refuses privilege escalation** on update; benign applies |
| 2 | Scan reports / private hosting | `report.py`, `host` | signed portable report; `visibility=private` |
| 3 | Org allow/deny policy | `orgpolicy.py` | denies sub-grade / provisional / forbidden-capability |
| 3 | Tamper-evident audit log | `audit.py` | hash-chained; detects tampering |
| 3 | Multi-curator trust roots | `repo.load_trust_roots`, `verify` | verifies any root; foreign key rejected |
| 3 | Scan API (Trust-as-a-Service) | `api.py` | live HTTP: scan/verify/transparency + token-gated `/sign` |
| 4 | Trust-graded signed static index | `index_build.py` | `site/registry/` HTML + **signed `index.json`** (verifies) |
| 4 | Cloudflare Pages deploy prep | `site/_headers`, `_redirects`, `DEPLOY_CLOUDFLARE.md` | static, deploy-ready |

**Verification:** self-test **75/75**; node integration exercises sandboxed code
execution, memory recall, and verified knowledge reads; `verify-all` 6/6 VERIFIED
11/11; transparency log 7 entries, integrity OK, deterministic root.

**Honest production caveats:** the code sandbox is defense-in-depth at the Python +
process layer, **not a hard OS sandbox** (use a container / microVM / WASM for
untrusted code); the pure-Python crypto is real and interop-verified but **not
constant-time**; **SSO is not built**. See [`docs/PHASES.md`](docs/PHASES.md).

## Suggested next steps (human-gated, not auto-run)

1. `git init` the `WARDEN/` folder and push as a public repo (the seed + private
   keys + `data/` are already gitignored).
2. Deploy `site/` to Cloudflare Pages for a free `*.pages.dev` URL — see
   [`DEPLOY_CLOUDFLARE.md`](DEPLOY_CLOUDFLARE.md). Wire the waitlist endpoint first.
3. Write the launch thread / one writeup per attack class (the content flywheel).
4. Treat hosting + paid tiers + production-grade sandboxing as the **business**
   rollout — gate it on real demand, not on the code merely existing.
