# Changelog

All notable changes to Warden are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.2.0] — Phases 1–4 (reference implementations)

The phase capabilities are now built as **reference implementations**:
local-first, pure Python standard library, zero third-party runtime dependencies,
all verified by a **73/73** self-test. The technical capability of every phase
runs on your machine today; what remains is the **business rollout** — hosting,
the paid tiers (Pro / Team / Scan API as products), billing, SSO, and
go-to-market. See [`docs/PHASES.md`](docs/PHASES.md) and
[`docs/BUILD_PATH.md`](docs/BUILD_PATH.md).

### Added — Phase 1 (sandboxed execution, private memory, knowledge packs)
- **Sandboxed execution of `kind:"code"` skills** — `warden/sandbox.py` +
  `warden/_sandbox_runner.py`: a capability broker (scrubbed env, redirected
  `HOME`, network / shell / filesystem guards, timeout) that runs a code skill in
  a subprocess, never the agent's process, consulting the same `policy.py` engine
  used at curation time. New command `run-code`. Sample skill
  `skills/util-brain/word-count`.
- **Private per-agent encrypted memory** — `warden/memory.py`, encrypted at rest
  with pure-Python ChaCha20-Poly1305 (`warden/chacha.py`, RFC 8439,
  byte-identical to the `cryptography` library). No shared pool. New command
  `memory remember|recall|list|stats`.
- **Signed read-only knowledge packs** — `warden/kpack.py`: signed,
  content-addressed, read-only reference bundles an agent can mount. New command
  `kpack list|sign|verify`. Sample pack `knowledge/owasp-agentic-top10`.

### Added — Phase 2 (safe auto-update, scan reports, private hosting)
- **Safe auto-update gate** — `warden/update.py`: evaluates a candidate version
  and **refuses privilege escalation or scan-reject** on update; re-verifies +
  re-scores on a clean pull. New command `update <id> <dir> [--apply]`.
- **Scan reports** — `warden/report.py`: a shareable, optionally signed report of
  scan findings + trust rationale. New command `scan-report <dir> [--sign]`.
- **Private hosting** — sign your own skill with `visibility=private`. New command
  `host <dir>`.

### Added — Phase 3 (org policy, audit log, multi-curator trust, Scan API)
- **Org allow/deny policy** — `warden/orgpolicy.py`: declarative minimum-grade /
  capability / profile governance the node enforces. New command
  `policy show|init|check`.
- **Tamper-evident audit log** — `warden/audit.py`: append-only, hash-linked node
  event log with integrity verification. New command `audit-log [N]`.
- **Multi-curator trust roots** — trust more than one curator key. New command
  `add-root <pubkey_hex> <name>`.
- **The Scan API (Trust-as-a-Service)** — `warden/api.py`: a stdlib HTTP service
  with scan / verify endpoints and a token-gated `/sign`. New command
  `serve-api [--port N] [--host H] [--sign]`.

### Added — Phase 4 (trust-graded static index + deploy prep)
- **Trust-graded signed static index** — `warden/index_build.py`: generates
  `site/registry/` (human-browsable `index.html` + signed `index.json`) from the
  live registry. New command `build-index [out]`.
- **Cloudflare Pages deploy prep** — `site/_headers`, `site/_redirects`, and
  [`DEPLOY_CLOUDFLARE.md`](DEPLOY_CLOUDFLARE.md).

### Production hardening (named, not hidden)
- The `kind:"code"` sandbox is **defense-in-depth at the Python + process layer,
  not a hard OS sandbox** (no seccomp / namespaces — Linux-only, out of scope for
  pure stdlib). Run untrusted code in a container / microVM / WASM in production
  and enforce the same policy there.
- Pure-Python Ed25519 and ChaCha20-Poly1305 are real and interop-verified but
  **not constant-time** — sign offline / with an HSM in production.
- **SSO is an integration point, not built** — it lands at productization.

### Still ahead (the business rollout, not code)
Hosting, the paid-tier products (Pro / Team / Scan API), billing, SSO, and
go-to-market. Reference code existing is not the same as the business being
validated. See [`docs/BUILD_PATH.md`](docs/BUILD_PATH.md).

## [0.1.0] — Phase 0 (reference release)

The Phase 0 artifact: the standard, the curated pack, and a working reference
node. Pure Python standard library; zero third-party dependencies.

### Added
- **The Agent Skill Trust Spec** (`TRUST_SPEC.md`) — the signed / scanned /
  pinned / sandboxed / behaviorally-scored / transparency-logged standard,
  written to the OWASP Agentic Skills Top 10.
- **Trust pipeline** (`warden/`):
  - `ed25519.py` — pure-Python Ed25519 (RFC 8032), interop-verified.
  - `canonical.py`, `content_address.py` — deterministic signing + content
    addressing (pin a hash, not a name).
  - `manifest.py`, `policy.py` — deny-by-default capability manifest + engine.
  - `scanner.py` — OWASP intake scanner (tool-poisoning, unsafe-exec,
    ssrf-exfil, secret-exfil, obfuscation, and **capability drift**) with a
    signed `scan_allow` waiver mechanism.
  - `trust.py` — per-version, time-aware behavioral trust score, reproducible
    from signed inputs.
  - `translog.py` — append-only, hash-linked, Merkle-rooted transparency log.
  - `sign.py` / `verify.py` — sign a bundle; cold-verify it (rug-pull catch).
  - `node.py` — the reference **local MCP node** over stdio (JSON-RPC).
  - `cli.py` — the `warden` command-line interface.
  - `_selftest.py` — 47-assertion zero-dep self-test.
- **Curated hardened skill-pack scaffold** (`skills/`): research-brain
  (idea-scout, fact-gate), build-brain (build-product, ship-gate),
  compliance-brain (secret-sentinel) — each with a capability manifest, tests,
  and a curator signature. Plus an intentionally-poisoned `_samples/` fixture
  the scanner rejects.
- **JSON Schemas** (`schema/`) for the manifest, signature, trust record, and
  transparency-log entry.
- **Examples**: a one-config-line MCP client config and an end-to-end stdio
  smoke client.

### Security posture
Trust is a **signal, not a guarantee**. See `SECURITY.md`.

### Not yet built (gated to later phases)
Sandboxed execution of *code* skills, the hosted registry, the public Scan API,
and team governance. See `docs/BUILD_PATH.md`.
