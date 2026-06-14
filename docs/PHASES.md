# Phases

Warden's roadmap, phase by phase, with the exact commands to drive each one.

**Phases 1–4 are now built as reference implementations** — local-first, pure
Python standard library, zero third-party runtime dependencies, all verified by a
73/73 self-test. This means the *technical capability* of every phase exists and
runs on your machine today. What remains is the **business rollout**: hosting, the
paid tiers (Pro / Team / Scan API as products), billing, SSO, and go-to-market.
The user consciously chose to build the technical capabilities ahead of the
original cheap-test launch gate. Reference code existing is **not** the same as
the business being validated — see [`BUILD_PATH.md`](BUILD_PATH.md).

Every command below is real. Run `py -m warden help` for the full surface. All
examples assume the repo root as the working directory; on Windows use the `py`
launcher.

---

## Phase 0 — Trust core (shipped)

**Delivers:** the Agent Skill Trust Spec, the curated hardened skill-pack, and a
working reference local MCP node that verifies every skill cold and serves it with
provenance. This is the trust foundation; everything else builds on it.

**Modules:** `ed25519.py`, `canonical.py`, `content_address.py`, `manifest.py`,
`policy.py`, `scanner.py`, `trust.py`, `translog.py`, `sign.py`, `verify.py`,
`node.py`, `cli.py`, `_selftest.py`.

**Commands:** `keygen`, `scan`, `sign` / `sign-all`, `verify` / `verify-all`,
`trust`, `list`, `audit`, `serve`, `selftest`, `version`.

```bash
py -m warden keygen          # generate the curator keypair (root of trust)
py -m warden sign-all        # scan + sign + log + register every curated skill
py -m warden verify-all      # cold-verify everything (hash, signature, scan, score, log)
py -m warden serve           # run the reference MCP node over stdio
py -m warden selftest        # the zero-dep self-test
```

Pure standard library, zero third-party dependencies, zero infrastructure, zero
PII. See [`../TRUST_SPEC.md`](../TRUST_SPEC.md) and
[`../BUILD_REPORT.md`](../BUILD_REPORT.md).

---

## Phase 1 — Sandboxed execution, private memory, knowledge packs

**Delivers** three reference capabilities that turn "instruction packs" into a
contained runtime with private state and mountable knowledge.

### (a) Sandboxed execution of `kind:"code"` skills

A code skill runs in a capability-brokered subprocess — scrubbed environment,
redirected `HOME`, network / shell / filesystem guards, and a timeout — never the
agent's own process. The same `policy.py` engine used at curation time is what the
sandbox consults at run time, so allow/deny is written once.

- **Modules:** `sandbox.py`, `_sandbox_runner.py`, `policy.py`.
- **Sample skill:** `skills/util-brain/word-count` (a real `kind:"code"` skill).
- **Command:** `run-code`

```bash
py -m warden run-code skills/util-brain/word-count "{\"text\": \"a b c d\"}"
# sandboxed run [OK]  output: {"words": 4, "chars": 7, "lines": 1, "avg_word_len": 1.0}
#   enforced: network=none, shell=False, env=scrubbed, profile=isolated-no-net
```

> **Hardening caveat.** This is defense-in-depth at the **Python + process layer,
> not a hard OS sandbox** (no seccomp / namespaces — those are Linux-only and out
> of scope for a pure-stdlib build). For untrusted code in production, run it in a
> container / microVM / WASM and enforce the same policy there.

### (b) Private per-agent encrypted memory

Each agent gets its own memory store, **encrypted at rest** with ChaCha20-Poly1305
(RFC 8439, pure Python, byte-identical to the `cryptography` library). There is no
shared memory pool — one agent cannot read another's notes.

- **Modules:** `memory.py`, `chacha.py`.
- **Command:** `memory remember|recall|list|stats`

```bash
py -m warden memory remember Ship the registry on Friday
py -m warden memory recall registry
py -m warden memory list      # (N entries, encrypted at rest)
```

### (c) Signed read-only knowledge packs

A knowledge pack is a signed, content-addressed, read-only bundle an agent can
mount — the same provenance discipline as skills, applied to reference material.

- **Module:** `kpack.py`.
- **Sample pack:** `knowledge/owasp-agentic-top10`.
- **Command:** `kpack list|sign|verify`

```bash
py -m warden kpack list
py -m warden kpack verify knowledge/owasp-agentic-top10
```

---

## Phase 2 — Safe auto-update, scan reports, private hosting

**Delivers** the Pro-tier *capabilities*: pulling a new skill version safely,
producing a shareable scan report, and signing your own skill privately.

### Safe auto-update gate

Evaluates a candidate version before it can replace an installed skill and
**refuses any privilege escalation or scan-reject** on update. On a clean update
it re-signs (re-verify + re-score on every pull). Apply with `--apply`.

- **Module:** `update.py`.
- **Command:** `update <skill_id> <candidate_dir> [--apply]`

```bash
py -m warden update research-brain/idea-scout ./candidate
# update research-brain/idea-scout: REFUSE
#   caps: no network  ->  network: any
#   capability escalation: a new version may not widen capabilities
```

### Scan reports

A shareable, optionally signed report of a skill's scan findings and trust
rationale — the artifact an author hands a reviewer.

- **Module:** `report.py`.
- **Command:** `scan-report <skill_dir> [--sign]`

```bash
py -m warden scan-report skills/research-brain/idea-scout --sign
```

### Private hosting

Sign your own skill into your instance, marked `visibility=private`, so the node
exposes it only to you.

- **Command:** `host <skill_dir>`

```bash
py -m warden host ./my-skill
# hosted (private) my-pack/my-skill  [Warden A/100 ✓]
```

---

## Phase 3 — Org policy, audit log, multi-curator trust, the Scan API

**Delivers** the Team-tier governance *capabilities* plus Trust-as-a-Service.

### Org allow/deny policy

A declarative org policy (minimum trust grade, capability allow/deny, required
profiles) the node enforces across the registry.

- **Module:** `orgpolicy.py`.
- **Command:** `policy show|init|check`

```bash
py -m warden policy init       # write an example org policy
py -m warden policy check      # ALLOW / DENY every registered skill against it
```

### Tamper-evident audit log

An append-only, hash-linked audit log of node events; `verify()` detects any
tampering.

- **Module:** `audit.py`.
- **Command:** `audit-log [N]`

```bash
py -m warden audit-log 25      # last 25 events; integrity OK / FAILED
```

### Multi-curator trust roots

Trust more than one curator key. The node will then also expose skills signed by
any added root — the basis for third-party curators.

- **Command:** `add-root <pubkey_hex> <name>`

```bash
py -m warden add-root 3af1...e9 partner-curator
```

### The Scan API (Trust-as-a-Service)

A stdlib HTTP service exposing scan / verify endpoints, with a token-gated `/sign`
— the supply-side product (skill authors and marketplaces scan + sign + score
their own skills).

- **Module:** `api.py`.
- **Command:** `serve-api [--port N] [--host H] [--sign]`

```bash
py -m warden serve-api --port 8799
# POST /scan   {skill...}      -> findings + verdict
# POST /sign   (token-gated)   -> signed trust record
```

> **Hardening caveat.** SSO is named as a Team capability in the plan but is an
> **integration point, not built** — it is wired in at productization, not in this
> reference build.

---

## Phase 4 — Trust-graded static index + Cloudflare deploy prep

**Delivers** a signed, trust-graded static index of the registry and the
deploy-prep to publish it.

### Signed static index

Generates `site/registry/` — a human-browsable `index.html` and a signed,
machine-verifiable `index.json` — from the live registry, trust grade included.

- **Module:** `index_build.py`.
- **Command:** `build-index [out]`

```bash
py -m warden build-index
# built trust-graded index -> .../site/registry  (N skills, M kpacks, signed=True)
```

### Cloudflare Pages deploy prep

`site/_headers` (CSP + hardening) and `site/_redirects` ship with the static
site; [`../DEPLOY_CLOUDFLARE.md`](../DEPLOY_CLOUDFLARE.md) is the runbook. The
landing site + registry are static and deploy with no build step; the Scan API is
a separate Python service hosted on a small VM/container behind HTTPS.

---

## Production hardening (the honest caveats, collected)

The reference implementations are real and verified, but a reference build is not
a production deployment. Three things must change before you trust untrusted code
or scale this up:

1. **Sandbox isolation level.** The `kind:"code"` sandbox is defense-in-depth at
   the **Python + process layer, not a hard OS sandbox.** There is no seccomp /
   namespace isolation — those are Linux-only and out of scope for a pure-stdlib
   build. For untrusted code in production, run it inside a container / microVM /
   WASM and enforce the same `policy.py` envelope there.
2. **Non-constant-time crypto.** The pure-Python Ed25519 and ChaCha20-Poly1305 are
   real and interop-verified (byte-identical to standard libraries), but they are
   **not constant-time.** Sign offline / with an HSM in production rather than
   exposing signing to untrusted timing.
3. **SSO is not built.** It is an integration point for the Team tier, wired in at
   productization, not in this reference build.

"Trust is a signal, not a guarantee" holds at every phase. Warden never claims
"100% safe."
