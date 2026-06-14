# Warden — the trusted skill brain for open agents

[![CI](https://github.com/chadcorp/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/chadcorp/warden/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Self-test: 75/75](https://img.shields.io/badge/self--test-75%2F75-brightgreen)

> Connect your open-source agent to one endpoint, and it gains a curated,
> cryptographically-signed, sandboxed set of skills — without poisoning it.

**Live → https://warden-8c4.pages.dev/** · browse the [trust-graded registry](https://warden-8c4.pages.dev/registry/) · [mirror](https://chadcorp.github.io/warden/)

The world has thousands of places to **find** agent skills and almost nowhere
trustworthy to **run** them. Warden is the run-trust layer: not a bigger
directory, a *vouched-for* one. It is OSS-native, local-first, and opinionated
about curation — and it treats trust as **a signal, not a guarantee.**

This repository is the **trust core (Phase 0)** — the Agent Skill Trust Spec, a
curated hardened skill-pack, and a working reference local node — plus the
**Phase 1–4 capabilities built as reference implementations** (sandboxed
execution, private encrypted memory, knowledge packs, governance, the Scan API).
Pure Python standard library — **zero third-party dependencies.** Nothing leaves
your box.

---

## The magic moment

One config line points any MCP-speaking agent at Warden. Within a minute it has
a curated skill set where **every** skill is visibly signed, sandboxed, and
trust-scored — capability and provenance in the same breath:

```
$ py examples/mcp_client_smoke.py

[warden] pinned curator key warden:cd015c720e6027fd
[warden] transparency log: 5 entries, root sha256:491104b0…, integrity OK
[warden] VERIFIED  build-brain/build-product        [Warden PROVISIONAL A/99 ✓]
[warden] VERIFIED  build-brain/ship-gate            [Warden A/100 ✓]
[warden] VERIFIED  compliance-brain/secret-sentinel [Warden PROVISIONAL C/79 ✓]
[warden] VERIFIED  research-brain/fact-gate         [Warden A/100 ✓]
[warden] VERIFIED  research-brain/idea-scout        [Warden A/100 ✓]
[warden] ready: 5 skill(s) exposed, 0 refused (deny-by-default)
```

…and when the agent calls a skill, it gets the skill **with its provenance**:

```
=== WARDEN PROVENANCE ==========================================
skill        : research-brain/idea-scout v1.0.0
trust        : [Warden A/100 ✓]  (a SIGNAL, not a guarantee)
pinned hash  : sha256:208b0208cd3c…
capabilities : no network, no filesystem, no shell, no secrets
sandbox      : isolated-no-net (deny-by-default; cannot act outside this envelope)
verified now : VERIFIED (11/11 checks)
================================================================
```

## Quickstart (≈60 seconds)

Requires Python 3.8+ (on Windows use the `py` launcher). No `pip install`.

```bash
# 1. generate your curator key (the root of trust; the private seed is gitignored)
py -m warden keygen

# 2. scan + sign + log + register every curated skill
py -m warden sign-all

# 3. cold-verify everything (re-derives the hash, checks the signature, re-scans,
#    recomputes the trust score, checks the transparency log)
py -m warden verify-all

# 4. see the curated set and the public log
py -m warden list
py -m warden audit

# 5. run the reference MCP node (stdio), or drive it with the demo client
py -m warden serve
py examples/mcp_client_smoke.py

# prove the scanner: a deliberately poisoned skill is REJECTED at the door
py -m warden scan skills/_samples/poisoned-weather

# everything verified in one shot
py -m warden selftest        # 75/75 (Phase 0–4)
```

### Wire it into your agent

Point any MCP client at the node. Claude Desktop style:

```json
{
  "mcpServers": {
    "warden": { "command": "py", "args": ["-m", "warden", "serve"],
                "cwd": "C:/path/to/WARDEN" }
  }
}
```

See [`examples/`](examples/) for the full config and a smoke client.

### Verify the live registry yourself

You don't have to trust us. Check the curator's signature on the public registry
from anywhere — this re-derives the canonical bytes and verifies the Ed25519
signature with Warden's own pure-Python verifier:

```python
import urllib.request, base64, json
from warden import ed25519
from warden.canonical import canonicalize

url = "https://warden-8c4.pages.dev/registry/index.json"
req = urllib.request.Request(url, headers={"User-Agent": "warden-verify/1.0"})  # any UA; some CDNs 403 the default
obj = json.load(urllib.request.urlopen(req, timeout=20))
data = obj["index"]
ok = ed25519.verify(bytes.fromhex(data["curator_key"]),
                    canonicalize(data), base64.b64decode(obj["signature"]))
print("VERIFIED" if ok else "TAMPERED", ed25519.fingerprint(bytes.fromhex(data["curator_key"])))
# -> VERIFIED warden:cd015c720e6027fd
```

Change one byte of the index and the signature fails. The
[GitHub mirror](https://chadcorp.github.io/warden/registry/index.json) serves the
identical signed bytes.

---

## Phases 1–4 (now built)

The phase capabilities are now built as **reference implementations** —
local-first, pure standard library, zero third-party dependencies, verified by a
**75/75** self-test. The full command surface (`py -m warden help`):

| Capability | Command |
|---|---|
| Run a `kind:"code"` skill in the sandbox | `py -m warden run-code <dir> "{...}"` |
| Private per-agent **encrypted** memory | `py -m warden memory remember\|recall\|list` |
| Safe auto-update (re-verify + re-score; refuses escalation) | `py -m warden update <id> <dir> [--apply]` |
| Shareable scan report | `py -m warden scan-report <dir> [--sign]` |
| Org allow/deny policy (ALLOW/DENY per skill) | `py -m warden policy show\|init\|check` |
| Tamper-evident audit log | `py -m warden audit-log [N]` |
| The Scan API (Trust-as-a-Service) | `py -m warden serve-api [--port N]` |
| Trust-graded signed static index → `site/registry/` | `py -m warden build-index [out]` |
| Signed read-only knowledge packs | `py -m warden kpack list\|sign\|verify` |
| Host your own skill (private) | `py -m warden host <dir>` |
| Trust another curator key | `py -m warden add-root <hex> <name>` |

What remains is the **business rollout**, not the code — see *Honest scope* below
and [`docs/PHASES.md`](docs/PHASES.md).

---

## The trust architecture (the moat)

Built to the OWASP Agentic Skills Top 10. Six pillars, all real in this repo:

| # | Pillar | Where |
|---|--------|-------|
| 1 | **Content-addressed + Ed25519-signed + pinned** — you connect to a *hash*, not a name. Kills rug-pulls. | `content_address.py`, `ed25519.py`, `sign.py` |
| 2 | **Intake scanning** — tool-poisoning, unsafe-exec, SSRF, secret-exfil, obfuscation, and **capability drift**. | `scanner.py` |
| 3 | **Capability manifest + deny-by-default** — a skill may touch only what it declares. | `manifest.py`, `policy.py` |
| 4 | **Sandboxed execution** — skills run in a declared profile, never the agent's process. | `policy.py` (profiles) |
| 5 | **Behavioral trust score** — per-version, time-aware; re-publishing re-evaluates. Not a static badge. | `trust.py` |
| 6 | **Public transparency log** — append-only, hash-linked, Merkle-rooted. Nothing changes silently. | `translog.py` |

The point the whole project turns on:

> **Verification of identity is not verification of behavior.** A "verified"
> badge can still turn malicious on its next update. So Warden pins the exact
> bytes, **re-scores every version**, scans for **drift** between what a skill
> *declares* and what it *does*, and writes every change to a public log.

```
 ┌───────────┐   ┌─────────────┐   ┌─────────────┐   ┌────────────┐
 │ Skills in │──▶│ Scan & sign │──▶│ Skill brain │──▶│ Your agent │
 │ any source│   │ OWASP + hash│   │  sandboxed  │   │ MCP, local │
 └───────────┘   └─────────────┘   └─────────────┘   └────────────┘
   untrusted        [trust ctrl]      [trust ctrl]      your side
   ····················· TRANSPARENCY LOG — every version auditable ··········
   [ pinned hash = no rug-pull ]   [ sandbox = contained ]   [ deny-by-default ]
```

## What's in here

```
WARDEN/
├── TRUST_SPEC.md          the standard (start here)
├── THREAT_MODEL.md        OWASP Agentic Skills Top 10 → mitigations
├── warden/                the reference node + pipeline (zero-dep stdlib)
├── skills/                curated hardened skill packs + registry + _samples
├── schema/                JSON Schemas (manifest, signature, trust, log entry)
├── keys/                  the pinned curator public key
├── examples/              one-config-line setup + magic-moment smoke client
├── docs/                  positioning, build path, FAQ
└── site/                  the landing + waitlist site (zero-dep static; deploy anywhere)
```

### Landing site

A zero-dependency static site (the launch + waitlist funnel) lives in
[`site/`](site/). Run it locally with `py -m http.server 4173 --directory site`
and open <http://localhost:4173>. Wire one endpoint (`WAITLIST_ENDPOINT` in
`site/app.js`) before deploying — details in [`site/README.md`](site/README.md).

## Honest scope

The Phase 0 curated skills are **instruction packs**: the node serves their
*verified* text plus a provenance block, and your agent's model follows them. The
**Phase 1–4 capabilities are now built as reference implementations** — local,
zero-dep, verified — so sandboxed `kind:"code"` execution, private encrypted
memory, knowledge packs, safe auto-updates, org policy, the audit log, and the
Scan API all run today (see the table above and [`docs/PHASES.md`](docs/PHASES.md)).

What remains is honest and named:

- **The business rollout** — hosting, the paid tiers (Pro / Team / Scan API as
  products), billing, **SSO** (an integration point, not built), and go-to-market.
  Reference code existing is not the same as the business being validated, so
  productizing/hosting stays **gated** behind a cheap test
  (see [`docs/BUILD_PATH.md`](docs/BUILD_PATH.md)).
- **Production-grade sandboxing** — the `kind:"code"` sandbox is defense-in-depth
  at the Python + process layer, **not a hard OS sandbox** (no seccomp /
  namespaces). For untrusted code in production, run it in a container / microVM /
  WASM and enforce the same policy there. The pure-Python Ed25519 and
  ChaCha20-Poly1305 are real and interop-verified but **not constant-time** (sign
  offline / HSM in production).

We would rather ship small and true than over-promise.

## How it makes money (without charging for the core)

The core is free forever — it is the funnel, and devs don't pay for cores. Revenue
comes from **governance** (teams), the **supply side** (a Scan API that vouches
for skill authors' and marketplaces' skills), and **hosting/convenience**. See
[`docs/BUILD_PATH.md`](docs/BUILD_PATH.md).

## Positioning in one breath

Not a directory (mcp.so, Glama, Smithery). Not a memory platform (Mem0, Zep,
Letta) — memory is a *supporting feature* here, never the headline. Not a hosted
identity-verification play (mcpskills.io, Apigene). Warden is **OSS-native +
local-first + behavioral-trust + opinionated curation.** Full comparison in
[`docs/POSITIONING.md`](docs/POSITIONING.md).

## Trust is a signal, not a guarantee

Read [`SECURITY.md`](SECURITY.md) before you rely on anything here. We never
claim "100% safe"; we claim *signed, scanned, contained, scored, and logged.*

## License

[Apache-2.0](LICENSE).
