# Build Path

How Warden ships, and how it makes money — both stated honestly. Phase 0 is built
and green. Phases 1–4 are now built as **reference implementations** — the
technical capability of each runs locally and is verified — while the **business
rollout** (hosting, paid tiers, billing, SSO, go-to-market) is the work that
remains and stays gated on real demand. Code existing is **not** the same as the
business being validated. We do not pour infra spend or productization effort
after an unvalidated wedge.

The one call we own throughout: **if Anthropic adds signing to the official MCP
registry, "signed" becomes table stakes.** So the durable moat is bet on
**curation + the behavioral trust score + local-first**, not signing alone. Eyes
open.

---

## Phases

### Phase 0 — Trust Spec + curated pack + reference node  ·  DONE / GREEN

What exists right now, in this repo:

- The **Agent Skill Trust Spec** — the signed / scanned / pinned / sandboxed
  standard, written to the OWASP Agentic Skills Top 10. The document that makes
  Warden the reference.
- The **curated hardened skill-pack scaffold** — the manifest format, the
  deny-by-default capability model, and five real curated skills across three
  packs (`research-brain`, `build-brain`, `compliance-brain`).
- The **reference local node** — a working MCP server over stdio
  (`py -m warden serve`) that verifies every skill cold at startup, exposes only
  the ones that pass, and serves each with its provenance. Plus the full tool
  surface: `keygen`, `scan`, `sign` / `sign-all`, `verify` / `verify-all`,
  `trust`, `list`, `audit`, `serve`, `selftest`, `version`.

Pure standard library, zero third-party dependencies, zero infrastructure, zero
PII. It builds authority and **doubles as the cheap test.**

> **Honest scope note.** In Phase 0 the curated skills are *instruction packs*.
> The node serves their **verified text + provenance**, and the agent's own model
> follows them. Phase 1 adds a sandbox that executes `kind:"code"` skills (now
> built — see below); the same policy engine (`warden/policy.py`) the curator
> consults is what the sandbox consults, so the allow/deny logic is written once
> and identical at curation time and run time.

### THE GATE — what must be true before the business rollout

The Phase 1–4 *capabilities* are now built as reference implementations
(local-first, zero-dep, verified). What stays gated is **productizing and hosting
them** — the paid tiers, billing, SSO, and any infrastructure. That gate clears
**only** if the cheap test passes, within **3 weeks** of launch:

- **150 GitHub stars**, **OR**
- **75 waitlist signups + 5 developers who actually connect an agent** to the
  node.

— *and* the three residual risks below are consciously accepted, not wished away.

If the gate does not clear, that is signal: the wedge is not pulling, and we do
not pour effort (or infra spend) into productizing — even though the code exists.

### Phase 1 — sandboxed execution + private memory + knowledge packs  ·  REFERENCE BUILT

The local node now executes `kind:"code"` skills in a capability-brokered sandbox
(scrubbed env, redirected HOME, network / shell / filesystem guards, timeout —
`warden/sandbox.py`, command `run-code`), plus private per-agent **encrypted**
memory (`warden/memory.py` over pure-Python ChaCha20-Poly1305, command `memory`)
and mountable signed **knowledge packs** (`warden/kpack.py`, command `kpack`).
This is where "instruction packs" becomes "contained execution." Open source.
*Hardening caveat:* the sandbox is defense-in-depth at the Python + process layer,
not a hard OS sandbox — see Production hardening in [`PHASES.md`](PHASES.md).

### Phase 2 — scan → sign → transparency pipeline + PRO  ·  REFERENCE BUILT

The Pro-tier capabilities are built: safe **auto-updates** that re-verify +
re-score and refuse privilege escalation (`warden/update.py`, command `update`),
shareable **scan reports** (`warden/report.py`, command `scan-report`), and
**private hosting** (command `host`). *Remaining (business rollout):* packaging
this as the paid **Pro** tier with billing.

### Phase 3 — TEAM + the Scan API  ·  REFERENCE BUILT

The Team-tier governance capabilities are built: org **allow/deny policy**
(`warden/orgpolicy.py`, command `policy`), a tamper-evident **audit log**
(`warden/audit.py`, command `audit-log`), and **multi-curator trust roots**
(command `add-root`). The **Scan API** — Trust-as-a-Service for skill authors and
marketplaces — is built as a stdlib HTTP service (`warden/api.py`, command
`serve-api`). *Remaining (business rollout):* hosting these as the paid **Team**
tier and the metered Scan API, plus **SSO** (an integration point, not built).

### Phase 4 — hosted convenience + ecosystem  ·  REFERENCE BUILT

The trust-graded **signed static index** is built (`warden/index_build.py`,
command `build-index` → `site/registry/`) along with Cloudflare Pages **deploy
prep** (`site/_headers`, `site/_redirects`, [`../DEPLOY_CLOUDFLARE.md`](../DEPLOY_CLOUDFLARE.md)).
*Remaining (business rollout):* a hosted node for teams who want convenience over
self-hosting, and onboarding third-party curators — only when revenue justifies
the infra.

---

## Monetization (open-core, honest)

The shape is a **services ramp, not viral consumer SaaS.** Devs pay for trust,
hosting, and saved time — **never for the skills, and never for the core.**

### OSS core — free, forever  ·  the funnel

The local node, a sane curated skill set, and the Trust Spec. **Devs will not pay
for this, and that is fine** — it is the top of the funnel and the credibility
engine. **The core never monetizes.** Stating that plainly is the point: the free
thing has to stay genuinely good and genuinely free for the rest to work.

### Pro — ~$19/mo

For the individual who wants more than the curated set:

- premium / expanded skill packs,
- safe auto-updates (re-verify + re-score on every pull),
- **host your own skills** behind the trust layer,
- scan-your-own.

### Team — ~$29/seat

For organizations, where **governance** is the thing they actually buy:

- governed **private registry**,
- org-wide **allow/deny policy**,
- **audit log**,
- **SSO**.

### Trust-as-a-Service / Scan API — B2B usage

The cleanest revenue: charge **skill authors and marketplaces** to scan + sign +
trust-score their skills. This is selling trust to the **supply side** — the side
with budget and reputational exposure — rather than nickel-and-diming the devs
who are our funnel.

---

## The three residual risks (named, not hidden)

A perfect plan is not one with no risk; it is one that knows its risk cold. Three
structural residuals, each met with a specific design choice.

### (a) Anthropic bakes signing into the official registry

Then **signing becomes table stakes.** Mitigation: the durable moat is **curation
+ the behavioral trust score + local-first**, none of which a signing feature
gives you. A signature proves *who*; our per-version behavioral score estimates
*how well-behaved* and can fall on the next version — the thing a static badge
structurally cannot do. We watch this one hardest.

### (b) Devs don't pay

Likely true for the core — and fine. Mitigation: **monetize the supply side**
(Scan API) **+ team governance + hosting**, never the core. Revenue comes from
authors/marketplaces who need vouching and from orgs who need governance, not
from individual builders.

### (c) Infrastructure unlike the usual ship-and-walk-away model

A trust service implies running things. Mitigation: **local-first keeps our infra
near-zero early.** The node runs on the dev's machine; we carry no per-user
inference cost and no PII. Hosted convenience comes only when revenue justifies
it, and the core stays small and OSS throughout.

Two further operational risks the plan tracks: **MCP / standard churn** (stay
MCP-*compatible*, not MCP-*locked* — ride the standard, don't bet the moat on its
current shape), and **liability as "the trusted brand"** (defense-in-depth +
sandbox-contains + transparency log + the "signal, not a guarantee" framing +
responsible disclosure from day one — see `SECURITY.md`).
