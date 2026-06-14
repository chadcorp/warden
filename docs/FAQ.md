# FAQ

Honest answers. Where the truthful answer is "not yet," it says so.

---

### Is this safe?

Safer — not "safe." Warden gives you a **signal, not a guarantee.** It will not
claim "100% safe," ever, and you should distrust anything in this space that
does.

What it actually does: every curated skill is content-addressed and pinned to a
hash, Ed25519-signed by a curator key the node pins, scanned at intake against
the OWASP Agentic Skills threat classes, wrapped in a deny-by-default capability
manifest, assigned a trust score recomputed per version, and recorded in a public
append-only log. That is defense-in-depth. It meaningfully shrinks the attack
surface. It does not make a guarantee, and we will not pretend otherwise.

---

### Why not just use a "verified" badge?

Because **identity is not behavior.** A verified badge proves *who* published a
skill. It does not stop that same publisher's skill from turning malicious on its
*next version* — the rug-pull.

Warden closes that gap two ways. First, you connect to a **hash**, not a name: if
the bundle changes, the hash changes, and the node refuses to serve it (it
re-verifies even at call time, so a swap after startup is caught). Second, the
**trust score is recomputed per version** — re-publishing re-evaluates from
scratch, and a skill that behaved yesterday can score lower today. A static badge
structurally cannot do either of those things.

---

### Does my data leave my machine?

**No.** Warden runs as a **local MCP node on your own box** over stdio. Your agent
talks to it as a subprocess. There is no Warden cloud in the loop, no per-user
inference on our servers, no telemetry phoning home. "Nothing leaves your box" is
a literal architectural property, not a marketing line — the reference node is
pure standard library and you can read every line of it.

A hosted version may come later as a *convenience* for teams who want it. The
local node stays the default and stays free.

---

### Why Ed25519 in pure Python?

Two reasons, both deliberate:

1. **Zero dependencies.** The whole `warden/` package has no third-party
   packages. That is what lets the node run on any Python 3.8+ anywhere, be
   audited end to end, and honestly claim local-first. A pure-Python Ed25519
   (RFC 8032) keeps that promise intact instead of dragging in a crypto wheel.
2. **Interop-verified.** It is real Ed25519, not a toy — signatures it produces
   verify against standard implementations and vice versa. You are not trusting a
   bespoke scheme; you are trusting a standard, implemented transparently.

The trade-off is honest: pure-Python signing is slower than a C library. At
curation scale (signing a curated set, verifying a handful of skills at startup)
that is irrelevant, and the portability + auditability is worth far more.

---

### How is the trust score computed?

It is a number in `[0, 100]`, recomputed **per version**, from signed inputs
(see `warden/trust.py`). The factors:

- **Intake scan results** (after any curator waivers). Findings cost points by
  severity; an un-waived CRITICAL means rejection outright.
- **Least privilege.** A skill that declares zero capabilities can leak nothing
  and pays no privilege penalty; each capability dimension it asks for costs a
  little. A broad `trusted-exec` profile is capped at 70.
- **Version history.** Prior yanks or incidents drag the score down.
- **Accrued clean observation.** Runs and days with no incident raise a ceiling
  over time. A brand-new version is **provisional** — capped below 100 until it
  earns trust — which is why you will see badges like `PROVISIONAL A/99`.

Two properties matter. It is **time-aware**: new code is treated with suspicion
and trust is *earned*. And it is **reproducible**: the scorer never reads the
clock — the observation window and an `as_of` date are passed in — so anyone can
recompute the exact same number from the signed inputs. Run `py -m warden trust
<skill_id>` to see the full rationale line by line.

---

### What do the badges mean?

`[Warden A/100 ✓]` is grade A, score 100, verified. `[Warden PROVISIONAL C/79 ✓]`
is a provisional skill (a newer version still earning trust) graded C at 79.
Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. `[Warden REJECTED]` means it did
not pass intake and the node will not expose it. The badge rides along in every
tool description and in the provenance block, so the agent sees capability and
trust together.

---

### What are the curated skills today?

Five, across three packs:

| Skill | Badge |
| --- | --- |
| `research-brain/idea-scout` | `[Warden A/100 ✓]` |
| `research-brain/fact-gate` | `[Warden A/100 ✓]` |
| `build-brain/build-product` | `[Warden PROVISIONAL A/99 ✓]` |
| `build-brain/ship-gate` | `[Warden A/100 ✓]` |
| `compliance-brain/secret-sentinel` | `[Warden PROVISIONAL C/79 ✓]` |

`secret-sentinel` is a `C` on purpose: it is a security-review skill that must
*name* sensitive indicators, so it ships an honest, logged scanner waiver, and
the score reflects the cost of that exception. Honesty over a vanity `A`.

---

### What is "drift" and why do you care so much about it?

Drift is when **the bundle does something its manifest says it cannot** —
declared-vs-actual mismatch. A skill whose manifest says `network: "none"` but
whose text tells the agent to POST your data to a server is drifting. The scanner
catches this as a CRITICAL.

It matters because it is the whole thesis in one check: *verification of identity
is not verification of behavior.* A skill can be perfectly signed by a perfectly
real author and still lie about what it does. Drift detection is where Warden
reconciles the claim against the content.

---

### What is NOT built yet?

The **phase capabilities are now built as reference implementations** — local,
zero-dependency, verified by a 75/75 self-test. Sandboxed `kind:"code"` execution
(`run-code`), private encrypted memory (`memory`), signed knowledge packs
(`kpack`), safe auto-updates (`update`), scan reports (`scan-report`), org policy
(`policy`), the audit log (`audit-log`), multi-curator trust roots (`add-root`),
the Scan API (`serve-api`), and the trust-graded static index (`build-index`) all
run today. See [`PHASES.md`](PHASES.md).

What genuinely remains is **not code — it is the business rollout**:

- **Hosting.** The local node and the static site/registry are the product; a
  hosted node for teams who want convenience is the **Phase 4 business** step, run
  only when revenue justifies the infra.
- **Paid-tier productization.** The Pro / Team / Scan API *capabilities* exist;
  packaging them as products with billing does not.
- **SSO.** Named as a Team capability, it is an **integration point, not built** —
  it lands at productization.
- **Production-grade sandboxing.** The `kind:"code"` sandbox is defense-in-depth
  at the Python + process layer, **not a hard OS sandbox** (no seccomp /
  namespaces). For untrusted code in production, run it in a container / microVM /
  WASM and enforce the same policy there.

Productizing and hosting stay **gated** behind a cheap test — see
[`BUILD_PATH.md`](BUILD_PATH.md). Reference code existing is not the same as the
business being validated; we do not build infra (or charge) on a hope.

---

### How does sandboxed execution work — is it a real sandbox?

It is **defense-in-depth at the Python + process layer, not a hard OS sandbox** —
and we say so plainly. A `kind:"code"` skill runs in a separate subprocess through
a capability broker (`warden/sandbox.py`): the environment is scrubbed, `HOME` is
redirected to a throwaway dir, network / shell / filesystem access are guarded per
the manifest, and a timeout bounds it. Critically, the sandbox consults the **same
`policy.py` engine** the curator used at sign time, so allow/deny is written once
and identical at curation and run time. Run it with `py -m warden run-code <dir>
"{...}"`.

What it is **not**: there is no seccomp or namespace isolation — those are
Linux-only and out of scope for a pure-stdlib build. So for genuinely untrusted
code in production, run it inside a container / microVM / WASM and enforce the same
policy envelope there. The reference sandbox is real and meaningfully shrinks the
attack surface; it is not a claim of OS-level containment.

---

### Is my memory really private?

Yes. Memory is **local and encrypted at rest** — there is no shared pool, and
nothing leaves your box. Each agent has its own store
(`py -m warden memory remember|recall|list`), encrypted with
ChaCha20-Poly1305 (`warden/chacha.py`, RFC 8439). That cipher is pure Python and
**byte-identical to the `cryptography` library**, so it is real AEAD, not a toy.
One agent cannot read another's notes, and no Warden cloud sees any of it. (Honest
crypto caveat: like the Ed25519, it is interop-verified but not constant-time —
fine for local at-rest encryption.)

---

### What's the Scan API?

It is **Trust-as-a-Service** for the supply side — skill authors and marketplaces
who want to scan + sign + trust-score their own skills without running the whole
node. `py -m warden serve-api` stands up a standard-library HTTP service
(`warden/api.py`) exposing scan / verify endpoints, with a **token-gated `/sign`**
so only an authorized caller can mint a signed trust record. It is built and runs
locally today; metering and hosting it as a paid B2B product is the business
rollout (Phase 3). The landing site stays static — the Scan API is a separate
Python service you run on a small VM/container behind HTTPS.

---

### Can I run my own — or multiple — curators?

Yes, both. The node anchors trust to **a key you control**: `py -m warden keygen`
generates your own curator keypair, and the node then exposes only skills *you*
signed (see also the curator-key FAQ below). To trust more than one curator,
`py -m warden add-root <pubkey_hex> <name>` adds another curator's public key to
your trust roots — the node will then also expose skills signed by that key. That
is the basis for **third-party curators**: trust is a set of keys you choose, not a
single brand.

---

### Can I enforce an org policy?

Yes. `py -m warden policy init` writes an example org policy you can edit, and
`py -m warden policy check` evaluates every registered skill against it —
**ALLOW / DENY** per skill (`warden/orgpolicy.py`). A policy can require a minimum
trust grade, allow or deny specific capabilities, and require particular sandbox
profiles, so an organization can refuse, say, anything that asks for network access
or anything below grade B. Paired with the tamper-evident audit log
(`py -m warden audit-log`), that is the governance Team buyers actually want.
Packaging this as the paid Team tier (with SSO) is the business step that remains.

---

### What if Anthropic adds signing to the official registry?

Then **signing becomes table stakes** — and we have said so from day one. It is
the risk we watch hardest. Our durable moat is *not* signing; it is **curation +
the behavioral trust score + local-first**, none of which a registry signing
feature gives you. A signature proves who; our per-version behavioral score
estimates how well-behaved and can fall on the next version. Signing being
commoditized would actually validate the category and let us compete on the parts
that are hard to copy.

---

### Do I have to pay?

**No. The core is free, forever, and never monetizes.** The local node, a sane
curated skill set, and the Trust Spec are open source — that is deliberately the
funnel, and it has to stay genuinely good and genuinely free.

Paid tiers sell things that are *not* the core — and while their **capabilities
are now built as reference implementations**, packaging them as products (billing,
hosting, gated on real demand) is still ahead: **Pro** (~$19/mo: premium packs,
safe auto-updates, host-your-own, scan-your-own), **Team** (~$29/seat: governed
private registry, org policy, audit log, SSO — SSO being the one integration point
not yet built), and a **Scan API** for skill authors and marketplaces. Devs pay
for trust, hosting, and saved time — never for the skills.

---

### Can I host my own skills behind the trust layer?

Yes — the capability is built. `py -m warden host <dir>` signs your own skill into
your instance marked `visibility=private`, so the node exposes it only to you (and
safe auto-updates re-verify it on every pull via `py -m warden update`). This is
the **Pro** tier feature, built as a reference implementation; what remains is
packaging it as a paid managed tier with billing — the business rollout, not the
code.

---

### Can I run my own curator key instead of trusting yours?

Yes. The node pins **a** curator public key — by default ours, but the key is
just a file you control (`keys/warden-curator.pub`). `py -m warden keygen`
generates your own keypair; sign your own skills with it; the node will then only
expose skills *you* signed. Trust is anchored to a key you choose, not to a brand
name. Rotating the key (`keygen --force`) invalidates every prior signature by
design — that is the point.

---

### Does Warden lock me into MCP?

Warden is **MCP-compatible, not MCP-locked.** Any MCP-speaking agent connects
with one config line, but the trust machinery (content-addressing, signing,
scanning, scoring, the transparency log) is independent of MCP's current shape.
If the standard churns, we ride it; we did not bet the moat on its present form.

---

### How do I contribute a skill?

Lay out `skills/<pack>/<name>/` with `SKILL.md`, `skill.manifest.json`, and
`tests/test.json`; declare a deny-by-default capability manifest; run
`py -m warden scan <dir>` until it is clean; then open a PR for a curator to scan
cold and sign. Full details, including the `scan_allow` waiver mechanism, are in
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Security issues go through
[`SECURITY.md`](../SECURITY.md), not public issues.
