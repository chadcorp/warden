# Positioning

Warden is **the run-trust layer for agent skills.** The world has roughly twenty
thousand places to *find* agent skills and zero trustworthy places to *run*
them. We do not compete on directory size, on memory, or on enterprise identity
verification. We own **trust + curation**, locally, for open agents.

The one sentence: *connect your open-source agent to one endpoint, and it gains
a curated, cryptographically signed, sandboxed set of skills that make it better
— without poisoning it.*

Trust here is always **a signal, not a guarantee.** We never claim "100% safe."

---

## The buyer

**Open-source agent builders** — the local-LLM + MCP crowd, the people already
wiring Ollama and an MCP client together on their own box. They feel the
supply-chain fear directly and they value local-first. They are the launch
audience.

Later, two adjacent buyers:

- **Teams** who need *governance* — a private registry, an org allow/deny
  policy, an audit trail. Governance is what organizations actually pay for.
- **Skill authors and marketplaces** who need their skills *vouched for* — the
  supply side, which has both budget and reputational risk.

---

## Warden vs MCP registries (mcp.so, Glama, Smithery, MCP Market)

**They are directories. Warden is the run-trust layer.**

A registry answers "what skills exist?" Warden answers "which of these can I let
my agent run, and what exactly will it be allowed to touch?" According to the
landscape cited in the project plan (see *truefoundry.com/blog/best-mcp-registries*),
mcp.so lists on the order of ~20k servers and Glama 6k+. That is discovery, not
trust. Listing scales by adding rows; trust scales by *removing* the ones that
shouldn't run.

Warden deliberately vouches for a curated few rather than indexing the many.
Each curated skill is content-addressed (you connect to a **hash**, not a name),
Ed25519-signed by a pinned curator key, scanned at intake against the OWASP
Agentic Skills threat classes, wrapped in a deny-by-default capability manifest,
and carried in an append-only transparency log. A directory entry can be swapped
underneath you; a pinned hash cannot.

> We are complementary to registries, not a replacement. A registry can point
> at a Warden-vouched skill. Warden is the thing that makes "I found it" turn
> into "I can safely run it."

---

## Warden vs memory platforms (Mem0, Zep, Letta)

**Memory is a supporting feature here, never the headline.**

The agent-memory category is crowded and funded — per the vendor landscape cited
in the plan (*agentmarketcap.ai*, Apr 2026), Mem0, Zep/Graphiti, and Letta are
all well-capitalized and shipping. We do not try to out-Mem0 Mem0.

Warden's memory layer is scoped on purpose and exists only to serve the trust
thesis:

- **Private per-agent memory** — yours, local, encrypted, default.
- **Vetted knowledge packs** — read-only, signed, versioned reference memory an
  agent can mount, with no injection path.
- **Deliberately no shared-mutable / P2P memory pool.** A community memory pool
  is exactly the "bad seeds" surface a trust-first product must refuse, and it
  is also a commodity collision with the memory incumbents. Refusing it is both
  the safe stance and a differentiator.

If you want a sophisticated memory product, use one of theirs. If you want skills
your agent can trust, that is us.

---

## Warden vs trust incumbents (mcpskills.io, Apigene)

**OSS-native + local-first + behavioral-trust + opinionated curation vs.
hosted / enterprise / identity-verification.**

A pre-install trust layer is already circling this space. Per the plan's sources,
mcpskills.io is a hosted pre-install check and Apigene lists 251+ OWASP-scanned,
*vendor-verified* servers. These are valuable — and they are a different shape:
hosted services oriented toward enterprise procurement and **identity
verification** (proving *who* published a thing).

Warden's wedge is the gap those leave open:

1. **OSS-native.** The core is open source and free, forever. The reference node
   is pure Python standard library — zero third-party dependencies — so it runs
   anywhere and is auditable end to end.
2. **Local-first.** The node runs as a **local MCP node on your own machine**
   over stdio. Nothing leaves your box. Zero per-user inference cost to us, zero
   PII liability. A hosted version is a later convenience, not the product.
3. **Behavioral trust, not just identity.** The plan's core finding: *verification
   of identity is not verification of behavior.* A vendor-verified badge proves
   who shipped a skill; it does not stop that skill from turning malicious on its
   next version. Warden pins a hash and assigns a **trust score recomputed per
   version** — see below.
4. **Opinionated curation.** We say no. A curated few we stand behind beats a
   verified many we merely list.

---

## The durable moat

Be honest about what is and is not defensible.

**Signing alone is NOT the moat.** If Anthropic bakes signing into the official
MCP registry, "signed" becomes table stakes overnight. The plan names this as the
risk to watch hardest, and we accept it with eyes open. The moat is the three
things signing does not give you:

### 1. Curation

Taste and accountability. A human curator signs each skill with a key they
control and stands behind it. The transparency log makes every decision public
and permanent. This compounds with reputation and cannot be commoditized by a
registry feature.

### 2. The behavioral trust score

This is the part identity verification structurally cannot replicate. The score
lives in `warden/trust.py` and is a number in `[0, 100]` **recomputed per
version** from:

- intake scan results (after any curator waivers),
- least-privilege of the declared capabilities (a skill that asks for nothing can
  leak nothing),
- version history (prior yanks / incidents drag the score down),
- **accrued clean observation** — runs and days with no incident. A brand-new
  version is **provisional** and capped until it earns trust over time.

Two consequences fall out of this design:

- **A signed skill can still lose trust.** Re-publishing re-evaluates from
  scratch. A signature proves *who*; this score estimates *how well-behaved*, and
  it can fall on the next version. That is precisely the rug-pull a static badge
  misses.
- **It is reproducible.** The scorer never reads the clock — the observation
  window and an `as_of` date are inputs — so anyone can recompute the same number
  from the signed inputs. Trust you can audit, not trust you have to take on
  faith.

### 3. Local-first

Running on the dev's own machine is both a trust property ("nothing leaves your
box") and a business property (our infrastructure stays near-zero early). It is
hard for a hosted-first incumbent to copy without abandoning their model.

> Curation + behavioral score + local-first is the bet. Signing is the price of
> admission, not the edge.

---

## One-line summary

| Category | They do | Warden does |
| --- | --- | --- |
| MCP registries | List ~20k servers (discovery) | Vouch for a curated few (run-trust) |
| Memory platforms | Headline memory product | Memory as a scoped, safe feature |
| Trust incumbents | Hosted, enterprise, identity-verified | OSS-native, local-first, behavioral-trust, curated |

Capability and provenance in the same breath — on your machine.
