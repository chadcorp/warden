# Contributing to Warden

Warden vouches for a **curated few**, not a directory of many. Contributions are
welcome — and held to that bar. A skill that ships here is content-addressed,
signed by a curator who stands behind it, scanned at the door, and recorded in a
public, append-only log. Nothing gets in silently.

Trust is **a signal, not a guarantee.** We never claim "100% safe," and neither
should any skill you submit.

If you have found a security issue in Warden itself (the scanner, the node, the
signing path), **do not open a public issue** — follow responsible disclosure in
[`SECURITY.md`](SECURITY.md).

---

## How to submit a skill

### 1. Lay out the bundle

Every skill lives at `skills/<pack>/<name>/` and ships exactly these files:

```
skills/<pack>/<name>/
├── SKILL.md               # the entrypoint — the instructions the agent follows
├── skill.manifest.json    # the capability manifest (deny-by-default) + metadata
└── tests/
    └── test.json          # behavioral test cases for the skill
```

`<pack>` is one of the curated packs (`research-brain`, `build-brain`,
`compliance-brain`) or a new pack you propose. `<name>` is lowercase kebab-case,
3–50 characters. A curator's signature (`skill.sig.json`) is added at sign time —
**you do not write it**, and you should not commit one.

> Browse `skills/research-brain/idea-scout/` for a clean, minimal reference
> bundle, and `skills/_samples/poisoned-weather/` for a deliberately malicious
> one that the scanner is supposed to reject.

### 2. Write the manifest (deny-by-default)

`skill.manifest.json` **declares exactly what the skill may touch.** Anything not
declared is denied at run time — "no network" means it cannot phone home, full
stop. A clean, minimal manifest is itself a trust signal: a skill that asks for
nothing can leak nothing, and scores higher for it.

A minimal instruction skill (the common case) declares zero capabilities:

```json
{
  "warden_manifest_version": "1.0",
  "name": "your-skill",
  "pack": "research-brain",
  "version": "1.0.0",
  "title": "Your Skill",
  "summary": "One sentence on what it does.",
  "description": "A fuller paragraph for the catalog.",
  "author": "Your Name",
  "license": "Apache-2.0",
  "kind": "instructions",
  "entrypoint": "SKILL.md",
  "sandbox_profile": "isolated-no-net",
  "capabilities": {
    "network": "none",
    "filesystem_read": [],
    "filesystem_write": [],
    "shell": false,
    "subprocess": false,
    "secrets": false
  },
  "tests": ["tests/test.json"],
  "tags": ["research", "ideation"]
}
```

Required fields (all validated by `warden/manifest.py`): `warden_manifest_version`
(`"1.0"`), `name`, `pack`, `version` (semver `MAJOR.MINOR.PATCH`), `title`,
`summary`, `author`, `license`, `kind` (`instructions` or `code`), `entrypoint`,
`sandbox_profile`, and `capabilities`.

**Capability grammar:**

- `network` — `"none"`, or a list of host globs (e.g. `["api.example.com"]`).
- `filesystem_read` / `filesystem_write` — lists of path globs.
- `shell`, `subprocess`, `secrets` — booleans.

**Sandbox profiles** (the manifest's declared caps must fit the profile, or the
node refuses to expose the skill):

| Profile | Allows | Use for |
| --- | --- | --- |
| `isolated-no-net` | nothing (no net, fs, shell, secrets) | instruction skills — the default |
| `net-allowlist` | network restricted to an explicit allowlist | skills that must call a named API |
| `fs-scoped` | filesystem restricted to explicit path globs | skills that read/write declared paths |
| `trusted-exec` | broad capability | discouraged — **trust score is capped at 70** |

> Capability sandboxing for **code** skills (`kind: "code"`) runs in Phase 1. In
> the Phase 0 reference node, skills are served as verified instructions; the
> node does not execute skill code. The same policy engine (`warden/policy.py`)
> that gates exposure today is what the Phase 1 sandbox will consult, so your
> manifest is the real, enforced contract either way.

### 3. Write tests

`tests/test.json` declares behavioral cases — given an input, the skill output
must contain certain strings:

```json
{
  "skill": "research-brain/your-skill",
  "cases": [
    {
      "name": "does the core thing",
      "input": { "task": "a representative request" },
      "expect_contains": ["expected phrase", "another phrase"],
      "rationale": "why this case proves the skill works"
    }
  ]
}
```

Declaring tests earns a small trust bump and is expected of a curated skill.

### 4. Scan until clean

Run the intake scanner against your bundle and fix everything it finds:

```
py -m warden scan skills/<pack>/<name>
```

The scanner is aligned to the OWASP Agentic Skills threat classes and checks for:
**tool-poisoning** (hidden / injection instructions in skill text or schemas),
**unsafe-exec** (`curl | sh`, `Invoke-Expression`, `os.system`, …),
**ssrf-exfil** (cloud-metadata IP, raw-IP URLs, known exfil sinks),
**secret-exfil** (credential access correlated with network egress in the same
file), **obfuscation** (invisible / bidi / tag Unicode, long base64 / hex blobs),
and **drift** — the heart of the thesis: the bundle *does* something its manifest
says it *cannot*. A manifest that declares `network: "none"` next to a skill that
tells the agent to POST your data somewhere is caught here.

Verdicts: any un-waived **CRITICAL** ⇒ `reject` (a curator will not sign it); a
**HIGH** or **MEDIUM** ⇒ `flag` (a curator reviews it); otherwise `pass`. Aim for
a clean `pass`.

### 5. A curator signs it

You do not sign your own skill. A Warden curator, holding the private curator
seed, runs:

```
py -m warden sign skills/<pack>/<name>
```

This re-scans, computes the content-address (pins a SHA-256 hash), computes the
trust score, writes the Ed25519 signature, registers the skill, and appends an
entry to the public transparency log. From then on, agents connect to the
**hash**, not the name — which is what kills rug-pulls.

Open a pull request with your bundle (no signature file). A curator reviews,
scans cold, and signs on merge.

---

## The `scan_allow` curator-waiver mechanism

Sometimes a *legitimate* skill trips the scanner for a *good* reason. The classic
case: a **security-review skill must name attack indicators** — credential-file
paths, exfil-sink hostnames — as patterns to *recognize*, not to *use*. The
scanner sees those strings and flags drift.

Warden does not handle this by weakening the scanner. It handles it with an
**accountable, signed, logged exception.** The manifest may carry a `scan_allow`
block:

```json
"scan_allow": [
  {
    "class": "drift",
    "reason": "This is a security-review skill; its instructions intentionally enumerate sensitive credential-file indicators as patterns to RECOGNIZE. It declares and uses no capabilities itself; the references are documentation, not behavior. Curator-acknowledged.",
    "scope": "SKILL.md"
  }
]
```

What a waiver does and does not do:

- It **downgrades** matching findings of that class from their severity to
  `ACK` (acknowledged) — they stay **visible**, never silent, and never
  auto-reject.
- It requires a **written reason.** That reason is covered by the curator's
  signature and recorded in the public transparency log. An exception nobody can
  see is not allowed.
- **It costs trust score.** Waived findings carry a penalty in
  `warden/trust.py` — exceptions are not free. A skill leaning on waivers will
  carry a lower grade, and that grade is visible to every agent.

See `skills/compliance-brain/secret-sentinel/skill.manifest.json` for a real,
justified waiver. It is also why that skill ships as `PROVISIONAL C/79` rather
than an `A` — the waiver is honest, and the score reflects it.

A waiver is the *only* sanctioned way past a finding. Do not obfuscate, do not
restructure to dodge a detector, and do not ask a curator to relax the scanner.
Name it, justify it, and let it cost what it costs.

---

## Code style

The `warden/` package is **pure Python standard library — zero third-party
dependencies.** This is a hard rule, not a preference. It is what lets the node
run anywhere, be audited end to end, and honestly claim "nothing leaves your
box."

- No `pip install` anything into `warden/`. If you reach for a dependency, that is
  a design discussion first, not a PR.
- Target Python 3.8+.
- The canonical JSON Schemas in `schema/` (`skill-manifest`, `signature`,
  `transparency-log-entry`, `trust-score`) are the contract for editors and CI.
  If you change a manifest or signature shape, keep the schema and the
  hand-rolled validator in `warden/manifest.py` in sync.
- Run the zero-dependency self-test before you push:

  ```
  py -m warden selftest
  ```

---

## Responsible disclosure

Found a way to slip a malicious skill past the scanner, forge a signature, or
break the node's verification? That is exactly the kind of thing we want to know
about privately first. **Do not file a public issue.** See
[`SECURITY.md`](SECURITY.md) for the disclosure process. Warden is "the trusted
brand," so a quiet report and a coordinated fix protect every user; a public
zero-day does not.
