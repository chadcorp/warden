# The Agent Skill Trust Spec

**Version 1.0 (Phase 0 reference) · Status: Draft · License: Apache-2.0**

This document defines how an agent skill is made *trustworthy to run*: how it is
structured, scanned, content-addressed, signed, capability-bounded, behaviorally
scored, and recorded in a public log — and how a consumer verifies all of that
cold. It is written to the OWASP Agentic Skills Top 10 threat classes (see
[`THREAT_MODEL.md`](THREAT_MODEL.md)).

The `warden/` package in this repository is the **reference implementation** of
this spec. Where prose and code disagree, that is a bug; file it.

> **Trust is a signal, not a guarantee.** Nothing in this spec licenses the claim
> that a skill is "safe." It licenses the narrower, verifiable claims that the
> bytes are pinned, a named curator signed them, the skill was scanned, it cannot
> exceed its declared capabilities, and its trust reflects observed behavior over
> time. See §11.

## 0. Conformance language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as in RFC 2119/8174. An implementation that performs all the
§9 verification checks and refuses to expose a skill that fails any of them is
**conformant**.

## 1. Terminology

- **Skill bundle** — a directory containing a skill's entrypoint, its capability
  manifest, and optional tests/assets.
- **Curator** — the holder of an Ed25519 key who vouches for skills by signing
  them. The root of trust a consumer pins.
- **Consumer** — the node or agent that verifies and runs skills.
- **Content address / digest** — a `sha256:<hex>` string over exact bytes.
- **Capability** — a thing a skill may touch: network, filesystem, shell,
  subprocess, secrets. Deny-by-default.
- **Trust score** — a per-version, time-aware number in `[0,100]` (§7).

## 2. Skill bundle structure

A skill bundle is a directory:

```
<pack>/<name>/
├── SKILL.md              entrypoint (kind=instructions) — what the agent follows
├── skill.manifest.json   the capability manifest (§3)
├── tests/                optional declared tests
└── skill.sig.json        the signature record (§6) — written by the curator
```

- The directory name path `<pack>/<name>` MUST equal `pack`/`name` in the manifest.
- `skill.sig.json` MUST NOT exist before signing and MUST be excluded from the
  content digest (§4).
- A bundle MAY contain any additional files; all authored files are covered by
  the digest and scanned.

## 3. Capability manifest

`skill.manifest.json` declares the **only** things the skill may touch. Schema:
[`schema/skill-manifest.schema.json`](schema/skill-manifest.schema.json).

Required fields: `warden_manifest_version` (`"1.0"`), `name` (lowercase
kebab-case), `pack`, `version` (semver), `title`, `summary`, `author`,
`license`, `kind` (`"instructions"` | `"code"`), `entrypoint`, `sandbox_profile`,
and `capabilities`.

### 3.1 Capabilities (deny-by-default)

```json
"capabilities": {
  "network": "none",          // "none" OR an array of domain globs
  "filesystem_read":  [],     // array of path globs; [] = none
  "filesystem_write": [],
  "shell": false,
  "subprocess": false,
  "secrets": false
}
```

Anything not granted is **denied** at run time. `"network": "none"` means the
skill cannot make any outbound connection — it cannot phone home.

### 3.2 Sandbox profiles

`sandbox_profile` names the containment envelope. A manifest's capabilities
**MUST** fit inside its profile's envelope, or signing/verification fails.

| Profile | network | fs | shell | secrets | use |
|---------|:------:|:--:|:-----:|:-------:|-----|
| `isolated-no-net` | ✗ | ✗ | ✗ | ✗ | pure reasoning / instruction skills (default) |
| `net-allowlist` | allowlist | ✗ | ✗ | ✗ | skills that call named APIs |
| `fs-scoped` | ✗ | globs | ✗ | ✗ | skills that read/write named paths |
| `trusted-exec` | any | any | any | any | broad; **trust-capped at 70** (§7) |

### 3.3 Scanner waivers (`scan_allow`)

A curator MAY waive a scanner finding **class** by listing it in `scan_allow`
with a written `reason` (and optional `scope`). A waiver:

- downgrades matching findings to severity `ACK` (so they no longer auto-reject),
- is covered by the curator signature and recorded in the transparency log,
- and **costs trust score** (`ACK` findings are penalized, §7).

Waivers are accountable exceptions, never silent suppressions. They exist for
cases like a security-review skill that must *name* attack indicators.

## 4. Content addressing

A bundle's **digest** pins every authored byte:

1. For each file (excluding `skill.sig.json`, `__pycache__/`, `.git/`, `*.pyc`,
   OS junk), compute `sha256:` + hex SHA-256 of its bytes.
2. Build a map `{ posix_relative_path: "sha256:<hex>" }`, sorted by key.
3. The bundle digest is `"sha256:" + SHA256( canonical_json(map) )` (§A).

Changing one byte of any file changes the digest. A consumer pins the digest;
re-derivation that does not match is a rug-pull and **MUST** fail verification.

## 5. Intake scanning

Every bundle is scanned before it can be signed. The scanner returns findings,
each with a `class`, `severity`, `file`, `line`, and `message`.

### 5.1 Classes (OWASP-aligned)

`tool-poisoning` · `unsafe-exec` · `ssrf-exfil` · `secret-exfil` · `obfuscation`
· `drift`. The keystone is **`drift`**: the bundle does something its manifest
declares it cannot (e.g. `network:"none"` but contains a network-egress call).
Drift operationalizes "identity ≠ behavior."

### 5.2 Severities and verdict

Severities (ascending): `INFO` < `ACK` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`.

- A bundle's **verdict** is `reject` if any **un-waived** `CRITICAL` finding
  exists; else `flag` if any `HIGH`/`MEDIUM`; else `pass`.
- A curator **MUST NOT** sign a bundle whose verdict is `reject`.
- `flag` bundles MAY be signed after curator review; the findings lower trust.

Implementations **SHOULD** favor *precision on the auto-reject path*: only
unambiguous CRITICAL signatures auto-reject; softer risks are flagged for review.

## 6. Signing

Skills are signed with **Ed25519 (RFC 8032)**. The curator's 32-byte private seed
never leaves their machine; the 32-byte public key is pinned by consumers.

### 6.1 The signing payload

The signature is computed over `canonical_json(payload)` (§A) where `payload`
contains, at minimum:

```
warden_skill_signature_version "1.0"
skill, name, pack, version, title
bundle_digest                  (§4)
manifest_digest                "sha256:"+SHA256(canonical_json(manifest))
capabilities, sandbox_profile  (from the manifest)
scan        { verdict, counts, waivers }                 (§5)
trust       { score, grade, status, provisional, inputs_digest }   (§7)
trust_inputs{ history, observation, has_tests, as_of }   (§7 — enables recompute)
curator_key (hex), curator_fingerprint, signed_at
```

`trust_inputs` is included so a verifier can **recompute** the trust score from
the signed inputs rather than believe the number (§9).

### 6.2 The signature record

Written to `skill.sig.json`. Schema:
[`schema/signature.schema.json`](schema/signature.schema.json).

```json
{ "algo": "ed25519", "payload": { … }, "signature": "<base64 64-byte sig>" }
```

A consumer **MUST** reject a non-canonical signature S ≥ L (malleability guard),
which the reference verifier enforces.

## 7. Behavioral trust score

A per-version, time-aware number in `[0,100]` with a letter grade
(A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60). **Not** a static identity badge:
re-publishing recomputes it from scratch. Schema:
[`schema/trust-score.schema.json`](schema/trust-score.schema.json).

### 7.1 Algorithm (reference, exact)

- Any un-waived `CRITICAL` ⇒ `status:"rejected"`, score `0`. Not eligible to be
  exposed. Otherwise start at **100** and apply:
- **Scan penalties** (post-waiver), each capped: `HIGH` −25 (≤ −60),
  `MEDIUM` −8 (≤ −24), `LOW` −3 (≤ −9), `ACK` −4 (≤ −16).
- **Least privilege**: −3 per declared capability dimension beyond none (≤ −15).
  A bundle that declares *zero* capabilities pays nothing.
- **Profile**: `trusted-exec` caps the score at **70**.
- **History**: −20 per prior yank (≤ −40); −15 per prior incident (≤ −45).
- **Tests**: +3 if tests are declared.
- **Observed incidents** on this version: −30 each (≤ −60).
- **Provisional (time-aware) cap**:
  `cap = 75 + min(clean_runs,50)·0.3 + min(observed_days,60)·0.25`, clamped to
  100. If `cap < 100` the version is **provisional** and the score is capped at
  `cap`. Trust thus *rises as clean observation accrues* — a brand-new version
  starts at ≤ 75 no matter how clean its scan.
- Clamp to `[0,100]`, round to integer.

### 7.2 Reproducibility

The score is a pure function of its inputs; the reference implementation **MUST
NOT** read the clock inside it (the observation window and `as_of` are inputs).
`inputs_digest = content_address(inputs)` lets anyone confirm reproduction.

## 8. Transparency log

Append-only, hash-linked, Merkle-rooted. Every publish (and yank) is one entry.
Schema: [`schema/transparency-log-entry.schema.json`](schema/transparency-log-entry.schema.json).

- Each entry carries `seq`, `prev` (the previous entry's `entry_hash`, `null` at
  seq 0), and `entry_hash = "sha256:"+SHA256(canonical_json(entry∖{entry_hash}))`.
- **Merkle root** (RFC 6962-style domain separation): leaf =
  `SHA256(0x00 ‖ entry_hash_hex)`, node = `SHA256(0x01 ‖ left ‖ right)`,
  duplicate the last node when a level has odd length.
- Verification recomputes every `entry_hash` and checks every `prev` link;
  any mismatch ⇒ the log is tampered. Nothing changes silently.

## 9. Verification (what a consumer does, cold)

Before exposing or running a skill, a consumer **MUST** perform these checks and
refuse the skill if any fails (reference: `verify.py`, 11 checks):

1. **signed** — `skill.sig.json` is present and well-formed.
2. **manifest_valid** — the manifest validates (§3).
3. **caps_within_profile** — declared capabilities fit the sandbox envelope.
4. **digest_matches_signature** — re-derived bundle digest (§4) == the signed
   digest. *(Rug-pull catch.)*
5. **matches_pinned_digest** — if the caller pinned a digest, it matches.
6. **manifest_digest_matches** — re-derived manifest digest == signed.
7. **signature_valid** — Ed25519 verifies `payload` under `curator_key`.
8. **trusted_curator** — `curator_key` == the consumer's pinned curator key.
9. **scan_not_rejected** — re-running the scanner now does not `reject`.
10. **trust_reproducible** — recomputing the score from `trust_inputs` == the
    signed score.
11. **translog_integrity + inclusion** — the log verifies and contains a publish
    entry for this skill/version with the matching digest.

A conformant node **MUST** also **re-verify on every `tools/call`** (defense in
depth: a rug-pull after startup is caught before the skill is served).

## 10. MCP binding (the node)

The reference consumer is a **local MCP node** speaking JSON-RPC 2.0 over stdio
(newline-delimited messages; logs to stderr; UTF-8).

- `initialize` → `protocolVersion`, `capabilities.tools`, `serverInfo`,
  and human `instructions`.
- `tools/list` → one tool per **verified** skill, named `<pack>__<name>` (with
  `-`→`_`), its description carrying the **trust badge**, the **capability
  envelope**, and the **pinned digest**; plus meta tools `warden__list`,
  `warden__trust`, `warden__audit`, `warden__whoami`.
- `tools/call` → re-verify (§9); on success return the verified entrypoint text
  **with a provenance block** (skill, trust badge, pinned hash, capabilities,
  sandbox, live verdict). On failure, refuse and serve nothing.

Only verified, non-rejected skills are ever exposed — deny-by-default at the
registry boundary, not only at the capability boundary.

> **Execution model.** For `kind:"instructions"` skills the node serves verified
> *text*; the agent's model executes it. For `kind:"code"` skills the node runs
> the entrypoint in the sandbox (`sandbox.py`), consulting this same policy
> engine. That sandbox is defense-in-depth at the Python + process layer, **not a
> hard OS sandbox** — run untrusted code in a container / microVM / WASM in
> production and enforce the same policy there (see `docs/PHASES.md`).

## 11. Security considerations

- Trust is a **signal, not a guarantee**; never surface "100% safe."
- Signing proves *who* and *unchanged-since*; the scanner and trust score
  estimate *how well-behaved*; the log makes everything *attributable*. None
  alone is sufficient — the value is the layering (defense in depth).
- The pure-Python Ed25519 is portable and interop-verified but **not
  constant-time**; production curators **SHOULD** sign offline with an HSM/hardware
  key.
- Signed payloads **MUST NOT** contain floats (non-portable serialization);
  canonicalization rejects them.

## 12. Conformance levels

- **L1 — Verifier.** Performs all §9 checks; refuses on any failure. (Minimum.)
- **L2 — Node.** L1 + the §10 MCP binding + re-verify on call.
- **L3 — Curator.** L2 + the §5 scanner + §6 signing + §8 logging pipeline.

---

## Appendix A — Canonical JSON

For any object to be signed or hashed:

- object keys sorted by Unicode code point;
- most compact separators (`,` and `:`), no insignificant whitespace;
- UTF-8 encoding, non-ASCII emitted directly (`ensure_ascii=false`);
- **no** floating-point numbers and **no** NaN/Infinity (rejected).

This is a pragmatic subset of RFC 8785 sufficient for the integer/string/array
payloads this spec signs. Reference: `canonical.py`.

## Appendix B — Profile envelopes

`within_envelope(profile, caps)` (reference: `policy.py`) returns false if caps
exceed the profile table in §3.2; signing and verification both enforce it.
