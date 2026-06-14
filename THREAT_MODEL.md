# Warden Threat Model

What Warden defends, how, and — honestly — what it does not.

> **Attribution note.** This document references the OWASP Agentic Skills Top 10
> and several disclosed supply-chain incidents (Snyk "ToxicSkills," "ClawHavoc").
> Those framings and figures are cited from the project plan's sources (see the
> end of this file); several are dated after this project's authoring and are
> reproduced as *reported by their sources*, not asserted as independently
> verified fact. Warden's engineering value does not depend on any specific
> number — the attack **classes** below are well understood, and the mitigations
> stand on their own.

## The supply chain we secure

An agent skill is untrusted third-party code/instructions that an autonomous
agent will *act on*. The chain is: **author → distribution → install → run.**
Warden inserts a trust-control boundary between distribution and run:

```
 author ──▶ [ scan · sign · pin · log ] ──▶ skill brain ──▶ agent
                       ▲ Warden boundary ▲        (deny-by-default + sandbox)
```

We secure the *skill* boundary. We do **not** secure your agent's own prompts,
your other tools, or your operating system.

## The attacker's goals (what we're stopping)

1. **Hijack the agent** — smuggle instructions that redirect what the agent does.
2. **Execute code** on the host via the skill.
3. **Exfiltrate secrets** — credentials, tokens, environment, keys.
4. **Rug-pull** — ship a benign skill, build trust, then swap in malice later.
5. **Hide** — make any of the above invisible to the user and to static review.

## Threat classes → mitigations

| Class | What it looks like | Warden mitigation | Pillar / code |
|-------|--------------------|-------------------|---------------|
| **Tool poisoning / prompt injection** | Hidden "ignore previous instructions," covert directives, instruction-smuggling tags inside skill text or tool descriptions | Intake scanner flags imperative hijack phrasing as CRITICAL; only un-waived CRITICAL auto-rejects | `scanner.py` (TP) · pillar 2 |
| **Unsafe command execution** | `curl … | sh`, `Invoke-Expression`, `os.system`, encoded PowerShell | Scanner CRITICAL/HIGH; deny-by-default means a skill has no shell unless it declares (and is profiled for) it | `scanner.py` (EX), `policy.py` · 2,3,4 |
| **SSRF / exfiltration sinks** | Reach to the cloud metadata IP, raw-IP URLs, known paste-bin / out-of-band collectors | Scanner CRITICAL on metadata endpoint and exfil sinks; deny-by-default network | `scanner.py` (NET), `policy.py` · 2,3 |
| **Secret exfiltration** | Reading env/credentials **correlated with** an outbound call | Scanner correlates secret-read + egress in one file; `secrets:false` + drift catches it | `scanner.py` (SEC, DRIFT-SEC) · 2,3 |
| **Capability drift** *(the keystone)* | A manifest that **declares** "no network / no secrets" while the bundle **does** egress or reads credentials | Scanner compares declared caps to actual content; mismatch is CRITICAL. *This is "identity ≠ behavior" made executable.* | `scanner.py` (DRIFT) · 1,2,3 |
| **Obfuscation** | Invisible / bidi / Unicode-tag characters, long base64/hex payload blobs | Scanner detects invisible & tag code points (CRITICAL for the tag block) and long encoded blobs | `scanner.py` (OBF) · 2 |
| **Rug-pull** | Silently changing a skill's bytes after you trusted it | Content-addressing + signing: re-derived hash must match the signed hash, every load and every call. A changed byte fails verification | `content_address.py`, `verify.py`, `node.py` · 1 |
| **Identity-only trust** | A "verified author" badge that says nothing about *this version's* behavior | Per-version, time-aware behavioral trust score; new versions are provisional-capped until clean observation accrues | `trust.py` · 5 |
| **Silent changes** | A skill or its trust quietly mutating with no record | Append-only, hash-linked, Merkle-rooted transparency log; tamper is detectable | `translog.py` · 6 |
| **Over-privilege** | A skill that asks for shell / broad fs / secrets it doesn't need | Least-privilege pressure in the trust score; sandbox-profile envelope refuses caps it can't contain | `trust.py`, `policy.py` · 3,4,5 |

## Defense in depth

No single layer is trusted to be sufficient:

1. **Sign + pin** so the bytes can't change unseen (catches rug-pull).
2. **Scan** so known-bad patterns are caught at the door (catches the obvious).
3. **Deny-by-default capabilities** so even a *missed* attack can't reach the
   network, the filesystem, the shell, or secrets it never declared.
4. **Sandbox profile** so declared capabilities are *contained*, not ambient.
5. **Per-version behavioral score** so trust is earned and revocable, never
   assumed from identity.
6. **Transparency log** so every publish and yank is public and permanent —
   making a bad actor *attributable*, which is the real deterrent.

A failure in one layer is meant to be *contained and visible* by the others.

## Honest residual risk

- **A trusted curator who signs malice.** Warden makes it attributable and
  permanent; it does not make curator-trust unnecessary.
- **A genuinely novel pattern** the static scanner has never seen. Mitigated,
  not eliminated, by deny-by-default + the provisional cap on new versions.
- **Behavior only visible at runtime** in code skills. The node runs `kind:"code"`
  skills in the sandbox (`sandbox.py`), but that is defense-in-depth at the Python
  + process layer, **not a hard OS sandbox** — a determined skill using ctypes or
  raw syscalls could bypass the Python guards. Run untrusted code in a container /
  microVM / WASM in production and enforce the same policy there.
- **The scanner is heuristic.** It favors precision on the auto-reject path
  (false-rejects are worse than a flag-for-review), so some softer risks are
  *flagged*, not blocked. That is a deliberate trade, surfaced — not hidden.

Trust is a **signal, not a guarantee.** See [`SECURITY.md`](SECURITY.md).

## Sources (from the project plan; reproduced as cited)

- OWASP Agentic Skills Top 10; Merkle-root signing + continuous scanning as the
  prescribed mitigation — https://obot.ai/blog/mcp-security-agent-skills-supply-chain/
- Snyk "ToxicSkills" (Feb 2026) and "ClawHavoc" supply-chain disclosures — same source.
- MCP server security scan (37% SSRF, 43% unsafe command execution, 41% zero-auth)
  — https://www.practical-devsecops.com/mcp-security-guide/
- MCP registry landscape — https://www.truefoundry.com/blog/best-mcp-registries
