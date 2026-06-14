# Security Policy

## Our one honest claim

Warden's trust score is **a signal, not a guarantee.** We will never tell you a
skill is "100% safe." What we promise is narrower and real:

- the bytes you run are the bytes that were signed (content-addressed + pinned);
- a named curator key vouched for them, on a public, append-only log;
- the skill was scanned for known-bad patterns at intake;
- the skill cannot act outside the capabilities it declared (deny-by-default);
- and the trust score reflects scan results, least privilege, and *observed
  behavior over time* — not a one-time identity check.

Defense in depth, not a silver bullet. A determined novel attack can still slip
a static scan; that is exactly why we layer signing + pinning + deny-by-default
+ sandboxing + per-version re-scoring + a public log, so that one failure is
contained and *visible* rather than silent.

## What Warden does NOT protect against (be honest with yourself)

- A curator who knowingly signs a malicious skill. (The transparency log makes
  this *attributable and permanent*, which is the deterrent — but trust in the
  curator is still trust.)
- A brand-new zero-day pattern the scanner has never seen. (Mitigated by
  deny-by-default capabilities and the provisional trust cap on new versions.)
- Anything outside the skill boundary: your agent's own prompts, your other
  tools, your OS. Warden secures the *skill supply chain*, not your whole stack.

## Reporting a vulnerability

If you find a security issue in Warden itself (the scanner missing a class, a
signature-verification bypass, a sandbox-escape in the node, a trust-score
manipulation), please report it responsibly:

1. **Do not** open a public issue with a working exploit.
2. Email the maintainers (see repository contact) with: a description, repro
   steps, affected version/commit, and impact.
3. You will get an acknowledgement within a few days and a coordinated
   disclosure timeline. We credit reporters who want credit.

For a malicious **skill** discovered in a registry, file it through the
responsible-disclosure path so it can be yanked, re-scored to `rejected`, and
recorded in the transparency log — the point of the log is that a yank is
public and permanent.

## Scope

In scope: the `warden/` reference implementation, the Trust Spec, the curated
skill manifests, and the signing/verification pipeline.

Out of scope: third-party skills not curated here, your MCP client, and your
operating system. Treat every un-curated, un-signed skill as untrusted.

## Cryptography note

This Phase 0 reference uses a pure-Python Ed25519 (RFC 8032) for portability and
zero dependencies; it is interoperable with mainstream implementations (verified
in the self-test). It is **not** constant-time and is not hardened against
side-channel attacks. A production curator should sign offline with a hardware
key or HSM and keep the private seed off any networked machine.
