# Agent-Skill Supply-Chain Threats — field reference

A signed, read-only reference an agent can mount. It names the threat *classes*
in the agent-skill supply chain and the mitigation each one calls for. It is
reference text, not instructions to act — and it is scanned at sign time so it
cannot smuggle directives into the agent.

## The classes

1. **Tool poisoning / injected instructions.** A skill's text or tool
   description tries to redirect the agent's behavior from inside the skill.
   *Mitigation:* scan skill text and schemas at intake; treat all skill content
   as data, never as commands.

2. **Unsafe command execution.** A skill induces remote code execution or runs a
   shell. *Mitigation:* deny shell by default; scan for execution patterns;
   contain execution in a sandbox.

3. **Server-side request forgery / exfiltration sinks.** A skill reaches a
   cloud-metadata address or an out-of-band collector. *Mitigation:* deny network
   by default; allowlist domains; flag known sinks.

4. **Secret exfiltration.** A skill reads credentials and sends them out.
   *Mitigation:* deny secret access by default; scrub secrets from any sandboxed
   process; flag credential-read correlated with egress.

5. **Capability drift.** A skill *declares* fewer capabilities than it actually
   uses. *Mitigation:* reconcile the declared manifest against the bundle's
   content; a mismatch is the keystone signal that identity is not behavior.

6. **Obfuscation.** Hidden or invisible content conceals any of the above.
   *Mitigation:* detect invisible / bidirectional / tag Unicode and long encoded
   blobs.

7. **Rug-pull.** A trusted skill's bytes are swapped after the fact.
   *Mitigation:* content-address and pin the bytes; re-derive and re-verify the
   hash on every load and call.

8. **Identity-only trust.** A "verified author" badge that says nothing about a
   given version's behavior. *Mitigation:* a per-version, time-aware behavioral
   trust score that re-evaluates on every publish.

9. **Silent change.** A skill or its trust mutates with no record.
   *Mitigation:* an append-only, hash-linked transparency log.

10. **Over-privilege.** A skill asks for more than it needs.
    *Mitigation:* least-privilege pressure in the trust score; refuse capabilities
    a sandbox profile cannot contain.

## The throughline

Verification of identity is not verification of behavior. Pin the bytes, bound
the capabilities, score the behavior per version, and log every change — so a
failure in any one layer is contained and visible rather than silent.

Trust is a signal, not a guarantee.
