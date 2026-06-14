# Examples

The magic moment, two ways: a self-contained smoke client you can run right now,
and the one config line that wires the node into a real MCP agent.

> A note on the `py` launcher. Run everything here with **`py`**, not bare
> `python`. On this machine (and many Windows setups) bare `python` is a broken
> Microsoft Store alias; `py` resolves a real interpreter. There is **no
> `#!/usr/bin/env python` shebang** in any of these scripts on purpose — the
> `py` launcher *does* honor shebangs, so a stray one could send the script to
> the wrong interpreter. Invoke explicitly with `py <script>` and there is
> nothing to guess.

---

## 1. Run the smoke client

```
py examples/mcp_client_smoke.py
```

This spawns the Warden node as a subprocess (`py -m warden serve`) and speaks
JSON-RPC 2.0 to it over stdio — exactly as an MCP agent would. It is a plain MCP
client in about eighty lines; any MCP-speaking agent does the same handshake.

### What you will see

**On stderr — the node verifies every skill cold at startup.** Before it serves
anything, the node pins the curator key, checks the transparency log's integrity,
and re-verifies each curated skill from scratch (re-derives the content hash,
checks the Ed25519 signature, re-runs the scan, recomputes the trust score). Only
skills that pass are exposed — **deny-by-default, even here**:

```
[warden] pinned curator key warden:cd015c720e6027fd
[warden] transparency log: 5 entries, root sha256:491104b0...a5d4c6, integrity OK
[warden] VERIFIED  build-brain/build-product        [Warden PROVISIONAL A/99 ✓]
[warden] VERIFIED  build-brain/ship-gate            [Warden A/100 ✓]
[warden] VERIFIED  compliance-brain/secret-sentinel [Warden PROVISIONAL C/79 ✓]
[warden] VERIFIED  research-brain/fact-gate         [Warden A/100 ✓]
[warden] VERIFIED  research-brain/idea-scout        [Warden A/100 ✓]
[warden] ready: 5 skill(s) exposed, 0 refused (deny-by-default)
```

**On stdout — the conversation**, in five steps:

1. **`initialize`** — the MCP handshake; the node reports its name, version, and
   protocol.
2. **`tools/list`** — every skill surfaces as a tool whose description **carries
   its trust badge and exact capability envelope** (capabilities, sandbox
   profile, pinned hash). Capability and provenance in the same breath. Four
   meta-tools also appear: `warden__list`, `warden__trust`, `warden__audit`,
   `warden__whoami`.
3. **`warden__whoami`** — node identity, pinned curator fingerprint, and the
   current Merkle root.
4. **`research_brain__idea_scout`** — a skill served **with a provenance block**:
   skill id + version, trust badge, pinned hash, capabilities, sandbox, who signed
   it, and a fresh verification result (`VERIFIED (11/11 checks)`), followed by
   the verified skill instructions. The node re-verifies on this call too — a
   rug-pull after startup is caught here.
5. **`warden__audit`** — the public, append-only **transparency log** with its
   Merkle root and every publish entry.

It ends on the point of the whole thing:

```
MAGIC MOMENT: one stdio connection -> a curated, signed, sandboxed,
trust-scored skill set. Capability and provenance in the same breath.
```

> **Honest scope (Phase 0).** The curated skills are *instruction packs*. The
> node serves their **verified text + provenance**; your agent's model is what
> follows the instructions. The node does **not** execute skill code in this
> build, and the provenance block says so. Sandboxed execution of `kind: "code"`
> skills is Phase 1 — see [`../docs/BUILD_PATH.md`](../docs/BUILD_PATH.md).

---

## 2. Wire the node into a real MCP agent

One config line points any MCP-speaking agent at the local node. Use
[`claude_desktop_config.json`](claude_desktop_config.json) as the template — it
is a Claude Desktop style `mcpServers` block, and the same shape works for other
MCP clients.

```json
{
  "mcpServers": {
    "warden": {
      "command": "py",
      "args": ["-m", "warden", "serve"],
      "cwd": "C:\\Users\\13067\\Desktop\\New folder\\WARDEN"
    }
  }
}
```

- **`command` / `args`** — launch the local node with `py -m warden serve`. (Bare
  `python` may be a broken Store alias; use `py`.)
- **`cwd`** — the absolute path to your WARDEN repo checkout, so the node finds
  the package and the curated registry. Change the example path to wherever you
  cloned the repo.

Merge that `warden` entry into your client's MCP config, restart the client, and
your agent gains the curated, signed, trust-scored skill set — locally, with
nothing leaving your box.

---

## First-run note

If you cloned a fresh checkout and the node reports no curator key or an empty
registry, build the local trust state once:

```
py -m warden keygen      # generate your curator keypair (one time)
py -m warden sign-all    # scan + sign every curated skill, (re)build the log
py -m warden verify-all  # cold-verify everything
```

Then run the smoke client. To sanity-check the whole package with no external
anything:

```
py -m warden selftest
```

Trust is a **signal, not a guarantee.** See [`../SECURITY.md`](../SECURITY.md).
