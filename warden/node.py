"""
The reference local Warden node -- an MCP server over stdio (JSON-RPC 2.0).

This is the magic moment. One config line points any MCP-speaking agent here.
At startup the node:

  * loads the curated registry,
  * VERIFIES every skill cold against the pinned curator key + transparency log
    (re-derives the hash, checks the signature, re-runs the scan, recomputes
    the trust score), and
  * exposes ONLY the skills that pass -- deny-by-default, even here.

Each skill surfaces as an MCP tool whose description carries its trust badge and
its exact capability envelope: capability + provenance in the same breath. On
`tools/call` the node RE-VERIFIES (defense in depth -- a rug-pull after startup
is caught) and returns the curated, signed instructions together with a
provenance block.

Phase 1+ wiring: `kind:"instructions"` skills are served as verified text +
provenance (the agent's model follows them); `kind:"code"` skills are EXECUTED
in the sandbox (sandbox.py) with the capability manifest enforced. The node also
exposes private encrypted memory (memory.py) and signed knowledge packs
(kpack.py), verifies against any trusted curator root (multi-curator), enforces
an optional org policy (orgpolicy.py), and records a tamper-evident audit log
(audit.py).

Pure standard library. Nothing leaves your box.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import (__version__, audit as audit_mod, ed25519, kpack, manifest as manifest_mod,
               memory as memory_mod, orgpolicy, repo, sandbox)
from .translog import TransparencyLog, merkle_root
from .verify import verify_skill
from .trust import badge

MCP_PROTOCOL_VERSION = "2024-11-05"
META_PREFIX = "warden"


def _tool_name(pack: str, name: str) -> str:
    return f"{pack}__{name}".replace("-", "_")


class LoadedSkill:
    def __init__(self, skill_id: str, row: Dict[str, Any], verification: Dict[str, Any]):
        self.skill_id = skill_id
        self.row = row
        self.verification = verification
        self.dir = os.path.join(repo.REPO_ROOT, row["dir"])

    @property
    def verified(self) -> bool:
        return self.verification.get("ok", False)

    @property
    def trust(self) -> Dict[str, Any]:
        return self.row.get("trust", {})

    @property
    def kind(self) -> str:
        return self.row.get("kind", "instructions")

    def manifest(self) -> Dict[str, Any]:
        try:
            return manifest_mod.load(self.dir)
        except Exception:
            return {}

    def tool_name(self) -> str:
        return _tool_name(self.row["pack"], self.row["name"])


class WardenNode:
    def __init__(self, log=sys.stderr):
        self._log = log
        self.curator_pub: Optional[bytes] = None
        self.trusted_pubs: List[bytes] = []
        self.translog: Optional[TransparencyLog] = None
        self.skills: List[LoadedSkill] = []
        self.kpacks: List[Dict[str, Any]] = []
        self.policy = orgpolicy.PolicyEngine()
        self._audit: Optional[audit_mod.AuditLog] = None
        self._memory_cache: Dict[str, memory_mod.MemoryStore] = {}
        self._load()

    def _audit_record(self, event: str, **fields) -> None:
        try:
            if self._audit is None:
                self._audit = audit_mod.AuditLog()
            self._audit.record(event, **fields)
        except Exception:
            pass  # auditing must never break serving

    def _memory(self, agent_id: str = "local") -> memory_mod.MemoryStore:
        if agent_id not in self._memory_cache:
            self._memory_cache[agent_id] = memory_mod.MemoryStore(agent_id)
        return self._memory_cache[agent_id]

    # -- bootstrap -----------------------------------------------------------
    def _logline(self, msg: str) -> None:
        line = f"[warden] {msg}"
        try:
            print(line, file=self._log, flush=True)
        except UnicodeEncodeError:
            # the caller handed us a stream with a legacy codepage; degrade the
            # trust badge (✓) rather than crash the node.
            enc = getattr(self._log, "encoding", None) or "ascii"
            print(line.encode(enc, "replace").decode(enc, "replace"),
                  file=self._log, flush=True)

    def _load(self) -> None:
        try:
            self.curator_pub = repo.load_curator_pub()
        except Exception:
            self.curator_pub = None
        self.trusted_pubs = repo.load_trust_roots()
        if self.trusted_pubs:
            roots = ", ".join(ed25519.fingerprint(p) for p in self.trusted_pubs)
            self._logline(f"trusted curator root(s): {roots}")
        else:
            self._logline("WARNING: no curator key pinned; cannot verify skills")

        policy_name = self.policy.p.get("name", "default")
        if os.path.isfile(repo.ORG_POLICY):
            self._logline(f"org policy: {policy_name} (governance enforced)")

        if os.path.isfile(repo.TRANSLOG_PATH):
            self.translog = TransparencyLog(repo.TRANSLOG_PATH)
            ok, errs = self.translog.verify()
            root = self.translog.current_root()
            self._logline(f"transparency log: {self.translog.count()} entries, "
                          f"root {root}, integrity {'OK' if ok else 'FAILED: ' + ';'.join(errs)}")

        reg = repo.load_registry()
        exposed, refused = 0, 0
        for skill_id, row in sorted(reg.get("skills", {}).items()):
            skill_dir = os.path.join(repo.REPO_ROOT, row["dir"])
            v = verify_skill(skill_dir, trusted_pubs=self.trusted_pubs, translog=self.translog)
            loaded = LoadedSkill(skill_id, row, v)
            if not (loaded.verified and loaded.trust.get("status") != "rejected"):
                refused += 1
                reasons = ", ".join(c["check"] for c in v.get("failed", [])) or "trust rejected"
                self._logline(f"REFUSED   {skill_id:<32} ({reasons}) -- not exposed")
                self._audit_record("refuse", skill=skill_id, reason=reasons)
                continue
            # governance: org policy sits on top of cryptographic verification
            scan_summary = self._signed_scan(loaded)
            allowed, preasons = self.policy.evaluate(row, loaded.manifest(), scan_summary)
            if not allowed:
                refused += 1
                self._logline(f"POLICY    {skill_id:<32} ({'; '.join(preasons)}) -- not exposed")
                self._audit_record("policy_deny", skill=skill_id, reasons=preasons)
                continue
            self.skills.append(loaded)
            exposed += 1
            tag = " [code]" if loaded.kind == "code" else ""
            self._logline(f"VERIFIED  {skill_id:<32} {badge(loaded.trust)}{tag}")
            self._audit_record("expose", skill=skill_id,
                               trust=f"{loaded.trust.get('grade')}/{loaded.trust.get('score')}",
                               kind=loaded.kind)

        # signed knowledge packs (read-only reference)
        for pd in kpack.discover():
            kv = kpack.verify_kpack(pd, trusted_pubs=self.trusted_pubs, translog=self.translog)
            if kv.get("ok"):
                self.kpacks.append({"dir": pd, **kv})

        kp = f", {len(self.kpacks)} knowledge pack(s)" if self.kpacks else ""
        self._logline(f"ready: {exposed} skill(s) exposed, {refused} refused{kp} (deny-by-default)")

    def _signed_scan(self, loaded: "LoadedSkill") -> Optional[Dict[str, Any]]:
        try:
            with open(os.path.join(loaded.dir, "skill.sig.json"), "r", encoding="utf-8") as fh:
                return json.load(fh).get("payload", {}).get("scan")
        except Exception:
            return None

    # -- MCP dispatch --------------------------------------------------------
    def handle(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                result = self._initialize()
            elif method in ("notifications/initialized", "initialized"):
                return None
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self._tools()}
            elif method == "tools/call":
                result = self._call(msg.get("params", {}))
            else:
                if is_notification:
                    return None
                return self._error(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # never crash the loop
            if is_notification:
                return None
            return self._error(mid, -32603, f"internal error: {exc}")

        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _error(self, mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    def _initialize(self) -> Dict[str, Any]:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "warden", "version": __version__},
            "instructions": (
                "Warden serves a curated set of cryptographically signed, scanned, and "
                "trust-scored skills. Pack-prefixed tools are verified skills (instructions "
                "are served as text; code skills run sandboxed). Each description carries a "
                "[Warden <grade>/<score>] badge and the exact capability envelope. Meta "
                "tools: warden__list, warden__trust, warden__audit, warden__whoami, "
                "warden__remember / warden__recall (private encrypted memory), and "
                "warden__knowledge / warden__knowledge_read (signed read-only reference). "
                "Trust is a SIGNAL, not a guarantee."
            ),
        }

    # -- tool catalog --------------------------------------------------------
    def _tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        for s in self.skills:
            m = self._manifest(s)
            input_schema = m.get("input_schema") or {
                "type": "object",
                "properties": {"task": {"type": "string",
                                        "description": "What you want this skill to do."}},
                "required": ["task"],
            }
            tools.append({
                "name": s.tool_name(),
                "description": (
                    f"{badge(s.trust)} {s.row['summary']} "
                    f"[capabilities: {s.row['capabilities_summary']}; "
                    f"sandbox: {s.row['sandbox_profile']}; pinned {s.row['bundle_digest'][:19]}...]"
                ),
                "inputSchema": input_schema,
            })
        tools.extend(self._meta_tools())
        return tools

    def _meta_tools(self) -> List[Dict[str, Any]]:
        obj = {"type": "object", "properties": {}}
        skill_arg = {
            "type": "object",
            "properties": {"skill": {"type": "string", "description": "skill id, e.g. research-brain/idea-scout"}},
            "required": ["skill"],
        }
        return [
            {"name": f"{META_PREFIX}__list", "description":
                "List every verified skill with its trust badge and capability envelope.",
             "inputSchema": obj},
            {"name": f"{META_PREFIX}__trust", "description":
                "Full trust detail (score, grade, rationale, provenance) for one skill.",
             "inputSchema": skill_arg},
            {"name": f"{META_PREFIX}__audit", "description":
                "The append-only transparency log (every publish) + current Merkle root.",
             "inputSchema": obj},
            {"name": f"{META_PREFIX}__whoami", "description":
                "Node identity, pinned curator key fingerprint, and log root.",
             "inputSchema": obj},
            {"name": f"{META_PREFIX}__remember", "description":
                "Save a note to your PRIVATE, local, encrypted memory.",
             "inputSchema": {"type": "object", "properties": {
                 "text": {"type": "string", "description": "the note to remember"},
                 "tags": {"type": "array", "items": {"type": "string"}}},
                 "required": ["text"]}},
            {"name": f"{META_PREFIX}__recall", "description":
                "Search your private encrypted memory for relevant notes.",
             "inputSchema": {"type": "object", "properties": {
                 "query": {"type": "string"}}, "required": ["query"]}},
            {"name": f"{META_PREFIX}__knowledge", "description":
                "List the signed, read-only knowledge packs available to mount.",
             "inputSchema": obj},
            {"name": f"{META_PREFIX}__knowledge_read", "description":
                "Read a file from a verified knowledge pack (reference, not instructions).",
             "inputSchema": {"type": "object", "properties": {
                 "pack": {"type": "string"}, "file": {"type": "string"}},
                 "required": ["pack", "file"]}},
        ]

    # -- tool execution ------------------------------------------------------
    def _call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}

        if name == f"{META_PREFIX}__list":
            return self._text(self._render_list())
        if name == f"{META_PREFIX}__whoami":
            return self._text(self._render_whoami())
        if name == f"{META_PREFIX}__audit":
            return self._text(self._render_audit())
        if name == f"{META_PREFIX}__trust":
            return self._text(self._render_trust(args.get("skill", "")))
        if name == f"{META_PREFIX}__remember":
            eid = self._memory().remember(args.get("text", ""), tags=args.get("tags") or [])
            return self._text(f"remembered ({eid}) in your private encrypted memory.")
        if name == f"{META_PREFIX}__recall":
            hits = self._memory().recall(args.get("query", ""), k=5)
            if not hits:
                return self._text("no matching memories.")
            return self._text("\n".join(f"- {h['text']}"
                                        + (f"  [{', '.join(h['tags'])}]" if h.get("tags") else "")
                                        for h in hits))
        if name == f"{META_PREFIX}__knowledge":
            return self._text(self._render_knowledge())
        if name == f"{META_PREFIX}__knowledge_read":
            return self._text(self._read_knowledge(args.get("pack", ""), args.get("file", "")))

        skill = self._find_by_tool(name)
        if skill is None:
            return self._text(f"unknown or unexposed tool: {name}", is_error=True)

        # defense in depth: re-verify at call time (catch a post-startup rug-pull)
        v = verify_skill(skill.dir, trusted_pubs=self.trusted_pubs, translog=self.translog)
        if not v.get("ok"):
            failed = ", ".join(c["check"] for c in v.get("failed", []))
            self._audit_record("call_refused", skill=skill.skill_id, reason=failed)
            return self._text(
                f"REFUSING to serve {skill.skill_id}: verification failed at call time "
                f"({failed}). The bundle may have changed since it was signed (possible "
                f"rug-pull). Nothing was executed.", is_error=True)

        self._audit_record("tool_call", skill=skill.skill_id, kind=skill.kind)
        provenance = self._provenance_block(skill, v)

        if skill.kind == "code":
            # EXECUTE in the sandbox, capability manifest enforced
            result = sandbox.run_code_skill(skill.dir, skill.manifest(), args)
            verdict = "OK" if result.get("ok") else (
                "TIMED OUT" if result.get("timed_out") else "ERROR")
            body = (
                f"{provenance}\n\n"
                f"--- SANDBOXED EXECUTION ({verdict}) --------------------------\n"
                f"output    : {json.dumps(result.get('output'), ensure_ascii=False)}\n"
                f"enforced  : network={result['policy']['network']}, "
                f"shell={result['policy']['shell']}, env=scrubbed, profile={result['policy']['profile']}\n"
            )
            if result.get("violations"):
                body += "violations: " + "; ".join(result["violations"]) + "\n"
            return self._text(body, is_error=not result.get("ok"))

        # instructions skill: serve the verified text + provenance
        instructions = self._read_entrypoint(skill)
        task = args.get("task") or json.dumps(args, ensure_ascii=False)
        body = (
            f"{provenance}\n\n"
            f"--- TASK -------------------------------------------------------\n{task}\n\n"
            f"--- VERIFIED SKILL INSTRUCTIONS -------------------------------\n{instructions}\n"
        )
        return self._text(body)

    # -- renderers -----------------------------------------------------------
    def _provenance_block(self, skill: LoadedSkill, v: Dict[str, Any]) -> str:
        t = skill.trust
        return (
            "=== WARDEN PROVENANCE ==========================================\n"
            f"skill        : {skill.skill_id} v{skill.row['version']}\n"
            f"trust        : {badge(t)}  (a SIGNAL, not a guarantee)\n"
            f"pinned hash  : {skill.row['bundle_digest']}\n"
            f"capabilities : {skill.row['capabilities_summary']}\n"
            f"sandbox      : {skill.row['sandbox_profile']} (deny-by-default; "
            "this skill cannot act outside the above envelope)\n"
            f"signed by    : {self._manifest(skill).get('author','?')} via curator "
            f"{ed25519.fingerprint(self.curator_pub) if self.curator_pub else '?'}\n"
            f"verified now : {v['verdict']} ({sum(1 for c in v['checks'] if c['ok'])}/"
            f"{len(v['checks'])} checks)\n"
            "================================================================"
        )

    def _render_list(self) -> str:
        lines = ["Verified skills (deny-by-default; only VERIFIED skills are exposed):", ""]
        for s in self.skills:
            lines.append(f"  {badge(s.trust):<22} {s.skill_id:<30} v{s.row['version']}")
            lines.append(f"      {s.row['summary']}")
            lines.append(f"      caps: {s.row['capabilities_summary']}")
        if self.translog:
            lines += ["", f"transparency root: {self.translog.current_root()} ({self.translog.count()} entries)"]
        return "\n".join(lines)

    def _render_whoami(self) -> str:
        return "\n".join([
            f"node           : warden v{__version__} (local MCP node, stdio)",
            f"curator key    : {ed25519.fingerprint(self.curator_pub) if self.curator_pub else 'NONE'}",
            f"skills exposed : {len(self.skills)}",
            f"log entries    : {self.translog.count() if self.translog else 0}",
            f"merkle root    : {self.translog.current_root() if self.translog else None}",
            "trust model    : content-addressed + Ed25519-signed + scanned + "
            "behaviorally-scored + transparency-logged. A signal, not a guarantee.",
        ])

    def _render_audit(self) -> str:
        if not self.translog:
            return "no transparency log present."
        ok, errs = self.translog.verify()
        lines = [f"Transparency log -- integrity {'OK' if ok else 'FAILED'}; "
                 f"root {self.translog.current_root()}", ""]
        for e in self.translog.entries():
            lines.append(f"  #{e['seq']} {e['action']:<7} {e['skill']} v{e['version']} "
                         f"trust {e['trust_grade']}/{e['trust_score']} "
                         f"{e['bundle_digest'][:19]}... @ {e['timestamp']}")
        if not ok:
            lines += ["", "ERRORS:"] + [f"  - {x}" for x in errs]
        return "\n".join(lines)

    def _render_trust(self, skill_id: str) -> str:
        s = next((x for x in self.skills if x.skill_id == skill_id), None)
        if not s:
            return f"no verified skill '{skill_id}'. Try warden__list."
        v = s.verification
        t = v.get("trust", {})
        lines = [f"{skill_id}  {badge(s.trust)}",
                 f"  status      : {t.get('status')}  provisional={t.get('provisional')}  "
                 f"as_of={t.get('as_of')}",
                 f"  scan        : {t.get('scan_verdict')}",
                 f"  capabilities: {t.get('capability_summary')}",
                 f"  pinned hash : {s.row['bundle_digest']}",
                 "  rationale   :"]
        for r in t.get("rationale", []):
            lines.append(f"    - {r}")
        lines.append(f"  verified now: {v['verdict']} "
                     f"({sum(1 for c in v['checks'] if c['ok'])}/{len(v['checks'])} checks)")
        return "\n".join(lines)

    def _render_knowledge(self) -> str:
        if not self.kpacks:
            return "no verified knowledge packs are mounted."
        lines = ["Verified knowledge packs (signed, read-only reference):", ""]
        for k in self.kpacks:
            m = kpack.load_manifest(k["dir"])
            lines.append(f"  [KPACK ✓] knowledge/{k['name']:<24} v{k['version']}")
            lines.append(f"      {m.get('summary','')}")
            lines.append(f"      files: {', '.join(m.get('files', []))}")
        lines.append("\nread with warden__knowledge_read {pack, file}.")
        return "\n".join(lines)

    def _read_knowledge(self, pack_name: str, file: str) -> str:
        match = next((k for k in self.kpacks if k["name"] == pack_name
                      or k["name"] == pack_name.replace("knowledge/", "")), None)
        if not match:
            return f"no verified knowledge pack '{pack_name}'. Try warden__knowledge."
        # re-verify on read (defense in depth)
        kv = kpack.verify_kpack(match["dir"], trusted_pubs=self.trusted_pubs, translog=self.translog)
        if not kv.get("ok"):
            return f"REFUSING: knowledge pack '{pack_name}' failed verification at read time."
        content = kpack.read_file(match["dir"], file)
        if content is None:
            return f"no readable file '{file}' in knowledge/{pack_name}."
        return (f"=== knowledge/{match['name']} :: {file} (verified, read-only) ===\n\n{content}")

    # -- helpers -------------------------------------------------------------
    def _manifest(self, skill: LoadedSkill) -> Dict[str, Any]:
        from . import manifest as manifest_mod
        try:
            return manifest_mod.load(skill.dir)
        except Exception:
            return {}

    def _read_entrypoint(self, skill: LoadedSkill) -> str:
        m = self._manifest(skill)
        entry = m.get("entrypoint", "SKILL.md")
        path = os.path.join(skill.dir, entry)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except Exception as exc:
            return f"(could not read entrypoint {entry}: {exc})"

    def _find_by_tool(self, tool_name: str) -> Optional[LoadedSkill]:
        for s in self.skills:
            if s.tool_name() == tool_name:
                return s
        return None

    def _text(self, text: str, is_error: bool = False) -> Dict[str, Any]:
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    # -- stdio loop ----------------------------------------------------------
    def serve(self, stdin=None, stdout=None) -> None:
        # MCP is UTF-8; force it so JSON-RPC + badges survive any console codepage.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
            except Exception:
                pass
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        self._logline("serving on stdio (newline-delimited JSON-RPC). Ctrl-C to stop.")
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                stdout.write(json.dumps(self._error(None, -32700, "parse error")) + "\n")
                stdout.flush()
                continue
            response = self.handle(msg)
            if response is not None:
                stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                stdout.flush()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    WardenNode().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
