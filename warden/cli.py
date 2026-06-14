"""
`warden` command-line interface.

    py -m warden keygen                 generate the curator keypair (one time)
    py -m warden scan   <skill_dir>     run the intake scanner, print findings
    py -m warden sign   <skill_dir>     scan + sign + log + register one skill
    py -m warden sign-all               sign every curated skill (rebuilds log)
    py -m warden verify <skill_dir>     cold-verify one skill
    py -m warden verify-all             cold-verify every registered skill
    py -m warden trust  <skill_id>      show a skill's trust detail
    py -m warden list                   show the registry
    py -m warden audit                  print + verify the transparency log
    py -m warden serve                  run the reference MCP node (stdio)
    py -m warden selftest               run the zero-dep self-test

  Phase 1-4:
    py -m warden run-code <dir> [json] run a code skill in the sandbox
    py -m warden memory remember|recall|list   private encrypted memory
    py -m warden update <id> <dir>      safe auto-update gate (--apply)
    py -m warden scan-report <dir>      shareable scan report (--sign)
    py -m warden policy show|init|check org allow/deny governance
    py -m warden audit-log              the tamper-evident audit log
    py -m warden serve-api [--port N]   the Trust-as-a-Service Scan API
    py -m warden build-index [out]      generate the trust-graded static index
    py -m warden kpack list|sign|verify signed knowledge packs
    py -m warden host <dir>             sign your own skill (private)
    py -m warden add-root <hex> <name>  trust another curator key
"""

from __future__ import annotations

import json
import os
import sys
from typing import List, Optional

from . import __version__, ed25519, manifest, repo, scanner
from .sign import sign_skill, SignError
from .translog import TransparencyLog
from .verify import verify_skill
from .trust import badge

# Fixed observation/history seed data for the curated demo skills, so the
# behavioral score is reproducible and the demo is honest about provisional vs
# established skills. Real deployments feed live observation here.
DEMO_AS_OF = "2026-06-13"
_DEMO_OBSERVATION = {
    "research-brain/idea-scout":      {"clean_runs": 50, "observed_days": 60},
    "research-brain/fact-gate":       {"clean_runs": 44, "observed_days": 55},
    "build-brain/build-product":      {"clean_runs": 38, "observed_days": 50},
    "build-brain/ship-gate":          {"clean_runs": 41, "observed_days": 52},
    "compliance-brain/secret-sentinel": {"clean_runs": 6, "observed_days": 9},  # newer -> provisional
    "util-brain/word-count":            {"clean_runs": 12, "observed_days": 14},  # new code skill
}


def _skill_id_for(skill_dir: str) -> str:
    from . import manifest as manifest_mod
    m = manifest_mod.load(skill_dir)
    return f"{m['pack']}/{m['name']}"


def cmd_keygen(args: List[str]) -> int:
    force = "--force" in args
    os.makedirs(repo.KEYS_DIR, exist_ok=True)
    if os.path.isfile(repo.CURATOR_SEED) and not force:
        pub = repo.load_curator_pub()
        print(f"curator key already exists: {ed25519.fingerprint(pub)}")
        print("(use --force to overwrite -- this rotates the curator identity)")
        return 0
    seed = ed25519.new_seed()
    pub = ed25519.public_key(seed)
    with open(repo.CURATOR_SEED, "w", encoding="utf-8") as fh:
        fh.write(seed.hex())
    with open(repo.CURATOR_PUB, "w", encoding="utf-8") as fh:
        fh.write(pub.hex())
    print(f"generated curator keypair: {ed25519.fingerprint(pub)}")
    print(f"  private seed -> {repo.rel(repo.CURATOR_SEED)}  (KEEP SECRET; gitignored)")
    print(f"  public key   -> {repo.rel(repo.CURATOR_PUB)}")
    return 0


def cmd_scan(args: List[str]) -> int:
    if not args:
        print("usage: warden scan <skill_dir>", file=sys.stderr)
        return 2
    skill_dir = args[0]
    result = scanner.scan_bundle(skill_dir)
    print(f"{skill_dir}: {scanner.summarize(result)}")
    if result.verdict == "empty":
        print("  no scannable files found here — is this a skill bundle?", file=sys.stderr)
        return 2
    for f in result.findings:
        print(f"  [{f.severity:<8}] {f.klass:<14} {f.file}:{f.line}  {f.message}")
        if f.snippet:
            print(f"             > {f.snippet[:100]}")
    if result.waivers:
        print("  waivers (curator-acknowledged):")
        for w in result.waivers:
            print(f"    - {w['class']}: {w['reason']}")
    return 0 if result.verdict != "reject" else 1


def cmd_sign(args: List[str]) -> int:
    if not args:
        print("usage: warden sign <skill_dir>", file=sys.stderr)
        return 2
    seed = repo.load_curator_seed()
    translog = TransparencyLog(repo.TRANSLOG_PATH)
    skill_dir = args[0]
    skill_id = _skill_id_for(skill_dir)
    obs = _DEMO_OBSERVATION.get(skill_id, {})
    try:
        res = sign_skill(skill_dir, seed, observation=obs, as_of=DEMO_AS_OF, translog=translog)
    except (SignError, Exception) as exc:
        print(f"REFUSED to sign {skill_dir}: {exc}", file=sys.stderr)
        return 1
    t = res["trust"]
    print(f"signed {res['skill']} v{res['version']}  {badge(t)}")
    print(f"  pinned {res['bundle_digest']}")
    print(f"  log seq #{res.get('translog_seq')}  entry {res.get('entry_hash','')[:23]}...")
    return 0


def cmd_sign_all(args: List[str]) -> int:
    # rebuild from scratch so the log + registry are deterministic
    if os.path.isfile(repo.TRANSLOG_PATH):
        os.remove(repo.TRANSLOG_PATH)
    root_side = os.path.join(repo.REPO_ROOT, "transparency.root")
    if os.path.isfile(root_side):
        os.remove(root_side)
    repo.save_registry({"warden_registry_version": repo.REGISTRY_VERSION,
                        "updated_at": DEMO_AS_OF, "curator_fingerprint": None, "skills": {}})
    seed = repo.load_curator_seed()
    translog = TransparencyLog(repo.TRANSLOG_PATH)
    rc = 0
    for skill_dir in repo.discover_skill_dirs(include_samples=False):
        skill_id = _skill_id_for(skill_dir)
        obs = _DEMO_OBSERVATION.get(skill_id, {})
        try:
            res = sign_skill(skill_dir, seed, observation=obs, as_of=DEMO_AS_OF, translog=translog)
            print(f"  signed {res['skill']:<32} {badge(res['trust'])}")
        except Exception as exc:
            print(f"  REFUSED {skill_id}: {exc}", file=sys.stderr)
            rc = 1
    # also sign knowledge packs into the same transparency log
    from . import kpack
    for pd in kpack.discover():
        try:
            r = kpack.sign_kpack(pd, seed, as_of=DEMO_AS_OF, translog=translog)
            print(f"  signed kpack knowledge/{r['kpack']:<24} [Warden KPACK ✓]")
        except Exception as exc:
            print(f"  REFUSED kpack {pd}: {exc}", file=sys.stderr)
            rc = 1
    print(f"transparency root: {translog.current_root()} ({translog.count()} entries)")
    return rc


def cmd_verify(args: List[str]) -> int:
    if not args:
        print("usage: warden verify <skill_dir>", file=sys.stderr)
        return 2
    pub = repo.load_curator_pub() if os.path.isfile(repo.CURATOR_PUB) else None
    translog = TransparencyLog(repo.TRANSLOG_PATH) if os.path.isfile(repo.TRANSLOG_PATH) else None
    v = verify_skill(args[0], trusted_pub=pub, translog=translog)
    print(f"{args[0]}: {v['verdict']}")
    for c in v["checks"]:
        mark = "ok " if c["ok"] else "XX "
        print(f"  [{mark}] {c['check']:<24} {c['detail']}")
    return 0 if v["ok"] else 1


def cmd_verify_all(args: List[str]) -> int:
    pub = repo.load_curator_pub() if os.path.isfile(repo.CURATOR_PUB) else None
    translog = TransparencyLog(repo.TRANSLOG_PATH) if os.path.isfile(repo.TRANSLOG_PATH) else None
    reg = repo.load_registry()
    rc = 0
    for skill_id, row in sorted(reg.get("skills", {}).items()):
        skill_dir = os.path.join(repo.REPO_ROOT, row["dir"])
        v = verify_skill(skill_dir, trusted_pub=pub, translog=translog)
        n_ok = sum(1 for c in v["checks"] if c["ok"])
        print(f"  {v['verdict']:<9} {skill_id:<32} {n_ok}/{len(v['checks'])} checks")
        if not v["ok"]:
            rc = 1
            for c in v["failed"]:
                print(f"      XX {c['check']}: {c['detail']}")
    return rc


def cmd_trust(args: List[str]) -> int:
    if not args:
        print("usage: warden trust <skill_id>", file=sys.stderr)
        return 2
    reg = repo.load_registry()
    row = reg.get("skills", {}).get(args[0])
    if not row:
        print(f"no skill '{args[0]}' in registry. Try: warden list", file=sys.stderr)
        return 1
    skill_dir = os.path.join(repo.REPO_ROOT, row["dir"])
    pub = repo.load_curator_pub() if os.path.isfile(repo.CURATOR_PUB) else None
    translog = TransparencyLog(repo.TRANSLOG_PATH) if os.path.isfile(repo.TRANSLOG_PATH) else None
    v = verify_skill(skill_dir, trusted_pub=pub, translog=translog)
    t = v.get("trust", {})
    print(f"{args[0]}  {badge(row['trust'])}  (verified now: {v['verdict']})")
    print(f"  capabilities: {t.get('capability_summary')}")
    print(f"  pinned hash : {row['bundle_digest']}")
    print("  rationale:")
    for r in t.get("rationale", []):
        print(f"    - {r}")
    return 0


def cmd_list(args: List[str]) -> int:
    reg = repo.load_registry()
    skills = reg.get("skills", {})
    print(f"Warden registry -- curator {reg.get('curator_fingerprint')} -- {len(skills)} skill(s)")
    for skill_id, row in sorted(skills.items()):
        print(f"  {badge(row['trust']):<22} {skill_id:<32} v{row['version']}")
        print(f"      {row['summary']}")
        print(f"      caps: {row['capabilities_summary']}  | {row['bundle_digest'][:23]}...")
    return 0


def cmd_audit(args: List[str]) -> int:
    if not os.path.isfile(repo.TRANSLOG_PATH):
        print("no transparency log yet. Run: warden sign-all")
        return 1
    translog = TransparencyLog(repo.TRANSLOG_PATH)
    ok, errs = translog.verify()
    print(f"transparency log: {translog.count()} entries, root {translog.current_root()}, "
          f"integrity {'OK' if ok else 'FAILED'}")
    for e in translog.entries():
        print(f"  #{e['seq']} {e['action']:<7} {e['skill']:<32} v{e['version']} "
              f"trust {e['trust_grade']}/{e['trust_score']} {e['bundle_digest'][:19]}...")
    if not ok:
        print("ERRORS:")
        for x in errs:
            print(f"  - {x}")
    return 0 if ok else 1


def cmd_serve(args: List[str]) -> int:
    from .node import WardenNode
    WardenNode().serve()
    return 0


def cmd_selftest(args: List[str]) -> int:
    from ._selftest import run
    return run()


def cmd_version(args: List[str]) -> int:
    print(f"warden {__version__}")
    return 0


# ---------------------------------------------------------------- Phase 1-4 --
def cmd_run_code(args: List[str]) -> int:
    if not args:
        print("usage: warden run-code <skill_dir> [json_input]", file=sys.stderr)
        return 2
    from . import sandbox, manifest as M
    skill_dir = args[0]
    inp = json.loads(args[1]) if len(args) > 1 else {}
    m = M.load(skill_dir)
    if m.get("kind") != "code":
        print(f"{skill_dir} is not a code skill (kind={m.get('kind')})", file=sys.stderr)
        return 2
    res = sandbox.run_code_skill(skill_dir, m, inp)
    verdict = "OK" if res.get("ok") else ("TIMED OUT" if res.get("timed_out") else "ERROR")
    print(f"sandboxed run [{verdict}]  output: {json.dumps(res.get('output'))}")
    print(f"  enforced: network={res['policy']['network']}, shell={res['policy']['shell']}, "
          f"env=scrubbed, profile={res['policy']['profile']}")
    for v in res.get("violations", []):
        print(f"  {v}")
    return 0 if res.get("ok") else 1


def cmd_memory(args: List[str]) -> int:
    from .memory import MemoryStore
    sub = args[0] if args else "list"
    store = MemoryStore("local")
    if sub == "remember":
        text = " ".join(args[1:])
        if not text:
            print("usage: warden memory remember <text>", file=sys.stderr); return 2
        print("remembered:", store.remember(text))
    elif sub == "recall":
        for h in store.recall(" ".join(args[1:]), k=8):
            print(f"  - {h['text']}" + (f"  [{', '.join(h['tags'])}]" if h.get("tags") else ""))
    elif sub == "stats":
        print(json.dumps(store.stats(), indent=2))
    else:  # list
        for e in store.all():
            print(f"  {e['id']}  {e['text']}")
        print(f"({len(store.all())} entries, encrypted at rest)")
    return 0


def cmd_update(args: List[str]) -> int:
    if len(args) < 2:
        print("usage: warden update <skill_id> <candidate_dir> [--apply]", file=sys.stderr)
        return 2
    from . import update
    skill_id, candidate = args[0], args[1]
    reg = repo.load_registry(); row = reg.get("skills", {}).get(skill_id)
    installed = os.path.join(repo.REPO_ROOT, row["dir"]) if row else None
    d = update.evaluate_update(skill_id, candidate, installed_dir=installed)
    print(f"update {skill_id}: {d['action'].upper()}")
    print(f"  caps: {d.get('old_capabilities')}  ->  {d.get('new_capabilities')}")
    for r in d["reasons"]:
        print(f"  {r}")
    if "--apply" in args and d["action"] == "apply" and installed:
        seed = repo.load_curator_seed()
        obs = _DEMO_OBSERVATION.get(skill_id, {})
        res = update.apply_update(skill_id, candidate, seed, installed_dir=installed,
                                  as_of=DEMO_AS_OF, observation=obs)
        print("  APPLIED — re-signed:", badge(res["trust"]) if res.get("applied") else "no")
    return 0 if d["action"] == "apply" else 1


def cmd_scan_report(args: List[str]) -> int:
    if not args:
        print("usage: warden scan-report <skill_dir> [--sign]", file=sys.stderr); return 2
    from . import report
    seed = repo.load_curator_seed() if ("--sign" in args and os.path.isfile(repo.CURATOR_SEED)) else None
    signed = report.build_scan_report(args[0], seed=seed,
                                      observation=_DEMO_OBSERVATION.get(_skill_id_for(args[0]), {}),
                                      as_of=DEMO_AS_OF)
    print(report.render_report(signed))
    return 0


def cmd_policy(args: List[str]) -> int:
    from . import orgpolicy, manifest as M
    sub = args[0] if args else "show"
    if sub == "init":
        if os.path.isfile(repo.ORG_POLICY) and "--force" not in args:
            print(f"{repo.rel(repo.ORG_POLICY)} exists (use --force).", file=sys.stderr); return 1
        with open(repo.ORG_POLICY, "w", encoding="utf-8") as fh:
            json.dump(orgpolicy.example_policy(), fh, indent=2)
        print(f"wrote example org policy -> {repo.rel(repo.ORG_POLICY)}")
    elif sub == "check":
        eng = orgpolicy.PolicyEngine(); reg = repo.load_registry()
        for sid, row in sorted(reg.get("skills", {}).items()):
            m = M.load(os.path.join(repo.REPO_ROOT, row["dir"]))
            allowed, reasons = eng.evaluate(row, m)
            print(f"  {'ALLOW' if allowed else 'DENY ':<6} {sid:<32} {'' if allowed else reasons[0]}")
    else:  # show
        print(json.dumps(orgpolicy.load_policy(), indent=2))
    return 0


def cmd_audit_log(args: List[str]) -> int:
    from .audit import AuditLog
    if not os.path.isfile(repo.AUDIT_LOG):
        print("no audit log yet (the node writes it as it runs)."); return 0
    al = AuditLog(); ok, errs = al.verify()
    print(f"audit log: {al.count()} entries, integrity {'OK' if ok else 'FAILED'}")
    for e in al.tail(int(args[0]) if args and args[0].isdigit() else 25):
        print(f"  #{e['seq']} {e['event']:<14} {json.dumps(e['fields'], ensure_ascii=False)}")
    return 0 if ok else 1


def cmd_serve_api(args: List[str]) -> int:
    from .api import run_api
    host = "127.0.0.1"; port = 8799
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        if a == "--host" and i + 1 < len(args):
            host = args[i + 1]
    seed = repo.load_curator_seed() if ("--sign" in args and os.path.isfile(repo.CURATOR_SEED)) else None
    run_api(host=host, port=port, seed=seed)
    return 0


def cmd_build_index(args: List[str]) -> int:
    from . import index_build
    out = args[0] if args and not args[0].startswith("-") else os.path.join(repo.REPO_ROOT, "site", "registry")
    seed = repo.load_curator_seed() if os.path.isfile(repo.CURATOR_SEED) else None
    res = index_build.write_index(out, seed=seed, as_of=DEMO_AS_OF)
    print(f"built trust-graded index -> {res['out']}  "
          f"({res['skills']} skills, {res['kpacks']} kpacks, signed={res['signed']})")
    return 0


def cmd_host(args: List[str]) -> int:
    if not args:
        print("usage: warden host <skill_dir>   (sign your own skill, marked private)", file=sys.stderr)
        return 2
    seed = repo.load_curator_seed()
    translog = TransparencyLog(repo.TRANSLOG_PATH)
    try:
        res = sign_skill(args[0], seed, observation=_DEMO_OBSERVATION.get(_skill_id_for(args[0]), {}),
                         as_of=DEMO_AS_OF, translog=translog, visibility="private")
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr); return 1
    print(f"hosted (private) {res['skill']}  {badge(res['trust'])}")
    return 0


def cmd_kpack(args: List[str]) -> int:
    from . import kpack
    sub = args[0] if args else "list"
    if sub == "sign" and len(args) > 1:
        seed = repo.load_curator_seed(); translog = TransparencyLog(repo.TRANSLOG_PATH)
        r = kpack.sign_kpack(args[1], seed, as_of=DEMO_AS_OF, translog=translog)
        print(f"signed knowledge/{r['kpack']}  {r['digest'][:23]}...")
    elif sub == "verify" and len(args) > 1:
        pub = repo.load_trust_roots()
        v = kpack.verify_kpack(args[1], trusted_pubs=pub,
                               translog=TransparencyLog(repo.TRANSLOG_PATH) if os.path.isfile(repo.TRANSLOG_PATH) else None)
        print(f"{args[1]}: {v['verdict']} ({sum(1 for c in v['checks'] if c['ok'])}/{len(v['checks'])})")
    else:  # list
        for pd in kpack.discover():
            m = kpack.load_manifest(pd)
            print(f"  knowledge/{m['name']:<24} v{m['version']}  {m['title']}")
    return 0


def cmd_add_root(args: List[str]) -> int:
    if len(args) < 2:
        print("usage: warden add-root <pubkey_hex> <name>", file=sys.stderr); return 2
    repo.add_trust_root(args[0], args[1], DEMO_AS_OF)
    print(f"added trust root '{args[1]}' -> {repo.rel(repo.TRUST_ROOTS)}")
    print("the node will now also trust skills signed by this curator.")
    return 0


_COMMANDS = {
    "keygen": cmd_keygen, "scan": cmd_scan, "sign": cmd_sign, "sign-all": cmd_sign_all,
    "verify": cmd_verify, "verify-all": cmd_verify_all, "trust": cmd_trust,
    "list": cmd_list, "audit": cmd_audit, "serve": cmd_serve,
    "selftest": cmd_selftest, "version": cmd_version,
    # Phase 1-4
    "run-code": cmd_run_code, "memory": cmd_memory, "update": cmd_update,
    "scan-report": cmd_scan_report, "policy": cmd_policy, "audit-log": cmd_audit_log,
    "serve-api": cmd_serve_api, "build-index": cmd_build_index, "host": cmd_host,
    "kpack": cmd_kpack, "add-root": cmd_add_root,
}


def _harden_stdio() -> None:
    """Force UTF-8 on stdout/stderr so trust badges (✓) print on any console
    (Windows defaults to a legacy codepage that cannot encode them)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _harden_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    fn = _COMMANDS.get(cmd)
    if not fn:
        print(f"unknown command: {cmd}\n{__doc__}", file=sys.stderr)
        return 2
    try:
        return fn(rest)
    except (scanner.ScanError, manifest.ManifestError) as exc:
        # expected input errors (bad path, missing/invalid manifest) — one clean line
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except Exception as exc:  # a user should never see a raw traceback
        if os.environ.get("WARDEN_DEBUG"):
            raise
        print(f"warden: {type(exc).__name__}: {exc}  (set WARDEN_DEBUG=1 for the trace)",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
