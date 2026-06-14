"""
Signed knowledge packs (Phase 1) -- read-only, signed, versioned reference
memory an agent can mount, with no injection path.

A knowledge pack is a directory under knowledge/<name>/ with a
`knowledge.manifest.json` plus content files. It is content-addressed and
Ed25519-signed exactly like a skill, and recorded in the same transparency log
(entries carry "type":"kpack"). Two differences from a skill:

  * it declares no capabilities and is never executed -- it is reference text;
  * it is still scanned for tool-poisoning at sign time, so mounted reference
    content cannot smuggle instructions into the agent ("no injection path").
"""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import ed25519, repo, scanner
from .canonical import canonicalize
from .content_address import bundle_digest, digest_obj
from .translog import TransparencyLog

KPACK_MANIFEST = "knowledge.manifest.json"
KPACK_SIG = "kpack.sig.json"
KPACK_VERSION = "1.0"
KPACK_REGISTRY = os.path.join(repo.KPACKS_DIR, "registry.json")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


class KpackError(Exception):
    pass


def load_manifest(pack_dir: str) -> Dict[str, Any]:
    path = os.path.join(pack_dir, KPACK_MANIFEST)
    if not os.path.isfile(path):
        raise KpackError(f"missing {KPACK_MANIFEST} in {pack_dir}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(m: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    if m.get("warden_kpack_version") != KPACK_VERSION:
        errs.append(f"warden_kpack_version must be '{KPACK_VERSION}'")
    for f in ("name", "version", "title", "summary", "author", "license"):
        if not isinstance(m.get(f), str) or not m.get(f):
            errs.append(f"'{f}' required")
    if isinstance(m.get("version"), str) and not _SEMVER.match(m["version"]):
        errs.append("'version' must be semver")
    if not isinstance(m.get("files", []), list):
        errs.append("'files' must be a list")
    return (not errs), errs


def discover() -> List[str]:
    out: List[str] = []
    if not os.path.isdir(repo.KPACKS_DIR):
        return out
    for entry in sorted(os.listdir(repo.KPACKS_DIR)):
        d = os.path.join(repo.KPACKS_DIR, entry)
        if os.path.isdir(d) and os.path.isfile(os.path.join(d, KPACK_MANIFEST)):
            out.append(d)
    return out


def sign_kpack(pack_dir: str, seed: bytes, *, as_of: str = "1970-01-01",
               translog: Optional[TransparencyLog] = None,
               update_registry: bool = True) -> Dict[str, Any]:
    m = load_manifest(pack_dir)
    ok, errs = validate(m)
    if not ok:
        raise KpackError("manifest invalid:\n  - " + "\n  - ".join(errs))

    # reject injection payloads in reference content
    scan = scanner.scan_bundle(pack_dir, {"capabilities": {}})
    poison = [f for f in scan.findings if f.klass == "tool-poisoning"
              and f.severity == "CRITICAL"]
    if poison:
        raise KpackError(f"refusing to sign: tool-poisoning in reference content "
                         f"({poison[0].file}:{poison[0].line})")

    digest = bundle_digest(pack_dir)
    mdigest = digest_obj(m)
    pub = ed25519.public_key(seed)
    payload = {
        "warden_kpack_signature_version": KPACK_VERSION,
        "kpack": m["name"], "version": m["version"], "title": m["title"],
        "bundle_digest": digest, "manifest_digest": mdigest,
        "scan": {"verdict": scan.verdict, "counts": scan.to_dict()["counts"]},
        "curator_key": pub.hex(), "curator_fingerprint": ed25519.fingerprint(pub),
        "signed_at": as_of,
    }
    sig = ed25519.sign(seed, canonicalize(payload))
    record = {"algo": "ed25519", "payload": payload,
              "signature": base64.b64encode(sig).decode("ascii")}
    with open(os.path.join(pack_dir, KPACK_SIG), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    if translog is not None:
        translog.append({
            "type": "kpack", "action": "publish", "timestamp": as_of,
            "skill": "knowledge/" + m["name"], "version": m["version"],
            "bundle_digest": digest, "manifest_digest": mdigest,
            "trust_score": 100, "trust_grade": "A",
            "curator": ed25519.fingerprint(pub), "signature": record["signature"],
        })

    if update_registry:
        _update_registry(m, pack_dir, digest, pub, as_of)
    return {"kpack": m["name"], "version": m["version"], "digest": digest, "record": record}


def verify_kpack(pack_dir: str, *, trusted_pub: Optional[bytes] = None,
                 trusted_pubs: Optional[List[bytes]] = None,
                 translog: Optional[TransparencyLog] = None) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def chk(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    sig_path = os.path.join(pack_dir, KPACK_SIG)
    if not chk("signed", os.path.isfile(sig_path)):
        return {"verdict": "FAILED", "ok": False, "checks": checks}
    with open(sig_path, "r", encoding="utf-8") as fh:
        sig = json.load(fh)
    payload = sig.get("payload", {})

    m = load_manifest(pack_dir)
    okm, errs = validate(m)
    chk("manifest_valid", okm, "; ".join(errs))

    rederived = bundle_digest(pack_dir)
    chk("digest_matches_signature", rederived == payload.get("bundle_digest"),
        f"{rederived} vs {payload.get('bundle_digest')}")

    try:
        pub = bytes.fromhex(payload.get("curator_key", ""))
        sig_bytes = base64.b64decode(sig.get("signature", ""))
        sig_ok = ed25519.verify(pub, canonicalize(payload), sig_bytes)
    except Exception:
        pub, sig_ok = b"", False
    chk("signature_valid", sig_ok)
    if trusted_pubs is not None:
        chk("trusted_curator", pub in trusted_pubs)
    elif trusted_pub is not None:
        chk("trusted_curator", pub == trusted_pub)

    rescan = scanner.scan_bundle(pack_dir, {"capabilities": {}})
    chk("no_injection", not any(f.klass == "tool-poisoning" and f.severity == "CRITICAL"
                                for f in rescan.findings))

    if translog is not None:
        entry = translog.find("knowledge/" + m["name"], m["version"])
        chk("translog_inclusion", entry is not None and entry.get("bundle_digest") == rederived)

    ok = all(c["ok"] for c in checks)
    return {"verdict": "VERIFIED" if ok else "FAILED", "ok": ok, "checks": checks,
            "name": m.get("name"), "title": m.get("title"), "version": m.get("version"),
            "digest": rederived}


def read_file(pack_dir: str, rel_path: str) -> Optional[str]:
    safe = os.path.normpath(rel_path).replace("\\", "/")
    if safe.startswith("..") or os.path.isabs(safe) or safe in (KPACK_SIG,):
        return None
    full = os.path.join(pack_dir, safe)
    if not os.path.isfile(full):
        return None
    with open(full, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _update_registry(m, pack_dir, digest, pub, as_of):
    os.makedirs(repo.KPACKS_DIR, exist_ok=True)
    reg = {"warden_kpack_registry_version": KPACK_VERSION, "updated_at": as_of,
           "curator_fingerprint": ed25519.fingerprint(pub), "packs": {}}
    if os.path.isfile(KPACK_REGISTRY):
        with open(KPACK_REGISTRY, "r", encoding="utf-8") as fh:
            reg = json.load(fh)
    reg["updated_at"] = as_of
    reg["curator_fingerprint"] = ed25519.fingerprint(pub)
    reg.setdefault("packs", {})[m["name"]] = {
        "name": m["name"], "version": m["version"], "title": m["title"],
        "summary": m["summary"], "tags": m.get("tags", []),
        "dir": repo.rel(pack_dir), "bundle_digest": digest,
        "files": m.get("files", []),
    }
    with open(KPACK_REGISTRY, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
