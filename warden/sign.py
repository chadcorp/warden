"""
Sign a curated skill bundle.

The pipeline, end to end:

    validate manifest -> check caps fit the sandbox profile -> intake scan
    (refuse on un-waived CRITICAL) -> content-address the bundle -> compute the
    behavioral trust score -> sign the canonical record with the curator's
    Ed25519 key -> append to the transparency log -> update the registry.

Output: `skill.sig.json` written into the skill directory, a new transparency
log entry, and a registry row. The signature covers the content digest, the
declared capabilities, the scan summary, AND the trust inputs -- so a verifier
can reproduce the exact trust score, not merely take it on faith.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional

from . import ed25519, manifest as manifest_mod, repo, scanner, trust as trust_mod
from .canonical import canonicalize
from .content_address import bundle_digest, digest_obj
from .policy import within_envelope
from .translog import TransparencyLog

SIGNATURE_FILENAME = "skill.sig.json"
SIGNATURE_VERSION = "1.0"


class SignError(Exception):
    pass


def sign_skill(
    skill_dir: str,
    seed: bytes,
    *,
    history: Optional[Dict[str, int]] = None,
    observation: Optional[Dict[str, int]] = None,
    as_of: str = "1970-01-01",
    translog: Optional[TransparencyLog] = None,
    write: bool = True,
    update_registry: bool = True,
    visibility: str = "public",
) -> Dict[str, Any]:
    m = manifest_mod.load(skill_dir)
    ok, errors = manifest_mod.validate(m)
    if not ok:
        raise SignError("manifest invalid:\n  - " + "\n  - ".join(errors))

    profile = m["sandbox_profile"]
    caps = m.get("capabilities", {})
    fits, violations = within_envelope(profile, caps)
    if not fits:
        raise SignError("capabilities exceed sandbox profile:\n  - " + "\n  - ".join(violations))

    scan = scanner.scan_bundle(skill_dir, m)
    scan_dict = scan.to_dict()
    if scan.verdict == "reject":
        raise SignError(
            f"intake scan REJECTS this skill (un-waived CRITICAL finding). "
            f"{scanner.summarize(scan)}. Refusing to sign.")

    bdigest = bundle_digest(skill_dir)
    mdigest = digest_obj(m)

    has_tests = bool(m.get("tests"))
    trust_inputs = {
        "history": history or {},
        "observation": observation or {},
        "has_tests": has_tests,
        "as_of": as_of,
    }
    trust = trust_mod.compute_trust(
        scan_result=scan_dict,
        capabilities=caps,
        sandbox_profile=profile,
        history=trust_inputs["history"],
        observation=trust_inputs["observation"],
        has_tests=has_tests,
        as_of=as_of,
    )

    pub = ed25519.public_key(seed)
    skill_id = f"{m['pack']}/{m['name']}"

    payload = {
        "warden_skill_signature_version": SIGNATURE_VERSION,
        "skill": skill_id,
        "name": m["name"],
        "pack": m["pack"],
        "version": m["version"],
        "title": m["title"],
        "bundle_digest": bdigest,
        "manifest_digest": mdigest,
        "capabilities": caps,
        "sandbox_profile": profile,
        "scan": {
            "verdict": scan_dict["verdict"],
            "counts": scan_dict["counts"],
            "waivers": scan_dict["waivers"],
        },
        "trust": {
            "score": trust["score"],
            "grade": trust["grade"],
            "status": trust["status"],
            "provisional": trust["provisional"],
            "inputs_digest": trust["inputs_digest"],
        },
        "trust_inputs": trust_inputs,
        "curator_key": pub.hex(),
        "curator_fingerprint": ed25519.fingerprint(pub),
        "signed_at": as_of,
    }

    sig = ed25519.sign(seed, canonicalize(payload))
    sig_record = {
        "algo": "ed25519",
        "payload": payload,
        "signature": base64.b64encode(sig).decode("ascii"),
    }

    result = {
        "skill": skill_id,
        "version": m["version"],
        "bundle_digest": bdigest,
        "trust": trust,
        "scan": scan_dict,
        "signature_record": sig_record,
        "dir": skill_dir,
    }

    if write:
        import json
        with open(os.path.join(skill_dir, SIGNATURE_FILENAME), "w", encoding="utf-8") as fh:
            json.dump(sig_record, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

        if translog is not None:
            entry = translog.append({
                "action": "publish",
                "timestamp": as_of,
                "skill": skill_id,
                "version": m["version"],
                "bundle_digest": bdigest,
                "manifest_digest": mdigest,
                "trust_score": trust["score"],
                "trust_grade": trust["grade"],
                "curator": ed25519.fingerprint(pub),
                "signature": sig_record["signature"],
            })
            result["translog_seq"] = entry["seq"]
            result["entry_hash"] = entry["entry_hash"]

        if update_registry:
            _update_registry(m, skill_dir, bdigest, mdigest, trust, pub,
                             result.get("translog_seq"), visibility)

    return result


def _update_registry(m, skill_dir, bdigest, mdigest, trust, pub, seq, visibility="public"):
    reg = repo.load_registry()
    skill_id = f"{m['pack']}/{m['name']}"
    reg["curator_fingerprint"] = ed25519.fingerprint(pub)
    reg["updated_at"] = m.get("version") and trust["as_of"]
    reg.setdefault("skills", {})[skill_id] = {
        "name": m["name"],
        "pack": m["pack"],
        "version": m["version"],
        "title": m["title"],
        "summary": m["summary"],
        "tags": m.get("tags", []),
        "dir": repo.rel(skill_dir),
        "sig_file": repo.rel(os.path.join(skill_dir, SIGNATURE_FILENAME)),
        "bundle_digest": bdigest,
        "manifest_digest": mdigest,
        "sandbox_profile": m["sandbox_profile"],
        "kind": m.get("kind", "instructions"),
        "visibility": visibility,
        "capabilities_summary": manifest_mod.capability_summary(m.get("capabilities", {})),
        "trust": {
            "score": trust["score"], "grade": trust["grade"],
            "status": trust["status"], "provisional": trust["provisional"],
        },
        "translog_seq": seq,
    }
    repo.save_registry(reg)
