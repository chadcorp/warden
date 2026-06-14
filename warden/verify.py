"""
Verify a skill bundle -- cold, trusting nothing.

This is what the node (and any agent) runs before exposing or using a skill. It
re-derives everything from the bytes on disk and the curator's public key:

  1. signature record present + well-formed
  2. manifest valid + caps fit the declared sandbox profile
  3. bundle digest RE-DERIVED from current files == the signed digest
        -> this is the rug-pull catch: change one byte, this fails
  4. (optional) re-derived digest == a caller-pinned hash
  5. Ed25519 signature verifies under the trusted curator key
  6. intake scan RE-RUN now does not reject
  7. trust score RE-COMPUTED from the signed inputs == the signed score
  8. (optional) entry present in a verifying transparency log

Any failure => verdict FAILED with reasons. Nothing is taken on faith; the
score is recomputed, not believed.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, List, Optional

from . import ed25519, manifest as manifest_mod, scanner, trust as trust_mod
from .canonical import canonicalize
from .content_address import bundle_digest, digest_obj
from .policy import within_envelope
from .sign import SIGNATURE_FILENAME
from .translog import TransparencyLog


def _load_sig(skill_dir: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(skill_dir, SIGNATURE_FILENAME)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_skill(
    skill_dir: str,
    *,
    trusted_pub: Optional[bytes] = None,
    trusted_pubs: Optional[List[bytes]] = None,
    pinned_digest: Optional[str] = None,
    translog: Optional[TransparencyLog] = None,
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    sig = _load_sig(skill_dir)
    if not check("signed", sig is not None, "skill.sig.json present"):
        return _result(skill_dir, False, checks, None)

    payload = sig.get("payload", {})

    # manifest valid + within profile
    try:
        m = manifest_mod.load(skill_dir)
        ok_m, errs = manifest_mod.validate(m)
    except Exception as exc:
        ok_m, errs, m = False, [str(exc)], {}
    check("manifest_valid", ok_m, "; ".join(errs) if errs else "ok")
    if ok_m:
        fits, viol = within_envelope(m.get("sandbox_profile", ""), m.get("capabilities", {}))
        check("caps_within_profile", fits, "; ".join(viol) if viol else "ok")

    # content digest re-derivation (rug-pull catch)
    rederived = bundle_digest(skill_dir)
    signed_digest = payload.get("bundle_digest")
    check("digest_matches_signature", rederived == signed_digest,
          f"re-derived {rederived} vs signed {signed_digest}")
    if pinned_digest is not None:
        check("matches_pinned_digest", rederived == pinned_digest,
              f"re-derived {rederived} vs pinned {pinned_digest}")

    # manifest digest
    if ok_m:
        check("manifest_digest_matches", digest_obj(m) == payload.get("manifest_digest"),
              "manifest content unchanged since signing")

    # signature verification
    pub_hex = payload.get("curator_key", "")
    try:
        sig_pub = bytes.fromhex(pub_hex)
    except Exception:
        sig_pub = b""
    sig_bytes = b""
    try:
        sig_bytes = base64.b64decode(sig.get("signature", ""))
    except Exception:
        pass
    sig_ok = bool(sig_pub) and ed25519.verify(sig_pub, canonicalize(payload), sig_bytes)
    check("signature_valid", sig_ok, f"ed25519 over canonical payload (curator {payload.get('curator_fingerprint','?')})")

    # the signing key is a curator we trust (single pin, or any trusted root)
    if trusted_pubs is not None:
        ok_root = sig_pub in trusted_pubs
        check("trusted_curator", ok_root,
              f"signed by a trusted root ({payload.get('curator_fingerprint','?')})" if ok_root
              else "signed by a key not in the trust roots")
    elif trusted_pub is not None:
        check("trusted_curator", sig_pub == trusted_pub,
              "signed by the expected curator key" if sig_pub == trusted_pub
              else "signed by a DIFFERENT key than the trusted curator")

    # re-run intake scan now
    rescan = scanner.scan_bundle(skill_dir, m if ok_m else None)
    check("scan_not_rejected", rescan.verdict != "reject", scanner.summarize(rescan))

    # recompute trust from signed inputs == signed score (reproducible, not believed)
    ti = payload.get("trust_inputs", {})
    recomputed_trust = trust_mod.compute_trust(
        scan_result=rescan.to_dict(),
        capabilities=(m.get("capabilities", {}) if ok_m else {}),
        sandbox_profile=(m.get("sandbox_profile", "") if ok_m else ""),
        history=ti.get("history", {}),
        observation=ti.get("observation", {}),
        has_tests=ti.get("has_tests", False),
        as_of=ti.get("as_of", payload.get("signed_at", "1970-01-01")),
    )
    signed_score = payload.get("trust", {}).get("score")
    check("trust_reproducible", recomputed_trust["score"] == signed_score,
          f"recomputed {recomputed_trust['score']} vs signed {signed_score}")

    # transparency-log inclusion
    if translog is not None:
        log_ok, log_errs = translog.verify()
        check("translog_integrity", log_ok, "; ".join(log_errs) if log_errs else "chain + hashes intact")
        entry = translog.find(payload.get("skill", ""), payload.get("version", ""))
        check("translog_inclusion",
              entry is not None and entry.get("bundle_digest") == rederived,
              "publish entry present with matching digest" if entry else "no publish entry found")

    verdict_ok = all(c["ok"] for c in checks)
    return _result(skill_dir, verdict_ok, checks, recomputed_trust)


def _result(skill_dir, ok, checks, trust):
    return {
        "skill_dir": skill_dir,
        "verdict": "VERIFIED" if ok else "FAILED",
        "ok": ok,
        "checks": checks,
        "failed": [c for c in checks if not c["ok"]],
        "trust": trust,
    }
