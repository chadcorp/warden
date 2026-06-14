"""
Scan reports (Phase 2 "scan-your-own" / Phase 3 Scan API payload).

Produces a structured, shareable, optionally curator-signed report on any skill
bundle: the intake scan verdict + findings, the content digest, and the trust
estimate. A signed report is portable proof that "Warden scanned this at this
digest and got this result" -- the unit the supply-side Scan API sells.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from . import __version__, ed25519, manifest as manifest_mod, scanner, trust as trust_mod
from .canonical import canonicalize
from .content_address import bundle_digest

REPORT_VERSION = "1.0"


def build_scan_report(skill_dir: str, *, seed: Optional[bytes] = None,
                      observation: Optional[Dict[str, int]] = None,
                      as_of: str = "1970-01-01") -> Dict[str, Any]:
    try:
        m = manifest_mod.load(skill_dir)
        manifest_ok, manifest_errs = manifest_mod.validate(m)
    except Exception as exc:
        m, manifest_ok, manifest_errs = {}, False, [str(exc)]

    scan = scanner.scan_bundle(skill_dir, m or None)
    scan_dict = scan.to_dict()
    caps = (m or {}).get("capabilities", {})
    profile = (m or {}).get("sandbox_profile", "isolated-no-net")
    trust = trust_mod.compute_trust(
        scan_result=scan_dict, capabilities=caps, sandbox_profile=profile,
        observation=observation or {}, has_tests=bool((m or {}).get("tests")), as_of=as_of)

    report = {
        "warden_scan_report_version": REPORT_VERSION,
        "scanner_version": __version__,
        "skill": f"{m.get('pack','?')}/{m.get('name','?')}" if m else "?",
        "version": m.get("version") if m else None,
        "manifest_valid": manifest_ok,
        "manifest_errors": manifest_errs,
        "bundle_digest": bundle_digest(skill_dir),
        "scan": {
            "verdict": scan_dict["verdict"],
            "counts": scan_dict["counts"],
            "waivers": scan_dict["waivers"],
            "findings": scan_dict["findings"],
        },
        "trust": {
            "score": trust["score"], "grade": trust["grade"],
            "status": trust["status"], "provisional": trust["provisional"],
        },
        "scanned_at": as_of,
    }

    if seed is not None:
        pub = ed25519.public_key(seed)
        report["curator_key"] = pub.hex()
        report["curator_fingerprint"] = ed25519.fingerprint(pub)
        sig = ed25519.sign(seed, canonicalize(report))
        return {"report": report, "signature": base64.b64encode(sig).decode("ascii"),
                "algo": "ed25519"}
    return {"report": report}


def verify_scan_report(signed: Dict[str, Any], *, trusted_pub: Optional[bytes] = None) -> bool:
    if "signature" not in signed:
        return False
    report = signed["report"]
    try:
        pub = bytes.fromhex(report.get("curator_key", ""))
        sig = base64.b64decode(signed["signature"])
    except Exception:
        return False
    if trusted_pub is not None and pub != trusted_pub:
        return False
    return ed25519.verify(pub, canonicalize(report), sig)


def render_report(signed: Dict[str, Any]) -> str:
    r = signed.get("report", signed)
    lines = [
        f"Warden scan report — {r['skill']} v{r.get('version')}",
        f"  digest : {r['bundle_digest']}",
        f"  scan   : {r['scan']['verdict']}  {r['scan']['counts'] or '{clean}'}",
        f"  trust  : {r['trust']['grade']}/{r['trust']['score']} "
        f"({'provisional' if r['trust']['provisional'] else r['trust']['status']})",
    ]
    if signed.get("signature"):
        lines.append(f"  signed : {r.get('curator_fingerprint')} (portable proof)")
    for f in r["scan"]["findings"][:12]:
        lines.append(f"    [{f['severity']:<8}] {f['class']:<14} {f['file']}:{f['line']}  {f['message']}")
    return "\n".join(lines)
