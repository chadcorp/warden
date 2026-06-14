"""
Safe auto-update (Phase 2 PRO).

The danger in "auto-update" is the rug-pull-via-update: a benign skill that, on
its next version, quietly asks for the network or starts reading secrets. So an
update is never applied blindly. The gate REFUSES a candidate that:

  * has an invalid manifest or capabilities exceeding its sandbox profile,
  * is rejected by the intake scanner, or
  * ESCALATES privileges vs the installed version (new network/fs/shell/secret
    capability, or a widened allowlist) -- this requires a human review.

Otherwise it re-signs the new version, re-scores it, and records it in the
transparency log. Re-verify + re-score on every pull.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from . import manifest as manifest_mod, repo, scanner
from .policy import within_envelope


def _caps_escalated(old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    old = old or {}
    new = new or {}

    on, nn = old.get("network", "none"), new.get("network", "none")
    if on == "none" and nn != "none":
        reasons.append("network: none -> declared (new outbound capability)")
    elif isinstance(on, list) and isinstance(nn, list) and set(nn) - set(on):
        reasons.append(f"network allowlist widened: +{sorted(set(nn) - set(on))}")
    elif on == "none" and isinstance(nn, list):
        reasons.append("network: none -> allowlist")

    for key, label in (("filesystem_read", "fs-read"), ("filesystem_write", "fs-write")):
        added = set(new.get(key, []) or []) - set(old.get(key, []) or [])
        if added:
            reasons.append(f"{label} paths added: {sorted(added)}")
    for key in ("shell", "subprocess", "secrets"):
        if (not old.get(key, False)) and new.get(key, False):
            reasons.append(f"{key}: false -> true (new capability)")
    return (len(reasons) > 0), reasons


def evaluate_update(skill_id: str, candidate_dir: str, *,
                    installed_dir: Optional[str] = None) -> Dict[str, Any]:
    reasons: List[str] = []
    action = "apply"

    if installed_dir is None:
        reg = repo.load_registry()
        row = reg.get("skills", {}).get(skill_id)
        installed_dir = os.path.join(repo.REPO_ROOT, row["dir"]) if row else None

    # candidate must be signable
    try:
        cm = manifest_mod.load(candidate_dir)
        ok, errs = manifest_mod.validate(cm)
    except Exception as exc:
        return {"action": "refuse", "reasons": [f"candidate manifest error: {exc}"]}
    if not ok:
        return {"action": "refuse", "reasons": ["candidate manifest invalid: " + "; ".join(errs)]}

    fits, viol = within_envelope(cm.get("sandbox_profile", ""), cm.get("capabilities", {}))
    if not fits:
        return {"action": "refuse", "reasons": ["candidate caps exceed sandbox profile: " + "; ".join(viol)]}

    scan = scanner.scan_bundle(candidate_dir, cm)
    if scan.verdict == "reject":
        return {"action": "refuse", "reasons": [f"candidate scan rejects: {scanner.summarize(scan)}"],
                "scan": scan.to_dict()}

    new_caps = cm.get("capabilities", {})
    old_caps: Dict[str, Any] = {}
    if installed_dir and os.path.isfile(os.path.join(installed_dir, manifest_mod.MANIFEST_FILENAME)):
        try:
            old_caps = manifest_mod.load(installed_dir).get("capabilities", {})
        except Exception:
            old_caps = {}

    escalated, esc_reasons = _caps_escalated(old_caps, new_caps)
    if escalated:
        action = "refuse"
        reasons.append("PRIVILEGE ESCALATION on update — requires human review:")
        reasons.extend("  - " + r for r in esc_reasons)

    if scan.verdict == "flag":
        reasons.append(f"note: candidate has scan flags ({scanner.summarize(scan)}) — review advised")

    return {
        "action": action,
        "skill": skill_id,
        "reasons": reasons or ["clean: no privilege escalation, scan not rejected"],
        "old_capabilities": manifest_mod.capability_summary(old_caps),
        "new_capabilities": manifest_mod.capability_summary(new_caps),
        "scan": scan.to_dict(),
    }


def apply_update(skill_id: str, candidate_dir: str, seed: bytes, *,
                 installed_dir: str, as_of: str = "1970-01-01",
                 observation: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Apply only if evaluate_update says 'apply'. Replaces the installed bundle
    and re-signs it (caller supplies a live transparency log via sign)."""
    from .sign import sign_skill
    from .translog import TransparencyLog

    decision = evaluate_update(skill_id, candidate_dir, installed_dir=installed_dir)
    if decision["action"] != "apply":
        return {"applied": False, "decision": decision}

    # replace installed content with candidate (excluding the old signature)
    for name in os.listdir(installed_dir):
        if name == "skill.sig.json":
            continue
        path = os.path.join(installed_dir, name)
        shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    for name in os.listdir(candidate_dir):
        src = os.path.join(candidate_dir, name)
        dst = os.path.join(installed_dir, name)
        shutil.copytree(src, dst) if os.path.isdir(src) else shutil.copy2(src, dst)

    translog = TransparencyLog(repo.TRANSLOG_PATH)
    res = sign_skill(installed_dir, seed, observation=observation or {}, as_of=as_of,
                     translog=translog)
    return {"applied": True, "decision": decision, "trust": res["trust"]}
