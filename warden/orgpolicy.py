"""
Org allow/deny policy (Phase 3 TEAM) -- governance is what orgs actually pay for.

A team points its node at an `org-policy.json` that constrains which verified
skills may be exposed, regardless of whether they pass cryptographic
verification. Governance sits ON TOP of trust: a skill can be perfectly signed
and still be refused because, say, the org forbids the `secrets` capability or
won't run anything below a B grade.

The default policy is permissive (a solo dev needs no governance). Every field
is optional; only the fields you set are enforced.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

from . import repo

_GRADE_RANK = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}

DEFAULT_POLICY: Dict[str, Any] = {
    "warden_org_policy_version": "1.0",
    "name": "default (permissive)",
    "min_trust_grade": None,          # e.g. "B"
    "min_trust_score": None,          # e.g. 80
    "allow_provisional": True,        # allow versions still earning trust
    "allowed_sandbox_profiles": None, # e.g. ["isolated-no-net", "net-allowlist"]
    "forbid_capabilities": [],        # e.g. ["shell", "secrets", "subprocess"]
    "allowed_packs": None,            # allowlist; None = any
    "denied_packs": [],
    "allowed_authors": None,
    "denied_authors": [],
    "banned_scan_classes": [],        # e.g. ["secret-exfil"] -> deny if present un-waived
    "allowed_visibility": None,       # e.g. ["public"]
}


def load_policy() -> Dict[str, Any]:
    if os.path.isfile(repo.ORG_POLICY):
        with open(repo.ORG_POLICY, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        merged = dict(DEFAULT_POLICY)
        merged.update(user)
        return merged
    return dict(DEFAULT_POLICY)


class PolicyEngine:
    def __init__(self, policy: Dict[str, Any] = None):
        self.p = policy or load_policy()

    def evaluate(self, row: Dict[str, Any], manifest: Dict[str, Any],
                 signed_scan: Dict[str, Any] = None) -> Tuple[bool, List[str]]:
        """row: registry row; manifest: skill manifest; signed_scan: the signed
        scan summary (verdict/counts/findings) if available. Returns (allowed, reasons)."""
        p = self.p
        reasons: List[str] = []
        trust = row.get("trust", {})
        caps = manifest.get("capabilities", {}) or {}

        if p.get("min_trust_grade"):
            need = _GRADE_RANK.get(p["min_trust_grade"], 0)
            have = _GRADE_RANK.get(trust.get("grade", "F"), 0)
            if have < need:
                reasons.append(f"trust grade {trust.get('grade')} < required {p['min_trust_grade']}")
        if p.get("min_trust_score") is not None and trust.get("score", 0) < p["min_trust_score"]:
            reasons.append(f"trust score {trust.get('score')} < required {p['min_trust_score']}")
        if not p.get("allow_provisional", True) and trust.get("provisional"):
            reasons.append("provisional versions are not allowed by policy")

        profs = p.get("allowed_sandbox_profiles")
        if profs and row.get("sandbox_profile") not in profs:
            reasons.append(f"sandbox profile '{row.get('sandbox_profile')}' not in allowed {profs}")

        for cap in p.get("forbid_capabilities", []) or []:
            v = caps.get(cap, "none" if cap == "network" else False)
            if (cap == "network" and v != "none") or (cap != "network" and v):
                reasons.append(f"capability '{cap}' is forbidden by policy")

        pack = manifest.get("pack")
        if p.get("allowed_packs") is not None and pack not in p["allowed_packs"]:
            reasons.append(f"pack '{pack}' not in allowed packs")
        if pack in (p.get("denied_packs") or []):
            reasons.append(f"pack '{pack}' is denied")

        author = manifest.get("author")
        if p.get("allowed_authors") is not None and author not in p["allowed_authors"]:
            reasons.append(f"author '{author}' not in allowed authors")
        if author in (p.get("denied_authors") or []):
            reasons.append(f"author '{author}' is denied")

        vis = row.get("visibility", "public")
        if p.get("allowed_visibility") is not None and vis not in p["allowed_visibility"]:
            reasons.append(f"visibility '{vis}' not allowed")

        banned = set(p.get("banned_scan_classes", []) or [])
        if banned and signed_scan:
            present = {f["class"] for f in signed_scan.get("findings", [])
                       if f.get("severity") not in ("ACK", "INFO")}
            hit = banned & present
            if hit:
                reasons.append(f"banned scan class(es) present: {sorted(hit)}")

        return (len(reasons) == 0), reasons


def example_policy() -> Dict[str, Any]:
    """A realistic strict team policy, for `warden policy --init`."""
    return {
        "warden_org_policy_version": "1.0",
        "name": "acme-corp strict",
        "min_trust_grade": "B",
        "allow_provisional": False,
        "allowed_sandbox_profiles": ["isolated-no-net", "net-allowlist"],
        "forbid_capabilities": ["shell", "subprocess", "secrets"],
        "denied_packs": [],
        "banned_scan_classes": ["secret-exfil", "unsafe-exec"],
        "allowed_visibility": ["public", "private"],
    }
