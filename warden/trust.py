"""
Behavioral trust score -- the durable moat.

NOT a static identity badge. A score in [0, 100] recomputed PER VERSION from:

  * intake scan results (post-waiver),
  * least-privilege of the declared capabilities,
  * version history (prior yanks / incidents),
  * accrued clean OBSERVATION (runs + days with no incident) -- the time-aware
    part: a brand-new version is PROVISIONAL and capped until it earns trust.

Re-publishing re-evaluates from scratch. "Verification of identity is not
verification of behavior": a signature proves who, this score estimates how
*well-behaved*, and it can fall on the next version.

Determinism: this function never reads the clock. The observation window and an
`as_of` date are passed in, so the score is fully reproducible -- anyone can
recompute it from the signed inputs and get the same number.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .content_address import digest_obj
from . import manifest as manifest_mod

TRUST_VERSION = "1.0"

# severity -> (per-finding penalty, max total penalty for that severity)
_PENALTY = {
    "CRITICAL": (100, 100),   # any un-waived critical => rejected anyway
    "HIGH": (25, 60),
    "MEDIUM": (8, 24),
    "LOW": (3, 9),
    "ACK": (4, 16),           # waived findings still cost -- exceptions aren't free
    "INFO": (0, 0),
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_trust(
    *,
    scan_result: Dict[str, Any],
    capabilities: Dict[str, Any],
    sandbox_profile: str,
    history: Dict[str, int] = None,
    observation: Dict[str, int] = None,
    has_tests: bool = False,
    as_of: str = "1970-01-01",
) -> Dict[str, Any]:
    history = history or {}
    observation = observation or {}
    caps = capabilities or {}
    rationale: List[str] = []

    counts = scan_result.get("counts", {})
    verdict = scan_result.get("verdict", "pass")

    # Hard reject on any un-waived CRITICAL.
    if counts.get("CRITICAL", 0) > 0 or verdict == "reject":
        return {
            "trust_version": TRUST_VERSION,
            "score": 0,
            "grade": "F",
            "status": "rejected",
            "provisional": False,
            "provisional_cap": 0,
            "as_of": as_of,
            "scan_verdict": verdict,
            "capability_summary": manifest_mod.capability_summary(caps),
            "rationale": ["REJECTED: un-waived CRITICAL finding(s) at intake; "
                          "skill is not eligible to be trusted or exposed."],
            "inputs_digest": _inputs_digest(scan_result, caps, sandbox_profile,
                                            history, observation, has_tests),
        }

    score = 100
    rationale.append("baseline 100 (no critical findings at intake)")

    # 1) scan-finding penalties (post-waiver)
    for sev in ("HIGH", "MEDIUM", "LOW", "ACK"):
        n = counts.get(sev, 0)
        if n:
            per, cap = _PENALTY[sev]
            pen = min(n * per, cap)
            score -= pen
            label = "waived/acknowledged" if sev == "ACK" else sev
            rationale.append(f"-{pen} for {n} {label} finding(s)")

    # 2) least privilege
    if manifest_mod.is_minimal(caps):
        rationale.append("+0 least-privilege: declares zero capabilities (cannot leak)")
    else:
        dims = 0
        for grant in ("network", "filesystem_read", "filesystem_write",
                      "shell", "subprocess", "secrets"):
            v = caps.get(grant, "none" if grant == "network" else False)
            if (grant == "network" and v != "none") or (grant != "network" and v):
                dims += 1
        pen = min(dims * 3, 15)
        if pen:
            score -= pen
            rationale.append(f"-{pen} least-privilege pressure ({dims} capability dimension(s) requested)")
    if sandbox_profile == "trusted-exec":
        score = min(score, 70)
        rationale.append("capped at 70: 'trusted-exec' profile carries broad capability")

    # 3) version history
    yanks = int(history.get("prior_yanks", 0))
    incidents = int(history.get("prior_incidents", 0))
    if yanks:
        score -= min(yanks * 20, 40)
        rationale.append(f"-{min(yanks*20,40)} for {yanks} prior yank(s)")
    if incidents:
        score -= min(incidents * 15, 45)
        rationale.append(f"-{min(incidents*15,45)} for {incidents} prior incident(s)")

    # 4) tests
    if has_tests:
        score = min(100, score + 3)
        rationale.append("+3 declares tests")

    # 5) observed incidents on THIS version
    obs_incidents = int(observation.get("incidents", 0))
    if obs_incidents:
        score -= min(obs_incidents * 30, 60)
        rationale.append(f"-{min(obs_incidents*30,60)} for {obs_incidents} observed incident(s) this version")

    # 6) time-aware provisional cap (trust accrues with clean observation)
    clean_runs = max(0, int(observation.get("clean_runs", 0)))
    observed_days = max(0, int(observation.get("observed_days", 0)))
    cap = 75 + min(clean_runs, 50) * 0.3 + min(observed_days, 60) * 0.25
    provisional_cap = int(min(100, round(cap)))
    provisional = provisional_cap < 100
    if provisional and score > provisional_cap:
        rationale.append(
            f"capped at {provisional_cap}: PROVISIONAL -- only {clean_runs} clean run(s) / "
            f"{observed_days} day(s) observed; trust rises as clean observation accrues")
        score = provisional_cap
    elif provisional:
        rationale.append(
            f"provisional ceiling {provisional_cap} (not binding; score already below it)")

    score = max(0, min(100, int(round(score))))

    return {
        "trust_version": TRUST_VERSION,
        "score": score,
        "grade": _grade(score),
        "status": "trusted",
        "provisional": provisional,
        "provisional_cap": provisional_cap,
        "as_of": as_of,
        "scan_verdict": verdict,
        "capability_summary": manifest_mod.capability_summary(caps),
        "rationale": rationale,
        "inputs_digest": _inputs_digest(scan_result, caps, sandbox_profile,
                                        history, observation, has_tests),
    }


def _inputs_digest(scan_result, caps, profile, history, observation, has_tests) -> str:
    return digest_obj({
        "counts": scan_result.get("counts", {}),
        "verdict": scan_result.get("verdict", "pass"),
        "caps": caps,
        "profile": profile,
        "history": history or {},
        "observation": observation or {},
        "has_tests": bool(has_tests),
    })


def badge(trust: Dict[str, Any]) -> str:
    """Compact provenance badge, e.g. '[Warden A/92 ✓]' or '[Warden PROVISIONAL B/82]'."""
    if trust.get("status") == "rejected":
        return "[Warden REJECTED]"
    tag = "PROVISIONAL " if trust.get("provisional") else ""
    return f"[Warden {tag}{trust['grade']}/{trust['score']} ✓]"
