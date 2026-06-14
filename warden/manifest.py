"""
Capability manifest: load + validate + reason about least privilege.

Every Warden skill ships a `skill.manifest.json` that DECLARES exactly what the
skill may touch. The contract is deny-by-default: anything not explicitly
declared is denied at run time (see policy.py). A clean, minimal manifest is
itself a trust signal -- a skill that asks for nothing can leak nothing.

This is a hand-rolled validator (no third-party dependency) so the reference
node stays pure standard library. The canonical JSON Schema lives at
schema/skill-manifest.schema.json for editors and CI; the two are kept in sync.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Tuple

MANIFEST_FILENAME = "skill.manifest.json"
MANIFEST_VERSION = "1.0"

VALID_KINDS = {"instructions", "code"}
VALID_SANDBOX_PROFILES = {
    "isolated-no-net",   # no network, no fs, no shell, no secrets (default for instructions)
    "net-allowlist",     # network restricted to an explicit allowlist
    "fs-scoped",         # filesystem restricted to explicit path globs
    "trusted-exec",      # broad capability -- discouraged; trust score is capped
}

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")
_DOMAIN_RE = re.compile(r"^[a-z0-9.\-*]+(:\d+)?$", re.IGNORECASE)


class ManifestError(Exception):
    pass


def load(skill_dir: str) -> Dict[str, Any]:
    path = os.path.join(skill_dir, MANIFEST_FILENAME)
    if not os.path.isfile(path):
        raise ManifestError(f"missing {MANIFEST_FILENAME} in {skill_dir}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"{path}: invalid JSON: {exc}") from exc


def _err(errors: List[str], msg: str) -> None:
    errors.append(msg)


def validate(m: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Return (ok, errors). Empty errors == valid."""
    errors: List[str] = []

    if not isinstance(m, dict):
        return False, ["manifest must be a JSON object"]

    if m.get("warden_manifest_version") != MANIFEST_VERSION:
        _err(errors, f"warden_manifest_version must be '{MANIFEST_VERSION}'")

    for field in ("name", "pack", "version", "title", "summary", "author",
                  "license", "kind", "entrypoint", "sandbox_profile"):
        if not isinstance(m.get(field), str) or not m.get(field):
            _err(errors, f"'{field}' is required and must be a non-empty string")

    name = m.get("name", "")
    if isinstance(name, str) and name and not _NAME_RE.match(name):
        _err(errors, "'name' must be lowercase kebab-case, 3-50 chars")

    version = m.get("version", "")
    if isinstance(version, str) and version and not _SEMVER_RE.match(version):
        _err(errors, "'version' must be semver MAJOR.MINOR.PATCH")

    kind = m.get("kind")
    if kind not in VALID_KINDS:
        _err(errors, f"'kind' must be one of {sorted(VALID_KINDS)}")

    profile = m.get("sandbox_profile")
    if profile not in VALID_SANDBOX_PROFILES:
        _err(errors, f"'sandbox_profile' must be one of {sorted(VALID_SANDBOX_PROFILES)}")

    caps = m.get("capabilities")
    if not isinstance(caps, dict):
        _err(errors, "'capabilities' object is required (deny-by-default)")
        caps = {}
    else:
        errors.extend(_validate_caps(caps))

    # Consistency: the declared sandbox profile must match the declared caps.
    errors.extend(_validate_profile_consistency(profile, caps))

    inp = m.get("input_schema")
    if inp is not None and not isinstance(inp, dict):
        _err(errors, "'input_schema' must be a JSON Schema object if present")

    tests = m.get("tests", [])
    if not isinstance(tests, list):
        _err(errors, "'tests' must be a list of paths")

    tags = m.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        _err(errors, "'tags' must be a list of strings")

    return (len(errors) == 0), errors


def _validate_caps(caps: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    net = caps.get("network", "none")
    if net != "none":
        if not isinstance(net, list) or not all(isinstance(d, str) for d in net):
            errors.append("capabilities.network must be 'none' or a list of domains")
        else:
            for d in net:
                if not _DOMAIN_RE.match(d):
                    errors.append(f"capabilities.network domain looks invalid: {d!r}")

    for key in ("filesystem_read", "filesystem_write"):
        val = caps.get(key, [])
        if not isinstance(val, list) or not all(isinstance(p, str) for p in val):
            errors.append(f"capabilities.{key} must be a list of path globs")

    for key in ("shell", "subprocess", "secrets"):
        if not isinstance(caps.get(key, False), bool):
            errors.append(f"capabilities.{key} must be a boolean")

    return errors


def _validate_profile_consistency(profile: Any, caps: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    net = caps.get("network", "none")
    fs_r = caps.get("filesystem_read", []) or []
    fs_w = caps.get("filesystem_write", []) or []
    shell = bool(caps.get("shell", False))
    subprocess = bool(caps.get("subprocess", False))
    secrets = bool(caps.get("secrets", False))

    if profile == "isolated-no-net":
        if net != "none" or fs_r or fs_w or shell or subprocess or secrets:
            errors.append(
                "sandbox_profile 'isolated-no-net' requires zero capabilities "
                "(network='none', no fs, no shell/subprocess/secrets)"
            )
    elif profile == "net-allowlist":
        if net == "none":
            errors.append("sandbox_profile 'net-allowlist' requires a non-empty network allowlist")
        if shell or subprocess:
            errors.append("sandbox_profile 'net-allowlist' must not declare shell/subprocess")
    elif profile == "fs-scoped":
        if not (fs_r or fs_w):
            errors.append("sandbox_profile 'fs-scoped' requires at least one fs path glob")
    # 'trusted-exec' permits anything but is trust-capped in trust.py.
    return errors


def is_minimal(caps: Dict[str, Any]) -> bool:
    """True iff the skill declares zero capabilities (asks for nothing)."""
    return (
        caps.get("network", "none") == "none"
        and not caps.get("filesystem_read")
        and not caps.get("filesystem_write")
        and not caps.get("shell", False)
        and not caps.get("subprocess", False)
        and not caps.get("secrets", False)
    )


def capability_summary(caps: Dict[str, Any]) -> str:
    """One-line human summary of what a skill may touch."""
    if is_minimal(caps):
        return "no network, no filesystem, no shell, no secrets"
    parts: List[str] = []
    net = caps.get("network", "none")
    parts.append("network: none" if net == "none" else f"network: {','.join(net)}")
    if caps.get("filesystem_read"):
        parts.append("fs-read: " + ",".join(caps["filesystem_read"]))
    if caps.get("filesystem_write"):
        parts.append("fs-write: " + ",".join(caps["filesystem_write"]))
    if caps.get("shell"):
        parts.append("shell: yes")
    if caps.get("subprocess"):
        parts.append("subprocess: yes")
    if caps.get("secrets"):
        parts.append("secrets: yes")
    return "; ".join(parts)
