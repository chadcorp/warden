"""
Deny-by-default capability enforcement.

A skill's manifest declares the *only* things it may touch. This engine answers
allow/deny questions against that declaration. Anything not explicitly granted
is denied -- "No network" means the skill cannot phone home, full stop.

In the Phase 0 reference node, enforcement is at the trust/exposure boundary:
the node refuses to expose a skill whose declared capabilities exceed its
sandbox profile, surfaces the exact capability set to the agent, and -- for
code-execution skills (Phase 1) -- this same engine is what the sandbox consults
before permitting any network/file/shell action. The decision logic is written
once, here, so the policy is identical at curation time and at run time.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Tuple


class Decision:
    def __init__(self, allowed: bool, reason: str):
        self.allowed = allowed
        self.reason = reason

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"Decision({'ALLOW' if self.allowed else 'DENY'}: {self.reason})"


class PolicyEngine:
    def __init__(self, capabilities: Dict[str, Any]):
        caps = capabilities or {}
        self.network = caps.get("network", "none")           # "none" | [domains]
        self.fs_read: List[str] = caps.get("filesystem_read", []) or []
        self.fs_write: List[str] = caps.get("filesystem_write", []) or []
        self.shell = bool(caps.get("shell", False))
        self.subprocess = bool(caps.get("subprocess", False))
        self.secrets = bool(caps.get("secrets", False))

    # -- network -------------------------------------------------------------
    def check_network(self, host: str) -> Decision:
        if self.network == "none":
            return Decision(False, "network capability is 'none' (deny-by-default)")
        host = (host or "").lower()
        for pattern in self.network:
            p = pattern.lower()
            if host == p or fnmatch.fnmatch(host, p):
                return Decision(True, f"host {host} matches allowlist entry '{pattern}'")
        return Decision(False, f"host {host} not in network allowlist {self.network}")

    # -- filesystem ----------------------------------------------------------
    def check_fs(self, path: str, mode: str) -> Decision:
        path = (path or "").replace("\\", "/")
        globs = self.fs_read if mode == "read" else self.fs_write
        if not globs:
            return Decision(False, f"no filesystem_{mode} paths declared (deny-by-default)")
        for pattern in globs:
            if fnmatch.fnmatch(path, pattern.replace("\\", "/")):
                return Decision(True, f"{mode} {path} matches '{pattern}'")
        return Decision(False, f"{mode} {path} not in filesystem_{mode} allowlist")

    # -- shell / subprocess --------------------------------------------------
    def check_shell(self) -> Decision:
        if self.shell or self.subprocess:
            return Decision(True, "shell/subprocess explicitly declared")
        return Decision(False, "shell/subprocess not declared (deny-by-default)")

    # -- secrets -------------------------------------------------------------
    def check_secrets(self) -> Decision:
        if self.secrets:
            return Decision(True, "secret access explicitly declared")
        return Decision(False, "secret access not declared (deny-by-default)")

    # -- summary -------------------------------------------------------------
    def granted(self) -> Dict[str, Any]:
        return {
            "network": self.network,
            "filesystem_read": self.fs_read,
            "filesystem_write": self.fs_write,
            "shell": self.shell,
            "subprocess": self.subprocess,
            "secrets": self.secrets,
        }


def profile_envelope(profile: str) -> Dict[str, Any]:
    """The maximum capabilities a sandbox profile may grant. The node refuses to
    expose a skill whose declared caps exceed this envelope."""
    return {
        "isolated-no-net": {
            "network": False, "fs": False, "shell": False, "secrets": False},
        "net-allowlist": {
            "network": True, "fs": False, "shell": False, "secrets": False},
        "fs-scoped": {
            "network": False, "fs": True, "shell": False, "secrets": False},
        "trusted-exec": {
            "network": True, "fs": True, "shell": True, "secrets": True},
    }.get(profile, {"network": False, "fs": False, "shell": False, "secrets": False})


def within_envelope(profile: str, capabilities: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """True iff declared caps fit inside the profile's envelope."""
    env = profile_envelope(profile)
    caps = capabilities or {}
    violations: List[str] = []
    if caps.get("network", "none") != "none" and not env["network"]:
        violations.append(f"profile '{profile}' forbids network, but caps declare it")
    if (caps.get("filesystem_read") or caps.get("filesystem_write")) and not env["fs"]:
        violations.append(f"profile '{profile}' forbids filesystem, but caps declare it")
    if (caps.get("shell") or caps.get("subprocess")) and not env["shell"]:
        violations.append(f"profile '{profile}' forbids shell, but caps declare it")
    if caps.get("secrets") and not env["secrets"]:
        violations.append(f"profile '{profile}' forbids secrets, but caps declare it")
    return (len(violations) == 0), violations
