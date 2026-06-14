"""
Sandboxed execution of code skills (Phase 1).

Runs a `kind:"code"` skill's entrypoint in a SEPARATE process with the
capability manifest enforced by a broker (`_sandbox_runner.py`):

  * env scrub -- the child is given a minimal allowlisted environment with all
    secret-looking variables removed, and HOME/USERPROFILE redirected into an
    empty sandbox directory (so even path-based credential reads like
    ~/.aws/credentials hit nothing).
  * network -- denied unless declared (Python-level socket guard).
  * filesystem -- confined to the ephemeral sandbox dir plus any declared globs.
  * shell/subprocess -- denied unless declared.
  * timeout -- the process is killed if it runs too long.

ISOLATION HONESTY: this is defense-in-depth at the process + Python layer, not a
hard OS sandbox (no seccomp/namespaces; those are Linux-only and outside a pure
stdlib build). A skill using ctypes or raw syscalls could bypass the Python
guards. For untrusted code in production, run inside a container / microVM / WASM
runtime -- and enforce this same policy there. The env scrub is the guarantee
that holds across languages: the child never receives secrets it was not granted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

from .repo import PACKAGE_DIR, rel

_RUNNER = os.path.join(PACKAGE_DIR, "_sandbox_runner.py")
_SECRET_ENV_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|SESSION)", re.I)

# system vars an interpreter genuinely needs to start, by platform.
_SAFE_ENV = {
    "nt": ["SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP",
           "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS"],
    "posix": ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"],
}

DEFAULT_TIMEOUT = 30


def _build_env(sandbox_root: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for name in _SAFE_ENV.get(os.name, _SAFE_ENV["posix"]):
        if name in os.environ and not _SECRET_ENV_RE.search(name):
            env[name] = os.environ[name]
    # redirect "home" into the empty sandbox so ~/.aws, ~/.ssh resolve to nothing
    env["HOME"] = sandbox_root
    env["USERPROFILE"] = sandbox_root
    env["HOMEPATH"] = sandbox_root
    env["PYTHONPATH"] = ""
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["WARDEN_SANDBOX"] = "1"
    return env


def run_code_skill(skill_dir: str, manifest: Dict[str, Any], input_obj: Any,
                   timeout: Optional[int] = None) -> Dict[str, Any]:
    caps = manifest.get("capabilities", {}) or {}
    profile = manifest.get("sandbox_profile", "isolated-no-net")
    entry = os.path.abspath(os.path.join(skill_dir, manifest.get("entrypoint", "skill.py")))
    if not os.path.isfile(entry):
        return {"ok": False, "error": f"entrypoint not found: {entry}"}

    sandbox_root = tempfile.mkdtemp(prefix="warden_sbx_")
    net = caps.get("network", "none")
    policy = {
        "network": "none" if net == "none" else "allowlist",
        "network_allow": net if isinstance(net, list) else [],
        "filesystem_read": caps.get("filesystem_read", []) or [],
        "filesystem_write": caps.get("filesystem_write", []) or [],
        "fs_unrestricted": profile == "trusted-exec",
        "allow_shell": bool(caps.get("shell") or caps.get("subprocess")),
        "sandbox_root": sandbox_root,
    }
    policy_path = os.path.join(sandbox_root, "_policy.json")
    with open(policy_path, "w", encoding="utf-8") as fh:
        json.dump(policy, fh)

    env = _build_env(sandbox_root)
    tmo = timeout or DEFAULT_TIMEOUT
    result: Dict[str, Any] = {"skill_dir": rel(skill_dir), "policy": {
        "network": net, "filesystem_read": policy["filesystem_read"],
        "filesystem_write": policy["filesystem_write"],
        "shell": policy["allow_shell"], "profile": profile, "env": "scrubbed",
    }}
    try:
        proc = subprocess.run(
            [sys.executable, _RUNNER, entry, policy_path],
            input=json.dumps(input_obj).encode("utf-8"),
            cwd=sandbox_root, env=env, capture_output=True, timeout=tmo,
        )
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        output = None
        if stdout:
            try:
                output = json.loads(stdout.splitlines()[-1])
            except Exception:
                output = stdout
        result.update({
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "timed_out": False,
            "output": output,
            "stdout": stdout,
            "stderr": stderr,
            "violations": [ln for ln in stderr.splitlines() if "warden-sandbox:" in ln],
        })
    except subprocess.TimeoutExpired:
        result.update({"ok": False, "timed_out": True, "returncode": None,
                       "output": None, "stdout": "", "stderr": f"timed out after {tmo}s",
                       "violations": [f"warden-sandbox: timeout after {tmo}s"]})
    finally:
        shutil.rmtree(sandbox_root, ignore_errors=True)
    return result
