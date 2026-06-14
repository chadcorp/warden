"""
Sandbox runner -- the in-process capability broker for a code skill.

Invoked by sandbox.py as a SEPARATE process:

    <python> _sandbox_runner.py <entrypoint.py> <policy.json>   (input on stdin)

The parent has already stripped secrets from the environment and redirected HOME
into an empty sandbox directory. This runner adds Python-level guards (network,
filesystem, shell) according to the policy, then runs the skill entrypoint as
__main__. The skill reads JSON from stdin and writes JSON to stdout.

HONEST LIMITATION: these are Python-level + process-level controls, NOT a hard
OS sandbox. A skill using ctypes or raw syscalls could bypass the Python guards.
For untrusted code in production, run this inside a container / microVM / WASM
runtime; the same policy is what that stronger sandbox should enforce. The one
guarantee that holds regardless of language is the parent's env scrub: the child
never receives secrets it was not granted.
"""

import builtins as _builtins
import json
import os
import os.path as _p
import sys


def _install_guards(policy):
    # ---- network ----
    if policy.get("network") == "none":
        import socket

        def _deny_net(*a, **k):
            raise PermissionError("warden-sandbox: network denied (capability network='none')")

        socket.socket = _deny_net
        socket.create_connection = _deny_net
        socket.getaddrinfo = _deny_net
        try:
            socket.create_server = _deny_net
        except Exception:
            pass

    # ---- filesystem ----
    if not policy.get("fs_unrestricted"):
        root = _p.abspath(policy.get("sandbox_root", "."))
        reads = [_p.abspath(g) for g in policy.get("filesystem_read", [])]
        writes = [_p.abspath(g) for g in policy.get("filesystem_write", [])]
        import fnmatch
        _real_open = _builtins.open

        def _guarded_open(file, mode="r", *a, **k):
            try:
                path = _p.abspath(str(file))
            except Exception:
                return _real_open(file, mode, *a, **k)
            writing = any(c in mode for c in "wax+")
            # always allow inside the ephemeral sandbox root
            if path == root or path.startswith(root + os.sep):
                return _real_open(file, mode, *a, **k)
            allow = writes if writing else (reads + writes)
            if any(fnmatch.fnmatch(path, g) for g in allow):
                return _real_open(file, mode, *a, **k)
            raise PermissionError(
                f"warden-sandbox: filesystem {'write' if writing else 'read'} denied: {path}")

        _builtins.open = _guarded_open

    # ---- shell / subprocess ----
    if not policy.get("allow_shell"):
        def _deny_shell(*a, **k):
            raise PermissionError("warden-sandbox: shell/subprocess denied (not declared)")
        os.system = _deny_shell
        try:
            import subprocess as _sp
            _sp.Popen = _deny_shell
            _sp.run = _deny_shell
            _sp.call = _deny_shell
        except Exception:
            pass


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: _sandbox_runner.py <entry> <policy>"}))
        return 2
    entry, policy_path = sys.argv[1], sys.argv[2]
    try:
        with open(policy_path, "r", encoding="utf-8") as fh:
            policy = json.load(fh)
    except Exception as exc:
        print(json.dumps({"error": f"bad policy: {exc}"}))
        return 2

    _install_guards(policy)

    import runpy
    try:
        runpy.run_path(entry, run_name="__main__")
        return 0
    except PermissionError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 13
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        sys.stderr.write(f"warden-sandbox: skill raised {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
