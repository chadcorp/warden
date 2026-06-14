"""
The magic moment, end to end, over real stdio.

Spawns the Warden node as a subprocess (exactly as an MCP agent would) and
speaks JSON-RPC to it: initialize -> tools/list -> call a skill -> audit. This
is a plain MCP client in ~80 lines; any MCP-speaking agent does the same thing.

    py examples/mcp_client_smoke.py

You will see (on stderr) the node verify every skill cold at startup, then
(on stdout) the trust-badged tool list and a skill served WITH its provenance.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Trust badges use ✓; force UTF-8 so this client prints on any console.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# The interpreter to launch the node with (sys.executable is correct under the
# `py` launcher; fall back to the launcher only if it is somehow unset).
PYTHON = sys.executable or "py"


class StdioClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [PYTHON, "-m", "warden", "serve"],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,  # stderr inherits -> you see verification
            text=True, encoding="utf-8", bufsize=1,
        )

    def request(self, method, params=None, mid=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if mid is not None:
            msg["id"] = mid
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if mid is None:
            return None
        line = self.proc.stdout.readline()
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def hr(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


def main():
    c = StdioClient()
    try:
        hr("1. initialize")
        init = c.request("initialize", {"protocolVersion": "2024-11-05",
                                        "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}, mid=1)
        info = init["result"]["serverInfo"]
        print(f"connected to {info['name']} v{info['version']} "
              f"(protocol {init['result']['protocolVersion']})")
        c.request("notifications/initialized")  # notification, no reply

        hr("2. tools/list  (each skill carries its trust badge + capability envelope)")
        tools = c.request("tools/list", {}, mid=2)["result"]["tools"]
        for t in tools:
            print(f"\n* {t['name']}\n    {t['description']}")

        hr("3. tools/call  warden__whoami")
        who = c.request("tools/call", {"name": "warden__whoami", "arguments": {}}, mid=3)
        print(who["result"]["content"][0]["text"])

        hr("4. tools/call  research_brain__idea_scout  (a skill served WITH provenance)")
        called = c.request("tools/call", {
            "name": "research_brain__idea_scout",
            "arguments": {"task": "a tax-mileage tracker for travel nurses"},
        }, mid=4)
        text = called["result"]["content"][0]["text"]
        # print the provenance block + the first lines of the verified instructions
        head = "\n".join(text.splitlines()[:18])
        print(head)
        print("    ... [verified skill instructions continue] ...")

        hr("5. tools/call  warden__audit  (the public transparency log)")
        audit = c.request("tools/call", {"name": "warden__audit", "arguments": {}}, mid=5)
        print(audit["result"]["content"][0]["text"])

        print("\n" + "=" * 70)
        print("MAGIC MOMENT: one stdio connection -> a curated, signed, sandboxed,")
        print("trust-scored skill set. Capability and provenance in the same breath.")
        print("=" * 70)
    finally:
        c.close()


if __name__ == "__main__":
    main()
