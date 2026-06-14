"""
Audit log (Phase 3 TEAM) -- a tamper-evident record of what the node did.

Append-only and hash-linked (same construction as the transparency log): every
verification, exposure/refusal decision, policy decision, and tool call can be
recorded, and `verify()` detects any after-the-fact edit. Where the transparency
log is the PUBLIC record of what was published, the audit log is the LOCAL/ORG
record of what was run.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .content_address import digest_obj
from . import repo

AUDIT_VERSION = "1.0"


class AuditLog:
    def __init__(self, path: Optional[str] = None):
        self.path = path or repo.AUDIT_LOG
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._entries: List[Dict[str, Any]] = []
        if os.path.isfile(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))

    def _head(self) -> Optional[str]:
        return self._entries[-1]["entry_hash"] if self._entries else None

    def record(self, event: str, *, ts: Optional[float] = None, **fields: Any) -> Dict[str, Any]:
        entry = {
            "seq": len(self._entries),
            # int epoch seconds: hash-chained entries must be canonicalizable (no floats)
            "ts": int(ts if ts is not None else time.time()),
            "event": event,
            "fields": fields,
            "prev": self._head(),
        }
        entry["entry_hash"] = digest_obj({k: v for k, v in entry.items() if k != "entry_hash"})
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        self._entries.append(entry)
        return entry

    def verify(self) -> Tuple[bool, List[str]]:
        errs: List[str] = []
        prev = None
        for i, e in enumerate(self._entries):
            if e.get("seq") != i:
                errs.append(f"entry {i}: seq mismatch")
            if e.get("prev") != prev:
                errs.append(f"entry {i}: broken chain link")
            recomputed = digest_obj({k: v for k, v in e.items() if k != "entry_hash"})
            if recomputed != e.get("entry_hash"):
                errs.append(f"entry {i}: hash mismatch (tampered)")
            prev = e.get("entry_hash")
        return (len(errs) == 0), errs

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        return self._entries[-n:]

    def count(self) -> int:
        return len(self._entries)
