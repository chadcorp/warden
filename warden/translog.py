"""
Public transparency log -- append-only, hash-linked, Merkle-rooted.

Every publish and every version lands here. Each entry is chained to the prior
entry's hash (like Certificate Transparency / a tamper-evident ledger), and the
whole set has a Merkle root for compact inclusion proofs. Nothing changes
silently: flip one byte of one historical entry and `verify()` fails, because
the chain hashes and the root no longer reconcile.

Stored as newline-delimited JSON (`transparency.log`) plus a small
`transparency.root` sidecar carrying the current head + Merkle root + count.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonicalize
from .content_address import digest_obj


def _leaf(entry_hash_hex: str) -> bytes:
    # RFC 6962-style domain separation (0x00 = leaf).
    return hashlib.sha256(b"\x00" + entry_hash_hex.encode("ascii")).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(entry_hashes: List[str]) -> Optional[str]:
    if not entry_hashes:
        return None
    level = [_leaf(h) for h in entry_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last (RFC 6962 uses promotion; this is fine + deterministic)
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return "sha256:" + level[0].hex()


class TransparencyLog:
    def __init__(self, path: str):
        self.path = path
        self.root_path = os.path.join(os.path.dirname(path) or ".", "transparency.root")
        self._entries: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        self._entries = []
        if os.path.isfile(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def head(self) -> Optional[str]:
        return self._entries[-1]["entry_hash"] if self._entries else None

    def count(self) -> int:
        return len(self._entries)

    def find(self, skill: str, version: str, action: str = "publish") -> Optional[Dict[str, Any]]:
        match = None
        for e in self._entries:
            if e["skill"] == skill and e["version"] == version and e["action"] == action:
                match = e  # last match wins
        return match

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Append a publish/yank record. Fills seq, prev, and entry_hash."""
        entry = dict(record)
        entry["seq"] = len(self._entries)
        entry["prev"] = self.head()
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        entry["entry_hash"] = digest_obj(body)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        self._entries.append(entry)
        self._write_root()
        return entry

    def _write_root(self) -> None:
        with open(self.root_path, "w", encoding="utf-8") as fh:
            json.dump({
                "count": self.count(),
                "head": self.head(),
                "merkle_root": merkle_root([e["entry_hash"] for e in self._entries]),
            }, fh, indent=2)

    def verify(self) -> Tuple[bool, List[str]]:
        """Recompute the chain + entry hashes; detect any tampering."""
        errors: List[str] = []
        prev: Optional[str] = None
        for i, entry in enumerate(self._entries):
            if entry.get("seq") != i:
                errors.append(f"entry {i}: seq mismatch ({entry.get('seq')})")
            if entry.get("prev") != prev:
                errors.append(f"entry {i}: broken chain link (prev != prior entry_hash)")
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed = digest_obj(body)
            if recomputed != entry.get("entry_hash"):
                errors.append(f"entry {i}: entry_hash mismatch (content tampered)")
            prev = entry.get("entry_hash")
        return (len(errors) == 0), errors

    def current_root(self) -> Optional[str]:
        return merkle_root([e["entry_hash"] for e in self._entries])
