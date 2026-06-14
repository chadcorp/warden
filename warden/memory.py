"""
Private per-agent memory -- yours, local, encrypted at rest.

The plan scopes memory deliberately: PRIVATE per-agent memory by default
(this module), plus read-only signed knowledge packs (kpack.py). There is
deliberately NO shared-mutable / P2P memory pool -- that is the exact "bad seeds"
injection surface a trust-first product must refuse.

Storage: one ChaCha20-Poly1305-sealed blob per agent under data/memory/. The
agent id is bound into the AEAD additional-data, so a memory file cannot be
swapped between agents, and any tampering (or a wrong key) fails to decrypt
rather than returning garbage.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from . import chacha, repo

MEMORY_FORMAT = "warden-memory/1.0"


def load_or_create_key() -> bytes:
    os.makedirs(repo.KEYS_DIR, exist_ok=True)
    if os.path.isfile(repo.MEMORY_KEY):
        with open(repo.MEMORY_KEY, "r", encoding="utf-8") as fh:
            return bytes.fromhex(fh.read().strip())
    key = chacha.new_key()
    with open(repo.MEMORY_KEY, "w", encoding="utf-8") as fh:
        fh.write(key.hex())
    return key


def _safe(agent_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", agent_id) or "local"


class MemoryStore:
    def __init__(self, agent_id: str = "local", key: Optional[bytes] = None):
        self.agent_id = agent_id
        self.key = key if key is not None else load_or_create_key()
        os.makedirs(repo.MEMORY_DIR, exist_ok=True)
        self.path = os.path.join(repo.MEMORY_DIR, f"{_safe(agent_id)}.mem")
        self._entries: List[Dict[str, Any]] = self._load()

    def _aad(self) -> bytes:
        return f"{MEMORY_FORMAT}/{self.agent_id}".encode("utf-8")

    def _load(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.path):
            return []
        with open(self.path, "rb") as fh:
            blob = fh.read()
        data = json.loads(chacha.open_(self.key, blob, self._aad()).decode("utf-8"))
        if data.get("format") != MEMORY_FORMAT or data.get("agent") != self.agent_id:
            raise ValueError("memory file does not belong to this agent")
        return data.get("entries", [])

    def _save(self) -> None:
        payload = json.dumps({
            "format": MEMORY_FORMAT, "agent": self.agent_id, "entries": self._entries,
        }, ensure_ascii=False).encode("utf-8")
        blob = chacha.seal(self.key, payload, self._aad())
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, self.path)

    # -- API -----------------------------------------------------------------
    def remember(self, text: str, tags: Optional[List[str]] = None,
                 meta: Optional[Dict[str, Any]] = None, ts: Optional[float] = None) -> str:
        eid = f"m{len(self._entries):04d}-{int((ts if ts is not None else time.time()))}"
        self._entries.append({
            "id": eid, "ts": ts if ts is not None else time.time(),
            "text": text, "tags": tags or [], "meta": meta or {},
        })
        self._save()
        return eid

    def recall(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        terms = [t for t in re.split(r"\W+", query.lower()) if t]
        scored = []
        for e in self._entries:
            hay = (e["text"] + " " + " ".join(e.get("tags", []))).lower()
            score = sum(hay.count(t) for t in terms)
            if score:
                scored.append((score, e))
        scored.sort(key=lambda x: (-x[0], -x[1]["ts"]))
        return [e for _, e in scored[:k]]

    def all(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def forget(self, eid: str) -> bool:
        n = len(self._entries)
        self._entries = [e for e in self._entries if e["id"] != eid]
        if len(self._entries) != n:
            self._save()
            return True
        return False

    def stats(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_id,
            "entries": len(self._entries),
            "encrypted": True,
            "cipher": "chacha20-poly1305",
            "path": repo.rel(self.path) if os.path.isfile(self.path) else None,
        }
