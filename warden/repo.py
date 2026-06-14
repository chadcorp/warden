"""
Repository paths + the curated registry index.

Centralizes where the curator key, the skills tree, the registry, and the
transparency log live, so every tool agrees. All paths are relative to the repo
root (the directory containing this `warden/` package).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# Repo root defaults to the package's parent (clone-and-run / editable install).
# Set WARDEN_HOME to point a relocated/installed node at a skills tree elsewhere.
REPO_ROOT = os.environ.get("WARDEN_HOME") or os.path.dirname(PACKAGE_DIR)

KEYS_DIR = os.path.join(REPO_ROOT, "keys")
CURATOR_SEED = os.path.join(KEYS_DIR, "curator.seed")          # PRIVATE -- gitignored
CURATOR_PUB = os.path.join(KEYS_DIR, "warden-curator.pub")     # public key (hex)

SKILLS_DIR = os.path.join(REPO_ROOT, "skills")
SAMPLES_DIR = os.path.join(SKILLS_DIR, "_samples")
REGISTRY_PATH = os.path.join(SKILLS_DIR, "registry.json")
TRANSLOG_PATH = os.path.join(REPO_ROOT, "transparency.log")

# Phase 1+ paths
DATA_DIR = os.path.join(REPO_ROOT, "data")
MEMORY_DIR = os.path.join(DATA_DIR, "memory")          # encrypted, gitignored
MEMORY_KEY = os.path.join(KEYS_DIR, "memory.key")      # PRIVATE, gitignored
KPACKS_DIR = os.path.join(REPO_ROOT, "knowledge")      # signed read-only packs
AUDIT_LOG = os.path.join(DATA_DIR, "audit.log")        # append-only audit trail
ORG_POLICY = os.path.join(REPO_ROOT, "org-policy.json")  # team allow/deny policy
TRUST_ROOTS = os.path.join(KEYS_DIR, "trust-roots.json")  # multi-curator roots

REGISTRY_VERSION = "1.0"


def rel(path: str) -> str:
    """Repo-relative POSIX path for display."""
    return os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")


def discover_skill_dirs(include_samples: bool = False) -> List[str]:
    """Every directory under skills/ that contains a skill.manifest.json."""
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(SKILLS_DIR):
        if not include_samples and (os.sep + "_samples") in (dirpath + os.sep):
            continue
        if "tests" in os.path.basename(dirpath):
            continue
        if "skill.manifest.json" in filenames:
            found.append(dirpath)
    return sorted(found)


def load_registry() -> Dict[str, Any]:
    if os.path.isfile(REGISTRY_PATH):
        with open(REGISTRY_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"warden_registry_version": REGISTRY_VERSION, "updated_at": None,
            "curator_fingerprint": None, "skills": {}}


def save_registry(reg: Dict[str, Any]) -> None:
    with open(REGISTRY_PATH, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def load_curator_pub() -> bytes:
    with open(CURATOR_PUB, "r", encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


def load_curator_seed() -> bytes:
    with open(CURATOR_SEED, "rb") as fh:
        raw = fh.read().strip()
    # seed stored as hex text for portability
    return bytes.fromhex(raw.decode("ascii"))


def load_trust_roots() -> List[bytes]:
    """All trusted curator public keys: the pinned curator plus any in
    keys/trust-roots.json (Phase 3 multi-curator / third-party curators)."""
    roots: List[bytes] = []
    if os.path.isfile(CURATOR_PUB):
        roots.append(load_curator_pub())
    if os.path.isfile(TRUST_ROOTS):
        with open(TRUST_ROOTS, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for r in data.get("roots", []):
            try:
                roots.append(bytes.fromhex(r["key_hex"]))
            except Exception:
                pass
    # de-dup, preserve order
    seen, out = set(), []
    for k in roots:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def add_trust_root(key_hex: str, name: str, added_at: str) -> None:
    os.makedirs(KEYS_DIR, exist_ok=True)
    data = {"warden_trust_roots_version": "1.0", "roots": []}
    if os.path.isfile(TRUST_ROOTS):
        with open(TRUST_ROOTS, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    from . import ed25519
    fp = ed25519.fingerprint(bytes.fromhex(key_hex))
    if not any(r.get("fingerprint") == fp for r in data.get("roots", [])):
        data.setdefault("roots", []).append(
            {"fingerprint": fp, "key_hex": key_hex, "name": name, "added_at": added_at})
        with open(TRUST_ROOTS, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
