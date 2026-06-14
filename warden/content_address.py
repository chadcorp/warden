"""
Content addressing for skill bundles.

"You connect to a HASH, not a name." A skill bundle is a directory of files
(SKILL.md, skill.manifest.json, tests/, ...). We compute a single, stable
digest over the *exact bytes of every file*:

    1. hash each file with SHA-256          -> {relpath: "sha256:<hex>"}
    2. canonicalize that file-map (sorted)  -> bytes
    3. bundle digest = "sha256:" + SHA-256(file-map bytes)

Change one byte in any file and the digest changes. Pin the digest and a
"rug-pull" (silent swap of a skill's contents after you trusted it) is
impossible: re-derivation will not match the pinned hash, and the signature --
which covers the digest -- will not verify.

Signature and metadata files produced by Warden itself are EXCLUDED from the
digest, otherwise signing would change the thing being signed.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, List

from .canonical import canonicalize

# Files Warden generates -- excluded so the digest is over authored content only.
EXCLUDED_NAMES = {
    "skill.sig.json",      # the signature record we are about to write
    "kpack.sig.json",      # knowledge-pack signature record
    ".warden",             # any local warden state
    ".DS_Store",
    "Thumbs.db",
}
EXCLUDED_SUFFIXES = (".pyc",)
EXCLUDED_DIRS = {"__pycache__", ".git"}


def _iter_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            if name in EXCLUDED_NAMES:
                continue
            if name.endswith(EXCLUDED_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            out.append(full)
    return out


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def file_map(root: str) -> Dict[str, str]:
    """Map of POSIX-style relative path -> per-file sha256 (sorted by key)."""
    fm: Dict[str, str] = {}
    for full in _iter_files(root):
        rel = os.path.relpath(full, root).replace(os.sep, "/")
        fm[rel] = hash_file(full)
    return dict(sorted(fm.items()))


def bundle_digest(root: str) -> str:
    """Single content address over every authored byte in the bundle."""
    fm = file_map(root)
    return "sha256:" + hashlib.sha256(canonicalize(fm)).hexdigest()


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_obj(obj) -> str:
    """Content address of a JSON-compatible object (canonicalized)."""
    return "sha256:" + hashlib.sha256(canonicalize(obj)).hexdigest()
