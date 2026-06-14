"""
Validate every Warden artifact against its published JSON Schema.

Used by CI and runnable locally. Requires `jsonschema` (a dev-only dependency;
the runtime node never needs it). Exits non-zero on any mismatch.

    python tools/schema_check.py
"""

from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed; skipping (pip install jsonschema)")
        return 0

    sch = os.path.join(ROOT, "schema")
    man_schema = _load(os.path.join(sch, "skill-manifest.schema.json"))
    sig_schema = _load(os.path.join(sch, "signature.schema.json"))
    log_schema = _load(os.path.join(sch, "transparency-log-entry.schema.json"))

    fails = 0

    for mp in glob.glob(os.path.join(ROOT, "skills", "**", "skill.manifest.json"), recursive=True):
        try:
            jsonschema.validate(_load(mp), man_schema)
        except Exception as exc:
            fails += 1
            print(f"FAIL manifest {os.path.relpath(mp, ROOT)}: {str(exc).splitlines()[0]}")

    for sp in glob.glob(os.path.join(ROOT, "skills", "**", "skill.sig.json"), recursive=True):
        try:
            jsonschema.validate(_load(sp), sig_schema)
        except Exception as exc:
            fails += 1
            print(f"FAIL signature {os.path.relpath(sp, ROOT)}: {str(exc).splitlines()[0]}")

    log = os.path.join(ROOT, "transparency.log")
    if os.path.isfile(log):
        with open(log, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if line.strip():
                    try:
                        jsonschema.validate(json.loads(line), log_schema)
                    except Exception as exc:
                        fails += 1
                        print(f"FAIL log entry {i}: {str(exc).splitlines()[0]}")

    if fails:
        print(f"\nschema check: {fails} FAILED")
        return 1
    print("schema check: all artifacts conform")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
