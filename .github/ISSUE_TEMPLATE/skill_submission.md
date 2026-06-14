---
name: Skill submission
about: Propose a skill for the curated pack
title: "[skill] <pack>/<name>"
labels: skill-submission
---

> Read [CONTRIBUTING.md](../../CONTRIBUTING.md) first. A curator scans cold and
> signs on merge — you do not commit a signature.

**Skill**
- pack/name:
- kind: `instructions` | `code`
- one-line summary:

**Capability manifest**
Paste your `skill.manifest.json` `capabilities` block. Least privilege scores
higher — declare only what the skill truly needs.

**Scan result**
Output of `py -m warden scan skills/<pack>/<name>` (aim for a clean `pass`). If
you used a `scan_allow` waiver, justify it here.

**Why it belongs in a *curated* set**
Warden vouches for a few, not a directory of many. Make the case.
