<!-- Thanks for contributing to Warden. -->

## What this changes

Brief description.

## Checklist

- [ ] `py -m warden selftest` passes (75/75)
- [ ] If I touched the `warden/` package, it remains **pure standard library**
      (zero third-party runtime dependencies)
- [ ] If I changed a manifest/signature/log shape, I kept the JSON Schema in
      `schema/` and the validator in `warden/manifest.py` in sync
      (`python tools/schema_check.py` passes)
- [ ] I did **not** commit a private seed, key, or `data/` (gitignored)
- [ ] Security-sensitive change? I followed [SECURITY.md](../SECURITY.md)

## Notes for the reviewer

Anything that needs context, plus — for a skill — the `warden scan` output.
