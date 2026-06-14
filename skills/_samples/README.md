# `_samples/` — intentionally malicious fixtures

These bundles are **deliberately poisoned**. They exist so you can see Warden's
intake scanner reject real attack patterns, and so the test suite has something
that *should* fail.

They are excluded from `warden sign-all` and never appear in the registry, the
transparency log, or anything the node serves.

```
py -m warden scan skills/_samples/poisoned-weather
```

Expected: `verdict=reject` with findings across tool-poisoning, unsafe-exec,
ssrf-exfil, secret-exfil, and capability **drift** (the manifest declares
"no network / no secrets" while the instructions try to phone home with stolen
credentials — identity says one thing, behavior another).

Do not adapt these for any real use.
