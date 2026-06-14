"""
Trust-graded public index generator (Phase 4 ecosystem).

Emits a static, browsable, **signed** index of the curated registry + knowledge
packs from the local trust state -- deployable as-is to Cloudflare Pages (or any
static host). Two artifacts:

  index.json   the machine-readable index, signed by the curator (tamper-evident)
  index.html   a human-browsable, trust-graded page

This is the "trust-graded public index" the plan's ecosystem phase calls for:
anyone can fetch index.json, verify the signature against the curator key, and
cross-check each entry against the public transparency log.
"""

from __future__ import annotations

import base64
import html
import json
import os
from typing import Any, Dict, List, Optional

from . import __version__, ed25519, repo
from .canonical import canonicalize
from .translog import TransparencyLog

INDEX_VERSION = "1.0"


def build_index_data(as_of: str = "1970-01-01") -> Dict[str, Any]:
    reg = repo.load_registry()
    skills: List[Dict[str, Any]] = []
    for sid, row in sorted(reg.get("skills", {}).items()):
        skills.append({
            "id": sid, "name": row["name"], "pack": row["pack"],
            "version": row["version"], "title": row["title"], "summary": row["summary"],
            "kind": row.get("kind", "instructions"), "visibility": row.get("visibility", "public"),
            "trust": row.get("trust", {}), "sandbox_profile": row.get("sandbox_profile"),
            "capabilities": row.get("capabilities_summary"),
            "bundle_digest": row.get("bundle_digest"), "tags": row.get("tags", []),
            "translog_seq": row.get("translog_seq"),
        })

    kpacks: List[Dict[str, Any]] = []
    kreg_path = os.path.join(repo.KPACKS_DIR, "registry.json")
    if os.path.isfile(kreg_path):
        with open(kreg_path, "r", encoding="utf-8") as fh:
            kreg = json.load(fh)
        for name, row in sorted(kreg.get("packs", {}).items()):
            kpacks.append({"name": name, "version": row["version"], "title": row["title"],
                           "summary": row["summary"], "bundle_digest": row["bundle_digest"],
                           "files": row.get("files", []), "tags": row.get("tags", [])})

    root, count = None, 0
    if os.path.isfile(repo.TRANSLOG_PATH):
        tl = TransparencyLog(repo.TRANSLOG_PATH)
        root, count = tl.current_root(), tl.count()

    return {
        "warden_index_version": INDEX_VERSION,
        "generated_at": as_of,
        "node_version": __version__,
        "curator_fingerprint": reg.get("curator_fingerprint"),
        "transparency_root": root,
        "transparency_count": count,
        "skills": skills,
        "knowledge_packs": kpacks,
    }


def build_signed_index(seed: Optional[bytes] = None, as_of: str = "1970-01-01") -> Dict[str, Any]:
    data = build_index_data(as_of)
    if seed is None:
        return {"index": data}
    pub = ed25519.public_key(seed)
    data["curator_key"] = pub.hex()
    sig = ed25519.sign(seed, canonicalize(data))
    return {"index": data, "signature": base64.b64encode(sig).decode("ascii"), "algo": "ed25519"}


# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #
def _badge(trust: Dict[str, Any]) -> str:
    if trust.get("status") == "rejected":
        return '<span class="ix-badge ix-rej">REJECTED</span>'
    cls = "ix-c" if trust.get("grade") in ("C", "D", "F") else "ix-a"
    tag = "PROVISIONAL " if trust.get("provisional") else ""
    return f'<span class="ix-badge {cls}">{html.escape(tag)}{trust.get("grade")}/{trust.get("score")} &#10003;</span>'


def render_html(signed: Dict[str, Any]) -> str:
    d = signed["index"]
    signed_note = ("signed by curator " + html.escape(str(d.get("curator_fingerprint")))
                   if signed.get("signature") else "UNSIGNED (set a curator key to sign)")
    rows = []
    for s in d["skills"]:
        rows.append(
            '<article class="ix-card">'
            f'<div class="ix-top">{_badge(s["trust"])}'
            f'<code>{html.escape(s["id"])}</code>'
            f'<span class="ix-ver">v{html.escape(s["version"])}</span>'
            f'<span class="ix-kind">{html.escape(s.get("kind","instructions"))}</span></div>'
            f'<p>{html.escape(s["summary"])}</p>'
            f'<div class="ix-meta"><span>caps: {html.escape(str(s.get("capabilities")))}</span>'
            f'<span>sandbox: {html.escape(str(s.get("sandbox_profile")))}</span>'
            f'<span class="ix-hash">{html.escape(str(s.get("bundle_digest")))}</span></div>'
            '</article>')
    krows = []
    for k in d.get("knowledge_packs", []):
        krows.append(
            '<article class="ix-card ix-kp">'
            f'<div class="ix-top"><span class="ix-badge ix-kpb">KPACK &#10003;</span>'
            f'<code>knowledge/{html.escape(k["name"])}</code>'
            f'<span class="ix-ver">v{html.escape(k["version"])}</span></div>'
            f'<p>{html.escape(k["summary"])}</p>'
            f'<div class="ix-meta"><span class="ix-hash">{html.escape(str(k.get("bundle_digest")))}</span></div>'
            '</article>')

    kp_section = ("<h2>Knowledge packs</h2><div class=\"ix-grid\">" + "".join(krows) + "</div>") if krows else ""

    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
        "<title>Warden — trust-graded registry</title>"
        "<link rel=\"icon\" href=\"../favicon.svg\" type=\"image/svg+xml\"/>"
        "<link rel=\"stylesheet\" href=\"../styles.css\"/>"
        "<style>"
        ".ix-wrap{max-width:1000px;margin:0 auto;padding:40px clamp(18px,5vw,40px)}"
        ".ix-grid{display:grid;gap:12px;margin:18px 0 36px}"
        ".ix-card{background:var(--bg-card);border:1px solid var(--line);border-radius:12px;padding:18px}"
        ".ix-top{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px}"
        ".ix-top code{color:var(--ink)}.ix-ver{color:var(--ink-faint);font-family:var(--mono);font-size:.8rem}"
        ".ix-kind{margin-left:auto;font-family:var(--mono);font-size:.72rem;color:var(--ink-faint);border:1px solid var(--line);padding:2px 8px;border-radius:6px}"
        ".ix-card p{color:var(--ink-dim);margin:0 0 10px;font-size:.93rem}"
        ".ix-meta{display:flex;gap:14px;flex-wrap:wrap;font-family:var(--mono);font-size:.72rem;color:var(--ink-faint)}"
        ".ix-hash{word-break:break-all}"
        ".ix-badge{font-family:var(--mono);font-size:.74rem;font-weight:700;padding:4px 9px;border-radius:7px;white-space:nowrap}"
        ".ix-a{background:rgba(46,230,166,.12);border:1px solid rgba(46,230,166,.34);color:var(--green)}"
        ".ix-c{background:rgba(255,194,75,.12);border:1px solid rgba(255,194,75,.34);color:var(--amber)}"
        ".ix-rej{background:rgba(255,93,108,.12);border:1px solid rgba(255,93,108,.34);color:var(--red)}"
        ".ix-kpb{background:rgba(92,200,255,.12);border:1px solid rgba(92,200,255,.34);color:var(--cyan)}"
        ".ix-head{border:1px solid var(--line);border-radius:14px;padding:24px;background:var(--bg-soft);margin-bottom:8px}"
        ".ix-head .mono{font-family:var(--mono);font-size:.8rem;color:var(--ink-faint);word-break:break-all}"
        "</style></head><body>"
        "<div class=\"ix-wrap\">"
        "<p><a href=\"../index.html\">&larr; Warden</a></p>"
        "<div class=\"ix-head\">"
        "<h1>Trust-graded registry</h1>"
        "<p style=\"color:var(--ink-dim)\">Every entry is content-addressed, Ed25519-signed, "
        "scanned, behaviorally trust-scored, and recorded in the public transparency log. "
        "Trust is a signal, not a guarantee.</p>"
        f"<p class=\"mono\">index {signed_note}<br/>transparency root: {html.escape(str(d.get('transparency_root')))} "
        f"({d.get('transparency_count')} entries) &middot; generated {html.escape(str(d.get('generated_at')))}</p>"
        "<p class=\"mono\">verify: fetch <code>index.json</code>, check its signature against the "
        "curator key, then cross-check each digest in the transparency log.</p>"
        "</div>"
        f"<h2>Skills ({len(d['skills'])})</h2>"
        "<div class=\"ix-grid\">" + "".join(rows) + "</div>"
        + kp_section +
        "</div></body></html>"
    )


def write_index(out_dir: str, seed: Optional[bytes] = None, as_of: str = "1970-01-01") -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    signed = build_signed_index(seed, as_of)
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(signed, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(signed))
    return {"out": repo.rel(out_dir), "skills": len(signed["index"]["skills"]),
            "kpacks": len(signed["index"]["knowledge_packs"]), "signed": "signature" in signed}
