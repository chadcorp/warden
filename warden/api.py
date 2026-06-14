"""
Scan API -- Trust-as-a-Service (Phase 3).

A small stdlib HTTP server that sells trust to the SUPPLY side: skill authors and
marketplaces upload a bundle and get back a scan + trust report (and, with a
token, a curator signature). This is the cleanest revenue surface in the plan --
the side with budget and reputational risk -- and it reuses the exact same
scanner / trust / signing pipeline as the local node.

Endpoints
  GET  /health                      -> {ok, version}
  GET  /registry                    -> public curated registry (names + trust)
  GET  /transparency                -> the transparency log + Merkle root
  GET  /trust/<pack>/<name>         -> a curated skill's trust row
  POST /scan      {files:{path:txt}} -> scan + trust report (the free funnel)
  POST /verify    {files:{...}}       -> full cold verification if a signature is included
  POST /sign      {files:{...}}       -> curator signature  (TOKEN REQUIRED)

Binds to 127.0.0.1 by default. Token auth via `Authorization: Bearer <token>`
or `X-Warden-Token`. SSO is an integration point, not built here.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from . import __version__, repo
from .report import build_scan_report
from .translog import TransparencyLog

MAX_BODY = 4 * 1024 * 1024  # 4 MB upload cap


def _materialize(files: Dict[str, str]) -> str:
    """Write an uploaded {relpath: content} map into a fresh temp dir, safely."""
    root = tempfile.mkdtemp(prefix="warden_api_")
    for rel, content in files.items():
        norm = os.path.normpath(rel).replace("\\", "/")
        if norm.startswith("..") or os.path.isabs(norm) or norm.startswith("/"):
            raise ValueError(f"unsafe path: {rel}")
        dst = os.path.join(root, norm)
        os.makedirs(os.path.dirname(dst) or root, exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
    return root


class _Handler(BaseHTTPRequestHandler):
    server_version = "Warden/" + __version__
    token: Optional[str] = None
    seed: Optional[bytes] = None

    def log_message(self, *a):  # quiet by default; the CLI prints a banner
        pass

    # -- helpers -------------------------------------------------------------
    def _send(self, code: int, obj: Any):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None, "bad Content-Length"
        if length <= 0:
            return None, "empty body"
        if length > MAX_BODY:
            return None, "body too large"
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")), None
        except Exception as exc:
            return None, f"invalid JSON: {exc}"

    def _authed(self) -> bool:
        if not self.token:
            return False
        auth = self.headers.get("Authorization", "")
        bearer = auth[7:] if auth.lower().startswith("bearer ") else None
        return (bearer == self.token) or (self.headers.get("X-Warden-Token") == self.token)

    # -- routing -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if path in ("", "/health"):
            return self._send(200, {"ok": True, "service": "warden-scan-api",
                                    "version": __version__})
        if path == "/registry":
            return self._send(200, repo.load_registry())
        if path == "/transparency":
            if not os.path.isfile(repo.TRANSLOG_PATH):
                return self._send(200, {"entries": [], "root": None})
            tl = TransparencyLog(repo.TRANSLOG_PATH)
            ok, _ = tl.verify()
            return self._send(200, {"entries": tl.entries(), "root": tl.current_root(),
                                    "integrity_ok": ok, "count": tl.count()})
        if path.startswith("/trust/"):
            sid = path[len("/trust/"):]
            row = repo.load_registry().get("skills", {}).get(sid)
            return self._send(200 if row else 404,
                              row or {"error": f"no skill '{sid}'"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if path not in ("/scan", "/verify", "/sign"):
            return self._send(404, {"error": "not found"})
        body, err = self._read_json()
        if err:
            return self._send(400, {"error": err})
        files = body.get("files") if isinstance(body, dict) else None
        if not isinstance(files, dict) or not files:
            return self._send(400, {"error": "expected {\"files\": {path: content}}"})

        if path == "/sign" and not self._authed():
            return self._send(401, {"error": "token required for /sign "
                                    "(Authorization: Bearer <token>)"})
        try:
            workdir = _materialize(files)
        except ValueError as exc:
            return self._send(400, {"error": str(exc)})

        try:
            if path == "/scan":
                seed = self.seed  # sign the report so it's portable proof
                return self._send(200, build_scan_report(workdir, seed=seed,
                                                          as_of=body.get("as_of", "1970-01-01")))
            if path == "/verify":
                from .verify import verify_skill
                pub = repo.load_curator_pub() if os.path.isfile(repo.CURATOR_PUB) else None
                if os.path.isfile(os.path.join(workdir, "skill.sig.json")):
                    return self._send(200, verify_skill(workdir, trusted_pub=pub))
                return self._send(200, {"note": "no signature in upload; returning scan report",
                                        **build_scan_report(workdir)})
            if path == "/sign":
                if not self.seed:
                    return self._send(503, {"error": "signing not configured on this server"})
                from .sign import sign_skill, SignError
                try:
                    tl = TransparencyLog(repo.TRANSLOG_PATH)
                    res = sign_skill(workdir, self.seed, as_of=body.get("as_of", "1970-01-01"),
                                     translog=tl, update_registry=False)
                    return self._send(200, {"signature": res["signature_record"],
                                            "trust": res["trust"], "logged": True})
                except SignError as exc:
                    return self._send(422, {"error": str(exc)})
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def run_api(host: str = "127.0.0.1", port: int = 8799,
            token: Optional[str] = None, seed: Optional[bytes] = None) -> None:
    _Handler.token = token or os.environ.get("WARDEN_API_TOKEN")
    _Handler.seed = seed
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"[warden] Scan API on http://{host}:{port}  "
          f"(sign={'on' if seed else 'off'}, auth={'on' if _Handler.token else 'off'})")
    print(f"[warden] GET /health /registry /transparency /trust/<pack>/<name> | "
          f"POST /scan /verify /sign")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[warden] Scan API stopped.")
        httpd.shutdown()
