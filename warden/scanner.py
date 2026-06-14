"""
Intake scanner -- the door every skill must pass through.

Aligned to the OWASP Agentic Skills Top 10 threat classes that a static pass
can catch before a skill is ever trusted:

  TP   tool-poisoning / hidden instructions (prompt injection in skill text or
       tool descriptions/schemas) -- the agent-hijack class
  EX   unsafe command execution (curl|sh, Invoke-Expression, os.system, ...)
  NET  SSRF / exfiltration sinks (cloud-metadata IP, raw-IP URLs, paste-bins)
  SEC  secret access correlated with egress (the exfiltration signature)
  OBF  obfuscation (invisible/bidi/tag Unicode, long base64/hex blobs)
  DRIFT capability drift -- the bundle DOES something its manifest says it CANNOT.
        This is the heart of Warden's thesis: "verification of identity is not
        verification of behavior." A signed skill that declares network='none'
        but tells the agent to POST your data somewhere is caught HERE.

Philosophy: precision over recall on the auto-REJECT path. Only unambiguous
CRITICAL signatures auto-reject. Everything softer is a FLAG a human curator
reviews. A curator may consciously WAIVE a finding class via the manifest's
`scan_allow` (with a written reason); that waiver is covered by the curator
signature and recorded in the public transparency log -- an accountable
exception, never a silent one. Trust score is penalized per waiver.

A SIGNAL, not a guarantee.
"""

from __future__ import annotations

import os
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from . import manifest as manifest_mod

# Severity ordering (higher index == more severe). "ACK" = waived/acknowledged.
SEVERITIES = ["INFO", "ACK", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


CODE_EXTS = {".py", ".js", ".ts", ".sh", ".ps1", ".bat", ".rb", ".pl", ".php"}
TEXT_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini"}
SCAN_EXTS = CODE_EXTS | TEXT_EXTS

# --- operational token patterns reused by correlation + drift -----------------
EGRESS = re.compile(
    r"(?i)(requests\.(get|post|put|patch|delete)\s*\(|urllib\.request\.urlopen|"
    r"http\.client\.|httpx\.\w+\(|aiohttp\.|socket\.socket\s*\(|fetch\s*\(|"
    r"axios\.\w+\(|XMLHttpRequest|Invoke-RestMethod|Invoke-WebRequest|\biwr\b|"
    r"\bcurl\s+-|\bwget\s+http|\bnc\s+-|netcat)"
)
SHELL_EXEC = re.compile(
    r"(?i)(\bos\.system\s*\(|subprocess\.(run|call|Popen|check_output|check_call)\s*\(|"
    r"\bInvoke-Expression\b|\biex\s*\(|\bbash\s+-c\b|\bsh\s+-c\b|\bcmd(\.exe)?\s*/c\b|"
    r"\bchild_process\b|\bos\.popen\s*\()"
)
SECRET_READ = re.compile(
    r"(?i)(os\.environ\s*[\[.]|os\.getenv\s*\(|process\.env\.[A-Za-z_]|"
    r"Get-ChildItem\s+Env:|\$Env:[A-Za-z_]|\.aws[\\/]credentials|\.ssh[\\/]id_|"
    r"\bid_rsa\b|\bload_dotenv\s*\(|\bdotenv\.config\s*\()"
)
DANGEROUS_EVAL = re.compile(r"(?i)(\beval\s*\(|\bexec\s*\(|\bFunction\s*\(\s*['\"])")

# --- explicit detector table: (id, klass, severity, scope, pattern, message) --
# scope: 'any' | 'code' | 'text'
_DETECTORS: List[Tuple[str, str, str, str, re.Pattern, str]] = [
    # --- tool-poisoning / hidden instructions (agent hijack) ------------------
    ("TP01", "tool-poisoning", "CRITICAL", "any",
     re.compile(r"(?i)\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|earlier|above|preceding)\s+"
                r"(instructions?|prompts?|directions?|context|rules?)"),
     "instruction to ignore prior instructions (prompt injection)"),
    ("TP02", "tool-poisoning", "CRITICAL", "any",
     re.compile(r"(?i)\bdisregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|system|earlier)\s+"
                r"(instructions?|prompt|message|rules?)"),
     "instruction to disregard system/prior instructions"),
    ("TP03", "tool-poisoning", "CRITICAL", "any",
     re.compile(r"(?i)\bdo\s+not\s+(tell|inform|notify|mention|reveal|disclose|report)\s+"
                r"(this\s+)?(to\s+)?(the\s+)?(user|operator|human|developer|owner)"),
     "instruction to act covertly / hide actions from the user"),
    ("TP04", "tool-poisoning", "CRITICAL", "any",
     re.compile(r"(?i)\bwithout\s+(the\s+)?(user|operator|human)('s)?\s+"
                r"(knowledge|consent|awareness|permission|noticing)"),
     "instruction to act without user knowledge/consent"),
    ("TP05", "tool-poisoning", "HIGH", "any",
     re.compile(r"(?i)\b(reveal|print|output|repeat|leak)\s+(your\s+|the\s+|all\s+)?"
                r"(system\s+prompt|hidden\s+instructions?|initial\s+instructions?|developer\s+message)"),
     "attempt to extract the system prompt"),
    ("TP06", "tool-poisoning", "HIGH", "any",
     re.compile(r"(?i)<\s*(important|system|admin|secret|hidden|instructions?)\s*>"),
     "instruction-smuggling tag in content"),
    ("TP07", "tool-poisoning", "HIGH", "any",
     re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer|jailbreak|dan|god)\s*(mode)?\b"),
     "jailbreak / mode-switch payload"),
    ("TP08", "tool-poisoning", "MEDIUM", "any",
     re.compile(r"(?i)\boverride\s+(the\s+|your\s+)?(safety|guardrails?|policy|policies|restrictions?|filters?)\b"),
     "instruction to override safety/policy"),

    # --- unsafe command execution --------------------------------------------
    ("EX01", "unsafe-exec", "CRITICAL", "any",
     re.compile(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python|perl)\b"),
     "pipe-to-shell remote code execution (curl|sh)"),
    ("EX02", "unsafe-exec", "CRITICAL", "any",
     re.compile(r"(?i)\b(iwr|invoke-webrequest|wget|curl)\b[^\n|]*\|\s*(iex|invoke-expression)\b"),
     "download piped to Invoke-Expression"),
    ("EX03", "unsafe-exec", "CRITICAL", "any",
     re.compile(r"(?i)\bpowershell(\.exe)?\b[^\n]*-e(nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{16,}"),
     "obfuscated PowerShell -EncodedCommand"),
    ("EX04", "unsafe-exec", "HIGH", "any",
     re.compile(r"(?i)\bos\.system\s*\("), "os.system() shell call"),
    ("EX05", "unsafe-exec", "HIGH", "any",
     re.compile(r"(?i)subprocess\.\w+\([^)]*shell\s*=\s*True"), "subprocess(shell=True)"),
    ("EX06", "unsafe-exec", "HIGH", "any",
     re.compile(r"(?i)\bInvoke-Expression\b|\biex\s*\("), "Invoke-Expression dynamic exec"),
    ("EX07", "unsafe-exec", "HIGH", "any",
     re.compile(r"(?i)\brm\s+-rf\s+(/|~|\$HOME)"), "destructive recursive delete"),
    ("EX08", "unsafe-exec", "MEDIUM", "code",
     DANGEROUS_EVAL, "dynamic eval/exec of code"),

    # --- SSRF / exfiltration sinks -------------------------------------------
    ("NET01", "ssrf-exfil", "CRITICAL", "any",
     re.compile(r"169\.254\.169\.254|metadata\.google\.internal"),
     "cloud instance-metadata endpoint (SSRF credential theft target)"),
    ("NET02", "ssrf-exfil", "HIGH", "any",
     re.compile(r"(?i)\bhttps?://(\d{1,3}\.){3}\d{1,3}(:\d+)?\b"),
     "hard-coded raw-IP URL"),
    ("NET03", "ssrf-exfil", "HIGH", "any",
     re.compile(r"(?i)\b(webhook\.site|requestbin\.\w+|burpcollaborator|interactsh|"
                r"\.oast\.|ngrok\.io|pipedream\.net|pastebin\.com/raw)\b"),
     "known data-exfiltration / out-of-band sink"),

    # --- obfuscation ----------------------------------------------------------
    ("OBF02", "obfuscation", "MEDIUM", "any",
     re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), "long base64-like blob (possible hidden payload)"),
    ("OBF03", "obfuscation", "MEDIUM", "any",
     re.compile(r"(?:\\x[0-9a-fA-F]{2}){24,}"), "long hex-escaped blob (possible shellcode/payload)"),
]

# Invisible / control / bidi / Unicode-tag code points used for smuggling.
_INVISIBLE_RANGES = [
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0x180E, 0x180E),
]
_TAG_RANGE = (0xE0000, 0xE007F)  # pure instruction-smuggling block


class Finding:
    def __init__(self, id: str, klass: str, severity: str, file: str,
                 line: int, message: str, snippet: str = ""):
        self.id = id
        self.klass = klass
        self.severity = severity
        self.file = file
        self.line = line
        self.message = message
        self.snippet = snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "class": self.klass, "severity": self.severity,
            "file": self.file, "line": self.line, "message": self.message,
            "snippet": self.snippet[:160],
        }


class ScanError(Exception):
    """The scan could not be performed (e.g. the path is not a skill directory).

    Raised rather than returned so a missing/typo'd path can never be mistaken
    for a clean result — the worst failure mode for a security scanner."""


class ScanResult:
    def __init__(self, findings: List[Finding], waivers: List[Dict[str, Any]],
                 n_files: Optional[int] = None):
        self.findings = findings
        self.waivers = waivers
        self.n_files = n_files  # files actually scanned; 0 => nothing to scan

    @property
    def counts(self) -> Dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def verdict(self) -> str:
        """'reject' on any (un-waived) CRITICAL, else 'flag' on any HIGH/MEDIUM,
        else 'empty' if nothing was scanned, else 'pass'."""
        sevs = {f.severity for f in self.findings}
        if "CRITICAL" in sevs:
            return "reject"
        if "HIGH" in sevs:
            return "flag"
        if {"MEDIUM"} & sevs:
            return "flag"
        if self.n_files == 0:
            return "empty"  # scanned nothing -> NOT a clean pass
        return "pass"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "counts": {k: v for k, v in self.counts.items() if v},
            "waivers": self.waivers,
            "findings": [f.to_dict() for f in self.findings],
        }


def _classify_scope(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return "code" if ext in CODE_EXTS else "text"


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _scan_invisibles(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for ch in line:
            cp = ord(ch)
            if _TAG_RANGE[0] <= cp <= _TAG_RANGE[1]:
                out.append(Finding("OBF01", "obfuscation", "CRITICAL", rel, lineno,
                                   f"Unicode TAG character U+{cp:04X} (invisible instruction smuggling)"))
                break
            for lo, hi in _INVISIBLE_RANGES:
                if lo <= cp <= hi:
                    name = unicodedata.name(ch, f"U+{cp:04X}")
                    out.append(Finding("OBF01b", "obfuscation", "HIGH", rel, lineno,
                                       f"invisible/bidi character {name}"))
                    break
    return out


def _iter_scan_files(skill_dir: str) -> List[Tuple[str, str]]:
    """Yield (relpath, abspath) for scannable files, excluding warden artifacts."""
    out: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(skill_dir):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git"}]
        for name in filenames:
            if name in {"skill.sig.json"}:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in SCAN_EXTS:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, skill_dir).replace(os.sep, "/")
            out.append((rel, full))
    return out


def scan_bundle(skill_dir: str, manifest: Optional[Dict[str, Any]] = None) -> ScanResult:
    """Scan a skill bundle and return findings + verdict."""
    if not os.path.isdir(skill_dir):
        raise ScanError(f"not a skill directory: {skill_dir}")
    if manifest is None:
        try:
            manifest = manifest_mod.load(skill_dir)
        except Exception:
            manifest = {}

    caps = (manifest or {}).get("capabilities", {}) or {}
    findings: List[Finding] = []

    file_texts: Dict[str, str] = {}
    for rel, full in _iter_scan_files(skill_dir):
        text = _read_text(full)
        if text is None:
            continue
        file_texts[rel] = text
        scope = _classify_scope(rel)

        # pattern detectors
        for det_id, klass, sev, det_scope, pat, msg in _DETECTORS:
            if det_scope != "any" and det_scope != scope:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                m = pat.search(line)
                if m:
                    findings.append(Finding(det_id, klass, sev, rel, lineno, msg,
                                            snippet=line.strip()))
        # invisible/bidi/tag unicode
        findings.extend(_scan_invisibles(rel, text))

        # secret-access correlated with egress in the same file == exfil signature
        if SECRET_READ.search(text) and EGRESS.search(text):
            sm = SECRET_READ.search(text)
            ln = text[: sm.start()].count("\n") + 1
            findings.append(Finding("SEC01", "secret-exfil", "HIGH", rel, ln,
                                    "secret/credential access correlated with network egress "
                                    "in the same file (exfiltration pattern)"))

    # ---- capability drift: declared (manifest) vs actual (bundle content) ----
    findings.extend(_drift_findings(caps, file_texts))

    # ---- apply curator waivers (manifest.scan_allow) -------------------------
    waivers_meta: List[Dict[str, Any]] = []
    scan_allow = (manifest or {}).get("scan_allow", []) or []
    if scan_allow:
        allow_index: Dict[str, Dict[str, Any]] = {}
        for w in scan_allow:
            if isinstance(w, dict) and w.get("class"):
                allow_index[w["class"]] = w
        for f in findings:
            w = allow_index.get(f.klass)
            if w:
                # downgrade to acknowledged; never auto-rejects, but stays visible
                f.severity = "ACK"
        for w in scan_allow:
            if isinstance(w, dict):
                waivers_meta.append({
                    "class": w.get("class"),
                    "reason": w.get("reason", ""),
                    "scope": w.get("scope", "bundle"),
                })

    return ScanResult(findings, waivers_meta, n_files=len(file_texts))


def _drift_findings(caps: Dict[str, Any], file_texts: Dict[str, str]) -> List[Finding]:
    """The Warden value-add: bundle behavior that exceeds declared capability."""
    out: List[Finding] = []
    declares_no_net = caps.get("network", "none") == "none"
    declares_no_shell = not caps.get("shell", False) and not caps.get("subprocess", False)
    declares_no_secrets = not caps.get("secrets", False)

    for rel, text in file_texts.items():
        if declares_no_net:
            m = EGRESS.search(text)
            if m:
                ln = text[: m.start()].count("\n") + 1
                out.append(Finding("DRIFT-NET", "drift", "CRITICAL", rel, ln,
                                   "manifest declares network='none' but bundle contains a "
                                   "network-egress call (declared-vs-actual mismatch)",
                                   snippet=m.group(0)))
        if declares_no_shell:
            m = SHELL_EXEC.search(text)
            if m:
                ln = text[: m.start()].count("\n") + 1
                out.append(Finding("DRIFT-EXEC", "drift", "CRITICAL", rel, ln,
                                   "manifest declares no shell/subprocess but bundle contains a "
                                   "command-execution call",
                                   snippet=m.group(0)))
        if declares_no_secrets:
            m = SECRET_READ.search(text)
            if m:
                ln = text[: m.start()].count("\n") + 1
                out.append(Finding("DRIFT-SEC", "drift", "HIGH", rel, ln,
                                   "manifest declares secrets=false but bundle reads "
                                   "environment/credential material",
                                   snippet=m.group(0)))
    return out


def summarize(result: ScanResult) -> str:
    c = result.counts
    if result.verdict == "empty":
        return "verdict=empty [no scannable files]"
    nonzero = ", ".join(f"{k}:{v}" for k, v in c.items() if v) or "clean"
    return f"verdict={result.verdict} [{nonzero}]"
