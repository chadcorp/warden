/* Warden landing — interactions. Zero dependencies. All content mirrors the
   real reference output (see WARDEN/BUILD_REPORT.md). */

// ============================================================
// CONFIG — wire your waitlist here before deploying.
// Set to a Formspree endpoint ("https://formspree.io/f/xxxx"), a Buttondown /
// Netlify Forms / custom URL that accepts a POST {email}. Leave "" for preview
// mode (shows success UX, logs a console warning, stores locally as a fallback).
// ============================================================
const WAITLIST_ENDPOINT = "https://formspree.io/f/mjgdjana";

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ------------------------------------------------------------
// 1. Hero terminal — type the command, then stream the output.
// ------------------------------------------------------------
const TERM_LINES = [
  [{ c: "c-prompt", t: "$ py examples/mcp_client_smoke.py" }],
  [],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-dim", t: "pinned curator key warden:cd015c720e6027fd" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-dim", t: "transparency log: 5 entries, root sha256:491104b0…, integrity " }, { c: "c-ok", t: "OK" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-ok", t: "VERIFIED  " }, { c: "c-dim", t: "build-brain/build-product        " }, { c: "c-prov", t: "[Warden PROVISIONAL A/99 ✓]" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-ok", t: "VERIFIED  " }, { c: "c-dim", t: "build-brain/ship-gate            " }, { c: "c-badge", t: "[Warden A/100 ✓]" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-ok", t: "VERIFIED  " }, { c: "c-dim", t: "compliance-brain/secret-sentinel " }, { c: "c-prov", t: "[Warden PROVISIONAL C/79 ✓]" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-ok", t: "VERIFIED  " }, { c: "c-dim", t: "research-brain/fact-gate         " }, { c: "c-badge", t: "[Warden A/100 ✓]" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-ok", t: "VERIFIED  " }, { c: "c-dim", t: "research-brain/idea-scout        " }, { c: "c-badge", t: "[Warden A/100 ✓]" }],
  [{ c: "c-tag", t: "[warden] " }, { c: "c-dim", t: "ready: 5 skill(s) exposed, 0 refused (deny-by-default)" }],
  [],
  [{ c: "c-prompt", t: "→ tools/call research-brain/idea-scout" }],
  [{ c: "c-head", t: "=== WARDEN PROVENANCE ===" }],
  [{ c: "c-dim", t: "trust        : " }, { c: "c-badge", t: "[Warden A/100 ✓]" }, { c: "c-dim", t: "  (a SIGNAL, not a guarantee)" }],
  [{ c: "c-dim", t: "pinned hash  : sha256:208b0208cd3c…" }],
  [{ c: "c-dim", t: "capabilities : " }, { c: "c-key", t: "no network, no filesystem, no shell, no secrets" }],
  [{ c: "c-dim", t: "verified now : " }, { c: "c-ok", t: "VERIFIED (11/11 checks)" }],
];

function segHTML(seg) {
  const span = document.createElement("span");
  if (seg.c) span.className = seg.c;
  span.textContent = seg.t;
  return span;
}

function renderTerminal() {
  const host = document.querySelector("[data-term-body] code");
  if (!host) return;
  host.textContent = "";

  if (reduceMotion) {
    TERM_LINES.forEach((line, i) => {
      line.forEach((seg) => host.appendChild(segHTML(seg)));
      if (i < TERM_LINES.length - 1) host.appendChild(document.createTextNode("\n"));
    });
    return;
  }

  const caret = document.createElement("span");
  caret.className = "caret";
  caret.innerHTML = "&nbsp;";

  // type line 0 (the command) char by char, then stream the rest line by line
  const cmd = TERM_LINES[0][0].t;
  const cmdSpan = document.createElement("span");
  cmdSpan.className = "c-prompt";
  host.appendChild(cmdSpan);
  host.appendChild(caret);

  let ci = 0;
  const typeCmd = () => {
    cmdSpan.textContent = cmd.slice(0, ci);
    ci++;
    if (ci <= cmd.length) {
      setTimeout(typeCmd, 26);
    } else {
      host.insertBefore(document.createTextNode("\n"), caret);
      streamLine(1);
    }
  };

  const streamLine = (idx) => {
    if (idx >= TERM_LINES.length) { return; }
    TERM_LINES[idx].forEach((seg) => host.insertBefore(segHTML(seg), caret));
    host.insertBefore(document.createTextNode("\n"), caret);
    const delay = TERM_LINES[idx].length === 0 ? 90 : 150;
    setTimeout(() => streamLine(idx + 1), delay);
  };

  setTimeout(typeCmd, 350);
}

// ------------------------------------------------------------
// 2. Scanner demo — real verdicts for a clean vs poisoned skill.
// ------------------------------------------------------------
const SCAN = {
  clean: {
    cmd: "$ warden scan skills/research-brain/idea-scout",
    head: [{ t: "research-brain/idea-scout: verdict=" }, { c: "v-pass", t: "pass" }, { t: " [clean]" }],
    findings: [{ t: "  no findings — signed and exposed. A skill that asks for nothing can leak nothing." }],
  },
  poison: {
    cmd: "$ warden scan skills/_samples/poisoned-weather",
    head: [{ t: "skills/_samples/poisoned-weather: verdict=" }, { c: "v-reject", t: "reject" }, { t: " [HIGH:6, CRITICAL:5]" }],
    findings: [
      { c: "s-crit", lvl: "[CRITICAL]", cls: "tool-poisoning", loc: "SKILL.md:12", msg: "instruction to ignore prior instructions" },
      { c: "s-crit", lvl: "[CRITICAL]", cls: "tool-poisoning", loc: "SKILL.md:13", msg: "act covertly / hide from the user" },
      { c: "s-crit", lvl: "[CRITICAL]", cls: "unsafe-exec   ", loc: "SKILL.md:16", msg: "pipe-to-shell RCE (curl | sh)" },
      { c: "s-crit", lvl: "[CRITICAL]", cls: "ssrf-exfil    ", loc: "SKILL.md:17", msg: "cloud instance-metadata endpoint" },
      { c: "s-crit", lvl: "[CRITICAL]", cls: "drift         ", loc: "SKILL.md:20", msg: "declares network='none' but egress" },
      { c: "s-high", lvl: "[HIGH]    ", cls: "ssrf-exfil    ", loc: "SKILL.md:20", msg: "known data-exfiltration sink" },
      { c: "s-high", lvl: "[HIGH]    ", cls: "secret-exfil  ", loc: "SKILL.md:18", msg: "secret access correlated with egress" },
      { c: "s-high", lvl: "[HIGH]    ", cls: "drift         ", loc: "SKILL.md:18", msg: "declares secrets=false but reads creds" },
    ],
    foot: "refusing to sign. identity says one thing — behavior says another.",
  },
};

function renderScan(which) {
  const out = document.querySelector("[data-scan-out]");
  if (!out) return;
  const data = SCAN[which];
  out.textContent = "";
  const add = (segs, cls) => {
    const div = document.createElement("div");
    if (cls) div.className = cls;
    (Array.isArray(segs) ? segs : [{ t: segs }]).forEach((s) => {
      const el = document.createElement("span");
      if (s.c) el.className = s.c;
      el.textContent = s.t;
      div.appendChild(el);
    });
    out.appendChild(div);
  };
  const span = (c, t) => ({ c, t });

  const cmd = document.createElement("div");
  cmd.innerHTML = `<span class="c-prompt"></span>`;
  cmd.firstChild.textContent = data.cmd;
  cmd.firstChild.className = "v-pass";
  cmd.firstChild.style.color = "var(--cyan)";
  out.appendChild(cmd);
  add(data.head);
  add("");
  if (which === "clean") {
    add(data.findings[0].t, "s-file");
  } else {
    data.findings.forEach((f) => {
      add([span(f.c, f.lvl + " "), span("", f.cls + " "), span("s-file", f.loc + "  "), span("", f.msg)]);
    });
    add("");
    add([{ c: "v-reject", t: "  " + data.foot }]);
  }
}

function initScanner() {
  const btns = document.querySelectorAll("[data-scan]");
  btns.forEach((b) => {
    b.addEventListener("click", () => {
      btns.forEach((x) => x.classList.remove("is-active"));
      b.classList.add("is-active");
      renderScan(b.dataset.scan);
    });
  });
  renderScan("clean");
}

// ------------------------------------------------------------
// 3. Rug-pull demo — tamper flips the re-derived hash + verdict.
// ------------------------------------------------------------
const HASH_SIGNED = "sha256:208b0208cd3c58a92102b2291fa28e4b…";
const HASH_TAMPERED = "sha256:b91f04a7e2c8d530f7a14e0c6db2af17…";

function initRugPull() {
  const btn = document.querySelector("[data-rug-toggle]");
  const now = document.querySelector("[data-rug-now]");
  const verdict = document.querySelector("[data-rug-verdict]");
  if (!btn || !now || !verdict) return;
  let tampered = false;
  btn.addEventListener("click", () => {
    tampered = !tampered;
    if (tampered) {
      now.textContent = HASH_TAMPERED;
      now.classList.add("is-bad");
      verdict.textContent = "FAILED — re-derived hash ≠ signed hash · the node refuses to serve it (rug-pull caught)";
      verdict.classList.add("is-bad");
      btn.textContent = "Restore the bundle";
      btn.classList.add("is-armed");
    } else {
      now.textContent = HASH_SIGNED;
      now.classList.remove("is-bad");
      verdict.textContent = "VERIFIED — 11/11 checks · the bytes match the signature";
      verdict.classList.remove("is-bad");
      btn.textContent = "Tamper with the bundle";
      btn.classList.remove("is-armed");
    }
  });
  now.textContent = HASH_SIGNED;
}

// ------------------------------------------------------------
// 4. Waitlist form — provider-agnostic, graceful preview mode.
// ------------------------------------------------------------
function initWaitlist() {
  const form = document.querySelector("[data-waitlist]");
  if (!form) return;
  const input = form.querySelector("input[type=email]");
  const msg = form.querySelector("[data-wl-msg]");
  const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.className = "wl-msg";
    const email = input.value.trim();
    if (!validEmail(email)) {
      input.classList.add("is-error");
      msg.textContent = "Please enter a valid email address.";
      msg.classList.add("err");
      return;
    }
    input.classList.remove("is-error");
    const btn = form.querySelector("button");
    btn.disabled = true; btn.textContent = "Joining…";

    const done = (ok, text) => {
      btn.disabled = false; btn.textContent = "Join the waitlist";
      msg.textContent = text;
      msg.classList.add(ok ? "ok" : "err");
      if (ok) { form.reset(); }
    };

    if (!WAITLIST_ENDPOINT) {
      // preview mode: no backend wired yet.
      try { localStorage.setItem("warden_waitlist", email); } catch (_) {}
      console.warn("[warden] WAITLIST_ENDPOINT is not set in app.js — running in preview mode; email not sent. Wire it before deploying.");
      done(true, "You're on the list — thank you. (Wire WAITLIST_ENDPOINT in app.js to start collecting for real.)");
      return;
    }
    try {
      const res = await fetch(WAITLIST_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ email }),
      });
      if (res.ok) done(true, "You're on the list — we'll be in touch at launch.");
      else done(false, "Something went wrong. Please try again, or star the repo to follow along.");
    } catch (_) {
      done(false, "Network error. Please try again later.");
    }
  });
}

// ------------------------------------------------------------
// 5. Scroll reveals.
// ------------------------------------------------------------
function initReveals() {
  const targets = document.querySelectorAll(
    ".section-head, .threat, .pillar, .arch, .start-block, .demo-card, .skill, .compare, .scope-card, .wedge-grid, .wl-inner"
  );
  if (reduceMotion || !("IntersectionObserver" in window)) {
    targets.forEach((t) => t.classList.add("in"));
    return;
  }
  targets.forEach((t) => t.classList.add("reveal"));
  const io = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    });
  }, { threshold: 0.12 });
  targets.forEach((t) => io.observe(t));
}

// ------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  renderTerminal();
  initScanner();
  initRugPull();
  initWaitlist();
  initReveals();
});
