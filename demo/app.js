"use strict";
console.log("app.js loaded", new Date().toISOString());

const $ = (id) => document.getElementById(id);

/* ---- global visibility: surface any uncaught error on the page ---------- */
function banner(msg) {
  let b = $("__err_banner");
  if (!b) {
    b = document.createElement("div");
    b.id = "__err_banner";
    b.style.cssText =
      "position:fixed;left:0;right:0;top:0;z-index:99;padding:10px 16px;" +
      "background:#c0322b;color:#fff;font:600 13px/1.4 system-ui;white-space:pre-wrap";
    document.body.appendChild(b);
  }
  b.textContent = "⚠ " + msg + "  (open DevTools → Console for detail)";
}
window.addEventListener("error", (e) => banner(e.message));
window.addEventListener("unhandledrejection", (e) =>
  banner(e.reason && e.reason.message ? e.reason.message : String(e.reason)));

if (location.protocol === "file:") {
  banner("This page is open as a local file. Run  python3 server.py  and visit " +
         "http://127.0.0.1:8080/ instead — the buttons need the server.");
}

async function post(path, body) {
  console.log("POST", path, body);
  let res;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (netErr) {
    throw new Error("could not reach the server (" + netErr.message +
      ") — is `python3 server.py` still running?");
  }
  let data;
  try { data = await res.json(); } catch { data = { error: `HTTP ${res.status} (non-JSON response)` }; }
  console.log("  <-", res.status, data);
  if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function showErr(el, msg) { el.textContent = msg; el.classList.remove("hidden"); }
function clearErr(el) { el.textContent = ""; el.classList.add("hidden"); }

function kv(el, pairs) {
  el.innerHTML = "";
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    const row = document.createElement("div");
    row.innerHTML = `<span class="k">${k}</span><span class="v"></span>`;
    row.querySelector(".v").textContent = String(v);
    el.appendChild(row);
  }
}

function renderFindings(el, findings) {
  el.innerHTML = "";
  if (findings && findings.table) {
    const pre = document.createElement("pre");
    pre.className = "report";
    pre.textContent = findings.table
      + `\n\n=> ${findings.errors} error(s), ${findings.warnings} warning(s)`;
    el.appendChild(pre);
    return;
  }
  if (!findings || !findings.items.length) {
    el.innerHTML = '<div class="INFO">(clean)</div>';
  }
  for (const f of (findings.items || [])) {
    const d = document.createElement("div");
    d.className = f.level;
    d.textContent = `${f.level.padEnd(5)} [${f.code}] ${f.message}`;
    el.appendChild(d);
  }
  if (findings) {
    const tot = document.createElement("div");
    tot.className = "INFO";
    tot.textContent = `=> ${findings.errors} error(s), ${findings.warnings} warning(s)`;
    el.appendChild(tot);
  }
}

/* ---- tabs --------------------------------------------------------------- */
document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll("main .card").forEach((c) => {
      c.classList.toggle("hidden", c.id !== "tab-" + btn.dataset.tab);
    });
  });
});

/* ---- (a) watermark ---------------------------------------------------------- */
const CHANNEL_LABEL = {
  "tzsataitw-1": "tzsataitw-1 — zero-width characters (works on any text)",
  "tzsataitw-2": "tzsataitw-2 — look-alike letters (needs a long paragraph)",
};

/* pre-generated sample sets (fairoze-1, synthid-1), loaded lazily by algorithm
   from /api/samples?algorithm=<algo>. Both are statistical marks spread across
   the whole text -- there is nothing to inject into a user's own paragraph, so
   the tab just lets you pick one. */
const SAMPLE_SETS = {};        // algo -> { locator, note, samples: [{id,title,chars,text}] }
let CUR_SAMPLE_ALGO = null;

const SAMPLE_CHANNEL = {
  "fairoze-1": "publicly-detectable statistical watermark (Fairoze), Ed25519 variant",
  "synthid-1": "symmetric statistical watermark (SynthID-Text) — no public key; verify via the d= document",
};

function populateSampleDropdown(algo) {
  const sel = $("wm-sample");
  sel.innerHTML = "";
  for (const s of (SAMPLE_SETS[algo]?.samples || [])) {
    const o = document.createElement("option");
    o.value = s.id;
    o.textContent = `${s.title}  (${s.chars} chars)`;
    sel.appendChild(o);
  }
}

async function loadSamples(algo) {
  if (!SAMPLE_SETS[algo]) {
    const res = await fetch("/api/samples?algorithm=" + encodeURIComponent(algo));
    const d = await res.json();
    SAMPLE_SETS[algo] = d.available ? d : { samples: [] };
  }
  CUR_SAMPLE_ALGO = algo;
  populateSampleDropdown(algo);
  return SAMPLE_SETS[algo];
}

function showSample() {
  const set = SAMPLE_SETS[CUR_SAMPLE_ALGO];
  if (!set) return;
  const s = (set.samples || []).find((x) => x.id === $("wm-sample").value);
  if (!s) return;
  $("wm-result").dataset.raw = s.text;
  $("wm-result").value = s.text;
  $("wm-viz").checked = false;
  showWmViz(false);
  const selNum = (set.locator || "").split(".")[0] || "?";
  kv($("wm-meta"), [
    ["algorithm", CUR_SAMPLE_ALGO],
    ["channel", SAMPLE_CHANNEL[CUR_SAMPLE_ALGO] || "statistical watermark"],
    ["locator", set.locator],
    ["length", s.chars + " canonical chars"],
    ["origin", "pre-generated on an open-weight model — not signed by this server"],
    ["next step", `Verify tab → domain demo.terryzink.com (selector ${selNum})`],
  ]);
  $("wm-out").classList.remove("hidden");
}

/* toggle the watermark tab between "sign my text" and "pick a pre-generated sample" */
function syncKeyAlgo() {
  const opt = $("wm-key").selectedOptions[0];
  const kind = opt ? opt.dataset.kind : "";
  const algo = opt ? opt.dataset.algo : "";
  const note = $("wm-algo-note");

  const sampleMode = kind === "samples";
  $("wm-sample-row").classList.toggle("hidden", !sampleMode);
  $("wm-nolocator-row").classList.toggle("hidden", sampleMode);
  $("wm-go").classList.toggle("hidden", sampleMode);
  $("wm-viz-label").classList.toggle("hidden", sampleMode);
  $("wm-text").disabled = sampleMode;
  $("wm-text").classList.toggle("grayed", sampleMode);

  if (sampleMode) {
    note.textContent = `${algo} spreads the mark across the whole text statistically — `
      + "there is nothing to inject into your own paragraph. Pick one of the "
      + "pre-generated samples below.";
    loadSamples(algo).then((d) => {
      if (d.samples.length) showSample();
      else note.textContent = `no ${algo} samples are available on this server.`;
    });
    return;
  }

  $("wm-out").classList.add("hidden");
  if (!algo) {
    note.textContent = "This key's _watermark-text record has no readable a= tag — "
      + "watermarking with it will fail.";
    $("wm-go").disabled = true;
  } else if (!CHANNEL_LABEL[algo]) {
    note.textContent = `This key is published for a=${algo}, which this demo can't `
      + "generate here.";
    $("wm-go").disabled = true;
  } else {
    note.textContent = `This key signs ${CHANNEL_LABEL[algo]} — fixed by its DNS a= tag, `
      + "not selectable here.";
    $("wm-go").disabled = false;
  }
}

(async function initKeys() {
  const sel = $("wm-key");
  try {
    const res = await fetch("/api/keys");
    const { keys, homoglyphs, symmetric_algorithms } = await res.json();
    if (Array.isArray(symmetric_algorithms) && symmetric_algorithms.length) {
      R_SYMMETRIC_ALGOS = symmetric_algorithms;
    }
    syncRecordAlgo();
    if (homoglyphs) {
      const cls = homoglyphs.replace(/[\]\\^-]/g, "\\$&");
      HOMOGLYPH_RE = new RegExp("[" + cls + "]", "gu");
    }
    sel.innerHTML = "";
    if (!keys || !keys.length) {
      sel.innerHTML = '<option value="">no demo keys configured on this server</option>';
      $("wm-go").disabled = true;
      $("wm-algo-note").textContent = "";
      return;
    }
    for (const k of keys) {
      const o = document.createElement("option");
      o.value = k.id;
      o.dataset.kind = k.kind || "signing";
      o.dataset.algo = k.algorithm || "";
      o.textContent = k.kind === "samples"
        ? `${k.locator}  ·  ${k.algorithm} (pre-generated samples)`
        : k.locator + (k.algorithm ? "  ·  " + k.algorithm : "");
      sel.appendChild(o);
    }
    syncKeyAlgo();
  } catch {
    sel.innerHTML = '<option value="">could not load keys</option>';
    $("wm-go").disabled = true;
  }
})();
$("wm-key").addEventListener("change", syncKeyAlgo);
$("wm-sample").addEventListener("change", showSample);

let HOMOGLYPH_RE = null;   // set from /api/keys \u2014 the tzsataitw-2 look-alike letters

function escapeHTML(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}
function vizInvisiblesHTML(s) {
  let out = escapeHTML(s)
    .replace(/\u200b/g, '<span class="zw">[ZWSP]</span>')
    .replace(/\u200c/g, '<span class="zw">[ZWNJ]</span>');
  if (HOMOGLYPH_RE) {
    out = out.replace(HOMOGLYPH_RE, (c) => `<span class="hg" title="U+${
      c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}">${c}</span>`);
  }
  return out;
}
function showWmViz(reveal) {
  if (reveal) {
    $("wm-result-viz").innerHTML = vizInvisiblesHTML($("wm-result").dataset.raw || "");
    $("wm-result").classList.add("hidden");
    $("wm-result-viz").classList.remove("hidden");
  } else {
    $("wm-result-viz").classList.add("hidden");
    $("wm-result").classList.remove("hidden");
  }
}

$("wm-go").addEventListener("click", async () => {
  const btn = $("wm-go"); clearErr($("wm-err")); $("wm-out").classList.add("hidden");
  if (!$("wm-text").value.trim()) { showErr($("wm-err"), "paste some text to watermark first"); return; }
  if (!$("wm-key").value) { showErr($("wm-err"), "no demo key selected — is there a *.private.pem in the server's keys/ folder?"); return; }
  btn.disabled = true; btn.textContent = "signing…";
  try {
    const r = await post("/api/watermark", {
      text: $("wm-text").value,
      key_id: $("wm-key").value,
      no_locator: $("wm-nolocator").checked,
    });
    $("wm-result").dataset.raw = r.watermarked;
    $("wm-result").value = r.watermarked;
    $("wm-viz").checked = false;
    showWmViz(false);
    kv($("wm-meta"), [
      ["algorithm", r.algorithm],
      ["channel", r.channel],
      ["locator", r.locator || "(none — bare signature)"],
      ["mark size", r.frame_bytes + " bytes"],
      ["signed over", r.signed_over],
      ["signature (b64)", r.signature_b64],
      ["canonical sha256", r.canonical_sha256],
    ]);
    $("wm-out").classList.remove("hidden");
    $("wm-out").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    showErr($("wm-err"), e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Watermark";
  }
});
$("wm-viz").addEventListener("change", (e) => showWmViz(e.target.checked));
$("wm-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("wm-result").dataset.raw || ""); } catch {}
});

/* ---- (b) verify ----------------------------------------------------------- */
$("v-go").addEventListener("click", async () => {
  const btn = $("v-go"); clearErr($("v-err")); $("v-out").classList.add("hidden");
  if (!$("v-text").value.trim()) { showErr($("v-err"), "paste the watermarked text to check"); return; }
  btn.disabled = true; btn.textContent = "checking…";
  try {
    const domain = $("v-domain").value.trim();
    const selRaw = $("v-selector").value.trim();
    const r = await post("/api/verify", {
      text: $("v-text").value,
      domain: domain || null,
      selector: selRaw === "" ? null : selRaw,
    });

    const vd = $("v-verdict");
    const alg = r.record_algorithm || r.algorithm;
    const isFairoze = alg === "fairoze-1";
    const isSynthid = alg === "synthid-1";
    const scoreNote = (r.score != null && r.threshold != null)
      ? `  (score ${r.score.toFixed(4)} ${r.verified ? "≥" : "<"} threshold ${r.threshold.toFixed(4)})`
      : "";
    if (r.hint === "needs-domain" || r.hint === "fairoze-needs-domain") {
      vd.className = "verdict warn"; vd.textContent = "NEEDS A DOMAIN";
      kv($("v-meta"), []);
      $("v-notes").textContent = r.detail || "";
    } else if (r.hint === "synthid-demo-samples-only") {
      vd.className = "verdict warn"; vd.textContent = "COULD NOT VERIFY";
      kv($("v-meta"), []);
      $("v-notes").textContent = r.detail || "";
    } else if (!r.mark_found) {
      vd.className = "verdict warn"; vd.textContent = "NO WATERMARK FOUND";
      kv($("v-meta"), []);
      $("v-notes").textContent = r.detail || "";
    } else if (r.verified) {
      vd.className = "verdict ok"; vd.textContent = "VALID — " + alg + scoreNote;
      $("v-notes").textContent = isSynthid
        ? "This is a symmetric scheme — the provider's own verify endpoint scored the text "
          + "above its detection threshold. There is no public key; you are trusting "
          + (r.verify_endpoint || "the provider's endpoint") + "."
        : "";
    } else if (isSynthid) {
      vd.className = "verdict err"; vd.textContent = "NOT DETECTED — synthid-1" + scoreNote;
      $("v-notes").textContent = "The provider's verify endpoint scored this text below its "
        + "SynthID detection threshold — no watermark, or it was edited/paraphrased enough to "
        + "wash the statistical signal out. " + (r.detail || "");
    } else if (r.detail) {
      vd.className = "verdict warn"; vd.textContent = "COULD NOT VERIFY";
      $("v-notes").textContent = r.detail;
    } else if (r.signature_ok) {
      vd.className = "verdict err"; vd.textContent = "REJECTED (signature valid, but the record disagrees)";
      $("v-notes").textContent = r.algorithm_mismatch || "";
    } else {
      vd.className = "verdict err"; vd.textContent = "INVALID — signature does not verify";
      $("v-notes").textContent = "forged, corrupted, or the visible text was changed after signing";
    }

    const triedCount = r.tried ? r.tried.length
                     : r.tried_locators ? r.tried_locators.length : undefined;
    const triedList = r.tried ? r.tried.map((t) => `${t.locator} (${t.algorithm})`).join(", ")
                    : undefined;
    const showMeta = r.mark_found && r.hint !== "needs-domain"
                  && r.hint !== "synthid-demo-samples-only";
    kv($("v-meta"), showMeta ? [
      ["algorithm", alg],
      ["channel", r.channel],
      ["check", isSynthid
        ? (r.verified ? "score above threshold" : "score below threshold")
        : (r.detail && !r.verified ? "signature does not verify"
          : r.signature_ok ? "signature cryptographically valid" : "not checked")],
      ["detector", r.engine === "live" ? "SynthID masked-mean, run live"
                 : r.engine === "table" ? "pre-computed (this server has no detector installed)"
                 : undefined],
      ["score", r.score != null ? r.score.toFixed(6) : undefined],
      ["threshold", r.threshold != null ? r.threshold.toFixed(6) : undefined],
      ["tokens scored", r.tokens_scored || undefined],
      ["verify endpoint", r.verify_endpoint || undefined],
      ["verified against", r.key_source || "—"],
      ["key located by", r.key_origin === "embedded-locator" ? "the locator embedded in the watermark"
                       : r.key_origin === "domain-crawl" ? `crawling ${r.provider || "the domain you entered"} from selector 1`
                       : r.key_origin === "domain-selector" ? "the domain + selector you entered"
                       : r.key_origin === "user-supplied" ? "the domain + selector you entered"
                       : r.key_origin === "file" ? "a local key file"
                       : r.key_origin === "none" ? "nothing — this mark has no locator and you gave no domain/selector"
                       : "—"],
      ["records tried", triedList || triedCount],
      ["fairoze message", isFairoze ? r.message : undefined],
      ["aligned at offset", isFairoze && r.offset != null ? r.offset : undefined],
      ["canonical chars", isFairoze ? r.canonical_chars : undefined],
      ["embedded locator", (isFairoze || isSynthid) ? undefined : (r.locator || "(none in the mark)")],
      ["provider", r.provider || undefined],
      ["selector", r.selector == null ? undefined : r.selector],
      ["record a=", r.record_algorithm || "—"],
      ["signature (hex)", r.signature_hex],
      ["canonical sha256", r.canonical_sha256],
    ] : []);

    if (r.key_locator_note) {
      $("v-notes").textContent = (r.algorithm_mismatch ? r.algorithm_mismatch + "\n" : "") + r.key_locator_note;
    }
    $("v-out").classList.remove("hidden");
    $("v-out").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    showErr($("v-err"), e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Verify";
  }
});

/* ---- (c) build a record -------------------------------------------------- */
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: type || "application/x-pem-file" }));
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
}

let R_SYMMETRIC_ALGOS = ["synthid-1"];   // refined from /api/keys

function syncRecordAlgo() {
  const sym = R_SYMMETRIC_ALGOS.includes($("r-algo").value);
  $("r-sym-fields").classList.toggle("hidden", !sym);
  $("r-keytype-wrap").classList.toggle("hidden", sym);
  $("r-go").textContent = sym ? "Generate record + verification document"
                              : "Generate record + key";
}
$("r-algo").addEventListener("change", syncRecordAlgo);
syncRecordAlgo();

$("r-go").addEventListener("click", async () => {
  const btn = $("r-go"); clearErr($("r-err")); $("r-out").classList.add("hidden");
  if (!$("r-domain").value.trim()) { showErr($("r-err"), "enter a domain"); return; }
  const algo = $("r-algo").value;
  const sym = R_SYMMETRIC_ALGOS.includes(algo);
  if (sym && !$("r-verify").value.trim()) {
    showErr($("r-err"), "a k=symmetric record needs a verify endpoint URL"); return;
  }
  btn.disabled = true; btn.textContent = "generating…";
  try {
    const payload = {
      domain: $("r-domain").value.trim(),
      selector: $("r-selector").value,
      algorithm: algo,
      c: $("r-c").value,
    };
    if (sym) {
      payload.verify = $("r-verify").value.trim();
      payload.d = $("r-durl").value.trim() || null;
      payload.canonicalization = $("r-canon").value.trim();
      payload.extra = $("r-extra").value;
    } else {
      payload.key_type = $("r-keytype").value;
    }
    const r = await post("/api/make-record", payload);

    $("r-record").textContent = r.record;
    $("r-zone").textContent = r.zonefile;

    $("r-verifydoc-wrap").classList.toggle("hidden", !r.symmetric);
    $("r-nokey-note").classList.toggle("hidden", !r.symmetric);
    for (const id of ["r-dl-priv", "r-dl-pub"]) {
      const b = $(id);
      b.disabled = !!r.symmetric;
      b.title = r.symmetric ? "no key pair — this is a k=symmetric record" : "";
      b.onclick = null;
    }
    if (r.symmetric) {
      $("r-verifydoc").textContent = r.verify_doc;
      $("r-durl-echo").textContent = r.d_url;
      $("r-dl-vd").onclick = () =>
        download(r.verify_doc_name || "verify.json", r.verify_doc, "application/json");
    } else {
      $("r-dl-priv").onclick = () => download(r.record_name + ".private.pem", r.private_pem);
      $("r-dl-pub").onclick = () => download(r.record_name + ".public.pem", r.public_pem);
    }
    renderFindings($("r-lint"), r.lint);
    $("r-out").classList.remove("hidden");
    $("r-out").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    showErr($("r-err"), e.message);
  } finally {
    btn.disabled = false; syncRecordAlgo();
  }
});

/* ---- (d) validate a domain --------------------------------------------- */
$("l-go").addEventListener("click", async () => {
  const btn = $("l-go"); clearErr($("l-err")); $("l-out").classList.add("hidden");
  if (!$("l-domain").value.trim()) { showErr($("l-err"), "enter a domain"); return; }
  btn.disabled = true; btn.textContent = "crawling…";
  try {
    const selRaw = $("l-selector").value.trim();
    const r = await post("/api/lint-domain", {
      domain: $("l-domain").value.trim(),
      selector: selRaw === "" ? null : selRaw,
    });
    kv($("l-summary"), [
      ["domain", r.domain],
      [selRaw ? "selector" : "selectors seen", selRaw || r.selectors_seen],
      ["r= declared", r.r == null ? "—" : r.r],
      ["totals", `${r.errors} error(s), ${r.warnings} warning(s)`],
      [selRaw ? "scope" : "crawl stopped", r.stopped_because],
    ]);

    const box = $("l-selectors"); box.innerHTML = "";
    const pre = document.createElement("pre");
    pre.className = "report";
    pre.textContent = r.report || "(no output)";
    box.appendChild(pre);

    const notes = $("l-notes"); notes.innerHTML = "";
    for (const note of (r.notes || [])) {
      const d = document.createElement("div"); d.className = "hint";
      d.textContent = "note: " + note; notes.appendChild(d);
    }
    $("l-out").classList.remove("hidden");
    $("l-out").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    showErr($("l-err"), e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Validate";
  }
});
