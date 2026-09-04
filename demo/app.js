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

/* the fairoze-1 pre-generated samples, loaded lazily from /api/fairoze-samples */
let FAIROZE_SAMPLES = null;   // { locator, samples: [{id, title, chars, text}] }

async function loadFairozeSamples() {
  if (FAIROZE_SAMPLES) return FAIROZE_SAMPLES;
  const res = await fetch("/api/fairoze-samples");
  const d = await res.json();
  FAIROZE_SAMPLES = d.available ? d : { samples: [] };
  const sel = $("wm-sample");
  sel.innerHTML = "";
  for (const s of FAIROZE_SAMPLES.samples) {
    const o = document.createElement("option");
    o.value = s.id;
    o.textContent = `${s.title}  (${s.chars} chars)`;
    sel.appendChild(o);
  }
  return FAIROZE_SAMPLES;
}

function showFairozeSample() {
  const id = $("wm-sample").value;
  const s = (FAIROZE_SAMPLES?.samples || []).find((x) => x.id === id);
  if (!s) return;
  $("wm-result").dataset.raw = s.text;
  $("wm-result").value = s.text;
  $("wm-viz").checked = false;
  showWmViz(false);
  kv($("wm-meta"), [
    ["algorithm", "fairoze-1"],
    ["channel", "publicly-detectable statistical watermark (Fairoze), Ed25519 variant"],
    ["locator", FAIROZE_SAMPLES.locator],
    ["length", s.chars + " canonical chars"],
    ["origin", "pre-generated on an open-weight model — not signed by this server"],
    ["next step", "Verify tab → domain demo.terryzink.com (selector 3)"],
  ]);
  $("wm-out").classList.remove("hidden");
}

/* toggle the watermark tab between "sign my text" and "pick a fairoze sample" */
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
    loadFairozeSamples().then((d) => {
      if (d.samples.length) showFairozeSample();
      else note.textContent = "no fairoze-1 samples are available on this server.";
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
    const { keys, homoglyphs } = await res.json();
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
$("wm-sample").addEventListener("change", showFairozeSample);

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
    const isFairoze = r.record_algorithm === "fairoze-1" || r.algorithm === "fairoze-1";
    if (r.hint === "fairoze-needs-domain") {
      vd.className = "verdict warn"; vd.textContent = "NEEDS A DOMAIN";
      kv($("v-meta"), []);
      $("v-notes").textContent = r.detail || "";
    } else if (!r.mark_found) {
      vd.className = "verdict warn"; vd.textContent = "NO WATERMARK FOUND";
      kv($("v-meta"), []);
      $("v-notes").textContent = r.detail || "";
    } else if (r.verified) {
      vd.className = "verdict ok"; vd.textContent = "VALID — " + r.algorithm;
      $("v-notes").textContent = "";
    } else if (isFairoze) {
      vd.className = "verdict err"; vd.textContent = "NOT VERIFIED — fairoze-1";
      $("v-notes").textContent = "This text carries a fairoze-1 mark for the key that was "
        + "tried, but it does not check out. fairoze-1 breaks on almost any edit — a single "
        + "changed character outside the final segment cascades through every later segment "
        + "(see the robustness samples). " + (r.detail || "");
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
    kv($("v-meta"), (r.mark_found && r.hint !== "fairoze-needs-domain") ? [
      ["algorithm", r.algorithm],
      ["channel", r.channel],
      ["signature", r.detail && !r.verified ? "does not verify"
                  : r.signature_ok ? "cryptographically valid" : "not checked"],
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
      ["embedded locator", isFairoze ? undefined : (r.locator || "(none in the mark)")],
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
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
}

$("r-go").addEventListener("click", async () => {
  const btn = $("r-go"); clearErr($("r-err")); $("r-out").classList.add("hidden");
  if (!$("r-domain").value.trim()) { showErr($("r-err"), "enter a domain"); return; }
  btn.disabled = true; btn.textContent = "generating…";
  try {
    const r = await post("/api/make-record", {
      domain: $("r-domain").value.trim(),
      selector: $("r-selector").value,
      algorithm: $("r-algo").value,
      key_type: $("r-keytype").value,
      c: $("r-c").value,
    });
    $("r-record").textContent = r.record;
    $("r-zone").textContent = r.zonefile;
    $("r-dl-priv").onclick = () => download(r.record_name + ".private.pem", r.private_pem);
    $("r-dl-pub").onclick = () => download(r.record_name + ".public.pem", r.public_pem);
    renderFindings($("r-lint"), r.lint);
    $("r-out").classList.remove("hidden");
    $("r-out").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    showErr($("r-err"), e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Generate record + key";
  }
});

/* ---- (d) validate a domain --------------------------------------------- */
$("l-go").addEventListener("click", async () => {
  const btn = $("l-go"); clearErr($("l-err")); $("l-out").classList.add("hidden");
  if (!$("l-domain").value.trim()) { showErr($("l-err"), "enter a domain"); return; }
  btn.disabled = true; btn.textContent = "crawling…";
  try {
    const r = await post("/api/lint-domain", {
      domain: $("l-domain").value.trim(),
      at: $("l-at").value.trim() || null,
    });
    kv($("l-summary"), [
      ["domain", r.domain],
      ["selectors seen", r.selectors_seen],
      ["r= declared", r.r == null ? "—" : r.r],
      ["totals", `${r.errors} error(s), ${r.warnings} warning(s)`],
      ["crawl stopped", r.stopped_because],
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
