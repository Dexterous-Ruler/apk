/* APKSHIELD dashboard — vanilla JS, talks to the Flask API on :8800 */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const SEV_COLOR = {
  CRITICAL: "var(--s-critical)", HIGH: "var(--s-high)", MEDIUM: "var(--s-medium)",
  LOW: "var(--s-low)", MINIMAL: "var(--s-minimal)",
};
const ASSESS_COLOR = {
  malicious: "var(--s-critical)", suspicious: "var(--s-high)",
  likely_benign: "var(--s-low)", benign: "var(--s-minimal)",
};

let LAST = null;

/* ---------------- boot ---------------- */
init();
async function init() {
  loadConfig();
  loadHistory();
  wireUpload();
}

async function loadConfig() {
  try {
    const c = await (await fetch("/api/config")).json();
    const pills = [];
    pills.push(pill(c.model_loaded, c.ml_model ? `ML · ${c.ml_model}` : "ML offline"));
    pills.push(pill(c.llm.available, c.llm.available ? `Claude · ${shortModel(c.llm.model)}` : "GenAI · template"));
    pills.push(pill(c.threat_intel.virustotal, "VirusTotal"));
    pills.push(pill(c.threat_intel.malwarebazaar, "MalwareBazaar"));
    if (c.dynamic) pills.push(pill(c.dynamic.virustotal_sandbox || c.dynamic.mobsf, "Dynamic sandbox"));
    $("#statusPills").innerHTML = pills.join("");
    renderSamples(c.samples || []);
  } catch (e) { /* offline */ }
}
const shortModel = (m) => (m || "").replace("claude-", "").replace(/-\d+$/, "");
function pill(on, label) {
  return `<span class="pill ${on ? "on" : "off"}"><span class="dot"></span>${esc(label)}</span>`;
}

function renderSamples(samples) {
  if (!samples.length) return;
  const order = { crafted: 0, benign: 1, real: 2 };
  samples.sort((a, b) => (order[a.group] ?? 9) - (order[b.group] ?? 9));
  const html = ['<span class="lbl">or try a sample</span>'];
  for (const s of samples) {
    let tag = "", label = prettyName(s.name), attrs = `data-sample="${esc(s.name)}"`;
    if (s.group === "real") {
      tag = `<span class="tag real">real · ${esc(s.family || "malware")}</span>`;
      label = esc(s.name) + "…";
      attrs = `data-real="${esc(s.sha)}"`;
    } else {
      const mal = /fake|sova|anubis|trojan|mal/i.test(s.name);
      tag = `<span class="tag ${mal ? "mal" : "ben"}">${mal ? "fake-bank" : "benign"}</span>`;
    }
    html.push(`<button class="chip-btn" ${attrs}>${tag}${label}</button>`);
  }
  $("#samples").innerHTML = html.join("");
  $$("#samples .chip-btn").forEach(b => b.addEventListener("click", () => {
    if (b.dataset.real) analyzeReal(b.dataset.real);
    else analyzeSample(b.dataset.sample);
  }));
}
const prettyName = (n) => n.replace(/_/g, " ").replace(/\bapk\b/i, "").trim();

/* ---------------- upload ---------------- */
function wireUpload() {
  const drop = $("#drop"), file = $("#file");
  $("#runDeep").addEventListener("click", runDeep);
  $("#clearHist").addEventListener("click", clearHistory);
  $("#browse").addEventListener("click", () => file.click());
  file.addEventListener("change", () => { if (file.files[0]) analyzeFile(file.files[0]); });
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.add("drag");
  }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); if (ev === "dragleave" && drop.contains(e.relatedTarget)) return;
    drop.classList.remove("drag");
  }));
  drop.addEventListener("drop", e => {
    const f = e.dataTransfer.files[0];
    if (f) analyzeFile(f);
  });
}

function stages(active, done) {
  $("#progress").classList.add("show");
  $$(".stage").forEach(s => {
    const st = s.dataset.st;
    s.classList.toggle("run", st === active);
    s.classList.toggle("done", done.includes(st));
  });
}
const ORDER = ["static", "ml", "imp", "genai", "ti"];
let progTimer = null;
function startProgress() {
  $("#results").classList.add("hidden");
  let i = 0; stages(ORDER[0], []);
  progTimer = setInterval(() => {
    i = Math.min(i + 1, ORDER.length - 1);
    stages(ORDER[i], ORDER.slice(0, i));
  }, 650);
}
function stopProgress() {
  clearInterval(progTimer);
  stages(null, ORDER);
  setTimeout(() => $("#progress").classList.remove("show"), 400);
}

async function analyzeFile(f) {
  if (!/\.apk$/i.test(f.name)) { alert("Please select an .apk file."); return; }
  startProgress();
  const fd = new FormData(); fd.append("apk", f);
  await post("/api/analyze", fd, f.name);
}
async function analyzeSample(name) {
  startProgress();
  await post(`/api/analyze-sample/${encodeURIComponent(name)}`, new FormData(), name);
}
async function analyzeReal(sha) {
  startProgress();
  await post(`/api/analyze-real/${encodeURIComponent(sha)}`, new FormData(), sha);
}
async function post(url, fd, label) {
  try {
    const r = await fetch(url, { method: "POST", body: fd });
    const data = await r.json();
    stopProgress();
    if (!r.ok || data.error) { alert("Analysis failed: " + (data.error || r.status)); return; }
    LAST = data; render(data); loadHistory();
  } catch (e) {
    stopProgress(); alert("Request failed: " + e.message);
  }
}

/* ---------------- render ---------------- */
function render(d) {
  $("#results").classList.remove("hidden");
  const risk = d.risk, m = d.static.manifest, imp = d.impersonation;
  $("#vFile").textContent = d.static.file.name;
  $("#vName").textContent = m.app_name || "(no label)";
  $("#vPkg").textContent = m.package || "—";
  const icon = $("#vIcon");
  if (d.icon) { icon.outerHTML = `<img id="vIcon" src="${d.icon}" alt="">`; }
  else { icon.outerHTML = `<span class="noicon" id="vIcon">▤</span>`; }

  // gauge
  animateGauge(risk.score, SEV_COLOR[risk.severity]);
  const sev = $("#sevBadge");
  sev.textContent = risk.severity;
  sev.style.background = hexAlpha(risk.severity, .16);
  sev.style.color = SEV_COLOR[risk.severity];
  const escal = risk.escalated_by_threat_intel;
  if (escal) {
    $("#vLabel").innerHTML = esc(risk.verdict_label)
      + `<div class="esc-note">▲ Escalated ${escal.from}→${escal.to} by external threat intel — `
      + `static analysis alone scored it ${escal.from} (modern payload hidden from static features); `
      + `multi-vendor AV consensus confirms it malicious.</div>`;
  } else {
    $("#vLabel").textContent = risk.verdict_label;
  }

  // layer bars
  const comp = risk.components, w = comp.weights;
  const bars = [
    layerBar("ML model", comp.ml, w.ml, "var(--signal)"),
    layerBar("Impersonation", comp.impersonation, w.impersonation, "var(--s-high)"),
    layerBar("Static combos", comp.static, w.static, "var(--violet)"),
  ];
  if ((comp.threat_intel || 0) > 0)
    bars.push(layerBar("Threat intel", comp.threat_intel, 35, "var(--s-critical)"));
  $("#vLayers").innerHTML = bars.join("");

  buildTabs(d);
  resetDeep(d.analysis_id);
  // the GenAI report is generated async so the verdict shows instantly
  if (d.genai && d.genai.pending) ensureReport(d.analysis_id);
}

async function ensureReport(aid) {
  try {
    const r = await fetch(`/api/report/${encodeURIComponent(aid)}`, { method: "POST", body: new FormData() });
    const genai = await r.json();
    if (!LAST || LAST.analysis_id !== aid) return;   // user moved on
    LAST.genai = genai;
    // refresh the verdict summary + AI Report tab in place
    const vp = $('.panel[data-panel="verdict"]'), ap = $('.panel[data-panel="ai"]');
    if (vp) vp.innerHTML = PANEL.verdict(LAST);
    if (ap) ap.innerHTML = PANEL.ai(LAST);
    const aiTab = $('#tabs .tab[data-tab="ai"] .cnt');
    if (aiTab) aiTab.textContent = (genai.report && genai.report.mitre_attack || []).length;
  } catch (e) { /* leave the template/pending state */ }
}

/* ---------------- deep analysis (RE + behavioral + dynamic) ------------ */
let DEEP_ID = null, deepTimer = null;
function resetDeep(aid) {
  DEEP_ID = aid;
  $("#deepIntro").classList.remove("hidden");
  $("#deepProgress").classList.remove("show");
  $("#deepTabs").classList.add("hidden");
  $("#deepTabs").innerHTML = "";
  $("#deepPanels").innerHTML = "";
  $("#deepStatus").textContent = "on demand";
}
function deepStages(active, done) {
  $("#deepProgress").classList.add("show");
  $$("#deepProgress .stage").forEach(s => {
    s.classList.toggle("run", s.dataset.st === active);
    s.classList.toggle("done", done.includes(s.dataset.st));
  });
}
async function runDeep() {
  if (!DEEP_ID) return;
  $("#deepIntro").classList.add("hidden");
  const order = ["behav", "re", "dyn"];
  let i = 0; deepStages(order[0], []);
  deepTimer = setInterval(() => { i = Math.min(i + 1, 2); deepStages(order[i], order.slice(0, i)); }, 4000);
  try {
    const r = await fetch(`/api/deep/${encodeURIComponent(DEEP_ID)}`, { method: "POST", body: new FormData() });
    const d = await r.json();
    clearInterval(deepTimer); deepStages(null, order);
    setTimeout(() => $("#deepProgress").classList.remove("show"), 400);
    if (!r.ok || d.error) { $("#deepIntro").classList.remove("hidden"); alert("Deep analysis failed: " + (d.error || r.status)); return; }
    renderDeep(d);
  } catch (e) {
    clearInterval(deepTimer); $("#deepProgress").classList.remove("show");
    $("#deepIntro").classList.remove("hidden"); alert("Deep analysis error: " + e.message);
  }
}

function renderDeep(d) {
  $("#deepStatus").textContent = `${d.behavioral.n_methods.toLocaleString()} methods · ${d.behavioral.seconds}s`;
  const re = d.reverse_engineering, reRep = re.report || {};
  const defs = [
    ["re", "AI Reverse Engineering", (reRep.per_method || []).length],
    ["behav", "Behavioral Flows", (d.behavioral.behavior_flows || []).length],
    ["dyn", "Dynamic Runtime", null],
    ["code", "Decompiled Code", (d.re_targets || []).length],
  ];
  const tabs = $("#deepTabs");
  tabs.classList.remove("hidden");
  tabs.innerHTML = defs.map((t, i) =>
    `<button class="tab ${i === 0 ? "active" : ""}" data-dtab="${t[0]}">${t[1]}${
      t[2] != null ? `<span class="cnt">${t[2]}</span>` : ""}</button>`).join("");
  $("#deepPanels").innerHTML = defs.map((t, i) =>
    `<div class="panel ${i === 0 ? "active" : ""}" data-dpanel="${t[0]}">${DEEP_PANEL[t[0]](d)}</div>`).join("");
  $$("#deepTabs .tab").forEach(b => b.addEventListener("click", () => {
    $$("#deepTabs .tab").forEach(x => x.classList.remove("active"));
    $$("#deepPanels .panel").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    $(`.panel[data-dpanel="${b.dataset.dtab}"]`).classList.add("active");
  }));
}

const DEEP_PANEL = {
  re(d) {
    const re = d.reverse_engineering, r = re.report || {};
    const color = ASSESS_COLOR[r.assessment] || "var(--ink-2)";
    const ground = re.grounding && re.grounding.grounded
      ? `<div class="ground ok">✓ RE grounded — every method/IOC cited appears in the supplied bytecode. <span class="engine-tag">${esc(re.engine)}</span></div>`
      : `<div class="ground warn">⚠ ${esc((re.grounding && re.grounding.issues || []).join("; ") || "ungrounded claims flagged")} <span class="engine-tag">${esc(re.engine)}</span></div>`;
    const per = (r.per_method || []).map(m =>
      `<div class="reason"><div class="pts" style="color:${m.malicious ? "var(--s-critical)" : "var(--ink-3)"}">${m.malicious ? "⚠" : "·"}</div>
        <div><div class="code">${esc(m.method)}</div><div class="det">${esc(m.what_it_does)}</div>
        <div class="muted" style="font-family:var(--mono);font-size:11px">${esc((m.key_apis || []).join(" · "))}</div></div></div>`).join("");
    const caps = (r.reconstructed_capabilities || []).map(c => `<div class="bullet">${esc(c)}</div>`).join("");
    const mitre = (r.mitre_attack || []).length
      ? `<table class="mitre"><thead><tr><th>Technique</th><th>Name</th><th>Evidence</th></tr></thead><tbody>${
        r.mitre_attack.map(t => `<tr><td class="tid">${esc(t.id)}</td><td>${esc(t.name)}</td><td>${esc(t.evidence)}</td></tr>`).join("")}</tbody></table>` : "";
    return `${ground}
      <div class="report-summary"><div class="hd">Reverse-engineered behavior
        <span class="assess" style="background:${color}22;color:${color}">${esc(r.assessment)}</span>
        <span class="cat">obfuscation: ${esc(r.obfuscation || "?")}</span>
        ${r.runtime_loaded_payload ? '<span class="cat" style="color:var(--s-high)">runtime-loaded payload</span>' : ""}</div>
        <div>${esc(r.overall_behavior)}</div></div>
      ${caps ? `<div class="card-h" style="padding:6px 0 8px;border:none"><h3>Reconstructed capabilities</h3></div>${caps}` : ""}
      <div class="card-h" style="padding:16px 0 8px;border:none"><h3>C2 / exfiltration</h3></div>
      <div class="det" style="color:var(--ink-2)">${esc(typeof r.c2_or_exfil === "string" ? r.c2_or_exfil : JSON.stringify(r.c2_or_exfil))}</div>
      <div class="card-h" style="padding:16px 0 8px;border:none"><h3>De-obfuscation notes</h3></div>
      <div class="det" style="color:var(--ink-2)">${esc(r.deobfuscation_notes)}</div>
      ${mitre ? `<div class="card-h" style="padding:16px 0 8px;border:none"><h3>MITRE ATT&CK (from code)</h3></div>${mitre}` : ""}
      <div class="card-h" style="padding:16px 0 8px;border:none"><h3>Per-method analysis</h3></div>${per || '<p class="empty">none</p>'}
      ${re.usage ? `<div class="note">Claude ${esc(re.model)} · ${re.usage.input_tokens} in / ${re.usage.output_tokens} out tokens — read the actual bytecode.</div>` : ""}
      ${re.error ? `<div class="note">⚠ ${esc(re.error)}</div>` : ""}`;
  },
  behav(d) {
    const b = d.behavioral;
    const cats = Object.entries(b.category_summary || {}).sort((a, c) => c[1] - a[1])
      .map(([k, v]) => `<span class="cat">${esc(k)} ×${v}</span>`).join(" ");
    const flows = (b.behavior_flows || []).map(f => `<div class="sig">
        <div class="sh"><span class="sn">${esc(f.method || "?")}</span>
        <span class="sp">${esc((f.sources || []).concat(f.sinks || f.reaches || []).join(" → ") || f.kind || "")}</span></div>
        <div class="se">${esc(f.interpretation)}</div></div>`).join("") || '<p class="empty">No source→sink data-flows traced.</p>';
    return `<p class="muted" style="margin-top:0">Static data-flow / taint analysis over the call graph — the runtime behavior the bytecode encodes, without executing it.</p>
      <div style="margin-bottom:14px">${cats}</div>
      <div class="card-h" style="padding:6px 0 8px;border:none"><h3>Behavior chains (source → sink)</h3></div>${flows}
      ${b.note ? `<div class="note">${esc(b.note)}</div>` : ""}`;
  },
  dyn(d) {
    const dy = d.dynamic, vt = dy.virustotal_sandbox || {};
    if (!dy.available && !(vt.note || "").includes("no public")) {
      return `<p class="empty">${esc(vt.note || "No dynamic sandbox data available.")}</p>
        <div class="note">Self-hosted live detonation (Frida + MobSF) activates when an Android instance is connected — see tools/frida_hooks.js.</div>`;
    }
    if (!dy.available) {
      return `<p class="empty">No public sandbox detonation report for this hash (new/targeted sample).</p>
        <div class="note">Real runtime behavior is available for known samples via VirusTotal's multi-sandbox detonation (hash-only), or via the self-hosted Frida/MobSF harness when an emulator is connected.</div>`;
    }
    const net = vt.network || {};
    const esc2 = a => (a || []).map(x => `<span class="ioc">${esc(x)}</span>`).join("") || '<span class="empty">none</span>';
    const mitre = (vt.runtime_mitre || []).map(m => `<tr><td class="tid">${esc(m.id)}</td><td>${esc(m.description || "")}</td></tr>`).join("");
    const escBanner = dy.escalation && dy.escalation.escalate
      ? `<div class="ground warn">▲ Dynamic escalation: ${esc((dy.escalation.reasons || []).join(" "))}</div>` : "";
    return `${escBanner}
      <p class="muted" style="margin-top:0">Real runtime behavior from <b>${esc(dy.primary_source || "sandbox")}</b> detonation — the sample executed in an isolated sandbox (we sent only the SHA-256, never the APK).</p>
      <div class="card-h" style="padding:6px 0 8px;border:none"><h3>Runtime network (C2 contacted at execution)</h3></div>
      <div class="muted dl">domains</div>${esc2(net.domains)}
      <div class="muted dl" style="margin-top:6px">IPs</div>${esc2(net.ips)}
      ${(vt.files_dropped || []).length ? `<div class="card-h" style="padding:14px 0 8px;border:none"><h3>Dropped at runtime</h3></div>${esc2(vt.files_dropped)}` : ""}
      ${mitre ? `<div class="card-h" style="padding:14px 0 8px;border:none"><h3>MITRE techniques observed during detonation</h3></div>
        <table class="mitre"><thead><tr><th>ID</th><th>Behavior signature</th></tr></thead><tbody>${mitre}</tbody></table>` : ""}
      ${(vt.tags || []).length ? `<div style="margin-top:10px">${vt.tags.map(t => `<span class="cat">${esc(t)}</span> `).join("")}</div>` : ""}`;
  },
  code(d) {
    const targets = d.re_targets || [];
    if (!targets.length) return '<p class="empty">No decompilable suspicious methods (synthetic or fully packed sample).</p>';
    return targets.slice(0, 8).map(t => `<div class="api-group">
      <h4>${esc(t.class)}.${esc(t.method)} ${t.is_entry_point ? '<span class="cat">entry point</span>' : ""}</h4>
      <div class="muted" style="font-size:12px;margin-bottom:4px">${esc((t.categories || []).join(", "))} · ${esc((t.apis || []).join(" · "))}</div>
      ${(t.urls || []).length ? t.urls.map(u => `<span class="ioc">${esc(u)}</span>`).join("") : ""}
      <pre class="smali">${esc((t.smali || []).slice(0, 40).join("\n"))}</pre></div>`).join("");
  },
};

function layerBar(name, val, weight, color) {
  const pct = weight > 0 ? Math.min(100, (val / weight) * 100) : 0;
  return `<div class="layer"><span class="ln">${name}</span>
    <span class="bar"><i style="width:${pct}%;background:${color}"></i></span>
    <span class="lv">${val.toFixed(1)}</span></div>`;
}

function animateGauge(score, color) {
  const arc = $("#gaugeArc"), C = 2 * Math.PI * 86;
  arc.style.stroke = color;
  const target = C * (1 - score / 100);
  let cur = C, t0 = null;
  $("#gScore").textContent = "0";
  arc.style.strokeDashoffset = C;
  function step(ts) {
    if (!t0) t0 = ts;
    const p = Math.min((ts - t0) / 900, 1), e = 1 - Math.pow(1 - p, 3);
    arc.style.strokeDashoffset = cur - (cur - target) * e;
    $("#gScore").textContent = Math.round(score * e);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function hexAlpha(sev, a) {
  const map = { CRITICAL: "255,59,92", HIGH: "251,113,54", MEDIUM: "251,191,36",
    LOW: "163,230,53", MINIMAL: "52,211,153" };
  return `rgba(${map[sev]},${a})`;
}

/* ---------------- tabs ---------------- */
function buildTabs(d) {
  const s = d.static, imp = d.impersonation, g = d.genai;
  const nFlags = s.permissions.red_flags.length;
  const nApi = s.dex.suspicious_apis.length;
  const nIoc = s.network.urls_interesting.length + s.network.ips.length;
  const nMitre = (g.report.mitre_attack || []).length;
  const defs = [
    ["verdict", "Verdict", d.risk.reasons.length],
    ["perms", "Permissions", nFlags],
    ["imp", "Impersonation", imp.signals.length],
    ["code", "Code & Network", nApi + nIoc],
    ["ai", "AI Report", nMitre],
    ["ti", "Threat Intel", null],
  ];
  $("#tabs").innerHTML = defs.map((t, i) =>
    `<button class="tab ${i === 0 ? "active" : ""}" data-tab="${t[0]}">${t[1]}${
      t[2] != null ? `<span class="cnt">${t[2]}</span>` : ""}</button>`).join("");
  $("#panels").innerHTML = defs.map((t, i) =>
    `<div class="panel ${i === 0 ? "active" : ""}" data-panel="${t[0]}">${PANEL[t[0]](d)}</div>`).join("");
  $$("#tabs .tab").forEach(b => b.addEventListener("click", () => {
    $$("#tabs .tab").forEach(x => x.classList.remove("active"));
    $$("#panels .panel").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    $(`.panel[data-panel="${b.dataset.tab}"]`).classList.add("active");
  }));
}

const PANEL = {
  verdict(d) {
    const g = d.genai.report;
    const reasons = d.risk.reasons.map(r =>
      `<div class="reason"><div class="pts">+${r.points.toFixed(1)}</div>
        <div><div class="code">${esc(r.code)}</div><div class="det">${esc(r.det || r.detail)}</div></div></div>`).join("");
    const findings = (g.key_findings || []).map(f => `<div class="bullet">${esc(f)}</div>`).join("");
    return `${summaryBlock(d.genai)}
      <div class="card-h" style="padding:0 0 8px;border:none"><h3>Why this score</h3></div>
      ${reasons}
      ${findings ? `<div class="card-h" style="padding:18px 0 8px;border:none"><h3>Key findings</h3></div>${findings}` : ""}`;
  },
  perms(d) {
    const p = d.static.permissions;
    if (!p.red_flags.length) return `<p class="empty">No red-flag permissions. Total requested: ${p.count}.</p>`;
    const rows = p.red_flags.map(r =>
      `<div class="flag"><span class="pm">${esc(r.short)}</span><span class="cat">${esc(r.category)}</span>
        <span class="why">${esc(r.why)}</span></div>`).join("");
    const comps = p.sensitive_bind_components.map(c =>
      `<div class="bullet">${esc(c.component)} — <span class="muted">${esc(c.meaning)}</span></div>`).join("");
    return `<div class="row spread" style="margin-bottom:12px">
        <span class="muted">${p.red_flags.length} red-flag of ${p.count} total permissions</span>
        <span class="muted">categories: ${esc(p.red_flag_categories.join(", "))}</span></div>
      ${rows}
      ${comps ? `<div class="card-h" style="padding:18px 0 8px;border:none"><h3>Sensitive bound components</h3></div>${comps}` : ""}`;
  },
  imp(d) {
    const i = d.impersonation;
    if (!i.signals.length) return `<p class="empty">No impersonation signals — the app does not claim a banking identity.</p>`;
    const head = `<div class="row spread" style="margin-bottom:14px">
      <div><div class="muted" style="font-family:var(--mono);font-size:11px">CLAIMS TO BE</div>
        <div style="font-family:var(--display);font-size:20px">${esc(i.claimed_bank || "—")}</div></div>
      <span class="sev-badge" style="background:${hexAlpha('HIGH',.16)};color:var(--s-high)">${esc(i.verdict.replace(/_/g," "))} · ${i.score}/100</span></div>`;
    const sigs = i.signals.map(s =>
      `<div class="sig"><div class="sh"><span class="sn">${esc(s.signal.replace(/_/g," "))}</span>
        <span class="sp">+${s.points}</span></div><div class="se">${esc(s.evidence)}</div></div>`).join("");
    return head + sigs;
  },
  code(d) {
    const s = d.static;
    const byCat = {};
    s.dex.suspicious_apis.forEach(a => { (byCat[a.category] ??= []).push(a); });
    const apis = Object.keys(byCat).length
      ? Object.entries(byCat).map(([cat, list]) =>
        `<div class="api-group"><h4>${esc(cat)}</h4>${list.map(a =>
          `<div class="api-row">${esc(a.api)} <span class="muted">— ${esc(a.why)}</span></div>`).join("")}</div>`).join("")
      : `<p class="empty">No suspicious API references found in the dex.</p>`;
    const urls = s.network.urls_interesting.map(u => `<span class="ioc">${esc(u)}</span>`).join("") || "";
    const ips = s.network.ips.map(u => `<span class="ioc">${esc(u)}</span>`).join("") || "";
    const sh = s.network.shell_command_strings.map(u => `<span class="ioc">${esc(u)}</span>`).join("") || "";
    const apkid = Object.entries(s.apkid.matches || {}).map(([k, v]) =>
      `<div class="api-row"><span class="cat">${esc(k)}</span> ${esc(v.join(", "))}</div>`).join("")
      || `<span class="empty">none</span>`;
    return `<div class="card-h" style="padding:0 0 8px;border:none"><h3>Suspicious API calls</h3></div>${apis}
      <div class="card-h" style="padding:18px 0 8px;border:none"><h3>Embedded indicators (IOCs)</h3></div>
      <div style="margin-bottom:8px"><div class="muted dl">URLs</div>${urls || '<span class="empty">none</span>'}</div>
      <div style="margin-bottom:8px"><div class="muted dl">IPs</div>${ips || '<span class="empty">none</span>'}</div>
      <div style="margin-bottom:8px"><div class="muted dl">Shell strings</div>${sh || '<span class="empty">none</span>'}</div>
      <div class="card-h" style="padding:18px 0 8px;border:none"><h3>APKiD — packer / obfuscation</h3></div>${apkid}`;
  },
  ai(d) {
    const g = d.genai;
    if (!g || g.pending) {
      return `<div class="ground ok" style="border-color:var(--line-2);color:var(--ink-2)">
        <span class="spinner"></span> Claude is generating the investigation report — verdict and evidence are ready in the other tabs.</div>`;
    }
    const r = g.report;
    const ground = g.grounding.grounded
      ? `<div class="ground ok">✓ Grounding check passed — every reported IOC traces to extracted evidence.
          <span class="engine-tag">${esc(g.engine)}</span></div>`
      : `<div class="ground warn">⚠ Caught ${g.grounding.issues.length} ungrounded claim(s) — stripped from the report:
          ${esc(g.grounding.issues.join("; "))}<span class="engine-tag">${esc(g.engine)}</span></div>`;
    const mitre = (r.mitre_attack || []).length
      ? `<table class="mitre"><thead><tr><th>Technique</th><th>Name</th><th>Evidence</th></tr></thead><tbody>${
        r.mitre_attack.map(t => `<tr><td class="tid">${esc(t.id)}</td><td>${esc(t.name)}</td><td>${esc(t.evidence)}</td></tr>`).join("")}</tbody></table>`
      : `<p class="empty">No MITRE techniques mapped.</p>`;
    const recs = (r.recommendations || []).map(x => `<div class="bullet">${esc(x)}</div>`).join("");
    const iocU = [...(r.iocs?.urls || []), ...(r.iocs?.ips || [])].map(x => `<span class="ioc">${esc(x)}</span>`).join("")
      || `<span class="empty">none</span>`;
    const hindi = r.user_warning_hindi
      ? `<div class="hindi"><span class="lbl">customer warning · हिंदी</span>${esc(r.user_warning_hindi)}</div>` : "";
    return `${ground}${summaryBlock(g, true)}
      <div class="card-h" style="padding:14px 0 8px;border:none"><h3>MITRE ATT&CK mapping</h3></div>${mitre}
      <div class="card-h" style="padding:18px 0 8px;border:none"><h3>Indicators of compromise</h3></div>${iocU}
      <div class="card-h" style="padding:18px 0 8px;border:none"><h3>Recommended actions</h3></div>${recs}
      ${hindi}
      ${g.usage ? `<div class="note">Claude ${esc(g.model)} · ${g.usage.input_tokens} in / ${g.usage.output_tokens} out tokens.</div>` : ""}
      ${g.error ? `<div class="note">⚠ ${esc(g.error)}</div>` : ""}`;
  },
  ti(d) {
    const t = d.threat_intel, vt = t.virustotal, mb = t.malwarebazaar;
    return `<div class="ti-grid">
      <div class="ti"><h4>VirusTotal</h4>${tiBlock(vt, () =>
        `<div class="big" style="color:var(--s-critical)">${vt.malicious}/${vt.total_engines}</div>
         <div class="muted">engines flagged malicious</div>
         ${vt.suggested_label ? `<div style="margin-top:8px">label: <b>${esc(vt.suggested_label)}</b></div>` : ""}
         <div style="margin-top:8px"><a href="${esc(vt.permalink)}" target="_blank">view report ↗</a></div>`)}</div>
      <div class="ti"><h4>MalwareBazaar</h4>${tiBlock(mb, () =>
        `<div class="big" style="color:var(--s-high)">${esc(mb.signature || "unknown family")}</div>
         <div class="muted">first seen ${esc(mb.first_seen || "—")}</div>
         ${mb.tags ? `<div style="margin-top:8px">${mb.tags.map(x => `<span class="cat">${esc(x)}</span> `).join("")}</div>` : ""}
         <div style="margin-top:8px"><a href="${esc(mb.permalink)}" target="_blank">view sample ↗</a></div>`)}</div>
    </div>
    <div class="note">Only the SHA-256 hash is sent to these services — never the APK bytes. Results cached locally.</div>`;
  },
};

function tiBlock(o, found) {
  if (o.status === "found") return found();
  if (o.status === "not_found") return `<div class="muted">Hash not known to this service (new or targeted sample).</div>`;
  if (o.status === "no_api_key") return `<div class="muted">${esc(o.note)}</div>`;
  return `<div class="muted">${esc(o.note || o.status)}</div>`;
}

function summaryBlock(g, full = false) {
  if (!g || g.pending) {
    return `<div class="report-summary"><div class="hd">
      <span class="spinner"></span> Generating AI investigation report…</div>
      <div class="muted">The verdict above is ready now — Claude is writing the
      plain-language report, MITRE mapping, IOCs and Hindi warning.</div></div>`;
  }
  const r = g.report;
  const color = ASSESS_COLOR[r.assessment] || "var(--ink-2)";
  return `<div class="report-summary">
    <div class="hd">${esc(r.headline || "")}
      <span class="assess" style="background:${color}22;color:${color}">${esc(r.assessment)} · ${esc(r.confidence)}</span></div>
    <div>${esc(r.summary || "")}</div></div>`;
}

/* ---------------- history ---------------- */
async function loadHistory() {
  try {
    const h = await (await fetch("/api/scans")).json();
    if (!h.length) { $("#hist").innerHTML = `<div class="empty">No scans yet.</div>`; return; }
    $("#hist").innerHTML = h.map(x =>
      `<div class="hist-item" data-id="${x.analysis_id}">
        <span class="sc" style="color:${SEV_COLOR[x.severity]}">${x.score}</span>
        <div><div class="hn">${esc(x.app_name || x.file)}</div><div class="hp">${esc(x.package || "")}</div></div>
        <span class="hs" style="color:${SEV_COLOR[x.severity]}">${esc(x.severity)}</span>
      </div>`).join("");
    $$("#hist .hist-item").forEach(el =>
      el.addEventListener("click", () => openScan(el.dataset.id)));
  } catch (e) { /* offline */ }
}
async function openScan(id) {
  const d = await (await fetch(`/api/scan/${id}`)).json();
  if (d && !d.error) { LAST = d; render(d); window.scrollTo({ top: 0, behavior: "smooth" }); }
}
async function clearHistory() {
  if (!confirm("Delete all saved scan records? This cannot be undone.")) return;
  try {
    const r = await fetch("/api/scans", { method: "DELETE" });
    const d = await r.json();
    loadHistory();
  } catch (e) { alert("Clear failed: " + e.message); }
}
