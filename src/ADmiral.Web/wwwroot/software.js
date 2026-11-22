/* ADmiral – Software and Vulnerabilities sections (installed programs, versions, CVE matching).
   Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

const SW = { list: null, sort: store.get("swsort", { key: "name", dir: 1 }), filter: "", sel: null };
const VU = { data: null, sort: store.get("vusort", { key: "score", dir: -1 }), filter: "", sev: "", sel: null };

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const sevChip = (s) => `<span class="sev sev-${esc(s)}">${esc(t("sev." + s))}</span>`;

function csvText(header, rows) {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return "﻿" + [header, ...rows].map((r) => r.map(q).join(";")).join("\r\n") + "\r\n";
}

/* ================================================================== software list */
const SW_COLS = [
  { id: "name", get: (s) => s.name.toLowerCase(), html: (s) => `${icon("apps", 16)}${esc(s.name)}` },
  { id: "publisher", get: (s) => s.publisher.toLowerCase(), html: (s) => esc(s.publisher) },
  { id: "devices", get: (s) => s.devices, num: true, html: (s) => String(s.devices) },
  { id: "version_count", get: (s) => s.version_count, num: true, html: (s) => String(s.version_count) },
  { id: "spread", get: (s) => (s.versions[0]?.version || ""), html: (s) => esc(spread(s)) },
];
const spread = (s) => s.versions.map((v) => `${v.version} (${v.devices})`).join(" · ") + (s.version_count > s.versions.length ? " · …" : "");

function swFiltered() {
  const q = SW.filter.trim().toLowerCase();
  let rows = SW.list || [];
  if (q) rows = rows.filter((s) => [s.name, s.publisher, ...s.versions.map((v) => v.version)].join(" ").toLowerCase().includes(q));
  const col = SW_COLS.find((c) => c.id === SW.sort.key) || SW_COLS[0];
  return [...rows].sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    return (x < y ? -1 : x > y ? 1 : a.name.localeCompare(b.name)) * SW.sort.dir;
  });
}

function drawSoftware() {
  const wrap = $("#swgrid");
  if (!wrap) return;
  const rows = swFiltered();
  SW.shown = rows;
  const head = `<th class="rn"></th>` + SW_COLS.map((c) => `<th data-swsort="${c.id}">${esc(t("swcol." + c.id))}${SW.sort.key === c.id ? `<span class="arr">${SW.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  const body = rows.slice(0, 3000).map((s) => `<tr data-swkey="${esc(s.key)}"${SW.sel === s.key ? ' class="sel"' : ""}><td class="rn"></td>${SW_COLS.map((c) => `<td class="${c.num ? "num" : ""}">${c.html(s)}</td>`).join("")}</tr>`).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(t("sw.empty"))}</div>`;
  $("#sb-left").textContent = tText("sw.count", { n: rows.length });
}

function renderSoftwarePage(el) {
  el.innerHTML = pageHead("apps", t("nav.software"), t("sw.sub"),
    `<button class="btn" data-swact="export">${icon("export", 16)}${esc(t("page.export"))}</button>
     <button class="btn" data-swact="details">${icon("details", 16)}${esc(t("tb.details"))}</button>
     <input class="page-filter" id="sw-filter" type="search" placeholder="${esc(t("sw.search"))}" value="${esc(SW.filter)}">`)
    + `<div class="grid-wrap" id="swgrid" tabindex="0"></div>`;
  const grid = $("#swgrid");
  grid.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-swsort]");
    if (th) {
      const k = th.dataset.swsort;
      SW.sort = SW.sort.key === k ? { key: k, dir: -SW.sort.dir } : { key: k, dir: 1 };
      store.set("swsort", SW.sort);
      return drawSoftware();
    }
    const tr = e.target.closest("tr[data-swkey]");
    if (!tr) return;
    SW.sel = tr.dataset.swkey;
    $$("#swgrid tbody tr").forEach((r) => r.classList.toggle("sel", r === tr));
  });
  grid.addEventListener("dblclick", (e) => { const tr = e.target.closest("tr[data-swkey]"); if (tr) openSoftware(tr.dataset.swkey); });
  let tmr;
  $("#sw-filter").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { SW.filter = e.target.value; drawSoftware(); }, 120); };
  $$("[data-swact]", el).forEach((b) => (b.onclick = () => {
    if (b.dataset.swact === "details") { if (SW.sel) openSoftware(SW.sel); return; }
    const rows = swFiltered();
    saveText("ADmiral-software.csv", csvText([t("swcol.name"), t("swcol.publisher"), t("swcol.devices"), t("swcol.version_count"), t("swcol.spread")],
      rows.map((s) => [s.name, s.publisher, s.devices, s.version_count, spread(s)])));
  }));
  (async () => {
    SW.list = (await guard(() => api("GET", "/api/software"))) || SW.list || [];
    if (S.section === "software") drawSoftware();
  })();
}

/* ------------------------------------------------------------------ software window */
async function openSoftware(key) {
  const list = (SW.shown || SW.list || []).map((s) => s.key);
  S.sw = { key, list: list.includes(key) ? list : [key], cat: S.sw?.cat || "versions", data: null, filter: "" };
  $("#swin").hidden = false;
  $("#swin-toolbar").innerHTML = ["prev", "next"].map((id) => `<button class="tb" data-sw="${id}">${icon(id, 30)}<span>${esc(t("sw." + id))}</span></button>`).join("")
    + `<span class="tb-sep"></span><button class="tb" data-sw="close">${icon("back", 30)}<span>${esc(t("cw.close"))}</span></button>`;
  await loadSoftware();
}
function closeSoftware() { S.sw = null; $("#swin").hidden = true; }
async function loadSoftware() {
  const sw = S.sw;
  if (!sw) return;
  const data = await guard(() => api("GET", `/api/software/${encodeURIComponent(sw.key)}`));
  if (!data || S.sw !== sw) return;
  sw.data = data;
  renderSoftware();
}
function swStep(d) {
  if (!S.sw) return;
  const i = S.sw.list.indexOf(S.sw.key) + d;
  if (i < 0 || i >= S.sw.list.length) return;
  S.sw.key = S.sw.list[i]; S.sw.filter = ""; SW.sel = S.sw.key;
  loadSoftware();
}

function renderSoftware() {
  const sw = S.sw, d = sw.data;
  const i = sw.list.indexOf(sw.key);
  $("#swin-title").textContent = tText("sw.title", { name: d.name, i: i + 1, n: sw.list.length });
  $('#swin-toolbar [data-sw="prev"]').disabled = i <= 0;
  $('#swin-toolbar [data-sw="next"]').disabled = i >= sw.list.length - 1;
  const cats = [["versions", "apps", d.all_versions.length], ["devices", "computers", d.devices], ["vulns", "warn", d.vulnerabilities.length]];
  $("#swin-cats").innerHTML = cats.map(([id, ic, n]) => `<div class="cat${sw.cat === id ? " sel" : ""}${n === 0 ? " empty-cat" : ""}" data-swcat="${id}">${icon(ic, 18)}<span>${esc(t("sw.cat." + id))}</span>${n ? `<span class="cnt">${n}</span>` : ""}</div>`).join("");
  $("#swin-head").innerHTML = `${icon("apps", 30)}<span>${esc(d.name)}</span><span class="faint">${esc(d.publisher)}</span><span class="grow"></span>`
    + `<span class="faint">${esc(d.cpe ? tText("sw.cpe", { cpe: d.cpe }) : t("sw.no_cpe"))}</span>`;
  $("#swin-status").textContent = tText("sw.status", { devices: d.devices, versions: d.all_versions.length });
  renderSwContent();
}

function renderSwContent() {
  const sw = S.sw, d = sw.data, el = $("#swin-content");
  const table = (cols, rows) => {
    const q = sw.filter.trim().toLowerCase();
    const shown = q ? rows.filter((r) => cols.some(([, get]) => String(get(r) ?? "").toLowerCase().includes(q))) : rows;
    return `<div class="subtable-tools"><input class="page-filter" id="sw-wfilter" type="search" placeholder="${esc(t("cw.filter"))}" value="${esc(sw.filter)}"><span class="faint">${shown.length} / ${rows.length}</span></div>`
      + (rows.length ? `<div class="grid-wrap"><table class="grid"><thead><tr><th class="rn"></th>${cols.map(([h]) => `<th>${esc(t(h))}</th>`).join("")}</tr></thead><tbody>
        ${shown.map((r) => `<tr${r.__cve ? ` data-cve="${esc(r.__cve)}"` : ""}><td class="rn"></td>${cols.map(([, get, fmt]) => `<td class="${fmt === "num" ? "num" : ""}">${fmt === "html" ? get(r) : esc(get(r) ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">${esc(t("cw.no_data"))}</div>`);
  };
  let html = "";
  if (sw.cat === "versions") {
    const max = Math.max(1, ...d.all_versions.map((v) => v.devices.length));
    html = table([["t.version", (v) => v.version], ["sw.devices", (v) => v.devices.length, "num"],
      ["sw.share", (v) => `<span class="usage"><span style="width:${Math.round((v.devices.length / max) * 100)}%"></span></span>`, "html"]], d.all_versions);
  } else if (sw.cat === "devices") {
    const rows = d.all_versions.flatMap((v) => v.devices.map((x) => ({ ...x, version: v.version })));
    html = table([["t.computer", (x) => `<a href="#" data-comp="${esc(x.guid)}">${esc(x.name)}</a>`, "html"], ["t.version", (x) => x.version]], rows);
  } else {
    const rows = d.vulnerabilities.map((v) => ({ ...v, __cve: v.cve }));
    html = d.cpe || rows.length ? table(vulnCols(), rows) : `<div class="empty">${esc(t("sw.no_cpe_help"))}</div>`;
  }
  el.innerHTML = html;
  const f = $("#sw-wfilter");
  if (f) f.oninput = (e) => { sw.filter = e.target.value; const pos = e.target.selectionStart; renderSwContent(); const nf = $("#sw-wfilter"); nf.focus(); nf.setSelectionRange(pos, pos); };
  $$("[data-comp]", el).forEach((a) => (a.onclick = (e) => { e.preventDefault(); closeSoftware(); S.section = "devices"; renderRail(); applySection(); renderPage(); openComputer(a.dataset.comp); }));
  $$("tr[data-cve]", el).forEach((tr) => (tr.ondblclick = () => openVuln(tr.dataset.cve)));
}

/* ================================================================== vulnerabilities */
const vulnCols = () => [
  ["vucol.cve", (v) => v.cve], ["vucol.score", (v) => (v.score == null ? "" : v.score.toFixed(1)), "num"],
  ["vucol.severity", (v) => sevChip(v.severity), "html"], ["vucol.kev", (v) => (v.kev ? `<span class="kev" title="${esc(t("vu.kev_tip"))}">KEV</span>` : ""), "html"],
  ["vucol.range", (v) => v.range], ["vucol.devices", (v) => v.devices, "num"],
];

const VU_COLS = [
  { id: "cve", get: (v) => v.cve, html: (v) => `${icon("warn", 16)}${esc(v.cve)}` },
  { id: "software", get: (v) => v.software.toLowerCase(), html: (v) => esc(v.software) },
  { id: "range", get: (v) => v.range, html: (v) => esc(v.range) },
  { id: "score", get: (v) => v.score ?? -1, num: true, html: (v) => (v.score == null ? "" : v.score.toFixed(1)) },
  { id: "severity", get: (v) => SEV_ORDER[v.severity] ?? 0, html: (v) => sevChip(v.severity) },
  { id: "kev", get: (v) => (v.kev ? 1 : 0), html: (v) => (v.kev ? `<span class="kev" title="${esc(t("vu.kev_tip"))}">KEV</span>` : "") },
  { id: "devices", get: (v) => v.devices, num: true, html: (v) => String(v.devices) },
  { id: "published", get: (v) => v.published || "", html: (v) => esc(v.published) },
];

function vuFiltered() {
  const q = VU.filter.trim().toLowerCase();
  let rows = VU.data?.items || [];
  if (VU.sev === "kev") rows = rows.filter((v) => v.kev);
  else if (VU.sev) rows = rows.filter((v) => v.severity === VU.sev);
  if (q) rows = rows.filter((v) => [v.cve, v.software, v.range].join(" ").toLowerCase().includes(q));
  const col = VU_COLS.find((c) => c.id === VU.sort.key) || VU_COLS[3];
  return [...rows].sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    return (x < y ? -1 : x > y ? 1 : a.cve.localeCompare(b.cve)) * VU.sort.dir;
  });
}

function drawVulns() {
  const wrap = $("#vugrid");
  if (!wrap || !VU.data) return;
  const d = VU.data, rows = vuFiltered();
  VU.shown = rows;
  const card = (id, label, n, cls = "") => `<button type="button" class="vcard${VU.sev === id ? " on" : ""}" data-vsev="${id}"><span>${esc(label)}</span><b class="${cls}">${n}</b></button>`;
  $("#vu-cards").innerHTML = card("critical", t("sev.critical"), d.counts.critical, "sev-critical-t") + card("high", t("sev.high"), d.counts.high, "sev-high-t")
    + card("medium", t("sev.medium"), d.counts.medium) + card("low", t("sev.low"), d.counts.low) + card("kev", t("vu.kev"), d.counts.kev, "sev-critical-t");
  const st = d.status;
  $("#vu-status").innerHTML = (st.error ? `<span class="st-bad">${esc(st.error)}</span><br>` : "")
    + esc(tText("vu.coverage", { mapped: d.coverage.mapped, total: d.coverage.total }))
    + (st.fetched_at ? " · " + esc(tText("vu.fetched", { when: fmtDate(st.fetched_at) })) : " · " + esc(t("vu.never")));
  const head = `<th class="rn"></th>` + VU_COLS.map((c) => `<th data-vusort="${c.id}">${esc(t("vucol." + c.id))}${VU.sort.key === c.id ? `<span class="arr">${VU.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  const body = rows.slice(0, 3000).map((v) => `<tr data-vcve="${esc(v.cve)}"${VU.sel === v.cve ? ' class="sel"' : ""}><td class="rn"></td>${VU_COLS.map((c) => `<td class="${c.num ? "num" : ""}">${c.html(v)}</td>`).join("")}</tr>`).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(d.items.length ? t("page.empty") : t("vu.empty"))}</div>`;
  $("#sb-left").textContent = tText("vu.count", { n: rows.length });
}

function renderVulnsPage(el) {
  el.innerHTML = pageHead("warn", t("nav.vulns"), t("vu.sub"),
    `<button class="btn" data-vuact="refresh">${icon("sync", 16)}${esc(t("vu.refresh"))}</button>
     <button class="btn" data-vuact="export">${icon("export", 16)}${esc(t("page.export"))}</button>
     <button class="btn" data-vuact="details">${icon("details", 16)}${esc(t("tb.details"))}</button>
     <input class="page-filter" id="vu-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(VU.filter)}">`)
    + `<div class="vcards" id="vu-cards"></div><div class="faint vstatus" id="vu-status"></div><div class="grid-wrap" id="vugrid" tabindex="0"></div>`;
  $("#vu-cards").addEventListener("click", (e) => {
    const b = e.target.closest("[data-vsev]");
    if (!b) return;
    VU.sev = VU.sev === b.dataset.vsev ? "" : b.dataset.vsev;
    drawVulns();
  });
  const grid = $("#vugrid");
  grid.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-vusort]");
    if (th) {
      const k = th.dataset.vusort;
      VU.sort = VU.sort.key === k ? { key: k, dir: -VU.sort.dir } : { key: k, dir: k === "score" || k === "devices" || k === "severity" ? -1 : 1 };
      store.set("vusort", VU.sort);
      return drawVulns();
    }
    const tr = e.target.closest("tr[data-vcve]");
    if (!tr) return;
    VU.sel = tr.dataset.vcve;
    $$("#vugrid tbody tr").forEach((r) => r.classList.toggle("sel", r === tr));
  });
  grid.addEventListener("dblclick", (e) => { const tr = e.target.closest("tr[data-vcve]"); if (tr) openVuln(tr.dataset.vcve); });
  let tmr;
  $("#vu-filter").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { VU.filter = e.target.value; drawVulns(); }, 120); };
  $$("[data-vuact]", el).forEach((b) => (b.onclick = () => {
    const a = b.dataset.vuact;
    if (a === "details") { if (VU.sel) openVuln(VU.sel); return; }
    if (a === "refresh") return startJob("vulns");
    saveText("ADmiral-vulnerabilities.csv", csvText(VU_COLS.map((c) => t("vucol." + c.id)),
      vuFiltered().map((v) => [v.cve, v.software, v.range, v.score ?? "", t("sev." + v.severity), v.kev ? "KEV" : "", v.devices, v.published])));
  }));
  (async () => {
    VU.data = (await guard(() => api("GET", "/api/vulnerabilities"))) || VU.data;
    if (S.section === "vulns") drawVulns();
  })();
}

/* ------------------------------------------------------------------ vulnerability window */
async function openVuln(cve) {
  const list = (VU.shown || []).map((v) => v.cve);
  S.vw = { cve, list: list.includes(cve) ? list : [cve] };
  $("#vwin").hidden = false;
  $("#vwin-toolbar").innerHTML = ["prev", "next"].map((id) => `<button class="tb" data-vw="${id}">${icon(id, 30)}<span>${esc(t("sw." + id))}</span></button>`).join("")
    + `<button class="tb" data-vw="copy">${icon("copy", 30)}<span>${esc(t("tb.copy"))}</span></button><span class="tb-sep"></span><button class="tb" data-vw="close">${icon("back", 30)}<span>${esc(t("cw.close"))}</span></button>`;
  await loadVuln();
}
function closeVuln() { S.vw = null; $("#vwin").hidden = true; }
function vwStep(d) {
  if (!S.vw) return;
  const i = S.vw.list.indexOf(S.vw.cve) + d;
  if (i < 0 || i >= S.vw.list.length) return;
  S.vw.cve = S.vw.list[i]; VU.sel = S.vw.cve;
  loadVuln();
}
async function loadVuln() {
  const vw = S.vw;
  if (!vw) return;
  const d = await guard(() => api("GET", `/api/vulnerabilities/${encodeURIComponent(vw.cve)}`));
  if (!d || S.vw !== vw) return;
  const i = vw.list.indexOf(vw.cve);
  $("#vwin-title").textContent = tText("vu.title", { cve: d.cve, i: i + 1, n: vw.list.length });
  $('#vwin-toolbar [data-vw="prev"]').disabled = i <= 0;
  $('#vwin-toolbar [data-vw="next"]').disabled = i >= vw.list.length - 1;
  $("#vwin-cats").innerHTML = `<div class="cat sel">${icon("warn", 18)}<span>${esc(t("vu.sec.cve"))}</span></div>`;
  $("#vwin-head").innerHTML = `${icon("warn", 30)}<span>${esc(d.cve)}</span>${sevChip(d.severity)}${d.kev ? `<span class="kev" title="${esc(t("vu.kev_tip"))}">KEV</span>` : ""}<span class="grow"></span><span class="faint">${esc(t("vu.probably"))}</span>`;
  $("#vwin-status").textContent = tText("vu.devices_n", { n: d.devices });
  $("#vwin-content").innerHTML = `<div class="form2"><div>
      <div class="fsec">${t("vu.sec.cve")}</div>
      ${fieldRow(t("vucol.score"), d.score == null ? "" : d.score.toFixed(1))}${fieldRow(t("vucol.severity"), sevChip(d.severity), { html: true })}
      ${fieldRow(t("vucol.kev"), d.kev ? t("v.yes") : t("v.no"))}${fieldRow(t("vucol.published"), d.published)}${fieldRow(t("vucol.range"), d.range)}
      ${fieldRow(t("vu.summary"), d.summary, { wrap: true })}
    </div><div>
      <div class="fsec">${t("vu.sec.affected")}</div>
      ${d.affected.map((a) => `<div class="frow"><label>${esc(a.name)}</label><div class="fval wrap">${a.versions.map((v) => `<div><b>${esc(v.version)}</b> – ${v.devices.map((x) => `<a href="#" data-comp="${esc(x.guid)}">${esc(x.name)}</a>`).join(", ")}</div>`).join("")}
        ${(a.fixes || []).map((f, i) => `<div style="margin-top:6px"><button class="btn primary" type="button" data-fix="${esc(a.key)}|${i}">${icon("rocket", 16)}${esc(tText("vu.fix_btn", { pkg: f.package_name, ver: f.version, n: f.devices.length }))}</button></div>`).join("")}</div></div>`).join("")}
    </div></div>`;
  $$("#vwin-content [data-fix]").forEach((b) => (b.onclick = () => {
    const [key, i] = b.dataset.fix.split("|");
    const a = d.affected.find((x) => x.key === key);
    if (a) vuFixDialog(a.fixes[Number(i)]);
  }));
  $$("#vwin-content [data-comp]").forEach((a) => (a.onclick = (e) => { e.preventDefault(); const cve = S.vw.cve; closeVuln(); openComputer(a.dataset.comp, () => openVuln(cve)); }));   // closing the computer returns to this vulnerability
}

// install the newer library version on the affected computers (several at once), through the normal deployment
function vuFixDialog(f) {
  const ext = (p) => (p.toLowerCase().match(/\.(msi|exe)$/) || [])[1];
  const sel = new Set(f.devices.map((x) => x.guid));
  const box = dialog(tText("vu.fix_title", { pkg: f.package_name, ver: f.version }), `
    <div class="faint">${esc(t("vu.fix_hint"))}</div>
    <label class="fld"><span>${esc(t("dp.installer"))}</span><select id="vf-file">${f.files.map((x, i) => `<option value="${i}">${esc(x.name)}</option>`).join("")}</select></label>
    <label class="fld"><span>${esc(t("dp.args"))}</span><input id="vf-args" class="field-in mono" type="text"></label>
    <div id="vf-presets" class="faint"></div><div class="faint">${esc(t("dp.args_hint"))}</div>
    <div class="subtable-tools"><span class="faint" id="vf-count"></span><button class="btn" id="vf-all" type="button">${esc(t("dp.all"))}</button><button class="btn" id="vf-none" type="button">${esc(t("dp.none"))}</button></div>
    <div id="vf-list" style="flex:none;max-height:260px;overflow:auto;border:1px solid var(--border-soft)">${f.devices.map((x) =>
      `<label class="chk" style="padding:2px 8px;display:flex"><input type="checkbox" data-g="${esc(x.guid)}" checked> ${esc(x.name)} <span class="faint">${esc(x.version)} → ${esc(f.version)}</span></label>`).join("")}</div>
    ${dpInvCheck("vf-inv")}`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="vf-go">${esc(t("dp.start"))}</button>`);
  const cur = () => f.files[Number($("#vf-file", box).value)];
  const count = () => ($("#vf-count", box).textContent = tText("dp.selected", { n: sel.size }));
  const presets = () => {
    const p = DP_PRESETS[ext(cur().path)] || [""];
    $("#vf-presets", box).innerHTML = p.map((a) => `<button class="btn" type="button" data-preset="${esc(a)}">${esc(a || t("dp.no_switches"))}</button>`).join(" ");
    $("#vf-args", box).value = p[0];
  };
  $("#vf-file", box).onchange = presets;
  $("#vf-presets", box).onclick = (e) => { const b = e.target.closest("[data-preset]"); if (b) $("#vf-args", box).value = b.dataset.preset; };
  $("#vf-list", box).onchange = (e) => { const g = e.target.dataset.g; if (!g) return; e.target.checked ? sel.add(g) : sel.delete(g); count(); };
  const all = (on) => { $$("#vf-list input", box).forEach((c) => { c.checked = on; on ? sel.add(c.dataset.g) : sel.delete(c.dataset.g); }); count(); };
  $("#vf-all", box).onclick = () => all(true);
  $("#vf-none", box).onclick = () => all(false);
  presets(); count();
  $("#vf-go", box).onclick = () => guard(async () => {
    if (!sel.size) return toast(t("dp.pick_computers"), true);
    const label = `${f.package_name} ${f.version} — ${cur().name}`;
    if (!(await confirmDialog(tText("dp.confirm", { pkg: label, n: sel.size })))) return;
    const args = $("#vf-args", box).value, file = cur().path, inv = $("#vf-inv", box).checked;
    closeDialog();
    closeVuln();
    if (inv) await dpRefreshInventory([...sel]);
    const r = await api("POST", "/api/deployments", { package_id: f.package_id, file, args, ids: [...sel] });
    DP.sel = r.id;
    setSection("deployments");
  });
}

/* ================================================================== window bindings */
function bindSoftwareWindows() {
  $("#swin").addEventListener("click", (e) => {
    if (e.target.id === "swin") return closeSoftware();
    const b = e.target.closest("[data-sw]");
    if (b && !b.disabled) { ({ close: closeSoftware, prev: () => swStep(-1), next: () => swStep(1) })[b.dataset.sw]?.(); return; }
    const cat = e.target.closest("[data-swcat]");
    if (cat && S.sw) { S.sw.cat = cat.dataset.swcat; S.sw.filter = ""; renderSoftware(); }
  });
  $("#vwin").addEventListener("click", (e) => {
    if (e.target.id === "vwin") return closeVuln();
    const b = e.target.closest("[data-vw]");
    if (b && !b.disabled) ({ close: closeVuln, prev: () => vwStep(-1), next: () => vwStep(1), copy: async () => { await copyText(S.vw.cve); toast(tText("copied", { n: 1 })); } })[b.dataset.vw]?.();
  });
}
