/* ADmiral – Printers: network printers read over SNMP (toner level, page count, model...), each with its own
   OIDs, a free "Location" and a note. Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, dialog, ...). */
"use strict";

const PR = { list: [], sort: store.get("prsort", { key: "ip", dir: 1 }), filter: "", sel: null, busy: false };

const PR_DEFAULTS = {
  oid_model: "1.3.6.1.2.1.25.3.2.1.3.1",
  oid_toner: "1.3.6.1.2.1.43.11.1.1.9.1.1",
  oid_toner_max: "1.3.6.1.2.1.43.11.1.1.8.1.1",
  oid_pages: "1.3.6.1.2.1.43.10.2.1.4.1.1",
  oid_serial: "1.3.6.1.2.1.43.5.1.1.17.1",
  oid_status: "1.3.6.1.2.1.25.3.5.1.1.1",
};
const PR_COLOR = {
  oid_toner: [1, 2, 3, 4].map((i) => `1.3.6.1.2.1.43.11.1.1.9.1.${i}`).join(", "),
  oid_toner_max: [1, 2, 3, 4].map((i) => `1.3.6.1.2.1.43.11.1.1.8.1.${i}`).join(", "),
};
const PR_OIDS = ["oid_model", "oid_toner", "oid_toner_max", "oid_pages", "oid_serial", "oid_status"];

const prIpKey = (ip) => (/^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip.split(".").map((x) => x.padStart(3, "0")).join(".") : "z" + ip.toLowerCase());

// one meter per toner: green, orange below 25 %, red below 10 %
function prToner(p) {
  if (!p.toner.length) return p.error ? `<span class="st-bad" title="${esc(p.error)}">${icon("dst_bad", 14)}</span>` : "";
  const w = p.toner.length > 1 ? 30 : 90;
  const cells = p.toner.map((x) => {
    if (x.pct == null) {
      const txt = x.level === -3 ? t("pr.toner_some") : t("pr.toner_unknown");
      return `<span class="faint" title="${esc(x.oid)}">${esc(txt)}</span>`;
    }
    const col = x.pct < 10 ? "var(--bad, #dc2626)" : x.pct < 25 ? "var(--warn, #d97706)" : "var(--ok, #16a34a)";
    return `<span class="pr-toner" title="${esc(x.oid)}"><span class="meter" style="width:${w}px;margin:0 4px 0 0"><span style="width:${x.pct}%;background:${col}"></span></span>${x.pct}%</span>`;
  });
  return `<span style="display:inline-flex;gap:8px">${cells.join("")}</span>`
    + (p.error ? ` <span class="st-warn" title="${esc(p.error)}">${icon("dst_warn", 14)}</span>` : "");
}

const PR_COLS = [
  { id: "ip", get: (p) => prIpKey(p.ip), html: (p) => `${icon("printer", 16)}${esc(p.ip)}`
      + (p.error && !p.toner.length ? ` <span class="st-bad" title="${esc(p.error)}">${icon("dst_bad", 14)}</span>` : "") },
  { id: "model", get: (p) => p.model.toLowerCase(), html: (p) => esc(p.model) + (p.status ? ` <span class="faint">(${esc(t("pr.status." + p.status))})</span>` : "") },
  { id: "location", get: (p) => p.location.toLowerCase(), html: (p) => esc(p.location) },
  { id: "toner", get: (p) => Math.min(...p.toner.map((x) => (x.pct == null ? 101 : x.pct)), 102), html: prToner },
  { id: "pages", get: (p) => p.pages ?? -1, num: true, html: (p) => (p.pages == null ? "" : p.pages.toLocaleString(locale())) },
  { id: "note", get: (p) => p.note.toLowerCase(), html: (p) => esc(p.note).replace(/\n/g, " · ") },
];

function prFiltered() {
  const q = PR.filter.trim().toLowerCase();
  let rows = PR.list;
  if (q) rows = rows.filter((p) => [p.ip, p.model, p.location, p.note, p.serial].join(" ").toLowerCase().includes(q));
  const col = PR_COLS.find((c) => c.id === PR.sort.key) || PR_COLS[0];
  return [...rows].sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    return (x < y ? -1 : x > y ? 1 : prIpKey(a.ip) < prIpKey(b.ip) ? -1 : 1) * PR.sort.dir;
  });
}

function drawPrinters() {
  const wrap = $("#prgrid");
  if (!wrap) return;
  const rows = prFiltered();
  const head = `<th class="rn"></th>` + PR_COLS.map((c) => `<th data-prsort="${c.id}">${esc(t("pr.col." + c.id))}${PR.sort.key === c.id ? `<span class="arr">${PR.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  const body = rows.map((p) => `<tr data-pr="${p.id}"${PR.sel === p.id ? ' class="sel"' : ""}><td class="rn"></td>${PR_COLS.map((c) =>
    `<td class="${c.num ? "num" : ""}">${c.html(p)}</td>`).join("")}</tr>`).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(t("pr.empty"))}</div>`;
  $("#sb-left").textContent = tText("pr.count", { n: rows.length });
}

async function prLoad() {
  const list = await guard(() => api("GET", "/api/printers"));
  if (list) PR.list = list;
  drawPrinters();
}

function prMerge(updated) {
  for (const u of [].concat(updated)) {
    const i = PR.list.findIndex((p) => p.id === u.id);
    if (i >= 0) PR.list[i] = u; else PR.list.push(u);
  }
  drawPrinters();
}

async function prPoll(ids) {
  if (PR.busy) return;
  PR.busy = true;
  const btn = $('[data-pract="poll"]');
  if (btn) btn.disabled = true;
  $("#sb-right") && ($("#sb-right").textContent = t("pr.polling"));
  try {
    const r = await guard(() => api("POST", "/api/printers/poll", ids ? { ids } : {}));
    if (r) prMerge(r);
  } finally {
    PR.busy = false;
    if ($('[data-pract="poll"]')) $('[data-pract="poll"]').disabled = false;
    $("#sb-right") && ($("#sb-right").textContent = "");
  }
}

/* ------------------------------------------------------------------ history chart + forecast */
const PR_COLORS = ["#3b82f6", "#06b6d4", "#d946ef", "#eab308"];
const PR_COLORS4 = ["#9ca3af", "#06b6d4", "#d946ef", "#eab308"];          // black, cyan, magenta, yellow
const prDay = (d) => new Date(d + "T12:00:00").getTime();

// a small SVG line chart: lines = [{color, pts: [[ms, value]], dash}], the y range is 0..yMax
function prSvg(lines, yMax, unit, yMin = 0) {
  const W = 680, H = 230, L = 46, R = 14, T = 10, B = 26;
  const xs = lines.flatMap((l) => l.pts.map((p) => p[0]));
  if (!xs.length) return "";
  let x0 = Math.min(...xs), x1 = Math.max(...xs);
  if (x1 === x0) x1 = x0 + 86400000;
  const X = (v) => L + ((v - x0) / (x1 - x0)) * (W - L - R), Y = (v) => T + (1 - (Math.min(v, yMax) - yMin) / (yMax - yMin)) * (H - T - B);
  const grid = [0, 1, 2, 3, 4].map((i) => {
    const v = yMin + ((yMax - yMin) * i) / 4, y = Y(v);
    return `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" style="stroke:var(--border-soft)"/><text x="${L - 6}" y="${y + 4}" text-anchor="end" font-size="11" fill="currentColor" opacity=".7">${Math.round(v).toLocaleString(locale())}${unit}</text>`;
  }).join("");
  const ticks = [0, 1, 2, 3, 4].map((i) => {
    const v = x0 + ((x1 - x0) * i) / 4;
    return `<text x="${X(v)}" y="${H - 8}" text-anchor="${i === 0 ? "start" : i === 4 ? "end" : "middle"}" font-size="11" fill="currentColor" opacity=".7">${new Date(v).toLocaleDateString(locale(), { month: "short", day: "numeric" })}</text>`;
  }).join("");
  const paths = lines.map((l) => `<polyline fill="none" stroke="${l.color}" stroke-width="2"${l.dash ? ' stroke-dasharray="6 4"' : ""} points="${l.pts.map((p) => `${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join(" ")}"/>`
    + (l.dash ? "" : l.pts.map((p) => `<circle cx="${X(p[0]).toFixed(1)}" cy="${Y(p[1]).toFixed(1)}" r="2.5" fill="${l.color}"/>`).join(""))).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px;display:block">${grid}${ticks}${paths}</svg>`;
}

async function prHistory(p) {
  const h = await guard(() => api("GET", `/api/printers/${p.id}/history`));
  if (!h) return;
  const days = h.days, fc = h.forecast;
  if (!days.length) return dialog(tText("pr.hist_title", { ip: p.ip }), `<div class="empty">${esc(t("pr.hist_none"))}</div>`);
  const n = Math.max(...days.map((d) => d.toner.length), 0);
  const colors = n === 4 ? PR_COLORS4 : PR_COLORS;
  const name = (i) => tText("pr.toner_n", { n: i + 1 });
  const lines = [], notes = [];
  for (let i = 0; i < n; i++) {
    const pts = days.filter((d) => d.toner[i] != null).map((d) => [prDay(d.day), d.toner[i]]);
    if (!pts.length) continue;
    lines.push({ color: colors[i % colors.length], pts });
    const f = fc.toner[i];
    const dot = `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${colors[i % colors.length]};margin-right:6px"></span>`;
    if (f && f.empty_on) {
      const last = pts[pts.length - 1], end = prDay(f.empty_on), cap = last[0] + 90 * 86400000;   // the chart shows at most 90 days ahead
      const stop = end <= cap ? [end, 0] : [cap, last[1] * (1 - (cap - last[0]) / (end - last[0]))];
      lines.push({ color: colors[i % colors.length], dash: true, pts: [last, stop] });
      notes.push(dot + esc(tText("pr.hist_use", { name: n > 1 ? name(i) : t("pr.col.toner"), last: f.last, per: f.per_day, date: new Date(end).toLocaleDateString(locale()), days: f.days_left })));
    } else {
      notes.push(dot + esc(tText("pr.hist_nofc", { name: n > 1 ? name(i) : t("pr.col.toner"), last: f ? f.last : "–" })));
    }
  }
  const pages = days.filter((d) => d.pages != null).map((d) => [prDay(d.day), d.pages]);
  const pmax = pages.length ? Math.max(...pages.map((x) => x[1])) : 0;
  const pmin = pages.length ? Math.min(...pages.map((x) => x[1])) : 0;
  const pad = Math.max(4, Math.ceil((pmax - pmin) * 0.1));
  dialog(tText("pr.hist_title", { ip: p.ip }), `<div style="min-width:620px">
    <div class="faint" style="margin-bottom:6px">${esc(tText("pr.hist_n", { n: days.length }))} · <span style="border-bottom:2px dashed currentColor">&nbsp;&nbsp;&nbsp;</span> ${esc(t("pr.hist_fc"))}</div>
    ${prSvg(lines, 100, "%")}
    <div style="display:flex;flex-direction:column;gap:3px;margin:8px 0 14px">${notes.map((x) => `<div>${x}</div>`).join("")}</div>
    ${pages.length ? `<b>${esc(t("pr.hist_pages"))}</b>${fc.pages_per_day != null ? ` <span class="faint">${esc(tText("pr.hist_ppd", { n: fc.pages_per_day.toLocaleString(locale()) }))}</span>` : ""}
    ${prSvg([{ color: "#3b82f6", pts: pages }], pmax + pad, "", Math.max(0, pmin - pad))}` : ""}</div>`);
}

/* ------------------------------------------------------------------ add / edit dialog */
function prDialog(p) {
  const cur = p || { ip: "", community: "public", version: "2c", model: "", location: "", note: "", ...PR_DEFAULTS };
  const fld = (id, label, val, extra = "") => `<label class="fld"><span>${esc(label)}</span><input id="${id}" type="text" value="${esc(val)}" ${extra}></label>`;
  const body = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;min-width:560px">
      ${fld("pr-ip", t("pr.f.ip"), cur.ip, 'autocomplete="off" spellcheck="false"')}
      ${fld("pr-model", t("pr.f.model"), cur.model)}
      ${fld("pr-comm", t("pr.f.community"), cur.community, 'autocomplete="off" spellcheck="false"')}
      <label class="fld"><span>${esc(t("pr.f.version"))}</span><select id="pr-ver"><option value="2c"${cur.version === "2c" ? " selected" : ""}>v2c</option><option value="1"${cur.version === "1" ? " selected" : ""}>v1</option></select></label>
      ${fld("pr-loc", t("pr.f.location"), cur.location)}
      <span></span>
      <label class="fld" style="grid-column:1/3"><span>${esc(t("pr.f.note"))}</span><textarea id="pr-note" rows="2">${esc(cur.note)}</textarea></label>
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin:14px 0 4px"><b>${esc(t("pr.oid.title"))}</b><span class="grow" style="flex:1"></span>
      <label class="faint">${esc(t("pr.preset"))} <select id="pr-preset" class="field-in"><option value=""></option>
        <option value="mono">${esc(t("pr.preset.mono"))}</option><option value="color">${esc(t("pr.preset.color"))}</option></select></label></div>
    <div class="faint" style="margin-bottom:6px">${esc(t("pr.oid.hint"))}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      ${PR_OIDS.map((k) => fld("pr-" + k, t("pr." + k.replace("_", ".")), cur[k], 'class="mono" spellcheck="false" style="width:100%"')).join("")}
    </div>
    <div style="margin-top:12px;display:flex;gap:10px;align-items:flex-start">
      <button class="btn" id="pr-test" type="button">${esc(t("pr.test"))}</button>
      <pre class="mono" id="pr-test-out" style="margin:0;flex:1;white-space:pre-wrap;user-select:text"></pre></div>`;
  const box = dialog(t(p ? "pr.title_edit" : "pr.title_add"), body,
    `${p ? `<button class="btn" id="pr-hist" type="button">${esc(t("pr.hist"))}</button>` : ""}<span style="flex:1"></span><button class="btn" data-dclose type="button">${esc(t("d.cancel"))}</button><button class="btn primary" id="pr-save" type="button">${esc(t(p ? "d.save" : "d.add"))}</button>`);
  const val = (id) => $("#" + id, box).value;
  const data = () => {
    const d = { ip: val("pr-ip").trim(), model: val("pr-model"), location: val("pr-loc"), note: val("pr-note"),
      community: val("pr-comm"), version: val("pr-ver") };
    PR_OIDS.forEach((k) => (d[k] = val("pr-" + k)));
    return d;
  };
  $("#pr-preset", box).onchange = (e) => {
    const v = e.target.value;
    if (v) Object.entries({ ...PR_DEFAULTS, ...(v === "color" ? PR_COLOR : {}) }).forEach(([k, x]) => { if (k === "oid_toner" || k === "oid_toner_max") $("#pr-" + k, box).value = x; });
    e.target.value = "";
  };
  $("#pr-test", box).onclick = async () => {
    const out = $("#pr-test-out", box);
    out.className = "mono";
    out.textContent = t("pr.test_run");
    try {
      const r = await api("POST", "/api/printers/test", data());
      if (r.error && !r.toner) { out.className = "mono st-bad"; out.textContent = r.error; return; }
      const toner = (r.toner || []).map((x) => (x.pct != null ? x.pct + "%" : x.level ?? "–")).join(", ") || "–";
      out.textContent = tText("pr.test_res", { model: r.model || "–", serial: r.serial || "–", status: r.status ? t("pr.status." + r.status) : "–", pages: r.pages ?? "–", toner })
        + (r.error ? "\n" + r.error : "");
    } catch (e) { out.className = "mono st-bad"; out.textContent = e.message; }
  };
  if (p) $("#pr-hist", box).onclick = () => prHistory(p);
  $("#pr-save", box).onclick = async () => {
    if (!val("pr-ip").trim()) return $("#pr-ip", box).focus();
    const r = await guard(() => (p ? api("PUT", `/api/printers/${p.id}`, data()) : api("POST", "/api/printers", data())));
    if (!r) return;
    closeDialog();
    PR.sel = r.id;
    prMerge(r);
  };
}

async function prDelete(p) {
  if (!(await confirmDialog(tText("pr.delete_confirm", { ip: p.ip })))) return;
  const r = await guard(() => api("DELETE", `/api/printers/${p.id}`));
  if (!r) return;
  PR.list = PR.list.filter((x) => x.id !== p.id);
  drawPrinters();
}

/* ------------------------------------------------------------------ IP range scan */
const PR_SCAN = store.get("prscan", { range: "", community: "public", version: "2c", all: false });

function prScanDialog() {
  let found = [];
  const body = `<div>
    <div style="display:grid;grid-template-columns:minmax(150px,2fr) minmax(90px,1fr) 90px auto;gap:10px;align-items:end">
      <label class="fld"><span>${esc(t("pr.scan.range"))}</span><input id="prs-range" type="text" value="${esc(PR_SCAN.range)}" placeholder="192.168.1.0/24" autocomplete="off" spellcheck="false"></label>
      <label class="fld"><span>${esc(t("pr.f.community"))}</span><input id="prs-comm" type="text" value="${esc(PR_SCAN.community)}" autocomplete="off" spellcheck="false"></label>
      <label class="fld"><span>${esc(t("pr.f.version"))}</span><select id="prs-ver"><option value="2c"${PR_SCAN.version === "2c" ? " selected" : ""}>v2c</option><option value="1"${PR_SCAN.version === "1" ? " selected" : ""}>v1</option></select></label>
      <button class="btn primary" id="prs-go" type="button">${icon("scan", 16)}${esc(t("pr.scan.go"))}</button>
    </div>
    <div class="faint" style="margin:6px 0 10px">${esc(t("pr.scan.hint"))}</div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <span id="prs-status" class="faint" style="flex:1"></span>
      <label class="faint"><input type="checkbox" id="prs-all"${PR_SCAN.all ? " checked" : ""}> ${esc(t("pr.scan.all"))}</label>
    </div>
    <div id="prs-out" class="grid-wrap" style="max-height:52vh;min-height:120px"></div></div>`;
  const box = dialog(t("pr.scan.title"), body);
  box.style.width = "min(1000px, calc(100vw - 32px))";
  const val = (id) => $("#" + id, box).value;
  const draw = () => {
    const out = $("#prs-out", box);
    const rows = found.filter((r) => PR_SCAN.all || r.printer);
    if (!rows.length) { out.innerHTML = found.length || $("#prs-status", box).dataset.done ? `<div class="empty">${esc(t("pr.scan.none"))}</div>` : ""; return; }
    out.innerHTML = `<table class="grid"><thead><tr>${["", "ip", "name", "model", "location", "serial", "pages"].map((c) => `<th>${c ? esc(t("pr.scan.col." + c)) : ""}</th>`).join("")}</tr></thead><tbody>
      ${rows.map((r) => `<tr data-ip="${esc(r.ip)}">
        <td>${r.known ? `<span class="faint">${esc(t("pr.scan.known"))}</span>` : `<button class="btn" data-prsadd="${esc(r.ip)}" type="button">${esc(t("d.add"))}</button>`}</td>
        <td>${icon(r.printer ? "printer" : "scan", 16)}${esc(r.ip)}</td><td>${esc(r.name)}</td>
        <td>${esc(r.model)}${r.color ? ` <span class="faint">(${esc(t("pr.scan.color"))})</span>` : ""}</td><td>${esc(r.location)}</td><td>${esc(r.serial)}</td>
        <td class="num">${r.pages == null ? "" : r.pages.toLocaleString(locale())}</td></tr>`).join("")}
      </tbody></table>`;
  };
  const go = async () => {
    const range = val("prs-range").trim();
    if (!range) return $("#prs-range", box).focus();
    Object.assign(PR_SCAN, { range, community: val("prs-comm").trim() || "public", version: val("prs-ver") });
    store.set("prscan", PR_SCAN);
    const btn = $("#prs-go", box), st = $("#prs-status", box);
    btn.disabled = true;
    st.className = "faint";
    st.textContent = t("pr.scan.running");
    delete st.dataset.done;
    found = [];
    draw();
    try {
      const r = await api("POST", "/api/printers/scan", { range, community: PR_SCAN.community, version: PR_SCAN.version });
      found = r.found;
      st.dataset.done = "1";
      st.textContent = tText("pr.scan.result", { n: r.scanned, p: found.filter((x) => x.printer).length, d: found.length });
    } catch (e) { st.className = "st-bad"; st.textContent = e.message; }
    finally { btn.disabled = false; draw(); }
  };
  $("#prs-go", box).onclick = go;
  $("#prs-range", box).onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } };
  $("#prs-all", box).onchange = (e) => { PR_SCAN.all = e.target.checked; store.set("prscan", PR_SCAN); draw(); };
  $("#prs-out", box).addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-prsadd]");
    if (!b) return;
    const r = found.find((x) => x.ip === b.dataset.prsadd);
    if (!r) return;
    b.disabled = true;
    b.textContent = t("pr.scan.adding");
    const data = { ip: r.ip, community: PR_SCAN.community, version: PR_SCAN.version, model: r.model, location: r.location,
      ...(r.color ? PR_COLOR : {}) };
    const p = await guard(() => api("POST", "/api/printers", data));
    if (!p) { b.disabled = false; b.textContent = t("d.add"); return; }
    r.known = p.id;
    prMerge(p);
    draw();
  });
  setTimeout(() => $("#prs-range", box).focus(), 40);
}

/* ------------------------------------------------------------------ page */
function renderPrintersPage(el) {
  el.innerHTML = pageHead("printer", t("nav.printers"), t("pr.sub"),
    `<button class="btn primary" data-pract="add">${esc(t("pr.add"))}</button>
     <button class="btn" data-pract="scan">${icon("scan", 16)}${esc(t("pr.scan"))}</button>
     <button class="btn" data-pract="poll">${icon("sync", 16)}${esc(t("pr.poll"))}</button>
     <input class="page-filter" id="pr-filter" type="search" placeholder="${esc(t("pr.search"))}" value="${esc(PR.filter)}">`)
    + `<div class="grid-wrap" id="prgrid" tabindex="0"></div>`;
  $('[data-pract="add"]', el).onclick = () => prDialog(null);
  $('[data-pract="poll"]', el).onclick = () => prPoll();
  $('[data-pract="scan"]', el).onclick = () => prScanDialog();
  $("#pr-filter").oninput = (e) => { PR.filter = e.target.value; drawPrinters(); };
  const grid = $("#prgrid");
  grid.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-prsort]");
    if (th) {
      const k = th.dataset.prsort;
      PR.sort = PR.sort.key === k ? { key: k, dir: -PR.sort.dir } : { key: k, dir: 1 };
      store.set("prsort", PR.sort);
      return drawPrinters();
    }
    const tr = e.target.closest("tr[data-pr]");
    if (!tr || e.target.closest("input")) return;
    PR.sel = Number(tr.dataset.pr);
    $$("tr[data-pr]", grid).forEach((r) => r.classList.toggle("sel", r === tr));
  });
  grid.addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr[data-pr]");
    if (!tr || e.target.closest("input")) return;
    const p = PR.list.find((x) => x.id === Number(tr.dataset.pr));
    if (p) prHistory(p);                                   // history + forecast only; editing is in the context menu
  });
  grid.addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-pr]");
    if (!tr) return;
    e.preventDefault();
    const p = PR.list.find((x) => x.id === Number(tr.dataset.pr));
    if (!p) return;
    PR.sel = p.id;
    $$("tr[data-pr]", grid).forEach((r) => r.classList.toggle("sel", r === tr));
    showMenu([
      { label: t("pr.edit"), action: () => prDialog(p) },
      { label: t("pr.hist"), action: () => prHistory(p) },
      { label: t("pr.poll_one"), icon: "sync", action: () => prPoll([p.id]) },
      { label: t("pr.delete"), action: () => prDelete(p) },
    ], e.clientX, e.clientY);
  });
  drawPrinters();
  prLoad().then(() => PR.list.length && prPoll());          // show what is stored at once, then read the printers
}
