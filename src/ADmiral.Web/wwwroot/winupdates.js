/* ADmiral – Windows updates: the newest Microsoft security release per Windows build (reference data) and
   how many computers run which build, from their collected inventories. Click a build to list its computers.
   Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

// showEmpty: also list the reference builds no computer on the network runs (hidden by default)
const WU = { data: null, filter: "", build: "", showEmpty: store.get("wuempty", false) };

async function loadWinUpdates() {
  WU.data = (await guard(() => api("GET", "/api/winupdates"))) || WU.data;
  return WU.data;
}

function wuGroups() {
  const q = WU.filter.trim().toLowerCase();
  const by = new Map();
  for (const c of WU.data?.computers || []) {
    if (!c.installed) continue;
    if (WU.build && c.build !== WU.build) continue;
    if (q && ![c.installed, c.os, c.name].join(" ").toLowerCase().includes(q)) continue;
    let g = by.get(c.installed);
    if (!g) by.set(c.installed, (g = { installed: c.installed, build: c.build, latest: c.latest, state: c.state, os: {}, computers: [] }));
    g.os[c.os] = (g.os[c.os] || 0) + 1;
    g.computers.push(c);
  }
  return [...by.values()].map((g) => ({ ...g, osName: Object.entries(g.os).sort((a, b) => b[1] - a[1])[0]?.[0] || "" }))
    .sort((a, b) => b.computers.length - a.computers.length || b.installed.localeCompare(a.installed));
}

const wuState = (g) => {
  const [cls, label] = ({ current: ["st-ok", t("sec.current")], missing: ["st-bad", t("sec.missing")], pending: ["st-warn", t("sec.pending")] })[g.state] || ["faint", t("sec.unknown")];
  return `<span class="${cls}">${esc(label)}</span>${g.state === "missing" && g.latest ? ` <span class="faint">→ ${esc(g.latest)}</span>` : ""}`;
};

function drawWinUpdates() {
  const box = $("#wu-body");
  if (!box || !WU.data) return;
  const { status, reference, computers } = WU.data;
  const total = computers.length, known = computers.filter((c) => c.installed).length;
  const missing = computers.filter((c) => c.state === "missing").length;
  const stat = status.error ? `<span class="st-bad">${esc(status.error)}</span>`
    : status.fetched_at ? esc(tText("s.upd_ok", { when: fmtDate(status.fetched_at), n: status.builds, months: (status.months || []).join(", ") })) : esc(t("wu.never"));
  const used = new Set(computers.map((c) => c.build));
  const emptyN = reference.filter((r) => !used.has(r.build)).length;
  const refRows = reference.filter((r) => WU.showEmpty || used.has(r.build)).map((r) => {
    const onBuild = computers.filter((c) => c.build === r.build);
    const miss = onBuild.filter((c) => c.state === "missing").length;
    return `<tr data-wubuild="${esc(r.build)}"${WU.build === r.build ? ' class="sel"' : ""}><td class="rn"></td><td>${icon("patch", 16)}${esc(r.build)}</td><td>${esc(r.build + "." + r.ubr)}</td><td>${esc(r.month || "")}</td><td>${esc(r.released || "")}</td><td class="num">${onBuild.length}</td><td class="num">${miss ? `<span class="st-bad">${miss}</span>` : "0"}</td></tr>`;
  }).join("");
  const groups = wuGroups();
  WU.shown = groups;
  const gRows = groups.map((g, i) => `<tr data-wugroup="${i}"><td class="rn"></td><td>${icon("computer", 16)}${esc(g.installed)}</td><td>${esc(g.osName)}</td><td>${wuState(g)}</td><td class="num"><b>${g.computers.length}</b></td></tr>`).join("");
  box.innerHTML = `<div class="faint" style="margin:0 0 8px">${stat} · ${esc(tText("wu.summary", { known, total, missing }))}</div>
    <h3 class="wu-h">${esc(t("wu.ref_title"))}${emptyN ? ` <label class="chk wu-empty" style="display:inline-flex;font-weight:normal;font-size:12.5px;margin-left:12px"><input type="checkbox" id="wu-empty" ${WU.showEmpty ? "checked" : ""}> ${esc(tText("wu.show_empty", { n: emptyN }))}</label>` : ""}</h3>
    ${refRows ? `<div class="grid-wrap wu-ref"><table class="grid"><thead><tr><th class="rn"></th>${["build", "latest", "month", "released", "devices", "missing"].map((c) => `<th>${esc(t("wu.col." + c))}</th>`).join("")}</tr></thead><tbody>${refRows}</tbody></table></div>`
      : `<div class="empty">${esc(t(reference.length ? "wu.none_used" : "wu.no_ref"))}</div>`}
    <h3 class="wu-h">${esc(t("wu.inst_title"))}${WU.build ? ` <span class="faint">(${esc(WU.build)} <a href="#" data-wuclear>✕</a>)</span>` : ""}</h3>
    ${groups.length ? `<div class="grid-wrap wu-inst"><table class="grid"><thead><tr><th class="rn"></th>${["installed", "os", "state", "devices"].map((c) => `<th>${esc(t("wu.col." + c))}</th>`).join("")}</tr></thead><tbody>${gRows}</tbody></table></div>`
      : `<div class="empty">${esc(t("wu.empty"))}</div>`}`;
  const ec = $("#wu-empty", box);
  if (ec) ec.onchange = () => { WU.showEmpty = ec.checked; store.set("wuempty", WU.showEmpty); drawWinUpdates(); };
  $("#sb-left").textContent = tText("wu.count", { n: groups.length });
}

function wuComputersDialog(g) {
  const rows = [...g.computers].sort((a, b) => a.name.localeCompare(b.name));
  const box = dialog(`${g.installed} – ${tText("wu.devices_n", { n: rows.length })}`,
    `<div class="grid-wrap" style="max-height:60vh;overflow:auto"><table class="grid"><thead><tr><th class="rn"></th><th>${esc(t("wu.col.computer"))}</th><th>${esc(t("wu.col.os"))}</th><th>${esc(t("wu.col.ou"))}</th><th>${esc(t("wu.col.state"))}</th></tr></thead><tbody>
    ${rows.map((c) => `<tr data-wuguid="${esc(c.guid)}"><td class="rn"></td><td>${icon("computer", 16)}${esc(c.name)}</td><td>${esc(c.os)}</td><td>${esc(c.ou)}</td><td>${wuState(c)}</td></tr>`).join("")}</tbody></table></div>
    <div class="faint" style="margin-top:6px">${esc(t("wu.dbl"))}</div>`,
    `<button class="btn" data-copy>${esc(t("tb.copy"))}</button><span style="flex:1"></span><button class="btn" data-dclose>${esc(t("d.close"))}</button>`);
  $$("[data-dclose]", box).forEach((b) => (b.onclick = closeDialog));
  box.querySelector("[data-copy]").onclick = async () => {
    try { await navigator.clipboard.writeText(rows.map((c) => c.name).join("\r\n")); toast(tText("copied", { n: rows.length })); } catch (e) { toast(String(e), true); }
  };
  box.querySelector("tbody").ondblclick = (e) => {
    const tr = e.target.closest("tr[data-wuguid]");
    if (tr) { closeDialog(); setSection("devices"); openComputer(tr.dataset.wuguid); }
  };
}

function renderWinUpdatesPage(el) {
  el.innerHTML = pageHead("patch", t("nav.winupdates"), t("wu.sub"),
    `<button class="btn" data-wuact="refresh">${icon("sync", 16)}${esc(t("wu.refresh"))}</button>
     <button class="btn" data-wuact="export">${icon("export", 16)}${esc(t("page.export"))}</button>
     <input class="page-filter" id="wu-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(WU.filter)}">`)
    + `<div class="wu-body" id="wu-body"><div class="empty">…</div></div>`;
  $("#sb-left").textContent = t("u.loading");
  const body = $("#wu-body");
  body.addEventListener("click", (e) => {
    if (e.target.closest("[data-wuclear]")) { e.preventDefault(); WU.build = ""; return drawWinUpdates(); }
    const ref = e.target.closest("tr[data-wubuild]");
    if (ref) { WU.build = WU.build === ref.dataset.wubuild ? "" : ref.dataset.wubuild; return drawWinUpdates(); }
    const g = e.target.closest("tr[data-wugroup]");
    if (g && WU.shown?.[Number(g.dataset.wugroup)]) wuComputersDialog(WU.shown[Number(g.dataset.wugroup)]);
  });
  let tmr;
  $("#wu-filter").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { WU.filter = e.target.value; drawWinUpdates(); }, 120); };
  $$("[data-wuact]", el).forEach((b) => (b.onclick = async () => {
    if (b.dataset.wuact === "refresh") {
      const job = await guard(() => api("POST", "/api/jobs/updates"));
      if (job) { await pollJob(job.id); await loadWinUpdates(); if (S.section === "winupdates") drawWinUpdates(); }
      return;
    }
    const rows = (WU.shown || []).flatMap((g) => g.computers.map((c) => [c.name, c.os, c.ou, c.installed, c.latest, t("sec." + (c.state || "unknown"))]));
    saveText("windows-updates.csv", csvText([t("wu.col.computer"), t("wu.col.os"), t("wu.col.ou"), t("wu.col.installed"), t("wu.col.latest"), t("wu.col.state")], rows));
  }));
  (async () => {
    try {
      await loadWinUpdates();
      if (S.section === "winupdates" && $("#wu-body") === body) drawWinUpdates();
    } finally {
      if (S.section === "winupdates" && $("#sb-left").textContent === t("u.loading")) $("#sb-left").textContent = tText("wu.count", { n: (WU.shown || []).length });
    }
  })();
}
