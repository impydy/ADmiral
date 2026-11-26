/* ADmiral – Deployments section: install a package-library installer on selected computers,
   with every step tracked (connecting, copying, starting, installing, cleanup).
   Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, dialog, ...). */
"use strict";

const DP = { list: [], sel: null, detail: null, timer: null };
const DP_STEPS = ["queued", "connecting", "copying", "starting", "installing", "cleanup", "done"];
const DP_PRESETS = { msi: ["/qn /norestart", "/quiet /norestart"], exe: ["/S", "/silent", "/verysilent /norestart", "/quiet /norestart", "--silent", ""] };
const dpExt = (p) => (p.toLowerCase().match(/\.(msi|exe)$/) || [])[1];

function dpStatusChip(d) {
  const cls = { running: "st-run", done: "st-ok", partial: "st-warn", failed: "st-bad", skipped: "faint" }[d.status] || "faint";
  return `<span class="${cls}">${esc(t("dp.st." + d.status))}</span>`;
}

// the exit code with a hover explanation of what it means
function dpCode(x) {
  if (x.exit_code == null) return "";
  const key = `dp.code.${x.exit_code}`;
  const tip = t(key) !== key ? t(key) : tText("dp.code.unknown", { code: x.exit_code });
  return ` <span class="dp-code mono" title="${esc(tip)}">(${esc(x.exit_code)})</span>`;
}

// one step of a chain as text (the deploy dialog)
function chStepText(s) {
  const f = (s.file || "").split("/").pop();
  const d = { install: `${f} ${s.args || ""}`, copy: `${f} → ${s.path}`, delete: s.path, reboot: tText(s.wait ? "ch.reboot_wait" : "ch.in_s", { s: s.seconds }),
    shutdown: tText("ch.in_s", { s: s.seconds }), wol: tText("ch.wol_text", { s: s.seconds }), powershell: (s.script || "").split("\n")[0], cmd: (s.script || "").split("\n")[0],
    wait: tText("ch.wait_text", { s: s.seconds }), message: `„${s.text || ""}” (${tText("ch.msg_text", { s: s.seconds })})` }[s.type] || "";
  return `${t("ch.type." + s.type)}${d ? ": " + d.trim() : ""}${s.continue_on_error ? " (" + t("ch.continue") + ")" : ""}`;
}

function dpTargetState(x) {
  if (x.step && x.step.startsWith("chain:")) {                 // chain:<i>:<n>:<type>
    const [, i, n, type] = x.step.split(":");
    const bar = `<span class="meter"><span style="width:${x.percent ?? 0}%"></span></span>`;
    return `<span class="st-run">${esc(tText("ch.running", { i, n, type: t("ch.type." + type) }))}</span>${bar}`;
  }
  if (x.step !== "done") {
    const pct = x.step === "copying" && x.percent != null ? ` ${x.percent}%` : "";
    const i = DP_STEPS.indexOf(x.step);
    const bar = `<span class="meter"><span style="width:${Math.round((i / (DP_STEPS.length - 1)) * 100)}%"></span></span>`;
    return `<span class="st-run">${esc(t("dp.step." + x.step))}${pct}</span>${bar}`;
  }
  if (x.outcome === "ok") return `<span class="st-ok">${esc(t("dp.out.ok"))}${dpCode(x)}</span>`;
  if (x.outcome === "reboot") return `<span class="st-warn">${esc(t("dp.out.reboot"))}${dpCode(x)}</span>`;
  if (x.outcome === "unreachable") return `<span class="faint">${esc(t("dp.out.unreachable"))}</span>`;
  if (x.outcome === "current") return `<span class="faint">${esc(t("dp.out.current"))}</span>`;
  return `<span class="st-bad">${esc(t("dp.out.failed"))}${dpCode(x)}</span>`;
}


/* ---------------------------------------------------------------- range, filters, statistics */
const dpDay = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
function dpMonthRange() {
  const n = new Date();
  return { from: dpDay(new Date(n.getFullYear(), n.getMonth(), 1)), to: dpDay(n) };
}
Object.assign(DP, dpMonthRange(), { q: "", status: "", sort: { key: "created", dir: -1 } });

const dpStart = (day) => new Date(day + "T00:00:00");
const dpEnd = (day) => new Date(day + "T23:59:59.999");
const dpIn = (d, from, to) => { const c = new Date(d.created); return c >= from && c <= to; };

function dpDur(sec) {
  if (sec == null) return "";
  if (sec < 60) return tText("dp.dur.s", { s: sec });
  const m = Math.floor(sec / 60);
  return sec % 60 ? tText("dp.dur.ms", { m, s: sec % 60 }) : tText("dp.dur.m", { m });
}

function dpRows() {
  const from = dpStart(DP.from), to = dpEnd(DP.to), q = DP.q.trim().toLowerCase();
  const rows = DP.list.filter((d) => dpIn(d, from, to) && (!DP.status || d.status === DP.status)
    && (!q || [d.package_name, d.version, d.args, d.package_id, d.status].join(" ").toLowerCase().includes(q)));
  const key = { created: (d) => d.created, package: (d) => d.package_name.toLowerCase(), total: (d) => d.total, ok: (d) => d.ok, failed: (d) => d.failed, statuses: (d) => d.failed * 1e6 + d.unreachable * 1e3 + d.reboot, avg: (d) => d.avg_seconds ?? -1 }[DP.sort.key];
  return rows.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0) * DP.sort.dir);
}

// numbers behind the four cards, for deployments in [from, to]
function dpStats(list, from, to) {
  const rows = list.filter((d) => dpIn(d, from, to));
  const done = rows.reduce((a, d) => a + d.ok + d.reboot + d.failed, 0);
  const good = rows.reduce((a, d) => a + d.ok + d.reboot, 0);
  const pk = new Map();
  for (const d of rows) {
    const p = pk.get(d.package_id) || { name: d.package_name, bad: 0, all: 0 };
    p.bad += d.failed; p.all += d.ok + d.reboot + d.failed;
    pk.set(d.package_id, p);
  }
  return { rows, total: rows.length, failed: rows.filter((d) => d.failed > 0).length, rate: done ? (good / done) * 100 : null,
    worst: [...pk.values()].filter((p) => p.bad > 0).map((p) => ({ ...p, rate: (p.bad / p.all) * 100 })).sort((a, b) => b.rate - a.rate || b.bad - a.bad).slice(0, 3) };
}

function dpSeries(rows, from, to, pick) {
  const days = [];
  for (let d = new Date(from); d <= to; d.setDate(d.getDate() + 1)) days.push(dpDay(d));
  const m = new Map(days.map((k) => [k, 0]));
  for (const r of rows) { const k = dpDay(new Date(r.created)); if (m.has(k)) m.set(k, m.get(k) + pick(r)); }
  return [...m.values()];
}

function dpSpark(vals) {
  const w = 190, h = 56, n = vals.length, max = Math.max(1, ...vals);
  if (n < 2) vals = [vals[0] || 0, vals[0] || 0];
  const pts = vals.map((v, i) => [(i / (vals.length - 1)) * w, h - 4 - (v / max) * (h - 10)]);
  const line = pts.map((p) => p.map((x) => x.toFixed(1)).join(",")).join(" ");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polygon points="0,${h} ${line} ${w},${h}" class="spark-fill"/><polyline points="${line}" class="spark-line"/></svg>`;
}

function dpDelta(cur, prev, lowerIsBetter = false, points = false) {
  if (cur == null || prev == null) return "";
  let txt, diff = cur - prev;
  if (points) txt = `${diff >= 0 ? "+" : ""}${diff.toFixed(2)}%`;
  else if (prev === 0) txt = cur === 0 ? "0%" : "+100%";
  else txt = `${diff >= 0 ? "+" : ""}${((diff / prev) * 100).toFixed(2)}%`;
  const good = diff === 0 ? null : lowerIsBetter ? diff < 0 : diff > 0;
  return `<span class="delta ${good == null ? "" : good ? "good" : "bad"}" title="${esc(t("dp.vs_prev"))}">${txt}</span>`;
}

function drawDpCards() {
  const el = $("#dpcards");
  if (!el) return;
  const from = dpStart(DP.from), to = dpEnd(DP.to);
  const span = to - from;
  const pf = new Date(from - span - 1), pt = new Date(from - 1);              // the period of the same length before
  const cur = dpStats(DP.list, from, to), prev = dpStats(DP.list, pf, pt);
  const fmtRate = (r) => (r == null ? "–" : r.toFixed(2) + "%");
  el.innerHTML = `
    <div class="dcard"><h4>${esc(t("dp.card.total"))}</h4><div class="dcard-body"><div><b>${cur.total}</b>${dpDelta(cur.total, prev.total)}</div>${dpSpark(dpSeries(cur.rows, from, to, () => 1))}</div></div>
    <div class="dcard"><h4>${esc(t("dp.card.rate"))}</h4><div class="dcard-body center"><div><b>${fmtRate(cur.rate)}</b>${dpDelta(cur.rate, prev.rate, false, true)}</div></div></div>
    <div class="dcard"><h4>${esc(t("dp.card.failed"))}</h4><div class="dcard-body"><div><b>${cur.failed}</b>${dpDelta(cur.failed, prev.failed, true)}</div>${dpSpark(dpSeries(cur.rows, from, to, (d) => (d.failed > 0 ? 1 : 0)))}</div></div>
    <div class="dcard"><h4>${esc(t("dp.card.worst"))}</h4>${cur.worst.length ? cur.worst.map((p) => `<div class="worst"><span class="trunc">${esc(p.name)}</span><span class="st-bad">${p.rate.toFixed(0)}%</span><span class="faint">${p.bad}/${p.all}</span></div>`).join("") : `<div class="faint" style="padding:10px 0">${esc(t("dp.card.none"))}</div>`}</div>`;
}

const DP_COLS = [["created", "dp.col.last"], ["package", "dp.col.deployment"], ["total", "dp.col.to"], ["statuses", "dp.col.statuses"], ["avg", "dp.col.avg"]];
function dpStatusCells(d) {
  const c = (n, ic, cls, tip) => `<span class="dst ${n ? cls : "faint"}" title="${esc(t(tip))}">${icon(ic, 14)} ${n}</span>`;
  return c(d.queued, "dst_queued", "", "dp.step.queued") + c(d.running, "dst_run", "st-run", "dp.step.installing")
    + c(d.ok, "dst_ok", "st-ok", "dp.out.ok") + c(d.reboot, "dst_warn", "st-warn", "dp.out.reboot") + c(d.failed, "dst_bad", "st-bad", "dp.out.failed")
    + c(d.unreachable, "dst_off", "", "dp.out.unreachable") + c(d.current, "dst_same", "", "dp.out.current");
}

// set a container's HTML without losing the scroll position (the page redraws every second while deploying);
// an unchanged HTML is not touched at all
function dpSetHtml(el, html) {
  if (el.__html === html) return;
  el.__html = html;
  const boxes = [el, ...el.querySelectorAll(".grid-wrap")].map((x) => [x.scrollTop, x.scrollLeft]);
  el.innerHTML = html;
  [el, ...el.querySelectorAll(".grid-wrap")].forEach((x, i) => { if (boxes[i]) { x.scrollTop = boxes[i][0]; x.scrollLeft = boxes[i][1]; } });
}

function drawDeployments() {
  const wrap = $("#dpgrid");
  if (!wrap) return;
  const rows = dpRows();
  DP.shown = rows;
  const head = `<th class="rn"></th>` + DP_COLS.map(([k, l]) => `<th${k ? ` data-dpsort="${k}"` : ""}>${esc(t(l))}${k && DP.sort.key === k ? `<span class="arr">${DP.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  dpSetHtml(wrap, rows.length ? `<table class="grid"><thead><tr>${head}</tr></thead><tbody>
    ${rows.map((d) => `<tr data-dp="${d.id}"${DP.sel === d.id ? ' class="sel"' : ""}><td class="rn"></td><td>${esc(fmtDate(d.created))}</td>
    <td><a class="dp-link">${esc(d.package_name)}${d.version ? ` (v.${esc(d.version)})` : ""}</a> <span class="faint mono">${esc(d.args)}</span></td>
    <td>${esc(tText("dp.devices", { n: d.total }))}</td><td class="dst-row">${dpStatusCells(d)}</td><td>${esc(dpDur(d.avg_seconds))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">${esc(t("dp.empty"))}</div>`);
  $("#sb-left").textContent = tText("dp.count", { n: rows.length });
}

async function dpShowLog(id) {
  const r = await guard(() => api("GET", `/api/deployments/${id}/log`));
  if (!r) return;
  const box = dialog(tText("dp.log.title", { id }), `<pre class="mono" id="dp-log-text" style="margin:0;max-height:60vh;overflow:auto;white-space:pre-wrap;user-select:text">${esc(r.text)}</pre>`,
    `<button class="btn" id="dp-log-copy" type="button">${esc(t("pk.copy"))}</button><span style="flex:1"></span><button class="btn primary" data-dclose>${t("d.ok")}</button>`);
  $("#dp-log-copy", box).onclick = () => { navigator.clipboard?.writeText(r.text); toast(t("dp.log.copied")); };
}

async function dpRetry(id) {
  const d = DP.list.find((x) => x.id === id);
  if (!d || !(await confirmDialog(tText("dp.retry_confirm", { n: d.failed + d.unreachable, pkg: d.package_name })))) return;
  const r = await guard(() => api("POST", `/api/deployments/${id}/retry`, {}));
  if (!r) return;
  DP.sel = r.id;
  toast(t("dp.retry_started"));
  await dpRefresh();
  dpWatch();
}

function drawDeployDetail() {
  const el = $("#dpdetail"), d = DP.detail;
  if (!el) return;
  if (!d) { dpSetHtml(el, ""); return; }
  dpSetHtml(el, `<div class="faint" style="padding:6px 10px">${esc(tText("dp.detail", { id: d.id, file: d.kind === "chain" ? t("ch.chain") : d.file, args: d.args || "–" }))}
    <button class="btn" data-dplog="${d.id}" style="margin-left:8px">${esc(t("dp.log.btn"))}</button></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="rn"></th>${["computer", "state", "started", "finished", "message"].map((c) => `<th>${esc(t("dp.col." + c))}</th>`).join("")}</tr></thead><tbody>
    ${d.targets.map((x) => `<tr><td class="rn"></td><td>${icon("computer", 16)}${esc(x.name)}</td><td>${dpTargetState(x)}</td><td>${esc(fmtDate(x.started))}</td><td>${esc(fmtDate(x.finished))}</td>
    <td class="${x.outcome === "failed" ? "st-bad" : "faint"}" title="${esc(x.log || "")}">${esc(x.error || (x.log ? x.log.split("\n").pop() : ""))}</td></tr>`).join("")}</tbody></table></div>`);
}

async function dpRefresh() {
  const list = await api("GET", "/api/deployments").catch(() => null);
  if (!list) return;
  DP.list = list;
  if (DP.sel == null && list.length) DP.sel = list[0].id;
  if (DP.sel != null) DP.detail = await api("GET", `/api/deployments/${DP.sel}`).catch(() => null);
  if (S.section !== "deployments") return dpStop();
  drawDpCards();
  drawDeployments();
  drawDeployDetail();
  if (!list.some((d) => d.status === "running")) dpStop();
}
function dpStop() { clearInterval(DP.timer); DP.timer = null; }
function dpWatch() { if (!DP.timer) DP.timer = setInterval(dpRefresh, 1000); }

// collect the inventory of the given computers (the normal collect job) and wait until it has finished
async function dpRefreshInventory(ids) {
  const job = await api("POST", "/api/jobs/collect", { ids });
  toast(tText("dp.inv_running", { n: ids.length }));
  await pollJob(job.id);
}
const dpInvCheck = (id) => `<label class="chk"><input type="checkbox" id="${id}"> ${esc(t("dp.refresh_inv"))}</label>`;

/* The confirmation text (plain text: confirmDialog escapes it): every target by name, then what a sync peer changed
   that may have put computers into this selection, then the computers skipped as not confirmed by AD yet. */
function dpConfirmText(pkg, pv) {
  const MAX = 40, day = (s) => String(s || "").slice(0, 16).replace("T", " ");
  const names = pv.names.slice(0, MAX).join(", ") + (pv.names.length > MAX ? " " + tText("dp.more", { n: pv.names.length - MAX }) : "");
  const parts = [tText("dp.confirm", { pkg, n: pv.ids.length }), names];
  if (pv.peer_collections.length)
    parts.push("⚠ " + tText("dp.peer_cols") + "\n" + pv.peer_collections.map((c) => `  ${c.name} (${day(c.at)})`).join("\n"));
  if (pv.peer_tags_total)
    parts.push("⚠ " + tText("dp.peer_tags") + "\n" + pv.peer_tags.map((x) => `  ${x.computer}: ${x.tag} (${day(x.at)})`).join("\n")
               + (pv.peer_tags_total > pv.peer_tags.length ? "\n  " + tText("dp.more", { n: pv.peer_tags_total - pv.peer_tags.length }) : ""));
  if (pv.refused.length) parts.push(tText("dp.skipped", { names: pv.refused.join(", ") }));
  return parts.join("\n\n");
}

/* pre: {pid, chain} or {pid, path} - the option chosen when the dialog opens (from the Packages page). */
async function dpNewDialog(pre) {
  const pk = await guard(() => api("GET", "/api/packages"));
  if (!pk) return;
  const options = [];
  // the packages (installation chains) first, then the library's single installers, then the Windows updates
  for (const p of pk.packages)
    if ((p.steps || []).length) options.push({ pid: p.id, chain: true, label: `${p.name} ${p.version || ""} — ${tText("ch.option", { n: p.steps.length })}`, steps: p.steps });
  for (const p of pk.packages) {
    if (p.kind === "chain" || p.kind === "winupdate") continue;
    for (const f of p.files) if (f.kind === "installer" && dpExt(f.path)) options.push({ pid: p.id, path: f.path, label: `${p.name} ${f.version || p.version} — ${f.path.split("/").pop()}` });
  }
  for (const p of pk.packages.filter((x) => x.kind === "winupdate").sort((a, b) => (b.os_build || "").localeCompare(a.os_build || "", undefined, { numeric: true })))
    for (const f of p.files) if (/\.(msu|cab)$/i.test(f.path)) options.push({ pid: p.id, path: f.path, wu: true, label: `${t("pk.wu.section")}: ${p.name} — ${p.os_build} (${p.version})` });
  if (!options.length) return toast(t("dp.no_installers"), true);
  const preIdx = pre ? Math.max(0, options.findIndex((o) => o.pid === pre.pid && (pre.chain ? o.chain : o.path === pre.path))) : 0;
  const comps = [...S.computers].sort((a, b) => a.name.localeCompare(b.name));
  const sel = new Set(S.sel);
  const colSel = new Set();                                   // chosen collections: all their computers are targets
  const covered = () => new Set(S.fleets.filter((f) => colSel.has(f.id)).flatMap((f) => f.guids || []));
  const effective = () => new Set([...sel, ...covered()]);
  const box = dialog(t("dp.new"), `
    <label class="fld"><span>${esc(t("dp.installer"))}</span><select id="dp-file">${options.map((o, i) => `<option value="${i}"${i === preIdx ? " selected" : ""}>${esc(o.label)}</option>`).join("")}</select></label>
    <div id="dp-argbox"><label class="fld"><span>${esc(t("dp.args"))}</span><input id="dp-args" class="field-in mono" type="text"></label>
    <div id="dp-presets" class="faint"></div>
    <div class="faint">${esc(t("dp.args_hint"))}</div></div>
    <div id="dp-chain" class="preview" hidden></div>
    ${S.fleets.length ? `<div class="faint">${esc(t("dp.collections"))}</div><div id="dp-cols" style="flex:none;max-height:120px;overflow:auto;border:1px solid var(--border-soft)">${S.fleets.map((f) => `<label class="chk" style="padding:2px 8px;display:flex"><input type="checkbox" data-f="${f.id}"> ${icon(f.kind === "dynamic" ? "coll_dyn" : "coll_stat", 16)} ${esc(f.name)} <span class="faint">${f.count}</span></label>`).join("")}</div>` : ""}
    <div class="subtable-tools"><input class="page-filter" id="dp-filter" type="search" placeholder="${esc(t("dp.filter"))}"><span class="faint" id="dp-count"></span>
      <button class="btn" id="dp-all" type="button">${esc(t("dp.all"))}</button><button class="btn" id="dp-none" type="button">${esc(t("dp.none"))}</button></div>
    <div id="dp-list" style="flex:none;max-height:230px;overflow:auto;border:1px solid var(--border-soft)"></div>
    ${dpInvCheck("dp-inv")}`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="dp-go">${esc(t("dp.start"))}</button>`);
  const cur = () => options[Number($("#dp-file", box).value)];
  const presets = () => {
    const o = cur();
    $("#dp-argbox", box).hidden = !!o.chain || !!o.wu;
    $("#dp-chain", box).hidden = !o.chain && !o.wu;
    if (o.wu) {
      $("#dp-chain", box).innerHTML = `${icon("patch", 14)} ${esc(t("dp.wu_hint"))}`;
      return;
    }
    if (o.chain) {
      $("#dp-chain", box).innerHTML = `<b>${esc(t("ch.steps"))}</b><ol style="margin:4px 0 0;padding-left:22px">${o.steps.map((s) => `<li>${esc(chStepText(s))}</li>`).join("")}</ol>`;
      return;
    }
    const ext = dpExt(o.path);
    $("#dp-presets", box).innerHTML = DP_PRESETS[ext].map((a) => `<button class="btn" type="button" data-preset="${esc(a)}">${esc(a || t("dp.no_switches"))}</button>`).join(" ");
    $("#dp-args", box).value = DP_PRESETS[ext][0];
  };
  const drawList = () => {
    const q = $("#dp-filter", box).value.trim().toLowerCase();
    const shown = comps.filter((c) => !q || c.name.toLowerCase().includes(q));
    const cov = covered();
    $("#dp-list", box).innerHTML = shown.map((c) => `<label class="chk" style="padding:2px 8px;display:flex"><input type="checkbox" data-g="${esc(c.guid)}"${sel.has(c.guid) || cov.has(c.guid) ? " checked" : ""}${cov.has(c.guid) ? " disabled" : ""}> ${esc(c.name)} <span class="faint">${c.online ? "" : esc(t("v.offline"))}</span></label>`).join("");
    $("#dp-count", box).textContent = tText("dp.selected", { n: effective().size });
    box._shown = shown;
  };
  $("#dp-file", box).onchange = presets;
  $("#dp-presets", box).onclick = (e) => { const b = e.target.closest("[data-preset]"); if (b) $("#dp-args", box).value = b.dataset.preset; };
  $("#dp-filter", box).oninput = drawList;
  $("#dp-list", box).onchange = (e) => { const g = e.target.dataset.g; if (!g) return; e.target.checked ? sel.add(g) : sel.delete(g); $("#dp-count", box).textContent = tText("dp.selected", { n: effective().size }); };
  const cols = $("#dp-cols", box);
  if (cols) cols.onchange = (e) => { const f = Number(e.target.dataset.f); if (!f) return; e.target.checked ? colSel.add(f) : colSel.delete(f); drawList(); };
  $("#dp-all", box).onclick = () => { box._shown.forEach((c) => sel.add(c.guid)); drawList(); };
  $("#dp-none", box).onclick = () => { box._shown.forEach((c) => sel.delete(c.guid)); drawList(); };
  presets(); drawList();
  $("#dp-go", box).onclick = () => guard(async () => {
    const o = cur();
    if (!effective().size) return toast(t("dp.pick_computers"), true);
    // the targets as the server sees them now (collection members fresh, not this page's cache), with what a sync
    // peer changed: exactly the computers listed here are deployed to
    const pv = await api("POST", "/api/deployments/preview", { ids: [...sel], fleet_ids: [...colSel] });
    if (!pv.ids.length) return toast(pv.refused.length ? tText("dp.skipped", { names: pv.refused.join(", ") }) : t("dp.pick_computers"), true);
    if (!(await confirmDialog(dpConfirmText(o.label, pv), { title: t("dp.new") }))) return;
    const all = new Set(pv.ids);
    const args = $("#dp-args", box).value, inv = $("#dp-inv", box).checked;
    if (inv) { closeDialog(); await dpRefreshInventory([...all]); }
    const r = await api("POST", "/api/deployments", o.chain ? { package_id: o.pid, chain: true, ids: [...all] } : { package_id: o.pid, file: o.path, args: o.wu ? "" : args, ids: [...all] });
    if (!inv) closeDialog();
    DP.sel = r.id;
    if (S.section !== "deployments") setSection("deployments");
    await dpRefresh();
    dpWatch();
  });
}


function dpExport(kind) {
  const rows = (DP.shown || dpRows()).map((d) => [fmtDate(d.created), d.package_name, d.version, d.args, d.total, d.queued, d.running, d.ok, d.reboot, d.failed, d.unreachable, d.current, d.avg_seconds ?? "", t("dp.st." + d.status)]);
  const header = ["dp.col.last", "dp.col.deployment", "dp.col.version", "dp.col.args", "dp.col.to", "dp.step.queued", "dp.step.installing", "dp.out.ok", "dp.out.reboot", "dp.out.failed", "dp.out.unreachable", "dp.out.current", "dp.col.avg_s", "dp.col.status"].map((k) => t(k));
  const name = `ADmiral-deployments-${DP.from}_${DP.to}`;
  if (kind === "csv") return saveText(name + ".csv", csvText(header, rows));
  return guard(async () => {
    const r = await api("POST", "/api/export/xlsx", { header, rows, sheet: t("nav.deployments") });
    await saveBinary(name + ".xlsx", r.content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  });
}

function renderDeploymentsPage(el) {
  const opt = (v, l) => `<option value="${v}"${DP.status === v ? " selected" : ""}>${esc(l)}</option>`;
  el.innerHTML = pageHead("rocket", t("nav.deployments"), "",
    `<button class="btn primary" data-dpact="new">${esc(t("dp.deploy"))}</button>`)
    + `<div class="dcards" id="dpcards"></div>
    <div class="dpbar">
      <label class="faint">${icon("filter", 16)} ${esc(t("dp.filter_label"))}
        <select id="dp-status" class="field-in">${opt("", t("dp.st.all"))}${["running", "done", "partial", "failed", "skipped"].map((s) => opt(s, t("dp.st." + s))).join("")}</select></label>
      <span class="dprange"><input type="date" id="dp-from" class="field-in" value="${esc(DP.from)}"> – <input type="date" id="dp-to" class="field-in" value="${esc(DP.to)}">
        <select id="dp-preset" class="field-in"><option value="">${esc(t("dp.range"))}</option><option value="month">${esc(t("dp.r.month"))}</option><option value="7">${esc(t("dp.r.7"))}</option><option value="30">${esc(t("dp.r.30"))}</option><option value="all">${esc(t("dp.r.all"))}</option></select></span>
      <span class="grow"></span>
      <input class="page-filter" id="dp-q" type="search" placeholder="${esc(t("dp.search"))}" value="${esc(DP.q)}">
      <span class="menu-wrap"><button class="btn" id="dp-export" type="button">${icon("export", 16)}${esc(t("page.export"))} ▾</button>
        <div class="dp-pop" id="dp-exp-menu" hidden><button data-dpexp="csv">CSV</button><button data-dpexp="xlsx">XLSX</button></div></span>
    </div>
    <div class="grid-wrap" id="dpgrid" style="max-height:32%"></div><div id="dpdetail" style="flex:1;overflow:auto;display:flex;flex-direction:column"></div>`;
  $('[data-dpact="new"]', el).onclick = dpNewDialog;
  const redraw = () => { drawDpCards(); drawDeployments(); };
  $("#dp-status").onchange = (e) => { DP.status = e.target.value; redraw(); };
  const setRange = (from, to) => { DP.from = from; DP.to = to; $("#dp-from").value = from; $("#dp-to").value = to; redraw(); };
  $("#dp-from").onchange = (e) => { if (e.target.value) { DP.from = e.target.value; if (DP.from > DP.to) DP.to = DP.from; setRange(DP.from, DP.to); } };
  $("#dp-to").onchange = (e) => { if (e.target.value) { DP.to = e.target.value; if (DP.from > DP.to) DP.from = DP.to; setRange(DP.from, DP.to); } };
  $("#dp-preset").onchange = (e) => {
    const v = e.target.value, today = dpDay(new Date());
    if (v === "month") setRange(dpMonthRange().from, today);
    else if (v === "all") setRange(DP.list.length ? dpDay(new Date(Math.min(...DP.list.map((d) => new Date(d.created))))) : today, today);
    else if (v) setRange(dpDay(new Date(Date.now() - (Number(v) - 1) * 86400000)), today);
    e.target.value = "";
  };
  let tmr;
  $("#dp-q").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { DP.q = e.target.value; drawDeployments(); }, 120); };
  $("#dp-export").onclick = (e) => { e.stopPropagation(); $("#dp-exp-menu").hidden = !$("#dp-exp-menu").hidden; };
  $("#dp-exp-menu").onclick = (e) => { const b = e.target.closest("[data-dpexp]"); if (b) { $("#dp-exp-menu").hidden = true; dpExport(b.dataset.dpexp); } };
  document.addEventListener("click", () => { const m = $("#dp-exp-menu"); if (m) m.hidden = true; });
  $("#dpgrid").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-dpsort]");
    if (th) {
      const k = th.dataset.dpsort;
      DP.sort = DP.sort.key === k ? { key: k, dir: -DP.sort.dir } : { key: k, dir: k === "package" ? 1 : -1 };
      return drawDeployments();
    }
    const tr = e.target.closest("tr[data-dp]");
    if (!tr) return;
    DP.sel = Number(tr.dataset.dp);
    dpRefresh().then(() => DP.list.some((d) => d.status === "running") && dpWatch());
  });
  $("#dpdetail").addEventListener("click", (e) => { const b = e.target.closest("[data-dplog]"); if (b) dpShowLog(Number(b.dataset.dplog)); });
  $("#dpgrid").addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-dp]");
    if (!tr) return;
    e.preventDefault();
    const id = Number(tr.dataset.dp), d = DP.list.find((x) => x.id === id);
    if (!d) return;
    DP.sel = id;
    dpRefresh();
    showMenu([
      { label: tText("dp.retry", { n: d.failed + d.unreachable }), icon: "rocket", disabled: d.status === "running" || !(d.failed + d.unreachable), action: () => dpRetry(id) },
      { label: t("dp.log.btn"), action: () => dpShowLog(id) },
    ], e.clientX, e.clientY);
  });
  dpRefresh().then(() => DP.list.some((d) => d.status === "running") && dpWatch());
}
