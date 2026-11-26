/* ADmiral – Send message (Tools, under Remote assistance): a message for the users logged on to the chosen
   computers. The targets are picked one by one, from collections or from OUs (all three can be combined); msg.exe
   shows it as SYSTEM. Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

const MSG = { sel: new Set(), cols: new Set(), ous: new Set(), tab: "pc", filter: "" };

function renderMessagePage(el) {
  const comps = [...S.computers].sort((a, b) => a.name.localeCompare(b.name));
  const ouList = [...new Set(comps.filter((c) => c.ou).map((c) => c.ou))].sort((a, b) => a.localeCompare(b));
  const ouCount = (o) => comps.filter((c) => c.ou === o).length;
  const covered = () => new Set([
    ...S.fleets.filter((f) => MSG.cols.has(f.id)).flatMap((f) => f.guids || []),
    ...comps.filter((c) => MSG.ous.has(c.ou)).map((c) => c.guid),
  ]);
  const effective = () => new Set([...MSG.sel, ...covered()]);
  const list = (id, html) => `<div id="${id}" class="msg-list">${html}</div>`;
  el.innerHTML = pageHead("message", t("nav.message"), t("msg.sub"), "") + `<div class="msg-page">
    <label class="fld"><span>${esc(t("msg.text"))}</span><textarea id="msg-text" rows="3" maxlength="500" placeholder="${esc(t("ch.msg_ph"))}"></textarea></label>
    <label class="chk">${esc(t("ch.msg_time"))} <input id="msg-secs" type="number" min="10" max="86400" value="300" style="width:90px"> s</label>
    <div style="display:flex;gap:4px;margin-top:6px;align-items:center">
      <button class="btn" type="button" data-mtab="pc">${icon("computer", 14)}${esc(t("msg.by_pc"))}</button>
      <button class="btn" type="button" data-mtab="col">${icon("coll_dyn", 14)}${esc(t("msg.by_col"))}</button>
      <button class="btn" type="button" data-mtab="ou">${icon("ou", 14)}${esc(t("msg.by_ou"))}</button>
      <span style="flex:1"></span><span class="faint" id="msg-count"></span></div>
    <div data-mpane="pc"><div class="subtable-tools"><input class="page-filter" id="msg-filter" type="search" placeholder="${esc(t("dp.filter"))}" value="${esc(MSG.filter)}">
      <button class="btn" id="msg-all" type="button">${esc(t("dp.all"))}</button><button class="btn" id="msg-none" type="button">${esc(t("dp.none"))}</button></div>${list("msg-pcs", "")}</div>
    <div data-mpane="col" hidden>${list("msg-cols", S.fleets.map((f) => `<label class="chk"><input type="checkbox" data-f="${f.id}"${MSG.cols.has(f.id) ? " checked" : ""}> ${icon(f.kind === "dynamic" ? "coll_dyn" : "coll_stat", 16)} ${esc(f.name)} <span class="faint">${f.count}</span></label>`).join("") || `<div class="empty">${esc(t("msg.no_cols"))}</div>`)}</div>
    <div data-mpane="ou" hidden>${list("msg-ous", ouList.map((o, i) => `<label class="chk"><input type="checkbox" data-ou="${i}"${MSG.ous.has(o) ? " checked" : ""}> ${icon("ou", 16)} ${esc(o)} <span class="faint">${ouCount(o)}</span></label>`).join("") || `<div class="empty">${esc(t("msg.no_ous"))}</div>`)}</div>
    <div class="faint">${esc(t("msg.hint"))}</div>
    <div><button class="btn primary" id="msg-go" type="button">${icon("message", 16)}${esc(t("msg.send"))}</button></div>
    <div id="msg-res"></div></div>`;
  const count = () => {
    const n = effective().size;
    $("#msg-count", el).textContent = tText("dp.selected", { n });
    $("#sb-left").textContent = tText("dp.selected", { n });
  };
  const drawPcs = () => {
    const q = MSG.filter.trim().toLowerCase();
    const cov = covered();
    MSG.shown = comps.filter((c) => !q || c.name.toLowerCase().includes(q));
    $("#msg-pcs", el).innerHTML = MSG.shown.map((c) => `<label class="chk"><input type="checkbox" data-g="${esc(c.guid)}"${MSG.sel.has(c.guid) || cov.has(c.guid) ? " checked" : ""}${cov.has(c.guid) ? " disabled" : ""}> ${esc(c.name)} <span class="faint">${c.online ? "" : esc(t("v.offline"))}</span></label>`).join("")
      || `<div class="empty">${esc(t("msg.no_pcs"))}</div>`;
    count();
  };
  const tab = (name) => {
    MSG.tab = name;
    $$("[data-mpane]", el).forEach((p) => (p.hidden = p.dataset.mpane !== name));
    $$("[data-mtab]", el).forEach((b) => b.classList.toggle("primary", b.dataset.mtab === name));
    if (name === "pc") drawPcs();
  };
  el.querySelector(".msg-page").addEventListener("click", (e) => { const b = e.target.closest("[data-mtab]"); if (b) tab(b.dataset.mtab); });
  $("#msg-filter", el).oninput = (e) => { MSG.filter = e.target.value; drawPcs(); };
  $("#msg-pcs", el).onchange = (e) => { const g = e.target.dataset.g; if (!g) return; e.target.checked ? MSG.sel.add(g) : MSG.sel.delete(g); count(); };
  $("#msg-cols", el).onchange = (e) => { const f = Number(e.target.dataset.f); if (!f) return; e.target.checked ? MSG.cols.add(f) : MSG.cols.delete(f); count(); };
  $("#msg-ous", el).onchange = (e) => { const o = ouList[Number(e.target.dataset.ou)]; if (o === undefined) return; e.target.checked ? MSG.ous.add(o) : MSG.ous.delete(o); count(); };
  $("#msg-all", el).onclick = () => { MSG.shown.forEach((c) => MSG.sel.add(c.guid)); drawPcs(); };
  $("#msg-none", el).onclick = () => { MSG.shown.forEach((c) => MSG.sel.delete(c.guid)); drawPcs(); };
  tab(MSG.tab);
  $("#msg-go", el).onclick = () => guard(async () => {
    const text = $("#msg-text", el).value.trim();
    if (!text) return $("#msg-text", el).focus();
    // OU members are sent as computers; collections by ID (the server reads their members fresh)
    const ids = [...new Set([...MSG.sel, ...comps.filter((c) => MSG.ous.has(c.ou)).map((c) => c.guid)])];
    const pv = await api("POST", "/api/deployments/preview", { ids, fleet_ids: [...MSG.cols] });
    if (!pv.ids.length) return toast(t("dp.pick_computers"), true);
    const MAX = 40;
    const names = pv.names.slice(0, MAX).join(", ") + (pv.names.length > MAX ? " " + tText("dp.more", { n: pv.names.length - MAX }) : "");
    if (!(await confirmDialog(`${tText("msg.confirm", { n: pv.ids.length })}\n\n„${text}”\n\n${names}`, { title: t("nav.message") }))) return;
    const job = await api("POST", "/api/messages", { ids: pv.ids, text, seconds: Number($("#msg-secs", el).value) || 300 });
    await pollJob(job.id);
    const done = await api("GET", `/api/jobs/${job.id}`).catch(() => null);
    const res = $("#msg-res");
    if (res && done?.result?.results) res.innerHTML = msgResults(done.result);
  });
}

/* Who got the message, who had nobody logged on, which computers failed. */
function msgResults(r) {
  const cls = { ok: "st-ok", nobody: "faint", failed: "st-bad", unreachable: "st-warn" };
  return `<h3 class="wu-h">${esc(t("msg.results"))}</h3><div class="faint" style="margin-bottom:6px">${esc(tText("res.message", r))}</div>
    <div class="grid-wrap" style="max-height:45vh;overflow:auto"><table class="grid"><thead><tr><th class="rn"></th><th>${esc(t("wu.col.computer"))}</th><th>${esc(t("msg.col.result"))}</th><th>${esc(t("msg.col.detail"))}</th></tr></thead><tbody>
    ${r.results.map((x) => `<tr><td class="rn"></td><td>${icon("computer", 16)}${esc(x.name)}</td><td class="${cls[x.outcome] || ""}">${esc(t("msg.out." + x.outcome))}</td><td class="faint">${esc(x.detail)}</td></tr>`).join("")}</tbody></table></div>`;
}
