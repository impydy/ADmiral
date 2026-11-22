/* ADmiral – Remote Assistance section: find a user, see where and when they logged on, offer help
   (msra /offerra <computer>) with one click; or type a computer name directly.
   Loaded after app.js and users.js (shares $, api, t, esc, icon, S, US, loadUsers, ...). */
"use strict";

const RA = { query: "", user: null, byName: store.get("ra_byname", false), host: "" };

function raConnect(name) {
  if (!name) return;
  if (!isDesktop()) return toast(t("ra.desktop_only"), true);
  guard(async () => { await window.pywebview.api.remote_assist(name); toast(tText("ra.started", { name })); });
}

const raBtn = (name) => `<button class="btn" type="button" data-raconn="${esc(name)}"${name ? "" : " disabled"}${isDesktop() ? "" : ` title="${esc(t("ra.desktop_only"))}"`}>${icon("ra", 16)}${esc(t("ra.connect"))}</button>`;
const raOnline = (guid) => { const c = S.byGuid.get(guid); return c?.online === true ? `<span class="dot ok" title="${esc(t("v.yes"))}"></span>` : c?.online === false ? `<span class="dot bad" title="${esc(t("v.no"))}"></span>` : `<span class="dot"></span>`; };

function raMatches() {
  const q = RA.query.trim().toLowerCase();
  if (!q) return [];
  return (US.list || []).filter((u) => [u.name, u.display_name, u.domain, u.mail, u.department].join(" ").toLowerCase().includes(q)).slice(0, 50);
}

function drawRaResults() {
  const el = $("#ra-body");
  if (!el || RA.byName) return;
  if (RA.user) return drawRaUser();
  const rows = raMatches();
  if (!RA.query.trim()) { el.innerHTML = `<div class="empty">${esc(t("ra.hint"))}</div>`; return; }
  el.innerHTML = rows.length ? `<div class="grid-wrap"><table class="grid"><thead><tr><th class="rn"></th>${["u", "acc", "dep", "last", "comp"].map((c) => `<th>${esc(t("ra.col." + c))}</th>`).join("")}</tr></thead><tbody>
    ${rows.map((u) => `<tr data-rauser="${esc(u.key)}"><td class="rn"></td><td>${icon("user", 16)}${esc(userLabel(u))}</td><td>${esc(userAccount(u))}</td><td>${esc(u.department)}</td><td>${esc(fmtDate(u.last_logon))}</td><td>${esc(u.last_computer)}</td></tr>`).join("")}</tbody></table></div>`
    : `<div class="empty">${esc(t("ra.no_user"))}</div>`;
}

async function raPick(key) {
  const u = await guard(() => api("GET", `/api/users/${encodeURIComponent(key)}`));
  if (!u) return;
  RA.user = u;
  drawRaUser();
}

function drawRaUser() {
  const u = RA.user, el = $("#ra-body");
  if (!u || !el) return;
  const comps = u.computer_list.filter((c) => c.name);
  const events = u.events.filter((e) => e.computer).slice(0, 300);
  el.innerHTML = `<div class="ra-user"><b>${icon("user", 16)}${esc(userLabel(u))}</b> <span class="faint">${esc(userAccount(u))}${u.mail ? " · " + esc(u.mail) : ""}</span>
      <button class="btn" type="button" data-raclear>${esc(t("ra.other_user"))}</button></div>
    <h4 class="ra-h">${esc(t("ra.computers"))} <span class="faint">(${comps.length})</span></h4>
    ${comps.length ? `<div class="grid-wrap" style="max-height:34%"><table class="grid"><thead><tr><th class="rn"></th><th></th>${["t.computer", "t.last", "t.first", "t.logons", "t.logon_type"].map((k) => `<th>${esc(t(k))}</th>`).join("")}</tr></thead><tbody>
      ${comps.map((c) => `<tr><td class="rn"></td><td class="nowrap">${raBtn(c.name)}</td><td>${raOnline(c.guid)}${esc(c.name)}</td><td>${esc(fmtDate(c.last))}</td><td>${esc(fmtDate(c.first))}</td><td class="num">${c.count}</td><td>${esc(c.types.map(logonType).join(", "))}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">${esc(t("ra.no_history"))}</div>`}
    <h4 class="ra-h">${esc(t("ra.logons"))} <span class="faint">(${events.length})</span></h4>
    ${events.length ? `<div class="grid-wrap" style="flex:1"><table class="grid"><thead><tr><th class="rn"></th><th></th>${["t.time", "t.computer", "t.logon_type", "t.source_ip"].map((k) => `<th>${esc(t(k))}</th>`).join("")}</tr></thead><tbody>
      ${events.map((e) => `<tr><td class="rn"></td><td class="nowrap">${raBtn(e.computer)}</td><td>${esc(fmtDate(e.time))}</td><td>${raOnline(e.guid)}${esc(e.computer)}</td><td>${esc(logonType(e.type))}</td><td>${esc(e.ip || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
}

function drawRaMode() {
  const byName = RA.byName;
  $("#ra-user-box").hidden = byName;
  $("#ra-host-box").hidden = !byName;
  if (byName) { $("#ra-body").innerHTML = `<div class="empty">${esc(t("ra.hint_host"))}</div>`; setTimeout(() => $("#ra-host")?.focus(), 30); }
  else { drawRaResults(); setTimeout(() => $("#ra-user")?.focus(), 30); }
}

function renderRemotePage(el) {
  el.innerHTML = pageHead("ra", t("nav.remote"), t("ra.sub"))
    + `<div class="dpbar">
      <label class="chk"><input type="checkbox" id="ra-byname"${RA.byName ? " checked" : ""}> ${esc(t("ra.by_name"))}</label>
      <span id="ra-user-box"><input class="page-filter" id="ra-user" type="search" placeholder="${esc(t("ra.search_user"))}" value="${esc(RA.query)}" style="width:320px"></span>
      <span id="ra-host-box" hidden><input class="page-filter" id="ra-host" type="text" list="ra-hosts" placeholder="${esc(t("ra.host_ph"))}" value="${esc(RA.host)}" style="width:260px" autocomplete="off">
        <datalist id="ra-hosts">${S.computers.map((c) => `<option value="${esc(c.name)}">`).join("")}</datalist>
        <button class="btn primary" type="button" id="ra-go">${icon("ra", 16)}${esc(t("ra.connect"))}</button></span>
    </div>
    <div id="ra-body" style="flex:1;overflow:auto;display:flex;flex-direction:column;min-height:0"></div>`;
  $("#ra-byname").onchange = (e) => { RA.byName = e.target.checked; store.set("ra_byname", RA.byName); drawRaMode(); };
  let tmr;
  $("#ra-user").oninput = (e) => { RA.query = e.target.value; RA.user = null; clearTimeout(tmr); tmr = setTimeout(drawRaResults, 120); };
  $("#ra-host").oninput = (e) => { RA.host = e.target.value; };
  $("#ra-host").onkeydown = (e) => { if (e.key === "Enter") raConnect(RA.host.trim()); };
  $("#ra-go").onclick = () => raConnect(RA.host.trim());
  $("#ra-body").addEventListener("click", (e) => {
    const b = e.target.closest("[data-raconn]");
    if (b) return raConnect(b.dataset.raconn);
    if (e.target.closest("[data-raclear]")) { RA.user = null; drawRaResults(); return $("#ra-user")?.focus(); }
    const tr = e.target.closest("tr[data-rauser]");
    if (tr) raPick(tr.dataset.rauser);
  });
  drawRaMode();
  loadUsers().then(() => { if (S.section === "remote" && !RA.byName && !RA.user) drawRaResults(); });
}
