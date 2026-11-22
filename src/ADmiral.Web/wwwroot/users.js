/* ADmiral – Users: the people seen in the computers' logon history, with their Active Directory data
   and the computers they used. Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

const US = { list: null, sort: store.get("usort", { key: "name", dir: 1 }), filter: "" };

const logonType = (n) => t("lt." + n);
const userLabel = (u) => u.display_name || u.name;
const userAccount = (u) => (u.domain ? `${u.domain}\\${u.name}` : u.name);

async function loadUsers() {
  US.list = (await guard(() => api("GET", "/api/users"))) || US.list || [];
  return US.list;
}

/* ------------------------------------------------------------------ page */
const USER_COLS = [
  { id: "name", get: (u) => userLabel(u).toLowerCase(), html: (u) => `${icon("user", 16)}${esc(userLabel(u))}` },
  { id: "account", get: (u) => userAccount(u).toLowerCase(), html: (u) => esc(userAccount(u)) },
  { id: "department", get: (u) => u.department.toLowerCase(), html: (u) => esc(u.department) },
  { id: "title", get: (u) => u.title.toLowerCase(), html: (u) => esc(u.title) },
  { id: "mail", get: (u) => u.mail.toLowerCase(), html: (u) => esc(u.mail) },
  { id: "computers", get: (u) => u.computers, num: true, html: (u) => String(u.computers) },
  { id: "logons", get: (u) => u.logons, num: true, html: (u) => String(u.logons) },
  { id: "last_logon", get: (u) => u.last_logon || "", html: (u) => esc(fmtDate(u.last_logon)) },
  { id: "last_computer", get: (u) => u.last_computer.toLowerCase(), html: (u) => esc(u.last_computer) },
  { id: "ad_state", get: (u) => adState(u)[1], html: (u) => { const [cls, l] = adState(u); return `<span class="${cls}">${esc(l)}</span>`; } },
];

function adState(u) {
  if (u.local) return ["faint", t("u.local")];
  if (!u.in_ad) return ["faint", t("u.not_in_ad")];
  return u.enabled === false ? ["st-bad", t("v.disabled")] : ["st-ok", t("v.enabled")];
}

function usersFiltered() {
  const q = US.filter.trim().toLowerCase();
  let rows = US.list || [];
  if (q) rows = rows.filter((u) => [u.name, u.display_name, u.domain, u.department, u.title, u.mail, u.last_computer].join(" ").toLowerCase().includes(q));
  const col = USER_COLS.find((c) => c.id === US.sort.key) || USER_COLS[0];
  return [...rows].sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    return (x < y ? -1 : x > y ? 1 : userLabel(a).localeCompare(userLabel(b))) * US.sort.dir;
  });
}

function drawUsers() {
  const wrap = $("#ugrid");
  if (!wrap) return;
  const rows = usersFiltered();
  US.shown = rows;
  const head = `<th class="rn"></th>` + USER_COLS.map((c) => `<th data-usort="${c.id}">${esc(t("ucol." + c.id))}${US.sort.key === c.id ? `<span class="arr">${US.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  const body = rows.slice(0, 2000).map((u, i) => `<tr data-ukey="${esc(u.key)}" data-i="${i}"${US.sel === u.key ? ' class="sel"' : ""}><td class="rn"></td>${USER_COLS.map((c) => `<td class="${c.num ? "num" : ""}">${c.html(u)}</td>`).join("")}</tr>`).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(t("u.empty"))}</div>`;
  $("#users-count").textContent = tText("sb.users", { n: rows.length });
}

function renderUsersPage(el) {
  el.innerHTML = pageHead("users", t("tree.users"), t("u.sub"),
    `<button class="btn" data-uact="refresh">${icon("sync", 16)}${esc(t("u.refresh"))}</button>
     <button class="btn" data-uact="import">${icon("sync", 16)}${esc(t("u.import"))}</button>
     <button class="btn" data-uact="details">${icon("details", 16)}${esc(t("tb.details"))}</button>
     <input class="page-filter" id="users-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(US.filter)}">`)
    + `<div class="grid-wrap" id="ugrid" tabindex="0"></div>`;
  $("#sb-left").textContent = t("u.loading");
  const grid = $("#ugrid");
  grid.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-usort]");
    if (th) {
      const k = th.dataset.usort;
      US.sort = US.sort.key === k ? { key: k, dir: -US.sort.dir } : { key: k, dir: 1 };
      store.set("usort", US.sort);
      return drawUsers();
    }
    const tr = e.target.closest("tr[data-ukey]");
    if (!tr) return;
    US.sel = tr.dataset.ukey;
    $$("#ugrid tbody tr").forEach((r) => r.classList.toggle("sel", r === tr));
  });
  grid.addEventListener("dblclick", (e) => { const tr = e.target.closest("tr[data-ukey]"); if (tr) openUser(tr.dataset.ukey); });
  let tmr;
  $("#users-filter").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { US.filter = e.target.value; drawUsers(); }, 120); };
  $$("[data-uact]", el).forEach((b) => (b.onclick = async () => {
    if (b.dataset.uact === "details") { if (US.sel) openUser(US.sel); return; }
    if (b.dataset.uact === "import") return adBrowserDialog("users");
    const r = await guard(() => api("POST", "/api/users/refresh"));
    if (r) { toast(tText("u.refreshed", { n: r.updated })); await loadUsers(); drawUsers(); renderTree(); }
  }));
  (async () => {
    try {
      await loadUsers();
      if (S.section !== "users" || $("#ugrid") !== grid) return;      // another page / a newer render took over
      drawUsers();
      renderTree();                                // the tree shows the user count once it is known
    } catch (e) {
      toast(String(e && e.message || e), true);    // never leave the status bar on "Loading…"
    } finally {
      if (S.section === "users") $("#sb-left").textContent = tText("sb.users", { n: (US.shown || US.list || []).length });
    }
  })();
}

/* ------------------------------------------------------------------ user window */
const UCATS = [["general", "user"], ["computers", "computers"], ["logons", "log"], ["ad_groups", "group"]];

async function openUser(key) {
  const list = (US.shown || US.list || []).map((u) => u.key);
  S.uw = { key, list: list.includes(key) ? list : [key], cat: S.uw?.cat || "general", data: null, filter: "" };
  $("#uwin").hidden = false;
  renderUwToolbar();
  await loadUser();
}

function closeUser() { S.uw = null; $("#uwin").hidden = true; }

async function loadUser() {
  const uw = S.uw;
  if (!uw) return;
  const data = await guard(() => api("GET", `/api/users/${encodeURIComponent(uw.key)}`));
  if (!data || S.uw !== uw) return;
  uw.data = data;
  renderUser();
}

function uwStep(d) {
  if (!S.uw) return;
  const i = S.uw.list.indexOf(S.uw.key) + d;
  if (i < 0 || i >= S.uw.list.length) return;
  S.uw.key = S.uw.list[i];
  S.uw.filter = "";
  US.sel = S.uw.key;
  loadUser();
}

function renderUwToolbar() {
  const b = (id, ic, label) => `<button class="tb" data-uw="${id}">${icon(ic, 30)}<span>${esc(t(label))}</span></button>`;
  $("#uwin-toolbar").innerHTML = b("prev", "prev", "u.prev") + b("next", "next", "u.next") + `<span class="tb-sep"></span>`
    + b("copy", "copy", "tb.copy") + b("close", "back", "cw.close");
}

function renderUser() {
  const uw = S.uw, u = uw.data;
  const i = uw.list.indexOf(uw.key);
  $("#uwin-title").textContent = tText("u.title", { name: userLabel(u), i: i + 1, n: uw.list.length });
  $('#uwin-toolbar [data-uw="prev"]').disabled = i <= 0;
  $('#uwin-toolbar [data-uw="next"]').disabled = i >= uw.list.length - 1;
  const counts = { general: null, computers: u.computer_list.length, logons: u.events.length, ad_groups: (u.ad.member_of || []).length };
  $("#uwin-cats").innerHTML = UCATS.map(([id, ic]) => `<div class="cat${uw.cat === id ? " sel" : ""}${counts[id] === 0 ? " empty-cat" : ""}" data-ucat="${id}">${icon(ic, 18)}<span>${esc(t("u.cat." + id))}</span>${counts[id] ? `<span class="cnt">${counts[id]}</span>` : ""}</div>`).join("");
  const [cls, label] = adState(u);
  $("#uwin-head").innerHTML = `${icon("user", 30)}<span>${esc(userLabel(u))}</span><span class="faint">${esc(userAccount(u))}</span><span class="grow"></span><span class="${cls}">${esc(label)}</span>`;
  const msg = $("#uwin-msg");
  msg.className = "cwin-msg";
  msg.hidden = u.in_ad || u.local;
  if (!msg.hidden) msg.innerHTML = `${icon("info", 16)}${esc(t("u.no_ad"))}`;
  $("#uwin-status").textContent = u.last_logon ? `${t("u.last_seen")}: ${fmtDate(u.last_logon)} – ${u.last_computer}` : "";
  renderUwContent();
}

function renderUwContent() {
  const uw = S.uw, u = uw.data, ad = u.ad || {};
  const el = $("#uwin-content");
  const table = (cols, rows) => {
    const q = uw.filter.trim().toLowerCase();
    const shown = q ? rows.filter((r) => cols.some(([, get]) => String(get(r) ?? "").toLowerCase().includes(q))) : rows;
    return `<div class="subtable-tools"><input class="page-filter" id="uw-filter" type="search" placeholder="${esc(t("cw.filter"))}" value="${esc(uw.filter)}"><span class="faint">${shown.length} / ${rows.length}</span></div>`
      + (rows.length ? `<div class="grid-wrap"><table class="grid"><thead><tr><th class="rn"></th>${cols.map(([h]) => `<th>${esc(t(h))}</th>`).join("")}</tr></thead><tbody>
        ${shown.map((r) => `<tr><td class="rn"></td>${cols.map(([, get, fmt]) => `<td class="${fmt === "num" ? "num" : ""}">${fmt === "html" ? get(r) : esc(get(r) ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">${esc(t("cw.no_data"))}</div>`);
  };
  let html = "";
  if (uw.cat === "general") {
    const types = [...new Set(u.computer_list.flatMap((c) => c.types))].sort().map(logonType).join(", ");
    html = `<div class="form2"><div>
      <div class="fsec">${t("u.sec.person")}</div>
      ${fieldRow(t("u.f.display_name"), ad.display_name)}${fieldRow(t("u.f.given_name"), ad.given_name)}${fieldRow(t("u.f.surname"), ad.surname)}
      ${fieldRow(t("u.f.account"), userAccount(u), { mono: true })}${fieldRow(t("u.f.upn"), ad.upn)}
      ${fieldRow(t("u.f.mail"), ad.mail)}${fieldRow(t("u.f.phone"), ad.phone)}${fieldRow(t("u.f.mobile"), ad.mobile)}
      <div class="fsec">${t("u.sec.org")}</div>
      ${fieldRow(t("u.f.title"), ad.title)}${fieldRow(t("u.f.department"), ad.department)}${fieldRow(t("u.f.company"), ad.company)}
      ${fieldRow(t("u.f.office"), ad.office)}${fieldRow(t("u.f.manager"), ad.manager)}${fieldRow(t("u.f.description"), ad.description, { wrap: true })}
    </div><div>
      <div class="fsec">${t("u.sec.account")}</div>
      ${fieldRow(t("u.f.state"), `<span class="${adState(u)[0]}">${esc(adState(u)[1])}</span>`, { html: true })}
      ${fieldRow(t("u.f.ad_logon"), fmtDate(ad.last_logon))}${fieldRow(t("u.f.created"), fmtDate(ad.created))}${fieldRow(t("u.f.pwd_set"), fmtDate(ad.password_set))}
      ${fieldRow(t("u.f.ou"), (ad.ou || "").split("/").slice(1).join("/") || ad.ou)}${fieldRow(t("u.f.dn"), ad.dn, { mono: true })}
      ${fieldRow(t("u.f.synced"), fmtDate(ad.synced_at))}
      <div class="fsec">${t("u.sec.usage")}</div>
      ${fieldRow(t("u.f.computers"), String(u.computers))}${fieldRow(t("u.f.logons"), String(u.logons))}
      ${fieldRow(t("u.f.last_logon"), fmtDate(u.last_logon))}${fieldRow(t("u.f.last_computer"), u.last_computer)}${fieldRow(t("u.f.types"), types)}
    </div></div>`;
  } else if (uw.cat === "computers") {
    html = table([["t.computer", (c) => `<a href="#" data-comp="${esc(c.guid)}">${esc(c.name)}</a>`, "html"], ["t.logons", (c) => c.count, "num"],
      ["t.first", (c) => fmtDate(c.first)], ["t.last", (c) => fmtDate(c.last)], ["t.logon_type", (c) => c.types.map(logonType).join(", ")]], u.computer_list);
  } else if (uw.cat === "logons") {
    html = table([["t.time", (e) => fmtDate(e.time)], ["t.computer", (e) => `<a href="#" data-comp="${esc(e.guid)}">${esc(e.computer)}</a>`, "html"],
      ["t.logon_type", (e) => logonType(e.type)], ["t.source_ip", (e) => e.ip]], u.events);
  } else if (uw.cat === "ad_groups") {
    html = table([["t.group", (g) => g.split(",")[0].replace(/^CN=/i, "")], ["t.dn", (g) => g]], ad.member_of || []);
  }
  el.innerHTML = html;
  const f = $("#uw-filter");
  if (f) f.oninput = (e) => { uw.filter = e.target.value; const pos = e.target.selectionStart; renderUwContent(); const nf = $("#uw-filter"); nf.focus(); nf.setSelectionRange(pos, pos); };
  $$("[data-comp]", el).forEach((a) => (a.onclick = (e) => { e.preventDefault(); closeUser(); openComputer(a.dataset.comp); }));
}

function bindUserWindow() {
  $("#uwin").addEventListener("click", (e) => {
    if (e.target.id === "uwin") return closeUser();
    const b = e.target.closest("[data-uw]");
    if (b && !b.disabled) {
      const u = S.uw?.data;
      ({
        close: closeUser, prev: () => uwStep(-1), next: () => uwStep(1),
        copy: async () => { await copyText(userAccount(u)); toast(tText("copied", { n: 1 })); },
      })[b.dataset.uw]?.();
      return;
    }
    const cat = e.target.closest("[data-ucat]");
    if (cat && S.uw) { S.uw.cat = cat.dataset.ucat; S.uw.filter = ""; renderUser(); }
  });
}
