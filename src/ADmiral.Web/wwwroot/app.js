/* ADmiral desktop UI – classic admin-tool layout, light/dark themes, Hungarian/English.
   No framework and no CDN, so it works on air-gapped admin machines. */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem("admiral." + k); return v == null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem("admiral." + k, JSON.stringify(v)); } catch (_) { /* storage unavailable */ } },
};

const S = {
  status: null, computers: [], byGuid: new Map(), fleets: [], tags: [],
  node: store.get("node", "welcome"), expanded: new Set(store.get("expanded", ["lib", "ad", "my"])),
  sel: new Set(), anchor: null, filter: "", treeFilter: "", sort: store.get("sort", { key: "name", dir: 1 }),
  list: [], cols: store.get("cols", null), job: null, cw: null, theme: "system", section: store.get("section", "devices"),
};

/* ================================================================== api */
const TOKEN = new URLSearchParams(location.search).get("token") || (() => { try { return sessionStorage.getItem("admiral-token") || ""; } catch (_) { return ""; } })();
try { if (TOKEN) sessionStorage.setItem("admiral-token", TOKEN); } catch (_) { /* private mode */ }
if (location.search) history.replaceState(null, "", location.pathname + location.hash);
const isDesktop = () => !!(window.pywebview && window.pywebview.api);

async function api(method, path, body) {
  const opts = { method, headers: { "X-ADmiral": "1", "X-ADmiral-Token": TOKEN } };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const type = res.headers.get("content-type") || "";
  const data = type.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    let msg = data && data.detail ? data.detail : `${res.status} ${res.statusText}`;
    if (Array.isArray(msg)) msg = msg.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
    throw new Error(msg);
  }
  return data;
}

function toast(msg, bad = false) {
  const el = document.createElement("div");
  el.className = "toast" + (bad ? " bad" : "");
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), bad ? 8000 : 4000);
}
async function guard(fn) { try { return await fn(); } catch (e) { toast(e.message, true); return undefined; } }

async function saveText(filename, text) {
  if (isDesktop()) {
    const path = await window.pywebview.api.save_file(filename, text);
    if (path) toast(tText("exp.saved", { path }));
    return;
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function saveBinary(filename, b64, type) {
  if (isDesktop()) {
    const path = await window.pywebview.api.save_binary(filename, b64);
    if (path) toast(tText("exp.saved", { path }));
    return;
  }
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([bytes], { type }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    const ok = document.execCommand("copy"); ta.remove(); return ok;
  }
}

/* ================================================================== formatting */
const locale = () => (LANG === "hu" ? "hu-HU" : "en-US");
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(locale(), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "");
const fmtDay = (iso) => (iso ? new Date(iso).toLocaleDateString(locale()) : "");
function fmtUptime(sec) {
  if (sec == null) return "";
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return tText("u.days_hours", { d, h });
  if (h) return tText("u.hours_mins", { h, m });
  return tText("u.mins", { m });
}
function ago(iso) {
  if (!iso) return t("v.never");
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 86400) return fmtDate(iso);
  return `${fmtDate(iso)} (${tText("v.days", { n: Math.floor(s / 86400) })})`;
}
const yesNo = (v) => (v === true ? t("v.yes") : v === false ? t("v.no") : t("v.unknown"));
const inv = (c, k) => (c.inventory || {})[k];
const isServer = (c) => /server/i.test(c.os || "") || /server/i.test(inv(c, "os_caption") || "");
function osShort(c) {
  const v = inv(c, "os_short");
  if (v) return v;
  const os = c.os || "";
  let m = os.match(/Server (\d{4}(?: R2)?)/);
  if (m) return m[1];
  m = os.match(/Windows (\d+(?:\.\d)?)/);
  return m ? m[1] : os;
}
const hasWinrm = (c) => (c.open_ports || []).some((p) => p === 5985 || p === 5986);
const PORTS = { 22: "SSH", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (HTTPS)" };
const gb = (v) => (v == null || v === "" ? "" : `${Number(v).toLocaleString(locale())} GB`);

function secState(c) {
  switch (c.security?.state) {
    case "current": return ["st-ok", t("sec.current")];
    case "missing": return ["st-bad", t("sec.missing")];
    case "pending": return ["st-warn", t("sec.pending")];
    default: return ["faint", t("sec.unknown")];
  }
}
const secTip = (c) => (c.security?.installed ? `${t("sec.installed")}: ${c.security.installed} · ${t("sec.latest")}: ${c.security.latest} (${c.security.released || ""})` : "");

function scanStatus(c) {
  const phase = S.job && S.job.status === "running" && S.job.active ? S.job.active[c.guid] : null;
  if (phase) return ["st-run", t(phase === "collect" ? "v.collecting" : phase === "deploy" ? "v.deploying" : "v.probing")];   // being queried right now
  switch (c.scan_status) {
    case "ok": return ["st-ok", t("v.ok")];
    case "partial": return ["st-warn", t("v.partial")];
    case "failed": return ["st-bad", t("v.failed")];
    case "offline": return ["muted", t("v.offline")];
    default: return ["faint", c.allow_scan === false ? t("v.disabled") : t("v.not_scanned")];
  }
}
const onlineCell = (c) => (c.online === true ? `<span class="dot ok"></span>${t("v.yes")}` : c.online === false ? `<span class="dot bad"></span>${t("v.no")}` : `<span class="dot"></span>${t("v.unknown")}`);

/* ================================================================== data */
async function loadAll() {
  const [computers, fleets, tags] = await Promise.all([api("GET", "/api/computers"), api("GET", "/api/fleets"), api("GET", "/api/tags")]);
  S.computers = computers;
  S.byGuid = new Map(computers.map((c) => [c.guid, c]));
  S.fleets = fleets;
  S.tags = tags;
  for (const g of [...S.sel]) if (!S.byGuid.has(g)) S.sel.delete(g);
}

/* ================================================================== theme & language */
function applyTheme(theme) {
  S.theme = theme || "system";
  const dark = S.theme === "dark" || (S.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  // the desktop window repaints its title bar to match (the bridge exists only in ADmiral.exe)
  if (isDesktop() && window.pywebview.api.set_theme) window.pywebview.api.set_theme(S.theme).catch(() => {});
}
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(S.theme));

async function setPref(key, value) {
  const cfgEditable = S.status && S.status.settings_editable;
  if (cfgEditable) {
    await guard(() => api("PUT", "/api/settings", { [key]: value }));
    S.status = await api("GET", "/api/status");
  } else {
    store.set("pref." + key, value);
    S.status[key] = value;
  }
  if (key === "theme") applyTheme(value);
  if (key === "language") { LANG = value; document.documentElement.lang = value; await guard(loadAll); renderAll(); }
}

/* ================================================================== built-in collections */
const BUILTIN = [
  ["online", "ping", (c) => c.online === true],
  ["offline", "computer", (c) => c.online === false],
  ["unscanned", "computer", (c) => c.online === null],
  ["failed", "warn", (c) => c.scan_status === "failed"],
  ["stale", "log", (c) => c.stale],
  ["disabled", "block", (c) => !c.enabled],
  ["noscan", "block", (c) => c.allow_scan === false],
  ["winrm", "sync", hasWinrm],
  ["reboot", "refresh", (c) => !!inv(c, "pending_reboot")],
  ["lowdisk", "disk", (c) => inv(c, "c_free_gb") != null && inv(c, "c_free_gb") < 15],
  ["smb1", "warn", (c) => !!(inv(c, "smb1_server") || inv(c, "smb1_client"))],
  ["servers", "server", isServer],
  ["workstations", "computer", (c) => !isServer(c)],
  // security-update state (own group "Updates" in the library)
  ["sec_missing", "warn", (c) => c.security?.state === "missing"],
  ["sec_pending", "refresh", (c) => c.security?.state === "pending"],
  ["sec_current", "ping", (c) => c.security?.state === "current"],
  ["sec_unknown", "computer", (c) => !c.security || c.security.state === "unknown"],
];
const UPDATE_COLLS = BUILTIN.filter(([id]) => id.startsWith("sec_"));

function domainName() {
  const ou = S.computers.find((c) => c.ou)?.ou || "";
  return ou.split("/")[0] || "AD";
}

function buildTree() {
  const C = S.computers;
  const count = (fn) => C.filter(fn).length;
  const nodes = [
    { id: "welcome", label: t("tree.welcome"), icon: "home" },
    { id: "all", label: t("tree.all"), icon: "computers", count: C.length },
    {
      id: "lib", label: t("tree.library"), icon: "library", children: [
        ...BUILTIN.filter(([id]) => !id.startsWith("sec_")).map(([id, ic, fn]) => ({ id: "b:" + id, label: t("b." + id), icon: "coll_builtin", count: count(fn) })),
        {
          id: "upd", label: t("tree.updates"), icon: "patch",
          children: UPDATE_COLLS.map(([id, ic, fn]) => ({ id: "b:" + id, label: t("b." + id), icon: "coll_builtin", count: count(fn) })),
        },
        {
          id: "os", label: t("tree.os"), icon: "window_os",
          children: [...new Set(C.map((c) => c.os || "?"))].sort().map((o) => ({ id: "os:" + o, label: o, icon: "coll_builtin", count: count((c) => (c.os || "?") === o) })),
        },
        {
          id: "hw", label: t("tree.hw"), icon: "hardware",
          children: [...new Set(C.map((c) => inv(c, "manufacturer")).filter(Boolean))].sort().map((m) => ({ id: "hw:" + m, label: m, icon: "coll_builtin", count: count((c) => inv(c, "manufacturer") === m) })),
        },
      ],
    },
  ];
  // AD OU tree
  const root = { id: "ou:" + domainName(), label: domainName(), icon: "domain", children: [], count: 0, path: domainName() };
  const index = new Map([[root.path, root]]);
  for (const c of C) {
    const parts = (c.ou || domainName()).split("/");
    let path = parts[0];
    let node = root;
    node.count++;
    for (const p of parts.slice(1)) {
      path += "/" + p;
      let child = index.get(path);
      if (!child) {
        child = { id: "ou:" + path, label: p, icon: "ou", children: [], count: 0, path };
        index.set(path, child);
        node.children.push(child);
      }
      child.count++;
      node = child;
    }
  }
  const sortRec = (n) => { n.children.sort((a, b) => a.label.localeCompare(b.label)); n.children.forEach(sortRec); if (!n.children.length) delete n.children; };
  sortRec(root);
  if (C.length) { root.id = "ad"; root.ouPath = root.path; nodes.push(root); }
  nodes.push({
    id: "my", label: t("tree.my"), icon: "library",
    children: S.fleets.map((f) => ({ id: "f:" + f.id, label: f.name, icon: f.kind === "dynamic" ? "coll_dyn" : "coll_stat", count: f.count })),
  });
  nodes.push({ id: "tags", label: t("tree.tags"), icon: "tag", children: S.tags.map((x) => ({ id: "t:" + x.tag, label: x.tag, icon: "tag", count: x.count })) });
  nodes.push({ id: "log", label: t("tree.log"), icon: "log" });
  return nodes;
}

function findNode(nodes, id) {
  for (const n of nodes) {
    if (n.id === id) return n;
    const f = n.children && findNode(n.children, id);
    if (f) return f;
  }
  return null;
}

function renderTree() {
  const nodes = buildTree();
  S.treeNodes = nodes;
  if (S.section === "settings") return;            // the pane shows the settings categories then
  const q = S.treeFilter.trim().toLowerCase();
  const visible = (n) => !q || n.label.toLowerCase().includes(q) || (n.children || []).some(visible);
  const out = [];
  const walk = (list, depth) => {
    for (const n of list) {
      if (!visible(n)) continue;
      const kids = n.children && n.children.length;
      const open = kids && (q || S.expanded.has(n.id));
      out.push(`<div class="tn${S.node === n.id ? " sel" : ""}" data-node="${esc(n.id)}" style="padding-left:${4 + depth * 16}px" role="treeitem" ${kids ? `aria-expanded="${!!open}"` : ""}>
        <span class="tw${kids ? (open ? " open" : "") : " leaf"}" data-tw="${esc(n.id)}">${icon("chevron", 12)}</span>${icon(n.icon, 16)}
        <span class="lbl">${esc(n.label)}</span>${n.count != null ? `<span class="cnt">(${n.count})</span>` : ""}</div>`);
      if (open) walk(n.children, depth + 1);
    }
  };
  walk(nodes, 0);
  $("#tree").innerHTML = out.join("");
}

function selectNode(id, opts = {}) {
  if (S.section !== "devices") setSection("devices", { render: false });
  if (S.node !== id) { S.sel.clear(); S.anchor = null; S.filter = ""; }
  S.node = id;
  store.set("node", id);
  // make sure parents are expanded so the selection is visible
  if (id.startsWith("b:") || id.startsWith("os:") || id.startsWith("hw:")) S.expanded.add("lib");
  if (id.startsWith("os:")) S.expanded.add("os");
  if (id.startsWith("hw:")) S.expanded.add("hw");
  if (id.startsWith("b:sec_")) S.expanded.add("upd");
  if (id.startsWith("f:")) S.expanded.add("my");
  if (id.startsWith("t:")) S.expanded.add("tags");
  if (id.startsWith("ou:")) {
    S.expanded.add("ad");
    const parts = id.slice(3).split("/");
    for (let i = 2; i < parts.length; i++) S.expanded.add("ou:" + parts.slice(0, i).join("/"));
  }
  renderTree();
  renderPage();
  updateToolbar();
  if (!opts.noScroll) $("#tree .tn.sel")?.scrollIntoView({ block: "nearest" });
}

/* ================================================================== node → computers */
function nodeComputers(id) {
  const C = S.computers;
  if (id === "all") return C;
  if (id.startsWith("b:")) { const b = BUILTIN.find((x) => x[0] === id.slice(2)); return b ? C.filter(b[2]) : []; }
  if (id.startsWith("os:")) return C.filter((c) => (c.os || "?") === id.slice(3));
  if (id.startsWith("hw:")) return C.filter((c) => inv(c, "manufacturer") === id.slice(3));
  if (id === "ad") return C;
  if (id.startsWith("ou:")) { const p = id.slice(3); return C.filter((c) => c.ou === p || (c.ou || "").startsWith(p + "/")); }
  if (id.startsWith("t:")) return C.filter((c) => c.tags.includes(id.slice(2)));
  if (id.startsWith("f:")) {
    const f = S.fleets.find((x) => String(x.id) === id.slice(2));
    const g = new Set(f ? f.guids : []);
    return C.filter((c) => g.has(c.guid));
  }
  return null;
}
const currentFleet = () => (S.node.startsWith("f:") ? S.fleets.find((x) => String(x.id) === S.node.slice(2)) : null);

/* ================================================================== grid */
const COLUMNS = [
  { id: "name", get: (c) => c.name.toLowerCase(), html: (c) => `${icon(isServer(c) ? "server" : "computer", 16, c.online === false || !c.enabled ? 'style="filter:grayscale(1);opacity:.55"' : "")}${esc(c.name)}` },
  { id: "online", get: (c) => (c.online === true ? 0 : c.online === false ? 2 : 1), html: onlineCell },
  { id: "scan_status", get: (c) => scanStatus(c)[1], html: (c) => { const [cls, l] = scanStatus(c); return `<span data-st class="${cls}" title="${esc(c.collect_error || "")}">${esc(l)}</span>`; } },
  { id: "os", get: (c) => osShort(c) },
  { id: "os_version", get: (c) => inv(c, "os_version") || (c.os_version || "").replace(/ \((\d+)\)/, ".$1") },
  { id: "release", get: (c) => inv(c, "os_display_version") || "" },
  { id: "security", get: (c) => secState(c)[1], html: (c) => { const [cls, l] = secState(c); return `<span class="${cls}" title="${esc(secTip(c))}">${esc(l)}</span>`; } },
  { id: "uptime", get: (c) => c.uptime_s ?? -1, html: (c) => esc(fmtUptime(c.uptime_s)) },
  { id: "ip", get: (c) => (c.ip || "").split(".").map((n) => n.padStart(3, "0")).join("."), html: (c) => esc(c.ip || "") },
  { id: "user", get: (c) => inv(c, "logged_on_user") || "" },
  { id: "manufacturer", get: (c) => inv(c, "manufacturer") || "" },
  { id: "model", get: (c) => inv(c, "model") || "" },
  { id: "serial", get: (c) => inv(c, "serial") || "" },
  { id: "memory", num: true, get: (c) => inv(c, "memory_gb") ?? -1, html: (c) => esc(gb(inv(c, "memory_gb"))) },
  { id: "cfree", num: true, get: (c) => inv(c, "c_free_gb") ?? -1, html: (c) => esc(gb(inv(c, "c_free_gb"))) },
  { id: "last_logon", get: (c) => c.last_logon || "", html: (c) => (c.last_logon ? `<span class="${c.stale ? "st-warn" : ""}">${esc(fmtDate(c.last_logon))}</span>` : `<span class="faint">${t("v.never")}</span>`) },
  { id: "scanned", get: (c) => c.collected_at || "", html: (c) => esc(fmtDate(c.scan_status === "failed" ? "" : c.collected_at)) },
  { id: "ou", get: (c) => c.ou || "", html: (c) => esc((c.ou || "").split("/").slice(1).join("/")) },
  { id: "os_name", get: (c) => inv(c, "os_caption") || c.os || "" },
  { id: "chassis", get: (c) => inv(c, "chassis") || "" },
  { id: "reboot", get: (c) => (inv(c, "pending_reboot") ? 1 : 0), html: (c) => (inv(c, "pending_reboot") == null ? "" : inv(c, "pending_reboot") ? `<span class="st-warn">${t("v.yes")}</span>` : t("v.no")) },
  { id: "location", get: (c) => c.location || "" },
  { id: "description", get: (c) => c.description || "" },
  { id: "tags", get: (c) => c.tags.join(","), html: (c) => c.tags.map((x) => `<span class="chip">${esc(x)}</span>`).join("") },
];
const DEFAULT_COLS = ["name", "online", "scan_status", "os", "os_version", "release", "security", "uptime", "ip", "user", "model", "last_logon"];
const visibleCols = () => (S.cols || DEFAULT_COLS).map((id) => COLUMNS.find((c) => c.id === id)).filter(Boolean);
const ROW_LIMIT = 5000;

function filteredList(base) {
  const q = S.filter.trim().toLowerCase();
  let rows = base;
  if (q) {
    const terms = q.split(/\s+/);
    rows = rows.filter((c) => {
      const hay = [c.name, c.dns_hostname, c.ip, c.os, c.ou, c.description, c.location, c.tags.join(" "), inv(c, "model"),
        inv(c, "manufacturer"), inv(c, "serial"), inv(c, "logged_on_user"), inv(c, "user_display_name"), inv(c, "os_display_version"), scanStatus(c)[1]].join(" ").toLowerCase();
      return terms.every((x) => hay.includes(x));
    });
  }
  const col = COLUMNS.find((c) => c.id === S.sort.key) || COLUMNS[0];
  return [...rows].sort((a, b) => {
    const x = col.get(a), y = col.get(b);
    return (x < y ? -1 : x > y ? 1 : a.name.localeCompare(b.name)) * S.sort.dir;
  });
}

function gridHTML(rows) {
  const cols = visibleCols();
  const head = `<th class="rn">${icon("columns", 14)}</th>` + (isDesktop() ? '<th class="ra"></th>' : "") + cols.map((c) => `<th data-sort="${c.id}">${esc(t("col." + c.id))}${S.sort.key === c.id ? `<span class="arr">${S.sort.dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("");
  const shown = rows.slice(0, ROW_LIMIT);
  const body = shown.map((c, i) => `<tr data-guid="${esc(c.guid)}" data-i="${i}" class="${S.sel.has(c.guid) ? "sel" : ""}"><td class="rn"></td>${isDesktop() ? `<td class="ra"><button type="button" class="ra-btn" data-ra="${esc(c.name)}" title="${esc(tText("ra.tip", { name: c.name }))}" aria-label="${esc(tText("ra.tip", { name: c.name }))}">${icon("ra", 16)}</button></td>` : ""}${cols.map((col) => `<td class="${col.num ? "num" : ""}${col.id === "tags" || col.id === "ou" ? " trunc" : ""}">${col.html ? col.html(c) : esc(col.get(c))}</td>`).join("")}</tr>`).join("");
  return `<table class="grid"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${rows.length > ROW_LIMIT ? `<div class="empty">${esc(tText("page.limit", { n: ROW_LIMIT }))}</div>` : ""}`;
}

function drawGrid() {
  const wrap = $("#grid");
  if (!wrap) return;
  const base = nodeComputers(S.node) || [];
  S.list = filteredList(base);
  wrap.innerHTML = S.list.length ? gridHTML(S.list) : `<div class="empty">${esc(S.computers.length ? t("page.empty") : t("page.empty_all"))}</div>`;
  updateStatus();
  updateToolbar();
}

function refreshSelectionClasses() {
  $$("#grid tbody tr").forEach((tr) => tr.classList.toggle("sel", S.sel.has(tr.dataset.guid)));
  updateStatus();
  updateToolbar();
}

function onGridClick(e) {
  const ra = e.target.closest("button[data-ra]");
  if (ra) {                                   // offer Remote Assistance: msra /offerra <computer>
    e.stopPropagation();
    guard(() => window.pywebview.api.remote_assist(ra.dataset.ra));
    return;
  }
  const th = e.target.closest("th[data-sort]");
  if (th) {
    const k = th.dataset.sort;
    if (S.sort.key === k) S.sort.dir *= -1; else S.sort = { key: k, dir: 1 };
    store.set("sort", S.sort);
    return drawGrid();
  }
  if (e.target.closest("th.rn")) return columnsDialog();
  const tr = e.target.closest("tr[data-guid]");
  if (!tr) return;
  const g = tr.dataset.guid, i = Number(tr.dataset.i);
  if (e.shiftKey && S.anchor != null) {
    const a = S.list.findIndex((c) => c.guid === S.anchor);
    const [lo, hi] = a < i ? [a, i] : [i, a];
    if (!e.ctrlKey) S.sel.clear();
    S.list.slice(lo, hi + 1).forEach((c) => S.sel.add(c.guid));
  } else if (e.ctrlKey || e.metaKey) {
    if (S.sel.has(g)) S.sel.delete(g); else S.sel.add(g);
    S.anchor = g;
  } else {
    S.sel.clear(); S.sel.add(g); S.anchor = g;
  }
  refreshSelectionClasses();
}

function moveSelection(delta) {
  if (!S.list.length) return;
  let i = S.list.findIndex((c) => c.guid === S.anchor);
  i = Math.max(0, Math.min(S.list.length - 1, (i < 0 ? -1 : i) + delta));
  const g = S.list[i].guid;
  S.sel.clear(); S.sel.add(g); S.anchor = g;
  refreshSelectionClasses();
  $(`#grid tr[data-guid="${CSS.escape(g)}"]`)?.scrollIntoView({ block: "nearest" });
}

/* ================================================================== page */
function pageHead(iconName, title, sub, buttons) {
  return `<div class="page-head"><h1>${icon(iconName, 30)}<span>${esc(title)}</span></h1>${sub ? `<span class="sub">${esc(sub)}</span>` : ""}
    <span class="spacer"></span>${buttons || ""}</div>`;
}

/* ================================================================== navigation rail */
const RAIL = [
  ["rail.inventory", [["devices", "computers"], ["users", "users"], ["printers", "printer"], ["-"], ["software", "apps"], ["vulns", "shield"], ["winupdates", "patch"]]],
  ["rail.actions", [["deployments", "rocket"], ["packages", "package"]]],
  ["rail.tools", [["remote", "ra"], ["reports", "report", true], ["scanners", "scan", true]]],
];

function renderRail() {
  $("#rail").innerHTML = `<div class="rail-brand"><img src="/static/favicon.svg" width="24" height="24" alt=""><span>ADmiral</span></div>`
    + RAIL.map(([sec, items]) => `<div class="rail-sec">${esc(t(sec))}</div>` + items.map(([id, ic, soon]) => id === "-" ? `<div class="rail-sep"></div>` :
      `<div class="rail-it${S.section === id ? " on" : ""}${soon ? " soon" : ""}" ${soon ? `title="${esc(t("rail.soon"))}"` : `data-sec="${id}"`} role="button">${icon(ic, 18)}<span>${esc(t("nav." + id))}</span></div>`).join("")).join("")
    + `<div class="rail-grow"></div><div class="rail-it" data-rail="discord" role="button">${icon("discord", 18)}<span>${esc(t("nav.discord"))}</span></div>`
    + `<div class="rail-it" data-rail="support" role="button">${icon("coffee", 18)}<span>${esc(t("nav.support"))}</span></div>`
    + `<div class="rail-it" data-sec="settings" role="button">${icon("settings", 18)}<span>${esc(t("nav.settings"))}</span></div>`;
}

function applySection() {
  const devices = S.section === "devices", settings = S.section === "settings";
  document.querySelector(".workspace").classList.toggle("no-tree", !devices && !settings);
  const users = S.section === "users" || S.section === "printers";
  $("#toolbar").style.display = devices ? "" : "none";
  $("#tree-filter").style.display = settings ? "none" : "";
  if (settings || users) hideMenu();
  if (devices) renderTree();
}

function setSection(id, opts = {}) {
  S.section = id;
  store.set("section", id);
  renderRail();
  applySection();
  if (opts.render !== false) { renderPage(); updateToolbar(); }
}

function renderPage() {
  const el = $("#page");
  if (S.section === "software") return renderSoftwarePage(el);
  if (S.section === "vulns") return renderVulnsPage(el);
  if (S.section === "users") return renderUsersPage(el);
  if (S.section === "printers") return renderPrintersPage(el);
  if (S.section === "packages") return renderPackagesPage(el);
  if (S.section === "deployments") return renderDeploymentsPage(el);
  if (S.section === "remote") return renderRemotePage(el);
  if (S.section === "settings") return renderSettings(el);
  if (S.section === "winupdates") return renderWinUpdatesPage(el);
  const id = S.node;
  if (id === "welcome") return renderWelcome(el);
  if (id === "log") return renderLog(el);
  if (["lib", "my", "tags", "os", "hw", "upd"].includes(id)) return renderCollectionList(el, id);
  const node = findNode(S.treeNodes || buildTree(), id);
  if (!node && id.startsWith("f:")) { S.node = "my"; return renderPage(); }
  const fleet = currentFleet();
  let sub = "";
  if (id.startsWith("b:") || id.startsWith("os:") || id.startsWith("hw:")) sub = t("page.builtin");
  else if (id.startsWith("ou:") || id === "ad") sub = t("page.ou");
  else if (id.startsWith("t:")) sub = t("page.tag");
  else if (fleet) sub = `${fleet.kind === "dynamic" ? t("v.dynamic") : t("v.static")}${fleet.description ? " · " + fleet.description : ""}`;
  const btn = (act, ic, label) => `<button class="btn" data-act="${act}">${icon(ic, 16)}${esc(label)}</button>`;
  const buttons = (fleet
    ? btn("scan", "scan", t("page.scan")) + btn("edit-coll", "edit", t("page.edit")) + btn("export", "export", t("page.export")) + btn("group", "group", t("page.group"))
    : btn("scan", "scan", t("page.scan")) + btn("details", "details", t("page.view_details")) + btn("export", "export", t("page.export")))
    + `<input class="page-filter" id="page-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(S.filter)}">`;
  el.innerHTML = pageHead(node?.icon || "computers", node?.label || id, sub, buttons) + `<div class="grid-wrap" id="grid" tabindex="0"></div>`;
  drawGrid();
  let tmr;
  $("#page-filter").oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { S.filter = e.target.value; drawGrid(); }, 120); };
  const grid = $("#grid");
  grid.addEventListener("click", onGridClick);
  grid.addEventListener("dblclick", (e) => { if (e.target.closest("button[data-ra]")) return; const tr = e.target.closest("tr[data-guid]"); if (tr) openComputer(tr.dataset.guid); });
  grid.addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-guid]");
    if (!tr) return;
    e.preventDefault();
    if (!S.sel.has(tr.dataset.guid)) { S.sel.clear(); S.sel.add(tr.dataset.guid); S.anchor = tr.dataset.guid; refreshSelectionClasses(); }
    showMenu(computerMenu(true), e.clientX, e.clientY);
  });
  el.querySelectorAll("[data-act]").forEach((b) => (b.onclick = () => ACTIONS[b.dataset.act]()));
}

function renderCollectionList(el, id) {
  const node = findNode(S.treeNodes, id);
  const kids = node?.children || [];
  el.innerHTML = pageHead(node.icon, node.label, "", id === "my" || id === "lib"
    ? `<button class="btn" data-act="new-dyn">${icon("coll_dyn", 16)}${esc(t("m.new_dyn").replace("…", ""))}</button><button class="btn" data-act="new-stat">${icon("coll_stat", 16)}${esc(t("m.new_stat").replace("…", ""))}</button>` : "")
    + `<div class="grid-wrap" tabindex="0"><table class="grid"><thead><tr><th class="rn"></th><th>${t("col.name")}</th><th>${t("coll.type")}</th><th>${t("sb.count", { n: "" }).trim() || "#"}</th><th>${t("col.description")}</th></tr></thead><tbody>
      ${kids.map((k) => {
        const f = k.id.startsWith("f:") ? S.fleets.find((x) => "f:" + x.id === k.id) : null;
        return `<tr data-open="${esc(k.id)}"><td class="rn"></td><td>${icon(k.icon, 16)}${esc(k.label)}</td><td>${f ? (f.kind === "dynamic" ? t("v.dynamic") : t("v.static")) : k.children ? "" : t("page.builtin")}</td><td class="num">${k.count ?? ""}</td><td class="trunc">${esc(f?.description || "")}</td></tr>`;
      }).join("") || `<tr><td></td><td colspan="4" class="faint">${t("tree.none")}</td></tr>`}</tbody></table></div>`;
  el.querySelectorAll("[data-act]").forEach((b) => (b.onclick = () => ACTIONS[b.dataset.act]()));
  el.querySelector(".grid-wrap").addEventListener("dblclick", (e) => { const tr = e.target.closest("tr[data-open]"); if (tr) selectNode(tr.dataset.open); });
  el.querySelector(".grid-wrap").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-open]");
    $$("tr.sel", el).forEach((x) => x.classList.remove("sel"));
    if (tr) tr.classList.add("sel");
  });
  updateStatus();
}

function renderWelcome(el) {
  el.innerHTML = pageHead("home", t("tree.welcome"), "", "") + `<div class="welcome" id="welcome"><div class="empty">…</div></div>`;
  updateStatus();
  guard(async () => {
    const s = await api("GET", "/api/summary");
    const tile = (n, label, node) => `<div class="tile" data-node="${esc(node)}"><div class="n">${esc(n)}</div><div class="l">${esc(label)}</div></div>`;
    const pct = (n) => (s.total ? (n / s.total) * 100 : 0);
    const bars = (items, prefix) => {
      const max = Math.max(1, ...items.map((i) => i[1]));
      return items.slice(0, 10).map(([label, n]) => `<div class="bar-row" data-node="${esc(prefix + label)}"><span class="bl" title="${esc(label)}">${esc(label)}</span><span class="bt"><span class="bf" style="width:${(Number(n) / max) * 100 || 0}%"></span></span><span class="bn">${esc(n)}</span></div>`).join("");
    };
    const dom = domainName();
    $("#welcome").innerHTML = `
      <div style="display:flex;gap:16px;align-items:center;margin-bottom:12px"><img src="/static/logo.svg" width="72" height="72" alt="">
        <div><h2>${t("w.title")}</h2><p class="lead" style="margin:0">${t("w.sub")}</p></div></div>
      ${s.total ? "" : `<ol><li>${t("w.step1")}</li><li>${t("w.step2")}</li><li>${t("w.step3")}</li></ol><p><button class="btn primary" id="w-sync">${icon("sync", 16)}${t("w.sync_now")}</button></p>`}
      ${s.total ? `<div class="tiles">
        ${tile(s.total, t("w.computers"), "all")}${tile(s.online, t("w.online"), "b:online")}${tile(s.offline, t("w.offline"), "b:offline")}
        ${tile(s.unscanned, t("w.unscanned"), "b:unscanned")}${tile(s.inventoried, t("w.inventoried"), "all")}${tile(s.scan_failed, t("w.failed"), "b:failed")}
        ${tile(s.stale, t("w.stale"), "b:stale")}${tile(s.pending_reboot, t("w.reboot"), "b:reboot")}${tile(s.low_disk, t("w.lowdisk"), "b:lowdisk")}${tile(s.smb1, t("w.smb1"), "b:smb1")}
      </div>
      <div class="muted">${esc(tText("w.last", { a: s.last_ad_sync ? fmtDate(s.last_ad_sync) : t("v.never"), b: s.last_scan ? fmtDate(s.last_scan) : t("v.never") }))}</div>
      <div class="health"><span style="width:${pct(s.online)}%;background:var(--ok)"></span><span style="width:${pct(s.offline)}%;background:var(--bad)"></span><span style="width:${pct(s.unscanned)}%;background:var(--faint)"></span></div>
      <div class="cols2" style="margin-top:14px">
        <div class="box"><h3>${t("w.by_os")}</h3><div class="bars">${bars(s.by_os, "os:")}</div></div>
        <div class="box"><h3>${t("w.by_ou")}</h3><div class="bars">${bars(s.by_ou.map(([o, n]) => [o, n]), "ou:" + dom + "/")}</div></div>
      </div>` : ""}`;
    const sync = $("#w-sync");
    if (sync) sync.onclick = () => adBrowserDialog();
    $("#welcome").onclick = (e) => {
      const n = e.target.closest("[data-node]");
      if (!n) return;
      let id = n.dataset.node;
      if (id.endsWith("/(root)")) id = "ad";
      selectNode(id);
    };
  });
}

function renderLog(el) {
  el.innerHTML = pageHead("log", t("tree.log"), "", `<button class="btn" data-act="refresh">${icon("refresh", 16)}${t("m.refresh")}</button>`) + `<div class="grid-wrap" id="logwrap" tabindex="0"><div class="empty">…</div></div>`;
  el.querySelector("[data-act]").onclick = () => renderLog(el);
  updateStatus();
  guard(async () => {
    const items = await api("GET", "/api/activity");
    $("#logwrap").innerHTML = items.length ? `<table class="grid"><thead><tr><th class="rn"></th><th>${t("log.time")}</th><th>${t("log.action")}</th><th>${t("log.detail")}</th></tr></thead><tbody>
      ${items.map((a) => `<tr><td class="rn"></td><td>${esc(fmtDate(a.ts))}</td><td>${esc(t("act." + a.action) === "act." + a.action ? a.action : t("act." + a.action))}</td><td>${esc(a.detail)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">${t("log.empty")}</div>`;
  });
}

/* ================================================================== status bar & toolbar state */
function updateStatus() {
  const left = $("#sb-left");
  const isGrid = !!$("#grid");
  left.textContent = isGrid ? `${tText("sb.count", { n: S.list.length })} ${S.sel.size ? tText("sb.selected", { n: S.sel.size }) : ""}` : tText("sb.count", { n: S.computers.length });
  const job = S.job;
  const right = $("#sb-right");
  if (job && job.status === "running") {
    const scanning = ["scan", "collect", "full"].includes(job.kind);
    const nActive = Object.keys(job.active || {}).length;     // computers being queried at this moment
    right.innerHTML = scanning && job.total ? esc(tText("sb.scanning", { n: nActive })) : esc(t("job." + job.kind));
    const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
    $("#sb-mid").innerHTML = `${esc(t("job." + job.kind))}<span class="meter"><span style="width:${pct}%"></span></span>${esc(job.message || "")}`;
  } else {
    right.textContent = t("sb.idle");
    $("#sb-mid").textContent = S.status?.mode === "demo" ? t("sb.demo") : "";
  }
}

function updateToolbar() {
  const fleet = currentFleet();
  const hasSel = S.sel.size > 0;
  const set = (id, on) => { const b = $(`#toolbar [data-tb="${id}"]`); if (b) b.disabled = !on; };
  set("details", hasSel);
  set("columns", !!$("#grid"));
  set("copy", hasSel || (S.list.length > 0 && !!$("#grid")));
  set("delete", !!fleet);
  set("group", !!fleet);
  set("export", !!fleet || (!!$("#grid") && S.list.length > 0));
  const running = S.job && S.job.status === "running";
  set("scan", !running);
  set("adsync", !running);
}

/* ================================================================== menus */
function computerMenu(ctx) {
  const hasSel = S.sel.size > 0;
  const fleet = currentFleet();
  const selected = [...S.sel].map((g) => S.byGuid.get(g)).filter(Boolean);
  const anyBlocked = selected.some((c) => c.allow_scan === false);
  return [
    { label: t("m.details"), icon: "details", key: "Enter", action: ACTIONS.details, disabled: !hasSel },
    "-",
    { label: t("m.scan_full"), icon: "scan", action: () => scanSelection("full"), disabled: !hasSel && ctx },
    { label: t("m.scan_ping"), icon: "ping", action: () => scanSelection("scan"), disabled: !hasSel && ctx },
    { label: t("m.scan_inv"), icon: "details", action: () => scanSelection("collect"), disabled: !hasSel && ctx },
    "-",
    { label: t("m.add_tag"), icon: "tag", action: () => tagDialog(true), disabled: !hasSel },
    { label: t("m.remove_tag"), action: () => tagDialog(false), disabled: !hasSel },
    { label: t("m.add_to_coll"), icon: "coll_stat", action: addToCollectionDialog, disabled: !hasSel },
    fleet && fleet.kind === "static" && { label: t("m.remove_from_coll"), action: ACTIONS["remove-from-coll"], disabled: !hasSel },
    "-",
    anyBlocked
      ? { label: t("m.allow_scan"), icon: "scan", action: () => setAllowScan([...S.sel], true), disabled: !hasSel }
      : { label: t("m.disallow_scan"), icon: "block", action: () => setAllowScan([...S.sel], false), disabled: !hasSel },
    "-",
    { label: t("m.remove_computers"), icon: "block", key: "Del", action: () => removeComputers([...S.sel]), disabled: !hasSel },
    "-",
    { label: t("m.copy_names"), icon: "copy", key: "Ctrl+C", action: ACTIONS.copy, disabled: !hasSel },
  ];
}

function menuHTML(items) {
  return items.filter(Boolean).map((it, i) => {
    if (it === "-") return `<div class="sep"></div>`;
    return `<div class="mi${it.disabled ? " dis" : ""}" data-mi="${i}"><span class="chk">${it.check ? "✓" : it.icon ? icon(it.icon, 16) : ""}</span><span>${esc(it.label)}</span><span class="k">${esc(it.key || "")}</span><span>${it.sub ? "›" : ""}</span>
      ${it.sub ? `<div class="sub menu-pop">${menuHTML(it.sub)}</div>` : ""}</div>`;
  }).join("");
}

let menuOwner = null;
function showMenu(items, x, y, owner) {
  const pop = $("#pop");
  const list = items.filter(Boolean);
  pop.innerHTML = menuHTML(list);
  pop.hidden = false;
  const r = pop.getBoundingClientRect();
  pop.style.left = Math.min(x, window.innerWidth - r.width - 4) + "px";
  pop.style.top = Math.min(y, window.innerHeight - r.height - 4) + "px";
  menuOwner = owner || null;
  const resolve = (el) => {
    // walk up the nested .mi chain to find the clicked item
    const path = [];
    let cur = el.closest(".mi");
    while (cur && pop.contains(cur)) { path.unshift(Number(cur.dataset.mi)); cur = cur.parentElement.closest(".mi"); }
    let arr = list, it = null;
    for (const i of path) { it = arr.filter(Boolean)[i]; arr = (it && it.sub) || []; }
    return it;
  };
  pop.onclick = (e) => {
    const it = resolve(e.target);
    if (!it || it.disabled || it.sub) return;
    hideMenu();
    it.action && it.action();
  };
}
function hideMenu() { $("#pop").hidden = true; menuOwner = null; }

/* ================================================================== toolbar */
function renderToolbar() {
  const b = (id, ic, label, drop) => `<button class="tb" data-tb="${id}">${icon(ic, 30)}<span>${esc(t(label))}</span>${drop ? `<span class="drop">▼</span>` : ""}</button>`;
  const sep = `<span class="tb-sep"></span>`;
  $("#toolbar").innerHTML = b("scan", "scan", "tb.scan", true) + b("adsync", "sync", "tb.ad_sync") + sep
    + b("library", "library", "tb.library") + b("new-dyn", "dyn", "tb.new_dyn") + b("new-stat", "stat", "tb.new_stat") + sep
    + b("export", "export", "tb.export") + b("group", "group", "tb.group") + sep
    + b("details", "details", "tb.details") + b("columns", "columns", "m.columns") + b("copy", "copy", "tb.copy") + b("delete", "delete", "tb.delete") + sep
    + b("settings", "settings", "tb.settings");
  $$("#toolbar .tb").forEach((btn) => (btn.onclick = (e) => {
    const id = btn.dataset.tb;
    if (id === "scan") {
      e.stopPropagation();
      const r = btn.getBoundingClientRect();
      return showMenu([
        { label: t("m.scan_full"), icon: "scan", action: () => scanSelection("full") },
        { label: t("m.scan_ping"), icon: "ping", action: () => scanSelection("scan") },
        { label: t("m.scan_inv"), icon: "details", action: () => scanSelection("collect") },
        "-",
        { label: t("m.ad_sync"), icon: "sync", action: () => adBrowserDialog() },
      ], r.left, r.bottom, btn);
    }
    const map = { columns: () => columnsDialog(), adsync: () => adBrowserDialog(), library: () => selectNode("lib"), settings: () => setSection("settings") };
    (map[id] || ACTIONS[id])();
  }));
  updateToolbar();
}

/* ================================================================== actions */
const selectedComputers = () => S.list.filter((c) => S.sel.has(c.guid));

const ACTIONS = {
  scan: () => scanSelection("full"),
  details: () => { const g = S.anchor && S.sel.has(S.anchor) ? S.anchor : [...S.sel][0]; if (g) openComputer(g); else toast(t("need_selection"), true); },
  copy: async () => {
    const rows = S.sel.size ? selectedComputers() : S.list;
    if (!rows.length) return;
    await copyText(rows.map((c) => c.dns_hostname || c.name).join("\r\n"));
    toast(tText("copied", { n: rows.length }));
  },
  export: () => exportDialog(),
  group: () => { const f = currentFleet(); if (f) groupCompareDialog(f); else toast(t("need_collection"), true); },
  delete: () => guard(async () => {
    const f = currentFleet();
    if (!f) return toast(t("need_collection"), true);
    if (!(await confirmDialog(tText("coll.confirm_delete", { name: f.name })))) return;
    await api("DELETE", `/api/fleets/${f.id}`);
    toast(t("coll.deleted"));
    await loadAll();
    selectNode("my");
  }),
  "new-dyn": () => fleetEditor(null, { kind: "dynamic" }),
  "new-stat": () => fleetEditor(null, { kind: "static", members: selectedComputers().map((c) => c.name) }),
  "edit-coll": () => { const f = currentFleet(); if (f) fleetEditor(f, {}); else toast(t("need_collection"), true); },
  "remove-from-coll": () => guard(async () => {
    const f = currentFleet();
    if (!f || f.kind !== "static") return toast(t("not_static"), true);
    const ids = [...S.sel];
    await api("POST", `/api/fleets/${f.id}/members`, { remove: ids });
    toast(tText("coll.removed", { n: ids.length }));
    S.sel.clear();
    await reload();
  }),
  "select-all": () => { S.list.forEach((c) => S.sel.add(c.guid)); refreshSelectionClasses(); },
  "select-none": () => { S.sel.clear(); refreshSelectionClasses(); },
  find: () => $("#page-filter")?.focus(),
  refresh: () => reload(),
  "test-conn": () => guard(async () => { const r = await api("POST", "/api/test-connection", {}); toast(r.message, !r.ok); }),
};

async function reload() {
  await guard(loadAll);
  renderTree();
  renderPage();
}

function scanScope() {
  if (S.sel.size) return { ids: [...S.sel] };
  const f = currentFleet();
  if (f) return { fleet_id: f.id };
  if ($("#grid") && S.node !== "all") return { ids: S.list.map((c) => c.guid) };
  return {};
}
function scanSelection(kind) {
  const scope = scanScope();
  if (scope.ids && !scope.ids.length) return toast(t("page.empty"), true);
  startJob(kind, scope);
}

// READ-ONLY: pick the OU to start the AD import from (only LDAP searches are issued).
async function adBrowserDialog(what = "computers") {
  hideMenu();
  const users = what === "users";
  const first = await guard(() => api("GET", "/api/ad/ous"));
  if (!first) return;
  const root = first.root;
  const box = dialog(t(users ? "ad.title_users" : "ad.title"), `<div class="callout">${icon("info", 16)} ${esc(t(users ? "ad.hint_users" : "ad.hint"))}</div>
    <div id="ad-tree" class="adtree" role="tree"></div>
    <div style="margin-top:8px"><span class="faint">${esc(t("ad.selected"))}</span> <span class="mono" id="ad-sel" style="overflow-wrap:anywhere"></span></div>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><span style="flex:1"></span><button class="btn primary" data-ok>${t("ad.import")}</button>`);
  const tree = $("#ad-tree", box);
  let selDn = root;
  const pick = (row, dn) => {
    $$(".tn.sel", tree).forEach((r) => r.classList.remove("sel"));
    row.classList.add("sel");
    selDn = dn;
    $("#ad-sel", box).textContent = dn === root ? t("ad.whole") : dn;
  };
  const addNode = (host, dn, name, depth, preload) => {
    const wrap = document.createElement("div");
    wrap.innerHTML = `<div class="tn" style="padding-left:${depth * 16}px" role="treeitem"><span class="tw">▸</span><span class="lbl">${esc(name)}</span></div>`;
    const row = wrap.firstElementChild, tw = row.querySelector(".tw");
    const kids = document.createElement("div");
    kids.hidden = true;
    wrap.appendChild(kids);
    let loaded = false;
    const fill = (list) => {
      loaded = true;
      list.forEach((c) => addNode(kids, c.dn, c.name, depth + 1));
      if (!list.length) tw.classList.add("leaf");
    };
    const toggle = async () => {
      const open = kids.hidden;
      if (open && !loaded) {
        const r = await guard(() => api("GET", "/api/ad/ous?parent=" + encodeURIComponent(dn)));
        if (!r) return;
        fill(r.children);
      }
      kids.hidden = !open;
      tw.classList.toggle("open", open);
    };
    tw.onclick = (e) => { e.stopPropagation(); toggle(); };
    row.onclick = () => pick(row, dn);
    row.ondblclick = toggle;
    host.appendChild(wrap);
    if (preload) { fill(preload); kids.hidden = false; tw.classList.add("open"); }
    return row;
  };
  const domain = root.split(",").filter((p) => /^dc=/i.test(p.trim())).map((p) => p.split("=")[1]).join(".") || root;
  pick(addNode(tree, root, domain, 0, first.children), root);
  box.querySelector("[data-ok]").onclick = () => {
    closeDialog();
    startJob(users ? "ad-users" : "ad-sync", selDn === root ? {} : { base_dn: selDn });
  };
}

async function removeComputers(ids) {
  hideMenu();
  if (!ids.length) return;
  if (!(await confirmDialog(tText("remove_confirm", { n: ids.length })))) return;
  await guard(async () => {
    const r = await api("POST", "/api/computers/remove", { ids });
    S.sel.clear();
    toast(tText("remove_done", { n: r.removed }));
    if (S.cw && typeof closeComputer === "function") closeComputer();
    await reload();
  });
}

async function restoreComputers() {
  await guard(async () => {
    const r = await api("POST", "/api/computers/restore");
    toast(tText("restore_done", { n: r.restored }));
    await reload();
  });
}

async function setAllowScan(ids, allow) {
  await guard(async () => {
    const r = await api("POST", "/api/allow-scan", { ids, allow });
    toast(tText("allow_done", { n: r.updated, state: allow ? t("v.enabled").toLowerCase() : t("v.disabled").toLowerCase() }));
    await reload();
    if (S.cw) loadComputer();
  });
}

/* ================================================================== jobs */
async function startJob(kind, scope = {}) {
  hideMenu();
  const job = await guard(() => api("POST", `/api/jobs/${kind}`, scope));
  if (job) pollJob(job.id);
}

// Update just the "Scan Status" cells of the visible grid rows (no full re-render: keeps scroll and selection).
function patchScanStatus() {
  document.querySelectorAll("#grid span[data-st]").forEach((el) => {
    const c = S.byGuid.get(el.closest("tr")?.dataset.guid);
    if (!c) return;
    const [cls, label] = scanStatus(c);
    el.className = cls;
    el.textContent = label;
  });
}

async function pollJob(id) {
  let lastDone = -1, lastLoad = 0;
  for (;;) {
    let job;
    try { job = await api("GET", `/api/jobs/${id}`); } catch (e) { toast(e.message, true); break; }
    S.job = job;
    updateStatus();
    updateToolbar();
    patchScanStatus();
    // live results: re-read the list (throttled) whenever more computers have finished
    if (job.status === "running" && job.done !== lastDone && Date.now() - lastLoad > 2000) {
      lastDone = job.done;
      lastLoad = Date.now();
      await guard(loadAll);
      patchScanStatus();
    }
    if (job.status !== "running") {
      const label = t("job." + job.kind);
      if (job.status === "error") toast(tText("job.failed", { label, err: job.error }), true);
      else toast(`${label}: ${resultText(job.kind, job.result)}`);
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  S.job = null;
  if (typeof US !== "undefined") US.list = null;          // the Users list may have changed (AD user import)
  await reload();
  if (S.section === "packages") pkLoad();
  updateStatus();
  if (S.cw) loadComputer();
}
function resultText(kind, r) {
  if (!r) return "OK";
  if ((kind === "collect" || kind === "full") && !r.attempted && !r.online) return t("res.nothing");
  return tText("res." + kind, r);
}

/* ================================================================== computer window */
const CATS = [
  ["computer", "computer"], ["ad_groups", "group"], ["apps", "apps"], ["disks", "disk"], ["nics", "nic"],
  ["hotfixes", "patch"], ["services", "services"], ["local_admins", "admin"], ["logons", "user"], ["ports", "ping"], ["collections", "coll_stat"], ["tags", "tag"],
];

function openComputer(guid, back) {
  const list = S.list.length && S.list.some((c) => c.guid === guid) ? S.list.map((c) => c.guid) : S.computers.map((c) => c.guid);
  S.cw = { guid, list, cat: S.cw?.cat || "computer", data: null, filter: "", back: back || null };
  $("#cwin").hidden = false;
  renderCwToolbar();
  loadComputer();
}
function closeComputer() {
  const back = S.cw?.back;                         // opened from another window (e.g. a vulnerability): return there
  S.cw = null; $("#cwin").hidden = true; $("#grid")?.focus();
  if (back) back();
}
function cwStep(d) {
  if (!S.cw) return;
  const i = S.cw.list.indexOf(S.cw.guid) + d;
  if (i < 0 || i >= S.cw.list.length) return;
  S.cw.guid = S.cw.list[i];
  S.cw.filter = "";
  if (S.sel.size <= 1) { S.sel.clear(); S.sel.add(S.cw.guid); S.anchor = S.cw.guid; refreshSelectionClasses(); }
  loadComputer();
}

async function loadComputer() {
  const cw = S.cw;
  if (!cw) return;
  const data = await guard(() => api("GET", `/api/computers/${encodeURIComponent(cw.guid)}`));
  if (!data || S.cw !== cw) return;
  cw.data = data;
  renderComputer();
}

function renderCwToolbar() {
  const b = (id, ic, label) => `<button class="tb" data-cw="${id}">${icon(ic, 30)}<span>${esc(t(label))}</span></button>`;
  $("#cwin-toolbar").innerHTML = b("scan", "scan", "cw.scan") + b("ping", "ping", "m.scan_ping") + (isDesktop() ? b("ra", "ra", "cw.ra") : "") + `<span class="tb-sep"></span>`
    + b("prev", "prev", "cw.prev") + b("next", "next", "cw.next") + `<span class="tb-sep"></span>`
    + b("allow", "block", "cw.toggle_disallow") + b("copy", "copy", "tb.copy") + `<span class="tb-sep"></span>` + b("close", "back", "cw.close");
}

function renderComputer() {
  const cw = S.cw, c = cw.data;
  const i = cw.list.indexOf(cw.guid);
  $("#cwin-title").textContent = tText("cw.title", { name: c.name, i: i + 1, n: cw.list.length });
  $('#cwin-toolbar [data-cw="prev"]').disabled = i <= 0;
  $('#cwin-toolbar [data-cw="next"]').disabled = i >= cw.list.length - 1;
  const allowBtn = $('#cwin-toolbar [data-cw="allow"]');
  allowBtn.innerHTML = `${icon(c.allow_scan ? "block" : "scan", 30)}<span>${esc(t(c.allow_scan ? "cw.toggle_disallow" : "cw.toggle_allow"))}</span>`;
  const running = S.job && S.job.status === "running";
  $('#cwin-toolbar [data-cw="scan"]').disabled = running || !c.allow_scan;
  $('#cwin-toolbar [data-cw="ping"]').disabled = running || !c.allow_scan;

  const counts = {
    computer: null, ad_groups: c.member_of.length, ports: c.open_ports.length, collections: c.fleets.length, tags: c.tags.length,
  };
  for (const k of ["apps", "disks", "nics", "hotfixes", "services", "local_admins", "logons"]) counts[k] = (c.items[k] || []).length;
  $("#cwin-cats").innerHTML = CATS.map(([id, ic]) => `<div class="cat${cw.cat === id ? " sel" : ""}${counts[id] === 0 && id !== "tags" ? " empty-cat" : ""}" data-cat="${id}">${icon(ic, 18)}<span>${esc(t("cw.cat." + id))}</span>${counts[id] ? `<span class="cnt">${counts[id]}</span>` : ""}</div>`).join("");

  const [stCls, stLabel] = scanStatus(c);
  $("#cwin-head").innerHTML = `${icon(isServer(c) ? "server" : "computer", 30, c.online === false ? 'style="filter:grayscale(1);opacity:.6"' : "")}<span>${esc(c.name)}</span><span class="grow"></span>
    <span>${onlineCell(c)}</span><span class="${stCls}">${esc(stLabel)}</span>`;

  const msg = $("#cwin-msg");
  msg.className = "cwin-msg";
  if (!c.allow_scan) { msg.hidden = false; msg.innerHTML = `${icon("info", 16)}${esc(t("cw.scan_disabled"))}`; }
  else if (c.scan_status === "failed") { msg.hidden = false; msg.classList.add("bad"); msg.innerHTML = `${icon("warn", 16)}${esc(tText("cw.scan_failed", { err: c.collect_error || "" }))}`; }
  else if (c.scan_status === "partial") { msg.hidden = false; msg.innerHTML = `${icon("warn", 16)}${esc(tText("cw.partial", { err: c.collect_error || "" }))}`; }
  else if (!c.collected_at) { msg.hidden = false; msg.innerHTML = `${icon("info", 16)}${esc(t("cw.never"))}`; }
  else msg.hidden = true;

  $("#cwin-status").textContent = c.collected_at ? `${t("f.success")}: ${fmtDate(c.collected_at)}` : "";
  renderCwContent();
}

function fieldRow(label, value, opts = {}) {
  const v = value == null || value === "" ? "" : value;
  return `<div class="frow"><label class="${opts.sub ? "sub" : ""}" title="${esc(label)}">${opts.sub ? "↳ " : ""}${esc(label)}</label><div class="fval${opts.wrap ? " wrap" : ""}${opts.mono ? " mono" : ""}" title="${esc(typeof v === "string" ? v : "")}">${opts.html ? v : esc(v)}</div></div>`;
}

function renderCwContent() {
  const cw = S.cw, c = cw.data, i = c.inventory || {};
  const el = $("#cwin-content");
  if (cw.cat === "computer") {
    const yn = (v) => (v == null ? "" : yesNo(v));
    const os = osShort(c);
    el.innerHTML = `<div class="form2"><div>
      <div class="fsec">${t("cw.general")}</div>
      ${fieldRow(t("f.name"), c.name)}${fieldRow(t("f.description"), c.description)}${fieldRow(t("f.host"), c.dns_hostname)}
      ${fieldRow(t("f.added"), fmtDate(c.added))}
      ${fieldRow(t("f.online"), onlineCell(c), { html: true })}
      ${fieldRow(t("f.uptime"), fmtUptime(c.uptime_s))}${fieldRow(t("f.boot"), fmtDate(i.last_boot))}
      ${fieldRow(t("f.user"), i.logged_on_user)}${fieldRow(t("f.display_name"), i.user_display_name, { sub: true })}
      ${fieldRow(t("f.ip"), i.ip_address || c.ip)}${fieldRow(t("f.mac"), i.mac_address, { mono: true })}${fieldRow(t("f.tz"), i.time_zone)}
      <div class="fsec">${t("cw.os")}</div>
      ${fieldRow(t("f.os"), os)}${fieldRow(t("f.os_name"), i.os_caption || c.os)}${fieldRow(t("f.os_version"), i.os_version || c.os_version)}
      ${fieldRow(t("f.release"), [i.os_display_version, i.os_build ? `(${i.os_build})` : ""].filter(Boolean).join(" ") || (i.os_service_pack ? `SP${i.os_service_pack}` : ""))}
      ${fieldRow(t("f.installed"), fmtDate(i.os_installed))}${fieldRow(t("f.os_serial"), i.os_serial)}${fieldRow(t("f.system_drive"), i.system_drive)}
      ${fieldRow(t("f.arch"), i.os_architecture)}${fieldRow(t("f.ps"), i.powershell_version)}
      ${fieldRow(t("f.smb1s"), i.smb1_server == null ? (c.inventory ? t("v.unknown") : "") : yn(i.smb1_server))}
      ${fieldRow(t("f.smb1c"), i.smb1_client == null ? (c.inventory ? t("v.unknown") : "") : yn(i.smb1_client))}
      ${fieldRow(t("f.ie"), i.ie_version)}${fieldRow(t("f.reboot"), yn(i.pending_reboot))}
    </div><div>
      <div class="fsec">${t("cw.ad")}</div>
      ${fieldRow(t("f.parent"), (c.ou || "").split("/").slice(1).join("/") || c.ou)}${fieldRow(t("f.description"), c.description)}
      ${fieldRow(t("f.domain"), i.domain || (c.ou || "").split("/")[0])}${fieldRow(t("f.dc"), i.domain_controller)}${fieldRow(t("f.location"), c.location)}
      ${fieldRow(t("f.last_logon"), fmtDate(c.last_logon))}${fieldRow(t("f.created"), fmtDate(c.created))}
      ${fieldRow(t("f.account"), c.enabled ? t("v.enabled") : t("v.disabled"))}${fieldRow(t("f.dn"), c.dn, { mono: true })}
      <div class="fsec">${t("cw.system")}</div>
      ${fieldRow(t("f.manufacturer"), i.manufacturer)}${fieldRow(t("f.model"), i.model)}
      ${fieldRow(t("f.memory"), gb(i.memory_gb))}${fieldRow(t("f.cpu"), i.cpu ? `${i.cpu}${i.cpu_cores ? ` (${i.cpu_count > 1 ? i.cpu_count + "× " : ""}${i.cpu_cores} core)` : ""}` : "")}
      ${fieldRow(t("f.chassis"), i.chassis)}${fieldRow(t("f.serial"), i.serial)}${fieldRow(t("f.bios_version"), i.bios_version)}
      ${fieldRow(t("f.bios_manufacturer"), i.bios_manufacturer)}${fieldRow(t("f.asset"), i.bios_asset_tag)}
      ${fieldRow(t("f.family"), i.family)}${fieldRow(t("f.version"), i.product_version)}${fieldRow(t("f.sku"), i.sku)}
      <div class="fsec">${t("cw.updates")}</div>
      ${fieldRow(t("sec.state"), `<span class="${secState(c)[0]}">${esc(secState(c)[1])}</span>`, { html: true })}
      ${fieldRow(t("sec.installed"), c.security?.installed)}${fieldRow(t("sec.latest"), c.security?.latest)}
      ${fieldRow(t("sec.released"), c.security?.released ? `${c.security.released} (${c.security.month})` : "")}
      ${fieldRow(t("f.reboot"), yn(i.pending_reboot))}
      <div class="fsec">${t("cw.scanning")}</div>
      ${fieldRow(t("f.allow_scan"), yesNo(c.allow_scan))}
      ${fieldRow(t("f.success"), c.scan_status !== "failed" || c.inventory ? fmtDate(c.collected_at) : "")}
      ${fieldRow(t("f.attempt"), fmtDate(c.last_scan_attempt))}
      ${fieldRow(t("f.status"), `<span class="${scanStatus(c)[0]}">${esc(scanStatus(c)[1])}</span>`, { html: true })}
      ${c.collect_error ? fieldRow(t("f.error"), c.collect_error, { wrap: true }) : ""}
      ${i.collected_via === "file" ? fieldRow(t("f.via"), t("v.via_file")) : ""}
      ${fieldRow(t("f.reach"), fmtDate(c.scanned_at))}
      ${fieldRow(t("f.ports"), c.open_ports.map((p) => `${p} ${PORTS[p] || ""}`.trim()).join(", "))}
    </div></div>`;
    return;
  }
  const table = (cols, rows, filterable) => {
    const q = cw.filter.trim().toLowerCase();
    const shown = q ? rows.filter((r) => cols.some(([, get]) => String(get(r) ?? "").toLowerCase().includes(q))) : rows;
    return (filterable ? `<div class="subtable-tools"><input class="page-filter" id="cw-filter" type="search" placeholder="${esc(t("cw.filter"))}" value="${esc(cw.filter)}"><span class="faint">${shown.length} / ${rows.length}</span></div>` : `<div style="height:8px"></div>`)
      + (rows.length ? `<div class="grid-wrap"><table class="grid"><thead><tr><th class="rn"></th>${cols.map(([h]) => `<th>${esc(t(h))}</th>`).join("")}</tr></thead><tbody>
        ${shown.map((r) => `<tr><td class="rn"></td>${cols.map(([, get, fmt]) => `<td class="${fmt === "num" ? "num" : ""}">${fmt === "html" ? get(r) : esc(get(r) ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">${esc(t("cw.no_data"))}</div>`);
  };
  const items = c.items || {};
  const cat = cw.cat;
  let html = "";
  if (cat === "ad_groups") html = table([["t.group", (g) => g.split(",")[0].replace(/^CN=/i, "")], ["t.dn", (g) => g]], c.member_of, false);
  else if (cat === "apps") html = table([["t.app", (a) => a.name], ["t.version", (a) => a.version], ["t.publisher", (a) => a.publisher], ["t.installed_on", (a) => (a.installed && /^\d{8}$/.test(a.installed) ? `${a.installed.slice(0, 4)}-${a.installed.slice(4, 6)}-${a.installed.slice(6)}` : a.installed)], ["t.arch", (a) => a.arch]], items.apps || [], true);
  else if (cat === "disks") html = table([["t.drive", (d) => d.drive], ["t.label", (d) => d.label], ["t.fs", (d) => d.file_system], ["t.size", (d) => gb(d.size_gb), "num"], ["t.free", (d) => gb(d.free_gb), "num"],
    ["t.used", (d) => { const p = d.size_gb ? Math.round(100 - (d.free_gb / d.size_gb) * 100) : 0; return `<span class="usage${p > 90 ? " hi" : ""}"><span style="width:${p}%"></span></span>${p}%`; }, "html"]], items.disks || [], false);
  else if (cat === "nics") html = table([["t.adapter", (n) => n.name], ["t.ip", (n) => n.ip], ["t.mac", (n) => n.mac], ["t.gateway", (n) => n.gateway], ["t.dns", (n) => n.dns], ["t.dhcp", (n) => yesNo(n.dhcp)]], items.nics || [], false);
  else if (cat === "hotfixes") html = table([["t.kb", (h) => h.id], ["t.desc", (h) => h.description], ["t.installed_on", (h) => h.installed_on], ["t.installed_by", (h) => h.installed_by]], items.hotfixes || [], true);
  else if (cat === "services") html = table([["t.service", (s) => s.name], ["t.display", (s) => s.display_name], ["t.state", (s) => s.state], ["t.start", (s) => s.start_mode], ["t.account", (s) => s.account]], items.services || [], true);
  else if (cat === "local_admins") html = table([["t.member", (m) => m.name], ["t.type", (m) => m.type], ["t.source", (m) => m.source]], items.local_admins || [], false);
  else if (cat === "logons") html = table([["t.time", (l) => fmtDate(l.time)], ["t.account", (l) => (l.domain ? `${l.domain}\\${l.user}` : l.user)], ["t.logon_type", (l) => t("lt." + l.type)], ["t.source_ip", (l) => l.ip]], items.logons || [], true);
  else if (cat === "ports") html = table([["t.port", (p) => p], ["t.service_name", (p) => PORTS[p] || ""]], c.open_ports, false);
  else if (cat === "collections") html = c.fleets.length ? `<div style="padding:10px 0;display:flex;flex-direction:column;gap:6px">${c.fleets.map((f) => `<a href="#" data-goto="f:${f.id}">${icon("coll_dyn", 16)} ${esc(f.name)}</a>`).join("")}</div>` : `<div class="empty">${esc(t("tree.none"))}</div>`;
  else if (cat === "tags") {
    html = `<div style="padding:10px 0" class="stack"><div>${c.tags.map((x) => `<span class="chip">${esc(x)} <a href="#" data-untag="${esc(x)}">×</a></span>`).join("") || `<span class="muted">${t("tag.none")}</span>`}</div>
      <form id="cw-tagform" style="display:flex;gap:6px;margin-top:10px"><input class="page-filter" id="cw-newtag" placeholder="${esc(t("tag.add"))}" list="cw-taglist"><datalist id="cw-taglist">${S.tags.map((x) => `<option value="${esc(x.tag)}">`).join("")}</datalist><button class="btn">${t("d.add")}</button></form></div>`;
  }
  el.innerHTML = html;
  const f = $("#cw-filter");
  if (f) {
    f.oninput = (e) => { cw.filter = e.target.value; const pos = e.target.selectionStart; renderCwContent(); const nf = $("#cw-filter"); nf.focus(); nf.setSelectionRange(pos, pos); };
  }
  $$("[data-goto]", el).forEach((a) => (a.onclick = (e) => { e.preventDefault(); if (S.cw) S.cw.back = null; closeComputer(); selectNode(a.dataset.goto); }));
  const retag = (body) => guard(async () => { await api("POST", "/api/tags", { ids: [c.guid], ...body }); await reload(); loadComputer(); });
  $$("[data-untag]", el).forEach((a) => (a.onclick = (e) => { e.preventDefault(); retag({ remove: [a.dataset.untag] }); }));
  const tf = $("#cw-tagform");
  if (tf) tf.onsubmit = (e) => { e.preventDefault(); const v = $("#cw-newtag").value.trim(); if (v) retag({ add: [v] }); };
}

function bindComputerWindow() {
  $("#cwin").addEventListener("click", (e) => {
    if (e.target.id === "cwin") return closeComputer();
    const b = e.target.closest("[data-cw]");
    if (b && !b.disabled) {
      const c = S.cw?.data;
      ({
        close: closeComputer, prev: () => cwStep(-1), next: () => cwStep(1),
        scan: () => startJob("full", { ids: [c.guid] }), ping: () => startJob("scan", { ids: [c.guid] }),
        allow: () => setAllowScan([c.guid], !c.allow_scan),
        ra: () => guard(() => window.pywebview.api.remote_assist(c.name)),
        copy: async () => { await copyText(c.dns_hostname || c.name); toast(tText("copied", { n: 1 })); },
      })[b.dataset.cw]?.();
      return;
    }
    const cat = e.target.closest("[data-cat]");
    if (cat) { S.cw.cat = cat.dataset.cat; S.cw.filter = ""; renderComputer(); }
  });
}


/* The advised NTFS permissions of a drop folder every computer writes into (ADmiral refuses an unsafe one). */
function shareAclBox() {
  const items = t("s.acl_items").split("\n").map((x) => `<li>${esc(x)}</li>`).join("");
  return `<div class="callout" style="margin:6px 0">${icon("info", 16)} <b>${esc(t("s.acl_title"))}</b><ul style="margin:4px 0 0 18px;padding:0">${items}</ul></div>`;
}

/* ================================================================== dialogs */
const LINK_SITE = "https://tidecrestlabs.com/", LINK_DISCORD = "https://discord.gg/E6ZDEnqSmY", LINK_KOFI = "https://ko-fi.com/tidecrestlabs";
function openUrl(url) {
  if (isDesktop() && window.pywebview.api.open_url) return window.pywebview.api.open_url(url);
  window.open(url, "_blank", "noopener,noreferrer");
}
function bindLinks(root) { $$("[data-url]", root).forEach((a) => (a.onclick = (e) => { e.preventDefault(); openUrl(a.dataset.url); })); }

function dialog(title, body, buttons) {
  const layer = $("#dlg");
  const box = $(".dlg", layer);
  box.innerHTML = `<div class="dlg-title"><span>${esc(title)}</span><button class="cwin-x" data-dclose aria-label="Close">✕</button></div>
    <div class="dlg-body">${body}</div><div class="dlg-foot">${buttons || `<button class="btn" data-dclose>${t("d.close")}</button>`}</div>`;
  box.style.width = "";                                    // a dialog may widen itself; the next one starts normal
  layer.hidden = false;
  $$("[data-dclose]", box).forEach((b) => (b.onclick = closeDialog));
  setTimeout(() => box.querySelector("input:not([type=checkbox]),select,textarea")?.focus(), 30);
  return box;
}
function closeDialog() { $("#dlg").hidden = true; }

/* Own confirmation window (instead of the browser's confirm()); a separate layer, so it can open on top of
   another dialog. Resolves true on OK / Enter, false on Cancel / Esc / click outside.
   opts.safe: a risky choice - Cancel has the focus and Enter means Cancel, so only a click on OK accepts. */
function confirmDialog(text, opts = {}) {
  return new Promise((resolve) => {
    const layer = document.createElement("div");
    layer.className = "dlg-layer cfm-layer";
    layer.innerHTML = `<div class="dlg cfm" role="alertdialog" aria-modal="true">
      <div class="dlg-title"><span>${esc(opts.title || "ADmiral")}</span></div>
      <div class="dlg-body"><div style="white-space:pre-line">${esc(text)}</div></div>
      <div class="dlg-foot"><button class="btn" data-no type="button">${esc(opts.no || t("d.cancel"))}</button>
      <button class="btn primary" data-yes type="button">${esc(opts.yes || t("d.ok"))}</button></div></div>`;
    const done = (v) => { document.removeEventListener("keydown", onKey, true); layer.remove(); resolve(v); };
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); done(false); }
      else if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); done(!opts.safe); }
    };
    layer.querySelector("[data-no]").onclick = () => done(false);
    layer.querySelector("[data-yes]").onclick = () => done(true);
    layer.addEventListener("mousedown", (e) => { if (e.target === layer) done(false); });
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(layer);
    layer.querySelector(opts.safe ? "[data-no]" : "[data-yes]").focus();
  });
}

function aboutDialog() {
  dialog(t("m.about"), `<div style="display:flex;gap:14px;align-items:center"><img src="/static/logo.svg" width="96" height="96" alt="">
    <div><div style="font-size:18px">ADmiral ${esc(S.status?.version || "")}</div><div class="muted">${esc(t("about.text"))}</div>
    ${S.status?.mode === "demo" ? `<div class="faint" style="margin-top:6px">${esc(t("sb.demo"))}</div>` : ""}
    <div style="margin-top:8px">${esc(t("about.author"))} <a href="${LINK_SITE}" data-url="${LINK_SITE}">TidecrestLabs</a></div></div></div>`);
  bindLinks($("#dlg"));
}
function supportDialog() {
  const box = dialog(t("sup.title"), `<div style="text-align:center"><img src="/static/kofi.svg" width="120" height="120" alt="Ko-fi">
    <p style="margin:12px 0 0">${esc(t("sup.text"))}</p></div>`,
    `<button class="btn" data-dclose>${esc(t("d.close"))}</button><button class="btn primary" id="sup-go" type="button">${esc(t("sup.btn"))}</button>`);
  $("#sup-go", box).onclick = () => { openUrl(LINK_KOFI); closeDialog(); };
}

function shortcutsDialog() {
  dialog(t("keys.title"), `<table class="grid"><tbody>${t("keys.list").split("|").map((l) => { const [k, v] = l.split(" – "); return `<tr><td><b>${esc(k)}</b></td><td>${esc(v)}</td></tr>`; }).join("")}</tbody></table>`);
}

function columnsDialog() {
  const vis = new Set((S.cols || DEFAULT_COLS));
  const box = dialog(t("cols.title"), `<div class="picklist">${COLUMNS.map((c) => `<label><input type="checkbox" value="${c.id}" ${vis.has(c.id) ? "checked" : ""} ${c.id === "name" ? "disabled" : ""}> ${esc(t("col." + c.id))}</label>`).join("")}</div>`,
    `<button class="btn" data-reset>${t("cols.reset")}</button><span style="flex:1"></span><button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" data-ok>${t("d.ok")}</button>`);
  box.querySelector("[data-reset]").onclick = () => { S.cols = null; store.set("cols", null); closeDialog(); drawGrid(); };
  box.querySelector("[data-ok]").onclick = () => {
    const checked = new Set($$(".picklist input:checked", box).map((i) => i.value));
    S.cols = COLUMNS.map((c) => c.id).filter((id) => id === "name" || checked.has(id));
    store.set("cols", S.cols);
    closeDialog();
    drawGrid();
  };
}

function tagDialog(add) {
  const ids = [...S.sel];
  if (!ids.length) return toast(t("need_selection"), true);
  const box = dialog(add ? t("tag.add_title") : t("tag.remove_title"),
    `<label class="fld"><span>${t("tag.name")} · ${t("sb.selected", { n: ids.length })}</span><input id="tg" list="tg-list"><datalist id="tg-list">${S.tags.map((x) => `<option value="${esc(x.tag)}">`).join("")}</datalist></label>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" data-ok>${add ? t("d.add") : t("d.remove")}</button>`);
  const go = () => guard(async () => {
    const tag = $("#tg", box).value.trim();
    if (!tag) return;
    await api("POST", "/api/tags", add ? { ids, add: [tag] } : { ids, remove: [tag] });
    closeDialog();
    toast(tText("tag.done", { n: ids.length }));
    await reload();
  });
  box.querySelector("[data-ok]").onclick = go;
  $("#tg", box).onkeydown = (e) => { if (e.key === "Enter") go(); };
}

function addToCollectionDialog() {
  const ids = [...S.sel];
  if (!ids.length) return toast(t("need_selection"), true);
  const statics = S.fleets.filter((f) => f.kind === "static");
  if (!statics.length) {
    return dialog(t("m.add_to_coll").replace("…", ""), `<div class="callout">${esc(t("coll.no_static"))}</div>`,
      `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" data-new>${esc(t("m.new_stat").replace("…", ""))}</button>`)
      .querySelector("[data-new]").onclick = () => { closeDialog(); ACTIONS["new-stat"](); };
  }
  const box = dialog(t("m.add_to_coll").replace("…", ""), `<label class="fld"><span>${t("coll.pick")} · ${t("sb.selected", { n: ids.length })}</span>
    <select id="ac">${statics.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("")}</select></label>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" data-ok>${t("d.add")}</button>`);
  box.querySelector("[data-ok]").onclick = () => guard(async () => {
    await api("POST", `/api/fleets/${encodeURIComponent($("#ac", box).value)}/members`, { add: ids });
    closeDialog();
    toast(tText("coll.added", { n: ids.length }));
    await reload();
  });
}

function exportDialog() {
  const fleet = currentFleet();
  const rows = S.sel.size ? selectedComputers() : S.list;
  const formats = fleet ? Object.keys(S.status.export_formats) : ["txt", "csv"];
  const title = fleet && !S.sel.size ? fleet.name : (S.sel.size ? t("exp.selection") : (findNode(S.treeNodes, S.node)?.label || ""));
  const box = dialog(tText("exp.title", { name: title }), `
    <label class="fld"><span>${t("exp.format")}</span><select id="ex-fmt">${formats.map((f) => `<option value="${f}">${esc(t("fmt." + f))}</option>`).join("")}</select></label>
    <label class="chk"><input type="checkbox" id="ex-online"> ${t("exp.online")}</label>`,
    `<button class="btn" data-copy>${t("d.copy")}</button><button class="btn primary" data-save>${t("d.download")}</button>`);
  const build = async () => {
    const fmt = $("#ex-fmt", box).value, online = $("#ex-online", box).checked;
    if (fleet && !S.sel.size) {
      const data = await api("GET", `/api/fleets/${fleet.id}/export?format=${fmt}&online_only=${online}`);
      return [typeof data === "string" ? data : JSON.stringify(data, null, 2), `${fleet.name.replace(/[^\w-]/g, "_")}.${fmt === "ansible" ? "ini" : fmt}`];
    }
    const list = online ? rows.filter((c) => c.online) : rows;
    const host = (c) => c.dns_hostname || c.name;
    if (fmt === "txt") return [list.map(host).join("\r\n") + "\r\n", "computers.txt"];
    const cols = visibleCols();
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const csv = [cols.map((c) => q(t("col." + c.id))).join(";")].concat(list.map((c) => cols.map((col) => {
      const tmp = document.createElement("div"); tmp.innerHTML = col.html ? col.html(c) : esc(col.get(c)); return q(tmp.textContent);
    }).join(";"))).join("\r\n");
    return ["\ufeff" + csv + "\r\n", "computers.csv"];
  };
  box.querySelector("[data-save]").onclick = () => guard(async () => { const [text, name] = await build(); await saveText(name, text); closeDialog(); });
  box.querySelector("[data-copy]").onclick = () => guard(async () => { const [text] = await build(); await copyText(text); toast(t("exp.copied")); });
}

// READ-ONLY: compares the collection with the AD group's current members. ADmiral never
// changes Active Directory; the lists can be copied for the admin's own tools.
function groupCompareDialog(fleet) {
  if (!fleet.ad_group_dn) {
    return dialog(tText("gs.title", { name: fleet.name }), `<div class="callout">${esc(t("gs.no_group"))}</div>`,
      `<button class="btn" data-dclose>${t("d.close")}</button><button class="btn primary" data-edit>${t("page.edit")}</button>`)
      .querySelector("[data-edit]").onclick = () => { closeDialog(); fleetEditor(fleet, {}); };
  }
  const box = dialog(tText("gs.title", { name: fleet.name }), `
    <div class="mono" style="overflow-wrap:anywhere">${esc(fleet.ad_group_dn)}</div>
    <div class="callout">${icon("info", 16)} ${esc(t("gs.readonly"))}</div>
    <div id="gs-plan"><div class="faint">…</div></div>`,
    `<button class="btn" id="gs-refresh">${icon("refresh", 16)}${t("m.refresh")}</button><span style="flex:1"></span><button class="btn" data-dclose>${t("d.close")}</button>`);
  const load = () => guard(async () => {
    const r = await api("GET", `/api/fleets/${fleet.id}/group-compare`);
    const list = (items, cls, key) => `<div><b>${esc(tText(key, { n: items.length }))}</b>
      ${items.length ? `<button class="btn" style="margin-left:8px;padding:1px 8px" data-copy="${cls}" title="${esc(t("tb.copy"))}">${icon("copy", 14)}</button><ul>${items.map((x) => `<li class="${cls}">${esc(x.name)}</li>`).join("")}</ul>` : `<div class="faint">${t("gs.none")}</div>`}</div>`;
    $("#gs-plan", box).innerHTML = `<div class="plan">${list(r.missing, "rem", "gs.missing")}${list(r.extra, "add", "gs.extra")}</div>
      <div class="faint" style="margin-top:8px">${esc(tText("gs.matching", { n: r.matching }))}${r.other_members.length ? " · " + esc(tText("gs.other", { n: r.other_members.length })) : ""}</div>
      ${!r.missing.length && !r.extra.length ? `<div class="callout" style="margin-top:8px">${esc(t("gs.in_sync"))}</div>` : ""}`;
    $$("[data-copy]", box).forEach((b) => (b.onclick = async () => {
      const items = b.dataset.copy === "rem" ? r.missing : r.extra;
      await copyText(items.map((x) => x.name).join("\r\n"));
      toast(tText("copied", { n: items.length }));
    }));
  });
  $("#gs-refresh", box).onclick = load;
  load();
}

function fleetEditor(fleet, preset) {
  const isNew = !fleet;
  const schema = S.status.rules;
  let kind = fleet?.kind || preset.kind || "dynamic";
  let match = fleet?.rules?.match || "all";
  const conds = fleet?.rules?.conditions?.map((c) => ({ ...c })) || [{ field: "ou", op: "contains", value: "" }];
  const box = dialog(isNew ? t("coll.new") : tText("coll.edit", { name: fleet.name }), `
    <div class="grid2"><label class="fld"><span>${t("coll.name")}</span><input id="fe-name" value="${esc(fleet?.name || "")}"></label>
      <label class="fld"><span>${t("coll.desc")}</span><input id="fe-desc" value="${esc(fleet?.description || "")}"></label></div>
    <label class="fld"><span>${t("coll.group")}</span><input id="fe-group" class="mono" value="${esc(fleet?.ad_group_dn || "")}" placeholder="CN=Deploy-Office-Pilot,OU=Groups,DC=corp,DC=local"></label>
    ${isNew ? `<div class="chk"><span class="muted">${t("coll.type")}</span><div class="seg" id="fe-kind"><button type="button" data-kind="dynamic">${t("coll.type_dyn")}</button><button type="button" data-kind="static">${t("coll.type_stat")}</button></div></div>` : ""}
    <div id="fe-body"></div>`, `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="fe-save">${isNew ? t("d.create") : t("d.save")}</button>`);

  const fdef = (f) => schema.fields.find((x) => x.field === f);
  const fieldLabel = (f) => { const k = "r.field." + f; const s = t(k); return s === k ? fdef(f)?.label || f : s; };
  const opLabel = (o) => { const k = "r.op." + o; const s = t(k); return s === k ? o : s; };
  const opsFor = (f) => schema.ops[fdef(f).type];
  let pt;
  const preview = () => {
    clearTimeout(pt);
    pt = setTimeout(async () => {
      const el = $("#fe-preview", box);
      if (!el) return;
      if (conds.some((c) => !schema.no_value_ops.includes(c.op) && String(c.value ?? "").trim() === "")) {
        el.innerHTML = `<span class="faint">${esc(t("r.value"))}…</span>`;
        return;
      }
      try {
        const r = await api("POST", "/api/fleets/preview", { match, conditions: conds });
        el.innerHTML = t("coll.preview", { n: r.count, o: r.online }) + (r.sample.length ? `<div class="faint" style="margin-top:4px">${r.sample.map(esc).join(", ")}${r.count > r.sample.length ? "…" : ""}</div>` : "");
      } catch (e) { el.innerHTML = `<span class="faint">${esc(e.message)}</span>`; }
    }, 220);
  };
  const valueInput = (c, i) => {
    if (schema.no_value_ops.includes(c.op)) return `<span></span>`;
    const type = fdef(c.field).type;
    if (type === "bool") return `<select data-i="${i}" data-k="value"><option value="true" ${String(c.value) !== "false" ? "selected" : ""}>${t("v.yes")}</option><option value="false" ${String(c.value) === "false" ? "selected" : ""}>${t("v.no")}</option></select>`;
    const list = { tag: "fe-tags", os: "fe-oses", ou: "fe-ous", manufacturer: "fe-mfr", model: "fe-models" }[c.field];
    return `<input data-i="${i}" data-k="value" value="${esc(c.value ?? "")}" ${type === "number" ? 'type="number"' : ""} ${list ? `list="${list}"` : ""} placeholder="${esc(t("r.value"))}">`;
  };
  const uniq = (fn) => [...new Set(S.computers.map(fn).filter(Boolean))].sort();
  const draw = () => {
    $$("#fe-kind button", box).forEach((b) => b.classList.toggle("on", b.dataset.kind === kind));
    const body = $("#fe-body", box);
    if (kind === "static") {
      body.innerHTML = isNew ? `<label class="fld"><span>${t("coll.members")}</span><textarea id="fe-members" rows="7" class="mono">${esc((preset.members || []).join("\n"))}</textarea></label>` : `<div class="muted">${t("coll.members_later")}</div>`;
      return;
    }
    body.innerHTML = `<div class="chk"><span class="muted">${t("coll.match")}</span><div class="seg" id="fe-match"><button type="button" data-m="all" class="${match === "all" ? "on" : ""}">${t("coll.match_all")}</button><button type="button" data-m="any" class="${match === "any" ? "on" : ""}">${t("coll.match_any")}</button></div></div>
      ${conds.map((c, i) => `<div class="rule"><select data-i="${i}" data-k="field">${schema.fields.map((f) => `<option value="${esc(f.field)}" ${f.field === c.field ? "selected" : ""}>${esc(fieldLabel(f.field))}</option>`).join("")}</select>
        <select data-i="${i}" data-k="op">${opsFor(c.field).map((o) => `<option value="${esc(o)}" ${o === c.op ? "selected" : ""}>${esc(opLabel(o))}</option>`).join("")}</select>
        ${valueInput(c, i)}<button type="button" class="btn" data-rm="${i}" ${conds.length === 1 ? "disabled" : ""} aria-label="Remove">✕</button></div>`).join("")}
      <div><button type="button" class="btn" id="fe-add">${t("coll.add_cond")}</button></div>
      <datalist id="fe-tags">${S.tags.map((x) => `<option value="${esc(x.tag)}">`).join("")}</datalist>
      <datalist id="fe-oses">${uniq((c) => c.os).map((o) => `<option value="${esc(o)}">`).join("")}</datalist>
      <datalist id="fe-ous">${uniq((c) => c.ou).map((o) => `<option value="${esc(o)}">`).join("")}</datalist>
      <datalist id="fe-mfr">${uniq((c) => inv(c, "manufacturer")).map((o) => `<option value="${esc(o)}">`).join("")}</datalist>
      <datalist id="fe-models">${uniq((c) => inv(c, "model")).map((o) => `<option value="${esc(o)}">`).join("")}</datalist>
      <div class="preview" id="fe-preview">…</div><div class="faint">${esc(t("coll.hint"))}</div>`;
    preview();
  };
  draw();
  box.addEventListener("click", (e) => {
    const d = e.target.dataset;
    if (d.kind) { kind = d.kind; draw(); }
    if (d.m) { match = d.m; draw(); }
    if (e.target.id === "fe-add") { conds.push({ field: "name", op: "glob", value: "" }); draw(); }
    if (d.rm) { conds.splice(Number(d.rm), 1); draw(); }
  });
  const onEdit = (e) => {
    const { i, k } = e.target.dataset;
    if (i === undefined) return;
    const c = conds[Number(i)];
    c[k] = e.target.value;
    if (k === "field") { const ops = opsFor(c.field); if (!ops.includes(c.op)) c.op = ops[0]; c.value = fdef(c.field).type === "bool" ? "true" : ""; draw(); }
    else if (k === "op") draw();
    else preview();
  };
  box.addEventListener("change", onEdit);
  box.addEventListener("input", (e) => { if (e.target.dataset.k === "value") onEdit(e); });
  $("#fe-save", box).onclick = () => guard(async () => {
    const body = { name: $("#fe-name", box).value, description: $("#fe-desc", box).value, ad_group_dn: $("#fe-group", box).value };
    if (kind === "dynamic") body.rules = { match, conditions: conds };
    let saved;
    if (isNew) {
      body.kind = kind;
      if (kind === "static") body.members = ($("#fe-members", box)?.value || "").split(/[\s,;]+/).filter(Boolean);
      saved = await api("POST", "/api/fleets", body);
    } else saved = await api("PUT", `/api/fleets/${fleet.id}`, body);
    closeDialog();
    toast(isNew ? tText("coll.created", { name: saved.name }) : t("coll.saved"));
    await guard(loadAll);
    selectNode("f:" + saved.id);
  });
}

/* ================================================================== settings page */
// Left column of the Settings page: quick jumps to the categories (built from the rendered sections).
function settingsNav() {
  const host = $("#settings");
  const items = $$(".section, .fsec", host).map((el, i) => {
    el.id = "ssec-" + i;
    const sub = el.classList.contains("fsec");
    const label = (sub ? el.textContent : (el.querySelector("h3")?.childNodes[0]?.textContent || "")).trim();
    return { id: el.id, label, sub, bottom: el.classList.contains("pin-bottom") };
  });
  const tree = $("#tree");
  tree.innerHTML = `<div class="snav-col">${items.map((it) => `<div class="tn snav${it.sub ? " sub" : ""}${it.bottom ? " bottom" : ""}" data-snav="${it.id}" role="treeitem"><span class="lbl">${esc(it.label)}</span></div>`).join("")}</div>`;
  const mark = (id) => $$(".snav", tree).forEach((n) => n.classList.toggle("sel", n.dataset.snav === id));
  tree.onclick = (e) => {
    const n = e.target.closest("[data-snav]");
    if (!n) return;
    const target = document.getElementById(n.dataset.snav);
    if (target) { target.scrollIntoView({ block: "start", behavior: "smooth" }); mark(n.dataset.snav); }
  };
  host.onscroll = () => {                                 // highlight the category being read
    const top = host.getBoundingClientRect().top + 12;
    let cur = items[0]?.id;
    for (const it of items) if (document.getElementById(it.id).getBoundingClientRect().top <= top) cur = it.id;
    mark(cur);
  };
  mark(items[0]?.id);
}

function renderSettings(el) {
  el.innerHTML = pageHead("settings", t("tree.settings"), "", `<span class="st-actions" id="st-actions"></span>`) + `<div class="settings" id="settings"><div class="empty">…</div></div>`;
  $("#tree").innerHTML = "";
  updateStatus();
  guard(async () => {
    const cfg = await api("GET", "/api/settings");
    const ro = cfg.editable ? "" : "disabled";
    const inp = (id, label, value, extra = "") => `<label class="fld"><span>${esc(label)}</span><input id="${id}" value="${esc(value ?? "")}" ${extra} ${ro}></label>`;
    const chk = (id, label, on) => `<label class="chk"><input type="checkbox" id="${id}" ${on ? "checked" : ""} ${ro}> ${esc(label)}</label>`;
    const pw = (id, label, isSet) => `<label class="fld"><span>${esc(label)}</span><input id="${id}" type="password" autocomplete="new-password" placeholder="${esc(isSet ? t("s.pw_saved") : t("s.pw_none"))}" ${ro}></label>`;
    const sel = (id, label, value, opts) => `<label class="fld"><span>${esc(label)}</span><select id="${id}" ${ro}>${opts.map(([v, l]) => `<option value="${v}" ${v === value ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>`;
    $("#settings").innerHTML = `
      ${cfg.editable ? "" : `<div class="callout">${esc(t("s.readonly"))}</div>`}
      <div class="section"><h3>${t("s.appearance")}</h3><div class="in grid3">
        ${sel("st-lang", t("s.language"), cfg.language, [["hu", "Magyar"], ["en", "English"]])}
        ${sel("st-theme", t("s.theme"), cfg.theme, [["system", t("m.theme_system")], ["light", t("m.theme_light")], ["dark", t("m.theme_dark")]])}
      </div></div>
      <div class="section"><h3>${t("s.directory")}</h3>
        <div class="in" id="st-ldap">
          <div class="grid3">
            ${inp("ldap-server", t("s.dc"), cfg.ldap.server, 'placeholder="dc01.corp.local"')}
            ${inp("ldap-base", t("s.base"), cfg.ldap.base_dn, 'placeholder="DC=corp,DC=local" class="mono"')}
            ${inp("ldap-port", t("s.port"), cfg.ldap.port, 'type="number" min="0" max="65535"')}
            ${sel("ldap-auth", t("s.ldap_auth"), cfg.ldap.auth, [["kerberos", t("s.auth_kerberos")], ["simple", t("s.auth_simple")]])}
            ${inp("ldap-user", t("s.bind"), cfg.ldap.user, 'placeholder="CORP\\svc-admiral"')}
            ${pw("ldap-pw", t("s.bind_pw"), cfg.ldap.password_set)}
            ${inp("ldap-filter", t("s.filter"), cfg.ldap.search_filter, 'class="mono"')}
          </div>
          <div class="chk" style="gap:18px;flex-wrap:wrap">${chk("ldap-ssl", t("s.ldaps"), cfg.ldap.use_ssl)}${chk("ldap-verify", t("s.verify"), cfg.ldap.verify_cert)}${chk("ldap-ntlm", t("s.ntlm_fb"), cfg.ldap.ntlm_fallback)}</div>
          ${inp("ldap-ca", t("s.ca"), cfg.ldap.ca_file, 'placeholder="C:\\certs\\corp-root.pem"')}
          <div class="chk"><button class="btn" id="st-test" type="button">${icon("ping", 16)}${t("s.test")}</button><span id="st-test-out" class="muted"></span></div>
          <div class="faint">${esc(t("s.ad_hint"))}</div>
        </div></div>
      <div class="section"><h3>${t("s.collect")}</h3><div class="in"><div class="grid2">
          ${sel("collect-method", t("s.collect_method"), cfg.collect.method, [["pdq", t("s.collect_pdq")], ["winrm", "WinRM"]])}
          ${inp("collect-timeout", t("s.collect_timeout"), cfg.collect.smb_timeout, 'type="number" min="5" max="600"')}
          ${inp("collect-response", t("s.collect_response"), cfg.collect.response_timeout, 'type="number" min="5" max="3600"')}
          ${inp("collect-delay", t("s.collect_delay"), cfg.collect.cleanup_delay, 'type="number" min="0" max="600"')}
        </div><div class="chk" style="gap:18px">${chk("collect-fb", t("s.collect_fb"), cfg.collect.winrm_fallback)}</div><div class="faint">${esc(t("s.collect_hint"))}</div></div></div>
      <div class="section"><h3>${t("s.winrm")}</h3><div class="in"><div class="grid2">
          ${inp("winrm-user", t("s.winrm_user"), cfg.winrm.user, 'placeholder="CORP\\svc-admiral"')}
          ${pw("winrm-pw", t("s.bind_pw"), cfg.winrm.password_set)}
          ${sel("winrm-transport", t("s.auth"), cfg.winrm.transport, [["kerberos", t("s.auth_kerberos")], ["ntlm", "NTLM"], ["credssp", "CredSSP"], ["basic", "Basic"]])}
          ${inp("winrm-workers", t("s.parallel"), cfg.winrm.workers, 'type="number" min="1" max="128"')}
        </div><div class="chk" style="gap:18px">${chk("winrm-https", t("s.https"), cfg.winrm.use_https)}${chk("winrm-verify", t("s.verify"), cfg.winrm.verify_cert)}${chk("winrm-ntlm", t("s.ntlm_fb"), cfg.winrm.ntlm_fallback)}</div><div class="faint">${esc(t("s.auth_hint"))}</div></div></div>
      <div class="section"><h3>${t("s.scanning")}</h3><div class="in grid2">
          ${inp("scan-ports", t("s.ports"), cfg.scan.ports.join(", "), 'class="mono"')}
          ${inp("scan-timeout", t("s.timeout"), cfg.scan.timeout, 'type="number" step="0.1" min="0.1"')}
          ${inp("scan-workers", t("s.probes"), cfg.scan.workers, 'type="number" min="1" max="512"')}
          ${inp("scan-interval", t("s.ping_interval"), cfg.scan.interval_minutes, 'type="number" min="0" max="1440"')}
          <div class="faint" style="grid-column:1/-1">${esc(t("s.ping_hint"))}</div>
          ${inp("stale-days", t("s.stale"), cfg.stale_days, 'type="number" min="1"')}
      </div></div>
      <div class="section"><h3>${t("s.vulns")}</h3><div class="in">
          <div class="chk" style="gap:18px">${chk("vuln-enabled", t("s.vuln_enabled"), cfg.vulns.enabled)}</div>
          <div class="grid2">
            ${inp("vuln-days", t("s.vuln_days"), cfg.vulns.refresh_days, 'type="number" min="1" max="90"')}
            ${pw("vuln-key", t("s.vuln_key"), cfg.vulns.api_key_set)}
          </div>
          <div class="faint">${esc(t("s.vuln_hint"))}</div>
          <div class="chk" style="gap:10px;margin-top:6px"><button class="btn" id="vuln-run" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.vuln_run"))}</button></div>
        </div></div>
      <div class="section"><h3>${t("s.packages")}</h3><div class="in">
          ${inp("pk-folder", t("s.pk_folder"), cfg.packages.folder, 'class="mono" placeholder="D:\\ADmiral\\packages"')}
          <div class="faint">${esc(t("s.pk_hint"))}</div>
        </div></div>
      <div class="section"><h3>${t("s.deploy")}</h3><div class="in">
          ${inp("dep-timeout", t("s.dep_timeout"), cfg.deploy.timeout_minutes, 'type="number" min="1" max="1440"')}
          <div class="faint">${esc(t("s.dep_hint"))}</div>
        </div></div>
      <div class="section"><h3>${t("s.offline")}</h3><div class="in">
          ${inp("off-inbox", t("s.off_inbox"), cfg.filecollect.inbox, 'class="mono" placeholder="\\\\server\\admiral-inbox"')}
          <div class="faint">${esc(t("s.off_hint"))}</div>
          ${shareAclBox()}
          <div class="chk" style="gap:18px">${chk("off-users", t("s.off_users"), cfg.filecollect.offline_allow_users)}</div>
          <div class="faint">${esc(t("s.off_users_hint"))}</div>
          <div id="off-out" class="faint" style="margin:6px 0"></div>
          <div class="chk" style="gap:10px"><button class="btn" id="off-run" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.off_run"))}</button><button class="btn" id="off-script" type="button">${esc(t("s.off_script"))}</button></div>
        </div></div>
      <div class="section"><h3>${t("s.logins")}</h3><div class="in">
          <div class="chk" style="gap:18px">${chk("lg-track", t("s.lg_enabled"), cfg.logins.enabled)}</div>
          <div class="grid2">
            ${inp("lg-path", t("s.lg_path"), cfg.logins.path, 'class="mono" placeholder="\\\\server\\logins$"')}
            ${inp("lg-interval", t("s.lg_interval"), cfg.logins.interval_minutes, 'type="number" min="1" max="1440"')}
          </div>
          <div class="faint">${esc(t("s.lg_hint"))}</div>
          ${shareAclBox()}
          <div id="lg-out" class="faint" style="margin:6px 0"></div>
          <div class="chk" style="gap:10px"><button class="btn" id="lg-run" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.lg_run"))}</button><button class="btn" id="lg-script" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.lg_script"))}</button></div>
        </div></div>
      <div class="section"><h3>${t("s.updates")}</h3><div class="in">
          <div class="chk" style="gap:18px">${chk("upd-enabled", t("s.upd_enabled"), cfg.updates.enabled)}</div>
          <div class="grid2">
            ${inp("upd-hours", t("s.upd_hours"), cfg.updates.refresh_hours, 'type="number" min="1" max="720"')}
            ${inp("upd-grace", t("s.upd_grace"), cfg.updates.grace_days, 'type="number" min="0" max="90"')}
          </div>
          <div class="faint">${esc(t("s.upd_hint"))}</div>
          <div id="upd-status" class="faint" style="margin:6px 0"></div>
          <div class="chk" style="gap:10px"><button class="btn" id="upd-run" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.upd_run"))}</button></div>
        </div></div>
      <div class="section"><h3>${t("s.proxy")}</h3><div class="in">
          <div class="grid2">
            ${inp("proxy-url", t("s.proxy_url"), cfg.proxy.url, 'placeholder="http://proxy.corp.local:8080"')}
            ${inp("proxy-pac", t("s.proxy_pac"), cfg.proxy.pac || "", 'placeholder="C:\\wpad.dat / http://wpad/wpad.dat / auto"')}
            ${inp("proxy-user", t("s.proxy_user"), cfg.proxy.user, 'autocomplete="off"')}
            ${pw("proxy-pw", t("s.proxy_pw"), cfg.proxy.password_set)}
          </div>
          <div class="faint">${esc(t("s.proxy_hint"))}</div>
          <div class="chk">${chk("proxy-untrusted-pac", t("s.proxy_untrusted_pac"), cfg.proxy.allow_untrusted_pac)}</div>
          <div class="chk" style="gap:10px"><button class="btn" id="proxy-test" type="button" ${cfg.editable ? "" : "disabled"}>${icon("ping", 16)}${esc(t("s.proxy_test"))}</button></div>
          <div id="proxy-test-out" class="muted" style="white-space:pre-line"></div>
        </div></div>
      <div class="section"><h3>${t("s.retry")}</h3><div class="in">
          <div class="grid2">${inp("retry-interval", t("s.retry_interval"), cfg.retry.interval_minutes, 'type="number" min="1" max="1440"')}</div>
          <div class="chk" style="gap:18px">${chk("retry-offline", t("s.retry_offline"), cfg.retry.offline)}${chk("retry-failed", t("s.retry_failed"), cfg.retry.failed)}</div>
          <div class="faint">${esc(t("s.retry_hint"))}</div>
          <div id="svc-status" style="margin:6px 0"></div>
          <div class="grid2" id="svc-install-fields" hidden>
            ${inp("svc-account", t("s.svc_account"), "", 'placeholder="CORP\\svc-admiral" autocomplete="off"')}
            ${pw("svc-pw", t("s.svc_pw"), false)}
          </div>
          <div class="chk" style="gap:10px" id="svc-buttons"></div>
        </div></div>
      <div class="section"><h3>${t("s.sync")}</h3><div class="in">
          <div class="chk" style="gap:18px">${chk("sy-enabled", t("s.sy_enabled"), cfg.sync.enabled)}</div>
          <div class="grid2">
            ${inp("sy-peer", t("s.sy_peer"), cfg.sync.peer, 'placeholder="10.1.2.3, pc02:8766, pc03"')}
            ${inp("sy-port", t("s.sy_port"), cfg.sync.port, 'type="number" min="1" max="65535"')}
            ${inp("sy-net", t("s.sy_net"), cfg.sync.network, 'class="mono" placeholder="10.1.2.0/24"')}
            ${inp("sy-interval", t("s.sy_interval"), cfg.sync.interval_minutes, 'type="number" min="0" max="1440"')}
            ${pw("sy-key", t("s.sy_key"), cfg.sync.key_set)}
          </div>
          <div class="chk" style="gap:18px;flex-wrap:wrap">${["computers", "fleets", "users", "printers"].map((c) => chk("sy-c-" + c, t("s.sy_c_" + c), cfg.sync.categories.includes(c))).join("")}</div>
          <div class="faint">${esc(t("s.sy_hint"))}</div>
          <div id="sy-status" class="faint" style="margin:6px 0"></div>
          <div class="chk" style="gap:10px"><button class="btn" id="sy-test" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.sy_test"))}</button><button class="btn" id="sy-run" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.sy_run"))}</button><button class="btn" id="sy-gen" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.sy_gen"))}</button></div>
        </div></div>
      <div class="section"><h3>${t("s.diag")}</h3><div class="in">
          <div class="faint">${esc(t("s.diag_hint"))}</div>
          <div class="chk" style="gap:10px"><button class="btn" id="dg-show" type="button">${t("s.diag_show")}</button><button class="btn" id="dg-copy" type="button">${t("s.diag_copy")}</button><button class="btn" id="dg-clear" type="button">${t("s.diag_clear")}</button><span id="dg-out" class="muted"></span></div>
          <textarea id="dg-text" class="mono" readonly rows="12" style="width:100%;display:none"></textarea>
        </div></div>
      <div class="section"><h3>${t("s.logs")}</h3><div class="in">
          <div class="faint">${esc(t("s.logs_hint"))}</div>
          ${chk("lg-debug", t("s.logs_debug"), cfg.debug_log !== false)}
          <div class="chk" style="gap:10px;flex-wrap:wrap">
            <select id="lg-file" aria-label="${esc(t("s.logs_file"))}"><option value="admiral.log">admiral.log</option><option value="admiral-debug.log">admiral-debug.log</option><option value="admiral-errors.jsonl">admiral-errors.jsonl</option></select>
            <button class="btn" id="lg-show" type="button">${t("s.logs_show")}</button><button class="btn" id="lg-copy" type="button">${t("s.diag_copy")}</button>${isDesktop() ? `<button class="btn" id="lg-open" type="button">${esc(t("s.logs_open"))}</button>` : ""}<span id="lg-out" class="muted"></span></div>
          <textarea id="lg-text" class="mono" readonly rows="16" style="width:100%;display:none;white-space:pre"></textarea>
          <div class="faint">${esc(t("s.lp_hint"))}</div>
          <div class="chk" style="gap:10px;flex-wrap:wrap"><button class="btn" id="lg-pack" type="button">${esc(t("s.lp_make"))}</button><span id="lp-out" class="muted"></span></div>
          <div id="lp-result" style="display:none"></div>
        </div></div>
      <div class="section pin-bottom"><h3>${t("s.appupd")}</h3><div class="in">
          <div class="chk" style="gap:18px">${chk("au-enabled", t("s.au_enabled"), cfg.appupdate.enabled)}${chk("au-proxy", t("s.au_proxy"), cfg.appupdate.use_proxy)}</div>
          <div class="faint">${esc(t("s.au_hint"))}</div>
          <div id="au-status" class="faint" style="margin:6px 0"></div>
          <div class="chk" style="gap:10px;flex-wrap:wrap"><button class="btn" id="au-check" type="button" ${cfg.editable ? "" : "disabled"}>${esc(t("s.au_check"))}</button><span id="au-last" class="muted"></span>
            <button class="btn primary" id="au-install" type="button" hidden></button><button class="btn" id="au-rollback" type="button" hidden></button></div>
        </div></div>
      <div class="faint" style="overflow-wrap:anywhere">${cfg.config_path ? `${t("s.config")}: <span class="mono">${esc(cfg.config_path)}</span><br>` : ""}${t("s.data")}: <span class="mono">${esc(cfg.db_path)}</span><br>${esc(cfg.passwords_persist ? t("s.pw_dpapi") : t("s.pw_mem"))}</div>
      `;
    $("#st-actions").innerHTML = `<button class="btn" id="st-shortcuts" type="button">${esc(t("m.shortcuts"))}</button><button class="btn" id="st-about" type="button">${esc(t("m.about"))}</button>`
      + (S.status?.hidden_computers > 0 ? `<button class="btn" id="st-restore" type="button">${esc(t("m.restore_computers"))}</button>` : "")
      + (isDesktop() ? `<button class="btn" id="st-folder" type="button">${esc(t("s.open_folder"))}</button>` : "")
      + (cfg.editable ? `<button class="btn primary" id="st-save" type="button">${esc(t("s.save"))}</button>` : "");
    settingsNav();

    const mode = cfg.mode;                                 // Active Directory only (demo: source checkout / tests)
    if (mode === "demo") $("#st-ldap").style.opacity = ".55";
    // the NTLMv2 fallback only applies to Kerberos (LDAP) / the Kerberos transport (WinRM)
    const drawFb = () => {
      if (!cfg.editable) return;
      $("#ldap-ntlm").disabled = $("#ldap-auth").value !== "kerberos";
      $("#winrm-ntlm").disabled = $("#winrm-transport").value !== "kerberos";
    };
    drawFb();
    $("#ldap-auth").onchange = drawFb;
    $("#winrm-transport").onchange = drawFb;
    const v = (id) => $("#" + id).value;
    const c = (id) => $("#" + id).checked;
    const collect = () => {
      const body = {
        mode, stale_days: Number(v("stale-days")), language: v("st-lang"), theme: v("st-theme"), debug_log: c("lg-debug"),
        ldap: { server: v("ldap-server").trim(), base_dn: v("ldap-base").trim(), auth: v("ldap-auth"), ntlm_fallback: c("ldap-ntlm"), user: v("ldap-user").trim(), search_filter: v("ldap-filter").trim(),
          port: Number(v("ldap-port") || 0), use_ssl: c("ldap-ssl"), verify_cert: c("ldap-verify"), ca_file: v("ldap-ca").trim() },
        winrm: { user: v("winrm-user").trim(), transport: v("winrm-transport"), ntlm_fallback: c("winrm-ntlm"), workers: Number(v("winrm-workers")), use_https: c("winrm-https"), verify_cert: c("winrm-verify") },
        collect: { method: v("collect-method"), winrm_fallback: c("collect-fb"), smb_timeout: Number(v("collect-timeout")), response_timeout: Number(v("collect-response")), cleanup_delay: Number(v("collect-delay")) },
        vulns: { enabled: c("vuln-enabled"), refresh_days: Number(v("vuln-days")) },
        filecollect: { inbox: v("off-inbox").trim(), offline_allow_users: c("off-users") },
        logins: { enabled: c("lg-track"), path: v("lg-path").trim(), interval_minutes: Number(v("lg-interval")) },
        packages: { folder: v("pk-folder").trim() },
        deploy: { timeout_minutes: Number(v("dep-timeout")) },
        proxy: { url: v("proxy-url").trim(), pac: v("proxy-pac").trim(), user: v("proxy-user").trim(), allow_untrusted_pac: c("proxy-untrusted-pac") },
        appupdate: { enabled: c("au-enabled"), use_proxy: c("au-proxy") },
        updates: { enabled: c("upd-enabled"), refresh_hours: Number(v("upd-hours")), grace_days: Number(v("upd-grace")) },
        retry: { interval_minutes: Number(v("retry-interval")), offline: c("retry-offline"), failed: c("retry-failed") },
        sync: { enabled: c("sy-enabled"), peer: v("sy-peer").trim(), port: Number(v("sy-port")), network: v("sy-net").trim(), interval_minutes: Number(v("sy-interval") || 0),
          categories: ["computers", "fleets", "users", "printers"].filter((x) => c("sy-c-" + x)) },
        scan: { ports: v("scan-ports").split(/[\s,;]+/).filter(Boolean).map(Number), timeout: Number(v("scan-timeout")), workers: Number(v("scan-workers")), interval_minutes: Number(v("scan-interval") || 0) },
      };
      if (v("ldap-pw")) body.ldap.password = v("ldap-pw");
      if (v("winrm-pw")) body.winrm.password = v("winrm-pw");
      if (v("proxy-pw")) body.proxy.password = v("proxy-pw");
      if (v("vuln-key")) body.vulns.api_key = v("vuln-key");
      if (v("sy-key")) body.sync.key = v("sy-key");
      return body;
    };
    const dgShow = () => guard(async () => {
      const r = await api("GET", "/api/diagnostics");
      const box = $("#dg-text");
      box.value = r.text; box.style.display = "";
      $("#dg-out").textContent = r.records ? `${r.records} ${t("s.diag_records")}` : t("s.diag_none");
    });
    const lgShow = () => guard(async () => {
      const r = await api("GET", "/api/logs/" + encodeURIComponent($("#lg-file").value));
      const box = $("#lg-text");
      box.value = r.exists ? r.text : ""; box.style.display = "";
      $("#lg-out").textContent = !r.exists ? t("s.logs_none") : `${(r.size / 1024).toFixed(0)} KB${r.truncated ? " · " + t("s.logs_tail") : ""}`;
      box.scrollTop = box.scrollHeight;                                // the newest lines are at the end
    });
    $("#lg-show").onclick = lgShow;
    $("#lg-file").onchange = lgShow;
    $("#lg-copy").onclick = () => guard(async () => {
      if (!$("#lg-text").value) await lgShow();
      const box = $("#lg-text");
      box.select();
      try { await navigator.clipboard.writeText(box.value); } catch (e) { document.execCommand("copy"); }
      $("#lg-out").textContent = t("s.diag_copied");
    });
    if ($("#lg-open")) $("#lg-open").onclick = () => guard(() => window.pywebview.api.open_logs_folder(""));
    $("#lg-pack").onclick = () => guard(async () => {
      const btn = $("#lg-pack");
      btn.disabled = true; $("#lp-out").textContent = t("s.lp_working");
      try {
        const r = await api("POST", "/api/logs/package");
        const counts = Object.entries(r.counts || {}).map(([k, n]) => `${n} ${t("s.lp_kind_" + k)}`).join(", ") || t("s.lp_nothing");
        $("#lp-out").textContent = tText("s.lp_done", { n: r.files.length });
        const body = tText("s.lp_issue_body", { id: r.id, version: r.version || "" });
        const url = `${r.issue_url}?title=${encodeURIComponent("Log package " + r.id)}&body=${encodeURIComponent(body)}`;
        const box = $("#lp-result");
        box.style.display = "";
        box.innerHTML = `<div class="chk" style="gap:10px;flex-wrap:wrap"><b>${esc(t("s.lp_id"))}:</b><span class="mono">${esc(r.id)}</span><button class="btn" type="button" id="lp-copy">${esc(t("s.diag_copy"))}</button></div>
          <div class="faint" style="overflow-wrap:anywhere">${esc(t("s.lp_folder"))}: <span class="mono">${esc(r.folder)}</span></div>
          <div class="faint">${esc(t("s.lp_replaced"))}: ${esc(counts)}</div>
          <div class="faint">${esc(t("s.lp_steps"))}</div>
          <div class="chk" style="gap:10px">${isDesktop() ? `<button class="btn" id="lp-open" type="button">${esc(t("s.lp_open"))}</button>` : ""}<button class="btn primary" id="lp-issue" type="button">${esc(t("s.lp_issue"))}</button></div>`;
        $("#lp-copy").onclick = async () => { await copyText(r.id); toast(t("s.diag_copied")); };
        if ($("#lp-open")) $("#lp-open").onclick = () => guard(async () => {
          const path = await window.pywebview.api.save_log_package(r.id);
          if (path) toast(tText("s.lp_saved", { path }));
        });
        $("#lp-issue").onclick = () => guard(() => openUrl(url));
      } finally { btn.disabled = false; }
    });
    $("#dg-show").onclick = dgShow;
    $("#dg-copy").onclick = () => guard(async () => {
      if (!$("#dg-text").value) await dgShow();
      const box = $("#dg-text");
      box.select();
      try { await navigator.clipboard.writeText(box.value); } catch (e) { document.execCommand("copy"); }
      $("#dg-out").textContent = t("s.diag_copied");
    });
    $("#dg-clear").onclick = () => guard(async () => {
      await api("POST", "/api/diagnostics/clear");
      $("#dg-text").value = ""; $("#dg-text").style.display = "none";
      $("#dg-out").textContent = t("s.diag_cleared");
    });
    $("#st-theme").onchange = (e) => applyTheme(e.target.value);       // live preview
    $("#st-test").onclick = () => guard(async () => {
      const out = $("#st-test-out");
      out.textContent = t("s.testing");
      const r = await api("POST", "/api/test-connection", collect());
      out.innerHTML = `<span class="${r.ok ? "st-ok" : "st-bad"}">${r.ok ? "✓" : "✕"} ${esc(r.message)}</span>`;
    });
    const save = $("#st-save");
    if (save) save.onclick = () => guard(async () => {
      const before = S.status.mode;
      await api("PUT", "/api/settings", collect());
      S.status = await api("GET", "/api/status");
      LANG = S.status.language;
      document.documentElement.lang = LANG;
      applyTheme(S.status.theme);
      toast(before !== S.status.mode ? t("s.saved_sync") : t("s.saved"));
      renderAll();
    });
    // ---- CVE data
    $("#vuln-run").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());
      setSection("vulns");
      startJob("vulns");
    });

    // ---- offline (file) collection
    $("#off-run").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());
      const r = await api("POST", "/api/offline/import");
      $("#off-out").innerHTML = r.error ? `<span class="st-bad">${esc(r.error)}</span>` : esc(r.configured
        ? tText("s.off_result", { imported: r.imported, found: r.found, unknown: r.unknown.length, failed: r.failed.length }) : t("s.off_none"));
      if (r.imported) { await reload(); }
    });
    $("#off-script").onclick = () => guard(async () => {
      const s = await api("GET", "/api/offline/script");
      await saveText(s.filename, s.content);
    });

    // ---- login tracking (GPO startup script -> log files -> logon history)
    $("#lg-run").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());
      const r = await api("POST", "/api/logins/import");
      $("#lg-out").innerHTML = r.error ? `<span class="st-bad">${esc(r.error)}</span>` : esc(r.configured
        ? tText("s.lg_result", { imported: r.imported, found: r.found, unknown: r.unknown, failed: r.failed }) : t("s.lg_none"));
      if (r.imported) { await reload(); }
    });
    $("#lg-script").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());
      const s = await api("GET", "/api/logins/script");
      await saveText(s.filename, s.content);
    });

    // ---- ADmiral's own updates (signed manifest at the configured location)
    const auDraw = (u) => {
      const st = $("#au-status"), ins = $("#au-install"), rb = $("#au-rollback");
      if (!st) return;
      $("#au-last").textContent = tText("s.au_last", { when: u.checked ? fmtDate(u.checked) : t("s.au_last_never") });
      st.innerHTML = u.error ? `<span class="st-bad">${esc(u.error)}</span>`
        : !u.checked ? esc(tText("s.au_never", { v: u.current }))
        : u.available ? `<span class="st-warn">${esc(tText("s.au_new", { v: u.latest, cur: u.current }))}</span>${u.notes ? " – " + esc(u.notes) : ""}`
        : esc(tText("s.au_ok", { v: u.current }));
      ins.hidden = !(u.available && u.can_install);
      ins.textContent = tText("s.au_install", { v: u.latest });
      rb.hidden = !(u.previous && u.can_install);
      rb.textContent = tText("s.au_rollback", { v: u.previous });
      if (u.available && !u.can_install) st.innerHTML += ` <span class="faint">(${esc(t("s.au_cannot"))})</span>`;
    };
    const auRun = async (rollback) => {
      const u = await api("GET", "/api/appupdate");
      const ver = rollback ? u.previous : u.latest;
      if (!(await confirmDialog(tText(rollback ? "s.au_confirm_rb" : "s.au_confirm", { v: ver })))) return;
      $("#au-status").textContent = t("s.au_downloading");
      const r = await api("POST", "/api/appupdate/install", { rollback });
      $("#au-status").textContent = tText("s.au_installing", { v: r.version });
    };
    guard(async () => auDraw(await api("GET", "/api/appupdate")));
    $("#au-check").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());
      $("#au-status").textContent = t("s.au_checking");
      auDraw(await api("POST", "/api/appupdate/check"));
    });
    $("#au-install").onclick = () => guard(() => auRun(false));
    $("#au-rollback").onclick = () => guard(() => auRun(true));

    // ---- security-update reference data
    guard(async () => {
      const u = await api("GET", "/api/updates");
      $("#upd-status").innerHTML = u.error ? `<span class="st-bad">${esc(u.error)}</span>`
        : u.fetched_at ? esc(tText("s.upd_ok", { when: fmtDate(u.fetched_at), n: u.builds, months: u.months.join(", ") })) : esc(t("s.upd_never"));
    });
    // Trusting an untrusted PAC file (auto / http) hands the proxy credentials to whoever answers that request on the
    // network: ticking the box needs an explicit confirmation of the risk; "Cancel" leaves it unticked.
    $("#proxy-untrusted-pac").onchange = async (e) => {
      if (!e.target.checked) return;
      const ok = await confirmDialog(t("s.proxy_untrusted_pac_warn"), { title: t("s.proxy_untrusted_pac_title"), yes: t("s.proxy_untrusted_pac_yes"), safe: true });
      if (!ok) e.target.checked = false;
    };
    $("#proxy-test").onclick = () => guard(async () => {
      const out = $("#proxy-test-out");
      out.className = "muted";
      out.textContent = t("s.proxy_testing");
      await api("PUT", "/api/settings", collect());      // test the proxy just typed in
      const r = await api("POST", "/api/proxy/test");
      out.className = r.ok ? "st-ok" : "st-bad";
      out.textContent = r.message;
    });
    $("#upd-run").onclick = () => guard(async () => {
      await api("PUT", "/api/settings", collect());      // use the proxy just typed in
      startJob("updates");
    });

    // ---- synchronisation with a second ADmiral
    const drawSync = async () => {
      const st = await api("GET", "/api/sync");
      // HTML: the peer name / error come from the other instance, so they are escaped here
      const lastHtml = st.last && st.last.time ? (st.last.ok ? esc(tText("s.sy_last_ok", { when: fmtDate(st.last.time), peer: st.last.peer, pulled: st.last.pulled, pushed: st.last.pushed }))
        : `<span class="st-bad">${esc(st.last.error)}</span>`) : esc(t("s.sy_never"));
      $("#sy-status").innerHTML = `${esc(st.enabled ? (st.by_service ? t("s.sy_by_service") : st.listening ? tText("s.sy_listening", { ip: st.local_ip, port: st.port }) : t("s.sy_not_listening")) : t("s.sy_off"))} · ${esc(tText("s.sy_net_now", { net: st.network }))}<br>${lastHtml}${st.last && st.last.errors && st.last.errors.length ? `<br><span class="st-warn">${esc(st.last.errors.join(" · "))}</span>` : ""}`;
    };
    guard(drawSync);
    $("#sy-gen").onclick = () => {
      // 32 random bytes, base64url: the same key goes into every instance (copy it from the field)
      const b = crypto.getRandomValues(new Uint8Array(32));
      const key = btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const f = $("#sy-key"); f.type = "text"; f.value = key; f.select();
      toast(t("s.sy_gen_done"));
    };
    const noPeer = () => {
      if ($("#sy-peer").value.trim()) return false;
      toast(t("s.sy_no_peer"), true);
      $("#sy-peer").focus();
      return true;
    };
    $("#sy-test").onclick = () => guard(async () => {
      if (noPeer()) return;
      await api("PUT", "/api/settings", collect());
      const r = await api("POST", "/api/sync/test");
      const bad = (r.peers || []).filter((p) => !p.ok);
      toast((r.peers || []).filter((p) => p.ok).map((p) => tText("s.sy_test_ok", { host: p.host, version: p.version })).join(" · ")
        + (bad.length ? " · " + bad.map((p) => `${p.peer}: ${p.error}`).join(" · ") : ""), bad.length > 0);
    });
    $("#sy-run").onclick = () => guard(async () => {
      if (noPeer()) return;
      await api("PUT", "/api/settings", collect());
      startJob("sync");
      setTimeout(() => guard(drawSync), 4000);
    });

    // ---- retry service (Windows service on this machine)
    const drawSvc = (st) => {
      const box = $("#svc-status"), btns = $("#svc-buttons");
      if (!st.supported) { box.innerHTML = `<span class="faint">${esc(t("s.svc_unsupported"))}</span>`; btns.innerHTML = ""; return; }
      const label = !st.installed ? t("s.svc_none") : st.running ? t("s.svc_running") : t("s.svc_stopped");
      const cls = !st.installed ? "faint" : st.running ? "st-ok" : "st-warn";
      box.innerHTML = `${esc(t("s.svc_state"))}: <b class="${cls}">${esc(label)}</b>${st.installed && st.account ? ` · ${esc(st.account)}` : ""}`;
      $("#svc-install-fields").hidden = st.installed || !cfg.editable;
      const b = (id, text, cls2 = "", off = false) => `<button class="btn ${cls2}" id="${id}" type="button" ${cfg.editable && !off ? "" : "disabled"}>${esc(text)}</button>`;
      // install and delete are always in the category (the one that does not apply is greyed out)
      btns.innerHTML = b("svc-install", t("s.svc_install"), st.installed ? "" : "primary", st.installed)
        + (st.installed ? (st.enabled ? b("svc-off", t("s.svc_off")) : b("svc-on", t("s.svc_on"), "primary")) : "")
        + b("svc-delete", t("s.svc_delete"), "", !st.installed);
    };
    const svcCall = (action, extra = {}) => guard(async () => {
      drawSvc(await api("POST", "/api/retry-service", { action, ...extra }));
      if (action === "install") { $("#svc-account").value = ""; $("#svc-pw").value = ""; }
    });
    $("#svc-buttons").onclick = async (e) => {
      const id = e.target.closest("button")?.id;
      if (id === "svc-install") svcCall("install", { account: $("#svc-account").value.trim(), password: $("#svc-pw").value });
      else if (id === "svc-on") svcCall("enable");
      else if (id === "svc-off") svcCall("disable");
      else if (id === "svc-delete" && (await confirmDialog(t("s.svc_confirm_delete")))) svcCall("delete");
    };
    guard(async () => drawSvc(await api("GET", "/api/retry-service")));

    $("#st-shortcuts").onclick = shortcutsDialog;
    $("#st-about").onclick = aboutDialog;
    if ($("#st-restore")) $("#st-restore").onclick = restoreComputers;
    const folder = $("#st-folder");
    if (folder) folder.onclick = () => window.pywebview.api.open_data_folder();
  });
}

/* ================================================================== chrome */
function renderAll() {
  $("#tree-filter").placeholder = t("tree.filter");
  renderRail();
  applySection();
  renderToolbar();
  renderTree();
  renderPage();
  if (S.cw) { renderCwToolbar(); if (S.cw.data) renderComputer(); }
  updateStatus();
}

function bindGlobal() {
  document.addEventListener("click", (e) => { if (!e.target.closest("#pop") && !e.target.closest('[data-tb="scan"]')) hideMenu(); });
  window.addEventListener("blur", hideMenu);
  window.addEventListener("resize", hideMenu);

  $("#tree").addEventListener("click", (e) => {
    const tw = e.target.closest("[data-tw]");
    const tn = e.target.closest("[data-node]");
    if (tw && !tw.classList.contains("leaf")) {
      const id = tw.dataset.tw;
      if (S.expanded.has(id)) S.expanded.delete(id); else S.expanded.add(id);
      store.set("expanded", [...S.expanded]);
      return renderTree();
    }
    if (tn) selectNode(tn.dataset.node, { noScroll: true });
  });
  $("#tree").addEventListener("dblclick", (e) => {
    const tn = e.target.closest("[data-node]");
    if (!tn || !tn.querySelector(".tw:not(.leaf)")) return;
    const id = tn.dataset.node;
    if (S.expanded.has(id)) S.expanded.delete(id); else S.expanded.add(id);
    store.set("expanded", [...S.expanded]);
    renderTree();
  });
  $("#tree-filter").oninput = (e) => { S.treeFilter = e.target.value; renderTree(); };
  $("#sb-right").onclick = (e) => { e.preventDefault(); selectNode("log"); };

  // tree / page splitter
  const sp = $("#splitter");
  const w0 = store.get("treeW", 270);
  document.querySelector(".workspace").style.setProperty("--tree-w", w0 + "px");
  sp.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const move = (ev) => {
      const w = Math.max(180, Math.min(520, ev.clientX - 6));
      document.querySelector(".workspace").style.setProperty("--tree-w", w + "px");
      store.set("treeW", w);
    };
    const up = () => { window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up); };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  });

  document.addEventListener("keydown", (e) => {
    const inField = e.target.matches("input, textarea, select");
    if (e.key === "Escape") {
      if (!$("#pop").hidden) return hideMenu();
      if (!$("#dlg").hidden) return closeDialog();
      if (S.vw) return closeVuln();
      if (S.sw) return closeSoftware();
      if (S.cw) return closeComputer();
      if (S.uw) return closeUser();
      if (S.sel.size && $("#grid") && !inField) { S.sel.clear(); refreshSelectionClasses(); updateStatus(); updateToolbar(); }
      return;
    }
    if (!$("#dlg").hidden) return;
    if (S.cw) {
      if (e.altKey && e.key === "ArrowLeft") { e.preventDefault(); cwStep(-1); }
      if (e.altKey && e.key === "ArrowRight") { e.preventDefault(); cwStep(1); }
      return;
    }
    if (e.key === "F5") { e.preventDefault(); ACTIONS.refresh(); return; }
    if (e.ctrlKey && e.key.toLowerCase() === "f") { e.preventDefault(); ACTIONS.find(); return; }
    if (inField || !$("#grid")) return;
    if (e.ctrlKey && e.key.toLowerCase() === "a") { e.preventDefault(); ACTIONS["select-all"](); }
    else if (e.ctrlKey && e.key.toLowerCase() === "c") { e.preventDefault(); ACTIONS.copy(); }
    else if (e.key === "Enter") { e.preventDefault(); ACTIONS.details(); }
    else if (e.key === "Delete" && S.sel.size) { e.preventDefault(); removeComputers([...S.sel]); }
    else if (e.key === "ArrowDown") { e.preventDefault(); moveSelection(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveSelection(-1); }
  });
  bindComputerWindow();
  bindUserWindow();
  bindSoftwareWindows();
  $("#rail").addEventListener("click", (e) => {
    const act = e.target.closest("[data-rail]");
    if (act) return act.dataset.rail === "discord" ? openUrl(LINK_DISCORD) : supportDialog();
    const it = e.target.closest("[data-sec]"); if (it) setSection(it.dataset.sec);
  });
}

async function boot() {
  try {
    S.status = await api("GET", "/api/status");
  } catch (e) {
    document.body.innerHTML = `<div class="callout bad" style="margin:20px">ADmiral API: ${esc(e.message)}</div>`;
    return;
  }
  // in read-only (server) mode the theme/language may live in this browser only
  if (!S.status.settings_editable) {
    S.status.language = store.get("pref.language", S.status.language);
    S.status.theme = store.get("pref.theme", S.status.theme);
  }
  LANG = S.status.language || "hu";
  document.documentElement.lang = LANG;
  applyTheme(S.status.theme);
  bindGlobal();
  await guard(loadAll);
  if (!findNode(buildTree(), S.node)) S.node = "welcome";
  renderAll();
  selectNode(S.node);
  const running = (S.status.jobs || []).find((j) => j.status === "running");
  if (running) pollJob(running.id);
  // the background check runs shortly after start-up: tell once if a new version was found
  setTimeout(async () => {
    try { const u = await api("GET", "/api/appupdate"); if (u.available) toast(tText("s.au_new", { v: u.latest, cur: u.current })); } catch { /* ignore */ }
  }, 45000);
}

boot();
