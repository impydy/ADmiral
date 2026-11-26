/* ADmiral – Package library section: installers and other files added by hand (versions, SHA-256 register) and
   Windows updates (.msu / .cab) grouped by Windows build, checked against the Windows Update Catalog.
   The installation chains that use these files are on the Packages page (chains.js).
   Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

const PK = { data: null, wu: null, open: new Set(), filter: "" };

const pkSize = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(1) + " GB" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");
const pkIsWuFile = (p) => /\.(msu|cab)$/i.test(p || "");
const pkLibrary = () => (PK.data?.packages || []).filter((p) => p.kind !== "chain");
// a name as an ID part: accents dropped (é -> e), anything else that is not allowed in an ID becomes "-"
const pkClean = (s) => String(s || "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^A-Za-z0-9._+-]+/g, "-").replace(/^[^A-Za-z0-9]+|[-.]+$/g, "");

/* An ID that is not taken yet: <prefix>.<name>, then -2, -3 ... */
function pkFreeId(prefix, name) {
  const base = `${prefix}.${pkClean(name) || "Package"}`.slice(0, 120);
  const taken = new Set((PK.data?.packages || []).map((p) => p.id.toLowerCase()));
  let id = base;
  for (let i = 2; taken.has(id.toLowerCase()); i++) id = `${base}-${i}`;
  return id;
}

function pkState(p) {
  if (!p.files.length) return `<span class="faint">${esc(t("pk.st.none"))}</span>`;
  if (p.verify_ok === false) return `<span class="st-bad">${esc(t("pk.st.bad"))}</span>`;
  const src = p.source_hash_checked ? ` <span class="faint">· ${esc(t(p.kind === "winupdate" ? "pk.st.catalog" : "pk.st.src"))}</span>` : "";
  return `<span class="st-ok">${esc(t("pk.st.ok"))}</span>${src}`;
}

/* ---------------------------------------------------------------- copying files into the library */
let pkUpRaf = 0;
function pkUpTick() {
  if (pkUpRaf) return;
  pkUpRaf = requestAnimationFrame(() => { pkUpRaf = 0; updateStatus(); });
}

/* One file as the raw request body; the upload progress goes to S.upload (shown in the status bar). */
function pkSend(f, q, i, n) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/packages-upload?${q}`);
    xhr.setRequestHeader("X-ADmiral", "1");
    xhr.setRequestHeader("X-ADmiral-Token", TOKEN);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    S.upload = { name: f.name, i, n, sent: 0, total: f.size, phase: "copy" };
    pkUpTick();
    xhr.upload.onprogress = (e) => {
      S.upload.sent = e.loaded;
      S.upload.total = e.total || f.size;
      if (S.upload.total && e.loaded >= S.upload.total) S.upload.phase = "check";
      pkUpTick();
    };
    xhr.upload.onload = () => { S.upload.phase = "check"; pkUpTick(); };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      let d = {};
      try { d = JSON.parse(xhr.responseText); } catch (_) { /* not JSON */ }
      reject(new Error(d.detail || `${xhr.status} ${xhr.statusText}`));
    };
    xhr.onerror = () => reject(new Error(t("pk.up.neterr")));
    xhr.onabort = () => reject(new Error(t("pk.up.neterr")));
    xhr.send(f);
  });
}

/* Copy the files one after the other. It runs in the background: the page (and the rest of the program) can be used
   meanwhile; the status bar shows the file, the percent and the bytes. */
async function pkUpload(files, meta) {
  if (S.upload) return toast(t("pk.up.wait"), true);
  let done = 0;
  try {
    for (const [i, f] of files.entries()) {
      const q = new URLSearchParams(meta.kind === "winupdate"
        ? { id: meta.id, name: f.name, kind: "winupdate", os_build: meta.os_build, kb: meta.kb, version: meta.version, digest: meta.digest || "" }
        : { id: meta.id, name: f.name, version: meta.version || "", title: meta.title || "", sha256: meta.sha256 || "" });
      await pkSend(f, q, i + 1, files.length);
      done++;
    }
    toast(tText("pk.uploaded", { n: done }));
  } finally {
    S.upload = null;
    updateStatus();
    await pkLoad();
  }
}

/* Name, version and (optionally) the vendor's SHA-256 of the file(s) being added. The ID (the folder) is not asked:
   it is the existing package's, or made from the name. Resolves {id,title,version,sha256} or null. */
function pkMetaDialog(files, existing) {
  return new Promise((resolve) => {
    const f0 = files[0].name;
    const stem = f0.replace(/\.[^.]*$/, "");
    const vm = stem.match(/(\d+(?:\.\d+)+)/);
    const clean = pkClean(stem.replace(/[-_. ]*v?\d+(?:\.\d+)+.*$/i, ""));
    const init = existing
      ? { title: existing.name || existing.id, version: vm ? vm[1] : "" }
      : { title: clean.replace(/-/g, " ") || f0, version: vm ? vm[1] : "" };
    const layer = document.createElement("div");
    layer.className = "dlg-layer cfm-layer";
    layer.innerHTML = `<div class="dlg cfm" role="dialog" aria-modal="true">
      <div class="dlg-title"><span>${esc(t("pk.meta.title"))}</span></div>
      <div class="dlg-body"><div class="faint" style="margin-bottom:8px">${esc(files.map((f) => `${f.name} (${pkSize(f.size)})`).join(", "))}</div>
      <label>${esc(t("pk.meta.name"))}<input id="pkm-title" type="text" style="width:100%" value="${esc(init.title)}"></label>
      <label style="display:block;margin-top:8px">${esc(t("pk.meta.ver"))}<input id="pkm-ver" type="text" style="width:100%" value="${esc(init.version)}"></label>
      <label style="display:block;margin-top:8px">${esc(t("pk.meta.sha"))}<input id="pkm-sha" type="text" style="width:100%" class="mono" ${files.length > 1 ? "disabled" : ""} placeholder="${esc(files.length > 1 ? t("pk.meta.sha_multi") : "")}"></label>
      <div class="faint" style="margin-top:8px">${esc(t("pk.meta.hint"))}</div></div>
      <div class="dlg-foot"><button class="btn" data-no type="button">${esc(t("d.cancel"))}</button>
      <button class="btn primary" data-yes type="button">${esc(t("pk.meta.ok"))}</button></div></div>`;
    const done = (v) => { layer.remove(); resolve(v); };
    layer.querySelector("[data-no]").onclick = () => done(null);
    layer.querySelector("[data-yes]").onclick = () => {
      const title = layer.querySelector("#pkm-title").value.trim();
      if (!title) return layer.querySelector("#pkm-title").focus();
      const sha = layer.querySelector("#pkm-sha").value.trim().toLowerCase();
      if (sha && !/^[0-9a-f]{64}$/.test(sha)) return layer.querySelector("#pkm-sha").focus();
      done({ sha256: sha, id: existing ? existing.id : pkFreeId("Manual", title), title, version: layer.querySelector("#pkm-ver").value.trim() });
    };
    layer.addEventListener("keydown", (e) => {
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") layer.querySelector("[data-yes]").click();
    });
    document.body.appendChild(layer);
    layer.querySelector("#pkm-title").focus();
  });
}

function pkPick(id) {
  const existing = id ? PK.data?.packages.find((x) => x.id === id) : null;
  if (existing?.kind === "winupdate") return pkWuDialog(existing);
  const inp = document.createElement("input");
  inp.type = "file";
  inp.multiple = true;
  inp.onchange = () => inp.files.length && guard(async () => {
    const files = [...inp.files];
    const meta = await pkMetaDialog(files, existing);
    if (meta) await pkUpload(files, meta);
  });
  inp.click();
}

/* Asks for a published hash; resolves the value or null. WU: SHA-1 / SHA-256, hex or base64 (as the catalog shows it). */
function pkAskHash(file, wu) {
  return new Promise((resolve) => {
    const ok = (v) => (wu ? /^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(v) || /^[A-Za-z0-9+/]{27}=$|^[A-Za-z0-9+/]{43}=$/.test(v) : /^[0-9a-f]{64}$/i.test(v));
    const layer = document.createElement("div");
    layer.className = "dlg-layer cfm-layer";
    layer.innerHTML = `<div class="dlg cfm" role="dialog" aria-modal="true">
      <div class="dlg-title"><span>${esc(t(wu ? "pk.wu.hash_title" : "pk.vendor.title"))}</span></div>
      <div class="dlg-body"><div class="faint" style="margin-bottom:8px">${esc(file)}</div>
      <label>${esc(t(wu ? "pk.wu.hash_label" : "pk.vendor.label"))}<input id="pkv-sha" type="text" class="mono" style="width:100%"></label>
      <div class="st-bad" id="pkv-err" style="margin-top:6px" hidden>${esc(t(wu ? "pk.wu.hash_bad" : "pk.vendor.bad"))}</div></div>
      <div class="dlg-foot"><button class="btn" data-no type="button">${esc(t("d.cancel"))}</button>
      <button class="btn primary" data-yes type="button">${esc(t("pk.vendor.check"))}</button></div></div>`;
    const done = (v) => { layer.remove(); resolve(v); };
    layer.querySelector("[data-no]").onclick = () => done(null);
    layer.querySelector("[data-yes]").onclick = () => {
      const v = layer.querySelector("#pkv-sha").value.trim();
      if (!ok(v)) { layer.querySelector("#pkv-err").hidden = false; return; }
      done(/^[0-9a-f]+$/i.test(v) ? v.toLowerCase() : v);
    };
    layer.addEventListener("keydown", (e) => {
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") layer.querySelector("[data-yes]").click();
    });
    document.body.appendChild(layer);
    layer.querySelector("#pkv-sha").focus();
  });
}

/* New library package without files: only its name and ID. */
function pkNewDialog() {
  const box = dialog(t("pk.new_title"), `
    <label class="fld"><span>${esc(t("pk.meta.name"))}</span><input id="pkn-name" type="text"></label>
    <label class="fld"><span>${esc(t("pk.meta.id"))}</span><input id="pkn-id" type="text" class="mono" placeholder="Ceg.Program"></label>
    <div class="faint">${esc(t("pk.new_hint"))}</div>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="pkn-ok">${t("d.create")}</button>`);
  $("#pkn-name", box).oninput = (e) => { const id = $("#pkn-id", box); if (!id.dataset.touched) id.value = e.target.value.trim() ? pkFreeId("Manual", e.target.value) : ""; };
  $("#pkn-id", box).oninput = (e) => (e.target.dataset.touched = "1");
  $("#pkn-ok", box).onclick = () => guard(async () => {
    const name = $("#pkn-name", box).value.trim(), id = $("#pkn-id", box).value.trim();
    if (!name) return $("#pkn-name", box).focus();
    if (!id) return $("#pkn-id", box).focus();
    const e = await api("POST", "/api/packages-new", { id, name });
    closeDialog();
    toast(tText("pk.created", { name: e.name }));
    await pkLoad();
  });
}

/* ---------------------------------------------------------------- Windows updates */
// the Windows builds the computers of the domain run, from the Windows updates data: [{build, os, n, latest, kb, month}]
function pkWuBuilds() {
  const wu = PK.wu;
  if (!wu) return [];
  const by = new Map();
  for (const c of wu.computers || []) {
    if (!c.build) continue;
    let b = by.get(c.build);
    if (!b) by.set(c.build, (b = { build: c.build, n: 0, os: {} }));
    b.n++;
    if (c.os) b.os[c.os] = (b.os[c.os] || 0) + 1;
  }
  const ref = new Map((wu.reference || []).map((r) => [r.build, r]));
  return [...by.values()].map((b) => {
    const r = ref.get(b.build);
    return { ...b, os: Object.entries(b.os).sort((x, y) => y[1] - x[1])[0]?.[0] || "", latest: r ? `${b.build.replace(/^10\.0\./, "")}.${r.ubr}` : "", kb: r?.kb || "", month: r?.month || "" };
  }).sort((a, b) => b.build.localeCompare(a.build, undefined, { numeric: true }));
}
const pkWuReady = () => !!(PK.wu?.status?.fetched_at && pkWuBuilds().length);
const pkBuildNum = (b) => String(b || "").replace(/^10\.0\./, "");

/* Add a Windows update file for one of the builds of the domain: name = KB, version = the build version it brings. */
function pkWuDialog(existing) {
  const builds = pkWuBuilds();
  if (!builds.length) return toast(t("pk.wu.need_query"), true);
  const pre = existing ? builds.find((b) => b.build === existing.os_build) || { build: existing.os_build, os: "", n: 0, latest: existing.version, kb: existing.kb } : builds[0];
  const opts = (existing ? [pre] : builds).map((b) => `<option value="${esc(b.build)}"${b.build === pre.build ? " selected" : ""}>${esc(`${pkBuildNum(b.build)} – ${b.os || "Windows"} · ${tText("pk.wu.n_pc", { n: b.n })}${b.latest ? ` · ${t("pk.wu.newest")}: ${b.latest}${b.kb ? ` (${b.kb})` : ""}` : ""}`)}</option>`).join("");
  let file = null;
  const box = dialog(t("pk.wu.title"), `
    <label class="fld"><span>${esc(t("pk.wu.build"))}</span><select id="wu-build" ${existing ? "disabled" : ""}>${opts}</select></label>
    <div class="row-flds" style="display:flex;gap:10px">
      <label class="fld" style="flex:1"><span>${esc(t("pk.wu.kb"))}</span><input id="wu-kb" type="text" class="mono" placeholder="KB5043080"></label>
      <label class="fld" style="flex:1"><span>${esc(t("pk.wu.version"))}</span><input id="wu-ver" type="text" class="mono" placeholder="26100.4061"></label></div>
    <div class="fld"><span>${esc(t("pk.wu.file"))}</span><div style="display:flex;gap:8px;align-items:center"><button class="btn" type="button" id="wu-pick">${icon("package", 14)}${esc(t("pk.wu.pick"))}</button><span class="faint trunc" id="wu-fname">${esc(t("pk.wu.nofile"))}</span></div></div>
    <label class="fld"><span>${esc(t("pk.wu.digest"))}</span><input id="wu-digest" type="text" class="mono"></label>
    <div class="st-warn" id="wu-warn" hidden></div>
    <div class="faint">${esc(t("pk.wu.hint"))}</div>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="wu-ok">${esc(t("pk.wu.add"))}</button>`);
  const fill = () => {
    const b = builds.find((x) => x.build === $("#wu-build", box).value) || pre;
    $("#wu-kb", box).value = existing?.kb || b.kb || "";
    $("#wu-ver", box).value = existing?.version || b.latest || `${pkBuildNum(b.build)}.`;
  };
  fill();
  $("#wu-build", box).onchange = fill;
  const check = () => {
    const kb = $("#wu-kb", box).value.trim().toUpperCase().replace(/^(\d)/, "KB$1");
    const fk = (file?.name.match(/kb(\d{6,8})/i) || [])[1];
    const w = $("#wu-warn", box);
    w.hidden = !(fk && kb && `KB${fk}` !== kb);
    w.textContent = w.hidden ? "" : tText("pk.wu.kb_mismatch", { file: `KB${fk}`, kb });
  };
  $("#wu-kb", box).oninput = check;
  $("#wu-pick", box).onclick = () => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.accept = ".msu,.cab";
    inp.onchange = () => {
      file = inp.files[0] || null;
      $("#wu-fname", box).textContent = file ? `${file.name} (${pkSize(file.size)})` : t("pk.wu.nofile");
      const fk = (file?.name.match(/kb(\d{6,8})/i) || [])[1];
      if (fk && !$("#wu-kb", box).value.trim()) $("#wu-kb", box).value = `KB${fk}`;
      check();
    };
    inp.click();
  };
  $("#wu-ok", box).onclick = () => guard(async () => {
    const build = $("#wu-build", box).value;
    const kb = $("#wu-kb", box).value.trim().toUpperCase().replace(/^(\d)/, "KB$1");
    const version = $("#wu-ver", box).value.trim().replace(/^10\.0\./, "");
    const digest = $("#wu-digest", box).value.trim();
    if (!/^KB\d{6,8}$/.test(kb)) return $("#wu-kb", box).focus();
    if (!new RegExp(`^${pkBuildNum(build)}\\.\\d{1,6}$`).test(version)) return toast(tText("pk.wu.bad_version", { b: pkBuildNum(build) }), true);
    if (!file) return toast(t("pk.wu.nofile"), true);
    if (!pkIsWuFile(file.name)) return toast(t("pk.wu.bad_file"), true);
    const id = `WU-${pkBuildNum(build)}-${kb}`;
    closeDialog();
    await pkUpload([file], { kind: "winupdate", id, os_build: build, kb, version, digest });
    // look the file up in the Windows Update Catalog right away (when nothing confirmed it yet)
    const p = PK.data?.packages.find((x) => x.id === id);
    const f = p ? [...p.files].sort((x, y) => (y.added || "").localeCompare(x.added || ""))[0] : null;
    if (f && !f.vendor_checked) await pkCatalog(id, f.path, true);
  });
}

async function pkCatalog(id, file, auto = false) {
  S.upload = { name: file.split("/").pop(), i: 1, n: 1, sent: 0, total: 0, phase: "check" };
  updateStatus();
  try {
    const r = await api("POST", "/api/packages-catalog", { id, file });
    toast(tText("pk.wu.cat_ok", { title: r.title }));
  } catch (e) {
    toast((auto ? t("pk.wu.cat_auto_fail") + " " : "") + e.message, true);
  } finally {
    S.upload = null;
    updateStatus();
    await pkLoad();
  }
}

/* ---------------------------------------------------------------- the page */
function pkFilesRow(p) {
  const wu = p.kind === "winupdate";
  const rows = [...p.files].sort((a, b) => (b.added || "").localeCompare(a.added || "")).map((f) => {
    const src = f.vendor_checked
      ? `<span class="st-ok" title="${esc(f.catalog_title || "")}">${esc(t(f.hash_source === "catalog" ? "pk.src.catalog" : f.hash_source === "catalog-name" ? "pk.src.name" : "pk.st.src"))}</span>`
      : wu ? `<button class="btn" data-pkact="catalog" data-id="${esc(p.id)}" data-file="${esc(f.path)}" title="${esc(t("pk.wu.cat_tip"))}">${esc(t("pk.wu.cat_btn"))}</button>
             <button class="btn" data-pkact="vendor" data-id="${esc(p.id)}" data-file="${esc(f.path)}">${esc(t("pk.wu.hash_btn"))}</button>`
        : `<button class="btn" data-pkact="vendor" data-id="${esc(p.id)}" data-file="${esc(f.path)}">${esc(t("pk.vendor.btn"))}</button>`;
    return `<tr><td>${esc(f.version || "–")}${!wu && f.version === p.version ? ` <span class="chip">${esc(t("pk.current"))}</span>` : ""}</td><td>${esc(f.path.split("/").pop())}</td><td class="num">${esc(pkSize(f.size))}</td><td>${esc(fmtDate(f.added))}</td>
      <td class="mono">${esc(f.sha256)}${f.sha1 ? `<div class="faint">SHA-1 ${esc(f.sha1)}</div>` : ""}</td>
      <td class="nowrap">${src} <button class="btn" data-pkact="rmfile" data-id="${esc(p.id)}" data-file="${esc(f.path)}">${esc(t("pk.rmfile"))}</button></td></tr>`;
  }).join("");
  return `<tr class="pk-files"><td class="rn"></td><td colspan="8"><table class="grid"><thead><tr><th>${esc(t("pk.f.version"))}</th><th>${esc(t("pk.f.file"))}</th><th>${esc(t("pk.f.size"))}</th><th>${esc(t("pk.f.added"))}</th><th>${esc(t("pk.f.sha"))}</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    ${p.verified ? `<div class="faint" style="margin-top:4px">${esc(tText("pk.verified", { d: fmtDate(p.verified) }))}</div>` : ""}</td></tr>`;
}

function pkRow(p) {
  const wu = p.kind === "winupdate";
  const files = PK.open.has(p.id) ? pkFilesRow(p) : "";
  const ver = `${esc(p.version)}${!wu && p.versions.length > 1 ? ` <span class="faint">${esc(tText("pk.n_versions", { n: p.versions.length }))}</span>` : ""}`;
  return `<tr data-pk="${esc(p.id)}"><td class="rn"></td><td>${icon(wu ? "patch" : "package", 16)}${esc(p.name)}</td><td class="mono">${esc(p.id)}</td><td>${esc(p.publisher)}</td><td>${ver}</td>
    <td class="num">${p.files.length ? esc(pkSize(p.size)) : ""}</td><td>${esc(fmtDate(p.downloaded))}</td><td>${pkState(p)}</td>
    <td class="nowrap">${wu ? "" : `<button class="btn" data-pkact="addfile" data-id="${esc(p.id)}">${esc(t("pk.addfile_row"))}</button> `}
    <button class="btn" data-pkact="verify" data-id="${esc(p.id)}"${p.files.length ? "" : " disabled"}>${esc(t("pk.verify"))}</button>
    <button class="btn" data-pkact="remove" data-id="${esc(p.id)}">${esc(t("pk.remove"))}</button></td></tr>${files}`;
}

function drawPackages() {
  const wrap = $("#pkgrid");
  if (!wrap || !PK.data) return;
  const q = PK.filter.trim().toLowerCase();
  const all = pkLibrary().filter((p) => !q || [p.id, p.name, p.publisher, p.version, p.kb, p.os_build].join(" ").toLowerCase().includes(q));
  const apps = all.filter((p) => p.kind !== "winupdate"), wus = all.filter((p) => p.kind === "winupdate");
  const head = `<thead><tr><th class="rn"></th>${["name", "id", "publisher", "version", "size", "downloaded", "status"].map((c) => `<th>${esc(t("pk.col." + c))}</th>`).join("")}<th></th></tr></thead>`;
  // Windows updates: one group per Windows build (the base build number), newest build first
  const builds = new Map(pkWuBuilds().map((b) => [b.build, b]));
  const groups = new Map();
  for (const p of wus) { const k = p.os_build || "?"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(p); }
  const wuBody = [...groups.entries()].sort((a, b) => b[0].localeCompare(a[0], undefined, { numeric: true })).map(([b, list]) => {
    const info = builds.get(b);
    const meta = info ? ` <span class="faint">${esc(`${info.os} · ${tText("pk.wu.n_pc", { n: info.n })}${info.latest ? ` · ${t("pk.wu.newest")}: ${info.latest}${info.kb ? ` (${info.kb})` : ""}` : ""}`)}</span>` : "";
    return `<tr class="pk-group"><td class="rn"></td><td colspan="8">${icon("window_os", 16)}<b>${esc(tText("pk.wu.group", { b: pkBuildNum(b) }))}</b>${meta}</td></tr>`
      + list.sort((x, y) => (y.version || "").localeCompare(x.version || "", undefined, { numeric: true })).map(pkRow).join("");
  }).join("");
  wrap.innerHTML = (apps.length ? `<table class="grid">${head}<tbody>${apps.map(pkRow).join("")}</tbody></table>` : `<div class="empty">${esc(t("pk.empty"))}</div>`)
    + `<h3 class="wu-h" style="margin:14px 10px 4px">${icon("patch", 16)} ${esc(t("pk.wu.section"))}</h3>`
    + (wus.length ? `<table class="grid">${head}<tbody>${wuBody}</tbody></table>` : `<div class="empty">${esc(t(pkWuReady() ? "pk.wu.empty" : "pk.wu.need_query"))}</div>`);
  const lib = pkLibrary();
  $("#sb-left").textContent = tText("pk.count", { n: lib.length, size: pkSize(lib.reduce((a, p) => a + p.size, 0)) });
  const info = $("#pk-info");
  if (info) info.textContent = tText("pk.folder", { path: PK.data.folder });
  const wb = $('[data-pkhead="wu"]');
  if (wb) { wb.disabled = !pkWuReady(); wb.title = pkWuReady() ? t("pk.wu.tip") : t("pk.wu.need_query"); }
}

async function pkLoad() {
  const [d, wu] = await Promise.all([guard(() => api("GET", "/api/packages")), api("GET", "/api/winupdates").catch(() => null)]);
  if (d) PK.data = d;
  if (wu) PK.wu = wu;
  if (S.section === "packages") drawPackages();
  if (S.section === "chains" && typeof drawChains === "function") drawChains();
}

/* The chains (Packages page) that use a file of this package: removing it would break them. */
function pkUsedBy(p) {
  const paths = new Set(p.files.map((f) => f.path));
  return (PK.data?.packages || []).filter((c) => c.id !== p.id && (c.steps || []).some((s) => s.file && paths.has(s.file))).map((c) => c.name);
}

function renderPackagesPage(el) {
  el.innerHTML = pageHead("library", t("nav.packages"), t("pk.sub"),
    `<button class="btn primary" data-pkhead="new">${icon("package", 16)}${esc(t("pk.new"))}</button>
     <button class="btn" data-pkhead="file">${icon("copy", 16)}${esc(t("pk.addfile"))}</button>
     <button class="btn" data-pkhead="wu" disabled title="${esc(t("pk.wu.need_query"))}">${icon("patch", 16)}${esc(t("pk.wu.btn"))}</button>
     <button class="btn" data-pkhead="verify">${esc(t("pk.verify_all"))}</button>
     <input class="page-filter" id="pk-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(PK.filter)}">`)
    + `<div class="faint mono" id="pk-info" style="padding:2px 10px"></div><div class="grid-wrap" id="pkgrid" tabindex="0"></div>`;
  $('[data-pkhead="file"]', el).onclick = () => pkPick();
  $('[data-pkhead="new"]', el).onclick = () => pkNewDialog();
  $('[data-pkhead="wu"]', el).onclick = () => pkWuDialog();
  let tmr;
  $("#pk-filter", el).oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { PK.filter = e.target.value; drawPackages(); }, 120); };
  $('[data-pkhead="verify"]', el).onclick = () => guard(async () => {
    const r = await api("POST", "/api/packages-verify", {});
    toast(tText("pk.verify_res", { n: r.length, bad: r.filter((x) => !x.ok && !x.problems.every((p) => p.problem === "not_downloaded")).length }));
    await pkLoad();
  });
  $("#pkgrid").addEventListener("click", (e) => {
    const b = e.target.closest("[data-pkact]");
    if (b) {
      const id = b.dataset.id, p = PK.data?.packages.find((x) => x.id === id);
      if (b.dataset.pkact === "addfile") return pkPick(id);
      if (b.dataset.pkact === "catalog") return pkCatalog(id, b.dataset.file);
      if (b.dataset.pkact === "vendor") {
        const file = b.dataset.file;
        return guard(async () => {
          const sha = await pkAskHash(file, p?.kind === "winupdate");
          if (!sha) return;
          await api("POST", "/api/packages-vendorhash", { id, file, sha256: sha });
          toast(t("pk.vendor.ok"));
          await pkLoad();
        });
      }
      if (b.dataset.pkact === "rmfile") {
        const file = b.dataset.file;
        return guard(async () => {
          if (!(await confirmDialog(tText("pk.rmfile_confirm", { file })))) return;
          await api("POST", "/api/packages-remove-file", { id, file });
          await pkLoad();
        });
      }
      if (b.dataset.pkact === "verify") return guard(async () => { await api("POST", "/api/packages-verify", { id }); await pkLoad(); });
      if (b.dataset.pkact === "remove") {
        return guard(async () => {
          const used = p ? pkUsedBy(p) : [];
          const text = tText("pk.remove_confirm", { id }) + (used.length ? "\n\n" + tText("pk.remove_used", { names: used.join(", ") }) : "");
          if (!(await confirmDialog(text, { safe: used.length > 0 }))) return;
          await api("DELETE", `/api/packages/${encodeURIComponent(id)}`); PK.open.delete(id); await pkLoad();
        });
      }
    }
    const tr = e.target.closest("tr[data-pk]");
    if (!tr) return;
    const id = tr.dataset.pk;
    PK.open.has(id) ? PK.open.delete(id) : PK.open.add(id);
    drawPackages();
  });
  pkLoad();
}
