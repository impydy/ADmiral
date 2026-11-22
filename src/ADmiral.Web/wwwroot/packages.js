/* ADmiral – Packages section (installers added by hand, with versions and a SHA-256 register).
   Loaded after app.js (shares its helpers: $, api, t, esc, icon, S, ...). */
"use strict";

const PK = { data: null, open: new Set(), filter: "" };

const pkSize = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(1) + " GB" : n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B");

function pkState(p) {
  if (!p.files.length) return `<span class="faint">${esc(t("pk.st.none"))}</span>`;
  if (p.verify_ok === false) return `<span class="st-bad">${esc(t("pk.st.bad"))}</span>`;
  return `<span class="st-ok">${esc(t("pk.st.ok"))}</span>${p.source_hash_checked ? ` <span class="faint">· ${esc(t("pk.st.src"))}</span>` : ""}`;
}

async function pkUpload(files, meta) {
  let { id, title, version, sha256 } = meta;
  for (const f of files) {
    const q = new URLSearchParams({ id, name: f.name, version: version || "", title: title || "", sha256: sha256 || "" });
    const res = await fetch(`/api/packages-upload?${q}`, { method: "POST", body: f,
      headers: { "X-ADmiral": "1", "X-ADmiral-Token": TOKEN, "Content-Type": "application/octet-stream" } });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.detail || `${res.status} ${res.statusText}`);
    }
  }
  toast(tText("pk.uploaded", { n: files.length }));
  await pkLoad();
}

/* Asks for the package name, ID (= folder) and version of the file(s) being added; prefilled from the
   existing package or guessed from the file name. Resolves {id,title,version} or null. */
function pkMetaDialog(files, existing) {
  return new Promise((resolve) => {
    const f0 = files[0].name;
    const stem = f0.replace(/\.[^.]*$/, "");
    const vm = stem.match(/(\d+(?:\.\d+)+)/);
    const clean = stem.replace(/[-_. ]*v?\d+(?:\.\d+)+.*$/i, "").replace(/[^A-Za-z0-9._+-]+/g, "-").replace(/^[^A-Za-z0-9]+|[-.]+$/g, "");
    const init = existing
      ? { id: existing.id, title: existing.name || existing.id, version: vm ? vm[1] : "" }
      : { id: `Manual.${clean || "Package"}`, title: clean.replace(/-/g, " ") || f0, version: vm ? vm[1] : "" };
    const layer = document.createElement("div");
    layer.className = "dlg-layer cfm-layer";
    layer.innerHTML = `<div class="dlg cfm" role="dialog" aria-modal="true">
      <div class="dlg-title"><span>${esc(t("pk.meta.title"))}</span></div>
      <div class="dlg-body"><div class="faint" style="margin-bottom:8px">${esc(files.map((f) => f.name).join(", "))}</div>
      <label>${esc(t("pk.meta.name"))}<input id="pkm-title" type="text" style="width:100%" value="${esc(init.title)}"></label>
      <label style="display:block;margin-top:8px">${esc(t("pk.meta.id"))}<input id="pkm-id" type="text" style="width:100%" class="mono" value="${esc(init.id)}" ${existing ? "disabled" : ""}></label>
      <label style="display:block;margin-top:8px">${esc(t("pk.meta.ver"))}<input id="pkm-ver" type="text" style="width:100%" value="${esc(init.version)}"></label>
      <label style="display:block;margin-top:8px">${esc(t("pk.meta.sha"))}<input id="pkm-sha" type="text" style="width:100%" class="mono" ${files.length > 1 ? "disabled" : ""} placeholder="${esc(files.length > 1 ? t("pk.meta.sha_multi") : "")}"></label>
      <div class="faint" style="margin-top:8px">${esc(t("pk.meta.hint"))}</div></div>
      <div class="dlg-foot"><button class="btn" data-no type="button">${esc(t("d.cancel"))}</button>
      <button class="btn primary" data-yes type="button">${esc(t("pk.meta.ok"))}</button></div></div>`;
    const done = (v) => { layer.remove(); resolve(v); };
    layer.querySelector("[data-no]").onclick = () => done(null);
    layer.querySelector("[data-yes]").onclick = () => {
      const id = layer.querySelector("#pkm-id").value.trim();
      if (!id) return layer.querySelector("#pkm-id").focus();
      const sha = layer.querySelector("#pkm-sha").value.trim().toLowerCase();
      if (sha && !/^[0-9a-f]{64}$/.test(sha)) return layer.querySelector("#pkm-sha").focus();
      done({ sha256: sha, id, title: layer.querySelector("#pkm-title").value.trim(), version: layer.querySelector("#pkm-ver").value.trim() });
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
  const inp = document.createElement("input");
  inp.type = "file";
  inp.multiple = true;
  inp.onchange = () => inp.files.length && guard(async () => {
    const files = [...inp.files];
    const meta = await pkMetaDialog(files, id ? PK.data?.packages.find((x) => x.id === id) : null);
    if (meta) await pkUpload(files, meta);
  });
  inp.click();
}

/* Asks for the SHA-256 published by the vendor; resolves the lower-case value or null. */
function pkAskHash(file) {
  return new Promise((resolve) => {
    const layer = document.createElement("div");
    layer.className = "dlg-layer cfm-layer";
    layer.innerHTML = `<div class="dlg cfm" role="dialog" aria-modal="true">
      <div class="dlg-title"><span>${esc(t("pk.vendor.title"))}</span></div>
      <div class="dlg-body"><div class="faint" style="margin-bottom:8px">${esc(file)}</div>
      <label>${esc(t("pk.vendor.label"))}<input id="pkv-sha" type="text" class="mono" style="width:100%"></label>
      <div class="st-bad" id="pkv-err" style="margin-top:6px" hidden>${esc(t("pk.vendor.bad"))}</div></div>
      <div class="dlg-foot"><button class="btn" data-no type="button">${esc(t("d.cancel"))}</button>
      <button class="btn primary" data-yes type="button">${esc(t("pk.vendor.check"))}</button></div></div>`;
    const done = (v) => { layer.remove(); resolve(v); };
    layer.querySelector("[data-no]").onclick = () => done(null);
    layer.querySelector("[data-yes]").onclick = () => {
      const v = layer.querySelector("#pkv-sha").value.trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(v)) { layer.querySelector("#pkv-err").hidden = false; return; }
      done(v);
    };
    layer.addEventListener("keydown", (e) => {
      if (e.key === "Escape") done(null);
      else if (e.key === "Enter") layer.querySelector("[data-yes]").click();
    });
    document.body.appendChild(layer);
    layer.querySelector("#pkv-sha").focus();
  });
}

function drawPackages() {
  const wrap = $("#pkgrid");
  if (!wrap || !PK.data) return;
  const q = PK.filter.trim().toLowerCase();
  const rows = PK.data.packages.filter((p) => !q || [p.id, p.name, p.publisher, p.version].join(" ").toLowerCase().includes(q));
  const head = ["name", "id", "publisher", "version", "size", "downloaded", "status"].map((c) => `<th>${esc(t("pk.col." + c))}</th>`).join("") + "<th></th>";
  const body = rows.map((p) => {
    const open = PK.open.has(p.id);
    const files = open ? `<tr class="pk-files"><td class="rn"></td><td colspan="8"><table class="grid"><thead><tr><th>${esc(t("pk.f.version"))}</th><th>${esc(t("pk.f.file"))}</th><th>${esc(t("pk.f.size"))}</th><th>${esc(t("pk.f.added"))}</th><th>${esc(t("pk.f.sha"))}</th><th></th></tr></thead><tbody>
        ${[...p.files].sort((a, b) => (b.added || "").localeCompare(a.added || "")).map((f) => `<tr><td>${esc(f.version || "–")}${f.version === p.version ? ` <span class="chip">${esc(t("pk.current"))}</span>` : ""}</td><td>${esc(f.path.split("/").pop())}</td><td class="num">${esc(pkSize(f.size))}</td><td>${esc(fmtDate(f.added))}</td><td class="mono">${esc(f.sha256)}</td>
          <td class="nowrap">${f.vendor_checked ? `<span class="st-ok">${esc(t("pk.st.src"))}</span>` : `<button class="btn" data-pkact="vendor" data-id="${esc(p.id)}" data-file="${esc(f.path)}">${esc(t("pk.vendor.btn"))}</button>`}
          <button class="btn" data-pkact="rmfile" data-id="${esc(p.id)}" data-file="${esc(f.path)}">${esc(t("pk.rmfile"))}</button></td></tr>`).join("")}</tbody></table>
        ${p.verified ? `<div class="faint" style="margin-top:4px">${esc(tText("pk.verified", { d: fmtDate(p.verified) }))}</div>` : ""}</td></tr>` : "";
    return `<tr data-pk="${esc(p.id)}"><td class="rn"></td><td>${icon("package", 16)}${esc(p.name)}</td><td class="mono">${esc(p.id)}</td><td>${esc(p.publisher)}</td><td>${esc(p.version)}${p.versions.length > 1 ? ` <span class="faint">${esc(tText("pk.n_versions", { n: p.versions.length }))}</span>` : ""}</td>
      <td class="num">${p.files.length ? esc(pkSize(p.size)) : ""}</td><td>${esc(fmtDate(p.downloaded))}</td><td>${pkState(p)}</td>
      <td class="nowrap"><button class="btn" data-pkact="addfile" data-id="${esc(p.id)}">${esc(t("pk.addfile_row"))}</button>
      <button class="btn" data-pkact="verify" data-id="${esc(p.id)}"${p.files.length ? "" : " disabled"}>${esc(t("pk.verify"))}</button>
      <button class="btn" data-pkact="remove" data-id="${esc(p.id)}">${esc(t("pk.remove"))}</button></td></tr>${files}`;
  }).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr><th class="rn"></th>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(t("pk.empty"))}</div>`;
  const total = PK.data.packages.reduce((a, p) => a + p.size, 0);
  $("#sb-left").textContent = tText("pk.count", { n: PK.data.packages.length, size: pkSize(total) });
  const info = $("#pk-info");
  if (info) info.textContent = tText("pk.folder", { path: PK.data.folder });
}

async function pkLoad() {
  const d = await guard(() => api("GET", "/api/packages"));
  if (d) PK.data = d;
  if (S.section === "packages") drawPackages();
}

function renderPackagesPage(el) {
  el.innerHTML = pageHead("package", t("nav.packages"), t("pk.sub"),
    `<button class="btn primary" data-pkhead="file">${icon("package", 16)}${esc(t("pk.addfile"))}</button>
     <button class="btn" data-pkhead="verify">${esc(t("pk.verify_all"))}</button>`)
    + `<div class="faint mono" id="pk-info" style="padding:2px 10px"></div><div class="grid-wrap" id="pkgrid" tabindex="0"></div>`;
  $('[data-pkhead="file"]', el).onclick = () => pkPick();
  $('[data-pkhead="verify"]', el).onclick = () => guard(async () => {
    const r = await api("POST", "/api/packages-verify", {});
    toast(tText("pk.verify_res", { n: r.length, bad: r.filter((x) => !x.ok && !x.problems.every((p) => p.problem === "not_downloaded")).length }));
    await pkLoad();
  });
  $("#pkgrid").addEventListener("click", (e) => {
    const b = e.target.closest("[data-pkact]");
    if (b) {
      const id = b.dataset.id;
      if (b.dataset.pkact === "addfile") return pkPick(id);
      if (b.dataset.pkact === "vendor") {
        const file = b.dataset.file;
        return guard(async () => {
          const sha = await pkAskHash(file);
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
          if (!(await confirmDialog(tText("pk.remove_confirm", { id })))) return; await api("DELETE", `/api/packages/${encodeURIComponent(id)}`); PK.open.delete(id); await pkLoad(); });
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
