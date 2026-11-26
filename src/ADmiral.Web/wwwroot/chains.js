/* ADmiral – Packages section (Actions): installation chains. A package here is an ordered list of steps (install,
   copy, script, restart, wait, message ...) run on each target computer; its files come from the package library
   (packages.js). Each package opens to show its steps. Loaded after packages.js. */
"use strict";

const CH = { open: new Set() };
const CH_TYPES = ["install", "copy", "delete", "scan", "reboot", "shutdown", "wol", "wait", "message", "powershell", "cmd"];
const CH_ICONS = { install: "package", copy: "copy", delete: "delete", scan: "scan", reboot: "refresh", shutdown: "block", wol: "ping", wait: "dst_queued", message: "info", powershell: "log", cmd: "log" };
const chIsInstaller = (path) => !!dpExt(path) || pkIsWuFile(path);
const chChains = () => (PK.data?.packages || []).filter((p) => p.kind === "chain" || (p.steps || []).length);

/* Every file a step can use: the package's own (older chains kept their files) and the whole library's. */
function chFiles(p) {
  const out = [], seen = new Set();
  for (const pk of [p, ...pkLibrary().filter((x) => x.id !== p.id)])
    for (const f of pk.files || []) if (!seen.has(f.path)) { seen.add(f.path); out.push({ ...f, pkg: pk }); }
  return out;
}
const chFileLabel = (f) => f.pkg.kind === "winupdate"
  ? `${f.pkg.name} (${f.version || f.pkg.version}) – ${f.path.split("/").pop()}`
  : `${f.path.split("/").pop()} (${f.version || "–"})`;

const chDefaults = (type, p) => {
  const files = chFiles(p), inst = files.find((f) => chIsInstaller(f.path)), any = files[0];
  return { install: { type, file: inst?.path || "", args: inst && dpExt(inst.path) ? DP_PRESETS[dpExt(inst.path)][0] : undefined }, copy: { type, file: any?.path || "", path: "C:\\ProgramData\\" },
    delete: { type, path: "C:\\" }, scan: { type }, reboot: { type, seconds: 30, wait: true }, shutdown: { type, seconds: 30 }, wol: { type, seconds: 300 },
    wait: { type, seconds: 60 }, message: { type, text: "", seconds: 300 }, powershell: { type, script: "" }, cmd: { type, script: "" } }[type];
};

/* New installation chain: only its name (the ID is made from it); then its editor opens. */
function chNewDialog() {
  const box = dialog(t("ch.new_title"), `
    <label class="fld"><span>${esc(t("ch.name"))}</span><input id="chn-name" type="text"></label>
    <div class="faint">${esc(t("ch.new_hint"))}</div>`,
    `<button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="chn-ok">${t("d.create")}</button>`);
  const go = () => guard(async () => {
    const name = $("#chn-name", box).value.trim();
    if (!name) return $("#chn-name", box).focus();
    const e = await api("POST", "/api/packages-new", { id: pkFreeId("Chain", name), name, kind: "chain" });
    closeDialog();
    await pkLoad();
    CH.open.add(e.id);
    chStepsDialog(e.id);
  });
  $("#chn-ok", box).onclick = go;
  $("#chn-name", box).onkeydown = (e) => { if (e.key === "Enter") go(); };
}

/* The chain editor: an ordered list of steps; each row has its own fields by type, move / remove buttons and
   "continue on error". Saved as a whole (the server checks every step). */
function chStepsDialog(id) {
  const p = PK.data?.packages.find((x) => x.id === id);
  if (!p) return;
  const steps = (p.steps || []).map((s) => ({ ...s }));
  const files = chFiles(p);
  // the files grouped by library package; install offers installers and Windows updates only
  const fileOpts = (cur, onlyInst) => {
    const groups = new Map();
    for (const f of files) {
      if (onlyInst && !chIsInstaller(f.path)) continue;
      const k = f.pkg.kind === "winupdate" ? `${t("pk.wu.section")} – ${pkBuildNum(f.pkg.os_build)}` : f.pkg.name;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    const html = [...groups.entries()].map(([g, list]) => `<optgroup label="${esc(g)}">${list.map((f) => `<option value="${esc(f.path)}" ${f.path === cur ? "selected" : ""}>${esc(chFileLabel(f))}</option>`).join("")}</optgroup>`).join("");
    const missing = cur && !files.some((f) => f.path === cur) ? `<option value="${esc(cur)}" selected>${esc(tText("ch.missing_file", { file: cur.split("/").pop() }))}</option>` : "";
    return missing + html || `<option value="">${esc(t(onlyInst ? "ch.no_installer" : "ch.no_file"))}</option>`;
  };
  const num = (i, k, v, min, max) => `<input type="number" min="${min}" max="${max}" style="width:90px" data-si="${i}" data-sk="${k}" value="${esc(v)}">`;
  const fields = (s, i) => {
    const inp = (k, ph, extra = "") => `<input data-si="${i}" data-sk="${k}" value="${esc(s[k] ?? "")}" placeholder="${esc(ph)}" ${extra}>`;
    switch (s.type) {
      case "install": return `<select data-si="${i}" data-sk="file">${fileOpts(s.file, true)}</select>`
        + (pkIsWuFile(s.file) ? `<span class="faint">${esc(t("ch.wu_hint"))}</span>` : inp("args", t("dp.args"), 'class="mono"'));
      case "copy": return `<select data-si="${i}" data-sk="file">${fileOpts(s.file, false)}</select>${inp("path", t("ch.dest"), 'class="mono"')}`;
      case "delete": return inp("path", t("ch.del_path"), 'class="mono"');
      case "reboot": return `<label class="chk">${t("ch.delay")} ${num(i, "seconds", s.seconds ?? 30, 15, 3600)} s</label>
        <label class="chk"><input type="checkbox" data-si="${i}" data-sk="wait" ${s.wait !== false ? "checked" : ""}> ${esc(t("ch.wait_back"))}</label>`;
      case "shutdown": return `<label class="chk">${t("ch.delay")} ${num(i, "seconds", s.seconds ?? 30, 15, 3600)} s</label>`;
      case "wol": return `<label class="chk">${t("ch.wol_wait")} ${num(i, "seconds", s.seconds ?? 300, 0, 3600)} s</label>`;
      case "wait": return `<label class="chk">${t("ch.wait_for")} ${num(i, "seconds", s.seconds ?? 60, 1, 14400)} s</label>`;
      case "message": return `<textarea data-si="${i}" data-sk="text" rows="2" maxlength="500" placeholder="${esc(t("ch.msg_ph"))}">${esc(s.text || "")}</textarea>
        <label class="chk">${t("ch.msg_time")} ${num(i, "seconds", s.seconds ?? 300, 10, 86400)} s</label>`;
      case "powershell": case "cmd": return `<textarea data-si="${i}" data-sk="script" rows="4" class="mono" spellcheck="false" placeholder="${esc(t("ch.ph." + s.type))}">${esc(s.script || "")}</textarea>`;
      default: return `<span class="faint">${esc(t("ch.scan_hint"))}</span>`;
    }
  };
  const box = dialog(tText("ch.title", { name: p.name }), `<div class="faint">${esc(t("ch.hint"))}</div><div id="ch-list" class="ch-list"></div>
    <div class="ch-add"><span class="muted">${esc(t("ch.add"))}</span>${CH_TYPES.map((ty) => `<button type="button" class="btn" data-chadd="${ty}">${icon(CH_ICONS[ty], 14)}${esc(t("ch.type." + ty))}</button>`).join("")}</div>`,
    `<span class="faint" id="ch-count"></span><span style="flex:1"></span><button class="btn" data-dclose>${t("d.cancel")}</button><button class="btn primary" id="ch-save">${t("d.save")}</button>`);
  box.classList.add("dlg-big");
  const draw = () => {
    $("#ch-list", box).innerHTML = steps.map((s, i) => `<div class="ch-step">
      <div class="ch-num">${i + 1}.</div>
      <div class="ch-type">${icon(CH_ICONS[s.type], 16)}<b>${esc(t("ch.type." + s.type))}</b></div>
      <div class="ch-fields">${fields(s, i)}</div>
      <div class="ch-tools"><label class="chk" title="${esc(t("ch.continue_tip"))}"><input type="checkbox" data-si="${i}" data-sk="continue_on_error" ${s.continue_on_error ? "checked" : ""}> ${esc(t("ch.continue"))}</label>
        <button type="button" class="btn" data-chmv="${i}:-1" ${i === 0 ? "disabled" : ""} aria-label="${esc(t("dl.up"))}">▲</button><button type="button" class="btn" data-chmv="${i}:1" ${i === steps.length - 1 ? "disabled" : ""} aria-label="${esc(t("dl.down"))}">▼</button>
        <button type="button" class="btn" data-chrm="${i}" aria-label="${esc(t("d.remove"))}">✕</button></div></div>`).join("") || `<div class="empty">${esc(t("ch.empty"))}</div>`;
    $("#ch-count", box).textContent = tText("ch.count", { n: steps.length });
  };
  draw();
  box.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (b.dataset.chadd) { steps.push(chDefaults(b.dataset.chadd, p)); draw(); $("#ch-list", box).lastElementChild?.scrollIntoView({ block: "nearest" }); }
    else if (b.dataset.chrm !== undefined) { steps.splice(Number(b.dataset.chrm), 1); draw(); }
    else if (b.dataset.chmv) { const [i, d] = b.dataset.chmv.split(":").map(Number); [steps[i], steps[i + d]] = [steps[i + d], steps[i]]; draw(); }
  });
  const onEdit = (e) => {
    const { si, sk } = e.target.dataset;
    if (si === undefined) return;
    const s = steps[Number(si)];
    s[sk] = e.target.type === "checkbox" ? e.target.checked : e.target.type === "number" ? Number(e.target.value) : e.target.value;
    if (sk === "file" && s.type === "install" && e.type === "change") {
      const ext = dpExt(s.file || "");
      if (ext) s.args = DP_PRESETS[ext][0];
      else delete s.args;
      draw();
    }
  };
  box.addEventListener("input", onEdit);
  box.addEventListener("change", onEdit);
  $("#ch-save", box).onclick = () => guard(async () => {
    await api("POST", "/api/packages-steps", { id: p.id, steps });
    closeDialog();
    toast(tText("ch.saved", { n: steps.length }));
    await pkLoad();
  });
}

/* ---------------------------------------------------------------- the page */
// one step, opened under its package: what it does, and for a file whether it is still in the library and checked
function chStepRow(p, s, i, files) {
  let extra = "";
  if (s.file) {
    const f = files.find((x) => x.path === s.file);
    extra = f
      ? ` <span class="faint">· ${esc(f.pkg.kind === "winupdate" ? `${f.pkg.name} ${f.pkg.os_build}` : f.pkg.name)} · ${esc(pkSize(f.size))}</span> ${f.vendor_checked ? `<span class="st-ok">${esc(t(f.hash_source === "catalog" || f.hash_source === "catalog-name" ? "pk.st.catalog" : "pk.st.src"))}</span>` : ""}`
      : ` <span class="st-bad">${esc(t("ch.file_gone"))}</span>`;
  }
  return `<div class="ch-view"><span class="ch-num">${i + 1}.</span>${icon(CH_ICONS[s.type] || "info", 14)}<span>${esc(chStepText(s))}</span>${extra}</div>`;
}

function drawChains() {
  const wrap = $("#chgrid");
  if (!wrap || !PK.data) return;
  const list = chChains();
  const q = (CH.filter || "").trim().toLowerCase();
  const rows = list.filter((p) => !q || [p.id, p.name].join(" ").toLowerCase().includes(q));
  const head = ["name", "steps", "files", "size", "status"].map((c) => `<th>${esc(t("ch.col." + c))}</th>`).join("") + "<th></th>";
  const body = rows.map((p) => {
    const files = chFiles(p), used = [...new Set((p.steps || []).filter((s) => s.file).map((s) => s.file))];
    const found = used.map((u) => files.find((f) => f.path === u));
    const missing = found.filter((f) => !f).length;
    const size = found.reduce((a, f) => a + (f?.size || 0), 0);
    const state = !(p.steps || []).length ? `<span class="faint">${esc(t("ch.st.empty"))}</span>`
      : missing ? `<span class="st-bad">${esc(tText("ch.st.missing", { n: missing }))}</span>`
      : found.some((f) => f.pkg.verify_ok === false) ? `<span class="st-bad">${esc(t("pk.st.bad"))}</span>` : `<span class="st-ok">${esc(t("ch.st.ready"))}</span>`;
    const open = CH.open.has(p.id);
    const steps = open ? `<tr class="pk-files"><td class="rn"></td><td colspan="6">${(p.steps || []).map((s, i) => chStepRow(p, s, i, files)).join("") || `<div class="faint">${esc(t("ch.empty"))}</div>`}</td></tr>` : "";
    return `<tr data-ch="${esc(p.id)}"><td class="rn"></td><td><span class="ch-caret">${open ? "▾" : "▸"}</span>${icon("package", 16)}${esc(p.name)}</td><td class="num">${(p.steps || []).length}</td><td class="num">${used.length}</td>
      <td class="num">${size ? esc(pkSize(size)) : ""}</td><td>${state}</td>
      <td class="nowrap"><button class="btn" data-chact="edit" data-id="${esc(p.id)}">${icon("edit", 14)}${esc(t("ch.edit"))}</button>
      <button class="btn" data-chact="deploy" data-id="${esc(p.id)}"${(p.steps || []).length && !missing ? "" : " disabled"}>${icon("rocket", 14)}${esc(t("ch.deploy"))}</button>
      <button class="btn" data-chact="remove" data-id="${esc(p.id)}">${esc(t("pk.remove"))}</button></td></tr>${steps}`;
  }).join("");
  wrap.innerHTML = rows.length ? `<table class="grid"><thead><tr><th class="rn"></th>${head}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">${esc(t("ch.page_empty"))}</div>`;
  $("#sb-left").textContent = tText("ch.page_count", { n: list.length });
}

function renderChainsPage(el) {
  el.innerHTML = pageHead("package", t("nav.chains"), t("ch.page_sub"),
    `<button class="btn primary" data-chhead="new">${icon("rocket", 16)}${esc(t("ch.new"))}</button>
     <input class="page-filter" id="ch-filter" type="search" placeholder="${esc(t("page.filter"))}" value="${esc(CH.filter || "")}">`)
    + `<div class="grid-wrap" id="chgrid" tabindex="0"><div class="empty">…</div></div>`;
  $('[data-chhead="new"]', el).onclick = () => chNewDialog();
  let tmr;
  $("#ch-filter", el).oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { CH.filter = e.target.value; drawChains(); }, 120); };
  $("#chgrid").addEventListener("click", (e) => {
    const b = e.target.closest("[data-chact]");
    if (b) {
      const id = b.dataset.id, p = PK.data?.packages.find((x) => x.id === id);
      if (b.dataset.chact === "edit") return chStepsDialog(id);
      if (b.dataset.chact === "deploy") return dpNewDialog({ pid: id, chain: true });
      if (b.dataset.chact === "remove") {
        return guard(async () => {
          // an older package keeps its files: removing it here removes them from the library too
          const text = tText("ch.remove_confirm", { name: p?.name || id }) + (p?.files?.length ? "\n\n" + t("ch.remove_files") : "");
          if (!(await confirmDialog(text, { safe: !!p?.files?.length }))) return;
          await api("DELETE", `/api/packages/${encodeURIComponent(id)}`);
          CH.open.delete(id);
          await pkLoad();
        });
      }
    }
    const tr = e.target.closest("tr[data-ch]");
    if (!tr) return;
    const id = tr.dataset.ch;
    CH.open.has(id) ? CH.open.delete(id) : CH.open.add(id);
    drawChains();
  });
  pkLoad();
}
