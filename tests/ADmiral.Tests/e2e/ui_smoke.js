// End-to-end UI test: drives the real ADmiral page in Chromium (Playwright).
// Usage: node ui_smoke.js <url-with-token>    exit code 0 = pass
"use strict";
const { chromium } = require("playwright");

const url = process.argv[2];
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

(async () => {
  const browser = await chromium.launch();
  // bypassCSP: Playwright's waitForFunction polls with eval inside the page, which ADmiral's CSP forbids
  // (the app itself never evaluates strings; every other step runs under the CSP)
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"], bypassCSP: true });
  const p = await ctx.newPage();
  // E2E_CPU_THROTTLE=6 simulates a slow CI machine (Chromium DevTools CPU throttling)
  if (process.env.E2E_CPU_THROTTLE) {
    const cdp = await ctx.newCDPSession(p);
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: Number(process.env.E2E_CPU_THROTTLE) });
  }
  const errors = [];
  const requests = [];
  p.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  p.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text()); });
  p.on("request", (r) => requests.push([r.method(), new URL(r.url()).pathname]));
  p.on("response", (r) => { if (r.status() >= 400) errors.push(`HTTP ${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });

  const step = async (name, fn) => {
    try { await fn(); } catch (e) { failures.push(`${name}: ${e.message.split("\n")[0]}`); }
  };
  const rows = () => p.locator("#grid tbody tr").count();
  // wait for an async re-render instead of sleeping a fixed time (CI machines are slower)
  const waitRows = (n) => p.waitForFunction((n) => document.querySelectorAll("#grid tbody tr").length === n, n, { timeout: 10000 });
  const waitTitle = (text) => p.waitForFunction((t) => document.querySelector("#cwin-title").textContent.includes(t), text, { timeout: 10000 });

  await p.goto(url);
  // the app opens on the Overview (its own rail item, above Inventory)
  await p.waitForSelector(".rail-it[data-sec='overview'].on");

  await step("token removed from address bar", async () => check(!p.url().includes("token="), "token still in URL"));
  await step("hungarian by default", async () => {
    check((await p.textContent("[data-tb='copy']")).includes("Másolás"), "toolbar not Hungarian");
    check((await p.textContent("[data-tb='adsync']")).includes("AD beolvasás"), "AD import label");
  });
  await step("welcome tiles", async () => {
    check((await p.locator(".tn[data-node='welcome']").count()) === 0, "overview still in the device tree");
    await p.waitForSelector(".tile");
    check((await p.locator(".tile").count()) >= 8, "tiles missing");
    await p.click(".tile[data-node='b:online']");
    check((await p.getAttribute(".tn.sel", "data-node")) === "b:online", "tile did not open collection");
    check((await p.locator("[data-tb='settings']").count()) === 0, "settings still in the device toolbar");
    check((await p.locator(".rail-it[data-sec='message']").count()) === 1, "send message missing from the Tools rail");
    check((await p.locator(".rail-it[data-rail='discord']").count()) === 0, "discord still in the rail");
  });
  await step("all computers grid + sort", async () => {
    await p.click(".tn[data-node='all']");
    check((await rows()) === 190, `expected 190 rows, got ${await rows()}`);
    await p.click("#grid th[data-sort='name']");
    const first = await p.textContent("#grid tbody tr:first-child td:nth-child(2)");
    check(first.trim().startsWith("SRV") || first.trim().startsWith("LT") || first.trim() > "M", "descending sort");
    await p.click("#grid th[data-sort='name']");
  });
  await step("page filter", async () => {
    await p.fill("#page-filter", "sql");
    await waitRows(8);
    await p.fill("#page-filter", "");
    await waitRows(190);
  });
  await step("multi-select + status bar", async () => {
    await p.click("#grid tbody tr:nth-child(1) td:nth-child(2)");
    await p.click("#grid tbody tr:nth-child(5) td:nth-child(2)", { modifiers: ["Shift"] });
    await p.click("#grid tbody tr:nth-child(8) td:nth-child(2)", { modifiers: ["Control"] });
    check((await p.textContent("#sb-left")).includes("6 kijelölve"), "selection count " + (await p.textContent("#sb-left")));
    await p.keyboard.press("Control+a");
    check((await p.textContent("#sb-left")).includes("190 kijelölve"), "ctrl+a");
    await p.click("#grid tbody tr:nth-child(2) td:nth-child(2)");
  });
  await step("context menu", async () => {
    await p.click("#grid tbody tr:nth-child(2) td:nth-child(2)", { button: "right" });
    await p.waitForSelector("#pop:not([hidden])");
    check((await p.textContent("#pop")).includes("Részletek"), "ctx menu items");
    await p.keyboard.press("Escape");
  });
  await step("computer window: every category", async () => {
    await p.keyboard.press("Enter");
    await p.waitForSelector("#cwin:not([hidden]) .fval");
    check((await p.textContent("#cwin-title")).includes("Számítógép [2 / 190]"), "cw title");
    for (const cat of ["ad_groups", "apps", "disks", "nics", "hotfixes", "services", "local_admins", "ports", "collections", "tags", "computer"]) {
      await p.click(`.cat[data-cat='${cat}']`);
      await p.waitForTimeout(80);
    }
    check((await p.locator(".fval").count()) > 40, "computer page fields");
    await p.click("[data-cw='next']");
    await waitTitle("[3 / 190]");
    await p.keyboard.press("Alt+ArrowLeft");
    await waitTitle("[2 / 190]");
  });
  await step("apps filter in computer window", async () => {
    await p.click(".cat[data-cat='apps']");
    const total = await p.locator(".cwin-content tbody tr").count();
    await p.fill("#cw-filter", "microsoft");
    await p.waitForTimeout(150);
    const filtered = await p.locator(".cwin-content tbody tr").count();
    check(total > 0 && filtered > 0 && filtered <= total, `apps filter ${filtered}/${total}`);
  });
  await step("allow-scan toggle shows yellow bar", async () => {
    await p.click(".cat[data-cat='computer']");
    await p.click("[data-cw='allow']");
    await p.waitForSelector("#cwin-msg:not([hidden])");
    check((await p.textContent("#cwin-msg")).includes("le van tiltva"), "disabled bar text");
    await p.click("[data-cw='allow']");
    await p.waitForSelector("#cwin-msg", { state: "hidden" });
    await p.keyboard.press("Escape");
    check(await p.locator("#cwin").isHidden(), "cw closed by Esc");
  });
  await step("tree: OU and built-in collections", async () => {
    if (!(await p.locator(".tn[data-node='ou:contoso.local/Servers']").count())) await p.click(".tn[data-node='ad'] .tw");
    await p.click(".tn[data-node='ou:contoso.local/Servers']");
    await p.click(".tn[data-node='ou:contoso.local/Servers'] .tw");          // expand -> App, File, SQL
    check((await p.locator(".tn[data-node^='ou:contoso.local/Servers/']").count()) === 3, "OU children");
    check((await rows()) === 31, `servers OU rows ${await rows()}`);
    await p.click(".tn[data-node='b:failed']");
    check((await rows()) > 0, "failed scans collection empty");
    await p.fill("#tree-filter", "SQL");
    await p.waitForTimeout(150);
    check((await p.locator(".tn").count()) < 10, "tree filter");
    await p.fill("#tree-filter", "");
  });
  await step("tag dialog", async () => {
    await p.click(".tn[data-node='all']");
    await p.click("#grid tbody tr:nth-child(1) td:nth-child(2)");
    await p.click("#grid tbody tr:nth-child(2) td:nth-child(2)", { modifiers: ["Control"] });
    await p.click("#grid tbody tr:nth-child(2) td:nth-child(2)", { button: "right" });
    await p.click("#pop .mi:has-text('Címke hozzáadása')");
    await p.fill("#tg", "e2e-tag");
    await p.click(".dlg [data-ok]");
    await p.waitForSelector(".toast");
    await p.click(".tn[data-node='tags'] .tw");
    await p.click(".tn[data-node='t:e2e-tag']");
    await waitRows(2);
    await p.click(".tn[data-node='all']");
    await p.click("#grid tbody tr:nth-child(1) td:nth-child(2)");
    await p.click("#grid tbody tr:nth-child(2) td:nth-child(2)", { modifiers: ["Control"] });
  });
  await step("static collection from selection + add/remove members", async () => {
    await p.click("[data-tb='new-coll']");
    check((await p.getAttribute("#fe-kind [data-kind='static']", "class") || "").includes("on"), "a selection starts a static collection");
    await p.fill("#fe-name", "E2E statikus");
    check((await p.locator("#fe-dual .dual-r option").count()) === 2, "members prefilled from selection");
    // add-all then remove-all then back to the two: the middle buttons move between the lists
    const left = await p.locator("#fe-dual .dual-l option").count();
    await p.click("#fe-dual [data-dl='add-all']");
    check((await p.locator("#fe-dual .dual-r option").count()) === left + 2, "add all");
    await p.click("#fe-dual [data-dl='rem-all']");
    check((await p.locator("#fe-dual .dual-r option").count()) === 0, "remove all");
    const names = await p.locator("#fe-dual .dual-l option").evaluateAll((os) => os.slice(0, 2).map((o) => o.value));
    await p.selectOption("#fe-dual .dual-l", names);
    await p.click("#fe-dual [data-dl='add']");
    check((await p.locator("#fe-dual .dual-r option").count()) === 2, "add selected");
    await p.click("#fe-save");
    await p.waitForSelector(".page-head h1:has-text('E2E statikus')");
    await waitRows(2);
    await p.click("#grid tbody tr:nth-child(1) td:nth-child(2)");
    await p.click("#grid tbody tr:nth-child(1) td:nth-child(2)", { button: "right" });
    await p.click("#pop .mi:has-text('Eltávolítás ebből a gyűjteményből')");
    await waitRows(1);
  });
  await step("dynamic collection with app rule", async () => {
    await p.click("[data-tb='new-coll']");
    await p.click("#fe-kind [data-kind='dynamic']");
    await p.fill("#fe-name", "E2E Chrome");
    await p.selectOption("select[data-k='field']", "app");
    await p.selectOption("select[data-k='op']", "any_contains");
    await p.fill("input[data-k='value']", "chrome");
    await p.waitForSelector("#fe-preview b");
    await p.fill("#fe-group", "CN=Deploy-Office-Pilot,OU=Groups,DC=contoso,DC=local");
    await p.click("#fe-save");
    await p.waitForSelector(".page-head h1:has-text('E2E Chrome')");
    check((await rows()) > 0, "dynamic collection rows");
  });
  await step("AD group comparison is read-only", async () => {
    await p.click("[data-tb='group']");
    await p.waitForSelector("#gs-plan .plan");
    const foot = await p.locator(".dlg-foot button").allTextContents();
    check(!foot.some((x) => /alkalmaz|apply/i.test(x)), "dialog offers an apply button: " + foot);
    check((await p.textContent(".dlg")).includes("Csak lekérdezés"), "read-only notice");
    await p.click(".dlg [data-dclose]");
  });
  await step("export dialog (copy)", async () => {
    await p.click("[data-tb='export']");
    await p.click("#rp-tabs [data-tab='filter']");
    await p.click("#rp-add");
    await p.selectOption("#rp-filter select[data-fk='op']", "ends_with");
    await p.fill("#rp-filter input[data-fk='value']", "zzz-no-such-name");
    await p.waitForFunction(() => document.querySelector("#rp-coll").disabled, null, { timeout: 5000 });
    await p.click("#rp-filter [data-rm-f='0']");
    check(!(await p.isDisabled("#rp-coll")), "new collection from report enabled");
    await p.click("#rp-tabs [data-tab='layout']");
    await p.selectOption("#ex-fmt", "txt");
    await p.click(".dlg [data-copy]");
    await p.waitForFunction(async () => (await navigator.clipboard.readText()).includes(".contoso.local"), null, { timeout: 10000, polling: 200 });
    await p.click(".dlg [data-dclose]");
  });
  await step("edit + delete collection", async () => {
    await p.click("[data-act='edit-coll']");
    await p.fill("#fe-desc", "módosítva");
    await p.click("#fe-save");
    await p.waitForSelector(".page-head .sub:has-text('módosítva')");
    await p.click("[data-tb='delete']");
    await p.click(".dlg [data-yes]");
    await p.waitForSelector(".tn.sel[data-node='my']");
  });
  await step("columns dialog", async () => {
    await p.click(".tn[data-node='all']");
    await p.click("[data-tb='columns']");
    await p.check(".picklist input[value='serial']");
    await p.click(".dlg [data-ok]");
    check((await p.locator("#grid th[data-sort='serial']").count()) === 1, "serial column added");
  });
  await step("scan selected computers (job + status bar)", async () => {
    await p.click("#grid tbody tr:nth-child(3) td:nth-child(2)");
    // the toolbar's Scan menu says it covers every computer; the selection is scanned from the right-click menu
    await p.click("[data-tb='scan']");
    check((await p.textContent("#pop .mi:nth-child(1)")).includes("Összes gép"), "toolbar scan menu names all computers");
    await p.keyboard.press("Escape");
    await p.click("#grid tbody tr:nth-child(3) td:nth-child(2)", { button: "right" });
    await p.click("#pop .mi:has-text('Szkennelés (elérhetőség + leltár)')");
    await p.waitForFunction(() => document.querySelector("#sb-right").textContent.includes("0 számítógép"), null, { timeout: 15000 });
    await p.waitForSelector(".toast");
  });
  await step("activity log", async () => {
    await p.click(".tn[data-node='log']");
    await p.waitForSelector("#logwrap tbody tr");
    check((await p.locator("#logwrap tbody tr").count()) >= 5, "log entries");
  });
  await step("users page renders and filters", async () => {
    await p.click(".rail-it[data-sec='users']");
    await p.waitForSelector("#ugrid table, #ugrid .empty");
    await p.fill("#users-filter", "zz-no-such-user");
    await p.waitForSelector("#ugrid .empty");
    await p.fill("#users-filter", "");
    await p.click(".rail-it[data-sec='devices']");
  });
  await step("dark theme via menu", async () => {
    await p.evaluate(() => setPref("theme", "dark"));
    await p.waitForFunction(() => document.documentElement.dataset.theme === "dark", null, { timeout: 10000 });
  });
  await step("language switch to English and back", async () => {
    await p.evaluate(() => setPref("language", "en"));
    await p.waitForFunction(() => document.querySelector("[data-tb='copy']").textContent.includes("Copy"));
    check((await p.textContent("[data-tb='adsync']")).includes("AD Import"), "english toolbar");
    await p.evaluate(() => setPref("language", "hu"));
    await p.waitForFunction(() => document.querySelector("[data-tb='adsync']").textContent.includes("AD beolvasás"));
  });
  await step("settings page test connection", async () => {
    await p.click(".rail-it[data-sec='settings']");          // Settings live at the bottom of the left rail
    await p.waitForSelector("#st-test");
    check((await p.locator(".snav").count()) > 5, "settings category jump list");
    check(await p.isVisible("#st-save") || !(await p.locator("#st-save").count()), "save button visible");
    await p.click("#st-test");
    await p.waitForFunction(() => document.querySelector("#st-test-out").textContent.includes("✓"));
    check((await p.inputValue("#st-theme")) === "dark", "theme persisted");
  });
  await step("untrusted PAC switch asks for confirmation", async () => {
    // Cancel (and Enter, which means Cancel here) leaves it off; only the explicit button turns it on
    await p.click("#proxy-untrusted-pac");
    await p.waitForSelector(".cfm-layer");
    await p.keyboard.press("Enter");
    await p.waitForSelector(".cfm-layer", { state: "detached" });
    check(!(await p.isChecked("#proxy-untrusted-pac")), "Enter must not accept the risk");
    await p.click("#proxy-untrusted-pac");
    await p.click(".cfm-layer [data-yes]");
    await p.waitForSelector(".cfm-layer", { state: "detached" });
    check(await p.isChecked("#proxy-untrusted-pac"), "confirmed: switch on");
    await p.click("#proxy-untrusted-pac");                     // turning it off needs no confirmation
    check(!(await p.locator(".cfm-layer").count()), "no dialog when switching off");
    check(!(await p.isChecked("#proxy-untrusted-pac")), "switch off");
  });
  await step("F5 refresh keeps the page", async () => {
    await p.click(".rail-it[data-sec='devices']");
    await p.click(".tn[data-node='all']");
    await p.keyboard.press("F5");
    await p.waitForTimeout(100);
    await waitRows(190);
  });
  await step("narrow window still usable", async () => {
    await p.setViewportSize({ width: 700, height: 800 });
    await p.waitForTimeout(200);
    const overflow = await p.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    check(!overflow, "horizontal page overflow at 700px");
  });

  const writes = requests.filter(([m, path]) => m !== "GET" && /group/i.test(path));
  check(writes.length === 0, "UI sent AD group write requests: " + JSON.stringify(writes));
  check(errors.length === 0, "browser errors: " + errors.join(" | "));
  await browser.close();
  if (failures.length) {
    console.log("FAILURES:\n- " + failures.join("\n- "));
    process.exit(1);
  }
  console.log(`OK (${requests.length} requests)`);
})().catch((e) => { console.log("CRASH " + e.stack); process.exit(2); });
