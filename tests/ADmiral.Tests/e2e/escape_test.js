// node escape_test.js <wwwroot>: the UI's escaping helpers, run without a browser (see WebXssTests.cs).
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const root = process.argv[2];
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const ctx = { window: {}, console };
vm.createContext(ctx);
vm.runInContext(read("tt.js"), ctx);
vm.runInContext(read("i18n.js") + "\n;this.t = t; this.tText = tText; this.setLang = (l) => { LANG = l; };", ctx);

// esc and the welcome page's bars(), taken from app.js as they are
const app = read("app.js");
const escLine = app.match(/^const esc = .*$/m)[0];
const barsStart = app.indexOf("const bars = (items, prefix) => {");
assert(barsStart > 0, "bars() not found in app.js");
const barsEnd = app.indexOf("\n    };", barsStart);
vm.runInContext(`${escLine}\n${app.slice(barsStart, barsEnd)}\n    };\nthis.esc = esc; this.bars = bars;`, ctx);

const PAYLOAD = `x"><meta http-equiv=refresh content="1;url=https://evil.example/"><img src=x onerror=alert(1) a='`;
const noMarkup = (html, what) => {
  assert(!/<meta|<img|"><|'>/i.test(html.replace(/<div class="bar-row" data-node="[^"]*">|<span class="b[ltfn]"[^>]*>|<\/?span>|<\/div>/g, "")), `${what}: ${html}`);
};

// 1. bars(): the prefix (the AD domain / OU from the synced data) and the label are escaped as one attribute value
const html = ctx.bars([[PAYLOAD, 3], ["OU=a&b", 1]], "ou:" + PAYLOAD + "/");
assert(!html.includes("<meta"), html);
assert(!html.includes("<img"), html);
const attrs = [...html.matchAll(/data-node="([^"]*)"/g)].map((m) => m[1]);
assert.strictEqual(attrs.length, 2, html);
assert(attrs[0].startsWith("ou:x&quot;&gt;&lt;meta"), attrs[0]);
assert(html.includes('data-node="ou:x&quot;'), html);
noMarkup(html, "bars");
// the click handler reads dataset.node: the browser un-escapes it back to the exact id
assert.strictEqual(attrs[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">"),
  "ou:" + PAYLOAD + "/OU=a&b");

// 2. t() escapes every substituted value by default; tText() leaves them for plain-text sinks
for (const lang of ["hu", "en"]) {
  ctx.setLang(lang);
  const h = ctx.t("pr.hist_title", { ip: PAYLOAD });
  assert(!h.includes("<meta") && !h.includes('"') && !h.includes("'"), h);
  assert(h.includes("&lt;meta http-equiv=refresh"), h);
  assert(ctx.tText("pr.hist_title", { ip: PAYLOAD }).includes(PAYLOAD));
  assert.strictEqual(ctx.t("pr.count", { n: 3 }), ctx.tText("pr.count", { n: 3 }));         // numbers unchanged
  assert(ctx.t("s.sy_last_ok", { when: "x", peer: "<b>p</b>", pulled: 1, pushed: 2 }).includes("&lt;b&gt;p&lt;/b&gt;"));
  assert(ctx.t("pr.count").includes("{n}"));                                                // no vars: as before
  assert(ctx.t("pr.count", { n: null }).includes("{n}"));                                    // missing value: placeholder kept
}

// 3. the Trusted Types default policy (tt.js) defuses elements that navigate / load, keeps ADmiral's own markup
const defuse = ctx.window.admiralDefuse;
assert.strictEqual(typeof defuse, "function");
for (const bad of ['<meta http-equiv="refresh" content="0;url=https://evil.example/">', "<META\nhttp-equiv=refresh>", "<base href=//evil>",
                   "<iframe src=//evil></iframe>", "<object data=x>", "<embed src=x>", "<link rel=prefetch href=//evil>", "<script>x</script>",
                   "<style>@import url(//evil)</style>", "<frameset>", "<meta/http-equiv=refresh>"]) {
  const out = defuse(bad);
  assert(!/<(meta|base|iframe|object|embed|link|script|style|frameset)/i.test(out), `${bad} -> ${out}`);
}
for (const ok of ['<div class="tile" data-node="all"><div class="n">3</div></div>', '<svg viewBox="0 0 16 16"><path d="M1 1"/></svg>',
                  '<form id="cw-tagform"><input id="x"></form>', "<span>metadata &lt;meta&gt;</span>", '<a href="#" data-goto="f:1">x</a>',
                  "<label>linked</label><b>style</b>"]) {
  assert.strictEqual(defuse(ok), ok);
}

// 4. every page script loads after tt.js (the policy must exist before the first innerHTML)
const index = read("index.html");
const scripts = [...index.matchAll(/<script src="\/static\/([^"]+)"/g)].map((m) => m[1]);
assert.strictEqual(scripts[0], "tt.js", scripts.join(","));
for (const f of fs.readdirSync(root).filter((f) => f.endsWith(".js") && f !== "tt.js")) assert(scripts.includes(f), `${f} not loaded`);

// 5. no t(key, vars) result goes into a plain-text sink (it would show &amp;...): those use tText
for (const f of fs.readdirSync(root).filter((f) => f.endsWith(".js"))) {
  const src = read(f);
  const bad = src.match(/(textContent\s*=|toast\(|confirmDialog\(|esc\()\s*t\("[^"]*",/g);
  assert(!bad, `${f}: ${bad}`);
}
console.log("escape tests ok");
