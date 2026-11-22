using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using ADmiral.Web;

namespace ADmiral.Tests;

/// <summary>tests/test_web.py and the <c>client</c> cases of test_misc / test_service / test_deploy / test_printers /
/// test_packages / test_ou_scope / test_software / test_logins / test_readonly: the JSON API over real HTTP.</summary>
public sealed class WebTests : IDisposable
{
    private readonly WebFixture W = new();

    public void Dispose() => W.Dispose();

    private AdmiralService App => W.App;

    // ---------------------------------------------------------------- test_web.py
    [Fact]
    public void Csrf_header_required()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/tags") { Content = WebFixture.JsonContent(new { ids = new[] { "LT-001" }, add = new[] { "x" } }) };
        req.Headers.Add("X-ADmiral-Token", WebFixture.Token);
        req.Headers.Add("X-ADmiral", "");
        using var r = W.Raw.Send(req);
        Assert.Equal(403, r.Code());
    }

    [Fact]
    public void Index_and_status()
    {
        using var index = W.Get("/");
        Assert.Contains("ADmiral", WebFixture.Text(index));
        var s = W.GetJson("/api/status");
        Assert.Equal("demo", (string?)s["mode"]);
        Assert.NotNull(s["export_formats"]!["txt"]);
        Assert.True((bool)s["desktop"]!);
    }

    [Fact]
    public void Fleet_crud_and_preview()
    {
        var rules = new { match = "all", conditions = new[] { new { field = "os", op = "contains", value = "server" } } };
        var p = WebFixture.Json(W.Post("/api/fleets/preview", rules));
        Assert.True((int)p["count"]! > 0);
        using var r = W.Post("/api/fleets", new { name = "Servers", kind = "dynamic", rules });
        Assert.Equal(201, r.Code());
        var fid = (long)WebFixture.Json(r)["id"]!;
        Assert.Equal((int)p["count"]!, W.GetJson($"/api/fleets/{fid}/members").AsArray().Count);
        Assert.Equal(400, W.Post("/api/fleets", new { name = "Servers", kind = "dynamic", rules }).Code());
        using var bad = W.Post("/api/fleets/preview", new { conditions = new[] { new { field = "x", op = "y", value = 1 } } });
        Assert.Equal(400, bad.Code());
        Assert.Contains("x", WebFixture.Detail(bad));
        using var exp = W.Get($"/api/fleets/{fid}/export?format=txt");
        Assert.Equal(200, exp.Code());
        Assert.Contains("attachment", exp.Content.Headers.ContentDisposition!.ToString());
        Assert.Equal("all servers", (string?)WebFixture.Json(W.Put($"/api/fleets/{fid}", new { description = "all servers" }))["description"]);
        Assert.Equal(204, W.Delete($"/api/fleets/{fid}").Code());
        Assert.Equal(404, W.Get($"/api/fleets/{fid}").Code());
    }

    [Fact]
    public void Group_compare_without_group()
    {
        var fid = (long)WebFixture.Json(W.Post("/api/fleets", new { name = "S", kind = "static", members = new[] { "LT-001" } }))["id"]!;
        using var r = W.Get($"/api/fleets/{fid}/group-compare");
        Assert.Equal(400, r.Code());
        Assert.Equal(I18n.T("err.no_group", ("name", "S")), WebFixture.Detail(r));
    }

    [Fact]
    public void Unknown_computer_in_tag()
    {
        using var r = W.Post("/api/tags", new { ids = new[] { "NOPE" }, add = new[] { "x" } });
        Assert.Equal(400, r.Code());
        Assert.Contains("NOPE", WebFixture.Detail(r));
    }

    [Fact]
    public void Jobs()
    {
        var job = WebFixture.Json(W.Post("/api/jobs/scan", new { }));
        var j = W.WaitJob(job);
        Assert.Equal("done", (string?)j["status"]);
        Assert.True((int)j["result"]!["scanned"]! > 0);
        Assert.True((int)W.GetJson("/api/summary")["online"]! > 0);
    }

    // ---------------------------------------------------------------- test_misc.py
    [Fact]
    public void Jobs_scopes_and_allow_scan()
    {
        Assert.Equal(1, (int)WebFixture.Json(W.Post("/api/allow-scan", new { ids = new[] { "LT-001" }, allow = false }))["updated"]!);
        var j = W.WaitJob(WebFixture.Json(W.Post("/api/jobs/full", new { ids = new[] { "LT-001", "LT-002" } })));
        Assert.Equal("done", (string?)j["status"]);
        Assert.Equal(1, (int)j["result"]!["scanned"]!);
        Assert.Equal(1, (int)j["result"]!["skipped"]!);
        var fid = (long)WebFixture.Json(W.Post("/api/fleets", new { name = "F", kind = "static", members = new[] { "LT-003" } }))["id"]!;
        Assert.Equal("done", (string?)W.WaitJob(WebFixture.Json(W.Post("/api/jobs/collect", new { fleet_id = fid })))["status"]);
        Assert.Equal(404, W.Post("/api/jobs/scan", new { fleet_id = 999 }).Code());
        Assert.Equal(400, W.Post("/api/jobs/scan", new { ids = new[] { "NOPE" } }).Code());
        Assert.Equal(422, W.Post("/api/jobs/bogus", new { }).Code());
        Assert.Equal(404, W.Get("/api/jobs/12345").Code());
        Assert.Equal(200, W.Get("/api/jobs").Code());
        var ad = W.WaitJob(WebFixture.Json(W.Post("/api/jobs/ad-sync")));
        Assert.Equal(190, (int)ad["result"]!["total"]!);
    }

    [Fact]
    public void One_scan_job_at_a_time()
    {
        var gate = new ManualResetEventSlim();
        App.ProbeOverride = (host, ports, timeout) =>
        {
            gate.Wait(TimeSpan.FromSeconds(5));
            return Demo.Probe(host, ports, timeout);
        };
        var first = WebFixture.Json(W.Post("/api/jobs/scan", new { ids = new[] { "LT-001" } }));
        using var busy = W.Post("/api/jobs/collect", new { });
        Assert.Equal(409, busy.Code());
        Assert.Equal(409, W.Post("/api/jobs/scan", new { }).Code());
        gate.Set();
        W.WaitJob(first);
    }

    [Fact]
    public void Misc_routes()
    {
        App.FullScan();
        var guid = W.Fx.Guid("LT-001");
        var c = W.GetJson($"/api/computers/{guid}");
        Assert.NotEmpty(c["items"]!["apps"]!.AsArray());
        Assert.NotNull(c["fleets"]);
        Assert.Equal(404, W.Get("/api/computers/nope").Code());
        Assert.Equal(190, (int)W.GetJson("/api/summary")["total"]!);
        Assert.True(W.GetJson("/api/activity?limit=5").AsArray().Count <= 5);
        Assert.Equal(422, W.Get("/api/activity?limit=abc").Code());
        Assert.Equal(200, W.Get("/api/tags").Code());
        var fid = (long)WebFixture.Json(W.Post("/api/fleets", new { name = "M", kind = "static" }))["id"]!;
        Assert.Equal(2, (int)WebFixture.Json(W.Post($"/api/fleets/{fid}/members", new { add = new[] { "LT-001", "LT-002" } }))["count"]!);
        Assert.Equal(1, (int)WebFixture.Json(W.Post($"/api/fleets/{fid}/members", new { remove = new[] { "LT-002" } }))["count"]!);
        Assert.Equal(400, W.Get($"/api/fleets/{fid}/export?format=xml").Code());
        Assert.Equal(200, W.Get($"/api/fleets/{fid}/export?format=json&online_only=true").Code());
        Assert.Equal(400, W.Put("/api/settings", new { theme = "dark" }).Code());           // read-only in server mode
        Assert.False((bool)W.GetJson("/api/settings")["editable"]!);
        using var t = W.Post("/api/test-connection", new { mode = "ldap", ldap = new { server = "127.0.0.1", base_dn = "DC=x", port = 1, use_ssl = false } });
        Assert.Equal(200, t.Code());
        Assert.False((bool)WebFixture.Json(t)["ok"]!);
        Assert.Equal("no-cache", W.Get("/").Headers.CacheControl!.ToString());
        foreach (var f in new[] { "app.js", "i18n.js", "icons.js", "app.css", "logo.svg", "admiral.ico" })
            Assert.Equal(200, W.Raw.Send(new HttpRequestMessage(HttpMethod.Get, $"/static/{f}")).Code());
        var s = W.GetJson("/api/status");
        Assert.False((bool)s["settings_editable"]!);
        Assert.Contains("app", s["rules"]!.ToJsonString());
    }

    [Fact]
    public void Ad_users_import_by_ou()
    {
        var j = W.WaitJob(WebFixture.Json(W.Post("/api/jobs/ad-users", new { base_dn = "OU=Users,DC=contoso,DC=local" })));
        Assert.Equal("done", (string?)j["status"]);
        Assert.True((int)j["result"]!["total"]! >= 1);
        var rows = W.GetJson("/api/users").AsArray();
        Assert.Contains(rows, r => (bool?)r!["in_ad"] == true);
        Assert.Equal(rows.ToJsonString(), W.GetJson("/api/users").ToJsonString());      // cached index gives the same answer
    }

    [Fact]
    public void Winupdates_page_data()
    {
        W.WaitJob(WebFixture.Json(W.Post("/api/jobs/ad-sync")));
        W.WaitJob(WebFixture.Json(W.Post("/api/jobs/updates")));
        W.WaitJob(WebFixture.Json(W.Post("/api/jobs/full")));
        var d = W.GetJson("/api/winupdates");
        Assert.NotEmpty(d["reference"]!.AsArray());
        Assert.Equal(d["reference"]!.AsArray().Count, (int)d["status"]!["builds"]!);
        var first = d["computers"]![0]!.AsObject();
        foreach (var k in new[] { "guid", "name", "build", "installed", "state", "latest" }) Assert.True(first.ContainsKey(k), k);
        Assert.Contains(d["computers"]!.AsArray(), c => c!["installed"] is JsonValue v && v.ToString() is { Length: > 0 } and not "false");
    }

    [Fact]
    public void Ad_ous_api_and_scoped_job()
    {
        var r = W.GetJson("/api/ad/ous");
        Assert.Equal("DC=contoso,DC=local", (string?)r["root"]);
        Assert.NotEmpty(r["children"]!.AsArray());
        var kids = W.GetJson("/api/ad/ous?parent=" + Uri.EscapeDataString("OU=Servers,DC=contoso,DC=local"))["children"]!.AsArray();
        Assert.Equal(new[] { "App", "File", "SQL" }, kids.Select(k => (string)k!["name"]!).Order());
        using var job = W.Post("/api/jobs/ad-sync", new { base_dn = "OU=Servers,DC=contoso,DC=local" });
        Assert.Equal(202, job.Code());
        W.WaitJob(WebFixture.Json(job));
    }

    // ---------------------------------------------------------------- test_service.py
    [Fact]
    public void Retry_service_api()
    {
        var r = W.GetJson("/api/retry-service");
        Assert.False((bool)r["supported"]!);
        Assert.False((bool)r["installed"]!);
        Assert.Equal(422, W.Post("/api/retry-service", new { action = "bogus" }).Code());
        Assert.Contains(W.Post("/api/retry-service", new { action = "delete" }).Code(), new[] { 400, 409 });
    }

    [Fact]
    public void Users_api()
    {
        App.Scan();
        App.Collect();
        var rows = W.GetJson("/api/users").AsArray();
        Assert.NotEmpty(rows);
        foreach (var k in new[] { "key", "display_name", "computers", "logons" }) Assert.True(rows[0]!.AsObject().ContainsKey(k), k);
        var key = (string)rows[0]!["key"]!;
        var one = W.GetJson("/api/users/" + Uri.EscapeDataString(key));
        Assert.NotEmpty(one["events"]!.AsArray());
        Assert.NotEmpty(one["computer_list"]!.AsArray());
        Assert.Equal(404, W.Get("/api/users/nope").Code());
        Assert.True((int)WebFixture.Json(W.Post("/api/users/refresh"))["updated"]! >= 1);
    }

    // ---------------------------------------------------------------- test_software.py
    [Fact]
    public void Software_api_and_vuln_job()
    {
        App.Scan();
        App.Collect();
        var list = W.GetJson("/api/software").AsArray();
        Assert.NotEmpty(list);
        var key = (string)list[0]!["key"]!;
        Assert.Equal(200, W.Get("/api/software/" + Uri.EscapeDataString(key)).Code());
        Assert.Equal(404, W.Get("/api/software/nope").Code());
        var j = WebFixture.Json(W.Post("/api/jobs/vulns", new { }));
        Assert.Equal("vulns", (string?)j["kind"]);
        W.WaitJob(j);
        Assert.NotEmpty(W.GetJson("/api/vulnerabilities")["items"]!.AsArray());
        Assert.Equal(404, W.Get("/api/vulnerabilities/CVE-0000-0000").Code());
    }

    [Fact]
    public void Software_key_with_slash_and_backslash_roundtrips()
    {
        // %2F and %5C inside a key are part of the key ({key:path})
        using var r = W.Get("/api/software/" + Uri.EscapeDataString("a/b\\c"));
        Assert.Equal(404, r.Code());
        Assert.Contains("a/b\\c", WebFixture.Detail(r));
    }

    [Fact]
    public void Vulnerability_offers_newer_library_version()
    {
        using var tmp = new CoreTemp();
        App.Settings.Packages.Folder = tmp.File("pk");
        App.Scan();
        App.Collect();
        App.RefreshVulns();
        void Upload(string pid, string title, string version, string name) =>
            Assert.Equal(201, W.PostBytes($"/api/packages-upload?id={pid}&name={name}&version={version}&title={title}", Encoding.ASCII.GetBytes(new string('x', 100))).Code());
        Upload("Google.Chrome", "Google%20Chrome", "1.0.0", "chrome-old.msi");
        Upload("Acme.Other", "Acme%20Other", "999.0", "other.exe");
        Upload("Google.Chrome", "Google%20Chrome", "999.0.0.1", "chrome-new.msi");
        var det = W.GetJson("/api/vulnerabilities/CVE-2026-1234");
        var fixes = det["affected"]![0]!["fixes"]!.AsArray();
        Assert.Single(fixes);
        Assert.Equal("Google.Chrome", (string?)fixes[0]!["package_id"]);
        Assert.Equal("999.0.0.1", (string?)fixes[0]!["version"]);
    }

    // ---------------------------------------------------------------- test_logins.py
    [Fact]
    public void Logins_api()
    {
        using var tmp = new CoreTemp();
        Assert.Equal(400, W.Get("/api/logins/script").Code());                  // no folder set yet
        App.Settings.Logins.Enabled = true;
        App.Settings.Logins.Path = tmp.Path;
        var s = W.GetJson("/api/logins/script");
        Assert.Equal("ADmiral-Logins.ps1", (string?)s["filename"]);
        Assert.Contains(tmp.Path, (string)s["content"]!);
        Assert.True((bool)WebFixture.Json(W.Post("/api/logins/import"))["configured"]!);
    }

    [Fact]
    public void Offline_script_and_import()
    {
        var s = W.GetJson("/api/offline/script");
        Assert.Equal(Offline.ScriptName, (string?)s["filename"]);
        Assert.Contains("ADmiral", (string)s["content"]!);
        Assert.Equal(200, W.Post("/api/offline/import").Code());
    }

    // ---------------------------------------------------------------- test_packages.py / test_deploy.py
    private JsonNode AddPackage(string folder)
    {
        App.Settings.Packages.Folder = Path.Combine(folder, "pk");
        using var r = W.PostBytes("/api/packages-upload?id=Acme.Tool&name=AcmeSetup.exe&version=1.2.3&title=Acme%20Tool",
                                  Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("installer", 500))));
        Assert.Equal(201, r.Code());
        return W.GetJson("/api/packages")["packages"]![0]!;
    }

    [Fact]
    public void Upload_api()
    {
        using var tmp = new CoreTemp();
        App.Settings.Packages.Folder = tmp.File("pk");
        Assert.Empty(W.GetJson("/api/packages")["packages"]!.AsArray());
        Assert.Equal(201, W.PostBytes("/api/packages-upload?id=Corp.Tool&name=setup.msi&version=1.0", Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("data", 1000)))).Code());
        var row = W.GetJson("/api/packages")["packages"]![0]!;
        Assert.Equal(4000, (long)row["size"]!);
        Assert.EndsWith("setup.msi", (string)row["files"]![0]!["path"]!);
        Assert.Equal(400, W.PostBytes("/api/packages-upload?id=bad%20id&name=a.exe", [1]).Code());
        Assert.Equal(422, W.PostBytes("/api/packages-upload?name=a.exe", [1]).Code());       // id is required
        Assert.True((bool)WebFixture.Json(W.Post("/api/packages-verify", new { }))[0]!["ok"]!);
        using var rm = W.Post("/api/packages-remove-file", new { id = "Corp.Tool", file = (string)row["files"]![0]!["path"]! });
        Assert.Equal(200, rm.Code());
        Assert.Empty(W.GetJson("/api/packages")["packages"]![0]!["files"]!.AsArray());
        Assert.Equal(200, W.Delete("/api/packages/Corp.Tool").Code());
        Assert.Empty(W.GetJson("/api/packages")["packages"]!.AsArray());
    }

    [Fact]
    public void Upload_with_wrong_sha256_is_refused_and_leaves_nothing()
    {
        using var tmp = new CoreTemp();
        App.Settings.Packages.Folder = tmp.File("pk");
        using var r = W.PostBytes("/api/packages-upload?id=Corp.Tool&name=setup.msi&sha256=" + new string('0', 64), [1, 2, 3]);
        Assert.Equal(400, r.Code());
        Assert.Contains("SHA-256", WebFixture.Detail(r));
        Assert.Empty(W.GetJson("/api/packages")["packages"]!.AsArray());
    }

    [Fact]
    public void Upload_size_cap()
    {
        using var tmp = new CoreTemp();
        App.Settings.Packages.Folder = tmp.File("pk");
        var old = PackageLibrary.MaxUploadBytes;
        PackageLibrary.MaxUploadBytes = 1000;
        try
        {
            using var r = W.PostBytes("/api/packages-upload?id=Corp.Tool&name=big.msi", new byte[5000]);
            Assert.Contains(r.Code(), new[] { 400, 413 });
        }
        finally
        {
            PackageLibrary.MaxUploadBytes = old;
        }
    }

    [Fact]
    public void Deployment_api_end_to_end()
    {
        using var tmp = new CoreTemp();
        var pkg = AddPackage(tmp.Path);
        var exe = pkg["files"]!.AsArray().First(f => ((string)f!["path"]!).EndsWith(".exe", StringComparison.Ordinal))!;
        var names = W.GetJson("/api/computers").AsArray().Take(3).Select(c => (string)c!["name"]!).ToArray();
        Assert.Equal(400, W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, ids = Array.Empty<string>() }).Code());
        Assert.Equal(422, W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, ids = names, timeout = 5 }).Code());
        using var r = W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, args = "/S", ids = names });
        Assert.Equal(202, r.Code());
        var body = WebFixture.Json(r);
        var dep = (long)body["id"]!;
        W.WaitJob(body["job"]!);
        var d = W.GetJson($"/api/deployments/{dep}");
        Assert.Equal(3, d["targets"]!.AsArray().Count);
        Assert.All(d["targets"]!.AsArray(), t => Assert.Equal("done", (string?)t!["step"]));
        Assert.Contains((string)d["status"]!, new[] { "done", "partial", "failed" });
        Assert.Equal("/S", (string?)d["args"]);
        Assert.Equal(3, (int)W.GetJson("/api/deployments")[0]!["total"]!);
        // a tampered installer is refused before anything is sent
        File.WriteAllBytes(Path.Combine(tmp.Path, "pk", (string)exe["path"]!), Encoding.ASCII.GetBytes("evil"));
        Assert.Equal(400, W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, ids = names }).Code());
        Assert.Equal(404, W.Get("/api/deployments/999").Code());
    }

    [Fact]
    public void Xlsx_export_and_list_counts()
    {
        var r = WebFixture.Json(W.Post("/api/export/xlsx", JsonNode.Parse("""{"header": ["A", "B"], "rows": [["x & <y>", 1], ["", 2.5]], "sheet": "T"}""")!.ToJsonString()));
        using var zip = new ZipArchive(new MemoryStream(Convert.FromBase64String((string)r["content"]!)));
        using var sr = new StreamReader(zip.GetEntry("xl/worksheets/sheet1.xml")!.Open());
        var sheet = sr.ReadToEnd();
        Assert.Contains("x &amp; &lt;y&gt;", sheet);
        Assert.Contains("<v>2.5</v>", sheet);
        Assert.Equal(422, W.Post("/api/export/xlsx", new { header = new[] { "A" }, rows = new[] { 1 } }).Code());

        using var tmp = new CoreTemp();
        var pkg = AddPackage(tmp.Path);
        var exe = pkg["files"]!.AsArray().First(f => ((string)f!["path"]!).EndsWith(".exe", StringComparison.Ordinal))!;
        var names = W.GetJson("/api/computers").AsArray().Take(3).Select(c => (string)c!["name"]!).ToArray();
        var start = WebFixture.Json(W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, ids = names }));
        W.WaitJob(start["job"]!);
        var d = W.GetJson("/api/deployments")[0]!;
        Assert.Equal(3, (int)d["total"]!);
        Assert.Equal(0, (int)d["queued"]!);
        Assert.Equal(0, (int)d["running"]!);
        Assert.Equal(3, (int)d["ok"]! + (int)d["reboot"]! + (int)d["failed"]!);
        Assert.NotNull(d["avg_seconds"]);
    }

    [Fact]
    public void Deployment_log_and_retry()
    {
        using var tmp = new CoreTemp();
        var pkg = AddPackage(tmp.Path);
        var exe = pkg["files"]!.AsArray().First(f => ((string)f!["path"]!).EndsWith(".exe", StringComparison.Ordinal))!;
        var names = W.GetJson("/api/computers").AsArray().Take(3).Select(c => (string)c!["name"]!).ToArray();
        var start = WebFixture.Json(W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, args = "/S", ids = names }));
        var dep = (long)start["id"]!;
        W.WaitJob(start["job"]!);
        var text = (string)W.GetJson($"/api/deployments/{dep}/log")["text"]!;
        Assert.Contains((string)exe["sha256"]!, text);
        Assert.All(names, n => Assert.Contains(n, text));
        Assert.Equal(404, W.Get("/api/deployments/999/log").Code());
        var d = W.GetJson($"/api/deployments/{dep}");
        var targets = d["targets"]!.AsArray();
        App.Store.UpdateTarget(dep, (string)targets[0]!["guid"]!, new Dictionary<string, object?> { ["outcome"] = "failed", ["step"] = "done" });
        App.Store.UpdateTarget(dep, (string)targets[1]!["guid"]!, new Dictionary<string, object?> { ["outcome"] = "ok", ["step"] = "done" });
        App.Store.UpdateTarget(dep, (string)targets[2]!["guid"]!, new Dictionary<string, object?> { ["outcome"] = "ok", ["step"] = "done" });
        using var r2 = W.Post($"/api/deployments/{dep}/retry");
        Assert.Equal(202, r2.Code());
        var b2 = WebFixture.Json(r2);
        W.WaitJob(b2["job"]!);
        var d2 = W.GetJson($"/api/deployments/{(long)b2["id"]!}");
        Assert.Equal(new[] { (string)targets[0]!["name"]! }, d2["targets"]!.AsArray().Select(t => (string)t!["name"]!));
        foreach (var t in targets)
            App.Store.UpdateTarget(dep, (string)t!["guid"]!, new Dictionary<string, object?> { ["outcome"] = "ok", ["step"] = "done" });
        Assert.Equal(400, W.Post($"/api/deployments/{dep}/retry").Code());
    }

    [Fact]
    public void Aborted_deployment_does_not_stay_queued()
    {
        using var tmp = new CoreTemp();
        var pkg = AddPackage(tmp.Path);
        var exe = pkg["files"]!.AsArray().First(f => ((string)f!["path"]!).EndsWith(".exe", StringComparison.Ordinal))!;
        var names = W.GetJson("/api/computers").AsArray().Take(2).Select(c => (string)c!["name"]!).ToArray();
        App.RunDeploymentHook = _ => throw new InvalidOperationException("directory unreachable");
        var start = WebFixture.Json(W.Post("/api/deployments", new { package_id = "Acme.Tool", file = (string)exe["path"]!, ids = names }));
        W.WaitJob(start["job"]!);
        var d = W.GetJson($"/api/deployments/{(long)start["id"]!}");
        Assert.Equal("failed", (string?)d["status"]);
        Assert.All(d["targets"]!.AsArray(), t => Assert.Contains("directory unreachable", (string)t!["error"]!));
    }

    // ---------------------------------------------------------------- test_printers.py
    [Fact]
    public void Printer_api()
    {
        using var agent = new FakeSnmpAgent();
        App.SnmpPort = agent.Port;
        var o = Printers.DefaultOids;
        agent.Values[o["oid_model"]] = "HP LaserJet M125nw";
        agent.Values[o["oid_toner"]] = 40;
        agent.Values[o["oid_toner_max"]] = 100;
        agent.Values[o["oid_pages"]] = 9876;
        agent.Values[o["oid_serial"]] = "CNB1234";
        agent.Values[o["oid_status"]] = 3;
        using var r = W.Post("/api/printers", new { ip = "127.0.0.1", location = "Titkárság", note = "TN-227K", unknown_field = "ignored" });
        Assert.Equal(201, r.Code());
        var p = WebFixture.Json(r);
        Assert.Equal("HP LaserJet M125nw", (string?)p["model"]);
        Assert.Equal(9876, (long)p["pages"]!);
        Assert.Equal(40, (int)p["toner"]![0]!["pct"]!);
        Assert.Equal("Titkárság", (string?)p["location"]);
        Assert.Equal(400, W.Post("/api/printers", new { ip = "127.0.0.1" }).Code());       // duplicate
        Assert.Equal(400, W.Post("/api/printers", new { ip = "bad ip!" }).Code());
        Assert.Equal(422, W.Post("/api/printers", new { ip = 5 }).Code());                 // a number is no string
        var id = (long)p["id"]!;
        var upd = WebFixture.Json(W.Put($"/api/printers/{id}", new { location = "Iroda 2", note = "kék" }));
        Assert.Equal("Iroda 2", (string?)upd["location"]);
        Assert.Equal(9876, (long)upd["pages"]!);
        var h = W.GetJson($"/api/printers/{id}/history");
        Assert.Single(h["days"]!.AsArray());
        Assert.Equal(404, W.Get("/api/printers/999/history").Code());
        agent.Silent = true;                                                                // unreachable: keeps the readings
        var down = WebFixture.Json(W.Put($"/api/printers/{id}", new { community = "other" }));
        Assert.NotEqual("", (string?)down["error"]);
        Assert.Equal(9876, (long)down["pages"]!);
        Assert.NotEqual("", (string?)WebFixture.Json(W.Post("/api/printers/test", new { ip = "127.0.0.1" }))["error"]);
        Assert.Single(W.GetJson("/api/printers").AsArray());
        Assert.Equal(200, W.Post("/api/printers/poll", new { }).Code());
        Assert.Equal(200, W.Post("/api/printers/poll", new { ids = new[] { id } }).Code());
        Assert.Equal(404, W.Put("/api/printers/999", new { note = "x" }).Code());
        Assert.Equal(200, W.Delete($"/api/printers/{id}").Code());
        Assert.Empty(W.GetJson("/api/printers").AsArray());
    }

    [Fact]
    public void Printer_scan_validates_the_range_and_version()
    {
        Assert.Equal(400, W.Post("/api/printers/scan", new { range = "10.0.0.0/16" }).Code());
        Assert.Equal(400, W.Post("/api/printers/scan", new { range = "127.0.0.1", version = "3" }).Code());
        Assert.Equal(422, W.Post("/api/printers/scan", new { }).Code());
    }

    // ---------------------------------------------------------------- misc routes the UI calls
    [Fact]
    public void Remaining_ui_routes_answer()
    {
        foreach (var path in new[] { "/api/appupdate", "/api/sync", "/api/updates", "/api/diagnostics", "/api/logs", "/api/fleets", "/api/computers" })
            Assert.True(W.Get(path).IsSuccessStatusCode, path);
        Assert.Equal(0, (int)WebFixture.Json(W.Post("/api/computers/restore"))["restored"]!);
        Assert.Equal(1, (int)WebFixture.Json(W.Post("/api/computers/remove", new { ids = new[] { "LT-001" } }))["removed"]!);
        Assert.Equal(1, (int)W.GetJson("/api/status")["hidden_computers"]!);
        Assert.Equal(1, (int)WebFixture.Json(W.Post("/api/computers/restore"))["restored"]!);
        Assert.Equal(200, W.Post("/api/appupdate/check").Code());
        Assert.Equal(422, W.Post("/api/appupdate/install").Code());          // the body is required
        Assert.Contains(W.Post("/api/sync/test").Code(), new[] { 200, 400 });             // not configured: an explained 400
        Assert.Contains(W.Post("/api/packages-verify").Code(), new[] { 200, 400 });       // no library folder in a memory db
    }

    // ---------------------------------------------------------------- test_readonly.py
    [Fact]
    public void No_write_endpoints_for_ad()
    {
        var routes = W.Web.Services.GetService(typeof(Microsoft.AspNetCore.Routing.EndpointDataSource)) as Microsoft.AspNetCore.Routing.EndpointDataSource;
        var paths = routes!.Endpoints.OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods ?? ["*"]).Select(m => (m, e.RoutePattern.RawText ?? "")))
            .ToList();
        Assert.Contains(paths, p => p.m == "GET" && p.Item2.EndsWith("/group-compare", StringComparison.Ordinal));
        Assert.DoesNotContain(paths, p => p.Item2.Contains("group", StringComparison.Ordinal) && p.m != "GET");
        Assert.DoesNotContain(paths, p => p.Item2.Contains("group-sync", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_api_call_of_the_ui_has_a_route()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        var calls = new HashSet<(string, string)>();
        foreach (var f in Directory.GetFiles(root, "*.js"))
        {
            var js = File.ReadAllText(f);
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(js, "api\\(\"(GET|POST|PUT|DELETE)\",\\s*[\"`](/api/[^\"`?$]*)"))
                calls.Add((m.Groups[1].Value, m.Groups[2].Value));
        }
        Assert.True(calls.Count > 40, $"only {calls.Count} calls found");
        var routes = (Microsoft.AspNetCore.Routing.EndpointDataSource)W.Web.Services.GetService(typeof(Microsoft.AspNetCore.Routing.EndpointDataSource))!;
        var patterns = routes.Endpoints.OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods ?? []).Select(m => (m, e.RoutePattern.RawText ?? "")))
            .ToList();
        foreach (var (method, path) in calls)
        {
            // "/api/fleets/" + an id -> "/api/fleets/{id:long}" etc.: compare the literal prefix
            var ok = patterns.Any(p => p.m == method && (p.Item2 == path || (p.Item2.Contains('{') && path.StartsWith(p.Item2[..p.Item2.IndexOf('{')], StringComparison.Ordinal))
                                                           || (path.EndsWith('/') && p.Item2.StartsWith(path, StringComparison.Ordinal))));
            Assert.True(ok, $"{method} {path} has no route");
        }
    }
}
