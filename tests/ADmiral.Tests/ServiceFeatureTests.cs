using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>The service cases of test_deploy.py, test_printers.py, test_logins.py, test_offline.py and
/// test_security.py (deployments, printers, the shared-folder imports, saved passwords).</summary>
public sealed class ServiceFeatureTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    // ------------------------------------------------------------------ deployments
    /// <summary>A manual package with one installer (what the Packages page does).</summary>
    private PackageFile AddPackage()
    {
        App.Settings.Packages.Folder = _f.Temp.File("pk");
        using (var up = App.UploadPackage("Acme.Tool", "AcmeSetup.exe", "1.2.3", "Acme Tool"))
        {
            up.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("installer", 500))));
            up.Commit();
        }
        var pkgs = (List<PackageRow>)App.PackagesStatus()["packages"]!;
        return Assert.Single(pkgs).Files.First(f => f.Path.EndsWith(".exe", StringComparison.Ordinal));
    }

    private List<string> FirstNames(int n) => [.. App.Computers().Take(n).Select(c => (string)c["name"]!)];

    [Fact]
    public void ComputersOnlyASyncPeerReportedAreNeverDeploymentTargets()
    {
        var exe = AddPackage();
        var comps = App.Computers().Take(2).ToList();
        var (peerOnly, ours) = ((string)comps[0]["name"]!, (string)comps[1]["name"]!);
        App.Store.Execute("CREATE TABLE IF NOT EXISTS sync_unconfirmed (guid TEXT PRIMARY KEY REFERENCES computers(guid) ON DELETE CASCADE, added TEXT NOT NULL)");
        App.Store.Execute("INSERT INTO sync_unconfirmed (guid, added) VALUES (?, ?)", (string)comps[0]["guid"]!, Db.UtcNow());

        Assert.ThrowsAny<ArgumentException>(() => App.StartDeployment("Acme.Tool", exe.Path, "/S", [peerOnly]));
        var r = App.StartDeployment("Acme.Tool", exe.Path, "/S", [peerOnly, ours]);
        Assert.Equal("done", _f.WaitJob(((JobInfo)r["job"]!).Id).Status);
        var targets = (List<Row>)App.Store.Deployment((long)r["id"]!)!["targets"]!;
        Assert.Equal([ours], targets.Select(t => (string)t["name"]!));
    }

    [Fact]
    public void DeploymentEndToEnd()
    {
        var exe = AddPackage();
        var names = FirstNames(3);
        Assert.ThrowsAny<ArgumentException>(() => App.StartDeployment("Acme.Tool", exe.Path, "", []));
        Assert.ThrowsAny<ArgumentException>(() => App.StartDeployment("Acme.Tool", "nope.exe", "", names));
        Assert.ThrowsAny<ArgumentException>(() => App.StartDeployment("Acme.Tool", exe.Path, "a\u0000b", names));
        var r = App.StartDeployment("Acme.Tool", exe.Path, "/S", names);
        var dep = (long)r["id"]!;
        Assert.Equal("done", _f.WaitJob(((JobInfo)r["job"]!).Id).Status);
        var d = App.Store.Deployment(dep)!;
        var targets = (List<Row>)d["targets"]!;
        Assert.Equal(3, targets.Count);
        Assert.All(targets, t => Assert.Equal("done", t["step"]));
        Assert.Contains((string)d["status"]!, new[] { "done", "partial", "failed" });
        Assert.Equal("/S", d["args"]);
        var row = App.Store.Deployments()[0];
        Assert.Equal(3, row["total"]);
        Assert.Equal(0, row["queued"]);
        Assert.Equal(0, row["running"]);
        Assert.Equal(3, (int)row["ok"]! + (int)row["reboot"]! + (int)row["failed"]!);
        // a tampered installer is refused before anything is sent
        File.WriteAllText(Path.Combine(_f.Temp.File("pk"), exe.Path), "evil");
        var ex = Assert.ThrowsAny<ArgumentException>(() => App.StartDeployment("Acme.Tool", exe.Path, "", names));
        Assert.Contains(exe.Path, ex.Message);
        Assert.Throws<NotFound>(() => App.DeploymentLog(999));
        Assert.Throws<NotFound>(() => App.RetryDeployment(999));
    }

    [Fact]
    public void DeploymentLogAndRetry()
    {
        var exe = AddPackage();
        var names = FirstNames(3);
        var r = App.StartDeployment("Acme.Tool", exe.Path, "/S", names);
        var dep = (long)r["id"]!;
        _f.WaitJob(((JobInfo)r["job"]!).Id);
        var text = App.DeploymentLog(dep);
        Assert.Contains($"Deployment #{dep} started", text);
        Assert.Contains(exe.Sha256, text);
        Assert.Contains("finished", text);
        Assert.All(names, n => Assert.Contains(n, text));
        Assert.Contains("Step: ", text);
        // force a failed computer, then repeat only for it
        var targets = (List<Row>)App.Store.Deployment(dep)!["targets"]!;
        void Set(int i, string outcome) =>
            App.Store.UpdateTarget(dep, (string)targets[i]["guid"]!, new Dictionary<string, object?> { ["outcome"] = outcome, ["step"] = "done" });
        Set(0, "failed");
        Set(1, "ok");
        Set(2, "ok");
        var r2 = App.RetryDeployment(dep);
        _f.WaitJob(((JobInfo)r2["job"]!).Id);
        var d2 = App.Store.Deployment((long)r2["id"]!)!;
        Assert.Equal([targets[0]["name"]], ((List<Row>)d2["targets"]!).Select(t => t["name"]));
        Assert.Contains($"repeat of #{dep}", App.DeploymentLog((long)r2["id"]!));
        Set(0, "ok");                                                   // nothing failed there any more -> refused
        Assert.ThrowsAny<ArgumentException>(() => App.RetryDeployment(dep));
    }

    [Fact]
    public void AbortedDeploymentDoesNotStayQueued()
    {
        var exe = AddPackage();
        App.RunDeploymentHook = _ => throw new InvalidOperationException("directory unreachable");
        var r = App.StartDeployment("Acme.Tool", exe.Path, "", FirstNames(2));
        Assert.Equal("error", _f.WaitJob(((JobInfo)r["job"]!).Id).Status);
        var d = App.Store.Deployment((long)r["id"]!)!;
        Assert.Equal("failed", d["status"]);
        Assert.All((List<Row>)d["targets"]!, t =>
        {
            Assert.Equal("done", t["step"]);
            Assert.Contains("directory unreachable", (string)t["error"]!);
        });
        Assert.Contains("aborted", App.DeploymentLog((long)r["id"]!));
    }

    [Fact]
    public void AlreadyInstalledVersionIsNotInstalledAgain()
    {
        App.FullScan();
        var host = App.Computers().First(c => ((List<JsonObject>)App.Computer((string)c["guid"]!)["items"].As<Dictionary<string, List<JsonObject>>>()["apps"])
                                              .Any(a => (string?)a["name"] == "VLC media player"));
        App.Settings.Packages.Folder = _f.Temp.File("pk");
        using (var up = App.UploadPackage("VideoLAN.VLC", "vlc-3.0.21-win64.msi", "3.0.21", "VLC media player"))
        {
            up.Write(Encoding.ASCII.GetBytes("msi"));
            up.Commit();
        }
        var msi = ((List<PackageRow>)App.PackagesStatus()["packages"]!).Single().Files.Single();
        var r = App.StartDeployment("VideoLAN.VLC", msi.Path, "", [(string)host["name"]!]);
        _f.WaitJob(((JobInfo)r["job"]!).Id);
        var t = Assert.Single((List<Row>)App.Store.Deployment((long)r["id"]!)!["targets"]!);
        Assert.Equal("current", t["outcome"]);
        Assert.Equal("skipped", App.Store.Deployment((long)r["id"]!)!["status"]);
    }

    [Fact]
    public void TimeoutSetting()
    {
        Assert.Equal(10, App.Settings.Deploy.TimeoutMinutes);
        App.Settings.Deploy.TimeoutMinutes = 0;
        Assert.ThrowsAny<ArgumentException>(() => Config.ValidateSettings(App.Settings, requireLdap: false));
    }

    [Fact]
    public void InterruptedDeploymentIsClosedAtStart()
    {
        var store = new Store(":memory:");
        var dep = store.CreateDeployment("A.B", "AB", "", "f.exe", "exe", "/S", [("g1", "PC1")]);
        Assert.Equal("running", store.Deployment(dep)!["status"]);
        using var app = new AdmiralService(new Settings { Mode = "demo", DbPath = ":memory:" }, store, new DemoDirectory(), applyProcessSettings: false);
        var d = app.Store.Deployment(dep)!;
        Assert.Equal("failed", d["status"]);
        Assert.Equal("failed", ((List<Row>)d["targets"]!)[0]["outcome"]);
    }

    [Fact]
    public void PackageLibraryNeedsAFolderWithAnInMemoryDatabase()
    {
        Assert.ThrowsAny<ArgumentException>(() => App.Library());
        App.Settings.Packages.Folder = _f.Temp.File("lib");
        Assert.Empty((List<PackageRow>)App.PackagesStatus()["packages"]!);
        Assert.ThrowsAny<ArgumentException>(() => App.PackageRemove("Not.There"));
        Assert.ThrowsAny<ArgumentException>(() => App.UploadPackage("../evil", "x.exe"));
    }

    // ------------------------------------------------------------------ printers
    private static JsonObject J(params (string K, JsonNode? V)[] kv)
    {
        var o = new JsonObject();
        foreach (var (k, v) in kv) o[k] = v;
        return o;
    }

    [Fact]
    public void PrinterLifecycle()
    {
        using var agent = new FakeSnmpAgent();
        App.SnmpPort = agent.Port;
        var o = Printers.DefaultOids;
        lock (agent.Values)
        {
            agent.Values[o["oid_model"]] = "HP LaserJet M125nw";
            agent.Values[o["oid_toner"]] = 40;
            agent.Values[o["oid_toner_max"]] = 100;
            agent.Values[o["oid_pages"]] = 9876;
            agent.Values[o["oid_serial"]] = "CNB1234";
            agent.Values[o["oid_status"]] = 3;
        }
        var p = App.PrinterAdd(J(("ip", "127.0.0.1"), ("location", "Titkárság"), ("note", "TN-227K")));
        Assert.Equal("HP LaserJet M125nw", p["model"]);
        Assert.Equal(9876L, p["pages"]);
        Assert.Equal(40, (int)((JsonArray)p["toner"]!)[0]!["pct"]!);
        Assert.Equal("CNB1234", p["serial"]);
        Assert.Equal("idle", p["status"]);
        Assert.Equal("", p["error"]);
        Assert.Equal("TN-227K", p["note"]);
        var pid = (long)p["id"]!;
        Assert.ThrowsAny<ArgumentException>(() => App.PrinterAdd(J(("ip", "127.0.0.1"))));        // duplicate
        Assert.ThrowsAny<ArgumentException>(() => App.PrinterAdd(J(("ip", "bad ip!"))));
        // inline edit of location / note: no new reading needed, readings stay
        var e = App.PrinterUpdate(pid, J(("location", "Iroda 2"), ("note", "kék")));
        Assert.Equal("Iroda 2", e["location"]);
        Assert.Equal(9876L, e["pages"]);
        // the history got today's reading
        var h = App.PrinterHistory(pid);
        Assert.Single((List<Row>)h["days"]!);
        Assert.Equal(0, App.PrinterCollectDaily());                    // today is already read
        App.Store.SavePrinterSample("127.0.0.1", "2000-01-01", 1, [90]);
        Assert.Equal(2, ((List<Row>)App.PrinterHistory(pid)["days"]!).Count);
        Assert.IsType<PrinterForecast>(App.PrinterHistory(pid)["forecast"]);
        // an unreachable printer keeps its last readings and shows the error
        agent.Silent = true;
        var down = App.PrinterUpdate(pid, J(("community", "other")));
        Assert.NotEqual("", down["error"]);
        Assert.Equal(9876L, down["pages"]);
        Assert.NotEqual("", App.PrinterTest(J(("ip", "127.0.0.1")))["error"]);   // test without saving
        Assert.Single(App.PrinterList());
        Assert.Single(App.PrinterPoll());
        Assert.Throws<NotFound>(() => App.PrinterUpdate(999, J(("note", "x"))));
        Assert.Throws<NotFound>(() => App.PrinterHistory(999));
        App.PrinterDelete(pid);
        Assert.Empty(App.PrinterList());
        Assert.Empty(App.Store.PrinterHistory("127.0.0.1"));            // the history goes with the printer
    }

    [Fact]
    public void PrinterScan()
    {
        using var agent = new FakeSnmpAgent();
        var o = Printers.DefaultOids;
        lock (agent.Values)
        {
            agent.Values[Printers.ScanOids["sys_descr"]] = "Konica Minolta bizhub C227";
            agent.Values[Printers.ScanOids["sys_name"]] = "KM-TITKARSAG";
            agent.Values[Printers.ScanOids["sys_location"]] = "2. emelet";
            agent.Values[Printers.ScanOids["colorant2"]] = "cyan";
            agent.Values[o["oid_serial"]] = "A7R0021";
            agent.Values[o["oid_pages"]] = 5000;
        }
        var r = App.PrinterScan("127.0.0.1-2", "public", "2c", port: agent.Port, timeout: 0.3);
        Assert.Equal(2, r["scanned"]);
        var f = Assert.Single((List<Dictionary<string, object?>>)r["found"]!);
        Assert.Equal("127.0.0.1", f["ip"]);
        Assert.Equal("KM-TITKARSAG", f["name"]);
        Assert.Equal(true, f["printer"]);
        Assert.Equal(true, f["color"]);
        Assert.Null(f["known"]);
        var pid = App.Store.AddPrinter(Printers.Clean(J(("ip", "127.0.0.1"))));
        var again = Assert.Single((List<Dictionary<string, object?>>)App.PrinterScan("127.0.0.1", port: agent.Port, timeout: 0.3)["found"]!);
        Assert.Equal(pid, again["known"]);
        Assert.ThrowsAny<ArgumentException>(() => App.PrinterScan("10.0.0.0/16"));
        Assert.ThrowsAny<ArgumentException>(() => App.PrinterScan("127.0.0.1", version: "3"));
    }

    // ------------------------------------------------------------------ login tracking + offline inbox
    private static byte[] Entry(string computer, string user = "anna", string when = "2026-01-02T08:00:00.0000000Z") =>
        Encoding.UTF8.GetBytes(new JsonObject
        {
            ["computer"] = computer, ["time"] = when, ["user"] = user, ["domain"] = "CONTOSO", ["type"] = 2, ["ip"] = "",
        }.ToJsonString());

    private List<JsonObject> Logons(string guid) => ((Dictionary<string, List<JsonObject>>)App.Computer(guid)["items"]!)["logons"];

    [Fact]
    public void ImportLoginFolder()
    {
        var folder = Directory.CreateDirectory(_f.Temp.File("logins")).FullName;
        App.Settings.Logins.Path = folder;
        Assert.False(App.ImportLogins().Configured);                     // switched off
        App.Settings.Logins.Enabled = true;
        var comps = App.Computers();
        var (a, b) = (comps[0], comps[1]);
        var ga = (string)a["guid"]!;
        var before = Logons(ga).Count;
        File.WriteAllBytes(Path.Combine(folder, "1.log"), Entry((string)a["name"]!, when: "2030-01-02T08:00:00.0000000Z"));
        File.WriteAllBytes(Path.Combine(folder, "2.log"), Entry(((string)a["name"]!).ToLowerInvariant(), "bela", "2030-01-03T08:00:00.0000000Z"));
        File.WriteAllBytes(Path.Combine(folder, "3.log"), Entry((string)b["name"]!, "cili", "2030-01-04T08:00:00.0000000Z"));
        File.WriteAllBytes(Path.Combine(folder, "4.log"), Entry("GHOST-9"));
        File.WriteAllBytes(Path.Combine(folder, "5.log"), "{broken"u8.ToArray());
        File.WriteAllBytes(Path.Combine(folder, "6.tmp"), "half written"u8.ToArray());
        var r = App.ImportLogins();
        Assert.Equal((5, 3, 1, 1), (r.Found, r.Imported, r.Unknown, r.Failed));
        var got = Logons(ga);
        Assert.Equal(before + 2, got.Count);
        Assert.Equal("bela", (string)got[0]["user"]!);
        Assert.Equal("cili", (string)Logons((string)b["guid"]!)[0]["user"]!);
        Assert.Contains(App.Users(), u => (string)u["name"]! == "bela");   // the user index saw the new data
        Assert.Equal(0, App.ImportLogins().Imported);                    // nothing new: no duplicates
        Assert.Equal(before + 2, Logons(ga).Count);
        Assert.Contains(App.Store.Activity(), x => (string?)x["action"] == "logins");
        Assert.Equal("ADmiral-Logins.ps1", App.LoginsScript()["filename"]);
        App.Settings.Logins.Path = "";
        Assert.ThrowsAny<ArgumentException>(() => App.LoginsScript());
    }

    [Fact]
    public void ForgedLoginFileIsNotImported()
    {
        var folder = Directory.CreateDirectory(_f.Temp.File("logins")).FullName;
        App.Settings.Logins.Enabled = true;
        App.Settings.Logins.Path = folder;
        App.FileSecurity = new FakeOwner("S-1-5-21-9-9-9-1200", "CORP\\OTHERPC$");
        File.WriteAllBytes(Path.Combine(folder, "x.log"), Entry((string)App.Computers()[0]["name"]!, "jdoe", "2026-01-01T08:00:00Z"));
        var r = App.ImportLogins();
        Assert.Equal(0, r.Imported);
        Assert.Equal(1, r.Failed);
        Assert.True(File.Exists(Path.Combine(folder, "x.bad")));
    }

    [Fact]
    public void EventLogCollectionKeepsTheFileEntries()
    {
        var guid = (string)App.Computers()[0]["guid"]!;
        App.Store.AddLogons(guid, [new JsonObject { ["time"] = "2031-05-05T08:00:00Z", ["user"] = "dora", ["domain"] = "CONTOSO", ["type"] = 2, ["ip"] = "" }]);
        App.Store.RecordInventory(guid, new JsonObject { ["os_caption"] = "Windows", ["logons"] = new JsonArray() });
        Assert.Equal("dora", (string)Logons(guid)[0]["user"]!);
    }

    private static byte[] InboxFile(string host)
    {
        var data = new JsonObject
        {
            ["os_caption"] = "Microsoft Windows 11 Pro",
            ["logons"] = new JsonArray(new JsonObject { ["time"] = "2026-01-02T08:00:00+00:00", ["user"] = "anna", ["domain"] = "CONTOSO", ["type"] = 2, ["ip"] = "" }),
        };
        return Encoding.UTF8.GetBytes(new JsonObject
        {
            ["format"] = 1, ["host"] = host, ["fqdn"] = $"{host.ToLowerInvariant()}.contoso.local", ["collected_at"] = "2026-01-02T08:05:00Z",
            ["data"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(data.ToJsonString())),
        }.ToJsonString());
    }

    [Fact]
    public void ImportInbox()
    {
        var res = App.ImportOffline();
        Assert.False(res.Configured);
        var inbox = Directory.CreateDirectory(_f.Temp.File("inbox")).FullName;
        App.Settings.FileCollect.Inbox = inbox;
        var comps = App.Computers();
        var (a, b) = ((string)comps[0]["name"]!, (string)comps[1]["name"]!);
        File.WriteAllBytes(Path.Combine(inbox, $"{a}.admiral.json"), InboxFile(a));
        File.WriteAllBytes(Path.Combine(inbox, $"{b.ToLowerInvariant()}.admiral.json"), InboxFile(b.ToLowerInvariant()));
        File.WriteAllBytes(Path.Combine(inbox, "GHOST-9.admiral.json"), InboxFile("GHOST-9"));
        File.WriteAllBytes(Path.Combine(inbox, "BROKEN.admiral.json"), "{nope"u8.ToArray());
        var r = App.ImportOffline();
        Assert.Equal(4, r.Found);
        Assert.Equal(2, r.Imported);
        Assert.Equal(["GHOST-9.admiral.json"], r.Unknown);
        Assert.Single(r.Failed);
        var got = _f.Computer(a);
        Assert.Equal("file", (string)((JsonObject)got["inventory"]!)["collected_via"]!);
        Assert.Equal("ok", got["scan_status"]);
        Assert.Contains(App.Store.Activity(), x => (string?)x["action"] == "offline");
        App.Settings.FileCollect.Inbox = _f.Temp.File("missing");
        Assert.NotNull(App.ImportOffline().Error);                       // unreachable share: reported, no crash
    }

    // ------------------------------------------------------------------ saved passwords
    private static AdmiralService PasswordApp(CoreTemp tmp)
    {
        var st = new Settings { Mode = "ldap", DbPath = ":memory:", Language = "en" };
        st.Ldap.Server = "dc01.corp.local";
        st.Ldap.BaseDn = "DC=corp,DC=local";
        st.Ldap.Password = "s3cret";
        st.Proxy.Url = "http://proxy:8080";
        st.Proxy.User = "p";
        st.Proxy.Password = "pp";
        var app = new AdmiralService(st, new Store(":memory:"), configPath: tmp.File("a.toml"), applyProcessSettings: false);
        app.Secrets.Set("ldap_password", "s3cret");
        return app;
    }

    [Fact]
    public void SavedPasswordIsNotSentToAChangedServer()
    {
        using var tmp = new CoreTemp();
        using var app = PasswordApp(tmp);
        Assert.Equal("", app.Merge(new JsonObject { ["ldap"] = new JsonObject { ["server"] = "evil.example" } }).Ldap.Password);
        Assert.Equal("s3cret", app.Merge(new JsonObject { ["ldap"] = new JsonObject { ["server"] = "dc01.corp.local", ["page_size"] = 1 } }).Ldap.Password);
        Assert.Equal("new", app.Merge(new JsonObject { ["ldap"] = new JsonObject { ["server"] = "dc02.corp.local", ["password"] = "new" } }).Ldap.Password);
        Assert.Equal("", app.Merge(new JsonObject { ["proxy"] = new JsonObject { ["url"] = "http://other:3128" } }).Proxy.Password);
        app.UpdateSettings(new JsonObject { ["ldap"] = new JsonObject { ["server"] = "dc02.corp.local" } });
        Assert.Equal("", app.Settings.Ldap.Password);
        Assert.Equal("", app.Secrets.Get("ldap_password"));
        Assert.IsType<AdDirectory>(app.Directory);
    }

    [Fact]
    public void ShortSyncKeyIsRefused()
    {
        using var tmp = new CoreTemp();
        using var app = PasswordApp(tmp);
        Assert.ThrowsAny<ArgumentException>(() => app.Merge(new JsonObject { ["sync"] = new JsonObject { ["key"] = "short" } }));
        Assert.Equal(new string('x', 43), app.Merge(new JsonObject { ["sync"] = new JsonObject { ["key"] = new string('x', 43) } }).Sync.Key);
    }

    [Fact]
    public void UpdateLocationIsFixed()
    {
        Assert.False(((Row)App.SettingsView()["appupdate"]!).ContainsKey("url"));
        Assert.Equal(Config.AppUpdateUrl, App.Merge(new JsonObject { ["appupdate"] = new JsonObject { ["url"] = "https://evil.example/" } }).AppUpdate.Url);
    }
}

internal static class ObjectExtensions
{
    public static T As<T>(this object? o) => (T)o!;
}
