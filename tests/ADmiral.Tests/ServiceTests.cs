using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>tests/test_service.py, the service cases of test_inventory.py, test_ou_scope.py, test_misc.py and
/// test_readonly.py (the <c>admiral</c> fixture).</summary>
public sealed class ServiceTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    private static JsonObject Rule(string field, string op, object value, string match = "all") => new()
    {
        ["match"] = match,
        ["conditions"] = new JsonArray(new JsonObject { ["field"] = field, ["op"] = op, ["value"] = JsonValue.Create(value) }),
    };

    private static HashSet<string> Names(IEnumerable<Row> rows) => [.. rows.Select(r => (string)r["name"]!)];

    // ------------------------------------------------------------------ AD sync, scan, collect
    [Fact]
    public void SyncIsIdempotentAndRemoves()
    {
        var total = App.Computers().Count;
        Assert.Equal(190, total);
        var r = App.SyncAd();
        Assert.Equal(new Dictionary<string, int> { ["added"] = 0, ["updated"] = total, ["removed"] = 0, ["total"] = total }, r);
        var gone = _f.Directory.Computers[^1];
        _f.Directory.Computers.RemoveAt(_f.Directory.Computers.Count - 1);
        Assert.Equal(1, App.SyncAd()["removed"]);
        Assert.DoesNotContain(App.Computers(), c => (string)c["guid"]! == (string)gone["guid"]!);
    }

    [Fact]
    public void ScanCollectPreservedAcrossSync()
    {
        var s = App.Scan();
        Assert.True(s["online"] > 0 && s["offline"] > 0);
        var c = App.Collect();
        Assert.True(c["collected"] > 0);
        Assert.True(c["failed"] > 0);                                   // ~1 in 23 demo hosts refuses
        App.SyncAd();
        Assert.Equal(c["collected"], App.Computers().Count(x => x["inventory"] is not null));
    }

    [Fact]
    public void FullScanStoresComputerPageFields()
    {
        Assert.True(App.FullScan()["collected"] > 0);
        var c = App.Computers().First(c => (string?)c["scan_status"] == "ok");
        var detail = App.Computer((string)c["guid"]!);
        var inv = (JsonObject)detail["inventory"]!;
        foreach (var key in new[] { "os_caption", "os_short", "os_display_version", "os_installed", "os_serial", "system_drive",
                                    "powershell_version", "smb1_server", "smb1_client", "time_zone", "last_boot", "ip_address",
                                    "mac_address", "manufacturer", "model", "memory_gb", "cpu", "chassis", "serial", "bios_version",
                                    "bios_manufacturer", "family", "domain", "domain_controller" })
            Assert.True(inv.ContainsKey(key), key);
        var items = (Dictionary<string, List<JsonObject>>)detail["items"]!;
        foreach (var k in new[] { "disks", "nics", "hotfixes", "apps", "services", "local_admins" }) Assert.NotEmpty(items[k]);
        Assert.NotNull(detail["uptime_s"]);
        Assert.NotNull(detail["added"]);
        Assert.False(inv.ContainsKey("apps"));                          // lists live in their own table
        var n = (long)App.Store.Scalar("SELECT COUNT(*) FROM computer_items WHERE guid = ?", c["guid"])!;
        Assert.Equal(items.Values.Sum(v => v.Count), n);
        Assert.Contains("fleets", detail.Keys);
        Assert.NotEmpty((List<string>)detail["apps"]!);
    }

    [Fact]
    public void FailedCollectionKeepsPreviousData()
    {
        App.FullScan();
        var guid = (string)App.Computers().First(c => (string?)c["scan_status"] == "ok")["guid"]!;
        App.Store.RecordInventory(guid, null, "boom");
        var after = App.Computer(guid);
        Assert.Equal("failed", after["scan_status"]);
        Assert.Equal("boom", after["collect_error"]);
        Assert.NotNull(after["inventory"]);
        Assert.NotEmpty(((Dictionary<string, List<JsonObject>>)after["items"]!)["apps"]);
    }

    [Fact]
    public void RescanReplacesRowsAndPartialKeepsFailedSection()
    {
        App.FullScan();
        var guid = (string)App.Computers().First(c => (string?)c["scan_status"] == "ok")["guid"]!;
        App.Store.RecordInventory(guid, new JsonObject
        {
            ["model"] = "New", ["apps"] = new JsonArray(new JsonObject { ["name"] = "Only" }),
            ["section_errors"] = new JsonObject { ["services"] = "denied" },
        });
        var after = App.Computer(guid);
        Assert.Equal("partial", after["scan_status"]);
        var items = (Dictionary<string, List<JsonObject>>)after["items"]!;
        Assert.Equal(["Only"], items["apps"].Select(a => (string)a["name"]!));
        Assert.NotEmpty(items["services"]);                            // old rows kept
    }

    [Fact]
    public void AllowScanExcludes()
    {
        App.SetAllowScan(["LT-001", "LT-002"], false);
        var r = App.FullScan(guids: ["LT-001", "LT-002", "LT-003"]);
        Assert.Equal(1, r["scanned"]);
        Assert.Equal(2, r["skipped"]);
        Assert.Null(_f.Computer("LT-001")["scanned_at"]);
    }

    [Fact]
    public void AppAndGroupRules()
    {
        App.FullScan();
        var f = App.CreateFleet("SQL hosts", "dynamic", ruleSet: Rule("app", "any_contains", "sql server"));
        var names = Names(App.FleetMembers((long)f["id"]!));
        Assert.NotEmpty(names);
        Assert.All(names, n => Assert.StartsWith("SQL", n));
        var g = App.CreateFleet("BitLocker", "dynamic", ruleSet: Rule("ad_group", "has", "bitlocker-laptops"));
        var members = Names(App.FleetMembers((long)g["id"]!));
        Assert.NotEmpty(members);
        Assert.All(members, n => Assert.StartsWith("LT", n));
    }

    [Fact]
    public void JobTracksComputersBeingQueried()
    {
        using var gate = new ManualResetEventSlim();
        App.ProbeOverride = (h, p, t) =>
        {
            gate.Wait(2000);
            return Demo.Probe(h, p, t);
        };
        var job = App.Jobs.Start("scan", "scan", p => App.Scan(progress: p));
        IReadOnlyDictionary<string, string> seen = new Dictionary<string, string>();
        for (var i = 0; i < 100 && seen.Count == 0; i++)
        {
            seen = App.Jobs.Get(job.Id)!.Active;
            if (seen.Count == 0) Thread.Sleep(20);
        }
        gate.Set();
        var done = _f.WaitJob(job.Id);
        Assert.NotEmpty(seen);
        Assert.Equal(["scan"], seen.Values.Distinct());
        Assert.Empty(done.Active);                                     // nothing marked busy after the job ends
        Assert.Equal("done", done.Status);
    }

    // ------------------------------------------------------------------ fleets
    [Fact]
    public void DynamicFleetAndTags()
    {
        App.Tag(["LT-001", "DT-002"], ["pilot"], []);
        var f = App.CreateFleet("Pilot", "dynamic", ruleSet: Rule("tag", "has", "pilot"));
        Assert.Equal(["DT-002", "LT-001"], Names(App.FleetMembers((long)f["id"]!)).Order());
        App.Tag(["LT-001"], [], ["pilot"]);
        Assert.Equal(["DT-002"], App.FleetMembers("pilot").Select(c => (string)c["name"]!));
        var fleets = App.Fleets();
        Assert.Equal(1, (int)fleets.Single()["count"]!);
        Assert.Single((List<string>)fleets.Single()["guids"]!);
    }

    [Fact]
    public void StaticFleetAndErrors()
    {
        var f = App.CreateFleet("Hand picked", "static", members: ["LT-001", "lt-002"]);
        var id = ((long)f["id"]!).ToString();
        Assert.Equal(2, App.FleetMembers(id).Count);
        Assert.Equal(1, App.ChangeStaticMembers(id, remove: ["LT-001"]));
        Assert.Throws<KeyNotFoundException>(() => App.ChangeStaticMembers(id, add: ["NOPE-999"]));
        Assert.ThrowsAny<ArgumentException>(() => App.CreateFleet("hand PICKED", "static"));
        var dyn = App.CreateFleet("Dyn", "dynamic", ruleSet: new JsonObject
        {
            ["conditions"] = new JsonArray(new JsonObject { ["field"] = "name", ["op"] = "glob", ["value"] = "x*" }),
        });
        Assert.ThrowsAny<ArgumentException>(() => App.ChangeStaticMembers(((long)dyn["id"]!).ToString(), add: ["LT-001"]));
    }

    [Fact]
    public void FleetErrors()
    {
        var f = App.CreateFleet("S", "static", members: ["LT-001"]);
        var id = (long)f["id"]!;
        Assert.ThrowsAny<ArgumentException>(() => App.CreateFleet(" ", "static"));
        Assert.ThrowsAny<ArgumentException>(() => App.CreateFleet("X", "weird"));
        Assert.ThrowsAny<ArgumentException>(() => App.UpdateFleet(id, rules: Rule("name", "equals", "a")));
        App.CreateFleet("T", "static");
        Assert.ThrowsAny<ArgumentException>(() => App.UpdateFleet(id, name: "t"));
        Assert.ThrowsAny<ArgumentException>(() => App.UpdateFleet(id, name: "  "));
        Assert.Throws<NotFound>(() => App.GetFleet("missing"));
        Assert.ThrowsAny<ArgumentException>(() => App.ExportFleet(id.ToString(), "xml"));
        Assert.ThrowsAny<ArgumentException>(() => App.CreateFleet("Bad rules", "dynamic", ruleSet: Rule("nope", "equals", "a")));
        var g = App.CreateFleet("G", "static", adGroupDn: "CN=Nope,DC=contoso,DC=local");
        Assert.Throws<NotFound>(() => App.GroupCompare(((long)g["id"]!).ToString()));
        var plain = App.CreateFleet("NoGroup", "static");
        Assert.ThrowsAny<ArgumentException>(() => App.GroupCompare(((long)plain["id"]!).ToString()));
        App.DeleteFleet("S");
        Assert.Throws<NotFound>(() => App.GetFleet(id));
    }

    [Fact]
    public void GroupCompareIsReadOnly()
    {
        var group = Demo.Groups[0];
        var before = _f.Directory.GroupMembers(group);                   // LT-001..004 + a user
        var f = App.CreateFleet("Laptops", "dynamic", adGroupDn: group, ruleSet: Rule("name", "glob", "LT-00*"));
        var id = ((long)f["id"]!).ToString();
        var r = App.GroupCompare(id);
        Assert.Equal(Enumerable.Range(5, 5).Select(i => $"LT-00{i}").ToHashSet(), Names((List<Row>)r["missing"]!));
        Assert.Equal(4, r["matching"]);
        Assert.Empty((List<Row>)r["extra"]!);
        Assert.Equal(["CN=Jane Admin,OU=Users,DC=contoso,DC=local"], (List<string>)r["other_members"]!);
        App.UpdateFleet(id, rules: Rule("name", "equals", "LT-001"));
        Assert.Equal(["LT-002", "LT-003", "LT-004"], Names((List<Row>)App.GroupCompare(id)["extra"]!).Order());
        Assert.Equal(before, _f.Directory.GroupMembers(group));         // comparing never changes AD
    }

    [Fact]
    public void ExportFormats()
    {
        var f = App.CreateFleet("SQL boxes", "dynamic", ruleSet: Rule("ou", "contains", "/SQL"));
        var id = ((long)f["id"]!).ToString();
        var (txt, mime, name) = App.ExportFleet(id, "txt");
        Assert.Equal("text/plain", mime);
        Assert.Equal("SQL_boxes.txt", name);
        Assert.Equal("sql-001.contoso.local", txt.Split('\n')[0].TrimEnd('\r'));
        var (ini, _, iniName) = App.ExportFleet(id, "ansible");
        Assert.StartsWith("[sql_boxes]", ini);
        Assert.Contains("ansible_connection=winrm", ini);
        Assert.EndsWith(".ini", iniName);
        Assert.StartsWith("name,dns_hostname,ip", App.ExportFleet(id, "csv").Body);
        Assert.Contains("$Targets = @(", App.ExportFleet(id, "ps1").Body);
        Assert.Contains(App.Activity(5), a => (string?)a["action"] == "export");
    }

    [Fact]
    public void PreviewRulesAndComputerFleets()
    {
        var rows = App.PreviewRules(Rule("ou", "contains", "/SQL"));
        Assert.Equal(8, rows.Count);
        Assert.ThrowsAny<ArgumentException>(() => App.PreviewRules(new JsonObject { ["match"] = "all" }));
        var f = App.CreateFleet("One", "static", members: ["SQL-001"]);
        var fleets = (List<Row>)_f.Computer("SQL-001")["fleets"]!;
        Assert.Equal(f["id"], Assert.Single(fleets)["id"]);
        Assert.Throws<NotFound>(() => App.Computer("nope"));
    }

    // ------------------------------------------------------------------ hide / restore, scoped sync, OU browser
    [Fact]
    public void RemoveComputersSurvivesAdSync()
    {
        var names = App.Computers().Take(2).Select(c => (string)c["name"]!).ToList();
        var total = App.Computers().Count;
        Assert.Equal(2, App.RemoveComputers(names));
        Assert.Equal(total - 2, App.Computers().Count);
        App.SyncAd();                                                    // must not bring them back
        Assert.Equal(total - 2, App.Computers().Count);
        Assert.Equal(2, App.Store.HiddenCount());
        Assert.Equal(2, App.RestoreComputers());
        Assert.Equal(total, App.Computers().Count);
    }

    [Fact]
    public void ScopedSyncKeepsComputersElsewhere()
    {
        var total = App.Computers().Count;
        var servers = $"OU=Servers,{Demo.Domain}";
        var inside = App.Computers().Where(c => ((string)c["dn"]!).EndsWith(servers, StringComparison.Ordinal)).ToList();
        // a computer inside the scope that has vanished from AD is dropped, nothing outside is touched
        var gone = _f.Directory.Computers.First(c => (string)c["guid"]! == (string)inside[0]["guid"]!);
        _f.Directory.Computers.Remove(gone);
        var r = App.SyncAd(baseDn: servers);
        Assert.Equal(1, r["removed"]);
        Assert.Equal(inside.Count - 1, r["total"]);
        Assert.Equal(total - 1, App.Computers().Count);
        _f.Directory.Computers.Add(gone);
        App.SyncAd();                                                    // a full sync restores it
        Assert.Equal(total, App.Computers().Count);
    }

    [Fact]
    public void DemoOuTreeAndScopedFetch()
    {
        var d = new DemoDirectory();
        var top = d.ListOus().Select(o => o.Name).ToHashSet();
        Assert.True(top.IsSupersetOf(["Workstations", "Servers", "Lab"]));
        var ws = $"OU=Workstations,{Demo.Domain}";
        Assert.Equal(["Desktops", "Kiosks", "Laptops"], d.ListOus(ws).Select(o => o.Name).Order());
        var below = d.FetchComputers(ws);
        Assert.NotEmpty(below);
        Assert.All(below, c => Assert.EndsWith(ws, (string)c["dn"]!));
        Assert.True(below.Count < d.FetchComputers().Count);
        var ous = App.AdOus($"OU=Servers,{Demo.Domain}");
        Assert.Equal(["App", "File", "SQL"], ((List<AdOu>)ous["children"]!).Select(o => o.Name).Order());
        Assert.Equal("DC=contoso,DC=local", App.AdOus()["root"]);
    }

    [Fact]
    public void DemoDirectoryHasNoWriteMethods()
    {
        var names = typeof(DemoDirectory).GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name).Where(n => !n.StartsWith("get_", StringComparison.Ordinal)).ToList();
        Assert.DoesNotContain(names, n => Regex.IsMatch(n, "^_?(Add|Remove|Modify|Delete|Move|Rename|Set|Update|Reset|Unlock|Enable|Disable)"));
    }

    // ------------------------------------------------------------------ settings
    [Fact]
    public void SettingsUpdateSwitchesDirectory()
    {
        using var tmp = new CoreTemp();
        using var app = new AdmiralService(new Settings { DbPath = ":memory:", Language = "en" }, new Store(":memory:"),
                                           configPath: tmp.File("a.toml"), applyProcessSettings: false);
        var v = app.UpdateSettings(new JsonObject
        {
            ["mode"] = "ldap", ["ldap"] = new JsonObject { ["server"] = "dc1", ["base_dn"] = "DC=x" }, ["theme"] = "dark",
        });
        Assert.Equal("ldap", v["mode"]);
        Assert.Equal("dark", v["theme"]);
        Assert.IsType<AdDirectory>(app.Directory);
        Assert.True(File.Exists(tmp.File("a.toml")));
        app.UpdateSettings(new JsonObject
        {
            ["collect"] = new JsonObject { ["method"] = "winrm" }, ["winrm"] = new JsonObject { ["transport"] = "ntlm" },
        });
        Assert.ThrowsAny<ArgumentException>(() => app.Collect());       // ldap mode, NTLM transport without WinRM credentials
        Assert.ThrowsAny<ArgumentException>(() => app.UpdateSettings(new JsonObject { ["language"] = "de" }));
        Assert.ThrowsAny<ArgumentException>(() => app.UpdateSettings(new JsonObject { ["ldap"] = "nope" }));
        using var ro = new AdmiralService(new Settings { DbPath = ":memory:", Language = "en" }, new Store(":memory:"), applyProcessSettings: false);
        Assert.ThrowsAny<ArgumentException>(() => ro.UpdateSettings(new JsonObject { ["theme"] = "dark" }));
    }

    [Fact]
    public void OfflineAllowUsersIsEditableFromTheUiAndPersisted()
    {
        using var tmp = new CoreTemp();
        using var app = new AdmiralService(new Settings { DbPath = ":memory:", Language = "en" }, new Store(":memory:"),
                                           configPath: tmp.File("a.toml"), applyProcessSettings: false);
        Assert.False(app.Settings.FileCollect.OfflineAllowUsers);                    // secure default
        app.UpdateSettings(new JsonObject { ["filecollect"] = new JsonObject { ["offline_allow_users"] = true } });
        Assert.True(app.Settings.FileCollect.OfflineAllowUsers);
        Assert.Contains("offline_allow_users = true", File.ReadAllText(tmp.File("a.toml")), StringComparison.Ordinal);
        Assert.True(Config.LoadSettings(tmp.File("a.toml"), new Dictionary<string, string>(), requireLdap: false).FileCollect.OfflineAllowUsers);
    }

    [Fact]
    public void CollectNeedsAdminRightsOnTheOu()
    {
        using var app = new AdmiralService(new Settings { Mode = "demo", DbPath = ":memory:" }, new Store(":memory:"), new NoAdminDirectory(),
                                           applyProcessSettings: false);
        app.SyncAd();
        foreach (var c in app.Computers()) app.Store.RecordScan((string)c["guid"]!, "10.0.0.1", [445, 5985]);
        app.Settings.Mode = "ldap";                                     // as if it were a real domain
        app.Settings.Ldap.Server = "dc01.contoso.local";
        app.Settings.Ldap.BaseDn = Demo.Domain;
        var ex = Assert.ThrowsAny<ArgumentException>(() => app.Collect());
        Assert.Contains("no rights here", ex.Message);
        Assert.Contains(app.Activity(5), a => (string?)a["action"] == "collect");
    }

    private sealed class NoAdminDirectory : IDirectory
    {
        private readonly DemoDirectory _d = new();
        public string Test() => _d.Test();
        public List<Dictionary<string, object?>> FetchComputers(string? baseDn = null) => _d.FetchComputers(baseDn).Take(5).ToList();
        public List<AdOu> ListOus(string? parent = null) => _d.ListOus(parent);
        public List<string> GroupMembers(string groupDn) => _d.GroupMembers(groupDn);
        public Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names) => _d.FetchUsers(names);
        public List<Dictionary<string, object?>> FetchOuUsers(string? baseDn = null) => _d.FetchOuUsers(baseDn);
        public (bool Ok, string Detail) IsAdminAccount(string user) => (false, "not an admin");
        public Dictionary<string, (bool Ok, string Detail)> OuAdminScope(string user, IEnumerable<string> ouDns) =>
            ouDns.ToDictionary(o => o, _ => (false, "no rights here"));
    }

    [Fact]
    public void UntrustedPacSwitchIsSavedAndShown()
    {
        using var f = new ServiceFixture(editable: true);
        var app = f.App;
        Assert.False((bool)((Row)app.SettingsView()["proxy"]!)["allow_untrusted_pac"]!);       // off by default
        app.UpdateSettings(new JsonObject { ["proxy"] = new JsonObject { ["pac"] = "auto", ["user"] = "jdoe@corp.local", ["password"] = "pw", ["allow_untrusted_pac"] = true } });
        Assert.True(app.Settings.Proxy.AllowUntrustedPac);
        Assert.True((bool)((Row)app.SettingsView()["proxy"]!)["allow_untrusted_pac"]!);
        Assert.Contains("allow_untrusted_pac = true", File.ReadAllText(f.Temp.File("admiral.toml")));
        // switching it off keeps the saved proxy password (it is not tied to the switch)
        app.UpdateSettings(new JsonObject { ["proxy"] = new JsonObject { ["pac"] = "auto", ["user"] = "jdoe@corp.local", ["allow_untrusted_pac"] = false } });
        Assert.False(app.Settings.Proxy.AllowUntrustedPac);
        Assert.Equal("pw", app.Settings.Proxy.Password);
    }

    [Fact]
    public void SettingsViewMasksSecretsAndOnlyEditableFieldsChange()
    {
        using var f = new ServiceFixture(editable: true);
        var app = f.App;
        app.Settings.Proxy.Password = "s3cret";
        var view = app.SettingsView();
        Assert.True((bool)view["editable"]!);
        var proxy = (Row)view["proxy"]!;
        Assert.True((bool)proxy["password_set"]!);
        Assert.False(proxy.ContainsKey("password"));
        Assert.DoesNotContain("s3cret", JsonSerializer.Serialize(view));
        Assert.False(((Row)view["appupdate"]!).ContainsKey("url"));
        // non-editable fields (bind address, database, update location) are ignored; unknown ones too
        app.UpdateSettings(new JsonObject
        {
            ["host"] = "0.0.0.0", ["db_path"] = "/etc/x.db", ["theme"] = "dark", ["bogus"] = 1,
            ["appupdate"] = new JsonObject { ["url"] = "https://evil.example/" },
            ["ldap"] = new JsonObject { ["page_size"] = 1 },
        });
        Assert.Equal("127.0.0.1", app.Settings.Host);
        Assert.Equal(":memory:", app.Settings.DbPath);
        Assert.Equal("dark", app.Settings.Theme);
        Assert.Equal(Config.AppUpdateUrl, app.Settings.AppUpdate.Url);
        Assert.Equal(500, app.Settings.Ldap.PageSize);
        var toml = File.ReadAllText(f.Temp.File("admiral.toml"));
        Assert.DoesNotContain("s3cret", toml);
        // a typed secret goes to the secret store, never into the view
        app.UpdateSettings(new JsonObject { ["winrm"] = new JsonObject { ["password"] = "w1nrm-pass" } });
        Assert.Equal("w1nrm-pass", app.Secrets.Get("winrm_password"));
        Assert.DoesNotContain("w1nrm-pass", JsonSerializer.Serialize(app.SettingsView()));
        Assert.DoesNotContain("w1nrm-pass", File.ReadAllText(f.Temp.File("admiral.toml")));
        Assert.ThrowsAny<ArgumentException>(() => app.UpdateSettings(new JsonObject { ["winrm"] = new JsonObject { ["password"] = 5 } }));
        Assert.ThrowsAny<ArgumentException>(() => app.UpdateSettings(new JsonObject { ["scan"] = new JsonObject { ["ports"] = new JsonArray(0) } }));
    }

    [Fact]
    public void LogsAndDebugSetting()
    {
        Assert.True((bool)App.SettingsView()["debug_log"]!);
        var files = (List<Row>)App.LogFiles()["files"]!;
        Assert.Equal(["admiral.log", "admiral-debug.log", "admiral-errors.jsonl"], files.Select(x => (string)x["name"]!));
        Assert.ThrowsAny<ArgumentException>(() => App.ReadLog("../../etc/passwd"));
    }

    // ------------------------------------------------------------------ summary, software, vulnerabilities, updates
    [Fact]
    public void SummarySoftwareAndVulnerabilities()
    {
        App.FullScan();
        var s = App.Summary();
        Assert.Equal(190, s["total"]);
        Assert.True((int)s["inventoried"]! > 0);
        Assert.NotEmpty((List<object[]>)s["by_os"]!);
        var sw = App.SoftwareList();
        var chrome = sw.First(r => r.Name == "Google Chrome");
        Assert.True(chrome.VersionCount >= 2);
        var detail = App.SoftwareDetail(chrome.Key);
        Assert.Equal("google:chrome", detail["cpe"]);
        Assert.NotEmpty((List<Row>)detail["all_versions"]!);
        Assert.Throws<NotFound>(() => App.SoftwareDetail("no such program"));

        var r = App.RefreshVulns();
        Assert.True(r["mapped"] >= 3);
        var v = App.Vulnerabilities();
        var items = (List<Row>)v["items"]!;
        Assert.Contains(items, i => (string)i["cve"]! == "CVE-2026-1234" && (bool)i["kev"]!);
        Assert.True((bool)items[0]["kev"]!);                            // exploited ones first
        var one = App.Vulnerability("cve-2026-1234");
        Assert.NotEmpty((List<Row>)one["affected"]!);
        Assert.Throws<NotFound>(() => App.Vulnerability("CVE-1999-0001"));
        Assert.NotEmpty((List<Row>)App.SoftwareDetail(chrome.Key)["vulnerabilities"]!);
        // hidden ones (no affected version / older than 10 years) are flagged and not counted
        var counted = items.Where(i => i["hidden"] is false).ToList();
        Assert.Equal(counted.Count(i => (bool)i["kev"]!), (int)((Row)v["counts"]!)["kev"]!);
        Assert.Equal(items.Count - counted.Count, (int)((Row)v["counts"]!)["hidden"]!);
    }

    [Fact]
    public void VulnHiddenReason()
    {
        var today = new DateTime(2026, 11, 25);
        Assert.Equal("no_range", AdmiralService.VulnHiddenReason("", "2026-01-01", today));
        Assert.Equal("old", AdmiralService.VulnHiddenReason("< 1.2", "2016-11-24", today));
        Assert.Null(AdmiralService.VulnHiddenReason("< 1.2", "2016-11-25", today));
        Assert.Null(AdmiralService.VulnHiddenReason("<= 3.0", "", today));         // no date: shown
    }

    [Fact]
    public void SecurityCollectionInService()
    {
        App.Scan();
        App.Collect();
        var res = App.RefreshUpdates();                                 // demo reference (no internet)
        Assert.True((int)res["builds"]! >= 5);
        Assert.NotNull(App.UpdatesStatus()["fetched_at"]);
        var states = App.Computers().Select(c => ((SecurityState)c["security"]!).State).ToHashSet();
        Assert.Contains("missing", states);
        Assert.Contains("current", states);
        var first = (string)App.Computers()[0]["guid"]!;
        Assert.Contains(((SecurityState)App.Computer(first)["security"]!).State, states.Append("unknown"));
        var wu = App.WinUpdates();
        Assert.NotEmpty((List<Row>)wu["reference"]!);
        Assert.Contains((List<Row>)wu["computers"]!, c => (string)c["state"]! == "missing" && ((string)c["installed"]!).Length > 0);
    }

    [Fact]
    public void ProxyPasswordIsASecret()
    {
        var view = App.SettingsView();
        Assert.False((bool)((Row)view["proxy"]!)["password_set"]!);
        Assert.False(((Row)view["proxy"]!).ContainsKey("password"));
        App.Settings.Proxy.Password = "s3cret";
        Assert.True((bool)((Row)App.SettingsView()["proxy"]!)["password_set"]!);
        Assert.DoesNotContain("s3cret", Persist.SettingsToToml(App.Settings));
    }

    // ------------------------------------------------------------------ users
    [Fact]
    public void LogonHistoryAndUsers()
    {
        var comps = App.Computers();
        string ga = (string)comps[0]["guid"]!, gb = (string)comps[1]["guid"]!;
        static JsonObject Ev(string user, string dom, string t, int typ = 2) =>
            new() { ["time"] = t, ["user"] = user, ["domain"] = dom, ["type"] = typ, ["ip"] = "" };
        App.Store.RecordInventory(ga, Collector.Normalize(new JsonObject
        {
            ["logons"] = new JsonArray(Ev("kovacs.anna", "CONTOSO", "2026-01-02T08:00:00+00:00"), Ev("DWM-1", "Window Manager", "2026-01-02T08:00:01+00:00"),
                                       Ev("LT-001$", "CONTOSO", "2026-01-02T08:00:02+00:00"), Ev("SYSTEM", "NT AUTHORITY", "2026-01-02T08:00:03+00:00")),
        }));
        App.Store.RecordInventory(gb, Collector.Normalize(new JsonObject
        {
            ["logons"] = new JsonArray(Ev("kovacs.anna", "CONTOSO", "2026-01-05T09:00:00+00:00", 10)),
        }));
        var rows = App.Users();
        Assert.Equal(["kovacs.anna"], rows.Select(r => (string)r["name"]!));            // system accounts are gone
        Assert.Equal(2, rows[0]["computers"]);
        Assert.Equal(2, rows[0]["logons"]);
        Assert.StartsWith("2026-01-05", (string)rows[0]["last_logon"]!);
        Assert.Equal(1, App.SyncUsers());                                               // AD attributes read once
        Assert.Equal(0, App.SyncUsers());                                               // fresh: not read again
        var u = App.User((string)rows[0]["key"]!);
        Assert.NotEqual("", (string)((JsonObject)u["ad"]!)["title"]!);
        Assert.Equal(2, ((List<Row>)u["computer_list"]!).Count);
        Assert.Equal(10, (int)((List<JsonObject>)u["events"]!)[0]["type"]!);
        Assert.Equal("Pénzügy", App.Users()[0]["department"]);
        Assert.Equal("Kovács Anna", App.Users()[0]["display_name"]);
        Assert.Throws<NotFound>(() => App.User("nobody"));
        JsonSerializer.Serialize(u);                                                    // serializable as the API returns it
    }

    [Fact]
    public void AdUsersImportByOu()
    {
        var r = App.SyncAdUsers(baseDn: $"OU=Users,{Demo.Domain}");
        Assert.Equal(8, r["total"]);
        Assert.Equal(8, r["added"]);
        var rows = App.Users();
        Assert.Equal(8, rows.Count);
        Assert.All(rows, x => Assert.True((bool)x["in_ad"]!));
        Assert.StartsWith("contoso\\", (string)rows[0]["key"]!);
        Assert.Equal(JsonSerializer.Serialize(rows), JsonSerializer.Serialize(App.Users()));   // the cached index gives the same answer
        Assert.Equal(0, App.SyncAdUsers()["added"]);
    }

    // ------------------------------------------------------------------ retry
    [Fact]
    public void RetryCandidatesAndPass()
    {
        var comps = App.Computers();
        string a = (string)comps[0]["guid"]!, b = (string)comps[1]["guid"]!, c = (string)comps[2]["guid"]!;
        App.Store.RecordScan(a, "10.0.0.1", []);                                        // offline
        App.Store.RecordScan(b, "10.0.0.2", [445, 5985]);
        App.Store.RecordInventory(b, null, "boom");                                     // failed
        App.Store.RecordScan(c, "10.0.0.3", [445, 5985]);
        App.Store.RecordInventory(c, new JsonObject { ["os_caption"] = "Windows 11" }); // ok
        var got = Retry.Candidates(App.Computers(), App.Settings).ToHashSet();
        Assert.Contains(a, got);
        Assert.Contains(b, got);
        Assert.DoesNotContain(c, got);
        App.Settings.Retry.Offline = false;
        got = [.. Retry.Candidates(App.Computers(), App.Settings)];
        Assert.Contains(b, got);
        Assert.DoesNotContain(a, got);
        App.Settings.Retry.Offline = true;
        var res = Retry.RetryPass(App);
        Assert.True(res["candidates"] >= 2);
        Assert.Contains(App.Store.Activity(), x => (string?)x["action"] == "retry");
    }

    [Fact]
    public void RetryServiceApi()
    {
        Assert.False(App.RetryServiceAction().Supported);
        Assert.False(App.RetryServiceAction().Installed);
        Assert.ThrowsAny<ArgumentException>(() => App.RetryServiceAction("delete"));     // read-only (no config file)
        using var f = new ServiceFixture(editable: true);
        Assert.ThrowsAny<ArgumentException>(() => f.App.RetryServiceAction("bogus"));
        Assert.Throws<RetryServiceError>(() => f.App.RetryServiceAction("delete"));
        Assert.ThrowsAny<ArgumentException>(() => f.App.RetryServiceAction("install", "u:someone", "pw"));
        Assert.False(f.App.ServiceOwnsSync);
        var s = new Settings { Mode = "demo" };
        s.Retry.IntervalMinutes = 0;
        Assert.ThrowsAny<ArgumentException>(() => Config.ValidateSettings(s));
    }

    // ------------------------------------------------------------------ sync between service instances
    [Fact]
    public void SyncTwoServiceInstances()
    {
        var net = new ServiceSyncNet();
        Settings Cfg(int port, int peer)
        {
            var st = new Settings { Mode = "demo", DbPath = ":memory:" };
            st.Sync.Enabled = true;
            st.Sync.Port = port;
            st.Sync.Key = "correct horse battery staple";
            st.Sync.Peer = $"127.0.0.1:{peer}";
            st.Sync.Network = "127.0.0.0/8";
            return st;
        }
        using var a = new ServiceFixture(settings: Cfg(18001, 18002), syncHandler: net);
        using var bStore = new Store(":memory:");
        using var b = new AdmiralService(Cfg(18002, 18001), bStore, new DemoDirectory(), syncHandler: net, applyProcessSettings: false);
        net.Peers[18001] = a.App.Sync;
        net.Peers[18002] = b.Sync;
        Assert.True(a.App.SyncListenerWanted);
        var guid = (string)a.App.Computers()[0]["guid"]!;
        a.App.Tag([guid], ["gyors"], []);
        a.App.CreateFleet("Szerverek", "static");
        var r = a.App.Sync.Run();
        Assert.True(r.Pushed > 0);
        Assert.Equal(0, r.Pulled);
        Assert.Equal(a.App.Computers().Count, b.Computers().Count);
        Assert.Contains("gyors", (List<string>)b.Computers().First(c => (string)c["guid"]! == guid)["tags"]!);
        Assert.NotNull(b.Store.FleetByName("Szerverek"));
        var r2 = a.App.Sync.Run();
        Assert.Equal(0, r2.Pushed + r2.Pulled);
    }

    [Fact]
    public void PeerCannotRedirectAKnownComputerOrWinForever()
    {
        var c = App.Computers()[0];
        var data = new SyncData(App.Store, body => App.Store.InTransaction(body));
        var rec = data.Export("computers", [(string)c["guid"]!])[0];
        var row = (JsonObject)rec["row"]!;
        row["dns_hostname"] = "evil.example";
        row["collected_at"] = "2099-01-01T00:00:00+00:00";
        Assert.Equal(0, data.Apply("computers", [rec]));                  // a time in the future is not believed
        row["collected_at"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(5));
        row["os"] = "Peer OS";
        row["collect_error"] = "peer note";
        Assert.Equal(1, data.Apply("computers", [rec]));                  // a newer record is merged...
        var after = App.Computers().First(x => (string)x["guid"]! == (string)c["guid"]!);
        Assert.Equal(c["os"], after["os"]);                               // ...but what AD says stays AD's word
        Assert.Equal(c["dns_hostname"], after["dns_hostname"]);           // ...but where we connect stays AD's business
    }

    [Fact]
    public void DeploymentPreviewListsTargetsAndWhatAPeerChanged()
    {
        var comps = App.Computers().OrderBy(c => (string)c["name"]!, StringComparer.OrdinalIgnoreCase).ToList();
        var (a, b, c) = (comps[0], comps[1], comps[2]);
        var data = new SyncData(App.Store, body => App.Store.InTransaction(body));
        var now = Db.UtcNow();
        // a peer creates a static collection holding b, and adds a tag to c
        Assert.Equal(1, data.Apply("fleets", [new JsonObject
        {
            ["name"] = "From peer", ["kind"] = "static", ["created"] = now, ["updated"] = now,
            ["members"] = new JsonArray((string)b["guid"]!),
        }]));
        var tagRec = data.Export("computers", [(string)c["guid"]!])[0];
        tagRec["tags"] = new JsonArray("peer-tag");
        data.Apply("computers", [tagRec]);
        var fid = (long)App.Store.FleetByName("From peer")!["id"]!;

        var pv = App.DeploymentPreview([(string)a["name"]!, (string)c["guid"]!], [fid]);
        Assert.Equal(new[] { a["name"], b["name"], c["name"] }.Order(), ((List<string>)pv["names"]!).Cast<object?>().Order());
        Assert.Equal(3, ((List<string>)pv["ids"]!).Count);
        Assert.Equal("From peer", Assert.Single((List<Row>)pv["peer_collections"]!)["name"]);
        var tag = Assert.Single((List<Row>)pv["peer_tags"]!);
        Assert.Equal((c["name"], "peer-tag"), (tag["computer"], tag["tag"]));
        Assert.Empty((List<string>)pv["refused"]!);
        Assert.Null(data.Export("fleets", ["From peer"])[0]["peer_changed"]);   // our own note is not sent to peers

        // edited here: no longer a peer's word
        App.Store.UpdateFleet(fid, new Dictionary<string, object?> { ["description"] = "checked" });
        App.Store.Tag([(string)c["guid"]!], add: ["peer-tag"]);
        pv = App.DeploymentPreview([(string)c["name"]!], [fid]);
        Assert.Empty((List<Row>)pv["peer_collections"]!);
        Assert.Equal(0, pv["peer_tags_total"]);
        // a later change by the peer marks it again
        var later = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(1));
        data.Apply("fleets", [new JsonObject { ["name"] = "From peer", ["kind"] = "static", ["created"] = now, ["updated"] = later, ["members"] = new JsonArray() }]);
        Assert.Single((List<Row>)App.DeploymentPreview([], [fid])["peer_collections"]!);
    }

    // ------------------------------------------------------------------ app update
    [Fact]
    public void LastUpdateCheckIsRemembered()
    {
        App.AppUpdateChecker = (_, _, _) => throw new UpdateError("offline");
        Assert.Null(App.AppUpdateState()["checked"]);
        var st = App.AppUpdateCheck();
        var checkedAt = (string)st["checked"]!;
        Assert.Contains("offline", (string)st["error"]!);
        Assert.False((bool)st["available"]!);
        App.ForgetAppUpdateCheck();                                       // as after a restart
        Assert.Equal(checkedAt, App.AppUpdateState()["checked"]);
        Assert.Equal(Config.AppUpdateUrl, App.AppUpdateState()["url"]);
        Assert.ThrowsAny<ArgumentException>(() => App.AppUpdateInstall());    // not an installed Windows program
    }

    [Fact]
    public void ReplayedOlderManifestIsRefused()
    {
        static JsonObject Signed(string at) => new() { ["signed"] = at };
        App.AppUpdateChecker = (_, _, _) => (Signed("2027-01-10T00:00:00Z"), new AppUpdateInfo("99.0.0", "", true, "98.0.0"));
        Assert.True((bool)App.AppUpdateCheck()["available"]!);
        // an older version, an older signing time, or no signing time at all: an old copy served again
        foreach (var (m, v) in new[] { (Signed("2027-02-01T00:00:00Z"), "98.5.0"), (Signed("2027-01-01T00:00:00Z"), "99.0.0"), (new JsonObject(), "99.0.0") })
        {
            App.AppUpdateChecker = (_, _, _) => (m, new AppUpdateInfo(v, "", true, null));
            var st = App.AppUpdateCheck();
            Assert.False((bool)st["available"]!);
            Assert.Contains("replayed", (string)st["error"]!);
        }
        // a fresh manifest (same version re-signed, or newer) is fine
        App.AppUpdateChecker = (_, _, _) => (Signed("2027-03-01T00:00:00Z"), new AppUpdateInfo("99.0.0", "", true, null));
        Assert.Null(App.AppUpdateCheck()["error"]);
    }

    [Fact]
    public void UpdateFoundIsReportedAndLogged()
    {
        App.AppUpdateChecker = (_, _, _) => ([], new AppUpdateInfo("99.0.0", "notes", true, null));
        var st = App.AppUpdateCheck();
        Assert.True((bool)st["available"]!);
        Assert.Equal("99.0.0", st["latest"]);
        Assert.Contains(App.Activity(), a => (string?)a["action"] == "appupdate");
    }

    // ------------------------------------------------------------------ remote assistance
    [Fact]
    public void RemoteAssistValidatesTheNameAndPassesSeparateArguments()
    {
        var starter = new FakeStarter();
        App.ProcessStarter = starter;
        App.RemoteAssist("LT-001.contoso.local.");
        var info = Assert.Single(starter.Started);
        Assert.Equal("msra.exe", Path.GetFileName(info.FileName));
        Assert.True(Path.IsPathRooted(info.FileName) || info.FileName.StartsWith("C:", StringComparison.Ordinal));
        Assert.Equal(new[] { "/offerra", "LT-001.contoso.local" }, info.ArgumentList);
        Assert.Equal("", info.Arguments);
        foreach (var bad in new[] { "", "pc1 & calc", "pc1\" /x", "-pc", "/expert", "a;b", "pc\n2", "..", new string('a', 300) })
            Assert.ThrowsAny<ArgumentException>(() => App.RemoteAssist(bad));
        Assert.Single(starter.Started);
    }

    [Fact]
    public void EventViewerValidatesTheNameAndPassesItAsOneArgument()
    {
        var starter = new FakeStarter();
        App.ProcessStarter = starter;
        App.EventViewer("LT-001.contoso.local");
        var info = Assert.Single(starter.Started);
        Assert.Equal("eventvwr.exe", Path.GetFileName(info.FileName));
        Assert.Equal(new[] { "LT-001.contoso.local" }, info.ArgumentList);
        Assert.Equal("", info.Arguments);
        Assert.Equal("", info.Verb);                                      // no elevation: runs as the signed-in user
        foreach (var bad in new[] { "", "pc1 & calc", "/c:x", "-pc", "a;b", new string('a', 300) })
            Assert.ThrowsAny<ArgumentException>(() => App.EventViewer(bad));
        Assert.Single(starter.Started);
    }

    [Fact]
    public void ComputerManagementStartsTheSnapInForTheValidatedHost()
    {
        var starter = new FakeStarter();
        App.ProcessStarter = starter;
        App.ComputerManagement("LT-001.contoso.local.");
        var info = Assert.Single(starter.Started);
        Assert.Equal("mmc.exe", Path.GetFileName(info.FileName));
        Assert.Equal("compmgmt.msc", Path.GetFileName(info.ArgumentList[0]));
        Assert.True(Path.IsPathRooted(info.ArgumentList[0]) || info.ArgumentList[0].StartsWith("C:", StringComparison.Ordinal));   // never a planted .msc
        Assert.Equal("/computer=LT-001.contoso.local", info.ArgumentList[1]);
        Assert.Equal(2, info.ArgumentList.Count);
        Assert.Equal("", info.Arguments);
        foreach (var bad in new[] { "", "pc1 & calc", "pc1 /a", "-pc", "a;b", new string('a', 300) })
            Assert.ThrowsAny<ArgumentException>(() => App.ComputerManagement(bad));
        Assert.Single(starter.Started);
    }

    [Fact]
    public void ActivityAndUnfinishedDeployments()
    {
        Assert.True(App.Activity(5).Count <= 5);
        Assert.Contains(App.Activity(), a => (string?)a["action"] == "ad-sync");
        Assert.Equal(0, App.UnfinishedDeployments());
        App.Store.CreateDeployment("A.B", "AB", "1", "f.exe", "exe", "/S", [("g1", "PC1"), ("g2", "PC2")]);
        Assert.Equal(0, App.UnfinishedDeployments());                    // no running job: nothing is being tracked
        using var gate = new ManualResetEventSlim();
        var job = App.Jobs.Start("deploy", "deploy", _ => gate.Wait(5000));
        try
        {
            Assert.Equal(2, App.UnfinishedDeployments());
        }
        finally
        {
            gate.Set();
        }
        _f.WaitJob(job.Id);
    }
}

/// <summary>The retry loop builds services with the process-wide settings (language, debug log), so it runs with the
/// other tests that touch them.</summary>
[Collection("Diagnostics")]
public sealed class RetryLoopTests
{
    [Fact]
    public void RunLoopReturnsAtOnceWhenStopped()
    {
        using var tmp = new CoreTemp();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Retry.RunLoop(tmp.Path, cts.Token, firstDelaySeconds: 0);
        Retry.SyncLoop(tmp.Path, cts.Token);
    }

    [Fact]
    public void RetryLoopRunsAPassFromTheDataFolder()
    {
        using var tmp = new CoreTemp();
        File.WriteAllText(tmp.File("admiral.toml"), "mode = \"demo\"\ndb_path = \"x.db\"\n[retry]\ninterval_minutes = 1\n");
        using (var seed = new AdmiralService(Retry.LoadSettings(tmp.Path), syncAutostart: false, applyProcessSettings: false))
        {
            Assert.Equal(tmp.File("x.db"), seed.Settings.DbPath);
            seed.SyncAd();
            seed.Store.RecordScan(seed.Store.ResolveNames(["LT-001"])[0], null, []);
        }
        using var cts = new CancellationTokenSource();
        var t = new Thread(() => Retry.RunLoop(tmp.Path, cts.Token, firstDelaySeconds: 0)) { IsBackground = true };
        t.Start();
        var found = false;
        for (var i = 0; i < 300 && !found; i++)
        {
            Thread.Sleep(50);
            using var check = new Store(tmp.File("x.db"));
            found = check.Activity().Any(a => (string?)a["action"] == "retry");
        }
        cts.Cancel();
        Assert.True(t.Join(TimeSpan.FromSeconds(20)));
        Assert.True(found);
    }
}
