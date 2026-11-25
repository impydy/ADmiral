using System.Text.Json.Nodes;
using ADmiral.Core;
using Microsoft.Data.Sqlite;

namespace ADmiral.Tests;

/// <summary>The Store parts of test_inventory.py / test_ou_scope.py plus every other query method.</summary>
public class DbTests
{
    private const string Domain = "DC=contoso,DC=local";

    private static Dictionary<string, object?> Rec(string guid, string name, string ou, bool enabled = true, string? lastLogon = null) => new()
    {
        ["guid"] = guid, ["name"] = name, ["dns_hostname"] = name.ToLowerInvariant() + ".contoso.local",
        ["dn"] = $"CN={name},{ou}", ["ou"] = DnUtil.OuPath($"CN={name},{ou}"), ["os"] = "Windows 11 Pro", ["enabled"] = enabled,
        ["last_logon"] = lastLogon ?? Db.UtcNow(), ["member_of"] = new List<string> { "CN=BitLocker-Laptops,OU=Groups," + Domain },
    };

    private static readonly string Servers = "OU=Servers," + Domain;
    private static readonly string Laptops = "OU=Laptops,OU=Workstations," + Domain;

    private static List<Dictionary<string, object?>> Fleet() =>
    [
        Rec("g-lt1", "LT-001", Laptops), Rec("g-lt2", "LT-002", Laptops), Rec("g-lt3", "LT-003", Laptops, lastLogon: "2020-01-01T00:00:00+00:00"),
        Rec("g-sql1", "SQL-01", Servers), Rec("g-sql2", "SQL-02", Servers), Rec("g-app", "APP-01", "OU=App," + Servers, enabled: false),
    ];

    private static Store NewStore()
    {
        var s = new Store(":memory:");
        s.UpsertFromAd(Fleet());
        return s;
    }

    private static JsonObject Inventory() => new()
    {
        ["model"] = "Latitude", ["last_boot"] = DateTime.UtcNow.AddHours(-2).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        ["apps"] = new JsonArray(new JsonObject { ["name"] = "Microsoft SQL Server 2019", ["version"] = "15.0", ["publisher"] = "Microsoft" },
                                 new JsonObject { ["name"] = "7-Zip 24.09 (x64)", ["version"] = "24.09" }),
        ["services"] = new JsonArray(new JsonObject { ["name"] = "Spooler" }),
        ["disks"] = new JsonArray(new JsonObject { ["drive"] = "C:" }),
        ["logons"] = new JsonArray(new JsonObject { ["time"] = "2026-01-01T08:00:00", ["user"] = "anna", ["domain"] = "CORP", ["type"] = 2 }),
    };

    [Fact]
    public void MigratesV0Database()
    {
        using var tmp = new CoreTemp();
        var path = tmp.File("old.db");
        using (var con = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            con.Open();
            using var cmd = con.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE computers (guid TEXT PRIMARY KEY, name TEXT NOT NULL, dns_hostname TEXT, dn TEXT,
                  ou TEXT, os TEXT, os_version TEXT, enabled INTEGER NOT NULL DEFAULT 1, last_logon TEXT,
                  created TEXT, description TEXT, ad_synced_at TEXT, ip TEXT, online INTEGER, open_ports TEXT,
                  scanned_at TEXT, inventory TEXT, collected_at TEXT, collect_error TEXT);
                INSERT INTO computers (guid, name, ad_synced_at, inventory) VALUES ('g1', 'OLD-PC', '2024-01-01T00:00:00+00:00', '{"model": "X"}');
                """;
            cmd.ExecuteNonQuery();
        }
        using (var store = new Store(path))
        {
            Assert.Equal(12, store.SchemaVersion);
            var c = store.Computer("g1")!;
            Assert.Equal("2024-01-01T00:00:00+00:00", c["added"]);
            Assert.Equal(true, c["allow_scan"]);
            Assert.Equal("ok", c["scan_status"]);
            Assert.Equal("X", (string?)((JsonObject)c["inventory"]!)["model"]);
        }
        using var again = new Store(path);
        Assert.Equal(12, again.SchemaVersion);                   // idempotent
    }

    [Fact]
    public void UtcNowFormat()
    {
        Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$", Db.UtcNow());
        Assert.Equal(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), Db.ParseIso("2024-01-01T00:00:00"));
        Assert.Equal(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), Db.ParseIso("2024-01-01T00:00:00Z"));
        Assert.Null(Db.ParseIso("garbage"));
    }

    [Fact]
    public void UpsertFromAdAndComputerRows()
    {
        using var s = new Store(":memory:");
        var r = s.UpsertFromAd(Fleet());
        Assert.Equal((6, 0, 0), (r["added"], r["updated"], r["removed"]));
        r = s.UpsertFromAd(Fleet().Take(5));
        Assert.Equal((0, 5, 1), (r["added"], r["updated"], r["removed"]));
        var all = s.Computers();
        Assert.Equal(["LT-001", "LT-002", "LT-003", "SQL-01", "SQL-02"], all.Select(c => (string)c["name"]!));
        var lt3 = all[2];
        Assert.Equal(true, lt3["stale"]);
        Assert.Equal(false, all[0]["stale"]);
        Assert.Equal(0L, all[0]["last_logon_days"]);
        Assert.Equal(true, all[0]["enabled"]);
        Assert.Null(all[0]["online"]);
        Assert.Empty((List<int>)all[0]["open_ports"]!);
        Assert.Single((List<string>)all[0]["member_of"]!);
        Assert.NotNull(all[0]["added"]);
        Assert.True(s.Version >= 2);
    }

    [Fact]
    public void ScopedSyncKeepsComputersElsewhere()
    {
        using var s = NewStore();
        var total = s.Computers().Count;
        var inside = Fleet().Where(c => DnUtil.IsUnder((string)c["dn"]!, Servers)).ToList();
        var gone = (string)inside[0]["guid"]!;
        // a computer inside the scope that has vanished from AD is dropped, nothing outside is touched
        var r = s.UpsertFromAd(inside.Where(c => (string)c["guid"]! != gone), Servers);
        Assert.Equal(1, r["removed"]);
        Assert.Equal(total - 1, s.Computers().Count);
        s.UpsertFromAd(Fleet());
        Assert.Equal(total, s.Computers().Count);
    }

    [Fact]
    public void HiddenComputersSurviveAdSync()
    {
        using var s = NewStore();
        var total = s.Computers().Count;
        var guids = s.ResolveNames(["lt-001", "g-sql1"]);
        Assert.Equal(["g-lt1", "g-sql1"], guids);
        s.SetHidden(guids, true);
        Assert.Equal(total - 2, s.Computers().Count);
        s.UpsertFromAd(Fleet());                                   // must not bring them back
        Assert.Equal(total - 2, s.Computers().Count);
        Assert.Equal(2, s.HiddenCount());
        Assert.Null(s.Computer("g-lt1"));
        Assert.Throws<KeyNotFoundException>(() => s.ResolveNames(["LT-001"]));
        Assert.Equal(2, s.RestoreHidden());
        Assert.Equal(total, s.Computers().Count);
        var ex = Assert.Throws<KeyNotFoundException>(() => s.ResolveNames(["nope", "LT-002"]));
        Assert.Contains("nope", ex.Message);
    }

    [Fact]
    public void RecordScan()
    {
        using var s = NewStore();
        s.RecordScan("g-lt1", "10.0.0.1", [5985, 445]);
        var c = s.Computer("g-lt1")!;
        Assert.Equal(true, c["online"]);
        Assert.Equal([445, 5985], (List<int>)c["open_ports"]!);
        Assert.Equal("10.0.0.1", c["ip"]);
        s.RecordScan("g-lt1", null, []);
        c = s.Computer("g-lt1")!;
        Assert.Equal(false, c["online"]);
        Assert.Equal("offline", c["scan_status"]);
        Assert.Equal("10.0.0.1", c["ip"]);                          // kept
        s.RecordScan("g-lt1", null, [445]);
        Assert.Null(s.Computer("g-lt1")!["scan_status"]);
    }

    [Fact]
    public void InventoryIsStoredWithListsInTheirOwnTable()
    {
        using var s = NewStore();
        s.RecordScan("g-lt1", "10.0.0.1", [445]);
        s.RecordInventory("g-lt1", Inventory());
        var c = s.Computer("g-lt1")!;
        Assert.Equal("ok", c["scan_status"]);
        Assert.NotNull(c["uptime_s"]);
        Assert.InRange((long)c["uptime_s"]!, 7000, 7400);
        var inv = (JsonObject)c["inventory"]!;
        Assert.False(inv.ContainsKey("apps"));
        var items = s.Items("g-lt1");
        Assert.Equal(Db.ListKinds.Order(), items.Keys.Order());
        Assert.Equal(2, items["apps"].Count);
        Assert.Single(items["logons"]);
        var n = (long)s.Scalar("SELECT COUNT(*) FROM computer_items WHERE guid = ?", "g-lt1")!;
        Assert.Equal(items.Values.Sum(v => v.Count), n);
        Assert.Equal(2, s.ItemCounts("g-lt1")["apps"]);
        Assert.Contains(s.AppRows(), r => r == ("g-lt1", "7-Zip 24.09 (x64)", "24.09", ""));
        Assert.Equal(["Microsoft SQL Server 2019", "7-Zip 24.09 (x64)"], s.AppIndex()["g-lt1"]);
        Assert.Single(s.LogonRows());
    }

    [Fact]
    public void FailedCollectionKeepsPreviousData()
    {
        using var s = NewStore();
        s.RecordInventory("g-lt1", Inventory());
        s.RecordInventory("g-lt1", null, "boom");
        var after = s.Computer("g-lt1")!;
        Assert.Equal("failed", after["scan_status"]);
        Assert.Equal("boom", after["collect_error"]);
        Assert.NotNull(after["inventory"]);
        Assert.NotEmpty(s.Items("g-lt1")["apps"]);
    }

    [Fact]
    public void RescanReplacesRowsAndPartialKeepsFailedSection()
    {
        using var s = NewStore();
        s.RecordInventory("g-lt1", Inventory());
        s.RecordInventory("g-lt1", new JsonObject
        {
            ["model"] = "New", ["apps"] = new JsonArray(new JsonObject { ["name"] = "Only" }),
            ["section_errors"] = new JsonObject { ["services"] = "denied" },
        });
        var after = s.Computer("g-lt1")!;
        Assert.Equal("partial", after["scan_status"]);
        Assert.Equal("services: denied", after["collect_error"]);
        var items = s.Items("g-lt1");
        Assert.Equal(["Only"], items["apps"].Select(a => (string?)a["name"]));
        Assert.NotEmpty(items["services"]);                        // old rows kept
        Assert.Single(items["logons"]);                            // logons are merged, never dropped
    }

    [Fact]
    public void LogonsAreMerged()
    {
        using var s = NewStore();
        s.RecordInventory("g-lt1", Inventory());
        s.AddLogons("g-lt1", [
            new JsonObject { ["time"] = "2026-02-01T08:00:00", ["user"] = "bela", ["domain"] = "CORP", ["type"] = 10 },
            new JsonObject { ["time"] = "2026-01-01T08:00:00", ["user"] = "ANNA", ["domain"] = "corp", ["type"] = 2 },  // duplicate
        ]);
        var logons = s.Items("g-lt1")["logons"];
        Assert.Equal(["bela", "ANNA"], logons.Select(l => (string?)l["user"]));
    }

    [Fact]
    public void LocalAccountsAreNotStoredAsLogonsOrLoggedOnUser()
    {
        using var s = NewStore();
        var inv = Inventory();
        inv["logged_on_user"] = @"lt-001\helyi";
        inv["user_display_name"] = "Helyi";
        inv["logons"] = new JsonArray(
            new JsonObject { ["time"] = "2026-03-01T08:00:00", ["user"] = "Administrator", ["domain"] = "LT-001", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-03-02T08:00:00", ["user"] = "helyi", ["domain"] = ".", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-03-03T08:00:00", ["user"] = "anna", ["domain"] = "CORP", ["type"] = 2 });
        inv["user_accounts"] = new JsonArray(new JsonObject { ["name"] = "Administrator", ["domain"] = "LT-001", ["type"] = "local" },
                                             new JsonObject { ["name"] = "anna", ["domain"] = "CORP", ["type"] = "domain" });
        s.RecordInventory("g-lt1", inv);
        Assert.Equal(["anna"], s.Items("g-lt1")["logons"].Select(l => (string?)l["user"]));
        var c = (JsonObject)s.Computer("g-lt1")!["inventory"]!;
        Assert.Null(c["logged_on_user"]);
        Assert.Null(c["user_display_name"]);
        Assert.Equal(2, s.Items("g-lt1")["user_accounts"].Count);       // the account list keeps the local ones
        // a domain user stays the logged-on user
        inv["logged_on_user"] = @"CORP\anna";
        s.RecordInventory("g-lt1", inv);
        Assert.Equal(@"CORP\anna", (string?)((JsonObject)s.Computer("g-lt1")!["inventory"]!)["logged_on_user"]);
    }

    [Fact]
    public void AllowScanTagsAndActivity()
    {
        using var s = NewStore();
        s.SetAllowScan(["g-lt1", "g-lt2"], false);
        Assert.Equal(false, s.Computer("g-lt1")!["allow_scan"]);
        s.Tag(["g-lt1", "g-lt2"], add: ["pilot", "eu"]);
        s.Tag(["g-lt2"], remove: ["eu"]);
        Assert.Equal(["eu", "pilot"], (List<string>)s.Computer("g-lt1")!["tags"]!);
        var tags = s.AllTags();
        Assert.Equal(("eu", 1L), ((string)tags[0]["tag"]!, (long)tags[0]["count"]!));
        Assert.Equal(("pilot", 2L), ((string)tags[1]["tag"]!, (long)tags[1]["count"]!));
        s.Log("scan", "first");
        s.Log("collect", "second");
        var act = s.Activity();
        Assert.Equal(["collect", "scan"], act.Select(a => (string)a["action"]!));
        Assert.Single(s.Activity(1));
    }

    [Fact]
    public void Fleets()
    {
        using var s = NewStore();
        var id = s.CreateFleet("SQL hosts", "dynamic", rules: new JsonObject
        {
            ["conditions"] = new JsonArray(new JsonObject { ["field"] = "app", ["op"] = "any_contains", ["value"] = "sql server" }),
        });
        var stat = s.CreateFleet("Pilot", "static", "desc", adGroupDn: "");
        var f = s.Fleet(id)!;
        Assert.Equal("dynamic", f["kind"]);
        Assert.IsType<JsonObject>(f["rules"]);
        Assert.Null(s.Fleet(stat)!["ad_group_dn"]);
        Assert.Equal(id, (long)s.FleetByName("sql HOSTS")!["id"]!);
        Assert.Equal(["Pilot", "SQL hosts"], s.Fleets().Select(x => (string)x["name"]!));
        Assert.Throws<SqliteException>(() => s.CreateFleet("pilot2", "weird"));
        s.UpdateFleet(stat, new Dictionary<string, object?> { ["name"] = "Pilot ring", ["rules"] = new JsonObject(), ["ad_group_dn"] = "CN=G" });
        var upd = s.Fleet(stat)!;
        Assert.Equal(("Pilot ring", null, "CN=G"), ((string)upd["name"]!, upd["rules"], (string?)upd["ad_group_dn"]));
        Assert.Throws<ArgumentException>(() => s.UpdateFleet(stat, new Dictionary<string, object?> { ["kind"] = "dynamic" }));
        Assert.Throws<ArgumentException>(() => s.UpdateFleet(stat, new Dictionary<string, object?> { ["name = 'x' --"] = "y" }));
        s.SetStaticMembers(stat, add: ["g-lt1", "g-lt2"]);
        s.SetStaticMembers(stat, remove: ["g-lt2"]);
        Assert.Equal(["g-lt1"], s.StaticMembers(stat));
        s.UpsertFromAd(Fleet().Skip(1), null);                     // g-lt1 vanished from AD: membership cascades
        Assert.Empty(s.StaticMembers(stat));
        s.DeleteFleet(stat);
        Assert.Null(s.Fleet(stat));
    }

    [Fact]
    public void Deployments()
    {
        using var s = NewStore();
        var dep = s.CreateDeployment("Google.Chrome", null, "131.0", "chrome.msi", "msi", "/qn",
                                     [("g-lt1", "LT-001"), ("g-lt2", "LT-002"), ("g-lt3", "LT-003")]);
        var d = s.Deployment(dep)!;
        Assert.Equal("Google.Chrome", d["package_name"]);
        Assert.Equal("running", d["status"]);
        Assert.Equal(3, ((List<Dictionary<string, object?>>)d["targets"]!).Count);
        s.UpdateTarget(dep, "g-lt1", new Dictionary<string, object?>
        {
            ["step"] = "done", ["outcome"] = "ok", ["started"] = "2026-01-01T00:00:00+00:00", ["finished"] = "2026-01-01T00:00:10+00:00",
            ["ignored; DROP TABLE x"] = 1,
        });
        s.UpdateTarget(dep, "g-lt2", new Dictionary<string, object?> { ["step"] = "running", ["percent"] = 50 });
        s.AddDeploymentEvent(dep, "copied", "LT-001");
        s.AddDeploymentEvent(dep, "started");
        Assert.Equal(["copied", "started"], s.DeploymentEvents(dep).Select(e => (string)e["message"]!));
        var list = s.Deployments();
        Assert.Equal((3, 1, 1, 1, 10L), ((int)list[0]["total"]!, (int)list[0]["queued"]!, (int)list[0]["running"]!, (int)list[0]["ok"]!, (long?)list[0]["avg_seconds"]));
        Assert.Equal(1, s.FailInterruptedDeployments());          // the program stopped: the rest failed
        Assert.Equal("partial", s.Deployment(dep)!["status"]);

        var dep2 = s.CreateDeployment("X", "X app", "1", "x.exe", "exe", "", [("g-lt1", "LT-001")]);
        s.UpdateTarget(dep2, "g-lt1", new Dictionary<string, object?> { ["outcome"] = "unreachable" });
        Assert.Equal("skipped", s.FinishDeployment(dep2));
        s.UpdateTarget(dep2, "g-lt1", new Dictionary<string, object?> { ["outcome"] = "reboot" });
        Assert.Equal("done", s.FinishDeployment(dep2));
        s.UpdateTarget(dep2, "g-lt1", new Dictionary<string, object?> { ["outcome"] = "failed" });
        Assert.Equal("failed", s.FinishDeployment(dep2));
        Assert.Null(s.Deployment(999));
    }

    [Fact]
    public void Printers()
    {
        using var s = new Store(":memory:");
        var id = s.AddPrinter(new Dictionary<string, object?> { ["ip"] = "10.0.0.9", ["location"] = "2nd floor", ["bogus"] = "x" });
        Assert.Throws<SqliteException>(() => s.AddPrinter(new Dictionary<string, object?> { ["ip"] = "10.0.0.9" }));
        var p = s.Printer(id)!;
        Assert.Equal("public", p["community"]);
        Assert.Empty((JsonArray)p["toner"]!);
        var updated = (string)p["updated"]!;
        s.UpdatePrinter(id, new Dictionary<string, object?> { ["toner"] = new List<int?> { 50, null }, ["pages"] = 1200 });
        p = s.Printer(id)!;
        Assert.Equal(2, ((JsonArray)p["toner"]!).Count);
        Assert.Equal(1200L, p["pages"]);
        Assert.Equal(updated, p["updated"]);                        // a reading is not an edit
        s.SavePrinterSample("10.0.0.9", "2026-01-01", 1000, [60]);
        s.SavePrinterSample("10.0.0.9", "2026-01-02", 1100, [55]);
        s.SavePrinterSample("10.0.0.9", "2026-01-02", 1150, [54]);  // same day: replaced
        var hist = s.PrinterHistory("10.0.0.9");
        Assert.Equal(["2026-01-01", "2026-01-02"], hist.Select(h => (string)h["day"]!));
        Assert.Equal(1150L, hist[1]["pages"]);
        Assert.Equal("2026-01-02", s.PrinterSampleDays()["10.0.0.9"]);
        Assert.Single(s.PrinterHistory("10.0.0.9", 1));
        Assert.Single(s.Printers());
        Assert.True(s.DeletePrinter(id));
        Assert.False(s.DeletePrinter(id));
        Assert.Empty(s.PrinterHistory("10.0.0.9"));
    }

    [Fact]
    public void CvesKevUpdatesAndUsers()
    {
        using var s = new Store(":memory:");
        s.SaveCves("google", "chrome", [new CveRecord("CVE-1", "2026-01-01", 8.8, "d", [[null, null, null, "131.0", null]])]);
        var cves = s.CvesFor("google", "chrome");
        Assert.Equal("CVE-1", cves[0].Cve);
        Assert.Equal(8.8, cves[0].Score);
        Assert.Equal("131.0", cves[0].Matches[0][3]);
        Assert.True(s.CveFetched().ContainsKey(("google", "chrome")));
        s.SaveCves("google", "chrome", []);
        Assert.Empty(s.CvesFor("google", "chrome"));

        s.SaveKev(["CVE-2", "CVE-1", "CVE-2"]);
        Assert.Equal(["CVE-1", "CVE-2"], s.KevSet().Order());

        s.SaveUpdateReference(new Dictionary<string, UpdateRef> { ["10.0.22631"] = new(4602, "2024-Dec", "2024-12-10") },
                              new Dictionary<string, string> { ["fetched_at"] = "x" });
        s.SetUpdateMeta(new Dictionary<string, string> { ["fetched_at"] = "y", ["months"] = "3" });
        var (builds, meta) = s.UpdateReference();
        Assert.Equal(4602, builds["10.0.22631"].Ubr);
        Assert.Equal("y", meta["fetched_at"]);

        var v = s.Version;
        s.SaveAdUsers(new Dictionary<string, JsonObject> { ["anna"] = new() { ["displayName"] = "Nagy Anna" } });
        Assert.True(s.Version > v);
        var users = s.AdUsers();
        Assert.Equal("Nagy Anna", (string?)users["anna"]["displayName"]);
        Assert.NotNull(users["anna"]["synced_at"]);
    }

    [Fact]
    public void ParametersAreNeverSqlText()
    {
        using var s = NewStore();
        const string evil = "x'); DROP TABLE computers; --";
        s.Log(evil, "?");
        s.Tag(["g-lt1"], add: [evil]);
        Assert.Equal(evil, s.Activity()[0]["action"]);
        Assert.Equal(6, s.Computers().Count);
        Assert.Throws<ArgumentException>(() => s.Query("SELECT * FROM computers WHERE guid = ?"));
        Assert.Single(s.Query("SELECT name FROM computers WHERE name = '?' OR guid = ?", "g-lt1"));
    }
}
