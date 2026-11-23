using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>syncdata.py: manifests, the merge plan and the merge rules (newer wins, nothing deleted, peers cannot
/// redirect a known computer or win forever) - test_security.py plus the rules of every category.</summary>
public class SyncDataTests
{
    internal static Dictionary<string, object?> Rec(string guid, string name) => new()
    {
        ["guid"] = guid, ["name"] = name, ["dns_hostname"] = name.ToLowerInvariant() + ".corp.local",
        ["dn"] = $"CN={name},OU=PCs,DC=corp,DC=local", ["ou"] = "OU=PCs,DC=corp,DC=local", ["os"] = "Windows 11 Pro", ["enabled"] = true,
    };

    internal static Store StoreWith(params string[] names)
    {
        var s = new Store(":memory:");
        s.UpsertFromAd(names.Select((n, i) => (IReadOnlyDictionary<string, object?>)Rec("g-" + n.ToLowerInvariant(), n)).ToList());
        return s;
    }

    [Fact]
    public void PlanPullsNewerPushesOlderAndUnionsTags()
    {
        var local = new Dictionary<string, string> { ["a"] = "2026-01-02|h1", ["b"] = "2026-01-01|h1", ["c"] = "2026-01-01|h1", ["mine"] = "x", ["same"] = "t|h" };
        var remote = new Dictionary<string, string> { ["a"] = "2026-01-01|h1", ["b"] = "2026-01-02|h1", ["c"] = "2026-01-01|h2", ["theirs"] = "y", ["same"] = "t|h" };
        var (pull, push) = SyncData.Plan(local, remote);
        Assert.Equal(["b", "c", "theirs"], pull.Order());
        Assert.Equal(["a", "c", "mine"], push.Order());
    }

    [Fact]
    public void PeerCannotRedirectAKnownComputerOrWinForever()
    {
        using var store = StoreWith("PC-1");
        var data = new SyncData(store);
        var rec = data.Export("computers", ["g-pc-1"])[0];
        var row = (JsonObject)rec["row"]!;
        row["dns_hostname"] = "evil.example";
        row["collected_at"] = "2099-01-01T00:00:00+00:00";
        Assert.Equal(0, data.Apply("computers", [rec]));                      // a time in the future is not believed
        row["collected_at"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(30));          // beyond the 10-minute clock skew
        Assert.Equal(0, data.Apply("computers", [rec]));
        var soon = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(5));
        row["collected_at"] = soon;
        row["os"] = "Peer OS";
        row["ou"] = "corp.local/Servers";
        row["enabled"] = 0;
        row["collect_error"] = "peer note";
        Assert.Equal(1, data.Apply("computers", [rec]));                      // a newer record is merged...
        var after = store.Query("SELECT * FROM computers WHERE guid = 'g-pc-1'")[0];
        Assert.Equal("peer note", after["collect_error"]);                    // ...its inventory / scan data...
        Assert.NotEqual("Peer OS", after["os"]);                              // ...but what AD says (and so which dynamic
        Assert.NotEqual("corp.local/Servers", after["ou"]);                   // collections it is in) stays this AD's word
        Assert.Equal(1L, after["enabled"]);
        Assert.Equal("pc-1.corp.local", after["dns_hostname"]);                // ...but where we connect stays AD's business
    }

    private static JsonObject PeerComputer(string guid, string name, string host) => new()
    {
        ["row"] = new JsonObject
        {
            ["guid"] = guid, ["name"] = name, ["dns_hostname"] = host, ["dn"] = $"CN={name},OU=PCs,DC=corp,DC=local",
            ["allow_scan"] = 1, ["enabled"] = 1, ["collected_at"] = Db.UtcNow(),
        },
    };

    private static JsonObject PeerSid(string guid, string name)
    {
        var c = PeerComputer(guid, name, name.ToLowerInvariant() + ".corp.local");
        c["row"]!["sid"] = "S-1-5-21-6-6-6-1001";
        return c;
    }

    [Fact]
    public void ComputerOnlyAPeerKnowsIsNotScannedUntilOurAdConfirmsIt()
    {
        using var store = StoreWith("PC-1");
        var data = new SyncData(store);
        Assert.Equal(1, data.Apply("computers", [PeerComputer("g-evil", "EVIL", "attacker.example")]));
        var row = store.Query("SELECT allow_scan, dns_hostname FROM computers WHERE guid = 'g-evil'")[0];
        Assert.Equal(0L, row["allow_scan"]);                                  // the peer's allow_scan = 1 is ignored
        // nor may a peer name the account SID the drop-folder owner check trusts
        Assert.Equal(1, data.Apply("computers", [PeerSid("g-evil2", "EVIL2")]));
        Assert.Null(store.Scalar("SELECT sid FROM computers WHERE guid = 'g-evil2'"));
        Assert.Contains("g-evil", data.Unconfirmed());
        Assert.False(store.Computers(30).Single(c => (string)c["guid"]! == "g-evil")["allow_scan"] is true);

        // a later (newer) record from the peer cannot switch scanning on, nor change the host
        var again = PeerComputer("g-evil", "EVIL", "other.example");
        ((JsonObject)again["row"]!)["collected_at"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(1, data.Apply("computers", [again]));
        row = store.Query("SELECT allow_scan, dns_hostname FROM computers WHERE guid = 'g-evil'")[0];
        Assert.Equal(0L, row["allow_scan"]);
        Assert.Equal("attacker.example", row["dns_hostname"]);
        Assert.Contains("g-evil", data.Unconfirmed());

        // nor switch it on / off for a computer our AD knows (the administrator's choice stays)
        store.SetAllowScan(["g-pc-1"], false);
        var known = data.Export("computers", ["g-pc-1"])[0];
        ((JsonObject)known["row"]!)["allow_scan"] = 1;
        ((JsonObject)known["row"]!)["collected_at"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(1, data.Apply("computers", [known]));
        Assert.Equal(0L, store.Scalar("SELECT allow_scan FROM computers WHERE guid = 'g-pc-1'"));
        Assert.DoesNotContain("g-pc-1", data.Unconfirmed());

        // our own AD sync reads the same GUID: host / DN / name are AD's, scanning returns to the default
        store.UpsertFromAd([Rec("g-pc-1", "PC-1"), Rec("g-evil", "REAL-PC")]);
        row = store.Query("SELECT allow_scan, dns_hostname, name FROM computers WHERE guid = 'g-evil'")[0];
        Assert.Equal(1L, row["allow_scan"]);
        Assert.Equal("real-pc.corp.local", row["dns_hostname"]);
        Assert.Equal("REAL-PC", row["name"]);
        Assert.Empty(data.Unconfirmed());
        Assert.Equal(0L, store.Scalar("SELECT allow_scan FROM computers WHERE guid = 'g-pc-1'"));   // not touched
        // and a quarantined computer AD later drops disappears with its marker
        Assert.Equal(1, data.Apply("computers", [PeerComputer("g-gone", "GONE", "gone.example")]));
        store.UpsertFromAd([Rec("g-pc-1", "PC-1"), Rec("g-evil", "REAL-PC")]);
        Assert.Empty(data.Unconfirmed());
    }

    [Fact]
    public void ServiceDoesNotScanOrCollectAComputerOnlyAPeerKnows()
    {
        using var fx = new ServiceFixture();
        var probed = new List<string>();
        fx.App.ProbeOverride = (h, p, t) =>
        {
            lock (probed) probed.Add(h);
            return new ProbeResult(null, []);
        };
        Assert.Equal(1, fx.App.Sync.Data.Apply("computers", [PeerComputer("g-evil", "EVIL", "attacker.example")]));
        var before = fx.App.Scan();
        Assert.DoesNotContain("attacker.example", probed);
        Assert.DoesNotContain("EVIL", probed);
        Assert.True(before["skipped"] >= 1);
        var r = fx.App.Scan(guids: ["g-evil"]);
        Assert.Equal(0, r["scanned"]);
        Assert.Equal(1, r["skipped"]);
        Assert.Equal(0, fx.App.Collect(guids: ["g-evil"])["attempted"]);
        Assert.DoesNotContain(probed, h => h.Contains("attacker", StringComparison.Ordinal));
    }

    [Fact]
    public void PeerTimestampsMayBeAtMostTenMinutesAhead()
    {
        Assert.Equal(TimeSpan.FromMinutes(10), SyncData.FutureSkew);
        var now = DateTimeOffset.Parse("2026-11-21T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(Db.FormatUtc(now.AddMinutes(10)), SyncData.Horizon(now));
        using var a = StoreWith("PC-1");
        using var b = StoreWith("PC-1");
        var da = new SyncData(a);
        var db = new SyncData(b);
        a.SaveAdUsers(new Dictionary<string, JsonObject> { ["bob"] = new() { ["displayName"] = "Bob" } });
        a.CreateFleet("Lab", "static", "test");
        a.AddPrinter(new Dictionary<string, object?> { ["ip"] = "10.0.0.5", ["model"] = "LaserJet", ["community"] = "public", ["version"] = "2c" });
        a.SavePrinterSample("10.0.0.5", "2026-11-20", 1000, [50, null]);
        var late = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(20));
        var user = da.Export("users", ["bob"])[0];
        user["synced_at"] = late;
        var fleet = da.Export("fleets", ["Lab"])[0];
        fleet["updated"] = late;
        var printer = (JsonObject)da.Export("printers", ["p:10.0.0.5"])[0]["printer"]!;
        printer["updated"] = late;
        var reading = (JsonObject)da.Export("printers", ["h:10.0.0.5|2026-11-20"])[0]["history"]!;
        reading["taken_at"] = late;
        var comp = PeerComputer("g-x", "X", "x.example");
        ((JsonObject)comp["row"]!)["collected_at"] = late;
        Assert.Equal(0, db.Apply("users", [user]));
        Assert.Equal(0, db.Apply("fleets", [fleet]));
        Assert.Equal(0, db.Apply("printers", [new JsonObject { ["printer"] = printer.DeepClone() }]));
        Assert.Equal(0, db.Apply("printers", [new JsonObject { ["history"] = reading.DeepClone() }]));
        Assert.Equal(0, db.Apply("computers", [comp]));
        // within the skew: accepted
        var ok = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(5));
        user["synced_at"] = ok;
        Assert.Equal(1, db.Apply("users", [user]));
    }

    [Fact]
    public void ComputersTagsAndItemsMoveToAnEmptyPeerAndNothingIsDeleted()
    {
        using var a = StoreWith("PC-1", "PC-2");
        using var b = StoreWith("PC-3");
        a.RecordInventory("g-pc-1", new JsonObject { ["model"] = "Latitude", ["apps"] = new JsonArray(new JsonObject { ["name"] = "7-Zip", ["version"] = "24.09" }) });
        a.Tag(["g-pc-1"], ["lab"]);
        var da = new SyncData(a);
        var db = new SyncData(b);
        var (pull, push) = SyncData.Plan(db.Manifest("computers"), da.Manifest("computers"));
        Assert.Equal(["g-pc-1", "g-pc-2"], pull.Order());
        Assert.Equal(["g-pc-3"], push);
        Assert.Equal(2, db.Apply("computers", [.. da.Export("computers", pull)]));
        Assert.Equal(3, (long)b.Scalar("SELECT COUNT(*) FROM computers")!);   // nothing deleted
        Assert.Equal("lab", b.Scalar("SELECT tag FROM tags WHERE guid = 'g-pc-1'"));
        Assert.True((long)b.Scalar("SELECT COUNT(*) FROM computer_items WHERE guid = 'g-pc-1'")! > 0);
        Assert.Equal(da.Manifest("computers")["g-pc-1"], db.Manifest("computers")["g-pc-1"]);
        Assert.Equal(0, db.Apply("computers", [.. da.Export("computers", pull)]));        // idempotent
        // a tag added on b only: same timestamps, different tag hash -> union both ways
        b.Tag(["g-pc-1"], ["b-only"]);
        var (p2, s2) = SyncData.Plan(da.Manifest("computers"), db.Manifest("computers"));
        Assert.Contains("g-pc-1", p2);
        Assert.Contains("g-pc-1", s2);
        Assert.Equal(1, da.Apply("computers", [.. db.Export("computers", ["g-pc-1"])]));
        Assert.Equal(2, (long)a.Scalar("SELECT COUNT(*) FROM tags WHERE guid = 'g-pc-1'")!);
    }

    [Fact]
    public void APeerWithoutInventoryNeverWipesOurs()
    {
        // b knows the computer (its AD sync is newer, its collection failed); a has an older but real inventory
        using var a = StoreWith("PC-1");
        using var b = StoreWith("PC-1");
        a.RecordInventory("g-pc-1", new JsonObject { ["model"] = "Latitude", ["apps"] = new JsonArray(new JsonObject { ["name"] = "7-Zip", ["version"] = "24.09" }) });
        a.AddLogons("g-pc-1", [new JsonObject { ["time"] = "2026-11-01T08:00:00+00:00", ["user"] = "anna", ["domain"] = "CORP", ["type"] = 2 }]);
        b.AddLogons("g-pc-1", [new JsonObject { ["time"] = "2026-11-02T08:00:00+00:00", ["user"] = "bela", ["domain"] = "CORP", ["type"] = 2 }]);
        var later = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(2));
        b.Execute("UPDATE computers SET ad_synced_at = ?, last_scan_attempt = ?, collect_error = 'RPC unavailable', scan_status = 'failed' WHERE guid = 'g-pc-1'", later, later);
        var da = new SyncData(a);
        var db = new SyncData(b);

        var (pull, push) = SyncData.Plan(da.Manifest("computers"), db.Manifest("computers"));
        Assert.Contains("g-pc-1", pull);                   // b's record is newer as a whole...
        Assert.Contains("g-pc-1", push);                   // ...but a's inventory is newer: it goes to b as well
        da.Apply("computers", [.. db.Export("computers", ["g-pc-1"])]);
        var row = a.Query("SELECT * FROM computers WHERE guid = 'g-pc-1'")[0];
        Assert.Contains("Latitude", (string)row["inventory"]!);            // kept
        Assert.NotNull(row["collected_at"]);
        Assert.Equal("RPC unavailable", row["collect_error"]);              // the newer failed attempt is shown
        Assert.True((long)a.Scalar("SELECT COUNT(*) FROM computer_items WHERE guid = 'g-pc-1' AND kind = 'apps'")! > 0);
        Assert.Equal(["anna", "bela"], a.Items("g-pc-1")["logons"].Select(l => (string)l!["user"]!).Order());   // merged

        db.Apply("computers", [.. da.Export("computers", ["g-pc-1"])]);   // b gets the inventory it never collected
        Assert.Contains("Latitude", (string)b.Scalar("SELECT inventory FROM computers WHERE guid = 'g-pc-1'")!);
        Assert.True((long)b.Scalar("SELECT COUNT(*) FROM computer_items WHERE guid = 'g-pc-1' AND kind = 'apps'")! > 0);
        var (p2, s2) = SyncData.Plan(da.Manifest("computers"), db.Manifest("computers"));
        Assert.Equal(da.Manifest("computers")["g-pc-1"].Split('|')[2], db.Manifest("computers")["g-pc-1"].Split('|')[2]);
        Assert.DoesNotContain("g-pc-1", s2);                // nothing left to send back
    }

    [Fact]
    public void BadlyTypedRecordsAreSkipped()
    {
        using var s = StoreWith("PC-1");
        var data = new SyncData(s);
        JsonNode?[] recs =
        [
            null,
            new JsonObject { ["row"] = "x" },
            new JsonObject { ["row"] = new JsonObject { ["guid"] = "g-new", ["name"] = new JsonObject() } },
            new JsonObject { ["row"] = new JsonObject { ["guid"] = "g-new", ["name"] = "NEW", ["os"] = new JsonArray() } },
            new JsonObject { ["row"] = new JsonObject { ["guid"] = "g-new", ["name"] = "NEW" }, ["items"] = new JsonArray(new JsonArray("apps", "x", "{}")) },
            new JsonObject { ["row"] = new JsonObject { ["guid"] = "", ["name"] = "NEW" } },
        ];
        Assert.Equal(0, data.Apply("computers", recs));
        Assert.Equal(1, (long)s.Scalar("SELECT COUNT(*) FROM computers")!);
        // unknown columns are dropped, not put into SQL
        var ok = new JsonObject { ["row"] = new JsonObject { ["guid"] = "g-new", ["name"] = "NEW", ["evil) VALUES (1); DROP TABLE tags; --"] = "x" } };
        Assert.Equal(1, data.Apply("computers", [ok]));
        Assert.Equal(0, (long)s.Scalar("SELECT COUNT(*) FROM tags")!);
        Assert.Throws<ArgumentException>(() => data.Apply("settings", []));
        Assert.Throws<ArgumentException>(() => data.Apply("computers", [.. Enumerable.Repeat<JsonNode?>(null, SyncData.MaxRecords + 1)]));
    }

    [Fact]
    public void FleetsUsersAndPrintersMergeByTimestamp()
    {
        using var a = StoreWith("PC-1");
        using var b = StoreWith("PC-1");
        var da = new SyncData(a);
        var db = new SyncData(b);
        var fid = a.CreateFleet("Lab", "static", "test");
        a.SetStaticMembers(fid, ["g-pc-1"]);
        a.SaveAdUsers(new Dictionary<string, JsonObject> { ["bob"] = new() { ["displayName"] = "Bob" } });
        a.AddPrinter(new Dictionary<string, object?> { ["ip"] = "10.0.0.5", ["model"] = "LaserJet", ["community"] = "public", ["version"] = "2c" });
        a.SavePrinterSample("10.0.0.5", "2026-11-20", 1000, [50, null]);
        foreach (var cat in new[] { "fleets", "users", "printers" })
        {
            var (pull, _) = SyncData.Plan(db.Manifest(cat), da.Manifest(cat));
            Assert.NotEmpty(pull);
            Assert.True(db.Apply(cat, [.. da.Export(cat, pull)]) > 0, cat);
            Assert.Equal(da.Manifest(cat), db.Manifest(cat));
            Assert.Equal(0, db.Apply(cat, [.. da.Export(cat, pull)]));         // nothing newer the second time
        }
        Assert.Equal("g-pc-1", b.Scalar("SELECT guid FROM fleet_members"));
        Assert.Equal("LaserJet", b.Scalar("SELECT model FROM printer WHERE ip = '10.0.0.5'"));
        Assert.Equal(1000L, b.Scalar("SELECT pages FROM printer_history"));

        // a future timestamp never wins (every category)
        var user = da.Export("users", ["bob"])[0];
        user["synced_at"] = "2099-01-01T00:00:00+00:00";
        user["data"] = "{\"displayName\":\"Mallory\"}";
        Assert.Equal(0, db.Apply("users", [user]));
        var fleet = da.Export("fleets", ["Lab"])[0];
        fleet["updated"] = "2099-01-01T00:00:00+00:00";
        Assert.Equal(0, db.Apply("fleets", [fleet]));
        user["synced_at"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(5));
        user["data"] = "not json";
        Assert.Equal(0, db.Apply("users", [user]));

        // invalid printer values are refused
        var pr = da.Export("printers", ["p:10.0.0.5"])[0];
        ((JsonObject)pr["printer"]!)["version"] = "3";
        ((JsonObject)pr["printer"]!)["updated"] = Db.FormatUtc(DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.Equal(0, db.Apply("printers", [pr]));
        ((JsonObject)pr["printer"]!)["version"] = "2c";
        ((JsonObject)pr["printer"]!)["ip"] = "not a host!";
        Assert.Equal(0, db.Apply("printers", [pr]));
    }
}
