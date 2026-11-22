using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>test_offline.py: ADmiral-Collect.ps1 stays in sync with the collector; the inbox import.</summary>
public sealed class OfflineTests : IDisposable
{
    private readonly CoreTemp _tmp = new();

    public void Dispose() => _tmp.Dispose();

    private static byte[] FileFor(string host, JsonObject? data = null, string? fqdn = null, string at = "2026-01-02T08:05:00Z")
    {
        data ??= [];
        if (!data.ContainsKey("os_caption")) data["os_caption"] = "Microsoft Windows 11 Pro";
        if (!data.ContainsKey("logons"))
            data["logons"] = new JsonArray(
                new JsonObject { ["time"] = "2026-01-02T08:00:00+00:00", ["user"] = "anna", ["domain"] = "CONTOSO", ["type"] = 2, ["ip"] = "" },
                new JsonObject { ["time"] = "2026-01-02T08:00:01+00:00", ["user"] = "DWM-1", ["domain"] = "Window Manager", ["type"] = 2, ["ip"] = "" });
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(data.ToJsonString()));
        return Encoding.UTF8.GetBytes(new JsonObject
        {
            ["format"] = 1, ["host"] = host, ["fqdn"] = fqdn ?? $"{host.ToLowerInvariant()}.contoso.local",
            ["collected_at"] = at, ["data"] = b64,
        }.ToJsonString());
    }

    [Fact]
    public void CommittedScriptIsInSyncWithTheCollector()
    {
        // Regenerate with Offline.WriteScript("scripts/ADmiral-Collect.ps1")
        var shipped = File.ReadAllText(Path.Combine(RepoRoot.Path, "scripts", Offline.ScriptName), Encoding.UTF8).Replace("\r\n", "\n");
        Assert.Equal(shipped, Offline.RenderScript());
        // same queries as the exe (a Windows checkout may give the C# sources CRLF line ends; the rendered script is LF)
        Assert.Contains(Collector.CombinedScript().Trim().Replace("\r\n", "\n"), Offline.RenderScript());
    }

    [Fact]
    public void ScriptIsAsciiAndHasTheParameter()
    {
        var text = Offline.RenderScript();
        Assert.All(text, c => Assert.True(c < 128));
        Assert.Contains("[string]$OutputPath", text);
        Assert.Contains(".admiral.json", text);
        Assert.DoesNotContain("@@", text);
    }

    [Fact]
    public void WriteScriptRoundTrips()
    {
        var p = _tmp.File("x.ps1");
        Offline.WriteScript(p);
        var bytes = File.ReadAllBytes(p);
        Assert.NotEqual(0xEF, bytes[0]);                                // plain ASCII, no BOM
        Assert.Equal(Offline.RenderScript(), Encoding.ASCII.GetString(bytes).Replace("\r\n", "\n"));
        Assert.Contains("\r\n", Encoding.ASCII.GetString(bytes));
    }

    [PwshFact]
    public void ScriptParsesInPowerShell() => PowerShellTests.AssertParses(Offline.RenderScript(), _tmp);

    [Fact]
    public void ParseFileRejectsGarbage()
    {
        foreach (var bad in new[]
                 {
                     ""u8.ToArray(), "not json"u8.ToArray(), """{"host":"x"}"""u8.ToArray(), """{"host":"x","data":"!!!"}"""u8.ToArray(),
                     Encoding.UTF8.GetBytes(new JsonObject { ["data"] = Convert.ToBase64String("{}"u8.ToArray()) }.ToJsonString()),
                     FileFor("bad host!"), FileFor("PC1", new JsonObject { ["apps"] = "not a list" }),
                     Encoding.UTF8.GetBytes(new JsonObject { ["host"] = "x", ["data"] = Convert.ToBase64String("[1]"u8.ToArray()) }.ToJsonString()),
                 })
            Assert.Throws<FormatException>(() => Offline.ParseFile(bad));
        var (env, rec) = Offline.ParseFile(FileFor("LT-001"));
        Assert.Equal("LT-001", (string?)env["host"]);
        Assert.Equal("file", (string?)rec["collected_via"]);
        Assert.Equal("2026-01-02T08:05:00Z", (string?)rec["file_collected_at"]);
        Assert.Equal(["anna"], ((JsonArray)rec["logons"]!).Select(x => (string?)x!["user"]));   // system accounts dropped
        Assert.Equal("11", (string?)rec["os_short"]);
    }

    [Fact]
    public void ImportInbox()
    {
        using var store = InboxFixture.NewStore();
        var inbox = _tmp.File("inbox");
        Directory.CreateDirectory(inbox);
        var settings = new Settings { FileCollect = { Inbox = inbox } };
        File.WriteAllBytes(Path.Combine(inbox, "PC1.admiral.json"), FileFor("PC1"));
        File.WriteAllBytes(Path.Combine(inbox, "pc2.admiral.json"), FileFor("pc2"));                 // name case does not matter
        File.WriteAllBytes(Path.Combine(inbox, "GHOST-9.admiral.json"), FileFor("GHOST-9"));         // not in the list
        File.WriteAllBytes(Path.Combine(inbox, "BROKEN.admiral.json"), "{nope"u8.ToArray());
        File.WriteAllBytes(Path.Combine(inbox, "PARTIAL.admiral.json.tmp"), "half written"u8.ToArray());   // ignored
        File.WriteAllText(Path.Combine(inbox, "readme.txt"), "x");
        var r = Offline.ImportInbox(store, settings);
        Assert.Equal(4, r.Found);
        Assert.Equal(2, r.Imported);
        Assert.Equal(["GHOST-9.admiral.json"], r.Unknown);
        Assert.Single(r.Failed);
        // a broken file is never one still being written (the script renames a finished temp file): deleted, so it
        // cannot block the computer's next delivery; a fresh temp file is left alone
        Assert.Equal(["GHOST-9.admiral.json", "PARTIAL.admiral.json.tmp", "readme.txt"],
                     Directory.GetFiles(inbox).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        var got = store.Computer("g-pc1")!;
        Assert.Equal("file", (string?)((JsonObject)got["inventory"]!)["collected_via"]);
        Assert.Equal("ok", got["scan_status"]);
        Assert.Equal(["anna"], store.Items("g-pc1")["logons"].Select(x => (string?)x["user"]));
        Assert.Contains(store.Activity(), a => (string?)a["action"] == "offline");
    }

    [Fact]
    public void ForgedInventoryOfAnotherComputerIsRefused()
    {
        using var store = InboxFixture.NewStore();
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1106", "CORP\\PC2$"));
        Assert.Equal(0, r.Imported);
        Assert.Single(r.Failed);
        Assert.Contains("not trusted", r.Failed[0]);
        Assert.False(File.Exists(_tmp.File("PC1.admiral.json")));        // removed: PC1 could never overwrite it
        // the right computer account may deliver it
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1105", "CORP\\PC1$"));
        Assert.Equal(1, r.Imported);
    }

    [Fact]
    public void UserOwnedFilesAreRefusedUnlessOfflineAllowUsers()
    {
        using var store = InboxFixture.NewStore();
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        Assert.False(settings.FileCollect.OfflineAllowUsers);              // default: computer accounts only
        var jdoe = new FakeOwner("S-1-5-21-1-2-3-1107", "CORP\\jdoe");
        var r = Offline.ImportInbox(store, settings, jdoe);
        Assert.Equal(0, r.Imported);
        Assert.Contains("user account", r.Failed.Single());
        Assert.False(File.Exists(_tmp.File("PC1.admiral.json")));
        settings.FileCollect.OfflineAllowUsers = true;                      // opt-in: logon scripts / by hand
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        r = Offline.ImportInbox(store, settings, jdoe);
        Assert.Equal(1, r.Imported);
        // another computer's account is a forgery even with the opt-in
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1106", "CORP\\PC2$"));
        Assert.Equal(0, r.Imported);
        Assert.Contains(Config.Editable["filecollect"], k => k == "offline_allow_users");
        Assert.Contains("offline_allow_users = false", Config.ExampleConfig);
    }

    [Fact]
    public void HugeSectionsAndFieldsAreCapped()
    {
        var apps = new JsonArray();
        for (var i = 0; i < Collector.MaxItemsPerSection + 500; i++) apps.Add(new JsonObject { ["name"] = $"app{i}" });
        var data = new JsonObject
        {
            ["apps"] = apps, ["os_caption"] = new string('W', 100_000),
            ["services"] = new JsonArray(new JsonObject { ["name"] = new string('s', 100_000), ["nested"] = new JsonObject { ["x"] = new string('n', 50_000) } }),
        };
        var (_, rec) = Offline.ParseFile(FileFor("PC1", data));
        Assert.Equal(Collector.MaxItemsPerSection, ((JsonArray)rec["apps"]!).Count);
        Assert.Equal(Collector.MaxFieldChars, ((string?)rec["os_caption"])!.Length);
        var svc = (JsonObject)((JsonArray)rec["services"]!)[0]!;
        Assert.Equal(Collector.MaxFieldChars, ((string?)svc["name"])!.Length);
        Assert.Equal(Collector.MaxFieldChars, ((string?)svc["nested"]!["x"])!.Length);
        // the store applies the same cap to whatever reaches it (sync, other paths)
        using var store = InboxFixture.NewStore();
        var big = new JsonObject { ["apps"] = apps.DeepClone() };
        store.RecordInventory("g-pc1", big);
        Assert.Equal(Collector.MaxItemsPerSection, store.Items("g-pc1")["apps"].Count);
        Assert.True(Offline.MaxBytes <= 8 * 1024 * 1024 && Collector.MaxOutputBytes <= 8 * 1024 * 1024);
    }

    [Fact]
    public void ImportWithoutOrWithBadFolder()
    {
        using var store = InboxFixture.NewStore();
        var r = Offline.ImportInbox(store, new Settings());
        Assert.False(r.Configured);
        Assert.Equal((0, 0), (r.Found, r.Imported));
        Assert.Empty(r.Unknown);
        Assert.Empty(r.Failed);
        Assert.Null(r.Error);
        r = Offline.ImportInbox(store, new Settings { FileCollect = { Inbox = _tmp.File("missing") } });
        Assert.NotNull(r.Error);                                        // unreachable share: reported, no crash
    }

    /// <summary>A security fake with an owner and a folder ACL.</summary>
    private sealed class FakeInbox(string ownerSid, string ownerName, PathSecurity? folder) : IFileSecurity
    {
        public bool Supported => true;
        public IReadOnlyList<string> BroadWriters(string path) => [];
        public bool HardenDir(string path, IEnumerable<string>? extraSids = null) => true;
        public (string Sid, string Name) Owner(string path) => (ownerSid, ownerName);
        public string CurrentUserSid() => "S-1-5-21-1-2-3-500";
        public PathSecurity? ReadSecurity(string path) => folder;
    }

    private const string DomainComputers = "S-1-5-21-1-2-3-515";
    private static readonly FakeOwner Pc1 = new("S-1-5-21-1-2-3-1105", "CORP\\PC1$");

    [Fact]
    public void FqdnOfAnotherComputerIsRefused()
    {
        // GHOST-9 (a real account, not in the list) claims the fqdn of PC1: must not land on PC1
        using var store = InboxFixture.NewStore();
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        File.WriteAllBytes(_tmp.File("GHOST-9.admiral.json"), FileFor("GHOST-9", fqdn: "pc1.contoso.local"));
        var r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1199", "CORP\\GHOST-9$"));
        Assert.Equal(0, r.Imported);
        Assert.Contains("does not belong", r.Failed.Single());
        Assert.Null(store.Computer("g-pc1")!["inventory"]);
        // without the fqdn, the name alone decides: unknown computer, nothing imported
        File.WriteAllBytes(_tmp.File("GHOST-9.admiral.json"), FileFor("GHOST-9", fqdn: ""));
        r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1199", "CORP\\GHOST-9$"));
        Assert.Equal(["GHOST-9.admiral.json"], r.Unknown);
    }

    [Fact]
    public void ComputerNamesWinOverOtherComputersDnsLabels()
    {
        using var store = new Store(":memory:");
        // "AAA" sorts first and carries the DNS label "pc1": the computer named PC1 must still win "pc1"
        store.UpsertFromAd(new[] { ("g-odd", "AAA", "pc1.other.local"), ("g-pc1", "PC1", "pc1x.contoso.local") }
            .Select(x => (IReadOnlyDictionary<string, object?>)new Dictionary<string, object?>
            {
                ["guid"] = x.Item1, ["name"] = x.Item2, ["dns_hostname"] = x.Item3, ["dn"] = $"CN={x.Item2},DC=contoso,DC=local",
                ["enabled"] = true, ["last_logon"] = Db.UtcNow(), ["member_of"] = new List<string>(),
            }));
        Assert.Equal("g-pc1", Inbox.ComputerIndex(store, 0)["pc1"]);
    }

    [Fact]
    public void OlderOrFutureFilesAreRefused()
    {
        using var store = InboxFixture.NewStore();
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var path = _tmp.File("PC1.admiral.json");
        File.WriteAllBytes(path, FileFor("PC1", at: "2026-01-02T08:05:00Z"));
        Assert.Equal(1, Offline.ImportInbox(store, settings, Pc1).Imported);
        File.WriteAllBytes(path, FileFor("PC1", at: "2026-01-01T08:05:00Z"));              // a replayed old copy
        var r = Offline.ImportInbox(store, settings, Pc1);
        Assert.Equal(0, r.Imported);
        Assert.Contains("not newer", r.Failed.Single());
        Assert.False(File.Exists(path));
        File.WriteAllBytes(path, FileFor("PC1", at: DateTimeOffset.UtcNow.AddDays(2).ToString("o")));
        r = Offline.ImportInbox(store, settings, Pc1);
        Assert.Contains("future", r.Failed.Single());
        File.WriteAllBytes(path, FileFor("PC1", at: "nonsense"));
        Assert.Contains("collected_at", Offline.ImportInbox(store, settings, Pc1).Failed.Single());
        File.WriteAllBytes(path, FileFor("PC1", at: "2026-01-03T08:05:00Z"));
        Assert.Equal(1, Offline.ImportInbox(store, settings, Pc1).Imported);
    }

    [Fact]
    public void UnsafeFolderAclStopsTheImport()
    {
        using var store = InboxFixture.NewStore();
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        // Domain Computers: Modify on files (object-inherit) - any computer could rewrite PC1's file
        var modify = new PathSecurity(WinSec.AdminsSid, [new AceInfo(0, 0x1 | 0x2, 0x1301BF, DomainComputers)]);
        var r = Offline.ImportInbox(store, settings, new FakeInbox("S-1-5-21-1-2-3-1105", "CORP\\PC1$", modify));
        Assert.Equal(0, r.Imported);
        Assert.Contains("Domain Computers", r.Error);
        Assert.True(File.Exists(_tmp.File("PC1.admiral.json")));
        // the recommended setup: create files on the folder only, CREATOR OWNER modify on files
        var good = new PathSecurity(WinSec.AdminsSid,
        [
            new AceInfo(0, 0, 0x100002 | 0x20 | 0x80, DomainComputers),
            new AceInfo(0, 0x1 | 0x2 | 0x8, 0x1301BF, WinSec.CreatorOwnerSid),
            new AceInfo(0, 0x3, 0x1F01FF, WinSec.SystemSid),
        ]);
        r = Offline.ImportInbox(store, settings, new FakeInbox("S-1-5-21-1-2-3-1105", "CORP\\PC1$", good));
        Assert.Null(r.Error);
        Assert.Equal(1, r.Imported);
    }

    [Fact]
    public void InboxAclProblems()
    {
        static List<string> P(params AceInfo[] aces) => WinSec.InboxAclProblems(new PathSecurity(WinSec.AdminsSid, aces), "");
        Assert.Empty(P(new AceInfo(0, 0, 0x2, DomainComputers)));                        // create files, folder only
        Assert.Single(P(new AceInfo(0, 0x1, 0x2, DomainComputers)));                     // write data on files
        Assert.Single(P(new AceInfo(0, 0, 0x40, DomainComputers)));                      // delete child
        Assert.Single(P(new AceInfo(0, 0x3, 0x1F01FF, "S-1-1-0")));                      // Everyone full control
        Assert.Empty(P(new AceInfo(0, 0x3, 0x1F01FF, "S-1-5-21-1-2-3-512")));            // Domain Admins
        Assert.Empty(P(new AceInfo(1, 0x3, 0x1F01FF, DomainComputers)));                 // deny entries do not grant
        Assert.Empty(P(new AceInfo(0, 0x1, 0x120089, DomainComputers)));                 // read on files is fine
        Assert.Single(WinSec.InboxAclProblems(new PathSecurity("", null), ""));          // NULL DACL
    }

    [Fact]
    public void FileNameDecidesWhoseFileItIs()
    {
        // GHOST-9 writes a valid inventory into PC1's file name: refused against PC1's account and removed
        using var store = InboxFixture.NewStore();
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var path = _tmp.File("PC1.admiral.json");
        File.WriteAllBytes(path, FileFor("GHOST-9"));
        var r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1199", "CORP\\GHOST-9$"));
        Assert.Contains("not trusted", r.Failed.Single());
        Assert.False(File.Exists(path));
        // PC1's own file that names another host inside is refused too
        File.WriteAllBytes(path, FileFor("PC2"));
        r = Offline.ImportInbox(store, settings, Pc1);
        Assert.Contains("says it comes from", r.Failed.Single());
        Assert.Null(store.Computer("g-pc2")!["inventory"]);
        // garbage planted under PC1's name by another computer: removed (it would block PC1 for good)
        File.WriteAllBytes(path, "{nope"u8.ToArray());
        Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-1-2-3-1106", "CORP\\PC2$"));
        Assert.False(File.Exists(path));
        // an owner that cannot be read proves nothing either way: the file stays
        File.WriteAllBytes(path, FileFor("PC1"));
        r = Offline.ImportInbox(store, settings, new FakeOwner("", ""));
        Assert.Contains("cannot be read", r.Failed.Single());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void OwnerMustBeTheComputersSidOnceAdReportedIt()
    {
        // two domains of one forest, both with a PC1: the name check alone would let EU\PC1$ pass for CORP's PC1
        using var store = InboxFixture.NewStore();
        store.Execute("UPDATE computers SET sid = 'S-1-5-21-1-2-3-1105' WHERE guid = 'g-pc1'");
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var path = _tmp.File("PC1.admiral.json");
        File.WriteAllBytes(path, FileFor("PC1"));
        var r = Offline.ImportInbox(store, settings, new FakeOwner("S-1-5-21-9-9-9-1105", "EU\\PC1$"));
        Assert.Equal(0, r.Imported);
        Assert.Contains("not by the account of PC1", r.Failed.Single());
        File.WriteAllBytes(path, FileFor("PC1"));
        Assert.Equal(1, Offline.ImportInbox(store, settings, Pc1).Imported);
        // the pure decision
        Assert.Null(WinSec.CheckOwner("S-1-5-21-1-2-3-1105", "CORP\\PC1$", "PC1", false, "S-1-5-21-1-2-3-1105"));
        Assert.NotNull(WinSec.CheckOwner("S-1-5-21-9-9-9-1105", "EU\\PC1$", "PC1", false, "S-1-5-21-1-2-3-1105"));
        Assert.NotNull(WinSec.CheckOwner("S-1-5-21-9-9-9-1107", "EU\\jdoe", "PC1", false, "S-1-5-21-1-2-3-1105"));
        Assert.Null(WinSec.CheckOwner("S-1-5-21-9-9-9-1107", "EU\\jdoe", "PC1", true, "S-1-5-21-1-2-3-1105"));
        Assert.Null(WinSec.CheckOwner("S-1-5-21-9-9-9-1105", "EU\\PC1$", "PC1", false));       // no SID known: name only
    }

    [Fact]
    public void FileOlderThanTheLastWinRMCollectionIsRefused()
    {
        using var store = InboxFixture.NewStore();
        store.RecordInventory("g-pc1", new JsonObject { ["os_caption"] = "collected over WinRM just now" });
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var path = _tmp.File("PC1.admiral.json");
        File.WriteAllBytes(path, FileFor("PC1", at: DateTimeOffset.UtcNow.AddDays(-1).ToString("o")));
        var r = Offline.ImportInbox(store, settings, Pc1);
        Assert.Contains("not newer", r.Failed.Single());
        Assert.False(File.Exists(path));
        Assert.Equal("collected over WinRM just now", (string?)((JsonObject)store.Computer("g-pc1")!["inventory"]!)["os_caption"]);
        File.WriteAllBytes(path, FileFor("PC1", at: DateTimeOffset.UtcNow.AddMinutes(5).ToString("o")));
        Assert.Equal(1, Offline.ImportInbox(store, settings, Pc1).Imported);
    }

    [Fact]
    public void StaleTemporaryFilesAreRemoved()
    {
        using var store = InboxFixture.NewStore();
        var settings = new Settings { FileCollect = { Inbox = _tmp.Path } };
        var planted = _tmp.File("PC1.admiral.json.tmp");                   // the old fixed name, planted to block PC1
        var running = _tmp.File("PC2.admiral.json.0123456789abcdef0123456789abcdef.tmp");
        var other = _tmp.File("notes.tmp");
        foreach (var p in new[] { planted, running, other }) File.WriteAllText(p, "x");
        File.SetLastWriteTimeUtc(planted, DateTime.UtcNow.AddHours(-3));
        File.SetLastWriteTimeUtc(other, DateTime.UtcNow.AddHours(-3));
        File.WriteAllBytes(_tmp.File("PC1.admiral.json"), FileFor("PC1"));
        Offline.ImportInbox(store, settings, Pc1);
        Assert.False(File.Exists(planted));
        Assert.True(File.Exists(running));                                  // fresh: maybe still being written
        Assert.True(File.Exists(other));                                    // not the script's
        Assert.Contains("[guid]::NewGuid()", Offline.RenderScript());       // the script's temp name cannot be guessed
    }

    [Fact]
    public void ResultSerializesWithTheUiFieldNames()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new OfflineImportResult { Configured = true });
        Assert.Equal("""{"configured":true,"found":0,"imported":0,"unknown":[],"failed":[]}""", json);
    }
}
