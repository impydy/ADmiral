using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>An <see cref="IFileSecurity"/> that reports a fixed owner (the forged-file tests of test_security.py).</summary>
internal sealed class FakeOwner(string sid, string name, bool supported = true) : IFileSecurity
{
    public bool Supported => supported;
    public IReadOnlyList<string> BroadWriters(string path) => [];
    public bool HardenDir(string path, IEnumerable<string>? extraSids = null) => true;
    public (string Sid, string Name) Owner(string path) => (sid, name);
    public string CurrentUserSid() => "";
}

internal static class InboxFixture
{
    public static Store NewStore()
    {
        var s = new Store(":memory:");
        var recs = new[] { ("g-pc1", "PC1"), ("g-pc2", "PC2"), ("g-lt1", "LT-001") }.Select(x => (IReadOnlyDictionary<string, object?>)new Dictionary<string, object?>
        {
            ["guid"] = x.Item1, ["name"] = x.Item2, ["dns_hostname"] = x.Item2.ToLowerInvariant() + ".contoso.local",
            ["dn"] = $"CN={x.Item2},OU=Computers,DC=contoso,DC=local", ["ou"] = "contoso.local/Computers", ["os"] = "Windows 11 Pro",
            ["enabled"] = true, ["last_logon"] = Db.UtcNow(), ["member_of"] = new List<string>(),
        });
        s.UpsertFromAd(recs);
        return s;
    }
}

/// <summary>test_logins.py (+ the forged-file case of test_security.py).</summary>
public sealed class LoginsTests : IDisposable
{
    private readonly CoreTemp _tmp = new();

    public void Dispose() => _tmp.Dispose();

    private static byte[] Entry(string computer, string user = "anna", string when = "2026-01-02T08:00:00.0000000Z", int typ = 2, string domain = "CONTOSO") =>
        Encoding.UTF8.GetBytes(new JsonObject
        {
            ["computer"] = computer, ["time"] = when, ["user"] = user, ["domain"] = domain, ["type"] = typ, ["ip"] = "",
        }.ToJsonString());

    [Fact]
    public void ScriptIsAsciiAndCarriesThePath()
    {
        var text = Logins.RenderScript(@"\\srv\logins$");
        Assert.All(text, c => Assert.True(c < 128));                 // Windows PowerShell 5.1 reads BOM-less files as ANSI
        Assert.Contains(@"[string]$OutputPath = '\\srv\logins$'", text);
        Assert.Contains("AtLogOn", text);
        Assert.Contains("[switch]$Log", text);
        Assert.Contains("it''s", Logins.RenderScript("it's"));       // a quote in the path cannot break out of the string
        Assert.Contains("it\u2019\u2019s", Logins.RenderScript("it\u2019s"));
        Assert.DoesNotContain("\n", text.Replace("\r\n", ""));       // CRLF throughout
        Assert.EndsWith("}\r\n", text);
    }

    [PwshFact]
    public void ScriptParsesInPowerShell() => PowerShellTests.AssertParses(Logins.RenderScript(@"\\srv\logins$"), _tmp);

    [Fact]
    public void ParseEntryRejectsGarbage()
    {
        foreach (var bad in new[]
                 {
                     ""u8.ToArray(), "nope"u8.ToArray(), "[]"u8.ToArray(), Entry("bad name!"), Entry("PC1", user: "DWM-1", domain: "Window Manager"),
                     Entry("PC1", typ: 3), Entry("PC1", user: "SYSTEM", domain: "NT AUTHORITY"), Encoding.ASCII.GetBytes(new string('x', 70000)),
                     [0xFF, 0xFE, 0x00], Encoding.UTF8.GetBytes(new string('[', 50) + new string(']', 50)),
                 })
            Assert.Throws<FormatException>(() => Logins.ParseEntry(bad));
        var (computer, ev) = Logins.ParseEntry(Entry("PC1"));
        Assert.Equal("PC1", computer);
        Assert.Equal("anna", (string?)ev["user"]);
        Assert.Equal(2, (int)ev["type"]!);
        // a UTF-8 BOM is fine
        var (c2, _) = Logins.ParseEntry([0xEF, 0xBB, 0xBF, .. Entry("PC2")]);
        Assert.Equal("PC2", c2);
    }

    private static Settings Cfg(string folder, bool enabled = true) => new() { Logins = { Enabled = enabled, Path = folder } };

    [Fact]
    public void ImportFolder()
    {
        using var store = InboxFixture.NewStore();
        var folder = _tmp.File("logins");
        Directory.CreateDirectory(folder);
        Assert.False(Logins.ImportFolder(store, Cfg(folder, enabled: false)).Configured);   // switched off
        var before = store.Items("g-pc1")["logons"].Count;
        File.WriteAllBytes(Path.Combine(folder, "1.log"), Entry("PC1", when: "2030-01-02T08:00:00.0000000Z"));
        File.WriteAllBytes(Path.Combine(folder, "2.log"), Entry("pc1", user: "bela", when: "2030-01-03T08:00:00.0000000Z"));   // case-insensitive
        File.WriteAllBytes(Path.Combine(folder, "3.log"), Entry("PC2", user: "cili", when: "2030-01-04T08:00:00.0000000Z"));
        File.WriteAllBytes(Path.Combine(folder, "4.log"), Entry("GHOST-9"));                // not in the list: stays
        File.WriteAllBytes(Path.Combine(folder, "5.log"), "{broken"u8.ToArray());           // invalid: renamed, not read again
        File.WriteAllBytes(Path.Combine(folder, "6.tmp"), "half written"u8.ToArray());      // ignored
        var r = Logins.ImportFolder(store, Cfg(folder));
        Assert.Equal((5, 3, 1, 1), (r.Found, r.Imported, r.Unknown, r.Failed));
        Assert.Equal(["4.log", "5.bad", "6.tmp"], Directory.GetFiles(folder).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        var got = store.Items("g-pc1")["logons"];
        Assert.Equal(before + 2, got.Count);
        Assert.Equal("bela", (string?)got[0]["user"]);                // newest first
        Assert.Equal("anna", (string?)got[1]["user"]);
        Assert.Equal("cili", (string?)store.Items("g-pc2")["logons"][0]["user"]);
        var again = Logins.ImportFolder(store, Cfg(folder));         // nothing new: no duplicates
        Assert.Equal(0, again.Imported);
        Assert.Equal(before + 2, store.Items("g-pc1")["logons"].Count);
        Assert.Contains(store.Activity(), a => (string?)a["action"] == "logins");
    }

    [Fact]
    public void ForgedLoginFileIsNotImported()
    {
        using var store = InboxFixture.NewStore();
        File.WriteAllBytes(_tmp.File("x.log"), Entry("PC1", user: "jdoe", domain: "CORP", when: "2026-01-01T08:00:00Z"));
        var r = Logins.ImportFolder(store, Cfg(_tmp.Path), new FakeOwner("S-1-5-21-9-9-9-1200", "CORP\\OTHERPC$"));
        Assert.Equal(0, r.Imported);
        Assert.Equal(1, r.Failed);
        Assert.True(File.Exists(_tmp.File("x.bad")));
        Assert.Empty(store.Items("g-pc1")["logons"]);
    }

    [Fact]
    public void FileOfTheRightComputerAccountIsImported()
    {
        using var store = InboxFixture.NewStore();
        File.WriteAllBytes(_tmp.File("x.log"), Entry("PC1"));
        var r = Logins.ImportFolder(store, Cfg(_tmp.Path), new FakeOwner("S-1-5-21-1-2-3-1105", "CORP\\PC1$"));
        Assert.Equal(1, r.Imported);
        r = Logins.ImportFolder(store, Cfg(_tmp.Path), new FakeOwner("S-1-5-21-1-2-3-1107", "CORP\\jdoe"));   // nothing left; users never allowed
        Assert.Equal(0, r.Found);
        File.WriteAllBytes(_tmp.File("y.log"), Entry("PC1", user: "x"));
        r = Logins.ImportFolder(store, Cfg(_tmp.Path), new FakeOwner("S-1-5-21-1-2-3-1107", "CORP\\jdoe"));
        Assert.Equal(1, r.Failed);
        r = Logins.ImportFolder(store, Cfg(_tmp.Path), new FakeOwner("", ""));                               // unreadable owner on Windows: refused
        Assert.Equal(0, r.Imported);
    }

    [Fact]
    public void UnreadableFolderIsReported()
    {
        using var store = InboxFixture.NewStore();
        var r = Logins.ImportFolder(store, Cfg(_tmp.File("missing")));
        Assert.True(r.Configured);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public void OversizedFileIsRefusedWithoutReadingItAll()
    {
        using var store = InboxFixture.NewStore();
        using (var f = File.Create(_tmp.File("big.log"))) f.SetLength(Logins.MaxBytes + 1);
        var r = Logins.ImportFolder(store, Cfg(_tmp.Path));
        Assert.Equal(1, r.Failed);
        Assert.True(File.Exists(_tmp.File("big.bad")));
    }

    [Fact]
    public void LinksAndOddNamesAreNotFollowed()
    {
        if (OperatingSystem.IsWindows()) return;                    // symlinks need privileges there
        using var store = InboxFixture.NewStore();
        var outside = _tmp.File("outside.json");
        File.WriteAllBytes(outside, Entry("PC1"));
        var folder = _tmp.File("in");
        Directory.CreateDirectory(folder);
        File.CreateSymbolicLink(Path.Combine(folder, "link.log"), outside);
        File.WriteAllBytes(Path.Combine(folder, "we ird.log"), Entry("PC1"));
        var r = Logins.ImportFolder(store, Cfg(folder));
        Assert.Equal(0, r.Found);
        Assert.True(File.Exists(outside));                            // never deleted through the link
    }
}
