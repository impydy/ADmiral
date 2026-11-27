#pragma warning disable CA5350 // the Windows Update Catalog publishes SHA-1: the tests compute it the same way
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>Windows updates in the library: IDs, hashes in the catalog's forms, the catalog lookup, the install script,
/// the new chain steps (wait, message) and a demo update deployment.</summary>
public sealed class WinUpdateTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private readonly string _tmp = Directory.CreateTempSubdirectory("admiral-wu-").FullName;
    private AdmiralService App => _f.App;

    public void Dispose()
    {
        _f.Dispose();
        Directory.Delete(_tmp, true);
    }

    private PackageLibrary Lib() => new(Path.Combine(_tmp, "lib"));

    private static (string Sha1, string Sha256) Hashes(byte[] b) =>
        (Convert.ToHexStringLower(SHA1.HashData(b)), Convert.ToHexStringLower(SHA256.HashData(b)));

    private static PackageEntry UpWu(PackageLibrary l, string name, byte[] data, string digest = "", string build = "10.0.26100", string kb = "KB5043080", string ver = "26100.1742")
    {
        using var u = l.UploadWinUpdate(build, kb, ver, name, digest);
        u.Write(data);
        return u.Commit();
    }

    [Fact]
    public void KbBuildAndVersionAreChecked()
    {
        Assert.Equal("KB5043080", WinUpdate.ValidKb("kb5043080"));
        Assert.Equal("KB5043080", WinUpdate.ValidKb(" 5043080 "));
        foreach (var bad in new[] { null, "", "KB12", "KB5043080; rm", "KB 5043080", "Q123456" }) Assert.Null(WinUpdate.ValidKb(bad));
        Assert.Equal("10.0.26100", WinUpdate.ValidBuild("26100"));
        Assert.Equal("10.0.19045", WinUpdate.ValidBuild("10.0.19045"));
        foreach (var bad in new[] { null, "", "6.1.7601", "10.0.26100.1", "x" }) Assert.Null(WinUpdate.ValidBuild(bad));
        Assert.Equal("26100.1742", WinUpdate.ValidVersion("10.0.26100.1742", "10.0.26100"));
        Assert.Equal("26100.42", WinUpdate.ValidVersion("26100.042", "10.0.26100"));
        Assert.Null(WinUpdate.ValidVersion("22631.1742", "10.0.26100"));            // another build's version
        Assert.Null(WinUpdate.ValidVersion("26100", "10.0.26100"));
        Assert.Equal("WU-26100-KB5043080", WinUpdate.PackageId("10.0.26100", "KB5043080"));
        Assert.True(WinUpdate.IsUpdateFile("a.MSU"));
        Assert.True(WinUpdate.IsUpdateFile("a.cab"));
        Assert.False(WinUpdate.IsUpdateFile("a.msi"));
        Assert.Equal("953449672073f8fb99badb4cc6d5d7849b9c83e8", WinUpdate.NameSha1("windows11.0-kb5043080-x64_953449672073F8FB99BADB4CC6D5D7849B9C83E8.msu"));
        Assert.Null(WinUpdate.NameSha1("windows11.0-kb5043080-x64.msu"));
    }

    [Fact]
    public void DigestsInEveryPublishedForm()
    {
        var data = "update"u8.ToArray();
        var (s1, s256) = Hashes(data);
        Assert.Equal(("sha256", s256), PackageLibrary.ParseDigest(s256.ToUpperInvariant()));
        Assert.Equal(("sha1", s1), PackageLibrary.ParseDigest(s1));
        Assert.Equal(("sha1", s1), PackageLibrary.ParseDigest(Convert.ToBase64String(SHA1.HashData(data))));
        Assert.Equal(("sha256", s256), PackageLibrary.ParseDigest(Convert.ToBase64String(SHA256.HashData(data))));
        foreach (var bad in new[] { null, "", "zz", new string('g', 64), Convert.ToBase64String(new byte[16]), "lTRJZyBz+PuZuttMxtXXhJucg+=" })
            Assert.Null(PackageLibrary.ParseDigest(bad));
    }

    [Fact]
    public void UpdateUploadMakesAWindowsUpdatePackage()
    {
        var l = Lib();
        var data = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("msu", 100)));
        var (s1, _) = Hashes(data);
        var e = UpWu(l, "windows11.0-kb5043080-x64.msu", data);
        Assert.Equal("WU-26100-KB5043080", e.Id);
        Assert.Equal(("winupdate", "10.0.26100", "KB5043080", "KB5043080", "26100.1742"), (e.Kind, e.OsBuild, e.Kb, e.Name, e.Version));
        var f = Assert.Single(e.Files);
        Assert.Equal(s1, f.Sha1);
        Assert.False(f.VendorChecked);
        // the catalog's base64 SHA-1 checks it
        e = l.CheckVendorHash(e.Id, f.Path, Convert.ToBase64String(SHA1.HashData(data)), "catalog", "2024-09 Cumulative Update");
        Assert.True(e.Files[0].VendorChecked);
        Assert.Equal("catalog", e.Files[0].HashSource);
        Assert.Throws<PackageError>(() => l.CheckVendorHash(e.Id, f.Path, Convert.ToBase64String(SHA1.HashData("other"u8))));
        // a normal upload into it is refused, and so are bad build / KB / version / file types
        Assert.Throws<PackageError>(() => { using var u = l.Upload(e.Id, "x.msi", "1"); u.Write("x"u8.ToArray()); u.Commit(); });
        Assert.Throws<PackageError>(() => l.UploadWinUpdate("6.1.7601", "KB1234567", "7601.1", "a.msu"));
        Assert.Throws<PackageError>(() => l.UploadWinUpdate("26100", "nope", "26100.1", "a.msu"));
        Assert.Throws<PackageError>(() => l.UploadWinUpdate("26100", "KB1234567", "22631.1", "a.msu"));
        Assert.Throws<PackageError>(() => l.UploadWinUpdate("26100", "KB1234567", "26100.1", "a.exe"));
        Assert.Throws<PackageError>(() => l.UploadWinUpdate("26100", "KB1234567", "26100.1", "a.msu", "not-a-hash"));
        var row = Assert.Single(l.Rows());
        Assert.Equal(("winupdate", "10.0.26100", "KB5043080"), (row.Kind, row.OsBuild, row.Kb));
    }

    [Fact]
    public void CatalogFileNameAndGivenDigestMustMatchTheContent()
    {
        var l = Lib();
        var data = "real update bytes"u8.ToArray();
        var (s1, s256) = Hashes(data);
        var e = UpWu(l, $"windows11.0-kb5043080-x64_{s1}.msu", data);
        // the name proves the file is intact, not that Microsoft published it: anyone can name a file after its own SHA-1
        Assert.False(e.Files[0].VendorChecked);
        Assert.Equal("catalog-name", e.Files[0].HashSource);
        // a damaged / swapped file under a catalog name is not added
        Assert.Throws<PackageError>(() => UpWu(l, $"windows11.0-kb5043080-x64_{s1}.cab", "tampered"u8.ToArray()));
        Assert.Throws<PackageError>(() => UpWu(l, "b.msu", data, digest: Convert.ToBase64String(SHA1.HashData("x"u8))));
        Assert.Throws<PackageError>(() => UpWu(l, "b.msu", data, digest: Convert.ToBase64String(SHA256.HashData("x"u8))));
        e = UpWu(l, "c.msu", data, digest: Convert.ToBase64String(SHA256.HashData(data)));
        Assert.All(e.Files.Where(f => f.HashSource != "catalog-name"), f => Assert.True(f.VendorChecked));
        // SHA-1 is for Windows updates only: an application package needs its vendor's SHA-256
        l.Create("Acme.App", "App");
        using (var up = l.Upload("Acme.App", "setup.msi"))
        {
            up.Write(data);
            up.Commit();
        }
        var path = l.Get("Acme.App")!.Files[0].Path;
        Assert.Throws<PackageError>(() => l.CheckVendorHash("Acme.App", path, s1));
        Assert.True(l.CheckVendorHash("Acme.App", path, s256).Files[0].VendorChecked);
        Assert.DoesNotContain(Directory.EnumerateFiles(l.Folder, "*", SearchOption.AllDirectories), p => p.Contains("upload-", StringComparison.Ordinal));
        Assert.NotEmpty(s256);
    }

    // trimmed from real catalog responses (Search.aspx / DownloadDialog.aspx)
    private const string SearchHtml = """
        <tr id="fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef_R0"><td id="fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef_C1_R0">
          <a id='fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef_link' href= "javascript:void(0);" onclick='goToDetails("fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef");' class="contentTextItemSpacerNoBreakLink">
                            2024-09 Cumulative Update for Microsoft server operating system version 24H2 for x64-based Systems (KB5043080)
                        </a></td></tr>
        <a id='8cea1349-3ff8-4482-af64-9db80cb71ffb_link' href= "javascript:void(0);" onclick='goToDetails("8cea1349-3ff8-4482-af64-9db80cb71ffb");'>
           2024-09 Cumulative Update for Windows 11 Version 24H2 for arm64-based Systems (KB5043080)
        </a>
        """;

    private static string Dialog(string sha1B64, string sha256B64) => $"""
        downloadInformation[0] = new Object();
        downloadInformation[0].updateID ='fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef';
        downloadInformation[0].enTitle ='2024-09 Cumulative Update for Microsoft server operating system version 24H2 for x64-based Systems (KB5043080)';
        downloadInformation[0].files = new Array();
        downloadInformation[0].files[0] = new Object();
        downloadInformation[0].files[0].url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/d8b7f92b/public/windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu';
        downloadInformation[0].files[0].digest = '{sha1B64}';
        downloadInformation[0].files[0].sha256 = '{sha256B64}';
        downloadInformation[0].files[0].fileName = 'windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu';
        """;

    [Fact]
    public void CatalogPagesAreParsed()
    {
        var rows = WinUpdate.ParseCatalogSearch(SearchHtml);
        Assert.Equal(2, rows.Count);
        Assert.Equal("fe12f49d-f2f0-4de3-a2ed-2946a5bbd7ef", rows[0].Id);
        Assert.EndsWith("(KB5043080)", rows[0].Title, StringComparison.Ordinal);
        var u = WinUpdate.ParseCatalogDialog("x", Dialog("lTRJZyBz+PuZuttMxtXXhJucg+g=", "gZYyYQoQGvEccpB/sT/wW1+0IiwOJj7poDvMHR1fJqQ="));
        var f = Assert.Single(u.Files);
        Assert.Equal("lTRJZyBz+PuZuttMxtXXhJucg+g=", f.Sha1Base64);
        Assert.StartsWith("windows11.0-kb5043080", f.FileName, StringComparison.Ordinal);
        // the catalog's base64 SHA-1 is the hex SHA-1 in its file name
        Assert.Equal(("sha1", "953449672073f8fb99badb4cc6d5d7849b9c83e8"), PackageLibrary.ParseDigest(f.Sha1Base64));
        Assert.Empty(WinUpdate.ParseCatalogSearch("<html>nothing</html>"));
        Assert.Empty(WinUpdate.ParseCatalogDialog("x", "").Files);
    }

    [Fact]
    public void CatalogLookupFindsTheFileByItsHash()
    {
        var data = "the msu"u8.ToArray();
        var (s1, s256) = Hashes(data);
        var calls = new List<(string Url, string? Form)>();
        string Fetch(string url, IReadOnlyDictionary<string, string>? form)
        {
            calls.Add((url, form?["updateIDs"]));
            if (form is null) return SearchHtml;
            return form["updateIDs"].Contains("8cea1349", StringComparison.Ordinal)
                ? Dialog(Convert.ToBase64String(SHA1.HashData(data)), Convert.ToBase64String(SHA256.HashData(data)))
                : Dialog("AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "");
        }
        var m = WinUpdate.CatalogLookup("5043080", s1, s256, Fetch);
        Assert.True(m.Found);
        Assert.Equal(WinUpdate.CatalogBase + "/Search.aspx?q=KB5043080", calls[0].Url);
        Assert.Contains("\"updateID\":\"8cea1349-3ff8-4482-af64-9db80cb71ffb\"", calls[^1].Form);
        Assert.False(WinUpdate.CatalogLookup("KB5043080", new string('1', 40), new string('1', 64), Fetch).Found);
        // where the catalog gives a SHA-256, it decides: a matching SHA-1 alone is not enough
        Assert.False(WinUpdate.CatalogLookup("KB5043080", s1, new string('1', 64), Fetch).Found);
        Assert.ThrowsAny<ArgumentException>(() => WinUpdate.CatalogLookup("x; y", s1, s256, Fetch));
    }

    [Fact]
    public void ProgressLinesAndOutcomes()
    {
        Assert.Equal(("10:21:33", (int?)45, ""), WinUpdate.ParseProgress("\uFEFF10:21:33 PROGRESS 45%\r"));
        Assert.Equal(("10:21:34", (int?)null, "Installing KB1 with DISM"), WinUpdate.ParseProgress("10:21:34 Installing KB1 with DISM"));
        Assert.Null(WinUpdate.ParseProgress("garbage"));
        Assert.Equal("current", WinUpdate.Outcome(new RemoteRunResult(0, "", "", 1, "current")));
        Assert.Equal("ok", WinUpdate.Outcome(new RemoteRunResult(0, "", "", 1, "installed")));
        Assert.Equal("reboot", WinUpdate.Outcome(new RemoteRunResult(3010, "", "", 1, "reboot")));
        Assert.Equal("failed", WinUpdate.Outcome(new RemoteRunResult(WinUpdate.NotApplicable, "not applicable", "", 1, "not_applicable")));
        Assert.Equal("failed", WinUpdate.Outcome(new RemoteRunResult(5, "DISM exit code 5", "", 1, "failed")));
    }

    private static IReadOnlyDictionary<string, string> Scratch(string dir) => new Dictionary<string, string>
    {
        [WinUpdate.ProgressSuffix] = Path.Combine(dir, "p.txt"), ["-dism.txt"] = Path.Combine(dir, "d.txt"), ["-dism.log"] = Path.Combine(dir, "d.log"),
    };

    [Fact]
    public void InstallScriptKeepsItsValuesInLiterals()
    {
        var s = WinUpdate.InstallScript(@"C:\Windows\ADmiral\0123456789ab\admiral-0123456789ab-wu.msu", "KB5043080", "10.0.26100",
            Scratch(@"C:\r"), "r", "o", "t");
        Assert.Contains("$kb = 'KB5043080'; $want = '26100'", s);
        Assert.Contains("/Add-Package", s);
        Assert.Contains("/NoRestart", s);
        Assert.Contains("expand.exe", s);                                   // an .msu DISM cannot take is expanded
        Assert.DoesNotContain("wusa", s, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expand.exe", WinUpdate.InstallScript(@"C:\x\admiral-0123456789ab-wu.cab", "KB1234567", null, Scratch(@"C:\r"), "r", "o", "t"));
    }

    // the script's decisions before DISM, run with stand-ins for the Windows-only commands
    private (JsonObject Result, string Progress) RunInstall(string mocks, string? want)
    {
        var dir = Directory.CreateTempSubdirectory("admiral-wu-ps-").FullName;
        try
        {
            var pkg = Path.Combine(dir, "u.msu");
            File.WriteAllText(pkg, "x");
            var script = WinUpdate.InstallScript(pkg.Replace('/', '\\'), "KB5043080", want, Scratch(dir), Path.Combine(dir, "run"),
                Path.Combine(dir, "out"), Path.Combine(dir, "tmp"));
            script = script.Replace(pkg.Replace('/', '\\'), pkg).Replace(dir.Replace('/', '\\'), dir);
            var (code, _, err, _) = Pwsh.Run(mocks + "\n" + script);
            Assert.True(code == 0, err);
            var res = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "out")))!;
            return (res, File.Exists(Path.Combine(dir, "p.txt")) ? File.ReadAllText(Path.Combine(dir, "p.txt")) : "");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [PwshFact]
    public void AlreadyInstalledUpdateIsSkipped()
    {
        const string mocks = """
            function Get-ItemProperty { [pscustomobject]@{ CurrentBuildNumber = '26100'; UBR = 1742; DisplayVersion = '24H2' } }
            function Get-HotFix { [pscustomobject]@{ HotFixID = 'KB5043080'; InstalledOn = [datetime]'2026-11-12' } }
            function Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' } } }
            """;
        var (r, prg) = RunInstall(mocks, "10.0.26100");
        Assert.Equal("current", (string)r["state"]!);
        Assert.Equal(0, (int)r["exit"]!);
        Assert.Contains("already installed (2026-11-12)", (string)r["output"]!);
        Assert.Contains("Windows build 10.0.26100.1742 (24H2)", prg);
    }

    [PwshFact]
    public void UpdateNotSignedByMicrosoftIsRefused()
    {
        // DISM and expand.exe run as SYSTEM: a file without a valid Microsoft signature never reaches them
        foreach (var sig in new[]
                 {
                     "[pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }",
                     "[pscustomobject]@{ Status = 'HashMismatch'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, C=US' } }",
                     "[pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Evil, O=Not Microsoft Corporation, C=US' } }",
                     "[pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=O=Microsoft Corporation Fake, O=Evil' } }",
                 })
        {
            var mocks = $$"""
                function Get-ItemProperty { [pscustomobject]@{ CurrentBuildNumber = '26100'; UBR = 1742; DisplayVersion = '24H2' } }
                function Get-HotFix { throw 'must not be asked' }
                function Start-Process { throw 'DISM must not run' }
                function Get-AuthenticodeSignature { {{sig}} }
                """;
            var (r, prg) = RunInstall(mocks, "10.0.26100");
            Assert.Equal("failed", (string)r["state"]!);
            Assert.Contains("not signed by Microsoft", (string)r["error"]!);
            Assert.DoesNotContain("must not", (string)r["error"]!);
            Assert.Contains("FAILED", prg);
        }
    }

    [PwshFact]
    public void UpdateForAnotherBuildIsRefused()
    {
        const string mocks = """
            function Get-ItemProperty { [pscustomobject]@{ CurrentBuildNumber = '22631'; UBR = 4460; DisplayVersion = '23H2' } }
            function Get-HotFix { throw 'must not be asked' }
            """;
        var (r, prg) = RunInstall(mocks, "10.0.26100");
        Assert.Equal("not_applicable", (string)r["state"]!);
        Assert.Contains("for Windows build 26100, this computer runs build 22631", (string)r["error"]!);
        Assert.Contains("FAILED", prg);
    }

    [Fact]
    public void WaitAndMessageSteps()
    {
        var e = new PackageEntry { Id = "Acme.Chain", Kind = "chain" };
        var steps = Chain.ValidateSteps(e,
        [
            new PackageStep { Type = "wait", Seconds = 0 },
            new PackageStep { Type = "wait", Seconds = 999999 },
            new PackageStep { Type = "message", Text = "  Restart \"soon\"\r\n  save\twork \\", Seconds = 1, Script = "x" },
        ]);
        Assert.Equal(1, steps[0].Seconds);
        Assert.Equal(Chain.MaxWait, steps[1].Seconds);
        Assert.Equal("Restart 'soon' save work", steps[2].Text);
        Assert.Equal("SERVER:evil hi", Chain.ValidMessage(" /SERVER:evil hi"));          // never one of msg.exe's options
        Assert.Equal(10, steps[2].Seconds);
        Assert.Null(steps[2].Script);
        Assert.Contains("wait 1s", Chain.Describe(steps[0]));
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(e, [new PackageStep { Type = "message", Text = "  " }]));
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(e, [new PackageStep { Type = "message", Text = new string('a', 501) }]));
        var script = Chain.MessageScript(@"C:\r\admiral-0123456789ab-user.txt", 60, "r", "o", "t");
        Assert.Contains("msg.exe\" '*' '/TIME:60' $m", script);
    }

    [Fact]
    public void ChainUsesTheFilesOfTheWholeLibrary()
    {
        var lib = new List<PackageEntry>
        {
            new() { Id = "Acme.App", Files = [new PackageFile { Path = "Acme.App/1/setup.msi" }] },
            new() { Id = "WU-26100-KB5043080", Kind = "winupdate", Files = [new PackageFile { Path = "WU-26100-KB5043080/26100.1742/u.msu" }] },
            new() { Id = "Other.Chain", Kind = "chain", Files = [new PackageFile { Path = "Other.Chain/1/x.msi" }] },
        };
        var chain = new PackageEntry { Id = "Chain.Setup", Kind = "chain" };
        var steps = Chain.ValidateSteps(chain,
        [
            new PackageStep { Type = "install", File = "Acme.App/1/setup.msi", Args = "/qn" },
            new PackageStep { Type = "install", File = "WU-26100-KB5043080/26100.1742/u.msu", Args = "/ignored" },
        ], lib);
        Assert.Null(steps[1].Args);                                        // a Windows update takes no switches
        Assert.Contains("Windows update", Chain.Describe(steps[1]));
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(chain, [new PackageStep { Type = "install", File = "Other.Chain/1/x.msi" }], lib));
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(chain, [new PackageStep { Type = "install", File = "Acme.App/1/setup.msi" }]));
    }

    [Fact]
    public void SharePathsForTheUpdateFiles()
    {
        const string dir = @"ADmiral\0123456789ab";
        foreach (var sfx in new[] { "-wu.msu", "-wu.cab", "-prg.txt", "-dism.txt", "-dism.log", "-user.txt" })
            Assert.Equal($@"{dir}\admiral-0123456789ab{sfx}", Remote.ValidateSharePath($@"{dir}\admiral-0123456789ab{sfx}"));
        Assert.Throws<ArgumentException>(() => Remote.ValidateSharePath($@"{dir}\admiral-0123456789ab-wu\..\x.txt"));
    }

    [Fact]
    public void ReleaseDataNamesTheKb()
    {
        var doc = JsonNode.Parse("""
            {"Vulnerability":[{"Remediations":[
              {"Description":{"Value":"5043080"},"FixedBuild":"10.0.26100.1742"},
              {"Description":{"Value":"5041585"},"FixedBuild":"10.0.22631.4169"},
              {"Description":{"Value":"Release Notes"},"FixedBuild":"10.0.22631.4169"},
              {"Description":{"Value":"5040000"},"FixedBuild":"10.0.26100.1000"}]}]}
            """);
        var r = Updates.ParseReleaseKbs(doc);
        Assert.Equal((1742L, "KB5043080"), r["10.0.26100"]);
        Assert.Equal((4169L, "KB5041585"), r["10.0.22631"]);
    }

    [Fact]
    public void ArchitectureOfFilesAndComputers()
    {
        Assert.Equal("x64", AdmiralService.UpdateFileArch("WU/26100.1/windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu"));
        Assert.Equal("arm64", AdmiralService.UpdateFileArch("windows11.0-kb5043080-arm64_aa.msu"));
        Assert.Equal("x86", AdmiralService.UpdateFileArch("windows10.0-kb5043080-x86.cab"));
        Assert.Null(AdmiralService.UpdateFileArch("update.msu"));
        Assert.Equal("x64", AdmiralService.ComputerArch(new JsonObject { ["os_architecture"] = "64 bites" }));
        Assert.Equal("arm64", AdmiralService.ComputerArch(new JsonObject { ["os_architecture"] = "ARM 64-bit Processor" }));
        Assert.Equal("x86", AdmiralService.ComputerArch(new JsonObject { ["os_architecture"] = "32-bit" }));
        Assert.Null(AdmiralService.ComputerArch(new JsonObject()));
    }

    [Fact]
    public void CompatibleComputersOfAWindowsUpdate()
    {
        App.FullScan();
        App.RefreshUpdates();
        App.Settings.Packages.Folder = _f.Temp.File("pkcompat");
        var comps = App.Computers();
        JsonObject? Inv(Row c) => c["inventory"] as JsonObject;
        // a build that client computers run
        var build = comps.Select(c => Inv(c)).Where(i => i is not null && Updates.ComputerFamily(i) == Updates.FamilyClient)
            .Select(i => (string?)i!["os_version"]).First(b => b is { Length: > 0 })!;
        using (var up = App.UploadWinUpdate(build, "KB5999999", $"{WinUpdate.BuildNumber(build)}.4600", "windows11.0-kb5999999-x64.msu"))
        {
            up.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("update", 300))));
            up.Commit();
        }
        var id = WinUpdate.PackageId(build, "KB5999999");
        var r = App.WinUpdateCompatible(id);
        Assert.Null(r["family"]);                                   // no catalog title, KB not in the reference: not known
        Assert.Equal("x64", r["arch"]);
        var needs = (List<Row>)r["needs"]!;
        var onBuild = comps.Where(c => (string?)Inv(c)?["os_version"] == build).Select(c => (string)c["guid"]!).ToHashSet();
        Assert.NotEmpty(needs);
        Assert.All(needs, n => Assert.Contains((string)n["guid"]!, onBuild));           // the demo revisions are all below 4600
        Assert.Equal(onBuild.Count, needs.Count);
        Assert.All((List<Row>)r["incompatible"]!, n => Assert.DoesNotContain((string)n["guid"]!, onBuild));
        Assert.Equal(comps.Count, needs.Count + ((List<Row>)r["installed"]!).Count + ((List<Row>)r["incompatible"]!).Count + ((List<Row>)r["unknown"]!).Count);

        // checked in the (demo) catalog, whose title says Windows 11: only client computers of the build fit
        var file = App.Library().Get(id)!.Files[0].Path;
        Assert.Equal(true, App.PackageCatalogCheck(id, file)["ok"]);
        var r2 = App.WinUpdateCompatible(id);
        Assert.Equal(Updates.FamilyClient, r2["family"]);
        Assert.All((List<Row>)r2["needs"]!, n => Assert.Equal(Updates.FamilyClient, Updates.ComputerFamily(Inv(App.Computer((string)n["guid"]!)))));
        Assert.Equal(file, r2["file"]);

        // a version below every revision: everything on the build has it already
        using (var up = App.UploadWinUpdate(build, "KB5999998", $"{WinUpdate.BuildNumber(build)}.10", "windows11.0-kb5999998-x64.msu"))
        {
            up.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("older", 300))));
            up.Commit();
        }
        var r3 = App.WinUpdateCompatible(WinUpdate.PackageId(build, "KB5999998"));
        Assert.Empty((List<Row>)r3["needs"]!);
        Assert.All((List<Row>)r3["installed"]!, n => Assert.Equal("newer", n["reason"]));

        // what a computer reports about itself must agree with its AD object: a client that claims to be a server
        // (or the other way round) is listed for a check, not silently left out
        var liar = (string)needs[0]["guid"]!;
        App.Store.Execute("UPDATE computers SET os = ? WHERE guid = ?", "Windows Server 2025 Standard", liar);
        var r4 = App.WinUpdateCompatible(id);
        Assert.Contains((List<Row>)r4["unknown"]!, n => (string)n["guid"]! == liar && (string)n["reason"]! == "family_conflict");
        Assert.DoesNotContain((List<Row>)r4["needs"]!, n => (string)n["guid"]! == liar);
        Assert.Equal(Updates.FamilyServer, Updates.OsNameFamily("Windows Server 2022 Datacenter"));
        Assert.Equal(Updates.FamilyClient, Updates.OsNameFamily("Windows 11 Enterprise LTSC"));

        Assert.Throws<NotFound>(() => App.WinUpdateCompatible("WU-1-KB1234567"));
    }

    [Fact]
    public void WindowsUpdateDeploymentInDemo()
    {
        App.FullScan();
        App.Settings.Packages.Folder = _f.Temp.File("pkwu");
        var comps = App.Computers().Where(c => c["online"] is true).ToList();
        var build = comps.Select(c => (c["inventory"] as JsonObject)?["os_version"]?.GetValue<string>()).First(b => b is { Length: > 0 })!;
        using (var up = App.UploadWinUpdate(build, "KB5043080", $"{WinUpdate.BuildNumber(build)}.9999", "windows11.0-kb5043080-x64.msu"))
        {
            up.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("update", 300))));
            up.Commit();
        }
        var id = WinUpdate.PackageId(build, "KB5043080");
        var file = App.Library().Get(id)!.Files[0].Path;
        // the demo catalog knows the file: it counts as checked
        var cat = App.PackageCatalogCheck(id, file);
        Assert.Equal(true, cat["ok"]);
        Assert.Equal("catalog", App.Library().Get(id)!.Files[0].HashSource);
        var same = comps.Where(c => (c["inventory"] as JsonObject)?["os_version"]?.GetValue<string>() == build).Take(3).Select(c => (string)c["name"]!).ToList();
        var other = comps.FirstOrDefault(c => (c["inventory"] as JsonObject)?["os_version"]?.GetValue<string>() is { Length: > 0 } b && b != build);
        var names = other is null ? same : [.. same, (string)other["name"]!];
        var r = App.StartDeployment(id, file, "", names);
        Assert.Equal("wuinstall", ((JobInfo)r["job"]!).Kind);                // its own job: other deployments are not held up
        Assert.Equal("done", _f.WaitJob(((JobInfo)r["job"]!).Id).Status);
        var dep = App.Store.Deployment((long)r["id"]!)!;
        Assert.Equal("msu", dep["kind"]);
        var targets = (List<Row>)dep["targets"]!;
        Assert.All(targets, t => Assert.Equal("done", t["step"]));
        var log = App.DeploymentLog((long)r["id"]!);
        Assert.Contains("Windows update result", log);
        Assert.Contains(targets, t => t["outcome"] as string is "reboot" or "current");
        if (targets.Any(t => t["outcome"] as string == "reboot")) Assert.Contains("installing 100%", log);
        if (other is not null)
        {
            var o = targets.Single(t => (string)t["name"]! == (string)other["name"]!);
            Assert.Equal("failed", o["outcome"]);
            Assert.Contains("not copied", (string)o["error"]!);
        }
    }
}
