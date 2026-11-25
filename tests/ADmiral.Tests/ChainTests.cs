using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>Package chains: step validation, the scripts run on the target, the remote runner and a demo deployment.</summary>
public sealed class ChainTests : IDisposable
{
    private static readonly SmbCreds Creds = new("svc", "pw", "CORP");
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    private static PackageEntry Entry() => new()
    {
        Id = "Acme.Kit",
        Files =
        [
            new PackageFile { Path = "Acme.Kit/1.0/setup.msi", Sha256 = new string('a', 64) },
            new PackageFile { Path = "Acme.Kit/1.0/app.cfg", Sha256 = new string('b', 64) },
        ],
    };

    [Fact]
    public void StepsAreCheckedAndCleaned()
    {
        var steps = Chain.ValidateSteps(Entry(),
        [
            new PackageStep { Type = "Install", File = "Acme.Kit/1.0/setup.msi", Args = "/qn", Script = "ignored" },
            new PackageStep { Type = "copy", File = "Acme.Kit/1.0/app.cfg", Path = @"C:\ProgramData\Acme\" },
            new PackageStep { Type = "delete", Path = @"C:\ProgramData\Acme\old.cfg", ContinueOnError = true },
            new PackageStep { Type = "reboot", Seconds = 1 },
            new PackageStep { Type = "shutdown" },
            new PackageStep { Type = "wol", Seconds = 99999 },
            new PackageStep { Type = "powershell", Script = "Get-Date\r\nexit 0" },
            new PackageStep { Type = "cmd", Script = "ipconfig /all" },
            new PackageStep { Type = "scan", Path = "x" },
        ]);
        Assert.Equal(["install", "copy", "delete", "reboot", "shutdown", "wol", "powershell", "cmd", "scan"], steps.Select(s => s.Type));
        Assert.Null(steps[0].Script);                                     // fields of other types are dropped
        Assert.Equal(@"C:\ProgramData\Acme", steps[1].Path);
        Assert.True(steps[2].ContinueOnError);
        Assert.Equal(Chain.MinPowerDelay, steps[3].Seconds);              // never so short the result cannot be written
        Assert.True(steps[3].Wait);
        Assert.Equal(Chain.DefaultPowerDelay, steps[4].Seconds);
        Assert.Equal(3600, steps[5].Seconds);
        Assert.Equal("Get-Date\nexit 0", steps[6].Script);
        Assert.Null(steps[8].Path);
    }

    [Theory]
    [InlineData("nope", null, null, null)]
    [InlineData("install", "Acme.Kit/1.0/app.cfg", null, null)]           // not an installer
    [InlineData("install", "Other/evil.exe", null, null)]                 // not a file of the package
    [InlineData("copy", "Acme.Kit/1.0/app.cfg", @"\\server\share", null)]
    [InlineData("copy", "Acme.Kit/1.0/app.cfg", @"C:\a\..\Windows", null)]
    [InlineData("copy", "Acme.Kit/1.0/app.cfg", @"C:\a\*.cfg", null)]
    [InlineData("copy", "Acme.Kit/1.0/app.cfg", "relative\\path", null)]
    [InlineData("delete", null, @"C:\", null)]
    [InlineData("delete", null, @"C:\Windows", null)]                     // at least two levels deep
    [InlineData("delete", null, @"C:\a\b:stream", null)]
    [InlineData("powershell", null, null, "   ")]
    [InlineData("cmd", null, null, "a\0b")]
    public void BadStepsAreRefused(string type, string? file, string? path, string? script)
    {
        var ex = Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(Entry(), [new PackageStep { Type = type, File = file, Path = path, Script = script }]));
        Assert.Contains("1", ex.Message);                                 // names the step
    }

    [Theory]
    [InlineData(@"C:\a\NUL")]
    [InlineData(@"C:\a\con.txt")]
    [InlineData(@"C:\a\COM1")]
    [InlineData(@"C:\a\b.")]                                            // Windows would trim the dot: another file
    [InlineData(@"C:\a\b \c")]
    [InlineData(@"C:\a\ b")]
    [InlineData(@"C:\\a\b")]
    public void DevicesAndSilentlyTrimmedNamesAreRefused(string path) =>
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidLocalPath(path, 1));

    [Fact]
    public void PathCheckIsLinearTime()
    {
        // the first pattern backtracked exponentially on a long segment followed by a bad character (ReDoS)
        var sw = System.Diagnostics.Stopwatch.StartNew();
        foreach (var bad in new[] { @"C:\" + new string('a', 230) + "?", @"C:\" + string.Concat(Enumerable.Repeat(@"a\", 110)) + "*" })
            Assert.ThrowsAny<ArgumentException>(() => Chain.ValidLocalPath(bad));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"took {sw.Elapsed}");
        Assert.Equal(@"C:\ProgramData\Acme\app.cfg", Chain.ValidLocalPath(@" C:\ProgramData\Acme\app.cfg "));
    }

    [Fact]
    public void NvdLinksOpenOnlyOverHttps()
    {
        Assert.True(DesktopLogic.IsAllowedExternalUrl("https://nvd.nist.gov/vuln/detail/CVE-2026-1234", out _));
        Assert.False(DesktopLogic.IsAllowedExternalUrl("http://nvd.nist.gov/vuln/detail/CVE-2026-1234", out _));
        Assert.False(DesktopLogic.IsAllowedExternalUrl("https://nvd.nist.gov.evil.example/", out _));
    }

    [Fact]
    public void TooManyStepsAreRefused() =>
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidateSteps(Entry(), Enumerable.Range(0, Chain.MaxSteps + 1).Select(_ => new PackageStep { Type = "scan" })));

    [Fact]
    public void MagicPacketAndAddresses()
    {
        var p = Chain.MagicPacket("00-1A-2b-3C-4d-5E")!;
        Assert.Equal(102, p.Length);
        Assert.All(p[..6], b => Assert.Equal(0xFF, b));
        Assert.Equal(new byte[] { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E }, p[96..]);
        Assert.Equal(p, Chain.MagicPacket("00:1a:2b:3c:4d:5e"));
        Assert.Equal(p, Chain.MagicPacket("001A2B3C4D5E"));
        foreach (var bad in new[] { null, "", "00-1A-2B-3C-4D", "00-1A:2B-3C-4D-5E", "zz-1A-2B-3C-4D-5E", "00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF" })
            Assert.Null(Chain.MagicPacket(bad));
        Assert.Equal(["255.255.255.255", "10.1.2.255"], Chain.WolAddresses("10.1.2.33"));
        Assert.Equal(["255.255.255.255"], Chain.WolAddresses("garbage"));
    }

    [Fact]
    public void PathsInTheScriptsStayInsideTheLiterals()
    {
        var evil = @"C:\Data\it's ‘x’";
        var del = Chain.DeleteScript(evil, "r", "o", "t");
        Assert.Contains("'C:\\Data\\it''s ‘‘x’’'", del);
        var copy = Chain.CopyScript("src", evil, "a'b.cfg", new string('c', 64), "r", "o", "t");
        Assert.Contains("'C:\\Data\\it''s ‘‘x’’\\a''b.cfg'", copy);
        Assert.Contains("Get-FileHash", copy);
        Assert.Contains("& cmd.exe /d /c 'C:\\run\\u.cmd'", Chain.ScriptRunner("cmd", @"C:\run\u.cmd", "r", "o", "t"));
        Assert.Contains("-File 'C:\\run\\u.ps1'", Chain.ScriptRunner("powershell", @"C:\run\u.ps1", "r", "o", "t"));
        Assert.Contains("shutdown.exe /r /f /t 15 ", Chain.PowerScript(true, 1, "r", "o", "t"));
        Assert.Contains("shutdown.exe /s /f /t 60 ", Chain.PowerScript(false, 60, "r", "o", "t"));
        var cmd = Encoding.UTF8.GetString(Chain.CmdFileBytes("echo a\necho b"));
        Assert.Equal("@echo off\r\nchcp 65001 >nul\r\necho a\r\necho b\r\n", cmd);
    }

    [Fact]
    public void RemoteRunnerSendsTheScriptFileAndCleansUp()
    {
        var be = new FakeTarget
        {
            OnRun = (t, _) =>
            {
                var b = t.Files.Keys.First(k => k.EndsWith(".ps1", StringComparison.Ordinal))[..^4];
                t.Files[b + ".run"] = "started"u8.ToArray();
                t.Files[b + ".out"] = Encoding.UTF8.GetBytes(new JsonObject { ["exit"] = 3, ["error"] = "", ["seconds"] = 2, ["output"] = "hello" }.ToJsonString());
            },
        };
        var steps = new List<string>();
        var res = Chain.RunRemote("pc1", Creds, new CollectSettings { CleanupDelay = 0 },
            [new Chain.Payload("-user.cmd", Bytes: Chain.CmdFileBytes("exit /b 3"))],
            (p, run, o, tmp) => Chain.ScriptRunner("cmd", p["-user.cmd"], run, o, tmp), (s, _) => steps.Add(s), 60, be.Backend);
        Assert.Equal(3, res.ExitCode);
        Assert.Equal("hello", res.Output);
        Assert.Contains(be.Put, p => p.EndsWith("-user.cmd", StringComparison.Ordinal));
        Assert.Empty(be.Files);                                           // script, payload and result all removed
        Assert.Equal(["connecting", "copying", "starting", "running", "cleanup"], steps.Distinct());
    }

    [Fact]
    public void ChainDeploymentRunsEveryStepInOrderInDemo()
    {
        App.FullScan();
        App.Settings.Packages.Folder = _f.Temp.File("pk");
        using (var up = App.UploadPackage("Acme.Kit", "AcmeSetup.exe", "1.0", "Acme Kit"))
        {
            up.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("installer", 200))));
            up.Commit();
        }
        var exe = App.Library().Get("Acme.Kit")!.Files[0].Path;
        Assert.ThrowsAny<ArgumentException>(() => App.StartChainDeployment("Acme.Kit", [(string)App.Computers()[0]["name"]!]));   // no steps yet
        App.PackageSetSteps("Acme.Kit",
        [
            new PackageStep { Type = "copy", File = exe, Path = @"C:\ProgramData\Acme" },
            new PackageStep { Type = "powershell", Script = "Write-Output ok" },
            new PackageStep { Type = "install", File = exe, Args = "/S" },
            new PackageStep { Type = "reboot", Wait = true },
            new PackageStep { Type = "scan" },
        ]);
        Assert.Equal(5, App.Library().Get("Acme.Kit")!.Steps.Count);
        var names = App.Computers().Where(c => c["online"] is true).Take(3).Select(c => (string)c["name"]!).ToList();
        var r = App.StartChainDeployment("Acme.Kit", names);
        Assert.Equal("done", _f.WaitJob(((JobInfo)r["job"]!).Id).Status);
        var dep = App.Store.Deployment((long)r["id"]!)!;
        Assert.Equal("chain", dep["kind"]);
        Assert.Equal("copy → powershell → install → reboot → scan", dep["args"]);
        var targets = (List<Row>)dep["targets"]!;
        Assert.All(targets, t => Assert.Equal("done", t["step"]));
        Assert.Contains(targets, t => t["outcome"] as string is "ok" or "reboot");
        var log = App.DeploymentLog((long)r["id"]!);
        foreach (var i in Enumerable.Range(1, 5)) Assert.Contains($"Step {i}/5", log);
        Assert.True(log.IndexOf("Step 1/5", StringComparison.Ordinal) < log.IndexOf("Step 5/5", StringComparison.Ordinal));
        // a failed computer is repeated with the chain, not with a single installer
        var failed = targets.Where(t => t["outcome"] as string == "failed").ToList();
        if (failed.Count > 0) Assert.Equal("chain", App.Store.Deployment((long)App.RetryDeployment((long)r["id"]!)["id"]!)!["kind"]);
    }

    [Fact]
    public void FailedStepStopsTheChainUnlessContinueOnError()
    {
        App.FullScan();
        App.Settings.Packages.Folder = _f.Temp.File("pk2");
        App.PackageCreate("Acme.Wake", "Wake");
        var sent = new List<string>();
        App.WolSender = (h, _, _) => sent.Add(h);
        // an offline computer without a MAC address: wake on LAN fails at once
        var off = App.Computers().First(c => c["online"] is false);
        App.PackageSetSteps("Acme.Wake", [new PackageStep { Type = "wol", Seconds = 0 }, new PackageStep { Type = "scan" }]);
        var r = App.StartChainDeployment("Acme.Wake", [(string)off["name"]!]);
        _f.WaitJob(((JobInfo)r["job"]!).Id);
        var log = App.DeploymentLog((long)r["id"]!);
        var t = Assert.Single((List<Row>)App.Store.Deployment((long)r["id"]!)!["targets"]!);
        Assert.Equal("failed", t["outcome"]);
        Assert.Contains("Chain stopped", log);
        Assert.DoesNotContain("Step 2/2", log);
        // a repeat runs exactly the original chain: refused once the chain was changed, allowed while it is the same
        var first = (long)r["id"]!;
        App.PackageSetSteps("Acme.Wake", [new PackageStep { Type = "wol", Seconds = 0, ContinueOnError = true }, new PackageStep { Type = "scan" }]);
        Assert.ThrowsAny<ArgumentException>(() => App.RetryDeployment(first));
        App.PackageSetSteps("Acme.Wake", [new PackageStep { Type = "wol", Seconds = 0 }, new PackageStep { Type = "scan" }]);
        _f.WaitJob(((JobInfo)App.RetryDeployment(first)["job"]!).Id);
        App.PackageSetSteps("Acme.Wake", [new PackageStep { Type = "wol", Seconds = 0, ContinueOnError = true }, new PackageStep { Type = "scan" }]);
        r = App.StartChainDeployment("Acme.Wake", [(string)off["name"]!]);
        _f.WaitJob(((JobInfo)r["job"]!).Id);
        Assert.Contains("Step 2/2", App.DeploymentLog((long)r["id"]!));
    }

    [Fact]
    public void PackageWithoutFilesCanBeCreatedOnce()
    {
        App.Settings.Packages.Folder = _f.Temp.File("pk3");
        var e = App.PackageCreate("Acme.Empty", " Empty ", "2.0");
        Assert.Equal("Empty", e.Name);
        Assert.Empty(e.Files);
        Assert.ThrowsAny<Exception>(() => App.PackageCreate("acme.empty", "again"));
        Assert.ThrowsAny<Exception>(() => App.PackageCreate("../x", "bad"));
        var row = Assert.Single((List<PackageRow>)App.PackagesStatus()["packages"]!);
        Assert.Empty(row.Steps);
    }
}
