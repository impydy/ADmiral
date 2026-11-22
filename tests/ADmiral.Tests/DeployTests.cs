using System.ComponentModel;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>test_deploy.py: the per-computer installation flow, quoting of the arguments, validation, classification.
/// (The HTTP API / service-level cases belong to the service layer.)</summary>
public sealed class DeployTests : IDisposable
{
    private static readonly SmbCreds Creds = new("svc", "pw", "CORP");
    private readonly CoreTemp _tmp = new();
    private readonly PackageLibrary _lib;

    public DeployTests() => _lib = new PackageLibrary(_tmp.File("pk"));

    public void Dispose() => _tmp.Dispose();

    /// <summary>"Running" the service writes the .run marker, the result and the installer output.</summary>
    private static FakeTarget Target(int exitCode = 0, JsonObject? extra = null) => new()
    {
        OnRun = (t, _) =>
        {
            t.Files[t.Base + ".run"] = "started"u8.ToArray();
            var res = new JsonObject { ["exit"] = exitCode, ["error"] = "", ["seconds"] = 3 };
            foreach (var (k, v) in extra ?? []) res[k] = v?.DeepClone();
            t.Files[t.Base + ".out"] = Encoding.UTF8.GetBytes(res.ToJsonString());
            t.Files[t.Base + ".log"] = "installer output"u8.ToArray();
        },
    };

    private string Installer(string kind)
    {
        Directory.CreateDirectory(_lib.Folder);
        File.WriteAllBytes(Path.Combine(_lib.Folder, "setup." + kind), Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("binary", 100))));
        return "setup." + kind;
    }

    private (FakeTarget Be, List<(string Step, int? Pct)> Steps, DeployResult Res) Run(string kind, string args, int code = 0, JsonObject? extra = null)
    {
        var rel = Installer(kind);
        var be = Target(code, extra);
        var steps = new List<(string, int?)>();
        var res = Deploy.DeployOne("pc1", Creds, _lib, rel, kind, args, new CollectSettings { CleanupDelay = 0 },
                                   (s, p) => steps.Add((s, p)), 60, be.Backend);
        return (be, steps, res);
    }

    [Fact]
    public void MsiInstallTracksStepsAndCleansUp()
    {
        var (be, steps, res) = Run("msi", "/qn /norestart");
        var names = steps.Select(s => s.Step).ToList();
        foreach (var (a, b) in new[] { ("connecting", "copying"), ("copying", "starting"), ("starting", "installing"), ("installing", "cleanup") })
            Assert.True(names.IndexOf(a) < names.IndexOf(b), $"{a} before {b}");
        Assert.Contains(("copying", (int?)50), steps);
        Assert.Contains(("copying", (int?)100), steps);
        Assert.Contains("msiexec.exe", be.Script);
        Assert.Contains("/qn /norestart", be.Script);
        Assert.Contains("/i", be.Script);
        Assert.Equal("ok", res.Outcome);
        Assert.Equal(0, res.ExitCode);
        Assert.Equal(3, res.Seconds);
        Assert.Contains("installer output", res.Log);
        Assert.Empty(be.Files);                                      // installer, script and result are all removed
        Assert.Contains("admiral-", be.Ran[0]);
        Assert.Contains("-File", be.Ran[0]);
        Assert.Single(be.RemovedServices);                           // the self-check ran
    }

    [Fact]
    public void ExeExitCodes()
    {
        var (be, _, res) = Run("exe", "/S", 3010);
        Assert.Equal("reboot", res.Outcome);
        Assert.Contains("-ArgumentList '/S'", be.Script);
        Assert.DoesNotContain("msiexec", be.Script);
        (_, _, res) = Run("exe", "", 1603);
        Assert.Equal("failed", res.Outcome);
        Assert.Equal(1603, res.ExitCode);
    }

    [Fact]
    public void ProgramListIsReportedInTheLog()
    {
        var (_, _, res) = Run("msi", "/qn", extra: new JsonObject { ["installed"] = new JsonArray("Acme Tool 1.2.3"), ["entries"] = 42 });
        Assert.Contains("New or changed programs: Acme Tool 1.2.3", res.Log);
        (_, _, res) = Run("msi", "/qn", extra: new JsonObject { ["installed"] = new JsonArray(), ["entries"] = 42 });
        Assert.Contains("no new or changed program", res.Log);
        (_, _, res) = Run("msi", "/qn", extra: new JsonObject { ["installed"] = "Single 1.0", ["entries"] = 42 });
        Assert.Contains("Single 1.0", res.Log);
    }

    [Fact]
    public void ScriptQuotesArguments()
    {
        var s = Deploy.InstallScript("exe", @"C:\a b\x.exe", "/D=C:\\it's", "r", "o", "t");
        Assert.Contains("'/D=C:\\it''s'", s);
    }

    [Theory]
    [InlineData("'; Remove-Item C:\\ -Recurse; '")]
    [InlineData("\u2019; calc.exe; \u2018")]
    [InlineData("\u201A$(calc)\u201B")]
    [InlineData("$env:USERNAME `n & | > %COMSPEC%")]
    public void ArgumentsCannotLeaveThePowerShellLiteral(string args)
    {
        var lit = Deploy.Q(args);
        // a single-quoted literal ends at the first quote char that is not doubled: walk it like PowerShell does
        var quotes = new HashSet<char> { '\'', '\u2018', '\u2019', '\u201A', '\u201B' };
        Assert.Contains(lit[0], quotes);
        var i = 1;
        var sb = new StringBuilder();
        while (true)
        {
            if (quotes.Contains(lit[i]))
            {
                if (i + 1 < lit.Length && quotes.Contains(lit[i + 1]))
                {
                    sb.Append(lit[i]);
                    i += 2;
                    continue;
                }
                break;
            }
            sb.Append(lit[i++]);
        }
        Assert.Equal(lit.Length - 1, i);                             // the literal ends exactly at its last char
        Assert.Equal(args, sb.ToString());                          // and holds the arguments verbatim
        var script = Deploy.InstallScript("exe", @"C:\Windows\Temp\admiral-0123456789ab-inst.exe", args, "r", "o", "t");
        Assert.Contains($"-ArgumentList {lit} -Wait", script);
    }

    [Fact]
    public void MsiArgumentsFollowTheFixedPackagePath()
    {
        var s = Deploy.InstallScript("msi", @"C:\Windows\Temp\admiral-0123456789ab-inst.msi", "INSTALLDIR=\"C:\\Program Files\\X\" /qn", "r", "o", "t");
        Assert.Contains("Start-Process -FilePath 'msiexec.exe' -WorkingDirectory 'C:\\Windows\\Temp' -ArgumentList '/i \"C:\\Windows\\Temp\\admiral-0123456789ab-inst.msi\" INSTALLDIR=\"C:\\Program Files\\X\" /qn' -Wait", s);
    }

    [Fact]
    public void ArgsValidation()
    {
        Assert.Equal("/S", Deploy.ValidArgs("  /S  "));
        Assert.Throws<DeployError>(() => Deploy.ValidArgs("/S\0"));
        Assert.Throws<DeployError>(() => Deploy.ValidArgs("/S\r/X"));
        Assert.Throws<DeployError>(() => Deploy.ValidArgs("/S\u2028/X"));
        Assert.Throws<DeployError>(() => Deploy.ValidArgs(new string('a', 501)));
        Assert.Equal("", Deploy.ValidArgs(null));
        Assert.Equal("msi", Deploy.InstallerKind("A.MSI"));
        Assert.Null(Deploy.InstallerKind("a.zip"));
        Assert.Equal("/qn /norestart", Deploy.DefaultArgs("msi"));
        Assert.Equal("", Deploy.DefaultArgs("zip"));
    }

    [Theory]
    [InlineData(0, "ok")]
    [InlineData(3010, "reboot")]
    [InlineData(1641, "reboot")]
    [InlineData(1603, "failed")]
    [InlineData(null, "failed")]
    public void Classify(int? code, string outcome) => Assert.Equal(outcome, Deploy.Classify(code));

    [Fact]
    public void UnreachableDetection()
    {
        Assert.True(Deploy.IsUnreachable(new Win32Exception(10060)));
        Assert.True(Deploy.IsUnreachable(new Win32Exception(53)));
        Assert.True(Deploy.IsUnreachable(new TimeoutException()));
        Assert.True(Deploy.IsUnreachable(new SocketException((int)SocketError.TimedOut)));
        Assert.True(Deploy.IsUnreachable(new IOException("[WinError 10060] timed out")));
        Assert.True(Deploy.IsUnreachable(new InvalidOperationException("x", new TimeoutException())));
        Assert.False(Deploy.IsUnreachable(new UnauthorizedAccessException("STATUS_ACCESS_DENIED")));
        Assert.False(Deploy.IsUnreachable(new Win32Exception(5)));
    }

    [Fact]
    public void ConnectFailuresAreClassified()
    {
        var rel = Installer("msi");
        var be = new FakeTarget { FailAt = "connect" };
        Assert.IsNotType<Unreachable>(Assert.ThrowsAny<DeployError>(() =>
            Deploy.DeployOne("pc1", Creds, _lib, rel, "msi", "", new CollectSettings(), (_, _) => { }, 60, be.Backend)));
        var timeout = new TimeoutTarget();
        Assert.Throws<Unreachable>(() =>
            Deploy.DeployOne("pc1", Creds, _lib, rel, "msi", "", new CollectSettings(), (_, _) => { }, 60, new PdqBackend(timeout, be, be)));
    }

    private sealed class TimeoutTarget : IRemoteFiles
    {
        public IRemoteSession Connect(string host, SmbCreds creds, int timeoutSeconds) => throw new TimeoutException("SMB connection timed out");
    }

    [Fact]
    public void InstallerThatNeverFinishesTimesOutAndIsCleanedUp()
    {
        var rel = Installer("exe");
        var be = new FakeTarget();                                    // the service runs, nothing ever appears
        var ex = Assert.Throws<DeployError>(() =>
            Deploy.DeployOne("pc1", Creds, _lib, rel, "exe", "/S", new CollectSettings { CleanupDelay = 0 }, (_, _) => { }, 30, be.Backend));
        Assert.Contains("did not finish within 30s", ex.Message);
        Assert.Empty(be.Files);
        Assert.Single(be.RemovedServices);
    }

    [Fact]
    public void RunFailureIsADeployErrorWithoutSelfCheck()
    {
        var rel = Installer("exe");
        var be = new FakeTarget { FailAt = "run" };
        Assert.Throws<DeployError>(() =>
            Deploy.DeployOne("pc1", Creds, _lib, rel, "exe", "/S", new CollectSettings(), (_, _) => { }, 30, be.Backend));
        Assert.Empty(be.Files);
        Assert.Empty(be.RemovedServices);
    }

    [Fact]
    public void InstallerComesOnlyFromTheLibrary()
    {
        var be = Target();
        foreach (var bad in new[] { "../outside.msi", "/etc/passwd", "C:\\Windows\\x.msi", "a/../../b.msi" })
            Assert.Throws<DeployError>(() =>
                Deploy.DeployOne("pc1", Creds, _lib, bad, "msi", "", new CollectSettings(), (_, _) => { }, 30, be.Backend));
        Assert.Throws<DeployError>(() => Deploy.ResolveInstaller(_lib, "missing.msi"));
        Directory.CreateDirectory(_lib.Folder);
        File.WriteAllText(Path.Combine(_lib.Folder, "notes.txt"), "x");
        Assert.Throws<DeployError>(() => Deploy.ResolveInstaller(_lib, "notes.txt"));
        Assert.Equal(0, be.Connects);
    }

    [Fact]
    public void TamperedInstallerIsRefusedBeforeAnythingIsSent()
    {
        var rel = Installer("msi");
        var sha = PackageLibrary.Sha256File(_lib.File(rel));
        Assert.Equal(_lib.File(rel), Deploy.ResolveInstaller(_lib, rel, sha));
        File.WriteAllBytes(_lib.File(rel), "evil"u8.ToArray());
        var be = Target();
        Assert.Throws<DeployError>(() =>
            Deploy.DeployOne("pc1", Creds, _lib, rel, "msi", "", new CollectSettings(), (_, _) => { }, 30, be.Backend, sha));
        Assert.Equal(0, be.Connects);
    }

    [Fact]
    public void InstallerSwappedDuringTheCopyIsCaughtByTheHashOfTheCopiedBytes()
    {
        // larger than any read buffer, so the copy really reads the file while it is being changed
        Directory.CreateDirectory(_lib.Folder);
        var path = Path.Combine(_lib.Folder, "big.exe");
        var original = new byte[512 * 1024];
        new Random(1).NextBytes(original);
        File.WriteAllBytes(path, original);
        var sha = PackageLibrary.Sha256File(path);
        var be = Target();
        var blocked = false;
        be.OnCopyChunk = chunk =>
        {
            if (chunk != 1) return;
            try
            {
                using var f = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);   // swap the tail in place
                f.Position = original.Length - 1024;
                f.Write(new byte[1024]);
            }
            catch (IOException) { blocked = true; }                  // Windows: the open handle denies writers
        };
        DeployResult? res = null;
        DeployError? err = null;
        try { res = Deploy.DeployOne("pc1", Creds, _lib, "big.exe", "exe", "/S", new CollectSettings { CleanupDelay = 0 }, (_, _) => { }, 30, be.Backend, sha); }
        catch (DeployError e) { err = e; }
        if (!OperatingSystem.IsWindows()) Assert.False(blocked);       // POSIX: no mandatory sharing modes, the hash must catch it
        if (blocked)
            Assert.NotNull(res);                                       // nothing changed: the original was installed
        else
        {
            Assert.NotNull(err);                                       // the bytes sent differ from the registered hash
            Assert.Empty(be.Ran);                                      // the remote command never ran
            Assert.Empty(be.Files);                                    // the copy was removed again
            Assert.Empty(be.Dirs);
        }
    }

    [Fact]
    public void BadHostKindOrArgsAreRefused()
    {
        var rel = Installer("msi");
        var be = Target();
        Assert.Throws<DeployError>(() => Deploy.DeployOne("pc1 & x", Creds, _lib, rel, "msi", "", new CollectSettings(), (_, _) => { }, 30, be.Backend));
        Assert.Throws<DeployError>(() => Deploy.DeployOne("pc1", Creds, _lib, rel, "bat", "", new CollectSettings(), (_, _) => { }, 30, be.Backend));
        Assert.Throws<DeployError>(() => Deploy.DeployOne("pc1", Creds, _lib, rel, "msi", "a\0b", new CollectSettings(), (_, _) => { }, 30, be.Backend));
        Assert.Equal(0, be.Connects);
    }

    [Fact]
    public void ServiceCommandAndFilesUseOnlyTheRandomTag()
    {
        var (be, _, _) = Run("exe", "/S --dir \"C:\\x y\"");
        var svc = be.RanServices[0];
        Assert.Matches("^ADmiral_[0-9a-f]{12}$", svc);
        var tag = svc[8..];
        var d = $"C:\\Windows\\ADmiral\\{tag}";
        Assert.Equal($"%COMSPEC% /Q /C start \"\" /D \"{d}\" /B %COMSPEC% /S /Q /C \"powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass " +
                     $"-File \"{d}\\admiral-{tag}.ps1\" > \"{d}\\admiral-{tag}.log\" 2>&1 < nul\"", be.Ran[0]);
        Assert.Contains($"-WorkingDirectory '{d}'", be.Script);          // the installer starts in its private run folder
        Assert.Contains($"admiral-{tag}-inst.exe", be.Script);
    }
}
