using System.Text.Json.Nodes;
using ADmiral.Core;
using Microsoft.Extensions.Logging;

namespace ADmiral.Tests;

/// <summary>Diag is process-wide (it replaces Log.Logger): these tests run alone, never next to other tests.</summary>
[CollectionDefinition("Diagnostics", DisableParallelization = true)]
public sealed class DiagnosticsCollection;

/// <summary>Installs diagnostics into a temporary folder for one test and removes it again.</summary>
internal sealed class DiagFolder : IDisposable
{
    private readonly CoreTemp _tmp = new();

    public DiagFolder(bool debug = true)
    {
        Diag.Uninstall();
        Diag.Install(_tmp.Path, debug: debug);
    }

    public string Path => _tmp.Path;

    public string File(string name) => _tmp.File(name);

    public List<JsonObject> Ledger() => Diag.ReadLedger(Path);

    public void Dispose()
    {
        Diag.Uninstall();
        Diag.ClearSecrets();
        Diag.MaxLedgerBytes = 5 * 1024 * 1024;
        _tmp.Dispose();
    }
}

[Collection("Diagnostics")]
public class DiagTests
{
    private static ILogger L => Log.Logger;

    private static string Read(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var r = new StreamReader(fs);
        return r.ReadToEnd();
    }

    [Fact]
    public void FilesAreCreatedAndLevelsRouted()
    {
        using var f = new DiagFolder();
        L.LogDebug("only in the debug file");
        L.LogInformation("normal info");
        L.LogWarning("something odd on {Host}", "pc1");
        Assert.Contains("only in the debug file", Read(f.File(Diag.DebugFile)));
        var main = Read(f.File(Diag.LogFile));
        Assert.Contains("normal info", main);
        Assert.DoesNotContain("only in the debug file", main);
        var rows = f.Ledger();
        Assert.Equal(["WARNING"], rows.Select(r => (string?)r["level"]));
        Assert.Equal("something odd on pc1", (string?)rows[0]["message"]);
        Assert.Equal("something odd on {Host}", (string?)rows[0]["template"]);
    }

    [Fact]
    public void ExceptionTracebackIsRecorded()
    {
        using var f = new DiagFolder();
        try
        {
            _ = new Dictionary<string, int>()["missing"];
        }
        catch (KeyNotFoundException ex)
        {
            L.LogWarning(ex, "swallowed");
        }
        var row = Assert.Single(f.Ledger());
        Assert.Equal("KeyNotFoundException", (string?)row["exception"]);
        Assert.Contains("missing", (string?)row["traceback"]);
    }

    [Fact]
    public void SecretsNeverReachAnyFile()
    {
        using var f = new DiagFolder();
        Diag.RegisterSecret("Tr0ub4dor&3");
        L.LogWarning("bind failed for password=Tr0ub4dor&3 and token: abcdef123456");
        L.LogError("literal {Value} leaked", "Tr0ub4dor&3");
        try
        {
            throw new InvalidOperationException("auth with Tr0ub4dor&3 failed; Authorization: Negotiate YIIGwQYGKwYBBQUCoIIGtTCCBrGgJDAiBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYB");
        }
        catch (InvalidOperationException ex)
        {
            L.LogError(ex, "boom");
        }
        L.LogWarning("proxy said Proxy-Authorization: Basic dXNlcjpwYXNz and \"api_key\": \"k-12345\" sync_key=abc123");
        foreach (var name in new[] { Diag.LogFile, Diag.DebugFile, Diag.LedgerFile })
        {
            var text = Read(f.File(name));
            foreach (var bad in new[] { "Tr0ub4dor", "abcdef123456", "YIIGwQYG", "dXNlcjpwYXNz", "k-12345", "abc123" })
                Assert.DoesNotContain(bad, text);
        }
        Assert.Contains("***", Read(f.File(Diag.LedgerFile)));
        Assert.DoesNotContain("Tr0ub4dor", Diag.Report());
    }

    [Fact]
    public void RedactPatterns()
    {
        Assert.Equal("password=***", Diag.Redact("password=hunter22"));
        Assert.Equal("password: \"***\" next", Diag.Redact("password: \"correct horse battery\" next"));
        Assert.Equal("secret='***'", Diag.Redact("secret='correct horse battery'"));
        Assert.Equal("token = \"***\"", Diag.Redact("token = \"unterminated value here"));
        Assert.Equal("{\"password\":\"***\",\"user\":\"x\"}", Diag.Redact("{\"password\":\"a b\\\" c\",\"user\":\"x\"}"));
        Assert.Equal("\"pwd\": \"***\"", Diag.Redact("\"pwd\": \"hunter22\""));
        Assert.Equal("Authorization: Bearer ***", Diag.Redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc"));
        Assert.Equal("Negotiate ***", Diag.Redact("Negotiate YIIGwQYGKwYBBQUCoIIGtTCC"));
        Assert.Equal("no secrets here", Diag.Redact("no secrets here"));
        Diag.RegisterSecret("ab");                       // too short to be registered
        Assert.Equal("ab", Diag.Redact("ab"));
    }

    [Fact]
    public void ReportGroupsTheSameProblemAcrossHosts()
    {
        using var f = new DiagFolder();
        foreach (var host in new[] { "pc1", "pc2", "pc3" })
            L.LogWarning("Collect {Host} failed: {Error}", host, "access denied");
        L.LogError("Something else");
        var text = Diag.Report();
        Assert.Contains("4 record(s) in 2 distinct problem(s)", text);
        Assert.Contains("WARNING x3", text);
        Assert.Contains("ERROR x1", text);
        Assert.True(text.IndexOf("ERROR x1", StringComparison.Ordinal) < text.IndexOf("WARNING x3", StringComparison.Ordinal));
        Assert.Contains("3 different messages", text);
        Diag.Clear();
        Assert.Contains("No warnings or errors recorded.", Diag.Report());
    }

    [Fact]
    public void ReportWhenNotInstalled()
    {
        Diag.Uninstall();
        Assert.Contains("not active", Diag.Report());
        Assert.False(Diag.ReadLog(Diag.LogFile).Exists);
        Diag.SetDebug(true);                             // a no-op before Install
        Assert.False(Diag.DebugEnabled);
    }

    [Fact]
    public void LedgerStaysBounded()
    {
        using var f = new DiagFolder();
        Diag.MaxLedgerBytes = 2000;
        for (var i = 0; i < 200; i++)
            L.LogWarning("entry {N} with some padding to grow the file quickly", i);
        Assert.True(new FileInfo(f.File(Diag.LedgerFile)).Length < 6000);
        Assert.StartsWith("entry 199", (string?)f.Ledger()[^1]["message"]);
    }

    [Fact]
    public void MainLogIsRotated()
    {
        using var f = new DiagFolder(debug: false);
        try
        {
            Diag.MainMaxBytes = 4000;
            for (var i = 0; i < 2000; i++)
                if (L.IsEnabled(LogLevel.Information)) L.LogInformation("line {N} with some padding to grow the file quickly", i);
            Assert.True(new FileInfo(f.File(Diag.LogFile)).Length <= 4200);
            Assert.True(System.IO.File.Exists(f.File(Diag.LogFile + ".1")));
            Assert.False(System.IO.File.Exists(f.File(Diag.LogFile + "." + (Diag.MainBackups + 1))));   // bounded on disk
            Assert.Contains("line 1999", Read(f.File(Diag.LogFile)));
        }
        finally
        {
            Diag.MainMaxBytes = 10 * 1024 * 1024;
        }
    }

    [Fact]
    public void FrameworkDebugStaysOut()
    {
        using var f = new DiagFolder();
        var framework = Diag.Provider!.CreateLogger("Microsoft.AspNetCore.Hosting");
        framework.LogInformation("framework chatter");
        framework.LogWarning("framework warning");
        Assert.DoesNotContain("framework chatter", Read(f.File(Diag.DebugFile)));
        Assert.Contains(f.Ledger(), r => (string?)r["message"] == "framework warning");
    }

    [Fact]
    public void DebugLogSwitchAndLogReader()
    {
        using var f = new DiagFolder(debug: false);
        L.LogDebug("hidden detail one");
        L.LogInformation("visible info one");
        Assert.True(!File.Exists(f.File(Diag.DebugFile)) || !Read(f.File(Diag.DebugFile)).Contains("hidden detail one"));
        Diag.SetDebug(true);
        Assert.True(Diag.DebugEnabled);
        L.LogDebug("detail two password=hunter22");
        L.LogWarning("a warning");
        var dbg = Diag.ReadLog(Diag.DebugFile);
        Assert.True(dbg.Exists);
        Assert.Contains("detail two", dbg.Text);
        Assert.DoesNotContain("hunter22", dbg.Text);
        Assert.Contains("visible info one", Diag.ReadLog(Diag.LogFile).Text);
        Assert.Contains("a warning", Diag.ReadLog(Diag.LedgerFile).Text);
        Diag.SetDebug(false);
        L.LogDebug("detail three");
        Assert.DoesNotContain("detail three", Diag.ReadLog(Diag.DebugFile).Text);
        Assert.Throws<ArgumentException>(() => Diag.ReadLog("../../etc/passwd"));
        // the logger still has admiral.log open: share it as the logger does (Windows refuses anything else)
        using (var fs = new FileStream(f.File(Diag.LogFile), FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            fs.Write(System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("x\n", 400_000))));
        var big = Diag.ReadLog(Diag.LogFile, maxBytes: 1000);
        Assert.True(big.Truncated);
        Assert.True(big.Text.Length <= 1000);
    }

    [Fact]
    public void InstallTwiceIsHarmless()
    {
        using var f = new DiagFolder();
        Assert.Equal(f.Path, Diag.Install(f.Path));
        L.LogWarning("once");
        Assert.Single(f.Ledger());
    }

    [Fact]
    public void LogDirMovesOldLogFiles()
    {
        using var tmp = new CoreTemp();
        File.WriteAllText(tmp.File(Diag.LogFile), "old main");
        File.WriteAllText(tmp.File($"{Diag.DebugFile}.1"), "old rotated");
        File.WriteAllText(tmp.File("admiral.db"), "db");
        var logs = Diag.LogDirFor(tmp.Path);
        Assert.Equal(Path.Combine(tmp.Path, Diag.LogDir), logs);
        Assert.Equal("old main", File.ReadAllText(Path.Combine(logs, Diag.LogFile)));
        Assert.True(File.Exists(Path.Combine(logs, $"{Diag.DebugFile}.1")));
        Assert.False(File.Exists(tmp.File(Diag.LogFile)));
        Assert.True(File.Exists(tmp.File("admiral.db")));                    // only log files move
        File.WriteAllText(tmp.File(Diag.LogFile), "newer");
        Diag.LogDirFor(tmp.Path);                                            // never overwrites what is already there
        Assert.Equal("old main", File.ReadAllText(Path.Combine(logs, Diag.LogFile)));
    }

    [Fact]
    public void JobFailuresReachTheLedger()
    {
        using var f = new DiagFolder();
        var jm = new JobManager();
        jm.Start("collect", "c", _ => throw new InvalidOperationException("kaboom password=s3cr3t"), background: false);
        var row = Assert.Single(f.Ledger());
        Assert.Equal("ERROR", (string?)row["level"]);
        Assert.Equal("InvalidOperationException", (string?)row["exception"]);
        Assert.DoesNotContain("s3cr3t", Read(f.File(Diag.LedgerFile)));
    }
}
