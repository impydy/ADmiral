using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>Collector parts of test_inventory.py / test_readonly.py / test_powershell.py (the WinRM error paths, with a
/// fake PowerShell runner instead of pywinrm) plus the process runner and the stdin-only credential handling.</summary>
public partial class CollectorTests
{
    // ------------------------------------------------------------------ the inventory scripts only read
    [GeneratedRegex(@"\b(Set|New|Remove|Add|Clear|Enable|Disable|Install|Uninstall|Register|Unregister|Restart|Stop|" +
                    @"Start|Suspend|Resume|Rename|Move|Copy|Reset|Update|Invoke|Write|Out|Export|Import|Push|Send|" +
                    @"Grant|Revoke|Block|Unblock|Lock|Unlock|Mount|Dismount|Format|Initialize|Repair|Restore|Backup|" +
                    @"Checkpoint|Complete|Confirm|Deny|Approve|Protect|Unprotect|Publish|Unpublish|Save|Sync|Edit|" +
                    @"Join|Undo|Use|Submit|Wait|Debug|Connect|Disconnect)-[A-Za-z]+", RegexOptions.IgnoreCase)]
    private static partial Regex PsWrite();

    [GeneratedRegex(@"(/add\b|/delete\b|\breg(\.exe)?\s+(add|delete|import)|\bsc(\.exe)?\s+(config|create|delete|stop|start)|" +
                    @"\bshutdown\b|\bnetsh\b|\bwmic\b|\bicacls\b|\btakeown\b|\bbcdedit\b|\bschtasks\b|" +
                    @"\bInvokeMethod\b|\.Invoke\(|\.Delete\(|\.Put\(|\.SetValue\(|\.Create\(|\.Terminate\(|" +
                    @"\bStartService\b|\bStopService\b|\bChangeStartMode\b|>\s*[A-Za-z\\$])", RegexOptions.IgnoreCase)]
    private static partial Regex PsDangerous();

    [GeneratedRegex(@"\b[A-Z][a-z]+-[A-Z][A-Za-z]+\b")]
    private static partial Regex Cmdlet();

    internal static readonly HashSet<string> AllowedCmdlets =
    [
        "get-ciminstance", "get-winevent", "get-itemproperty", "get-service", "get-smbserverconfiguration",
        "get-localgroupmember", "get-localgroup", "get-bitlockervolume", "test-path", "select-object", "where-object", "sort-object", "foreach-object",
        "measure-object", "convertto-json", "new-object",
    ];

    internal static HashSet<string> Cmdlets(string script) => [.. Cmdlet().Matches(script).Select(m => m.Value.ToLowerInvariant())];

    public static TheoryData<string> Sections() => [.. Collector.SectionNames];

    [Theory]
    [MemberData(nameof(Sections))]
    public void InventoryScriptsOnlyRead(string section) => AssertReadOnly(Collector.Script(section));

    [Fact]
    public void CombinedScriptOnlyReads() => AssertReadOnly(Collector.CombinedScript());

    private static void AssertReadOnly(string script)
    {
        Assert.Empty(PsWrite().Matches(script));
        Assert.False(PsDangerous().IsMatch(script), PsDangerous().Match(script).Value);
        Assert.Subset(AllowedCmdlets, Cmdlets(script));
    }

    [Fact]
    public void ScriptsHaveTheWrapperAndAreAscii()
    {
        foreach (var s in Collector.SectionNames)
        {
            var script = Collector.Script(s);
            Assert.StartsWith("\n$ErrorActionPreference = 'SilentlyContinue'", script);
            Assert.EndsWith("[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))\n", script);
            Assert.DoesNotContain("{body}", script);
            Assert.All(script, c => Assert.True(c < 128));
        }
        Assert.Contains("$r.logons = @(Get-WinEvent", Collector.CombinedScript());
        Assert.Contains("$r.user_accounts = ", Collector.CombinedScript());
        Assert.Contains("$r.local_groups = $lg", Collector.CombinedScript());
        Assert.Contains("$r.monitors = @(Get-CimInstance -Namespace root\\wmi WmiMonitorID", Collector.CombinedScript());
        Assert.Contains("Win32_UserAccount -Filter 'LocalAccount=True'", Collector.CombinedScript());   // never enumerates the domain
        Assert.Contains("$r.os_caption = $os.Caption", Collector.CombinedScript());
        Assert.Throws<ArgumentException>(() => Collector.Script("nope"));
    }

    // ------------------------------------------------------------------ decode / normalize
    [Fact]
    public void OsShortAndDecode()
    {
        Assert.Equal("2012 R2", Collector.OsShort("Microsoft Windows Server 2012 R2 Standard"));
        Assert.Equal("11", Collector.OsShort("Microsoft Windows 11 Pro"));
        Assert.Null(Collector.OsShort("Linux"));
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(new JsonObject { ["name"] = "Kovács Ágnes" }.ToJsonString()));
        Assert.Equal("Kovács Ágnes", (string?)Collector.DecodeOutput(Encoding.ASCII.GetBytes($"noise\r\n{payload}\r\n"))["name"]);
        var n = Collector.Normalize(new JsonObject
        {
            ["disks"] = new JsonObject { ["drive"] = "C:" }, ["chassis_type"] = 10, ["memory_bytes"] = 17179869184L,
        });
        Assert.Equal("C:", (string?)((JsonArray)n["disks"]!)[0]!["drive"]);
        Assert.Equal("Notebook", (string?)n["chassis"]);
        Assert.Equal(16.0, (double)n["memory_gb"]!);
        Assert.False(n.ContainsKey("chassis_type"));
        Assert.False(n.ContainsKey("memory_bytes"));
    }

    [Fact]
    public void NormalizeEdgeCases()
    {
        var n = Collector.Normalize(new JsonObject
        {
            ["chassis_type"] = "99", ["apps"] = null, ["os_caption"] = "Microsoft Windows Server 2022 Standard",
            ["logons"] = new JsonArray(
                new JsonObject { ["time"] = "2026-01-01T08:00:00Z", ["user"] = "anna", ["domain"] = "CORP", ["type"] = 2 },
                new JsonObject { ["time"] = "2026-01-01T08:00:01Z", ["user"] = "DWM-1", ["domain"] = "Window Manager", ["type"] = 2 }),
        });
        Assert.Equal("Type 99", (string?)n["chassis"]);
        Assert.Null(n["apps"]);
        Assert.Equal("2022", (string?)n["os_short"]);
        Assert.Single((JsonArray)n["logons"]!);
        Assert.False(Collector.Normalize(new JsonObject { ["chassis_type"] = "x" }).ContainsKey("chassis"));
    }

    [Fact]
    public void DecodeRejectsGarbage()
    {
        Assert.Throws<CollectError>(() => Collector.DecodeOutput("garbage"u8.ToArray()));
        Assert.Throws<CollectError>(() => Collector.DecodeOutput([]));
        Assert.Throws<CollectError>(() => Collector.DecodeOutput(Encoding.ASCII.GetBytes(Convert.ToBase64String("[1,2]"u8.ToArray()))));
        Assert.Throws<CollectError>(() => Collector.DecodeOutput(Encoding.ASCII.GetBytes(Convert.ToBase64String([0xC3, 0x28]))));
        var deep = new string('[', 100) + new string(']', 100);
        Assert.Throws<CollectError>(() => Collector.DecodeOutput(Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(deep)))));
    }

    [Fact]
    public void LogScriptErrorsRemovesTheList()
    {
        var rec = new JsonObject { ["a"] = 1, ["ps_errors"] = new JsonArray("x: No events were found", "y: boom") };
        Collector.LogScriptErrors("pc", "general", rec);
        Assert.False(rec.ContainsKey("ps_errors"));
        Assert.Equal(1, (int)rec["a"]!);
    }

    // ------------------------------------------------------------------ WinRM through a fake runner
    internal static string Ok(JsonObject obj) => Convert.ToBase64String(Encoding.UTF8.GetBytes(obj.ToJsonString()));

    private sealed class FakeRunner : IPowerShellRunner
    {
        public List<JsonObject> Requests { get; } = [];
        public List<string> RawStdin { get; } = [];
        public Func<JsonObject, int, JsonObject?> Respond { get; set; } = (_, _) => null;
        public int ExitCode { get; set; }
        public string Stderr { get; set; } = "";
        public byte[]? RawStdout { get; set; }

        public PowerShellResult Run(string stdin, TimeSpan timeout, long maxOutputBytes)
        {
            RawStdin.Add(stdin);
            var req = (JsonObject)JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(stdin)))!;
            Requests.Add(req);
            Assert.True(timeout > TimeSpan.FromSeconds(30));
            Assert.Equal(Collector.MaxOutputBytes, maxOutputBytes);
            if (RawStdout is { } raw) return new PowerShellResult(ExitCode, raw, Stderr);
            var resp = Respond(req, Requests.Count);
            return new PowerShellResult(ExitCode, resp is null ? [] : Encoding.ASCII.GetBytes("banner\r\n" + Ok(resp) + "\r\n"), Stderr);
        }
    }

    private static JsonObject Resp(params (string Name, string Out, string Error)[] parts)
    {
        var s = new JsonObject();
        foreach (var (name, o, e) in parts) s[name] = new JsonObject { ["out"] = o, ["error"] = e };
        return new JsonObject { ["open_error"] = null, ["open_code"] = 0, ["sections"] = s };
    }

    private static JsonObject OpenError(string message, int code = 0) =>
        new() { ["open_error"] = message, ["open_code"] = code, ["sections"] = new JsonObject() };

    [Fact]
    public void WinrmHappyPathSendsEverythingThroughStdin()
    {
        var runner = new FakeRunner
        {
            Respond = (_, _) => Resp(
                ("general", Ok(new JsonObject { ["model"] = "Latitude 7440", ["os_caption"] = "Microsoft Windows 11 Pro", ["ps_errors"] = new JsonArray() }), ""),
                ("hardware", Ok(new JsonObject { ["disks"] = new JsonObject { ["drive"] = "C:" } }), ""),
                ("apps", Ok(new JsonObject { ["apps"] = new JsonArray(new JsonObject { ["name"] = "7-Zip" }) }), ""),
                ("services", Ok(new JsonObject { ["services"] = new JsonArray(), ["local_admins"] = new JsonArray() }), ""),
                ("logons", Ok(new JsonObject { ["logons"] = new JsonArray() }), "")),
        };
        var cfg = new WinRMSettings { User = "CORP\\svc", Password = "pw'; Remove-Item C:\\ -Recurse #", Transport = "ntlm" };
        var inv = Collector.WinrmCollect("pc01.contoso.local", cfg, runner: runner);
        Assert.Equal("Latitude 7440", (string?)inv["model"]);
        Assert.Equal("11", (string?)inv["os_short"]);
        Assert.Single((JsonArray)inv["disks"]!);
        Assert.False(inv.ContainsKey("section_errors"));
        var req = Assert.Single(runner.Requests);
        Assert.Equal("pc01.contoso.local", (string?)req["host"]);
        Assert.Equal(5985, (int)req["port"]!);
        Assert.Equal("Negotiate", (string?)req["auth"]);
        Assert.Equal("CORP\\svc", (string?)req["user"]);
        Assert.Equal(cfg.Password, (string?)req["password"]);         // the password travels as data, verbatim
        Assert.Equal(Collector.Driver, (string?)req["driver"]);
        Assert.Equal(Collector.SectionNames, ((JsonArray)req["order"]!).Select(x => (string)x!));
        foreach (var s in Collector.SectionNames) Assert.Equal(Collector.Script(s), (string?)req["sections"]![s]);
        Assert.Matches("^[A-Za-z0-9+/=]+$", runner.RawStdin[0]);       // ASCII-only stdin, independent of code pages
    }

    [Fact]
    public void LoaderArgumentsAreConstantAndCarryNoData()
    {
        var args = Collector.LoaderArguments();
        Assert.Equal(args, Collector.LoaderArguments());
        var enc = args[^1];
        Assert.Equal("-EncodedCommand", args[^2]);
        var loader = Encoding.Unicode.GetString(Convert.FromBase64String(enc));
        Assert.Equal(Collector.Loader, loader);
        Assert.Contains("[Console]::In.ReadToEnd()", loader);
        Assert.Contains("-NonInteractive", args);
        Assert.Contains("-NoProfile", args);
    }

    [Fact]
    public void DriverTakesEveryInputFromTheRequestObject()
    {
        // nothing in the driver is a placeholder to splice data into
        Assert.DoesNotContain("@@", Collector.Driver);
        Assert.DoesNotContain("{0}", Collector.Driver);
        Assert.Contains("ConvertTo-SecureString -String ([string]$r.password)", Collector.Driver);
        Assert.Contains("$r.password = $null", Collector.Driver);
        Assert.Contains("ComputerName = [string]$r.host", Collector.Driver);
        Assert.Contains("Remove-PSSession", Collector.Driver);
        Assert.Contains("$Error.Clear()", Collector.Driver);           // one section's errors are not the next one's
    }

    [Fact]
    public void WinrmKerberosMapsThePrincipalAndNeedsTheFqdn()
    {
        var runner = new FakeRunner { Respond = (_, _) => Resp(("general", Ok(new JsonObject { ["model"] = "X" }), "")) };
        var cfg = new WinRMSettings { User = "CORP\\svc", Password = "pw", Transport = "kerberos", UseHttps = true };
        Collector.WinrmCollect("pc1.corp.local", cfg, "CORP.LOCAL", runner);
        Assert.Equal("svc@CORP.LOCAL", (string?)runner.Requests[0]["user"]);
        Assert.Equal("Kerberos", (string?)runner.Requests[0]["auth"]);
        Assert.Equal(5986, (int)runner.Requests[0]["port"]!);
        // an IP address cannot work with Kerberos, and without the fallback that is a clear error before anything runs
        var r2 = new FakeRunner();
        var ex = Assert.Throws<CollectError>(() => Collector.WinrmCollect("10.0.0.5", cfg, runner: r2));
        Assert.Contains("FQDN", ex.Message);
        Assert.Empty(r2.Requests);
    }

    [Fact]
    public void WinrmCurrentLogonSessionSendsNoPassword()
    {
        var runner = new FakeRunner { Respond = (_, _) => Resp(("general", Ok(new JsonObject { ["model"] = "X" }), "")) };
        Collector.WinrmCollect("pc1.corp.local", new WinRMSettings { User = "", Password = "stale", Transport = "kerberos" }, runner: runner);
        Assert.Equal("", (string?)runner.Requests[0]["user"]);
        Assert.Equal("", (string?)runner.Requests[0]["password"]);
    }

    [Fact]
    public void WinrmAuthFailure()
    {
        var runner = new FakeRunner { Respond = (_, _) => OpenError("PSRemotingTransportException: Access is denied.", 5) };
        var ex = Assert.Throws<Collector.WinRMOpenError>(() =>
            Collector.WinrmCollect("pc", new WinRMSettings { User = "u", Password = "p", Transport = "ntlm" }, runner: runner));
        Assert.Contains("Access is denied", ex.Message);
        Assert.Equal(Collector.WinRMFailure.Auth, ex.Kind);
    }

    [Fact]
    public void WinrmPartialAndTotalFailure()
    {
        var cfg = new WinRMSettings { User = "u", Password = "p", Transport = "ntlm", UseHttps = true, VerifyCert = false };
        var runner = new FakeRunner
        {
            Respond = (_, _) => Resp(
                ("general", Ok(new JsonObject { ["model"] = "X" }), ""),
                ("hardware", "", "RemoteException: Hozzáférés megtagadva"),
                ("apps", Ok(new JsonObject { ["apps"] = new JsonArray() }), ""),
                ("services", "garbage", ""),
                ("logons", Ok(new JsonObject { ["logons"] = new JsonArray() }), "")),
        };
        var inv = Collector.WinrmCollect("pc", cfg, runner: runner);
        Assert.Equal("X", (string?)inv["model"]);
        Assert.Empty((JsonArray)inv["apps"]!);
        var errs = (JsonObject)inv["section_errors"]!;
        Assert.Equal(["hardware", "services"], errs.Select(kv => kv.Key).Order());
        Assert.Contains("Hozzáférés megtagadva", (string?)errs["hardware"]);
        Assert.False(runner.Requests[0]["verify_cert"]!.GetValue<bool>());

        var all = new FakeRunner
        {
            Respond = (_, _) => Resp([.. Collector.SectionNames.Select(s => (s, "", "denied"))]),
        };
        var ex = Assert.Throws<CollectError>(() => Collector.WinrmCollect("pc", cfg, runner: all));
        Assert.Contains("denied", ex.Message);
    }

    [Fact]
    public void WinrmProcessFailureReportsStderr()
    {
        var runner = new FakeRunner { RawStdout = [], ExitCode = 1, Stderr = "powershell.exe: something broke" };
        var ex = Assert.Throws<CollectError>(() =>
            Collector.WinrmCollect("pc", new WinRMSettings { User = "u", Password = "p", Transport = "ntlm" }, runner: runner));
        Assert.Contains("exit 1", ex.Message);
        Assert.Contains("something broke", ex.Message);
    }

    [Fact]
    public void KerberosAuthFailureFallsBackToNtlmWhenAllowed()
    {
        var runner = new FakeRunner
        {
            Respond = (req, n) => (string?)req["auth"] == "Kerberos"
                ? OpenError("PSRemotingTransportException: WinRM cannot process the request. Kerberos authentication error 0x80090322", unchecked((int)0x80090322))
                : Resp(("general", Ok(new JsonObject { ["model"] = "NTLM" }), "")),
        };
        var cfg = new WinRMSettings { User = "CORP\\svc", Password = "pw", Transport = "kerberos", NtlmFallback = true };
        var inv = Collector.WinrmCollect("pc1.corp.local", cfg, runner: runner);
        Assert.Equal("NTLM", (string?)inv["model"]);
        Assert.Equal(["Kerberos", "Negotiate"], runner.Requests.Select(r => (string)r["auth"]!));
        Assert.Equal("CORP\\svc", (string?)runner.Requests[1]["user"]);
    }

    [Fact]
    public void NoFallbackAfterANetworkErrorOrWhenOff()
    {
        var net = new FakeRunner { Respond = (_, _) => OpenError("PSRemotingTransportException: WinRM cannot complete the operation ... timed out", unchecked((int)0x80338126)) };
        var cfg = new WinRMSettings { User = "CORP\\svc", Password = "pw", Transport = "kerberos", NtlmFallback = true };
        Assert.Throws<Collector.WinRMOpenError>(() => Collector.WinrmCollect("pc1.corp.local", cfg, runner: net));
        Assert.Single(net.Requests);

        var auth = new FakeRunner { Respond = (_, _) => OpenError("Access is denied", 5) };
        cfg.NtlmFallback = false;
        Assert.Throws<Collector.WinRMOpenError>(() => Collector.WinrmCollect("pc1.corp.local", cfg, runner: auth));
        Assert.Single(auth.Requests);
    }

    [Fact]
    public void BothFailuresAreReported()
    {
        var runner = new FakeRunner { Respond = (_, _) => OpenError("Access is denied", 5) };
        var cfg = new WinRMSettings { User = "CORP\\svc", Password = "pw", Transport = "kerberos", NtlmFallback = true };
        var ex = Assert.Throws<CollectError>(() => Collector.WinrmCollect("pc1.corp.local", cfg, runner: runner));
        Assert.Contains("Kerberos:", ex.Message);
        Assert.Contains("NTLMv2 fallback:", ex.Message);
        Assert.Equal(2, runner.Requests.Count);
    }

    [Theory]
    [InlineData(5, "", Collector.WinRMFailure.Auth)]
    [InlineData(1326, "", Collector.WinRMFailure.Auth)]
    [InlineData(53, "", Collector.WinRMFailure.Network)]
    [InlineData(unchecked((int)0x80338012), "", Collector.WinRMFailure.Network)]
    [InlineData(0, "The WinRM client cannot process the request. Kerberos authentication cannot be used", Collector.WinRMFailure.Auth)]
    [InlineData(0, "The operation timed out", Collector.WinRMFailure.Network)]
    [InlineData(0, "something else", Collector.WinRMFailure.Other)]
    public void ClassifyWinRMErrors(int code, string message, Collector.WinRMFailure expected) =>
        Assert.Equal(expected, Collector.ClassifyWinRMError(code, message));

    [Fact]
    public void InvalidHostOrTransportIsRefused()
    {
        var runner = new FakeRunner();
        Assert.Throws<CollectError>(() => Collector.WinrmCollect("pc1;calc", new WinRMSettings { Transport = "ntlm" }, runner: runner));
        Assert.Throws<CollectError>(() => Collector.WinrmCollect("pc1", new WinRMSettings { Transport = "weird" }, runner: runner));
        Assert.Empty(runner.Requests);
        Assert.Equal("Basic", Collector.PsAuthentication("basic"));
        Assert.Equal("Credssp", Collector.PsAuthentication("credssp"));
    }

    [Fact]
    public void DefaultRunnerNeedsWindows()
    {
        if (OperatingSystem.IsWindows()) return;
        var ex = Assert.Throws<CollectError>(() => Collector.WinrmCollect("pc1", new WinRMSettings { Transport = "ntlm" }));
        Assert.Contains("Windows", ex.Message);
    }

    // ------------------------------------------------------------------ the real process runner (with /bin/sh)
    private static bool HasSh => !OperatingSystem.IsWindows() && File.Exists("/bin/sh");

    [Fact]
    public void ProcessRunnerPassesStdinAndCapturesOutput()
    {
        if (!HasSh) return;
        var r = new PowerShellProcessRunner("/bin/sh", ["-c", "cat; echo err >&2; exit 3"]);
        var res = r.Run("secret-from-stdin", TimeSpan.FromSeconds(20), 1024);
        Assert.Equal(3, res.ExitCode);
        Assert.Equal("secret-from-stdin", Encoding.UTF8.GetString(res.Stdout));
        Assert.Contains("err", res.Stderr);
    }

    [Fact]
    public void ProcessRunnerEnforcesTheTimeout()
    {
        if (!HasSh) return;
        var r = new PowerShellProcessRunner("/bin/sh", ["-c", "sleep 30"]);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ex = Assert.Throws<CollectError>(() => r.Run(new string('x', 4_000_000), TimeSpan.FromMilliseconds(300), 1024));   // never reads stdin
        Assert.Contains("did not finish", ex.Message);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20));
    }

    [Fact]
    public void ProcessRunnerEnforcesTheOutputCap()
    {
        if (!HasSh) return;
        var r = new PowerShellProcessRunner("/bin/sh", ["-c", "head -c 200000 /dev/zero"]);
        var ex = Assert.Throws<CollectError>(() => r.Run("", TimeSpan.FromSeconds(20), 1000));
        Assert.Contains("more than 1000 bytes", ex.Message);
    }

    [Fact]
    public void ProcessRunnerReportsAMissingExecutable()
    {
        var r = new PowerShellProcessRunner("/nonexistent/powershell.exe", []);
        Assert.Throws<CollectError>(() => r.Run("", TimeSpan.FromSeconds(5), 1000));
    }
}
