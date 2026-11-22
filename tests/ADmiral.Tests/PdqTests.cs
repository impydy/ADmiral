using System.ComponentModel;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>test_pdq.py: the SMB/service orchestration, the self-check, the SCM logic, credentials, validation.</summary>
public partial class PdqTests
{
    private static readonly SmbCreds Creds = new("svc", "p", "CORP");

    private static byte[] B64(JsonObject payload) => Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToJsonString())));

    private static readonly byte[] Good = B64(new JsonObject { ["os_caption"] = "Microsoft Windows 11 Pro" });

    /// <summary>A target whose service run leaves <paramref name="output"/> as the .out file.</summary>
    private static FakeTarget Target(byte[]? output = null, string? failAt = null, bool leftover = false, bool locked = false) => new()
    {
        FailAt = failAt, LeftoverService = leftover, Locked = locked,
        OnRun = (t, _) => t.Files[t.Base + ".out"] = output ?? [],
    };

    private static CollectSettings Cfg(int responseTimeout = 300, int cleanupDelay = 10) =>
        new() { ResponseTimeout = responseTimeout, CleanupDelay = cleanupDelay };

    // ------------------------------------------------------------------ combined script is read-only
    [GeneratedRegex(@"\b(Set|New|Remove|Add|Clear|Enable|Disable|Install|Uninstall|Stop|Start|Invoke|Write|Format|Restart)-[A-Za-z]+", RegexOptions.IgnoreCase)]
    private static partial Regex PsWriteShort();

    [Fact]
    public void CombinedScriptIsReadOnlyAndComplete()
    {
        var script = Collector.CombinedScript();
        Assert.Empty(PsWriteShort().Matches(script));
        var cmdlets = CollectorTests.Cmdlets(script);
        Assert.Subset(CollectorTests.AllowedCmdlets, cmdlets);
        Assert.Contains("Win32_OperatingSystem", script);
        Assert.Contains("Uninstall", script);
        Assert.Contains("Win32_Service", script);
    }

    // ------------------------------------------------------------------ orchestration
    [Fact]
    public void HappyPath()
    {
        var output = B64(new JsonObject
        {
            ["os_caption"] = "Microsoft Windows 11 Enterprise", ["memory_bytes"] = 17179869184L,
            ["apps"] = new JsonArray(new JsonObject { ["name"] = "7-Zip" }),
        });
        var be = Target(output);
        var rec = Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend);
        Assert.EndsWith("Windows 11 Enterprise", (string)rec["os_caption"]!);
        Assert.Equal("11", (string?)rec["os_short"]);                  // Normalize ran
        Assert.Equal(16.0, (double)rec["memory_gb"]!);
        Assert.IsType<JsonArray>(rec["apps"]);
        Assert.Single(be.Ran);
        Assert.Contains("powershell", be.Ran[0], StringComparison.OrdinalIgnoreCase);
        Assert.Contains(".out", be.Ran[0]);
        Assert.Single(be.Put);                                         // the script was uploaded
        Assert.Contains("Win32_OperatingSystem", be.Script);
        Assert.Equal(5, be.Deleted.Count);                             // script + output + temp output + stderr + run folder
        Assert.Empty(be.Files);                                        // nothing left
        Assert.Single(be.DirsCreated);                                 // one private run folder ...
        Assert.Empty(be.Dirs);                                         // ... removed afterwards
        Assert.Equal(2, be.Closes);                                    // collection session + self-check session
    }

    [Fact]
    public void UploadedScriptHasBomAndIsTheCombinedScript()
    {
        var be = Target(Good);
        byte[]? uploaded = null;
        be.OnRun = (t, _) =>
        {
            uploaded = t.Files[t.Base + ".ps1"];
            t.Files[t.Base + ".out"] = Good;
        };
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, uploaded![..3]);
        Assert.Equal(Collector.CombinedScript(), Encoding.UTF8.GetString(uploaded[3..]));
    }

    [Fact]
    public void NamesAreRandomAndCommandIsBuiltFromConstantsOnly()
    {
        var a = Target(Good);
        var b = Target(Good);
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), a.Backend);
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), b.Backend);
        Assert.NotEqual(a.RanServices[0], b.RanServices[0]);
        Assert.Matches("^ADmiral_[0-9a-f]{12}$", a.RanServices[0]);
        var tag = a.RanServices[0]["ADmiral_".Length..];
        Assert.Equal(Pdq.CollectCommand(tag), a.Ran[0]);
        Assert.DoesNotContain("pc1", a.Ran[0]);                        // no host name / user data in the command line
        Assert.DoesNotContain("svc", a.Ran[0]);
        Assert.Matches(@"^ADmiral\\([0-9a-f]{12})\\admiral-\1\.ps1$", a.Put[0]);
        Assert.Throws<ArgumentException>(() => Pdq.CollectCommand("x\" & calc"));
    }

    [Fact]
    public void CommandDetachesPowerShell()
    {
        var be = Target(Good);
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend);
        Assert.Contains("start", be.Ran[0], StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/B", be.Ran[0]);                              // survives the SCM's ~30 s kill
        Assert.Contains(" & ren ", be.Ran[0]);                         // .tmp renamed to .out when complete
    }

    [Fact]
    public void RunFailureRaisesAndCleansUp()
    {
        var be = Target(failAt: "run");
        Assert.Throws<CollectError>(() => Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend));
        Assert.Equal(1, be.Closes);                                    // session closed on failure
        Assert.Empty(be.Files);
    }

    [Fact]
    public void NoOutputTimesOut()
    {
        var be = Target([]);                                           // file present but empty
        var ex = Assert.Throws<CollectError>(() => Pdq.Collect("pc1.corp.local", Creds, Cfg(5, 0), be.Backend));
        Assert.Contains("no valid output within 5s", ex.Message);
        Assert.True(be.Elapsed >= TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void RetriesPartialOutput()
    {
        var reads = new Queue<byte[]>([[], Good[..10], Good]);          // empty, half-written, complete
        var be = Target();
        be.ReadOverride = _ => reads.Dequeue();
        var rec = Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend);
        Assert.EndsWith("Windows 11 Pro", (string)rec["os_caption"]!);
    }

    [Fact]
    public void TimeoutErrorReportsRemoteStateAndStderr()
    {
        var be = Target([]);
        be.ReadOverride = p => p.EndsWith(".err", StringComparison.Ordinal) ? "Access is denied"u8.ToArray() : [];
        be.ExistsOverride = p => p.EndsWith(".ps1", StringComparison.Ordinal);
        var ex = Assert.Throws<CollectError>(() => Pdq.Collect("pc1.corp.local", Creds, Cfg(5), be.Backend));
        Assert.Contains("script file present", ex.Message);
        Assert.Contains("output file missing", ex.Message);
        Assert.Contains("Access is denied", ex.Message);
    }

    [Theory]
    [InlineData("pc1 & calc")]
    [InlineData("\\\\evil\\share")]
    [InlineData("pc1\"")]
    [InlineData("")]
    [InlineData("-pc1")]
    [InlineData("a/b")]
    [InlineData("pc%COMSPEC%")]
    public void InvalidHostIsRefusedBeforeAnything(string host)
    {
        var be = Target(Good);
        Assert.Throws<CollectError>(() => Pdq.Collect(host, Creds, Cfg(), be.Backend));
        Assert.Equal(0, be.Connects);
    }

    [Theory]
    [InlineData("pc1", true)]
    [InlineData("pc1.corp.local", true)]
    [InlineData("PC_01.corp.local.", true)]
    [InlineData("10.0.0.5", true)]
    [InlineData("fe80::1", true)]
    [InlineData("pc1..corp", false)]
    [InlineData("pc-.corp", false)]
    [InlineData("pc 1", false)]
    public void HostValidation(string host, bool ok) => Assert.Equal(ok, Remote.IsValidHost(host));

    [Fact]
    public void SharePathsAreRestrictedToOurFiles()
    {
        const string dir = @"ADmiral\0123456789ab";
        Assert.Equal(dir + @"\admiral-0123456789ab.ps1", Remote.ValidateSharePath(dir + @"\admiral-0123456789ab.ps1"));
        Assert.Equal(dir + @"\admiral-0123456789ab-inst.msi", Remote.ValidateSharePath(dir + @"\admiral-0123456789ab-inst.msi"));
        foreach (var bad in new[]
                 {
                     @"Temp\admiral-0123456789ab.ps1", @"ADmiral\0123456789ab\..\..\System32\x.dll", @"System32\config",
                     dir + @"\admiral-0123456789ab.ps1:ads", dir + @"\x.ps1", @"ADmiral\0123456789ab\admiral-ba9876543210.ps1", "",
                 })
            Assert.Throws<ArgumentException>(() => Remote.ValidateSharePath(bad));
        Assert.Equal(dir, Remote.ValidateShareDir(dir));
        foreach (var bad in new[] { "ADmiral", @"ADmiral\..", @"Temp\0123456789ab", dir + @"\x" })
            Assert.Throws<ArgumentException>(() => Remote.ValidateShareDir(bad));
        Assert.Equal(@"C:\Windows\ADmiral\0123456789ab\admiral-0123456789ab.out", Pdq.RemotePath(dir + @"\admiral-0123456789ab.out"));
    }

    [Fact]
    public void RunsInAPrivateRunFolderNotInWindowsTemp()
    {
        var be = Target(Good);
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend);
        var tag = be.RanServices[0]["ADmiral_".Length..];
        Assert.Equal([$@"ADmiral\{tag}"], be.DirsCreated);           // created before the script was copied
        Assert.Contains($@"start """" /D ""C:\Windows\ADmiral\{tag}"" /B", be.Ran[0]);   // working directory = the run folder
        Assert.DoesNotContain(@"\Temp\", be.Ran[0]);
        Assert.Empty(be.Dirs);
        // the self-check removes a run folder that was left behind
        var left = Target(Good);
        left.OnRun = (t, _) => { t.Files[t.Base + ".out"] = Good; t.Locked = true; };
        Pdq.Collect("pc1.corp.local", Creds, Cfg(), left.Backend);
        Assert.Empty(left.Dirs);
    }

    // ------------------------------------------------------------------ self-check
    private static List<CleanupReport> Run(FakeTarget be, CollectSettings? cfg = null)
    {
        var reports = new List<CleanupReport>();
        try
        {
            Pdq.Collect("pc1.corp.local", Creds, cfg ?? Cfg(), be.Backend, reports.Add);
        }
        catch (CollectError)
        {
        }
        return reports;
    }

    [Fact]
    public void SelfCheckCleanComputerNeedsNoAction()
    {
        var be = Target(Good);
        var rep = Assert.Single(Run(be));
        Assert.True(rep.Clean);
        Assert.False(rep.Acted);
        Assert.Equal("absent", rep.Service);
        Assert.Equal(be.RanServices, be.RemovedServices);
        Assert.Empty(be.Killed);
        Assert.Equal(2, be.Connects);                                   // collection + a fresh connection for the check
        Assert.Contains(TimeSpan.FromSeconds(10), be.Sleeps);           // cleanup_delay
    }

    [Fact]
    public void SelfCheckRemovesLeftoverService()
    {
        var rep = Assert.Single(Run(Target(Good, leftover: true)));
        Assert.Equal("removed", rep.Service);
        Assert.True(rep.Acted);
        Assert.True(rep.Clean);
    }

    [Fact]
    public void SelfCheckStopsRunningScriptAndDeletesLockedFile()
    {
        var be = Target(Good, locked: true);                            // the .out file cannot be deleted at first
        var rep = Assert.Single(Run(be));
        Assert.NotEmpty(be.Killed);
        Assert.True(rep.ProcessKilled);
        Assert.True(rep.Acted);
        Assert.Empty(rep.FilesLeft);
        Assert.True(rep.Clean);
        Assert.Empty(be.Files);
        Assert.Matches("^[0-9a-f]{12}$", be.Killed[0]);
        Assert.Equal("ADmiral_" + be.Killed[0], be.RanServices[0]);
    }

    [Fact]
    public void SelfCheckReportsWhatItCouldNotClean()
    {
        var rep = Assert.Single(Run(Target(Good, failAt: "kill", locked: true)));
        Assert.False(rep.Clean);
        Assert.NotEmpty(rep.FilesLeft);
        Assert.Contains(rep.Errors, e => e.Contains("process", StringComparison.Ordinal));
    }

    [Fact]
    public void SelfCheckRunsAfterAFailedCollectionToo()
    {
        var be = Target([], locked: true);                              // never answers
        var rep = Assert.Single(Run(be, Cfg(5, 0)));
        Assert.NotEmpty(be.RemovedServices);
        Assert.True(rep.ProcessKilled);
        Assert.True(rep.Clean);
    }

    [Fact]
    public void SelfCheckSkippedWhenTheServiceDidNotStart()
    {
        var be = Target(Good, failAt: "run");
        Assert.Empty(Run(be));
        Assert.Empty(be.RemovedServices);
        Assert.Equal(1, be.Connects);
        be = Target(Good, failAt: "connect");
        Assert.Empty(Run(be));
        Assert.Empty(be.RemovedServices);
    }

    [Fact]
    public void SelfCheckFailureNeverBreaksTheInventory()
    {
        var be = Target(Good, failAt: "remove_service");
        var reports = new List<CleanupReport>();
        var rec = Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend, reports.Add);
        Assert.EndsWith("Windows 11 Pro", (string)rec["os_caption"]!);
        Assert.Equal("failed", reports[0].Service);
        Assert.False(reports[0].Clean);
    }

    [Fact]
    public void CleanupHandlerExceptionIsSwallowed()
    {
        var be = Target(Good);
        var rec = Pdq.Collect("pc1.corp.local", Creds, Cfg(), be.Backend, _ => throw new InvalidOperationException("handler"));
        Assert.NotNull(rec);
    }

    [Fact]
    public void KillCommandTargetsOnlyThisRun()
    {
        var cmd = Pdq.KillCommand("abc123abc123");
        var enc = cmd[(cmd.LastIndexOf(' ') + 1)..];
        var ps = Encoding.Unicode.GetString(Convert.FromBase64String(enc));
        Assert.Contains("admiral-abc123abc123", ps);
        Assert.Contains("$PID", ps);
        Assert.Contains("Stop-Process", ps);
        Assert.Contains("-EncodedCommand", cmd);
        Assert.DoesNotContain("admiral-abc123abc123", cmd);            // no quoting pitfalls in the binary path
        Assert.Throws<ArgumentException>(() => Pdq.KillCommand("*'; calc"));
    }

    [Fact]
    public void DefaultTimeouts()
    {
        var c = new CollectSettings();
        Assert.Equal(300, c.ResponseTimeout);                           // wait max 5 minutes
        Assert.Equal(10, c.CleanupDelay);
    }

    [Fact]
    public void CleanupReportFlags()
    {
        Assert.True(new CleanupReport("pc1").Clean);
        Assert.False(new CleanupReport("pc1").Acted);
        var r = new CleanupReport("pc1") { Service = "removed", FilesRemoved = [@"Temp\a.out"], ProcessKilled = true };
        Assert.True(r.Acted);
        Assert.True(r.Clean);
        Assert.False(new CleanupReport("pc2") { Service = "failed" }.Clean);
        Assert.False(new CleanupReport("pc2") { Errors = ["service: boom"] }.Clean);
    }

    // ------------------------------------------------------------------ credentials
    [Theory]
    [InlineData("CORP\\svc-admiral", "CORP.LOCAL", "svc-admiral", "CORP")]
    [InlineData("svc-admiral@corp.local", "CORP.LOCAL", "svc-admiral", "CORP")]
    [InlineData("svc-admiral", "CORP.LOCAL", "svc-admiral", "CORP")]
    public void CredsFromLdap(string user, string realm, string expUser, string expDom)
    {
        var ldap = new LdapSettings
        {
            Server = "ldaps://dc01.corp.local", BaseDn = "DC=corp,DC=local", User = user, Password = "secret", Auth = "kerberos",
            NtlmFallback = true,
        };
        var c = Pdq.CredsFromLdap(ldap, realm);
        Assert.Equal(expUser, c.Username);
        Assert.Equal(expDom, c.Domain);
        Assert.Equal("dc01.corp.local", c.Kdc);                        // scheme stripped
        Assert.True(c.UseKerberos);
        Assert.True(c.NtlmFallback);
        Assert.Equal("secret", c.Password);
        Assert.Equal(realm, c.Realm);
    }

    [Fact]
    public void CredsFromLdapSimpleIsNtlm()
    {
        var ldap = new LdapSettings { Server = "dc01", BaseDn = "DC=corp,DC=local", User = "CORP\\a", Auth = "simple" };
        Assert.False(Pdq.CredsFromLdap(ldap, "CORP.LOCAL").UseKerberos);
    }

    [Fact]
    public void KerberosUsesTheDnsRealmNotTheNetbiosName()
    {
        var c = new SmbCreds("svc", "pw", "CONTOSO", "contoso.local");
        Assert.Equal("CONTOSO.LOCAL", c.KerberosRealm);
        Assert.Equal("CONTOSO\\svc", c.Account);                        // NTLM / WNet still use the NetBIOS name
    }

    [Fact]
    public void CredsNeverPrintThePassword()
    {
        var c = new SmbCreds("svc", "s3cret-pw", "CORP");
        Assert.DoesNotContain("s3cret-pw", c.ToString());
        Assert.Contains("svc", c.ToString());
    }

    // ------------------------------------------------------------------ the SCM logic of the real backend
    private sealed class FakeScm(int startCode = 1053, int deleteError = 0, bool exists = true, bool running = true,
                                 bool deleteRemoves = true, int openError = 0) : IScmApi
    {
        public List<string> Calls { get; } = [];
        public string? Binary { get; private set; }
        private bool _exists = exists;

        public nint OpenManager(string host)
        {
            Calls.Add("manager");
            return 1;
        }

        public nint CreateService(nint scm, string name, string display, string binaryPath)
        {
            Calls.Add("create");
            Binary = binaryPath;
            return 2;
        }

        public int Start(nint service)
        {
            Calls.Add("start");
            return startCode;
        }

        public nint OpenService(nint scm, string name, out int error)
        {
            Calls.Add("open");
            if (openError != 0)
            {
                error = openError;
                return 0;
            }
            error = _exists ? 0 : ScmServiceControl.ErrorServiceDoesNotExist;
            return _exists ? 3 : 0;
        }

        public int QueryState(nint service) => running ? 4 : 1;

        public int Stop(nint service)
        {
            Calls.Add("stop");
            return 0;
        }

        public int Delete(nint service)
        {
            Calls.Add("delete");
            if (deleteError != 0) return deleteError;
            if (deleteRemoves) _exists = false;
            return 0;
        }

        public void Close(nint handle) => Calls.Add("close");
    }

    [Theory]
    [InlineData(1053)]
    [InlineData(1067)]
    [InlineData(0)]
    public void RunCommandCountsScmTimeoutAsStarted(int code)
    {
        var fake = new FakeScm(startCode: code);
        new ScmServiceControl(fake).RunCommand("pc1", Creds, "cmd", "ADmiral_0123456789ab");
        Assert.Equal(["manager", "create", "start", "delete"], fake.Calls.Take(4));
        Assert.Equal(2, fake.Calls.Count(c => c == "close"));          // service and manager handles
        Assert.Equal("cmd", fake.Binary);
    }

    [Fact]
    public void RunCommandRaisesWhenTheServiceCannotStartButStillDeletesIt()
    {
        var fake = new FakeScm(startCode: 2);                           // file not found: the process never ran
        var ex = Assert.Throws<CollectError>(() => new ScmServiceControl(fake).RunCommand("pc1", Creds, "cmd", "ADmiral_0123456789ab"));
        Assert.Contains("did not start", ex.Message);
        Assert.Contains("delete", fake.Calls);
    }

    [Fact]
    public void RunCommandLeavesAFailedDeleteToTheSelfCheck() =>
        new ScmServiceControl(new FakeScm(deleteError: 5)).RunCommand("pc1", Creds, "cmd", "ADmiral_0123456789ab");   // no exception

    [Fact]
    public void RunCommandRefusesForeignServiceNamesAndHosts()
    {
        var scm = new ScmServiceControl(new FakeScm());
        Assert.Throws<ArgumentException>(() => scm.RunCommand("pc1", Creds, "cmd", "Spooler"));
        Assert.Throws<CollectError>(() => scm.RunCommand("pc1 x", Creds, "cmd", "ADmiral_0123456789ab"));
    }

    [Fact]
    public void RemoveServiceAbsent() =>
        Assert.Equal("absent", new ScmServiceControl(new FakeScm(exists: false)).RemoveService("pc1", Creds, "ADmiral_0123456789ab"));

    [Fact]
    public void RemoveServiceStopsAndDeletesALeftover()
    {
        var fake = new FakeScm(exists: true, running: true);
        Assert.Equal("removed", new ScmServiceControl(fake).RemoveService("pc1", Creds, "ADmiral_0123456789ab"));
        Assert.Contains("stop", fake.Calls);
        Assert.Contains("delete", fake.Calls);
    }

    [Fact]
    public void RemoveServiceMarkedForDeleteCountsAsRemoved()
    {
        var fake = new FakeScm(deleteError: ScmServiceControl.ErrorServiceMarkedForDelete, deleteRemoves: false);
        // still openable afterwards => it stays: loud failure
        Assert.Throws<CollectError>(() => new ScmServiceControl(fake).RemoveService("pc1", Creds, "ADmiral_0123456789ab"));
    }

    [Fact]
    public void RemoveServiceFailsLoudlyIfItStays()
    {
        var fake = new FakeScm(exists: true, running: false, deleteRemoves: false);
        var ex = Assert.Throws<CollectError>(() => new ScmServiceControl(fake).RemoveService("pc1", Creds, "ADmiral_0123456789ab"));
        Assert.Contains("still present", ex.Message);
    }

    [Fact]
    public void RemoveServiceAccessDeniedRaises() =>
        Assert.Throws<Win32Exception>(() => new ScmServiceControl(new FakeScm(openError: 5)).RemoveService("pc1", Creds, "ADmiral_0123456789ab"));

    [Fact]
    public void KillScriptRunsAShortLivedServiceWithTheKillCommand()
    {
        var fake = new FakeScm();
        new ScmServiceControl(fake).KillScript("pc1", Creds, "0123456789ab");
        Assert.Equal(Pdq.KillCommand("0123456789ab"), fake.Binary);
    }

    [Fact]
    public void ScmUsesTheConnectHookAndClosesIt()
    {
        var opened = new List<string>();
        var closed = 0;
        var scm = new ScmServiceControl(new FakeScm(), (h, c) =>
        {
            opened.Add(h);
            return new Disposer(() => closed++);
        });
        scm.RunCommand("pc1.corp.local", Creds, "cmd", "ADmiral_0123456789ab");
        scm.RemoveService("pc1.corp.local", Creds, "ADmiral_0123456789ab");
        Assert.Equal(["pc1.corp.local", "pc1.corp.local"], opened);
        Assert.Equal(2, closed);
    }

    private sealed class Disposer(Action a) : IDisposable
    {
        public void Dispose() => a();
    }

    [Fact]
    public void DefaultBackendNeedsWindows()
    {
        if (OperatingSystem.IsWindows()) return;
        var ex = Assert.Throws<CollectError>(() => Pdq.Collect("pc1.corp.local", Creds, Cfg()));
        Assert.Contains("Windows", ex.Message);
    }
}
