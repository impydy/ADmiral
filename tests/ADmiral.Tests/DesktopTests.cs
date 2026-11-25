using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

// Port of tests/test_desktop.py + tests/test_desktop_launcher.py (the parts that are not WinForms / WebView2) and the
// winservice parts of tests/test_service.py, against src/ADmiral.Core/DesktopLogic.cs.

public sealed class DesktopDataDirTests
{
    private static DesktopEnv Env(string? exeDir, Dictionary<string, string> vars, bool windows, string userHome = "/home/u") =>
        new(exeDir, n => vars.GetValueOrDefault(n), windows, userHome);

    [Fact]
    public void DataDirRules()
    {
        using var tmp = new CoreTemp();
        var vars = new Dictionary<string, string> { ["ADMIRAL_HOME"] = tmp.File("h") };
        Assert.Equal(tmp.File("h"), DesktopLogic.DataDir(Env(null, vars, windows: true)));
        vars.Clear();
        vars["APPDATA"] = tmp.File("roaming");
        Assert.Equal(Path.Combine(tmp.File("roaming"), "ADmiral"), DesktopLogic.DataDir(Env(null, vars, windows: true)));
        vars.Clear();
        Assert.Equal(Path.Combine("/home/u", "AppData", "Roaming", "ADmiral"), DesktopLogic.DataDir(Env(null, vars, windows: true)));
        vars["XDG_CONFIG_HOME"] = tmp.File("xdg");
        Assert.Equal(Path.Combine(tmp.File("xdg"), "admiral"), DesktopLogic.DataDir(Env(null, vars, windows: false)));
        vars.Clear();
        Assert.Equal(Path.Combine("/home/u", ".config", "admiral"), DesktopLogic.DataDir(Env(null, vars, windows: false)));
        // portable: admiral.toml next to the exe wins (even over ADMIRAL_HOME)
        var exeDir = tmp.File("portable");
        Directory.CreateDirectory(exeDir);
        File.WriteAllText(Path.Combine(exeDir, "admiral.toml"), "");
        vars["ADMIRAL_HOME"] = tmp.File("h");
        Assert.Equal(exeDir, DesktopLogic.DataDir(Env(exeDir, vars, windows: true)));
    }

    [Fact]
    public void DataDirChosenInInstaller()
    {
        using var tmp = new CoreTemp();
        var app = Path.Combine(tmp.Path, "Program Files", "ADmiral");
        Directory.CreateDirectory(app);
        var vars = new Dictionary<string, string> { ["APPDATA"] = tmp.File("roaming") };
        var env = Env(app, vars, windows: true);
        var roaming = Path.Combine(tmp.File("roaming"), "ADmiral");
        Assert.Equal(roaming, DesktopLogic.DataDir(env));                                // no pointer -> per-user default
        var target = Path.Combine(tmp.Path, "Közös adatok", "ADmiral");
        // Inno Setup writes UTF-8 with a BOM; accented folder names must survive
        File.WriteAllBytes(Path.Combine(app, DesktopLogic.DataPointer), [.. new byte[] { 0xEF, 0xBB, 0xBF }, .. Encoding.UTF8.GetBytes(target + "\r\n")]);
        Assert.Equal(target, DesktopLogic.DataDir(env));
        vars["ADMIRAL_DATA_TEST"] = tmp.File("env");
        File.WriteAllText(Path.Combine(app, DesktopLogic.DataPointer), "$ADMIRAL_DATA_TEST/x");   // $VAR works on every OS
        Assert.Equal(tmp.File("env") + "/x", DesktopLogic.DataDir(env));
        File.WriteAllText(Path.Combine(app, DesktopLogic.DataPointer), "%ADMIRAL_DATA_TEST%\\y");  // and %VAR% on Windows
        Assert.Equal(tmp.File("env") + "\\y", DesktopLogic.DataDir(env));
        File.WriteAllText(Path.Combine(app, DesktopLogic.DataPointer), "  \n");
        Assert.Equal(roaming, DesktopLogic.DataDir(env));                                // empty pointer ignored
        File.WriteAllText(Path.Combine(app, DesktopLogic.DataPointer), target);
        vars["ADMIRAL_HOME"] = tmp.File("h");
        Assert.Equal(tmp.File("h"), DesktopLogic.DataDir(env));                          // env var beats the pointer
    }

    [Fact]
    public void ExpandVarsLeavesUnknownVariables()
    {
        string? Get(string n) => n == "A" ? "1" : null;
        Assert.Equal("1/1/$B/%A%", DesktopLogic.ExpandVars("$A/${A}/$B/%A%", Get, windows: false));
        Assert.Equal("1/%B%", DesktopLogic.ExpandVars("%A%/%B%", Get, windows: true));
    }

    [Fact]
    public void WebViewProfileIsPerUser()
    {
        var vars = new Dictionary<string, string> { ["LOCALAPPDATA"] = @"C:\Users\x\AppData\Local" };
        Assert.Equal(Path.Combine(@"C:\Users\x\AppData\Local", "ADmiral", "webview"), DesktopLogic.WebViewDir("/data", Env(null, vars, true)));
        Assert.Equal(Path.Combine("/data", "webview"), DesktopLogic.WebViewDir("/data", Env(null, vars, false)));
    }

    private sealed class FakeAcl(params IReadOnlyList<string>[] answers) : IFileSecurity
    {
        private int _calls;
        public bool HardenOk { get; init; } = true;
        public bool Throws { get; init; }
        public int Hardened { get; private set; }
        public bool Supported => true;

        public IReadOnlyList<string> BroadWriters(string path)
        {
            if (Throws) throw new UnauthorizedAccessException("no ACL");
            return answers[Math.Min(_calls++, answers.Length - 1)];
        }

        public bool HardenDir(string path, IEnumerable<string>? extraSids = null)
        {
            Hardened++;
            return HardenOk;
        }

        public (string Sid, string Name) Owner(string path) => ("", "");
        public string CurrentUserSid() => "S-1-5-21-1-2-3-1000";
    }

    /// <summary>A folder with a real owner + DACL that <see cref="HardenDir"/> replaces by the intended one.</summary>
    private sealed class FakeDacl(PathSecurity initial) : IFileSecurity
    {
        public const string Me = "S-1-5-21-1-2-3-1000";
        public PathSecurity Current { get; private set; } = initial;
        public bool HardenWorks { get; init; } = true;
        public List<string> HardenedWith { get; } = [];
        public bool Supported => true;
        public IReadOnlyList<string> BroadWriters(string path) => WinSec.BroadWritersFromAces(Current.Aces);
        public PathSecurity? ReadSecurity(string path) => Current;
        public string? ResolveSid(string account) => account == @"CORP\ADmiral-Admins" ? "S-1-5-21-1-2-3-5000" : WinSec.SidText(account);
        public (string Sid, string Name) Owner(string path) => (Current.OwnerSid, "");
        public string CurrentUserSid() => Me;

        public bool HardenDir(string path, IEnumerable<string>? extraSids = null)
        {
            HardenedWith.AddRange(extraSids ?? []);
            if (!HardenWorks) return true;                              // "succeeds" but changes nothing
            Current = new PathSecurity(WinSec.AdminsSid, [.. WinSec.HardenGrants(Me, extraSids).Select(g => Ace(g.Sid, g.Rights == "RX" ? 0x1200a9 : 0x1301bf))]);
            return true;
        }
    }

    private static AceInfo Ace(string sid, int mask = 0x1f01ff, byte flags = 0x3, byte type = 0) => new(type, flags, mask, sid);

    private static PathSecurity Installed(params AceInfo[] extra) => new(WinSec.AdminsSid,
        [Ace(WinSec.SystemSid), Ace(WinSec.AdminsSid), Ace(WinSec.OwnerRightsSid, 0x1200a9), Ace(FakeDacl.Me, 0x1301bf), .. extra]);

    [Fact]
    public void SecureDataDirRefusesForeignWritersAndOwners()
    {
        // what the installer leaves: fine, nothing changed
        var ok = new FakeDacl(Installed());
        Assert.Null(DesktopLogic.SecureDataDir("/d", ok));
        Assert.Empty(ok.HardenedWith);
        // a pre-planted folder: the attacker's own FullControl entry survived "icacls /grant:r" -> restricted again
        const string attacker = "S-1-5-21-1-2-3-1666";
        var planted = new FakeDacl(Installed(Ace(attacker)));
        Assert.Null(DesktopLogic.SecureDataDir("/d", planted));
        Assert.DoesNotContain(planted.Current.Aces!, a => a.Sid == attacker);
        // an inherit-only write entry counts too (it applies to every file ADmiral creates later)
        Assert.Equal([attacker], WinSec.UnexpectedAccess(Installed(Ace(attacker, 0x2, 0xB)), FakeDacl.Me, []));
        // the attacker as owner (can rewrite the DACL any time)
        Assert.Equal([$"owner {attacker}"], WinSec.UnexpectedAccess(Installed() with { OwnerSid = attacker }, FakeDacl.Me, []));
        // read-only entries and deny entries are fine
        Assert.Empty(WinSec.UnexpectedAccess(Installed(Ace(attacker, 0x1200a9), Ace(attacker, 0x1f01ff, 0x3, 1)), FakeDacl.Me, []));
        // the installer's /DATAUSER= group and the service account are expected; hardening keeps them
        const string svc = "S-1-5-21-1-2-3-2000";
        var withUsers = new FakeDacl(Installed(Ace("S-1-5-21-1-2-3-5000", 0x1301bf), Ace(svc, 0x1301bf), Ace(attacker)));
        Assert.Null(DesktopLogic.SecureDataDir("/d", withUsers, [@"CORP\ADmiral-Admins", "*" + svc]));
        Assert.Equal(["S-1-5-21-1-2-3-5000", svc], withUsers.HardenedWith);
        Assert.Contains(withUsers.Current.Aces!, a => a.Sid == svc);
        // hardening that does not stick: refused with the bilingual text naming the SID
        var stuck = new FakeDacl(Installed(Ace(attacker)) with { OwnerSid = attacker }) { HardenWorks = false };
        var problem = DesktopLogic.SecureDataDir("/d", stuck);
        Assert.NotNull(problem);
        Assert.Contains(attacker, problem);
        Assert.Contains("nem tudta korlátozni", problem);
    }

    [Fact]
    public void DataUsersFileIsReadFromTheProgramFolder()
    {
        var dir = Directory.CreateTempSubdirectory("admiral-du-").FullName;
        try
        {
            Assert.Empty(DesktopLogic.DataUsers(dir));
            File.WriteAllText(Path.Combine(dir, DesktopLogic.DataUsersFile), "\uFEFFCORP\\jdoe\r\n# comment\r\n*S-1-5-21-1-2-3-5000\r\ncorp\\JDOE\r\n\r\n");
            Assert.Equal([@"CORP\jdoe", "*S-1-5-21-1-2-3-5000"], DesktopLogic.DataUsers(dir));
            Assert.True(DesktopLogic.AddDataUser(dir, "CORP\\svc-admiral\""));
            Assert.True(DesktopLogic.AddDataUser(dir, @"corp\svc-admiral"));          // no duplicates
            Assert.Equal([@"CORP\jdoe", "*S-1-5-21-1-2-3-5000", @"CORP\svc-admiral"], DesktopLogic.DataUsers(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void PortableSettingsOnlyFromAFolderNoUserCanChange()
    {
        var dir = Directory.CreateTempSubdirectory("admiral-port-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "admiral.toml"), "");
            var vars = new Dictionary<string, string>();
            var safe = Env(dir, vars, false) with { Security = new FakeAcl([]) };
            Assert.Equal(dir, DesktopLogic.DataDir(safe));
            var broad = Env(dir, vars, false) with { Security = new FakeAcl(["Users"]) };
            Assert.NotEqual(dir, DesktopLogic.DataDir(broad));                  // the planted admiral.toml is ignored
            var problem = DesktopLogic.ProgramDirProblem(dir, new FakeAcl(["Authenticated Users"]));
            Assert.Contains("Authenticated Users", problem);
            Assert.Null(DesktopLogic.ProgramDirProblem(dir, new FakeAcl([])));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void SecureDataDirRefusesAFolderEveryUserCanChange()
    {
        var fine = new FakeAcl([]);
        Assert.Null(DesktopLogic.SecureDataDir("/d", fine));
        Assert.Equal(0, fine.Hardened);

        var fixable = new FakeAcl(["Users"], []);                  // first run: restricted, then safe
        Assert.Null(DesktopLogic.SecureDataDir("/d", fixable));
        Assert.Equal(1, fixable.Hardened);

        var stuck = new FakeAcl(["Everyone", "Users"]) { HardenOk = false };
        var problem = DesktopLogic.SecureDataDir("/d", stuck);
        Assert.NotNull(problem);
        Assert.Contains("Everyone, Users", problem);
        Assert.Contains("could not restrict", problem);
        Assert.Contains("nem tudta korlátozni", problem);

        var stillBroad = new FakeAcl(["Users"]);                    // "hardened" but an entry survived
        Assert.NotNull(DesktopLogic.SecureDataDir("/d", stillBroad));

        // an unreadable ACL (network folder, old Windows) does not block the start
        Assert.Null(DesktopLogic.SecureDataDir("/d", new FakeAcl([]) { Throws = true }));
    }

    [Fact]
    public void BuildCreatesConfigAndRespectsExisting()
    {
        using var tmp = new CoreTemp();
        using (var a = DesktopLogic.BuildService(tmp.Path, applyProcessSettings: false))
        {
            Assert.True(File.Exists(tmp.File("admiral.toml")));
            Assert.Equal(tmp.File("admiral.db"), a.Settings.DbPath);
            Assert.Equal("ldap", a.Settings.Mode);                     // a release starts without demo data
            Assert.Equal(tmp.File("admiral.toml"), a.ConfigPath);
        }
        File.WriteAllText(tmp.File("admiral.toml"), "mode = \"demo\"\ndb_path = \"other.db\"\ntheme = \"dark\"\n");
        using var b = DesktopLogic.BuildService(tmp.Path, applyProcessSettings: false);
        Assert.Equal(tmp.File("other.db"), b.Settings.DbPath);
        Assert.Equal("dark", b.Settings.Theme);
    }

    [Fact]
    public void TokenIsRandomPerLaunch()
    {
        var t1 = DesktopLogic.NewToken();
        var t2 = DesktopLogic.NewToken();
        Assert.Equal(43, t1.Length);                                   // 32 bytes, base64url without padding
        Assert.NotEqual(t1, t2);
        Assert.Matches("^[A-Za-z0-9_-]+$", t1);
    }

    [Fact]
    public void ParseArgs()
    {
        Assert.Equal(new DesktopArgs(), DesktopLogic.ParseArgs([]));
        var a = DesktopLogic.ParseArgs(["--retry-service", "--home", @"D:\ADmiral data"]);
        Assert.True(a.RetryService);
        Assert.Equal(@"D:\ADmiral data", a.Home);
        Assert.True(DesktopLogic.ParseArgs(["--self-test"]).SelfTest);
        Assert.True(DesktopLogic.ParseArgs(["--ui-test", "whatever"]).UiTest);     // unknown arguments ignored
        Assert.True(DesktopLogic.ParseArgs(["--debug"]).Debug);
        Assert.Equal("x", DesktopLogic.ParseArgs(["--home=x"]).Home);
        Assert.Throws<ArgumentException>(() => DesktopLogic.ParseArgs(["--home"]));
        Assert.Throws<ArgumentException>(() => DesktopLogic.ParseArgs(["--home", "--self-test"]));
        Assert.True(DesktopLogic.ParseArgs(["--elevated"]).Elevated);
    }

    [Fact]
    public void WindowAlwaysRunsElevated()
    {
        DesktopArgs P(params string[] a) => DesktopLogic.ParseArgs(a);
        Assert.Equal(DesktopLogic.Elevation.Run, DesktopLogic.ElevationNeeded(P(), isElevated: true));
        Assert.Equal(DesktopLogic.Elevation.Restart, DesktopLogic.ElevationNeeded(P(), isElevated: false));
        Assert.Equal(DesktopLogic.Elevation.Restart, DesktopLogic.ElevationNeeded(P("--debug"), isElevated: false));
        // the elevated restart that is still not elevated (UAC off, standard user): refuse instead of looping
        Assert.Equal(DesktopLogic.Elevation.Refuse, DesktopLogic.ElevationNeeded(P("--elevated"), isElevated: false));
        // the service (its account was granted the data folder) and the CI checks never restart
        Assert.Equal(DesktopLogic.Elevation.Run, DesktopLogic.ElevationNeeded(P("--retry-service"), isElevated: false));
        Assert.Equal(DesktopLogic.Elevation.Run, DesktopLogic.ElevationNeeded(P("--self-test"), isElevated: false));
        Assert.Equal(DesktopLogic.Elevation.Run, DesktopLogic.ElevationNeeded(P("--ui-test"), isElevated: false));

        Assert.Equal(new[] { "--home", @"D:\x y", "--elevated" }, DesktopLogic.ElevatedArgs(["--home", @"D:\x y"]));
        Assert.Equal(new[] { "--elevated" }, DesktopLogic.ElevatedArgs(["--elevated"]));
        var text = DesktopLogic.NeedAdminText();
        Assert.Contains("rendszergazda", text);
        Assert.Contains("administrator", text);
    }

    [Fact]
    public void StartupFailureExplainsWebView2()
    {
        var text = DesktopLogic.StartupFailureText(new InvalidOperationException("WebView2 runtime missing"), "/d");
        Assert.Contains("WebView2 Runtime", text);
        Assert.Contains("admiral.log", text);
        var other = DesktopLogic.StartupFailureText(new IOException("disk full"), "/d");
        Assert.DoesNotContain("WebView2", other);
        Assert.Contains("disk full", other);
    }
}

public sealed class DesktopNavigationTests
{
    [Fact]
    public void OpenUrlOnlyOpensTheProjectsOwnLinks()
    {
        foreach (var ok in new[] { "https://tidecrestlabs.com/", "https://discord.gg/E6ZDEnqSmY", "https://ko-fi.com/tidecrestlabs",
                                   "https://github.com/impydy/ADmiral/issues/new?title=Log%20package", "https://WWW.TideCrestLabs.com/x" })
        {
            Assert.True(DesktopLogic.IsAllowedExternalUrl(ok, out var u), ok);
            Assert.Equal("https", u!.Scheme);
        }
        foreach (var bad in new[] { "http://tidecrestlabs.com/", "https://evil.example/", "file:///C:/Windows/System32/cmd.exe",
                                    "https://tidecrestlabs.com.evil.example/", "javascript:alert(1)", "https://github.com/evil/repo",
                                    "https://github.com/impydy/ADmiral-fake/issues", "http://github.com/impydy/ADmiral/issues",
                                    "https://tidecrestlabs.com:8443/", "https://user@tidecrestlabs.com/", "", "   ",
                                    "\\\\server\\share\\x.exe", "C:\\Windows\\notepad.exe", "ms-settings:", "https://ko-fi.com.\u0000x/" })
            Assert.False(DesktopLogic.IsAllowedExternalUrl(bad, out _), bad);
    }

    [Fact]
    public void NavigationOnlyWithinTheLocalOrigin()
    {
        var origin = new Uri("http://127.0.0.1:51234");
        Assert.True(DesktopLogic.IsLocalOrigin("http://127.0.0.1:51234/?token=x", origin));
        Assert.True(DesktopLogic.IsLocalOrigin("http://127.0.0.1:51234/static/app.js", origin));
        Assert.True(DesktopLogic.IsLocalOrigin("about:blank", origin));
        foreach (var bad in new[] { "http://127.0.0.1:51235/", "https://127.0.0.1:51234/", "http://localhost:51234/", "http://evil.example/",
                                    "http://user@127.0.0.1:51234/", "file:///C:/", "data:text/html,x", "", "javascript:alert(1)" })
            Assert.False(DesktopLogic.IsLocalOrigin(bad, origin), bad);
        Assert.True(DesktopLogic.IsLocalDownload("blob:http://127.0.0.1:51234/0d9f", origin));
        Assert.True(DesktopLogic.IsLocalDownload("http://127.0.0.1:51234/api/x.csv", origin));
        Assert.False(DesktopLogic.IsLocalDownload("blob:https://evil.example/1", origin));
        Assert.False(DesktopLogic.IsLocalDownload("https://evil.example/x.exe", origin));
    }

    [Fact]
    public void InjectedNavigationsNeverLeaveTheLocalOriginNorStartTheBrowser()
    {
        var origin = new Uri("http://127.0.0.1:51234");
        const DesktopLogic.NavigationAction allow = DesktopLogic.NavigationAction.Allow, refuse = DesktopLogic.NavigationAction.Refuse;
        // own pages, main frame or frame
        Assert.Equal(allow, DesktopLogic.DecideNavigation("http://127.0.0.1:51234/?token=x", origin, false, true));
        Assert.Equal(allow, DesktopLogic.DecideNavigation("http://127.0.0.1:51234/static/x", origin, false, false));
        Assert.Equal(allow, DesktopLogic.DecideNavigation("about:blank", origin, false, false));
        // an injected <meta http-equiv=refresh> / script / frame (not user initiated): refused, even to ADmiral's own links
        foreach (var url in new[] { "https://evil.example/", "http://127.0.0.1:51235/", "http://localhost:51234/", "data:text/html,x",
                                    "javascript:alert(1)", "file:///C:/", "https://tidecrestlabs.com/", "https://github.com/impydy/ADmiral/issues", "" })
        {
            Assert.Equal(refuse, DesktopLogic.DecideNavigation(url, origin, false, true));
            Assert.Equal(refuse, DesktopLogic.DecideNavigation(url, origin, false, false));
            Assert.Equal(refuse, DesktopLogic.DecideNavigation(url, origin, true, false));      // a frame never opens the browser
        }
        Assert.Equal(refuse, DesktopLogic.DecideNavigation("about:blank", origin, false, true));  // the app is never blanked
        Assert.Equal(refuse, DesktopLogic.DecideNavigation("https://evil.example/", origin, true, true));
        // a click on one of ADmiral's own links: cancelled in the window, opened in the browser
        Assert.Equal(DesktopLogic.NavigationAction.OpenExternal, DesktopLogic.DecideNavigation("https://tidecrestlabs.com/", origin, true, true));
    }

    [Fact]
    public void BridgeScriptDefinesThePywebviewApiForTheLocalOriginOnly()
    {
        var js = DesktopLogic.BridgeScript(new Uri("http://127.0.0.1:51234/"));
        Assert.Contains("\"http://127.0.0.1:51234\"", js);
        Assert.Contains("pywebview", js);
        Assert.Contains("window.top !== window", js);
        foreach (var m in DesktopLogic.BridgeMethods) Assert.Contains($"\"{m}\"", js);
    }
}

public sealed class DesktopBridgeTests
{
    private sealed class FakeShell(string? picked) : IDesktopShell
    {
        public string? Picked { get; set; } = picked;
        public string? Suggested { get; private set; }
        public List<string> Folders { get; } = [];
        public List<Uri> Urls { get; } = [];
        public bool Quitted { get; private set; }

        public string? PickSaveFile(string suggestedName)
        {
            Suggested = suggestedName;
            return Picked;
        }

        public void OpenFolder(string path) => Folders.Add(path);
        public void OpenUrl(Uri url) => Urls.Add(url);
        public void Quit() => Quitted = true;
        public List<string> Themes { get; } = [];
        public void SetTheme(string theme) => Themes.Add(theme);
    }

    [Fact]
    public void SetThemeRepaintsTheTitleBar()
    {
        using var tmp = new CoreTemp();
        var shell = new FakeShell(null);
        var b = new DesktopBridge(shell, tmp.Path);
        Assert.True(JsonNode.Parse(b.Handle("""{"id": 1, "method": "set_theme", "args": ["dark"]}"""))!["ok"]!.GetValue<bool>());
        Assert.True(JsonNode.Parse(b.Handle("""{"id": 2, "method": "set_theme", "args": ["system"]}"""))!["ok"]!.GetValue<bool>());
        Assert.False(JsonNode.Parse(b.Handle("""{"id": 3, "method": "set_theme", "args": ["pink"]}"""))!["ok"]!.GetValue<bool>());
        Assert.Equal(["dark", "system"], shell.Themes);

        Assert.True(DesktopLogic.TitleBarDark("dark", windowsDark: false));
        Assert.False(DesktopLogic.TitleBarDark("light", windowsDark: true));
        Assert.True(DesktopLogic.TitleBarDark("system", windowsDark: true));
        Assert.False(DesktopLogic.TitleBarDark("system", windowsDark: false));
        Assert.True(DesktopLogic.TitleBarDark(null, windowsDark: true));
        Assert.Equal((0x2B2B2B, 0xE8E8E8), DesktopLogic.TitleBarColors(dark: true));
        Assert.Equal((0xFFFFFF, 0x1B1B1B), DesktopLogic.TitleBarColors(dark: false));
    }

    [Fact]
    public void SaveFileAndQuit()
    {
        using var tmp = new CoreTemp();
        var target = tmp.File("out.txt");
        var shell = new FakeShell(target);
        var b = new DesktopBridge(shell, tmp.Path);
        Assert.Equal(target, b.SaveFile("x.txt", "ő\r\nű"));
        Assert.Equal(Encoding.UTF8.GetBytes("ő\r\nű"), File.ReadAllBytes(target));     // newlines kept as given, no BOM
        Assert.Equal("x.txt", shell.Suggested);
        Assert.Equal(target, b.SaveBinary("t.xlsx", Convert.ToBase64String([1, 2, 3])));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(target));
        Assert.Throws<ArgumentException>(() => b.SaveBinary("t.xlsx", "not base64!"));
        b.SaveFile(@"..\..\Windows\evil.txt", "a");
        Assert.Equal("evil.txt", shell.Suggested);                                     // no folder part in the proposal
        shell.Picked = null;                                                            // cancelled
        Assert.Null(b.SaveFile("x.txt", "a"));
        Assert.Null(b.SaveBinary("x.bin", "AA=="));
        b.Call("quit", _ => "");
        Assert.True(shell.Quitted);
    }

    [Fact]
    public void HandleSpeaksThePromiseProtocol()
    {
        using var tmp = new CoreTemp();
        var shell = new FakeShell(tmp.File("a.csv"));
        var b = new DesktopBridge(shell, tmp.Path);
        var ok = JsonNode.Parse(b.Handle("""{"id": 7, "method": "save_file", "args": ["a.csv", "x;y"]}"""))!;
        Assert.Equal(7, ok["id"]!.GetValue<long>());
        Assert.True(ok["ok"]!.GetValue<bool>());
        Assert.Equal(tmp.File("a.csv"), ok["result"]!.GetValue<string>());
        var bad = JsonNode.Parse(b.Handle("""{"id": 8, "method": "__proto__", "args": []}"""))!;
        Assert.False(bad["ok"]!.GetValue<bool>());
        Assert.Contains("unknown bridge method", bad["error"]!.GetValue<string>());
        var refused = JsonNode.Parse(b.Handle("""{"id": 9, "method": "open_url", "args": ["https://evil.example/"]}"""))!;
        Assert.Equal("this link is not allowed", refused["error"]!.GetValue<string>());
        Assert.Empty(shell.Urls);
        Assert.False(JsonNode.Parse(b.Handle("not json"))!["ok"]!.GetValue<bool>());
        Assert.False(JsonNode.Parse(b.Handle("""{"method": "quit"}"""))!["ok"]!.GetValue<bool>());     // no id
        Assert.False(shell.Quitted);
        var cancelled = JsonNode.Parse(b.Handle("""{"id": 10, "method": "save_file", "args": [1, 2]}"""))!;   // non-string args
        Assert.True(cancelled["ok"]!.GetValue<bool>());
    }

    [Fact]
    public void ExposesExactlyThePythonBridgeMethods()
    {
        Assert.Equal(["computer_management", "event_viewer", "open_data_folder", "open_logs_folder", "open_url", "quit", "remote_assist", "save_binary", "save_file", "save_log_package", "set_theme"],
                     DesktopLogic.BridgeMethods.Order(StringComparer.Ordinal));
        using var tmp = new CoreTemp();
        var b = new DesktopBridge(new FakeShell(null), tmp.Path, remoteAssist: _ => { }, logFolder: () => tmp.Path);
        foreach (var m in DesktopLogic.BridgeMethods.Where(m => m != "quit"))
        {
            try { b.Call(m, _ => ""); }
            catch (ArgumentException exc) { Assert.DoesNotContain("unknown bridge method", exc.Message); }
            catch (InvalidOperationException) { }
        }
    }

    [Fact]
    public void OpenUrlOpensOnlyAllowedLinks()
    {
        using var tmp = new CoreTemp();
        var shell = new FakeShell(null);
        var b = new DesktopBridge(shell, tmp.Path);
        b.OpenUrl("https://github.com/impydy/ADmiral/issues/new?title=Log%20package");
        Assert.Throws<ArgumentException>(() => b.OpenUrl("https://github.com/impydy/ADmiral-fake/issues"));
        Assert.Single(shell.Urls);
        b.Call("open_data_folder", _ => "");
        Assert.Equal([tmp.Path], shell.Folders);
    }

    [Fact]
    public void OpenLogsFolderAcceptsOnlyAPackageId()
    {
        using var tmp = new CoreTemp();
        var shell = new FakeShell(null);
        var b = new DesktopBridge(shell, tmp.Path, logFolder: () => tmp.Path);
        b.OpenLogsFolder("");
        Assert.Equal([tmp.Path], shell.Folders);
        b.OpenLogsFolder("ADM-AB12-CD34");                                  // a package that does not exist: nothing opened
        Assert.Single(shell.Folders);
        Directory.CreateDirectory(Path.Combine(tmp.Path, LogReport.OutDir, "ADM-AB12-CD34"));
        b.OpenLogsFolder("ADM-AB12-CD34");
        Assert.Equal(Path.Combine(tmp.Path, LogReport.OutDir, "ADM-AB12-CD34"), shell.Folders[^1]);
        foreach (var bad in new[] { "..", "../../Windows", "ADM-AB12-CD34\\..\\..", "C:\\Windows", "adm-ab12-cd34x", "ADM-AB12-CD34\n" })
            Assert.Throws<ArgumentException>(() => b.OpenLogsFolder(bad));
        Assert.Equal(Path.Combine(tmp.Path, "logs"), DesktopLogic.LogsFolder(null, tmp.Path, ""));
    }

    [Fact]
    public void SaveLogPackageWritesAZipOfThePackageOnly()
    {
        using var tmp = new CoreTemp();
        var pkg = Path.Combine(tmp.Path, LogReport.OutDir, "ADM-AB12-CD34");
        Directory.CreateDirectory(pkg);
        File.WriteAllText(Path.Combine(pkg, "README.txt"), "hello");
        File.WriteAllText(Path.Combine(pkg, "admiral.log"), "log");
        var target = tmp.File("out.zip");
        var b = new DesktopBridge(new FakeShell(target), tmp.Path, logFolder: () => tmp.Path);
        Assert.Equal(target, b.SaveLogPackage("ADM-AB12-CD34"));
        using (var zip = System.IO.Compression.ZipFile.OpenRead(target))
            Assert.Equal(["README.txt", "admiral.log"], zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal));
        Assert.Throws<InvalidOperationException>(() => b.SaveLogPackage("ADM-ZZ12-CD34"));            // no such package
        foreach (var bad in new[] { "", "..", "ADM-AB12-CD34\\..", "C:\\Windows" })
            Assert.Throws<ArgumentException>(() => b.SaveLogPackage(bad));
        Assert.Null(new DesktopBridge(new FakeShell(null), tmp.Path, logFolder: () => tmp.Path).SaveLogPackage("ADM-AB12-CD34"));   // cancelled
    }

    [Fact]
    public void RemoteAssistGoesThroughTheValidatedCommand()
    {
        using var tmp = new CoreTemp();
        var started = new List<string>();
        var b = new DesktopBridge(new FakeShell(null), tmp.Path,
                                  remoteAssist: h => started.Add(string.Join(" ", AdmiralService.RemoteAssistStartInfo(h).ArgumentList)));
        b.Call("remote_assist", _ => " pc01.corp.local ");
        Assert.Equal(["/offerra pc01.corp.local"], started);
        foreach (var bad in new[] { "", "a b", "pc; calc", "pc&calc", "-x", "pc|1", "$(x)", new string('a', 300) })
            Assert.Throws<ArgumentException>(() => b.Call("remote_assist", _ => bad));
        Assert.Throws<InvalidOperationException>(() => new DesktopBridge(new FakeShell(null), tmp.Path).Call("remote_assist", _ => "pc01"));
    }

    [Fact]
    public void EventViewerGoesThroughTheValidatedCommand()
    {
        using var tmp = new CoreTemp();
        var started = new List<string>();
        var b = new DesktopBridge(new FakeShell(null), tmp.Path, eventViewer: h => started.Add(string.Join(" ", AdmiralService.EventViewerStartInfo(h).ArgumentList)));
        b.Call("event_viewer", _ => " pc01.corp.local ");
        Assert.Equal(["pc01.corp.local"], started);
        foreach (var bad in new[] { "", "a b", "pc; calc", "/s", "-x", "pc|1", new string('a', 300) })
            Assert.Throws<ArgumentException>(() => b.Call("event_viewer", _ => bad));
        Assert.Throws<InvalidOperationException>(() => new DesktopBridge(new FakeShell(null), tmp.Path).Call("event_viewer", _ => "pc01"));
    }

    [Fact]
    public void ComputerManagementGoesThroughTheValidatedCommand()
    {
        using var tmp = new CoreTemp();
        var started = new List<string>();
        var b = new DesktopBridge(new FakeShell(null), tmp.Path,
                                  computerManagement: h => started.Add(AdmiralService.ComputerManagementStartInfo(h).ArgumentList[1]));
        b.Call("computer_management", _ => " pc01.corp.local ");
        Assert.Equal(["/computer=pc01.corp.local"], started);
        foreach (var bad in new[] { "", "a b", "pc; calc", "/s", "-x", "pc|1", new string('a', 300) })
            Assert.Throws<ArgumentException>(() => b.Call("computer_management", _ => bad));
        Assert.Throws<InvalidOperationException>(() => new DesktopBridge(new FakeShell(null), tmp.Path).Call("computer_management", _ => "pc01"));
    }
}

public sealed class DesktopChecksTests
{
    [Fact]
    public void UiProbeResult()
    {
        // ExecuteScriptAsync returns the JSON encoding of the returned string
        static string Wrap(string inner) => System.Text.Json.JsonSerializer.Serialize(inner);
        Assert.Equal((true, true), DesktopChecks.UiProbeResult(Wrap("""{"title":"ADmiral","toolbar_items":8,"tree_nodes":9,"bridge":true,"error":""}""")));
        Assert.Equal((false, false), DesktopChecks.UiProbeResult(Wrap("""{"title":"ADmiral","toolbar_items":0,"tree_nodes":0,"bridge":false}""")));
        Assert.Equal((true, false), DesktopChecks.UiProbeResult(Wrap("""{"title":"ADmiral","toolbar_items":8,"tree_nodes":9,"bridge":true,"error":"LDAP failed"}""")));
        Assert.Equal((true, false), DesktopChecks.UiProbeResult(Wrap("""{"title":"Other","toolbar_items":8,"tree_nodes":9,"bridge":true,"error":""}""")));
        Assert.Equal((false, false), DesktopChecks.UiProbeResult("null"));
        Assert.Equal((false, false), DesktopChecks.UiProbeResult("{broken"));
        Assert.Contains("pywebview", DesktopChecks.UiProbe);
    }

    [Fact]
    public async Task SelfTestHttpChecks()
    {
        const string token = "tok";
        HttpResponseMessage Answer(HttpRequestMessage r)
        {
            var good = r.Headers.TryGetValues("X-ADmiral-Token", out var v) && v.Single() == token;
            var path = r.RequestUri!.AbsolutePath;
            if (path == "/api/status") return good ? FakeHttp.Json("""{"desktop": true}""") : FakeHttp.Status(HttpStatusCode.Unauthorized);
            if (path == "/") return FakeHttp.Json("<title>ADmiral</title>");
            return path.StartsWith("/static/", StringComparison.Ordinal) ? FakeHttp.Json("x") : FakeHttp.Status(HttpStatusCode.NotFound);
        }
        using var fake = new FakeHttp(Answer);
        using var http = fake.Client();
        var checks = await DesktopChecks.HttpChecksAsync(http, new Uri("http://127.0.0.1:1/"), token);
        Assert.Equal(["api status", "token enforced", "ui bundled"], checks.Select(c => c.Name));
        Assert.All(checks, c => Assert.True(c.Ok, c.Name));

        using var open = new FakeHttp(_ => FakeHttp.Json("""{"desktop": true}"""));           // a server without the token check
        using var http2 = open.Client();
        var bad = await DesktopChecks.HttpChecksAsync(http2, new Uri("http://127.0.0.1:1/"), token);
        Assert.False(bad.Single(c => c.Name == "token enforced").Ok);
    }
}

public sealed class WinServiceLogicTests
{
    [Fact]
    public void ServiceCommandLine()
    {
        var cmd = DesktopLogic.ServiceCommandLine(@"C:\Program Files\ADmiral\ADmiral.exe", @"C:\ProgramData\ADmiral");
        Assert.Equal(@"""C:\Program Files\ADmiral\ADmiral.exe"" --retry-service --home C:\ProgramData\ADmiral", cmd);
        Assert.Contains("--home", cmd);
        // a trailing backslash must not escape the closing quote (D:\ -> "D:\\")
        Assert.EndsWith(@"--home ""D:\My Data\\""", DesktopLogic.ServiceCommandLine(@"C:\A\ADmiral.exe", @"D:\My Data\"));
        Assert.Equal(@"""D:\My Data\\""", DesktopLogic.QuoteWindowsArg(@"D:\My Data\"));
        Assert.Equal(@"C:\x\", DesktopLogic.QuoteWindowsArg(@"C:\x\"));              // nothing to quote: kept as it is
        Assert.Equal("\"a\\\\\\\"b\"", DesktopLogic.QuoteWindowsArg("a\\\"b"));
        Assert.Equal("\"\"", DesktopLogic.QuoteWindowsArg(""));
        foreach (var (exe, home) in new[] { (@"C:\A\ADmiral.exe", "D:\\x\" --evil \""), (@"C:\A\ADmiral.exe", "relative"), ("ADmiral.exe", @"C:\d"),
                                           (@"C:\A\ADmiral.exe", "C:\\d\n--x"), (@"C:\A\ADmiral.exe", "") })
            Assert.Throws<RetryServiceError>(() => DesktopLogic.ServiceCommandLine(exe, home));
    }

    [Fact]
    public void ServiceStatusAndAccount()
    {
        var st = DesktopLogic.ServiceStatusFrom(4, DesktopLogic.StartAuto, @"CORP\svc");
        Assert.Equal(new RetryServiceStatus(true, true, true, "running", true, @"CORP\svc"), st);
        Assert.Equal("stopped", DesktopLogic.ServiceStatusFrom(1, DesktopLogic.StartDemand, null).State);
        Assert.False(DesktopLogic.ServiceStatusFrom(1, DesktopLogic.StartDemand, null).Enabled);
        Assert.True(DesktopLogic.ServiceStatusFrom(2, 3, "").Running);                  // starting counts as running
        Assert.Equal("?", DesktopLogic.ServiceStatusFrom(99, 3, "").State);
        Assert.Equal(@"CORP\svc", DesktopLogic.ValidServiceAccount(@" CORP\svc "));
        Assert.Equal("svc@corp.local", DesktopLogic.ValidServiceAccount("svc@corp.local"));
        Assert.Equal(@".\local", DesktopLogic.ValidServiceAccount(@".\local"));
        foreach (var bad in new[] { "", "  ", @"a\b\c", @"\svc", "svc\"x", "a\nb", "a;b", "a|b" })
            Assert.Throws<RetryServiceError>(() => DesktopLogic.ValidServiceAccount(bad));
    }

    private sealed class FakeControl : IRetryServiceControl
    {
        public List<string> Calls { get; } = [];
        public RetryServiceStatus Status() => new(true);

        public RetryServiceStatus Install(string home, string account, string password)
        {
            Calls.Add($"install {home} {account} {password}");
            return new RetryServiceStatus(true, true, true, "running", true, account);
        }

        public RetryServiceStatus SetEnabled(bool enabled)
        {
            Calls.Add($"enabled {enabled}");
            return new RetryServiceStatus(true, true, enabled, enabled ? "running" : "stopped", enabled);
        }

        public RetryServiceStatus Delete()
        {
            Calls.Add("delete");
            return new RetryServiceStatus(true);
        }
    }

    [Fact]
    public void ServiceApiDrivesTheControlWithTheDataFolder()
    {
        using var f = new ServiceFixture(editable: true);
        var ctl = new FakeControl();
        f.App.RetryService = ctl;
        f.App.Settings.Ldap.User = @"CORP\svc";
        f.App.Settings.Ldap.Password = "pw";
        Assert.True(f.App.RetryServiceAction("install").Running);                       // default: the saved LDAP account
        Assert.Equal($"install {f.Temp.Path} CORP\\svc pw", ctl.Calls[0]);
        f.App.RetryServiceAction("disable");
        f.App.RetryServiceAction("enable");
        f.App.RetryServiceAction("delete");
        Assert.Equal(["enabled False", "enabled True", "delete"], ctl.Calls[1..]);
        Assert.Contains(f.App.Store.Activity(), a => (string?)a["action"] == "service");
    }
}
