#pragma warning disable CA1873 // log arguments are cheap here
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// The platform-independent part of the desktop launcher (port of the pure logic in admiral/desktop.py and
// admiral/winservice.py): where the data folder is, the data-folder ACL rule, the per-launch token, the argument
// parsing, which links the window may open, the JS bridge the page calls (window.pywebview.api.*) and the service
// command line. The WinForms / WebView2 / Service Control Manager parts live in src/ADmiral.Desktop and only call this.

/// <summary>What <see cref="DesktopLogic.DataDir"/> looks at (the real process, or a fake in tests).</summary>
public sealed record DesktopEnv(string? ExeDir, Func<string, string?> GetEnv, bool IsWindows, string UserHome)
{
    /// <summary>The ACL checks used for the program folder (null = <see cref="WinSec.Default"/>).</summary>
    public IFileSecurity? Security { get; init; }

    /// <summary>The running process: the folder of ADmiral.exe, the real environment.</summary>
    public static DesktopEnv Current() => new(
        Path.GetDirectoryName(Environment.ProcessPath ?? "") is { Length: > 0 } d && !IsDotnetHost() ? d : null,
        Environment.GetEnvironmentVariable, OperatingSystem.IsWindows(),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

    // `dotnet ADmiral.dll` (development): the exe folder is the SDK's, never a portable install
    private static bool IsDotnetHost() =>
        Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "").Equals("dotnet", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The command line of ADmiral.exe.</summary>
public sealed record DesktopArgs(bool SelfTest = false, bool UiTest = false, bool RetryService = false, string? Home = null)
{
    public bool Debug { get; init; }
    /// <summary>This process is the elevated restart of a non-elevated start (<c>--elevated</c>): never restart again.</summary>
    public bool Elevated { get; init; }
}

/// <summary>What the bridge needs from the window (WinForms in the app, a fake in tests).</summary>
public interface IDesktopShell
{
    /// <summary>Show a "save as" dialog proposing <paramref name="suggestedName"/>; the chosen path or null (cancelled).</summary>
    string? PickSaveFile(string suggestedName);

    /// <summary>Open a folder in Explorer.</summary>
    void OpenFolder(string path);

    /// <summary>Open an already validated https link in the default browser.</summary>
    void OpenUrl(Uri url);

    /// <summary>Close the window.</summary>
    void Quit();

    /// <summary>The page's theme changed ("system", "light" or "dark"): repaint the window frame (title bar) to match.</summary>
    void SetTheme(string theme);
}

public static partial class DesktopLogic
{
    public const string AppName = "ADmiral";

    /// <summary>Written by the installer when a custom data folder is chosen.</summary>
    public const string DataPointer = "admiral-data.txt";

    /// <summary>github.com links only into ADmiral's own repository (issues).</summary>
    public const string GithubRepoPath = "/impydy/ADmiral/";

    /// <summary>Hosts of the links the UI may open in the default browser.</summary>
    public static readonly IReadOnlySet<string> OpenUrlHosts = new HashSet<string>(StringComparer.Ordinal)
    {
        "tidecrestlabs.com", "www.tidecrestlabs.com", "ko-fi.com", "discord.gg", "nvd.nist.gov",
    };

    // ------------------------------------------------------------------ the Windows service
    public const string ServiceName = "ADmiralRetry";
    public const string ServiceDisplayName = "ADmiral";
    public const string ServiceDescription = "ADmiral: periodically retries the computers that were offline or whose inventory "
                                             + "collection failed, and synchronises with the other ADmiral when that is enabled.";
    public const string RetryServiceFlag = "--retry-service";

    /// <summary>SERVICE_STATUS.dwCurrentState -> name.</summary>
    public static readonly IReadOnlyDictionary<int, string> ServiceStates = new Dictionary<int, string>
    {
        [1] = "stopped", [2] = "starting", [3] = "stopping", [4] = "running", [5] = "continuing", [6] = "pausing", [7] = "paused",
    };

    public const int StartAuto = 2, StartDemand = 3;

    // ------------------------------------------------------------------ data folder
    /// <summary>Where settings, the database and the log live. First match wins:
    /// <list type="number">
    /// <item><c>admiral.toml</c> next to the exe -> portable: data beside the program</item>
    /// <item>the <c>ADMIRAL_HOME</c> environment variable</item>
    /// <item><c>admiral-data.txt</c> next to the exe -> the folder chosen in the installer (environment variables expanded)</item>
    /// <item><c>%APPDATA%\ADmiral</c> (per user; <c>$XDG_CONFIG_HOME/admiral</c> off Windows)</item>
    /// </list></summary>
    public static string DataDir(DesktopEnv env)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (env.ExeDir is { Length: > 0 } exeDir && File.Exists(Path.Combine(exeDir, "admiral.toml")))
        {
            // portable install - only from a folder no ordinary user can change (else anyone could plant the settings)
            if (ProgramDirProblem(exeDir, env.Security) is null) return exeDir;
            Log.Logger.LogWarning("Ignoring {File} next to the program: the folder {Dir} is writable by every user", "admiral.toml", exeDir);
        }
        if (env.GetEnv("ADMIRAL_HOME") is { Length: > 0 } home)
            return home;
        if (env.ExeDir is { Length: > 0 } dir && File.Exists(Path.Combine(dir, DataPointer)))
        {
            string chosen;
            try
            {
                chosen = ReadPointer(Path.Combine(dir, DataPointer));
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                chosen = "";
            }
            if (chosen.Length > 0) return ExpandVars(chosen, env.GetEnv, env.IsWindows);
        }
        if (env.IsWindows)
            return Path.Combine(env.GetEnv("APPDATA") is { Length: > 0 } appData ? appData : Path.Combine(env.UserHome, "AppData", "Roaming"), AppName);
        return Path.Combine(env.GetEnv("XDG_CONFIG_HOME") is { Length: > 0 } xdg ? xdg : Path.Combine(env.UserHome, ".config"), "admiral");
    }

    /// <summary>The first line of the installer's pointer file (UTF-8, with or without BOM), trimmed; at most 4 KiB read.</summary>
    private static string ReadPointer(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buf = new byte[4096];
        var n = f.ReadAtLeast(buf, buf.Length, throwOnEndOfStream: false);
        var text = new UTF8Encoding(false).GetString(buf, 0, n).TrimStart('﻿');
        var line = text.Split('\n', 2)[0];
        return line.Trim();
    }

    /// <summary>Expand <c>$VAR</c>, <c>${VAR}</c> and (on Windows) <c>%VAR%</c>; unknown variables stay as they are
    /// (like Python's <c>os.path.expandvars</c>).</summary>
    public static string ExpandVars(string text, Func<string, string?> getEnv, bool windows)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(getEnv);
        var outp = VarRe().Replace(text, m =>
        {
            var name = m.Groups["b"].Success ? m.Groups["b"].Value : m.Groups["n"].Value;
            return getEnv(name) ?? m.Value;
        });
        if (windows)
            outp = WinVarRe().Replace(outp, m => getEnv(m.Groups[1].Value) ?? m.Value);
        return outp;
    }

    [GeneratedRegex(@"\$(?:\{(?<b>[A-Za-z0-9_]+)\}|(?<n>[A-Za-z_][A-Za-z0-9_]*))")]
    private static partial Regex VarRe();

    [GeneratedRegex(@"%([A-Za-z0-9_()]+)%")]
    private static partial Regex WinVarRe();

    /// <summary>The WebView2 profile (history, storage): always private to the Windows user, never in a shared folder.</summary>
    public static string WebViewDir(string home, DesktopEnv env)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (env.IsWindows && env.GetEnv("LOCALAPPDATA") is { Length: > 0 } local)
            return Path.Combine(local, AppName, "webview");
        return Path.Combine(home, "webview");
    }

    /// <summary>Written by the installer next to the exe: the accounts it gave modify rights on the data folder (the
    /// installing user, <c>/DATAUSER=</c>, the retry-service account), one per line, as <c>DOMAIN\name</c> or <c>*SID</c>.
    /// It lives in the program folder (administrators only), never in the data folder it describes.</summary>
    public const string DataUsersFile = "admiral-datausers.txt";

    public const int MaxDataUsers = 64;

    /// <summary>The accounts listed in <see cref="DataUsersFile"/> next to the exe (empty when there is none).</summary>
    public static List<string> DataUsers(string? exeDir)
    {
        var outp = new List<string>();
        if (string.IsNullOrEmpty(exeDir)) return outp;
        var path = Path.Combine(exeDir, DataUsersFile);
        try
        {
            if (!File.Exists(path)) return outp;
            using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[16 * 1024];
            var n = f.ReadAtLeast(buf, buf.Length, throwOnEndOfStream: false);
            foreach (var raw in new UTF8Encoding(false).GetString(buf, 0, n).TrimStart('\uFEFF').Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#') || outp.Contains(line, StringComparer.OrdinalIgnoreCase)) continue;
                outp.Add(line);
                if (outp.Count >= MaxDataUsers) break;
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            Log.Logger.LogWarning("Could not read {File}: {Error}", path, exc.Message);
        }
        return outp;
    }

    /// <summary>Add <paramref name="account"/> to <see cref="DataUsersFile"/> (the retry-service install does this, so a
    /// later installer run grants it again). Best effort: false when the file cannot be written.</summary>
    public static bool AddDataUser(string exeDir, string account)
    {
        ArgumentNullException.ThrowIfNull(account);
        var clean = new string(account.Where(c => c >= 32 && c != '"').ToArray()).Trim();
        if (clean.Length == 0) return false;
        var users = DataUsers(exeDir);
        if (users.Contains(clean, StringComparer.OrdinalIgnoreCase)) return true;
        users.Add(clean);
        try
        {
            File.WriteAllText(Path.Combine(exeDir, DataUsersFile), string.Join("\r\n", users) + "\r\n", new UTF8Encoding(false));
            return true;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            Log.Logger.LogWarning("Could not record {Account} in {File}: {Error}", clean, DataUsersFile, exc.Message);
            return false;
        }
    }

    /// <summary>The data folder may only be changed by SYSTEM, Administrators, the current user and the accounts the
    /// installer granted (<paramref name="dataUsers"/>: <see cref="DataUsers"/> and the retry-service account), and must be
    /// owned by SYSTEM / Administrators / the current user: whoever can write it controls the settings, the package library
    /// and the database the administrator acts on (a folder pre-created by another user with their own entry would
    /// otherwise stay theirs). An unsafe folder is restricted (fresh DACL, owner taken); if that is not possible the
    /// (bilingual) error text is returned, otherwise null.</summary>
    public static string? SecureDataDir(string home, IFileSecurity? security = null, IEnumerable<string>? dataUsers = null)
    {
        var fs = security ?? WinSec.Default;
        var extraSids = new List<string>();
        foreach (var account in dataUsers ?? [])
        {
            if (fs.ResolveSid(account) is { } sid && !WinSec.IsBroad(sid)) extraSids.Add(sid);
            else Log.Logger.LogWarning("Data folder user {Account} could not be resolved (or is a group of every user); ignored", account);
        }
        List<string> problems;
        try
        {
            problems = Problems(home, fs, extraSids);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            // an unreadable ACL (network folder, old Windows) must not block the start
            Log.Logger.LogWarning("Could not read the permissions of {Home}: {Type}: {Message}", home, exc.GetType().Name, exc.Message);
            return null;
        }
        if (problems.Count == 0) return null;
        var who = string.Join(", ", problems);
        Log.Logger.LogWarning("The data folder {Home} can be changed by {Who}; restricting it", home, who);
        if (fs.HardenDir(home, extraSids))
        {
            // re-read: HardenDir may report success while an inherited / explicit entry survived
            try
            {
                var left = Problems(home, fs, extraSids);
                if (left.Count == 0)
                {
                    Log.Logger.LogInformation("The data folder {Home} is now restricted to SYSTEM, Administrators and the ADmiral users", home);
                    return null;
                }
                who = string.Join(", ", left);
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                Log.Logger.LogWarning("Could not re-read the permissions of {Home}: {Message}", home, exc.Message);
                return null;
            }
        }
        return $"The data folder {home} can be changed by accounts other than SYSTEM, Administrators and the ADmiral users ({who}), "
               + "and ADmiral could not restrict it. Run the installer again (as an administrator), or restrict the "
               + "folder to SYSTEM, Administrators and the ADmiral users.\n\n"
               + $"Az adatmappát ({home}) a SYSTEM, a rendszergazdák és az ADmiral felhasználóin kívül mások is módosíthatják ({who}), és az "
               + "ADmiral nem tudta korlátozni. Futtassa újra a telepítőt rendszergazdaként, vagy korlátozza a mappát "
               + "a SYSTEM, a rendszergazdák és az ADmiral felhasználói számára.";
    }

    /// <summary>Broad writers, plus (when the owner and DACL can be read) every unexpected writer and a foreign owner.</summary>
    private static List<string> Problems(string home, IFileSecurity fs, IReadOnlyList<string> extraSids)
    {
        var outp = new List<string>(fs.BroadWriters(home));
        if (fs.ReadSecurity(home) is { } sec)
            foreach (var p in WinSec.UnexpectedAccess(sec, fs.CurrentUserSid(), extraSids))
                if (!outp.Contains(p)) outp.Add(p);
        return outp;
    }

    /// <summary>A program folder that is not Program Files must not be writable by anyone but SYSTEM / Administrators
    /// (the exe, its DLLs and a portable <c>admiral.toml</c> there decide what ADmiral runs). The (bilingual) warning text,
    /// or null when the folder is fine / cannot be checked.</summary>
    public static string? ProgramDirProblem(string? exeDir, IFileSecurity? security = null)
    {
        if (string.IsNullOrEmpty(exeDir)) return null;
        IReadOnlyList<string> broad;
        try { broad = (security ?? WinSec.Default).BroadWriters(exeDir); }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogWarning("Could not read the permissions of the program folder {Dir}: {Message}", exeDir, exc.Message);
            return null;
        }
        if (broad.Count == 0) return null;
        var who = string.Join(", ", broad);
        return $"The program folder {exeDir} can be changed by every user of this computer ({who}): anyone could replace "
               + "ADmiral's files and run code with your rights. ADmiral will not start from it. Install ADmiral with the "
               + "installer (Program Files), or restrict the folder to SYSTEM and Administrators.\n\n"
               + $"A programmappát ({exeDir}) a számítógép minden felhasználója módosíthatja ({who}): bárki kicserélhetné az "
               + "ADmiral fájljait, és az Ön jogaival futtathatna kódot. Az ADmiral nem indul el innen. Telepítse az ADmiralt a "
               + "telepítővel (Program Files), vagy korlátozza a mappát a SYSTEM és a rendszergazdák számára.";
    }

    // ------------------------------------------------------------------ start-up
    /// <summary>A fresh per-launch API token: 32 random bytes, base64url (43 characters).</summary>
    public static string NewToken()
    {
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        return Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Marks the elevated restart of the window (see <see cref="ElevationNeeded"/>).</summary>
    public const string ElevatedFlag = "--elevated";

    /// <summary>What a start of ADmiral.exe must do about administrator rights. The window always runs elevated: the
    /// data folder (C:\ProgramData\ADmiral) is only open to SYSTEM, Administrators and the accounts the installer
    /// granted, so a normal user - or an administrator's filtered UAC token - cannot use it. The retry service (its
    /// account was granted the folder) and the CI checks (--self-test / --ui-test) are never restarted.</summary>
    public enum Elevation { Run, Restart, Refuse }

    public static Elevation ElevationNeeded(DesktopArgs args, bool isElevated)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (isElevated || args.RetryService || args.SelfTest || args.UiTest) return Elevation.Run;
        // already restarted once and still not elevated (UAC switched off for a standard user): no loop
        return args.Elevated ? Elevation.Refuse : Elevation.Restart;
    }

    /// <summary>The arguments of the elevated restart: the same ones, plus <see cref="ElevatedFlag"/>.</summary>
    public static List<string> ElevatedArgs(IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(argv);
        var list = argv.ToList();
        if (!list.Contains(ElevatedFlag)) list.Add(ElevatedFlag);
        return list;
    }

    /// <summary>"Needs administrator rights" in both languages (the settings, and so the language, are not read yet).</summary>
    public static string NeedAdminText()
    {
        var (hu, en) = I18n.Messages["err.need_admin"];
        return hu + "\n\n" + en;
    }

    /// <summary>Parse ADmiral.exe's arguments (<c>--self-test</c>, <c>--ui-test</c>, <c>--retry-service</c>,
    /// <c>--home &lt;dir&gt;</c>, <c>--debug</c>). Unknown arguments are ignored (a shortcut may pass anything);
    /// <c>--home</c> without a value throws <see cref="ArgumentException"/>.</summary>
    public static DesktopArgs ParseArgs(IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(argv);
        var a = new DesktopArgs();
        for (var i = 0; i < argv.Count; i++)
        {
            switch (argv[i])
            {
                case "--self-test": a = a with { SelfTest = true }; break;
                case "--ui-test": a = a with { UiTest = true }; break;
                case RetryServiceFlag: a = a with { RetryService = true }; break;
                case "--debug": a = a with { Debug = true }; break;
                case ElevatedFlag: a = a with { Elevated = true }; break;
                case "--home":
                    if (i + 1 >= argv.Count || argv[i + 1].Length == 0 || argv[i + 1].StartsWith("--", StringComparison.Ordinal))
                        throw new ArgumentException("--home needs a folder");
                    a = a with { Home = argv[++i] };
                    break;
                default:
                    if (argv[i].StartsWith("--home=", StringComparison.Ordinal) && argv[i].Length > 7) a = a with { Home = argv[i][7..] };
                    break;
            }
        }
        return a;
    }

    /// <summary>Create the service for the data folder <paramref name="home"/> (a first start writes admiral.toml with an
    /// empty Active Directory configuration; <paramref name="demo"/> - tests / screenshots only - uses the fake demo
    /// domain instead). The service may save settings (config path set) and keeps passwords in secrets.json.</summary>
    public static AdmiralService BuildService(string home, bool demo = false, bool applyProcessSettings = true, ISecretProtector? protector = null)
    {
        Directory.CreateDirectory(home);
        var cfg = Path.Combine(home, "admiral.toml");
        if (!File.Exists(cfg))
        {
            var first = new Settings { Mode = demo ? "demo" : "ldap", DbPath = Path.Combine(home, "admiral.db") };  // a release never starts with the demo domain
            Persist.SaveSettings(first, cfg);
        }
        var settings = Config.LoadSettings(cfg, requireLdap: false);     // empty until the user fills in the AD settings
        if (!Path.IsPathRooted(settings.DbPath) && settings.DbPath != ":memory:")
            settings.DbPath = Path.Combine(home, settings.DbPath);
        var secrets = new SecretStore(Path.Combine(home, "secrets.json"), protector);
        secrets.Apply(settings);
        return new AdmiralService(settings, configPath: cfg, secrets: secrets, applyProcessSettings: applyProcessSettings);
    }

    /// <summary>The text of the start-up failure dialog (with a hint for a missing WebView2 runtime).</summary>
    public static string StartupFailureText(Exception exc, string home)
    {
        ArgumentNullException.ThrowIfNull(exc);
        var all = exc.ToString();
        var hint = "";
        if (all.Contains("WebView2", StringComparison.OrdinalIgnoreCase))
            hint = "\n\nADmiral needs the Microsoft Edge WebView2 Runtime. It is built into Windows 10/11; on Windows "
                   + "Server install Microsoft's Evergreen WebView2 Runtime.\n"
                   + "Az ADmiral ablakához a Microsoft Edge WebView2 Runtime szükséges (Windows Serveren telepítse az "
                   + "„Evergreen WebView2 Runtime”-ot).";
        return $"ADmiral could not start:\n\n{exc.Message}{hint}\n\nDetails: {Path.Combine(home, "logs", Diag.LogFile)}";
    }

    // ------------------------------------------------------------------ links and navigation
    /// <summary>True when <paramref name="url"/> is one of ADmiral's own links (https, an allow-listed host, or
    /// ADmiral's GitHub repository); <paramref name="uri"/> is then the normalized link to open.</summary>
    public static bool IsAllowedExternalUrl(string? url, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(url) || url.Length > 2048) return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort || u.UserInfo.Length > 0) return false;
        var host = u.IdnHost.ToLowerInvariant();
        var github = host == "github.com" && u.AbsolutePath.StartsWith(GithubRepoPath, StringComparison.Ordinal);
        if (!(OpenUrlHosts.Contains(host) || github)) return false;
        uri = u;
        return true;
    }

    /// <summary>True when the window may navigate to <paramref name="url"/>: only the local API origin
    /// (<paramref name="origin"/>, e.g. http://127.0.0.1:51234) and about:blank.</summary>
    public static bool IsLocalOrigin(string? url, Uri origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (string.IsNullOrEmpty(url)) return false;
        if (url == "about:blank") return true;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        return u.Scheme == origin.Scheme && u.Port == origin.Port && u.UserInfo.Length == 0
               && string.Equals(u.Host, origin.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>What the window does with a navigation it is asked to make.</summary>
    public enum NavigationAction
    {
        /// <summary>Stay: a page of the exact local origin.</summary>
        Allow,
        /// <summary>Cancel it and open the (allow-listed) link in the default browser.</summary>
        OpenExternal,
        /// <summary>Cancel it.</summary>
        Refuse,
    }

    /// <summary>The decision for WebView2's NavigationStarting / FrameNavigationStarting. Only the exact local origin
    /// stays in the window; the main frame never goes to about:blank (an injected meta refresh / script could blank
    /// the app). Anything else is cancelled; an allow-listed ADmiral link is opened in the browser only when the user
    /// clicked it - a meta refresh, a script or a frame is not a click, so it can never start the browser.</summary>
    public static NavigationAction DecideNavigation(string? url, Uri origin, bool isUserInitiated, bool isMainFrame)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (IsLocalOrigin(url, origin) && !(isMainFrame && url == "about:blank")) return NavigationAction.Allow;
        if (isUserInitiated && isMainFrame && IsAllowedExternalUrl(url, out _)) return NavigationAction.OpenExternal;
        return NavigationAction.Refuse;
    }

    /// <summary>True when a download comes from the local origin (or a blob: URL the local page created).</summary>
    public static bool IsLocalDownload(string? url, Uri origin) =>
        url is not null && (IsLocalOrigin(url, origin)
                            || (url.StartsWith("blob:", StringComparison.Ordinal) && IsLocalOrigin(url[5..], origin)));

    // ------------------------------------------------------------------ the service command line
    /// <summary>Quote one argument for CommandLineToArgvW / the C runtime (backslashes before quotes doubled).</summary>
    public static string QuoteWindowsArg(string arg)
    {
        ArgumentNullException.ThrowIfNull(arg);
        if (arg.Length > 0 && arg.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0) return arg;
        var sb = new StringBuilder("\"");
        var slashes = 0;
        foreach (var c in arg)
        {
            if (c == '\\')
            {
                slashes++;
                continue;
            }
            if (c == '"')
            {
                sb.Append('\\', slashes * 2 + 1).Append('"');
            }
            else
            {
                sb.Append('\\', slashes).Append(c);
            }
            slashes = 0;
        }
        sb.Append('\\', slashes * 2).Append('"');
        return sb.ToString();
    }

    /// <summary>What the Service Control Manager starts: <c>"ADmiral.exe" --retry-service --home "&lt;data folder&gt;"</c>.
    /// Both paths must be absolute, without quotes or control characters (they never come from the network, but a
    /// malformed path must not turn into extra arguments).</summary>
    public static string ServiceCommandLine(string exePath, string home)
    {
        foreach (var (what, p) in new[] { ("program", exePath), ("data folder", home) })
        {
            if (string.IsNullOrWhiteSpace(p) || p.Any(c => c == '"' || char.IsControl(c)) || p.Length > 1024)
                throw new RetryServiceError($"invalid {what} path for the service: '{p}'");
        }
        if (!LooksRooted(exePath) || !LooksRooted(home))
            throw new RetryServiceError("the service needs absolute paths");
        return $"{QuoteWindowsArg(exePath)} {RetryServiceFlag} --home {QuoteWindowsArg(home)}";
    }

    private static bool LooksRooted(string p) =>
        Path.IsPathFullyQualified(p) || (p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && p[2] == '\\') || p.StartsWith(@"\\", StringComparison.Ordinal);

    /// <summary>The settings-page view of a queried service.</summary>
    public static RetryServiceStatus ServiceStatusFrom(int currentState, int startType, string? account) =>
        new(true, true, currentState is 2 or 4, ServiceStates.GetValueOrDefault(currentState, "?"), startType == StartAuto, account ?? "");

    /// <summary>A service account as CreateService accepts it (DOMAIN\user, .\user or user@domain), or an exception.</summary>
    public static string ValidServiceAccount(string? account)
    {
        var a = (account ?? "").Trim();
        if (a.Length == 0) throw new RetryServiceError("service account is required");
        if (a.Length > 256 || a.Any(c => char.IsControl(c) || c is '"' or '/' or '[' or ']' or ':' or ';' or '|' or '=' or ',' or '+' or '*' or '?' or '<' or '>'))
            throw new RetryServiceError($"invalid service account: '{a}'");
        if (a.Count(c => c == '\\') > 1 || a.StartsWith('\\') || a.EndsWith('\\'))
            throw new RetryServiceError($"invalid service account: '{a}'");
        return a;
    }

    // ------------------------------------------------------------------ the JS bridge (window.pywebview.api)
    /// <summary>Methods the page may call (the same names the Python shell exposed).</summary>
    public static readonly IReadOnlyList<string> BridgeMethods =
        ["save_file", "save_binary", "quit", "open_data_folder", "open_logs_folder", "save_log_package", "remote_assist", "event_viewer", "computer_management", "open_url", "set_theme"];

    // ------------------------------------------------------------------ the window frame (title bar)
    /// <summary>Dark title bar? The ADmiral theme setting; "system" (or anything else) follows Windows' app mode.</summary>
    public static bool TitleBarDark(string? theme, bool windowsDark) => theme switch
    {
        "dark" => true,
        "light" => false,
        _ => windowsDark,
    };

    /// <summary>Title bar background and text (0xRRGGBB): the page's --bar and --text colours (app.css), so the title
    /// bar and the toolbar under it look like one surface (Windows 11; Windows 10 only switches light/dark).</summary>
    public static (int Caption, int Text) TitleBarColors(bool dark) => dark ? (0x2B2B2B, 0xE8E8E8) : (0xFFFFFF, 0x1B1B1B);

    /// <summary>The window background behind the page while it loads (the page's --win colour).</summary>
    public static int WindowBackColor(bool dark) => dark ? 0x1F1F1F : 0xF0F0F0;

    /// <summary>Largest file the page may save through the bridge.</summary>
    public const int MaxSaveBytes = 64 * 1024 * 1024;

    /// <summary>The script injected into every document of the window: defines <c>window.pywebview.api.&lt;method&gt;()</c>
    /// (each returns a Promise) on top of WebView2's postMessage. <paramref name="origin"/> = the only origin it runs on.</summary>
    public static string BridgeScript(Uri origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        var o = JsonSerializer.Serialize(origin.GetLeftPart(UriPartial.Authority));
        var methods = JsonSerializer.Serialize(BridgeMethods);
        return "(function () {\n"
               + "  'use strict';\n"
               + $"  if (window.top !== window || location.origin !== {o} || !window.chrome || !window.chrome.webview) return;\n"
               + "  var wv = window.chrome.webview, seq = 0, pending = new Map();\n"
               + "  wv.addEventListener('message', function (e) {\n"
               + "    var m = e.data; if (!m || typeof m.id !== 'number' || !pending.has(m.id)) return;\n"
               + "    var p = pending.get(m.id); pending.delete(m.id);\n"
               + "    if (m.ok) p.resolve(m.result === undefined ? null : m.result); else p.reject(new Error(m.error || 'error'));\n"
               + "  });\n"
               + "  var api = {};\n"
               + $"  {methods}.forEach(function (name) {{\n"
               + "    api[name] = function () {\n"
               + "      var args = Array.prototype.slice.call(arguments);\n"
               + "      return new Promise(function (resolve, reject) {\n"
               + "        var id = ++seq; pending.set(id, { resolve: resolve, reject: reject });\n"
               + "        wv.postMessage({ id: id, method: name, args: args });\n"
               + "      });\n"
               + "    };\n"
               + "  });\n"
               + "  Object.defineProperty(window, 'pywebview', { value: Object.freeze({ api: Object.freeze(api) }), writable: false, configurable: false });\n"
               + "})();\n";
    }

    /// <summary>A suggested file name without any folder part or characters Windows refuses.</summary>
    public static string SafeFileName(string? name)
    {
        var n = (name ?? "").Replace('\\', '/');
        n = n[(n.LastIndexOf('/') + 1)..];
        n = new string([.. n.Where(c => !char.IsControl(c) && c is not ('<' or '>' or ':' or '"' or '|' or '?' or '*'))]).Trim().TrimEnd('.');
        if (n.Length > 200) n = n[..200];
        return n.Length == 0 ? "export.txt" : n;
    }

    /// <summary>The folder to open for "open logs": the log folder, or one anonymized package in it
    /// (<c>ADM-XXXX-XXXX</c>; anything else throws <see cref="ArgumentException"/>).</summary>
    public static string LogsFolder(string? installedFolder, string home, string? packageId)
    {
        var folder = installedFolder ?? Path.Combine(home, Diag.LogDir);
        if (string.IsNullOrEmpty(packageId)) return folder;
        if (!LogPackageIdRe().IsMatch(packageId)) throw new ArgumentException("not a log package id");
        return Path.Combine(folder, LogReport.OutDir, packageId);
    }

    [GeneratedRegex(@"\A" + LogReport.IdPattern + @"\z")]
    private static partial Regex LogPackageIdRe();
}

/// <summary>Executes the page's bridge calls: <c>{"id": n, "method": "...", "args": [...]}</c> in,
/// <c>{"id": n, "ok": true, "result": ...}</c> or <c>{"id": n, "ok": false, "error": "..."}</c> out.</summary>
public sealed class DesktopBridge(IDesktopShell shell, string home, Action<string>? remoteAssist = null, Func<string?>? logFolder = null,
                                  Action<string>? eventViewer = null, Action<string>? computerManagement = null)
{
    /// <summary>Handle one message from the page (already checked to come from the local origin). Never throws.</summary>
    public string Handle(string json)
    {
        long? id = null;
        try
        {
            if (json.Length > DesktopLogic.MaxSaveBytes / 3 * 4 + 64 * 1024) throw new ArgumentException("message too large");
            var msg = JsonNode.Parse(json) as JsonObject ?? throw new ArgumentException("bad message");
            id = msg["id"] is JsonValue v && v.TryGetValue<long>(out var n) ? n : throw new ArgumentException("bad message id");
            var method = msg["method"] is JsonValue mv && mv.TryGetValue<string>(out var m) ? m : "";
            var args = msg["args"] as JsonArray ?? [];
            string Arg(int i) => i < args.Count && args[i] is JsonValue av && av.TryGetValue<string>(out var s) ? s : "";
            var result = Call(method, i => Arg(i));
            return new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = result is null ? null : JsonValue.Create(result) }.ToJsonString();
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            if (exc is not (ArgumentException or InvalidOperationException or JsonException))
                Log.Logger.LogError(exc, "Desktop bridge call failed");
            return new JsonObject { ["id"] = id, ["ok"] = false, ["error"] = exc.Message }.ToJsonString();
        }
    }

    /// <summary>One bridge method; returns the saved path (save_*) or null.</summary>
    public string? Call(string method, Func<int, string> arg)
    {
        ArgumentNullException.ThrowIfNull(arg);
        switch (method)
        {
            case "save_file":
                return SaveFile(arg(0), arg(1));
            case "save_binary":
                return SaveBinary(arg(0), arg(1));
            case "quit":
                shell.Quit();
                return null;
            case "open_url":
                OpenUrl(arg(0));
                return null;
            case "set_theme":
                var theme = arg(0);
                if (theme is not ("system" or "light" or "dark")) throw new ArgumentException("theme must be 'system', 'light' or 'dark'");
                shell.SetTheme(theme);
                return null;
            case "open_data_folder":
                shell.OpenFolder(home);
                return null;
            case "open_logs_folder":
                OpenLogsFolder(arg(0));
                return null;
            case "save_log_package":
                return SaveLogPackage(arg(0));
            case "remote_assist":
                if (remoteAssist is null) throw new InvalidOperationException("Remote Assistance is not available");
                remoteAssist(arg(0));
                return null;
            case "event_viewer":
                if (eventViewer is null) throw new InvalidOperationException("The Event Viewer is not available");
                eventViewer(arg(0));
                return null;
            case "computer_management":
                if (computerManagement is null) throw new InvalidOperationException("Computer Management is not available");
                computerManagement(arg(0));
                return null;
            default:
                throw new ArgumentException($"unknown bridge method '{method}'");
        }
    }

    public string? SaveFile(string filename, string content)
    {
        if (Encoding.UTF8.GetByteCount(content) > DesktopLogic.MaxSaveBytes) throw new ArgumentException("the file is too large");
        var path = shell.PickSaveFile(DesktopLogic.SafeFileName(filename));
        if (string.IsNullOrEmpty(path)) return null;
        File.WriteAllText(path, content, new UTF8Encoding(false));          // newlines kept as given
        return path;
    }

    /// <summary>Like <see cref="SaveFile"/> for binary content (e.g. an .xlsx), passed as base64.</summary>
    public string? SaveBinary(string filename, string contentB64)
    {
        if (contentB64.Length > DesktopLogic.MaxSaveBytes / 3 * 4 + 4) throw new ArgumentException("the file is too large");
        byte[] data;
        try
        {
            data = Convert.FromBase64String(contentB64);
        }
        catch (FormatException exc)
        {
            throw new ArgumentException("not base64 content", exc);
        }
        var path = shell.PickSaveFile(DesktopLogic.SafeFileName(filename));
        if (string.IsNullOrEmpty(path)) return null;
        File.WriteAllBytes(path, data);
        return path;
    }

    /// <summary>Open one of ADmiral's own links in the default browser (anything else is refused).</summary>
    public void OpenUrl(string url)
    {
        if (!DesktopLogic.IsAllowedExternalUrl(url, out var uri)) throw new ArgumentException("this link is not allowed");
        shell.OpenUrl(uri!);
    }

    /// <summary>Save one anonymized log package (<c>ADM-XXXX-XXXX</c>) as a .zip where the user picks. ADmiral runs as
    /// administrator and its data folder is closed to the signed-in user, so Explorer cannot open the package folder
    /// itself; the package holds no names, so a copy outside is fine. Returns the saved path (null = cancelled).</summary>
    public string? SaveLogPackage(string packageId)
    {
        if (string.IsNullOrEmpty(packageId)) throw new ArgumentException("not a log package id");
        var folder = DesktopLogic.LogsFolder(logFolder?.Invoke() ?? Diag.InstalledFolder, home, packageId);
        if (!Directory.Exists(folder)) throw new InvalidOperationException("the log package no longer exists");
        using var buf = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(buf, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var f in new DirectoryInfo(folder).EnumerateFiles("*", new EnumerationOptions
                     { RecurseSubdirectories = false, AttributesToSkip = FileAttributes.ReparsePoint }).OrderBy(f => f.Name, StringComparer.Ordinal))
            {
                if (f.Length > DesktopLogic.MaxSaveBytes) continue;
                var entry = zip.CreateEntry(f.Name, System.IO.Compression.CompressionLevel.Optimal);
                using var to = entry.Open();
                using var from = f.OpenRead();
                from.CopyTo(to);
            }
        }
        if (buf.Length > DesktopLogic.MaxSaveBytes) throw new ArgumentException("the file is too large");
        var path = shell.PickSaveFile(packageId + ".zip");
        if (string.IsNullOrEmpty(path)) return null;
        File.WriteAllBytes(path, buf.ToArray());
        return path;
    }

    /// <summary>Open the log folder, or one anonymized package in it (<c>ADM-XXXX-XXXX</c>; nothing else is accepted).</summary>
    public void OpenLogsFolder(string packageId)
    {
        var folder = DesktopLogic.LogsFolder(logFolder?.Invoke() ?? Diag.InstalledFolder, home, packageId);
        if (Directory.Exists(folder)) shell.OpenFolder(folder);
    }
}

/// <summary>Checks of a packaged build that need no window (<c>ADmiral.exe --self-test</c>) and of the real window
/// (<c>--ui-test</c>).</summary>
public static class DesktopChecks
{
    /// <summary>Evaluated in the real WebView2 window by --ui-test: did the page render and is the bridge reachable?</summary>
    public const string UiProbe = """
        (function () {
          var tb = document.querySelector('#toolbar');
          return JSON.stringify({
            title: document.title,
            toolbar_items: tb ? tb.querySelectorAll('button').length : 0,
            tree_nodes: document.querySelectorAll('#tree .tn').length,
            bridge: !!(window.pywebview && window.pywebview.api && typeof window.pywebview.api.save_file === 'function'),
            error: (document.querySelector('.callout.bad') || {}).textContent || ''
          });
        })()
        """;

    /// <summary>(ready, ok) of one probe result: ready = the page is complete enough to judge, ok = the ui-test passes.</summary>
    public static (bool Ready, bool Ok) UiProbeResult(string? json)
    {
        try
        {
            // ExecuteScriptAsync returns the JSON encoding of the script's value: here a JSON string holding JSON
            var node = JsonNode.Parse(string.IsNullOrEmpty(json) ? "{}" : json);
            if (node is JsonValue v && v.TryGetValue<string>(out var inner)) node = JsonNode.Parse(inner);
            if (node is not JsonObject o) return (false, false);
            static int Num(JsonNode? n) => n is JsonValue x && x.TryGetValue<int>(out var i) ? i : 0;
            var ready = Num(o["tree_nodes"]) > 0 && Num(o["toolbar_items"]) > 0 && o["bridge"] is JsonValue b && b.TryGetValue<bool>(out var br) && br;
            var error = o["error"] is JsonValue e && e.TryGetValue<string>(out var es) ? es : "";
            var title = o["title"] is JsonValue t && t.TryGetValue<string>(out var ts) ? ts : "";
            return (ready, ready && title == DesktopLogic.AppName && error.Length == 0);
        }
        catch (JsonException)
        {
            return (false, false);
        }
    }

    /// <summary>The self-test's HTTP checks against a running API (<paramref name="baseUri"/>): status with the token,
    /// the token enforced, the bundled UI.</summary>
    public static async Task<List<(string Name, bool Ok)>> HttpChecksAsync(HttpClient http, Uri baseUri, string token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(http);
        var checks = new List<(string, bool)>();
        async Task<(HttpStatusCode Status, string Body)> Get(string path, string tok)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, path));
            req.Headers.Add("X-ADmiral", "1");
            req.Headers.Add("X-ADmiral-Token", tok);
            using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            return (resp.StatusCode, await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        }
        async Task Check(string name, Func<Task<bool>> body)
        {
            try { checks.Add((name, await body().ConfigureAwait(false))); }
            catch (Exception exc) when (exc is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
            {
                Log.Logger.LogError("self-test {Name}: {Error}", name, exc.Message);
                checks.Add((name, false));
            }
        }
        await Check("api status", async () =>
        {
            var (st, body) = await Get("/api/status", token).ConfigureAwait(false);
            return st == HttpStatusCode.OK && JsonNode.Parse(body)?["desktop"]?.GetValue<bool>() == true;
        }).ConfigureAwait(false);
        await Check("token enforced", async () => (await Get("/api/status", "wrong").ConfigureAwait(false)).Status == HttpStatusCode.Unauthorized).ConfigureAwait(false);
        await Check("ui bundled", async () =>
        {
            var (st, body) = await Get("/", token).ConfigureAwait(false);
            if (st != HttpStatusCode.OK || !body.Contains(DesktopLogic.AppName, StringComparison.Ordinal)) return false;
            foreach (var f in new[] { "app.js", "i18n.js", "icons.js", "app.css" })
                if ((await Get("/static/" + f, token).ConfigureAwait(false)).Status != HttpStatusCode.OK) return false;
            return true;
        }).ConfigureAwait(false);
        return checks;
    }
}
