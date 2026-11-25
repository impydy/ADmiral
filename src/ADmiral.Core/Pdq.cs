using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// ======================================================================================= seams
/// <summary>How to authenticate to a target's ADMIN$ / Service Control Manager (the administrative AD account).
/// An empty <see cref="Password"/> means "the current Windows logon session" (no explicit credential).</summary>
public sealed record SmbCreds(string Username, string Password, string Domain, string Realm = "", string Kdc = "",
                              bool UseKerberos = true, bool NtlmFallback = false)
{
    /// <summary>The Kerberos realm is the DNS domain (CORP.LOCAL); the NetBIOS name (CORP) is only right for NTLM.</summary>
    public string KerberosRealm => (Realm.Length > 0 ? Realm : Domain).ToUpperInvariant();

    /// <summary><c>DOMAIN\user</c> (or the bare user name) for WNetAddConnection2.</summary>
    public string Account => Domain.Length > 0 ? $"{Domain}\\{Username}" : Username;

    public bool HasExplicitCredential => Username.Length > 0 && Password.Length > 0;

    /// <summary>Never print the password (records would by default).</summary>
    public override string ToString() =>
        $"SmbCreds {{ Username = {Username}, Domain = {Domain}, Realm = {Realm}, Kdc = {Kdc}, UseKerberos = {UseKerberos}, " +
        $"NtlmFallback = {NtlmFallback}, Password = {(Password.Length > 0 ? "***" : "(none)")} }}";
}

/// <summary>An open connection to one target's <c>ADMIN$</c> share (<c>C:\Windows</c>). Share paths are relative to the
/// share, e.g. <c>ADmiral\0123456789ab\admiral-0123456789ab.ps1</c>: every run works in its own new folder
/// (<see cref="CreatePrivateDir"/>) that only SYSTEM and Administrators can write, so no user of the target can plant a
/// DLL or swap a file next to the installer / script that runs there as LocalSystem.</summary>
public interface IRemoteSession : IDisposable
{
    /// <summary>Create the run folder <paramref name="shareDir"/> (<c>ADmiral\&lt;tag&gt;</c>) with a protected DACL
    /// (SYSTEM + Administrators full control, nothing inherited); fails if it already exists.</summary>
    void CreatePrivateDir(string shareDir);

    /// <summary>Remove the run folder and whatever is left in it (no-op when it is gone).</summary>
    void DeleteDir(string shareDir);

    /// <summary>Does the run folder still exist?</summary>
    bool DirExists(string shareDir);

    /// <summary>Create a new file (fails if it exists).</summary>
    void PutFile(string sharePath, byte[] data);

    /// <summary>Copy a (possibly large) local file in chunks from the already open <paramref name="source"/> (read to its
    /// end), reporting (sent, total) bytes.</summary>
    void PutLocal(string sharePath, Stream source, Action<long, long>? progress = null);

    /// <summary>Read a file another process may still hold open for writing; refuses files over <paramref name="maxBytes"/>.</summary>
    byte[] ReadFile(string sharePath, long maxBytes);

    void DeleteFile(string sharePath);
    bool FileExists(string sharePath);
}

/// <summary>SMB file access to targets (UNC paths to <c>\\host\ADMIN$</c> on Windows; fakes in tests).</summary>
public interface IRemoteFiles
{
    IRemoteSession Connect(string host, SmbCreds creds, int timeoutSeconds);
}

/// <summary>The remote Service Control Manager operations the collector and the deployment need.</summary>
public interface IServiceControl
{
    /// <summary>Create, start and delete a temporary LocalSystem service <paramref name="serviceName"/> running
    /// <paramref name="command"/>. Returns once the process was launched; throws if it could not be created / started.</summary>
    void RunCommand(string host, SmbCreds creds, string command, string serviceName);

    /// <summary>Make sure the service does not exist: "absent" (never was / already gone) or "removed" (stopped and
    /// deleted now). Throws if it stays.</summary>
    string RemoveService(string host, SmbCreds creds, string serviceName);

    /// <summary>Stop the still running script of run <paramref name="tag"/> through one more short-lived service.</summary>
    void KillScript(string host, SmbCreds creds, string tag);
}

/// <summary>Monotonic time and sleeping, swappable so the polling loops are testable instantly.</summary>
public interface IClock
{
    TimeSpan Elapsed { get; }
    void Sleep(TimeSpan duration);
}

public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();
    private readonly Stopwatch _watch = Stopwatch.StartNew();
    public TimeSpan Elapsed => _watch.Elapsed;
    public void Sleep(TimeSpan duration) => Thread.Sleep(duration);
}

/// <summary>Everything the PDQ-style flows need from the platform.</summary>
public sealed record PdqBackend(IRemoteFiles Files, IServiceControl Services, IClock Clock)
{
    /// <summary>The native Windows backend (SMB through UNC paths, the SCM through advapi32).</summary>
    [SupportedOSPlatform("windows")]
    public static PdqBackend Native() =>
        new(new NativeRemoteFiles(), new ScmServiceControl(new NativeScmApi(), NetConnection.OpenIpc), SystemClock.Instance);

    /// <summary><see cref="Native"/> on Windows; a clear <see cref="CollectError"/> elsewhere.</summary>
    public static PdqBackend Default() =>
        OperatingSystem.IsWindows() ? Native() : throw new CollectError("PDQ-style collection and deployment need Windows");
}

/// <summary>Outcome of the post-run self-check of one computer.</summary>
public sealed class CleanupReport(string host)
{
    public string Host { get; } = host;
    /// <summary>absent (nothing to do) | removed (was left behind) | failed</summary>
    public string Service { get; set; } = "absent";
    public List<string> FilesRemoved { get; set; } = [];
    public List<string> FilesLeft { get; set; } = [];
    public bool ProcessKilled { get; set; }
    public List<string> Errors { get; set; } = [];

    /// <summary>Nothing is left on the computer.</summary>
    public bool Clean => Service != "failed" && FilesLeft.Count == 0 && Errors.Count == 0;

    /// <summary>The check found leftovers and cleaned them up.</summary>
    public bool Acted => Service == "removed" || FilesRemoved.Count > 0 || ProcessKilled;
}

// ======================================================================================= validation
/// <summary>Validation of the values that end up in remote paths and service command lines.</summary>
public static partial class Remote
{
    // labels of letters (any script: AD allows "KÖNYVELÉS-PC"), digits, '_' and '-'; a label never starts with '-' (so a
    // name can never look like a command-line switch), but may end with one (Windows accepts "PC-")
    [GeneratedRegex(@"\A(?=.{1,253}\z)[\p{L}\p{N}_][\p{L}\p{N}_-]{0,62}(?:\.[\p{L}\p{N}_][\p{L}\p{N}_-]{0,62})*\.?\z")]
    private static partial Regex HostName();

    /// <summary>A DNS / NetBIOS host name (letters of any script) or an IP address; anything else (spaces, quotes, slashes, '%', '&amp;', '$'...)
    /// is refused before it reaches a UNC path, an SCM call or a remoting request.</summary>
    public static bool IsValidHost(string? host)
    {
        var h = host ?? "";
        if (h.Length == 0 || h.Length > 253) return false;
        if (Kerberos.IsIpAddress(h)) return !h.Contains('%') && !h.Contains('/');
        return HostName().IsMatch(h);
    }

    public static string ValidateHost(string? host) =>
        IsValidHost(host) ? host! : throw new CollectError($"'{host}' is not a valid computer name");

    [GeneratedRegex(@"^[0-9a-f]{12}$")]
    private static partial Regex TagPattern();

    public static bool IsValidTag(string? tag) => TagPattern().IsMatch(tag ?? "");

    /// <summary>A new unpredictable run tag (48 random bits, lower-case hex).</summary>
    public static string NewTag() => RandomNumberGenerator.GetHexString(12, lowercase: true);

    [GeneratedRegex(@"^ADmiral\\(?<t>[0-9a-f]{12})\\admiral-\k<t>(?:-inst|-user|-f\d{1,3})?\.[a-z0-9]{1,8}$")]
    private static partial Regex SharePathPattern();

    [GeneratedRegex(@"^ADmiral\\[0-9a-f]{12}$")]
    private static partial Regex ShareDirPattern();

    /// <summary>Only the files these flows create may be touched on a target:
    /// <c>ADmiral\&lt;tag&gt;\admiral-&lt;tag&gt;[-inst].&lt;ext&gt;</c>.</summary>
    public static string ValidateSharePath(string sharePath) =>
        SharePathPattern().IsMatch(sharePath ?? "") ? sharePath! : throw new ArgumentException($"refused remote path '{sharePath}'");

    /// <summary>Only a run folder <c>ADmiral\&lt;tag&gt;</c> may be created / removed on a target.</summary>
    public static string ValidateShareDir(string shareDir) =>
        ShareDirPattern().IsMatch(shareDir ?? "") ? shareDir! : throw new ArgumentException($"refused remote folder '{shareDir}'");

    [GeneratedRegex(@"^ADmiral_k?[0-9a-f]{10,12}$")]
    private static partial Regex ServiceNamePattern();

    public static string ValidateServiceName(string name) =>
        ServiceNamePattern().IsMatch(name ?? "") ? name! : throw new ArgumentException($"refused service name '{name}'");
}

// ======================================================================================= orchestration
/// <summary>PDQ Inventory-style agentless collection over SMB + the Service Control Manager (ported from admiral/pdq.py).
/// <para>Per computer: connect to <c>ADMIN$</c> with the administrative account; drop the read-only inventory script
/// (<see cref="Collector.CombinedScript"/>) into a new run folder <c>C:\Windows\ADmiral\&lt;tag&gt;</c> (SYSTEM and
/// Administrators only, never <c>C:\Windows\Temp</c>, which every user can write); run it once as LocalSystem through a temporary
/// service; read the output back; delete the files; then, on a fresh connection, a self-check verifies that the service
/// and every file are gone and removes / stops whatever is left.</para>
/// <para>Names are unpredictable (<c>admiral-&lt;48 random bits&gt;</c>, service <c>ADmiral_&lt;same&gt;</c>), and the
/// service command line is built only from constants and that validated tag: no host name, user input or remote data is
/// ever part of it.</para></summary>
public static class Pdq
{
    public const string Share = "ADMIN$";
    /// <summary>The share's folder on the target (<c>ADMIN$</c> = <c>C:\Windows</c>).</summary>
    public const string RemoteRoot = @"C:\Windows";
    /// <summary>Parent of the per-run folders, relative to the share.</summary>
    public const string ShareDir = "ADmiral";
    public const string ServiceDisplay = "ADmiral inventory";

    /// <summary>Largest stderr file read back for an error message.</summary>
    public const long MaxErrBytes = 64 * 1024;

    /// <summary>UTF-8 with a BOM: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.</summary>
    public static byte[] ScriptBytes(string script) => [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(script)];

    public static string SharePath(string tag, string suffix) => Remote.ValidateSharePath($@"{ShareDir}\{tag}\admiral-{tag}{suffix}");

    /// <summary>The run folder of <paramref name="tag"/>, relative to the share: <c>ADmiral\&lt;tag&gt;</c>.</summary>
    public static string RunDir(string tag) => Remote.ValidateShareDir($@"{ShareDir}\{tag}");

    /// <summary>A share path (file or run folder) as a local path on the target.</summary>
    public static string RemotePath(string sharePath) => $@"{RemoteRoot}\{sharePath}";

    /// <summary>The service command of a collection run. <c>start /B</c> detaches PowerShell from the "service" (the SCM
    /// kills a process that does not report back within ~30 s); PowerShell writes to a .tmp file that is renamed to .out
    /// only after it exited, so .out never exists half-written.</summary>
    public static string CollectCommand(string tag)
    {
        if (!Remote.IsValidTag(tag)) throw new ArgumentException("invalid tag", nameof(tag));
        var ps = RemotePath(SharePath(tag, ".ps1"));
        var tmp = RemotePath(SharePath(tag, ".tmp"));
        var err = RemotePath(SharePath(tag, ".err"));
        var inner = $"powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"{ps}\" " +
                    $"> \"{tmp}\" 2> \"{err}\" < nul & ren \"{tmp}\" admiral-{tag}.out";
        return StartIn(tag, inner);
    }

    /// <summary><c>start /B</c> of <paramref name="inner"/> with the run folder as the working directory (never
    /// System32 / Temp: nothing a user can write is on the process's DLL / file search path).</summary>
    public static string StartIn(string tag, string inner) =>
        $"%COMSPEC% /Q /C start \"\" /D \"{RemotePath(RunDir(tag))}\" /B %COMSPEC% /S /Q /C \"{inner}\"";

    /// <summary>Create the run folder (protected DACL) on the open session.</summary>
    internal static void MakeRunDir(IRemoteSession sess, string tag) => sess.CreatePrivateDir(RunDir(tag));

    /// <summary>Remove the run folder (best effort: the self-check retries).</summary>
    internal static void RemoveRunDir(IRemoteSession sess, string tag)
    {
        try { sess.DeleteDir(RunDir(tag)); }
        catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "PDQ: could not remove the run folder"); }
    }

    /// <summary>Service command that stops the (still running) script of this run, and only it. The script is passed
    /// as -EncodedCommand, so the binary path holds no quotes of its own.</summary>
    public static string KillCommand(string tag)
    {
        if (!Remote.IsValidTag(tag)) throw new ArgumentException("invalid tag", nameof(tag));
        var ps = "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | " +
                 $"Where-Object {{ $_.CommandLine -like '*admiral-{tag}*' -and $_.ProcessId -ne $PID }} | " +
                 "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }";
        var enc = Convert.ToBase64String(Encoding.Unicode.GetBytes(ps));
        return "%COMSPEC% /Q /C start \"\" /B powershell.exe -NonInteractive -NoProfile " +
               $"-ExecutionPolicy Bypass -EncodedCommand {enc}";
    }

    /// <summary>Collect inventory from <paramref name="host"/> the PDQ way. Throws <see cref="CollectError"/> on failure.
    /// The self-check runs (and reports through <paramref name="onCleanup"/>) only if the service was actually started,
    /// whether the collection succeeded or not; its own failure never breaks the result.</summary>
    public static JsonObject Collect(string host, SmbCreds creds, CollectSettings? cfg = null, PdqBackend? backend = null,
                                     Action<CleanupReport>? onCleanup = null, string? bitlockerKey = null)
    {
        cfg ??= new CollectSettings();
        Remote.ValidateHost(host);
        backend ??= PdqBackend.Default();
        var tag = Remote.NewTag();
        var svc = $"ADmiral_{tag}";
        string psShare = SharePath(tag, ".ps1"), outShare = SharePath(tag, ".out"), errShare = SharePath(tag, ".err"),
               tmpShare = SharePath(tag, ".tmp");
        string[] files = [outShare, tmpShare, errShare, psShare];

        IRemoteSession sess;
        try
        {
            sess = backend.Files.Connect(host, creds, cfg.SmbTimeout);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            throw new CollectError($"SMB {exc.GetType().Name}: {exc.Message}", exc);
        }

        var started = false;
        JsonObject result;
        try
        {
            try
            {
                MakeRunDir(sess, tag);
                sess.PutFile(psShare, ScriptBytes(Collector.CombinedScript(bitlockerKey)));
                backend.Services.RunCommand(host, creds, CollectCommand(tag), svc);
                started = true;                     // the self-check applies from here on
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                throw exc as CollectError ?? new CollectError($"{exc.GetType().Name}: {exc.Message}", exc);
            }
            try
            {
                result = ReadResult(sess, outShare, cfg.ResponseTimeout, backend.Clock);
            }
            catch (CollectError exc)
            {
                throw new CollectError($"{exc.Message}; {RemoteState(sess, psShare, outShare, tmpShare, errShare)}", exc);
            }
            Collector.LogScriptErrors(host, "pdq", result);
        }
        finally
        {
            foreach (var path in files)
            {
                try { sess.DeleteFile(path); }
                catch (Exception exc) when (exc is not OutOfMemoryException)
                {
                    Log.Logger.LogDebug(exc, "PDQ: could not delete a file");   // the self-check picks it up
                }
            }
            RemoveRunDir(sess, tag);
            try { sess.Dispose(); }
            catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "PDQ: ignored error"); }
            if (started) RunSelfCheck(backend, host, creds, svc, tag, files, cfg, onCleanup);
        }
        if (result.Count == 0) throw new CollectError("empty inventory from the remote script");
        return Collector.Normalize(result);
    }

    /// <summary>What the target holds after a failed run (script / output present? what PowerShell wrote to stderr?).</summary>
    internal static string RemoteState(IRemoteSession sess, string psShare, string outShare, string tmpShare, string errShare)
    {
        var parts = new List<string>();
        foreach (var (label, path) in new[] { ("script", psShare), ("output", outShare), ("running-output", tmpShare) })
        {
            try { parts.Add($"{label} file {(sess.FileExists(path) ? "present" : "missing")}"); }
            catch (Exception exc) when (exc is not OutOfMemoryException) { parts.Add($"{label} file ? ({exc.GetType().Name}: {Cut(exc.Message, 160)})"); }
        }
        try
        {
            var err = Encoding.UTF8.GetString(sess.ReadFile(errShare, MaxErrBytes)).Trim();
            parts.Add(err.Length > 0 ? $"PowerShell stderr: '{Cut(err, 500)}'" : "PowerShell stderr empty");
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            parts.Add($"stderr file unreadable ({exc.GetType().Name}: {Cut(exc.Message, 160)})");
        }
        return string.Join("; ", parts);
    }

    internal static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    /// <summary>Poll the output file until it holds a complete, decodable record; missing / locked / partial output is
    /// retried until the deadline.</summary>
    internal static JsonObject ReadResult(IRemoteSession sess, string sharePath, int timeoutSeconds, IClock clock)
    {
        var deadline = clock.Elapsed + TimeSpan.FromSeconds(Math.Max(5, timeoutSeconds));
        Exception? last = null;
        while (clock.Elapsed < deadline)
        {
            try
            {
                var data = sess.ReadFile(sharePath, Collector.MaxOutputBytes);
                if (data.Length > 0 && Encoding.ASCII.GetString(data).Trim().Length > 0) return Collector.DecodeOutput(data);
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                last = exc;                       // not written yet / locked / incomplete
            }
            clock.Sleep(TimeSpan.FromSeconds(1));
        }
        throw new CollectError($"no valid output within {timeoutSeconds}s" + (last is null ? "" : $" ({last.GetType().Name}: {last.Message})"));
    }

    // ----------------------------------------------------------------------------------- self-check
    internal static void RunSelfCheck(PdqBackend backend, string host, SmbCreds creds, string svc, string tag,
                                      IReadOnlyList<string> files, CollectSettings cfg, Action<CleanupReport>? onCleanup)
    {
        CleanupReport report;
        try
        {
            report = SelfCheck(backend, host, creds, svc, tag, files, cfg);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            report = new CleanupReport(host) { Service = "failed", Errors = [$"{exc.GetType().Name}: {exc.Message}"] };
        }
        var level = report.Clean && !report.Acted ? LogLevel.Information : LogLevel.Warning;
        if (Log.Logger.IsEnabled(level))
            Log.Logger.Log(level, "PDQ {Host}: self-check: service={Service}, files removed=[{Removed}], left=[{Left}], process killed={Killed}{Errors}",
            host, report.Service, string.Join(", ", report.FilesRemoved), string.Join(", ", report.FilesLeft), report.ProcessKilled,
            report.Errors.Count > 0 ? ", errors=" + string.Join(" | ", report.Errors) : "");
        if (onCleanup is null) return;
        try { onCleanup(report); }
        catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogError(exc, "PDQ {Host}: cleanup report handler failed", host); }
    }

    /// <summary>Verify, on a fresh connection, that nothing of this run is left on <paramref name="host"/>; fix what is:
    /// 1. the temporary service must not exist (stopped and deleted if it does);
    /// 2. the files must not exist (deleted if they do);
    /// 3. a file that cannot be deleted is held open by the still running script: that process is stopped and the file
    ///    deleted again.</summary>
    public static CleanupReport SelfCheck(PdqBackend backend, string host, SmbCreds creds, string svc, string tag,
                                          IReadOnlyList<string> files, CollectSettings cfg)
    {
        var rep = new CleanupReport(host);
        if (cfg.CleanupDelay > 0) backend.Clock.Sleep(TimeSpan.FromSeconds(cfg.CleanupDelay));
        try
        {
            rep.Service = backend.Services.RemoveService(host, creds, svc);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            rep.Service = "failed";
            rep.Errors.Add($"service: {exc.GetType().Name}: {exc.Message}");
        }
        IRemoteSession sess;
        try
        {
            sess = backend.Files.Connect(host, creds, cfg.SmbTimeout);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            rep.Errors.Add($"SMB: {exc.GetType().Name}: {exc.Message}");
            return rep;
        }
        try
        {
            var present = files.Where(sess.FileExists).ToList();
            foreach (var p in present) TryDelete(sess, p);
            var stuck = present.Where(sess.FileExists).ToList();
            if (stuck.Count > 0)                    // locked => the script is still running
            {
                try
                {
                    backend.Services.KillScript(host, creds, tag);
                    rep.ProcessKilled = true;
                    backend.Clock.Sleep(TimeSpan.FromSeconds(3));
                }
                catch (Exception exc) when (exc is not OutOfMemoryException)
                {
                    rep.Errors.Add($"process: {exc.GetType().Name}: {exc.Message}");
                }
                foreach (var p in stuck) TryDelete(sess, p);
            }
            rep.FilesLeft = [.. files.Where(sess.FileExists)];
            rep.FilesRemoved = [.. present.Where(p => !rep.FilesLeft.Contains(p))];
            if (Remote.IsValidTag(tag))
            {
                var dir = RunDir(tag);
                if (sess.DirExists(dir))
                {
                    TryDeleteDir(sess, dir);
                    if (sess.DirExists(dir)) rep.FilesLeft.Add(dir);
                    else rep.FilesRemoved.Add(dir);
                }
            }
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            rep.Errors.Add($"files: {exc.GetType().Name}: {exc.Message}");
        }
        finally
        {
            try { sess.Dispose(); }
            catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "PDQ: ignored error"); }
        }
        return rep;
    }

    private static void TryDeleteDir(IRemoteSession sess, string dir)
    {
        try { sess.DeleteDir(dir); }
        catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "PDQ: ignored error"); }
    }

    private static void TryDelete(IRemoteSession sess, string path)
    {
        try { sess.DeleteFile(path); }
        catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "PDQ: ignored error"); }   // caller re-checks
    }

    // ----------------------------------------------------------------------------------- credentials
    /// <summary>SMB credentials from the (administrative) LDAP account ADmiral binds with.</summary>
    public static SmbCreds CredsFromLdap(LdapSettings ldap, string realm)
    {
        var user = (ldap.User ?? "").Trim();
        string domain, username;
        if (user.Contains('\\'))
        {
            var i = user.IndexOf('\\');
            (domain, username) = (user[..i], user[(i + 1)..]);
        }
        else if (user.Contains('@'))
        {
            var i = user.LastIndexOf('@');
            (username, domain) = (user[..i], user[(i + 1)..].Split('.')[0].ToUpperInvariant());
        }
        else
        {
            username = user;
            domain = string.IsNullOrEmpty(realm) ? "" : realm.Split('.')[0];
        }
        var kdc = ldap.Server ?? "";
        foreach (var prefix in new[] { "ldaps://", "ldap://" })
            if (kdc.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) kdc = kdc[prefix.Length..];
        return new SmbCreds(username, ldap.Password ?? "", domain, realm ?? "", kdc, UseKerberos: ldap.Auth != "simple",
                            NtlmFallback: ldap.NtlmFallback);
    }
}

// ======================================================================================= SCM logic
/// <summary>The raw advapi32 SCM calls (P/Invoke on Windows; a fake in tests). Error results are Win32 codes (0 = ok).</summary>
public interface IScmApi
{
    /// <summary>Open the target's SCM (throws <see cref="Win32Exception"/>).</summary>
    nint OpenManager(string host);
    /// <summary>Create a LocalSystem, demand-start, own-process service (throws <see cref="Win32Exception"/>).</summary>
    nint CreateService(nint scm, string name, string display, string binaryPath);
    int Start(nint service);
    /// <summary>The service handle, or 0 with <paramref name="error"/> set.</summary>
    nint OpenService(nint scm, string name, out int error);
    /// <summary>SERVICE_STATUS.dwCurrentState (1 = stopped) or throws.</summary>
    int QueryState(nint service);
    int Stop(nint service);
    int Delete(nint service);
    void Close(nint handle);
}

/// <summary>The create-start-delete / remove-and-verify logic on top of <see cref="IScmApi"/> (testable everywhere).</summary>
public sealed class ScmServiceControl(IScmApi api, Func<string, SmbCreds, IDisposable?>? connect = null) : IServiceControl
{
    public const int ErrorServiceDoesNotExist = 1060, ErrorServiceMarkedForDelete = 1072, ServiceStopped = 1;

    /// <summary>StartService errors that still mean "the process was launched": the command is not a real service, so
    /// the SCM reports a timeout (1053) or that the process ended (1067).</summary>
    public static readonly IReadOnlySet<int> StartedCodes = new HashSet<int> { 0, 1053, 1067 };

    private IDisposable? Connect(string host, SmbCreds creds) => connect?.Invoke(host, creds);

    public void RunCommand(string host, SmbCreds creds, string command, string serviceName)
    {
        Remote.ValidateHost(host);
        Remote.ValidateServiceName(serviceName);
        using var conn = Connect(host, creds);
        var scm = api.OpenManager(host);
        try
        {
            var svc = api.CreateService(scm, serviceName, Pdq.ServiceDisplay, command);
            int startError;
            try
            {
                startError = api.Start(svc);
                var del = api.Delete(svc);
                if (del != 0)
                    Log.Logger.LogWarning("PDQ {Host}: could not delete service {Name} now ({Error}); the self-check will",
                                          host, serviceName, new Win32Exception(del).Message);
            }
            finally
            {
                api.Close(svc);
            }
            if (!StartedCodes.Contains(startError))
                throw new CollectError($"the service did not start: {new Win32Exception(startError).Message} ({startError})");
        }
        finally
        {
            api.Close(scm);
        }
    }

    public string RemoveService(string host, SmbCreds creds, string serviceName)
    {
        Remote.ValidateHost(host);
        Remote.ValidateServiceName(serviceName);
        using var conn = Connect(host, creds);
        var scm = api.OpenManager(host);
        try
        {
            var svc = api.OpenService(scm, serviceName, out var err);
            if (svc == 0)
                return err == ErrorServiceDoesNotExist ? "absent" : throw new Win32Exception(err);
            try
            {
                if (api.QueryState(svc) != ServiceStopped) api.Stop(svc);   // not stoppable / already stopping: fine
                var del = api.Delete(svc);
                if (del != 0 && del != ErrorServiceMarkedForDelete) throw new Win32Exception(del);
            }
            finally
            {
                api.Close(svc);
            }
            // verify: a service marked for deletion disappears once the last handle is closed
            var again = api.OpenService(scm, serviceName, out err);
            if (again == 0)
                return err is ErrorServiceDoesNotExist or ErrorServiceMarkedForDelete ? "removed" : throw new Win32Exception(err);
            api.Close(again);
            throw new CollectError($"service {serviceName} is still present after deleting it");
        }
        finally
        {
            api.Close(scm);
        }
    }

    public void KillScript(string host, SmbCreds creds, string tag) =>
        RunCommand(host, creds, Pdq.KillCommand(tag), "ADmiral_k" + RandomNumberGenerator.GetHexString(10, lowercase: true));
}

// ======================================================================================= native Windows
/// <summary>A WNetAddConnection2 connection to <c>\\host\share</c> with explicit credentials, cancelled on dispose.
/// The password goes straight to the API (never a command line); nothing is persisted (no CONNECT_UPDATE_PROFILE).</summary>
[SupportedOSPlatform("windows")]
public sealed class NetConnection : IDisposable
{
    private const int ResourceTypeAny = 0, ResourceTypeDisk = 1;
    private const int ErrorSessionCredentialConflict = 1219;
    private readonly string _remote;
    private bool _open;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
    private static extern int WNetAddConnection2(NetResource resource, string? password, string? username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
    private static extern int WNetCancelConnection2(string name, int flags, [MarshalAs(UnmanagedType.Bool)] bool force);

    private NetConnection(string remote) => _remote = remote;

    /// <summary>Connect to <c>\\host\share</c>; null when <paramref name="creds"/> carry no password (the current logon
    /// session is used then).</summary>
    public static NetConnection? Open(string host, string share, SmbCreds creds)
    {
        Remote.ValidateHost(host);
        if (share is not ("ADMIN$" or "IPC$")) throw new ArgumentException("unexpected share", nameof(share));
        if (creds.UseKerberos && !creds.NtlmFallback) Kerberos.RequireFqdn(host, "SMB target");   // IP + no fallback: clear error
        if (!creds.HasExplicitCredential) return null;
        var remote = $@"\\{host}\{share}";
        var res = new NetResource { Type = share == "IPC$" ? ResourceTypeAny : ResourceTypeDisk, RemoteName = remote };
        var rc = WNetAddConnection2(res, creds.Password, creds.Account, 0);
        if (rc == ErrorSessionCredentialConflict)
            throw new Win32Exception(rc, $"{remote}: this Windows session already has a connection to {host} with other " +
                                         "credentials (close it, e.g. 'net use', or run ADmiral as the administrative account)");
        if (rc != 0) throw new Win32Exception(rc, $"{remote}: {new Win32Exception(rc).Message}");
        return new NetConnection(remote) { _open = true };
    }

    public static IDisposable? OpenIpc(string host, SmbCreds creds) => Open(host, "IPC$", creds);

    public void Dispose()
    {
        if (!_open) return;
        _open = false;
        WNetCancelConnection2(_remote, 0, true);
    }
}

/// <summary>SMB file access through UNC paths (<c>\\host\ADMIN$\Temp\...</c>).</summary>
[SupportedOSPlatform("windows")]
public sealed class NativeRemoteFiles : IRemoteFiles
{
    public IRemoteSession Connect(string host, SmbCreds creds, int timeoutSeconds)
    {
        Remote.ValidateHost(host);
        // the redirector's own timeouts are long; bound the connection attempt
        var task = Task.Run(() =>
        {
            var conn = NetConnection.Open(host, Pdq.Share, creds);
            try
            {
                var root = $@"\\{host}\{Pdq.Share}";
                if (!Directory.Exists(Path.Combine(root, "Temp")))     // C:\Windows\Temp: any administrator can see it
                    throw new IOException($@"{root} is not accessible (not an administrator, or the share is off)");
                return new NativeRemoteSession(root, conn);
            }
            catch
            {
                conn?.Dispose();
                throw;
            }
        });
        try
        {
            if (!task.Wait(TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds))))
            {
                // the attempt goes on in the background: close the connection if it still succeeds, and observe its
                // failure (otherwise the finalizer reports it as an "unobserved task exception" error)
                task.ContinueWith(t =>
                {
                    if (t.IsFaulted && Log.Logger.IsEnabled(LogLevel.Debug)) Log.Logger.LogDebug("SMB {Host}: the abandoned connection attempt failed: {Error}", host, t.Exception?.InnerException?.Message);
                    else if (t.IsCompletedSuccessfully) t.Result.Dispose();
                    _ = t.Exception;                       // observed, whatever the log level
                }, TaskScheduler.Default);
                throw new TimeoutException($"SMB connection to {host} timed out after {timeoutSeconds}s");
            }
        }
        catch (AggregateException agg) when (agg.InnerException is { } inner)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw();
        }
        return task.Result;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class NativeRemoteSession(string root, NetConnection? conn) : IRemoteSession
{
    private string Full(string sharePath) => $@"{root}\{Remote.ValidateSharePath(sharePath)}";

    private string FullDir(string shareDir) => $@"{root}\{Remote.ValidateShareDir(shareDir)}";

    /// <summary>SYSTEM + Administrators full control, protected (nothing inherited from C:\Windows).</summary>
    private static System.Security.AccessControl.DirectorySecurity PrivateAcl()
    {
        var sec = new System.Security.AccessControl.DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const System.Security.AccessControl.InheritanceFlags inherit =
            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WinSec.SystemSid, WinSec.AdminsSid })
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),
                System.Security.AccessControl.FileSystemRights.FullControl, inherit, System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
        return sec;
    }

    public void CreatePrivateDir(string shareDir)
    {
        var dir = FullDir(shareDir);
        var parent = new DirectoryInfo(Path.GetDirectoryName(dir)!);
        if (!parent.Exists) parent.Create(PrivateAcl());
        else if ((parent.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"{parent.FullName} is a link; refusing to use it");
        var d = new DirectoryInfo(dir);
        if (d.Exists) throw new IOException($"{dir} already exists");
        d.Create(PrivateAcl());                          // created with the DACL (no moment with inherited rights)
    }

    public void DeleteDir(string shareDir)
    {
        var dir = FullDir(shareDir);
        if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);   // our own folder; links inside are not followed
    }

    public bool DirExists(string shareDir) => Directory.Exists(FullDir(shareDir));

    public void PutFile(string sharePath, byte[] data)
    {
        using var f = new FileStream(Full(sharePath), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        f.Write(data);
    }

    public void PutLocal(string sharePath, Stream src, Action<long, long>? progress = null)
    {
        using var dst = new FileStream(Full(sharePath), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
        var total = src.CanSeek ? src.Length : 0;
        var buf = new byte[1 << 20];
        long sent = 0;
        int n;
        while ((n = src.Read(buf, 0, buf.Length)) > 0)
        {
            dst.Write(buf, 0, n);
            sent += n;
            progress?.Invoke(sent, total);
        }
        if (total == 0) progress?.Invoke(0, 0);
    }

    public byte[] ReadFile(string sharePath, long maxBytes)
    {
        // the script may still hold the file open for writing: allow concurrent writers
        using var f = new FileStream(Full(sharePath), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (f.Length > maxBytes) throw new IOException($"{sharePath} is larger than {maxBytes} bytes");
        var buf = new byte[f.Length];
        f.ReadExactly(buf);
        return buf;
    }

    public void DeleteFile(string sharePath)
    {
        var p = Full(sharePath);
        if (File.Exists(p)) File.Delete(p);
    }

    public bool FileExists(string sharePath) => File.Exists(Full(sharePath));

    public void Dispose() => conn?.Dispose();
}

/// <summary>advapi32 Service Control Manager calls.</summary>
[SupportedOSPlatform("windows")]
public sealed class NativeScmApi : IScmApi
{
    private const int ScManagerConnect = 0x1, ScManagerCreateService = 0x2;
    private const int ServiceWin32OwnProcess = 0x10, ServiceDemandStart = 3, ServiceErrorIgnore = 0;
    private const int ServiceQueryStatus = 0x4, ServiceStart = 0x10, ServiceStop = 0x20, DeleteAccess = 0x10000;
    private const int ServiceControlStop = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern nint OpenSCManager(string machine, string? database, int access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateServiceW")]
    private static extern nint CreateServiceNative(nint scm, string name, string display, int access, int type, int start,
        int errorControl, string binaryPath, string? loadOrderGroup, nint tagId, string? dependencies, string? account, string? password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW")]
    private static extern nint OpenServiceNative(nint scm, string name, int access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "StartServiceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceNative(nint service, int argc, nint argv);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(nint service, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(nint service, int control, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(nint service);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint handle);

    public nint OpenManager(string host)
    {
        var h = OpenSCManager($@"\\{Remote.ValidateHost(host)}", null, ScManagerConnect | ScManagerCreateService);
        return h != 0 ? h : throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public nint CreateService(nint scm, string name, string display, string binaryPath)
    {
        // account null = LocalSystem
        var h = CreateServiceNative(scm, Remote.ValidateServiceName(name), display, ServiceQueryStatus | ServiceStart | ServiceStop | DeleteAccess,
                                    ServiceWin32OwnProcess, ServiceDemandStart, ServiceErrorIgnore, binaryPath, null, 0, null, null, null);
        return h != 0 ? h : throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public int Start(nint service) => StartServiceNative(service, 0, 0) ? 0 : Marshal.GetLastWin32Error();

    public nint OpenService(nint scm, string name, out int error)
    {
        var h = OpenServiceNative(scm, Remote.ValidateServiceName(name), ServiceQueryStatus | ServiceStop | DeleteAccess);
        error = h == 0 ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    public int QueryState(nint service) =>
        QueryServiceStatus(service, out var st) ? st.CurrentState : throw new Win32Exception(Marshal.GetLastWin32Error());

    public int Stop(nint service) => ControlService(service, ServiceControlStop, out _) ? 0 : Marshal.GetLastWin32Error();

    int IScmApi.Delete(nint service) => DeleteService(service) ? 0 : Marshal.GetLastWin32Error();

    public void Close(nint handle)
    {
        if (handle != 0) CloseServiceHandle(handle);
    }
}
