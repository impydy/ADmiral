using System.ComponentModel;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python DeployError")]
public class DeployError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>The computer could not be connected to (timeout, unreachable): not an installer failure.</summary>
public sealed class Unreachable(string message, Exception? inner = null) : DeployError(message, inner);

/// <summary>Result of one installation.</summary>
public sealed record DeployResult(
    [property: JsonPropertyName("exit_code")] int? ExitCode,
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("seconds")] int? Seconds,
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("log")] string Log);

/// <summary>Software deployment (ported from admiral/deploy.py): copy an installer from the package library to a
/// computer and run it there silently as SYSTEM - agentless, over SMB + the Service Control Manager like the collector
/// in <see cref="Pdq"/>. Steps: connecting -> copying (byte progress) -> starting -> installing -> cleanup -> done.
/// <para><b>How the installer arguments are quoted</b> (they come from the administrator and are passed on, but can never
/// leave the intended command line):</para>
/// <list type="number">
/// <item><see cref="ValidArgs"/>: at most 500 characters, no control characters (line breaks become spaces).</item>
/// <item>The generated PowerShell script holds the arguments only inside a PowerShell <i>single-quoted</i> literal
/// (<see cref="Q"/>): no <c>$</c> variable expansion, no backtick escapes, no subexpressions. The only special characters
/// are the single quotes, and every one PowerShell recognises (<c>'</c> U+0027 and the typographic U+2018..U+201B) is
/// doubled, so the literal cannot be terminated from inside.</item>
/// <item>The literal goes to <c>Start-Process -FilePath &lt;installer | msiexec.exe&gt; -ArgumentList '&lt;args&gt;'</c>,
/// which hands the string to CreateProcess unchanged as the tail of the installer's command line. No cmd.exe is involved
/// (no <c>%VAR%</c> expansion, no <c>&amp;</c> / <c>|</c> / <c>&gt;</c>), so double quotes in the arguments
/// (<c>INSTALLDIR="C:\Program Files\X"</c>) are interpreted only by the installer's own parser - exactly as when the
/// administrator types them after the installer's name. For an MSI the tail is <c>/i "&lt;fixed path&gt;" &lt;args&gt;</c>.</item>
/// <item>The script is written as UTF-8 with BOM (Windows PowerShell 5.1 would read a BOM-less file as ANSI) and the
/// service command line that starts it contains only constants and the random run tag.</item>
/// </list></summary>
public static partial class Deploy
{
    public static readonly IReadOnlyList<string> Steps = ["queued", "connecting", "copying", "starting", "installing", "cleanup", "done"];
    public static readonly IReadOnlyDictionary<string, string> InstallerKinds = new Dictionary<string, string> { [".msi"] = "msi", [".exe"] = "exe" };
    public static readonly IReadOnlySet<int> RebootCodes = new HashSet<int> { 3010, 1641 };

    /// <summary>Common silent switches by installer type (shown as presets in the UI).</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Presets = new Dictionary<string, IReadOnlyList<string>>
    {
        ["msi"] = ["/qn /norestart"],
        ["exe"] = ["/S", "/silent", "/verysilent /norestart", "/quiet /norestart", "--silent"],
    };

    public const int MaxArgsLength = 500;
    public const long MaxResultBytes = 64 * 1024;
    public const long MaxLogBytes = 1024 * 1024;

    [GeneratedRegex(@"\b10060\b|timed out", RegexOptions.IgnoreCase)]
    private static partial Regex TimeoutText();

    /// <summary>Win32 / socket codes of "the computer is not there": bad network path, network / host unreachable, semaphore
    /// timeout, WSAETIMEDOUT, ETIMEDOUT, WSAEHOSTUNREACH.</summary>
    private static readonly HashSet<int> UnreachableCodes = [53, 121, 1231, 1232, 10060, 110, 10065];

    /// <summary>A connection attempt that timed out or found no computer (not an authentication or installer failure).</summary>
    public static bool IsUnreachable(Exception exc)
    {
        for (Exception? e = exc; e is not null; e = e.InnerException)
        {
            if (e is TimeoutException) return true;
            if (e is SocketException se && (UnreachableCodes.Contains(se.ErrorCode) || se.SocketErrorCode is SocketError.TimedOut
                                                or SocketError.HostUnreachable or SocketError.NetworkUnreachable)) return true;
            if (e is Win32Exception we && UnreachableCodes.Contains(we.NativeErrorCode)) return true;
            if (TimeoutText().IsMatch(e.Message)) return true;
        }
        return false;
    }

    public static string? InstallerKind(string filename) =>
        InstallerKinds.GetValueOrDefault(Path.GetExtension(filename ?? "").ToLowerInvariant());

    public static string DefaultArgs(string kind) => Presets.TryGetValue(kind, out var p) ? p[0] : "";

    /// <summary>ok | reboot (installed, restart needed) | failed</summary>
    public static string Classify(int? code) => code == 0 ? "ok" : code is { } c && RebootCodes.Contains(c) ? "reboot" : "failed";

    /// <summary>A PowerShell single-quoted string literal. Every quote character PowerShell accepts as a single quote is
    /// doubled (the typographic ones too: PowerShell would otherwise end the literal at them).</summary>
    public static string Q(string text)
    {
        var sb = new StringBuilder(text.Length + 2).Append('\'');
        foreach (var ch in text)
        {
            if (ch is '\'' or '\u2018' or '\u2019' or '\u201A' or '\u201B') sb.Append(ch);
            sb.Append(ch);
        }
        return sb.Append('\'').ToString();
    }

    [GeneratedRegex(@"[\x00-\x08\x0b-\x1f\x7f\u2028\u2029]")]
    private static partial Regex BadArgChars();

    /// <summary>Switches are free text, but control characters would break the generated script.</summary>
    public static string ValidArgs(string? args)
    {
        var a = (args ?? "").Trim();
        if (a.Length > MaxArgsLength || BadArgChars().IsMatch(a)) throw new DeployError("Invalid installer arguments.");
        return a;
    }

    /// <summary>PowerShell run on the target: start the installer, wait, write <c>{exit, error, seconds, installed,
    /// entries}</c> to <paramref name="out_"/> (through <paramref name="tmp"/>, renamed when complete).</summary>
    public static string InstallScript(string kind, string installer, string args, string run, string out_, string tmp)
    {
        args = (args ?? "").Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ').Trim();
        string file, arglist;
        if (kind == "msi")
            (file, arglist) = ("msiexec.exe", $"/i \"{installer}\" {args}".Trim());
        else
            (file, arglist) = (installer, args);
        // the installer runs in its own run folder (SYSTEM + Administrators only): nothing a user planted can be loaded
        var workDir = installer.Contains('\\') ? installer[..installer.LastIndexOf('\\')] : "";
        var start = $"Start-Process -FilePath {Q(file)} " + (workDir.Length > 0 ? $"-WorkingDirectory {Q(workDir)} " : "") +
                    (arglist.Length > 0 ? $"-ArgumentList {Q(arglist)} " : "") + "-Wait -PassThru -WindowStyle Hidden";
        const string snap = "function Snap { try { $k = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', " +
                            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; " +
                            "@(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | " +
                            "ForEach-Object { \"$($_.DisplayName) $($_.DisplayVersion)\" }) } catch { @() } }";
        return string.Join("\n",
            "$ErrorActionPreference = 'Stop'",
            $"Set-Content -LiteralPath {Q(run)} -Value 'started'",
            snap,
            "$before = @(Snap)",
            "$t0 = Get-Date; $code = $null; $err = ''",
            $"try {{ $p = {start}; $code = $p.ExitCode }} catch {{ $err = $_.Exception.Message }}",
            "$after = @(Snap)",
            "$new = @($after | Where-Object { $before -notcontains $_ } | Select-Object -First 15)",
            "$o = [ordered]@{ exit = $code; error = $err; seconds = [int]((Get-Date) - $t0).TotalSeconds; " +
            "installed = $new; entries = $after.Count } | ConvertTo-Json -Compress",
            $"[IO.File]::WriteAllText({Q(tmp)}, $o)",
            $"Move-Item -LiteralPath {Q(tmp)} -Destination {Q(out_)} -Force",
            "");
    }

    /// <summary>The local path of an installer of the library - always through <see cref="PackageLibrary.File"/> (no
    /// path outside the library) - checked to exist and, when <paramref name="expectedSha256"/> is given, to be unchanged.</summary>
    public static string ResolveInstaller(PackageLibrary library, string relPath, string? expectedSha256 = null)
    {
        string local;
        try
        {
            local = library.File(relPath);
        }
        catch (PackageError exc)
        {
            throw new DeployError(exc.Message, exc);
        }
        if (InstallerKind(local) is null) throw new DeployError($"{relPath} is not an .msi or .exe installer");
        if (!File.Exists(local)) throw new DeployError($"{relPath} is missing from the package library");
        if (!string.IsNullOrEmpty(expectedSha256)
            && !string.Equals(PackageLibrary.Sha256File(local), expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new DeployError(I18n.T("err.dep_hash", ("file", relPath)));
        return local;
    }

    /// <summary>Install <paramref name="relPath"/> of <paramref name="library"/> on <paramref name="host"/>. Reports
    /// <c>onStep(step, percent)</c>. Throws <see cref="Unreachable"/> when the computer cannot be reached and
    /// <see cref="DeployError"/> when the installer could not be run at all; an installer that ran and failed is a result
    /// with outcome "failed". <paramref name="timeoutSeconds"/> limits the installation (at least 30 s).</summary>
    public static DeployResult DeployOne(string host, SmbCreds creds, PackageLibrary library, string relPath, string kind, string args,
                                         CollectSettings cfg, Action<string, int?> onStep, int timeoutSeconds = 600,
                                         PdqBackend? backend = null, string? expectedSha256 = null)
    {
        var local = ResolveInstaller(library, relPath, expectedSha256);
        try
        {
            Remote.ValidateHost(host);
        }
        catch (CollectError exc)
        {
            throw new DeployError(exc.Message, exc);
        }
        if (kind is not ("msi" or "exe")) throw new DeployError($"unknown installer kind '{kind}'");
        args = ValidArgs(args);
        backend ??= DefaultBackend();

        var tag = Remote.NewTag();
        var svc = $"ADmiral_{tag}";
        var ext = Path.GetExtension(local).ToLowerInvariant();
        var names = new Dictionary<string, string>();
        foreach (var s in new[] { "ps1", "out", "tmp", "run", "log" }) names[s] = Pdq.SharePath(tag, "." + s);
        var instShare = Pdq.SharePath(tag, "-inst" + ext);
        var script = InstallScript(kind, Pdq.RemotePath(instShare), args, Pdq.RemotePath(names["run"]), Pdq.RemotePath(names["out"]),
                                   Pdq.RemotePath(names["tmp"]));
        var inner = $"powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"{Pdq.RemotePath(names["ps1"])}\" " +
                    $"> \"{Pdq.RemotePath(names["log"])}\" 2>&1 < nul";
        var command = Pdq.StartIn(tag, inner);
        string[] files = [instShare, .. names.Values];

        // one handle for the whole copy: nobody may change, rename or delete the installer while it is open
        // (FileShare.Read), and the SHA-256 is taken of exactly the bytes sent to the target
        FileStream source;
        try
        {
            source = new FileStream(local, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            throw new DeployError($"{relPath}: {exc.Message}", exc);
        }
        using var sourceHandle = source;

        onStep("connecting", null);
        IRemoteSession sess;
        try
        {
            sess = backend.Files.Connect(host, creds, cfg.SmbTimeout);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            if (IsUnreachable(exc)) throw new Unreachable($"SMB {exc.GetType().Name}: {exc.Message}", exc);
            throw new DeployError($"SMB {exc.GetType().Name}: {exc.Message}", exc);
        }

        var started = false;
        JsonObject result;
        var logText = "";
        try
        {
            try
            {
                var last = -1;
                onStep("copying", 0);
                Pdq.MakeRunDir(sess, tag);
                using (var hashing = new HashingReadStream(source))
                {
                    sess.PutLocal(instShare, hashing, (sent, total) =>
                    {
                        var pct = total > 0 ? (int)(sent * 100 / total) : 100;
                        if (pct == last) return;
                        last = pct;
                        onStep("copying", pct);
                    });
                    var sent = hashing.HashHex();
                    if (hashing.BytesRead != source.Length
                        || (!string.IsNullOrEmpty(expectedSha256) && !string.Equals(sent, expectedSha256, StringComparison.OrdinalIgnoreCase)))
                    {
                        Log.Logger.LogError("Deploy {Host}: the copied installer {File} does not match its registered SHA-256; aborted", host, relPath);
                        throw new DeployError(I18n.T("err.dep_hash", ("file", relPath)));
                    }
                }
                sess.PutFile(names["ps1"], Pdq.ScriptBytes(script));
                onStep("starting", null);
                backend.Services.RunCommand(host, creds, command, svc);
                started = true;
            }
            catch (Exception exc) when (exc is not OutOfMemoryException and not DeployError)
            {
                throw new DeployError($"{exc.GetType().Name}: {exc.Message}", exc);
            }

            onStep("starting", null);
            var clock = backend.Clock;
            var deadline = clock.Elapsed + TimeSpan.FromSeconds(Math.Max(30, timeoutSeconds));
            var seenRun = false;
            JsonObject? got = null;
            while (clock.Elapsed < deadline)
            {
                if (!seenRun)
                {
                    try { seenRun = sess.FileExists(names["run"]); }
                    catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Deploy: ignored error"); }
                    if (seenRun) onStep("installing", null);
                }
                try
                {
                    var data = sess.ReadFile(names["out"], MaxResultBytes);
                    if (data.Length > 0 && Encoding.UTF8.GetString(data).Trim().Length > 0)
                    {
                        got = Collector.ParseJson(data, 8) as JsonObject ?? throw new FormatException("not a JSON object");
                        break;
                    }
                }
                catch (Exception exc) when (exc is not OutOfMemoryException)
                {
                    Log.Logger.LogDebug(exc, "Deploy: no result yet");   // not written yet
                }
                clock.Sleep(TimeSpan.FromSeconds(1));
            }
            result = got ?? throw new DeployError($"the installer did not finish within {timeoutSeconds}s");
            try
            {
                var t = Encoding.UTF8.GetString(sess.ReadFile(names["log"], MaxLogBytes)).Trim();
                logText = t.Length > 1500 ? t[^1500..] : t;
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                Log.Logger.LogDebug(exc, "Deploy: no installer output");
            }
        }
        finally
        {
            onStep("cleanup", null);
            foreach (var path in files.Reverse())
            {
                try { sess.DeleteFile(path); }
                catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Deploy: could not delete a file"); }
            }
            Pdq.RemoveRunDir(sess, tag);
            try { sess.Dispose(); }
            catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Deploy: ignored error"); }
            if (started) Pdq.RunSelfCheck(backend, host, creds, svc, tag, files, cfg, null);
        }

        var code = Collector.Int(result["exit"]);
        var outcome = Classify(code);
        var err = (result["error"] is JsonValue erv && erv.GetValueKind() == JsonValueKind.String ? erv.GetValue<string>() : "").Trim();
        var installed = result["installed"] switch
        {
            JsonArray a => a.Select(x => x is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : x?.ToJsonString() ?? "")
                            .Where(s => s.Length > 0).ToList(),
            JsonValue v when v.GetValueKind() == JsonValueKind.String => [v.GetValue<string>()],
            _ => new List<string>(),
        };
        if (result.ContainsKey("entries"))             // the target reported its program list (before / after)
        {
            if (installed.Count > 0)
                logText = (logText.Length > 0 ? logText + "\n" : "") + "New or changed programs: " + string.Join("; ", installed);
            else if (outcome is "ok" or "reboot")
                logText = (logText.Length > 0 ? logText + "\n" : "") +
                          "NOTE: the installer reported success, but no new or changed program appeared in the registry " +
                          "(it may have installed nothing, or the same version was already there).";
        }
        var seconds = Collector.Int(result["seconds"]);
        return new DeployResult(code, outcome, seconds, err, logText);
    }

    private static PdqBackend DefaultBackend()
    {
        try
        {
            return PdqBackend.Default();
        }
        catch (CollectError exc)
        {
            throw new DeployError(exc.Message, exc);
        }
    }
}

/// <summary>A read-only pass-through stream that hashes (SHA-256) every byte read through it.</summary>
internal sealed class HashingReadStream(Stream inner) : Stream
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    public long BytesRead { get; private set; }

    public string HashHex() => Convert.ToHexStringLower(_hash.GetHashAndReset());

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var n = inner.Read(buffer);
        _hash.AppendData(buffer[..n]);
        BytesRead += n;
        return n;
    }

    public override bool CanRead => true;
    public override bool CanSeek => inner.CanSeek;              // Length only (for the progress total)
    public override bool CanWrite => false;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) _hash.Dispose();                         // the inner stream belongs to the caller
        base.Dispose(disposing);
    }
}
