using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>Result of one remote step (copy, delete, script, reboot ...) run as SYSTEM on a computer.</summary>
public sealed record RemoteRunResult(int? ExitCode, string Error, string Output, int? Seconds, string State = "");

/// <summary>Package chains: the steps of a package (<see cref="PackageStep"/>) run one after the other on each target
/// computer. The remote steps use the same agentless path as the installer (<see cref="Deploy"/>): the files go over SMB
/// into a protected run folder, a one-off service starts PowerShell as SYSTEM, the result is read back and everything
/// is removed.
/// <para>What the administrator types is never spliced into a command line: paths go into PowerShell single-quoted
/// literals (<see cref="Deploy.Q"/>), script text is written into its own file (<c>-user.ps1</c> / <c>-user.cmd</c>) that
/// is run as a file, and the computer name is validated like everywhere else.</para></summary>
public static partial class Chain
{
    public static readonly IReadOnlyList<string> StepTypes = ["install", "copy", "delete", "scan", "reboot", "shutdown", "wol", "powershell", "cmd", "wait", "message"];

    public const int MaxSteps = 50;
    public const int MaxScriptChars = 64 * 1024;
    public const int MaxOutputChars = 8000;
    /// <summary>reboot / shutdown: at least this delay, so the result can be written before Windows goes down.</summary>
    public const int MinPowerDelay = 15;
    public const int DefaultPowerDelay = 30;
    public const int DefaultWolWait = 300;
    public const int MaxWait = 4 * 3600;
    public const int DefaultWait = 60;
    public const int MaxMessageChars = 500;
    public const int DefaultMessageSeconds = 300;

    // C:\folder\file.ext - absolute, local drive, no wildcard / stream / control characters. Each segment is exactly
    // "\" + name, so the pattern matches in linear time (no nested optional quantifier to backtrack on). A time limit
    // guards it anyway.
    [GeneratedRegex(@"^[A-Za-z]:(?:\\[^\\/:*?""<>|\x00-\x1f]+)*$", RegexOptions.None, matchTimeoutMilliseconds: 200)]
    private static partial Regex LocalPathRe();

    private static readonly HashSet<string> DeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>A checked absolute local path on the target (copy destination / file to delete); <paramref name="minDepth"/>
    /// folders deep at least, so a drive root or a top folder cannot be named by mistake.</summary>
    public static string ValidLocalPath(string? path, int minDepth = 1)
    {
        var p = (path ?? "").Trim().TrimEnd('\\');
        bool shape;
        try { shape = p.Length is >= 3 and <= 240 && LocalPathRe().IsMatch(p); }
        catch (RegexMatchTimeoutException) { shape = false; }
        if (!shape) throw new ArgumentException(I18n.T("err.chain_path", ("path", path ?? "")));
        var parts = p[3..].Split('\\');
        // no empty, "." / ".." or blank segment, no segment Windows would silently trim (trailing dot / space), no device name
        if (parts.Any(s => s.Trim().Trim('.').Length == 0 || s != s.TrimEnd('.', ' ') || s != s.TrimStart(' ')
                           || DeviceNames.Contains(s.Split('.')[0].Trim()))
            || parts.Length < minDepth)
            throw new ArgumentException(I18n.T("err.chain_path", ("path", path ?? "")));
        return p;
    }

    private static string ValidScript(string? script)
    {
        var s = (script ?? "").Replace("\r\n", "\n");
        if (s.Trim().Length == 0) throw new ArgumentException(I18n.T("err.chain_script"));
        if (s.Length > MaxScriptChars || s.Contains('\0')) throw new ArgumentException(I18n.T("err.chain_script"));
        return s;
    }

    /// <summary>The message text: one paragraph of at most <see cref="MaxMessageChars"/>; line breaks become spaces,
    /// control characters and double quotes (they would break msg.exe's command line) are replaced, and it never starts
    /// with '/' or '-' (msg.exe would take it for one of its options, e.g. /SERVER:).</summary>
    public static string ValidMessage(string? text)
    {
        var sb = new StringBuilder();
        foreach (var ch in (text ?? "").Replace("\r\n", "\n"))
            sb.Append(ch is '\n' or '\t' ? ' ' : ch == '"' ? '\'' : char.IsControl(ch) || ch is '\u2028' or '\u2029' ? ' ' : ch);
        var t = string.Join(' ', sb.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries)).TrimEnd('\\', ' ').TrimStart('/', '-', ' ');
        if (t.Length == 0 || t.Length > MaxMessageChars) throw new ArgumentException(I18n.T("err.chain_message", ("n", MaxMessageChars)));
        return t;
    }

    /// <summary>The cleaned chain of <paramref name="entry"/>: every step checked, unknown fields dropped. Files must belong
    /// to the package or - with <paramref name="library"/> - to any package of the library (an installation chain uses
    /// the library's files); install needs an .msi / .exe or a Windows update (.msu / .cab). Throws
    /// <see cref="ArgumentException"/> naming the bad step.</summary>
    public static List<PackageStep> ValidateSteps(PackageEntry entry, IEnumerable<PackageStep?>? steps, IEnumerable<PackageEntry>? library = null)
    {
        var lib = library?.ToList() ?? [];
        var list = (steps ?? []).ToList();
        if (list.Count > MaxSteps) throw new ArgumentException(I18n.T("err.chain_many", ("n", MaxSteps)));
        var outp = new List<PackageStep>();
        for (var i = 0; i < list.Count; i++)
        {
            var s = list[i] ?? throw new ArgumentException(I18n.T("err.chain_step", ("n", i + 1), ("why", "empty")));
            try
            {
                outp.Add(Clean(entry, lib, s));
            }
            catch (ArgumentException exc)
            {
                throw new ArgumentException(I18n.T("err.chain_step", ("n", i + 1), ("why", exc.Message)), exc);
            }
        }
        return outp;
    }

    /// <summary>The file of a step: one of the package's own, else one of the library's (never a chain's).</summary>
    public static PackageFile? FindFile(PackageEntry entry, IEnumerable<PackageEntry> library, string? path) =>
        entry.Files.FirstOrDefault(x => x.Path == path)
        ?? library.Where(p => p.Kind != "chain").SelectMany(p => p.Files).FirstOrDefault(x => x.Path == path);

    private static PackageStep Clean(PackageEntry entry, List<PackageEntry> library, PackageStep s)
    {
        var type = (s.Type ?? "").Trim().ToLowerInvariant();
        if (!StepTypes.Contains(type)) throw new ArgumentException($"unknown step type '{s.Type}'");
        var c = new PackageStep { Type = type, ContinueOnError = s.ContinueOnError == true ? true : null };
        PackageFile File()
        {
            var f = FindFile(entry, library, s.File);
            return f ?? throw new ArgumentException(I18n.T("err.chain_file", ("file", s.File ?? "")));
        }
        switch (type)
        {
            case "install":
                var inst = File();
                c.File = inst.Path;
                if (WinUpdate.IsUpdateFile(inst.Path)) break;                    // a Windows update: no switches
                if (Deploy.InstallerKind(inst.Path) is null) throw new ArgumentException(I18n.T("err.dep_file"));
                try { c.Args = Deploy.ValidArgs(s.Args); }
                catch (DeployError exc) { throw new ArgumentException(exc.Message, exc); }
                break;
            case "copy":
                c.File = File().Path;
                c.Path = ValidLocalPath(s.Path);
                break;
            case "delete":
                c.Path = ValidLocalPath(s.Path, minDepth: 2);
                break;
            case "powershell":
            case "cmd":
                c.Script = ValidScript(s.Script);
                break;
            case "reboot":
            case "shutdown":
                c.Seconds = Math.Clamp(s.Seconds ?? DefaultPowerDelay, MinPowerDelay, 3600);
                if (type == "reboot") c.Wait = s.Wait != false;
                break;
            case "wol":
                c.Seconds = Math.Clamp(s.Seconds ?? DefaultWolWait, 0, 3600);
                break;
            case "wait":
                c.Seconds = Math.Clamp(s.Seconds ?? DefaultWait, 1, MaxWait);
                break;
            case "message":
                c.Text = ValidMessage(s.Text);
                c.Seconds = Math.Clamp(s.Seconds ?? DefaultMessageSeconds, 10, 86400);
                break;
        }
        return c;
    }

    /// <summary>One line describing the step (the deployment list / log).</summary>
    public static string Describe(PackageStep s) => s.Type switch
    {
        "install" => $"install {System.IO.Path.GetFileName(s.File)}" + (string.IsNullOrEmpty(s.Args) ? "" : $" {s.Args}")
                     + (WinUpdate.IsUpdateFile(s.File) ? " (Windows update, DISM)" : ""),
        "wait" => $"wait {s.Seconds}s",
        "message" => $"message to the logged-on users ({s.Seconds}s): {FirstLine(s.Text)}",
        "copy" => $"copy {System.IO.Path.GetFileName(s.File)} -> {s.Path}",
        "delete" => $"delete {s.Path}",
        "reboot" => $"reboot in {s.Seconds}s" + (s.Wait == true ? " and wait" : ""),
        "shutdown" => $"shutdown in {s.Seconds}s",
        "wol" => $"wake on LAN (wait {s.Seconds}s)",
        "powershell" or "cmd" => $"{s.Type}: {FirstLine(s.Script)}",
        _ => s.Type,
    } + (s.ContinueOnError == true ? " [continue on error]" : "");

    private static string FirstLine(string? text)
    {
        var l = (text ?? "").Split('\n').Select(x => x.Trim()).FirstOrDefault(x => x.Length > 0) ?? "";
        return l.Length > 60 ? l[..60] + "…" : l;
    }

    // ------------------------------------------------------------------ Wake on LAN
    [GeneratedRegex(@"^[0-9A-Fa-f]{2}([-:]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$")]
    private static partial Regex MacRe();

    /// <summary>The 102-byte magic packet for <paramref name="mac"/> (6 × 0xFF, then the MAC 16 times); null for a bad MAC.</summary>
    public static byte[]? MagicPacket(string? mac)
    {
        var m = (mac ?? "").Trim();
        if (!MacRe().IsMatch(m)) return null;
        var hex = m.Replace("-", "").Replace(":", "");
        var bytes = Convert.FromHexString(hex);
        if (bytes.All(b => b == 0) || bytes.All(b => b == 0xFF)) return null;
        var packet = new byte[102];
        for (var i = 0; i < 6; i++) packet[i] = 0xFF;
        for (var r = 0; r < 16; r++) bytes.CopyTo(packet, 6 + r * 6);
        return packet;
    }

    /// <summary>Where the magic packet is sent: the limited broadcast, plus the computer's /24 directed broadcast when its
    /// last IPv4 address is known (routers may forward that one to the computer's subnet).</summary>
    public static List<string> WolAddresses(string? lastIp)
    {
        var outp = new List<string> { "255.255.255.255" };
        if (Ipv4.TryParse(lastIp ?? "", out _))
        {
            var parts = lastIp!.Trim().Split('.');
            var directed = $"{parts[0]}.{parts[1]}.{parts[2]}.255";
            if (!outp.Contains(directed)) outp.Add(directed);
        }
        return outp;
    }

    // ------------------------------------------------------------------ the PowerShell run on the target
    /// <summary>Common frame: mark the start, run <paramref name="body"/> (it sets $code / $out, or throws), write
    /// <c>{exit, error, seconds, output}</c> through <paramref name="tmp"/> to <paramref name="out_"/>.</summary>
    private static string Frame(string body, string run, string out_, string tmp) => string.Join("\n",
        "$ErrorActionPreference = 'Stop'",
        $"Set-Content -LiteralPath {Deploy.Q(run)} -Value 'started'",
        "$t0 = Get-Date; $code = $null; $err = ''; $out = ''",
        "try {",
        body,
        "} catch { $err = $_.Exception.Message; if ($code -eq $null) { $code = 1 } }",
        $"if ($out.Length -gt {MaxOutputChars}) {{ $out = $out.Substring($out.Length - {MaxOutputChars}) }}",
        "$o = [ordered]@{ exit = $code; error = $err; seconds = [int]((Get-Date) - $t0).TotalSeconds; output = $out } | ConvertTo-Json -Compress",
        $"[IO.File]::WriteAllText({Deploy.Q(tmp)}, $o)",
        $"Move-Item -LiteralPath {Deploy.Q(tmp)} -Destination {Deploy.Q(out_)} -Force",
        "");

    /// <summary>Copy the uploaded file to <paramref name="destDir"/>\<paramref name="name"/> and check its SHA-256 there.</summary>
    public static string CopyScript(string src, string destDir, string name, string sha256, string run, string out_, string tmp)
    {
        var dest = destDir.TrimEnd('\\') + "\\" + name;
        return Frame(string.Join("\n",
            $"  New-Item -ItemType Directory -Path {Deploy.Q(destDir)} -Force | Out-Null",
            $"  Copy-Item -LiteralPath {Deploy.Q(src)} -Destination {Deploy.Q(dest)} -Force",
            $"  $h = (Get-FileHash -LiteralPath {Deploy.Q(dest)} -Algorithm SHA256).Hash.ToLowerInvariant()",
            $"  if ($h -ne {Deploy.Q(sha256.ToLowerInvariant())}) {{ throw ('SHA-256 mismatch after copy: ' + $h) }}",
            $"  $code = 0; $out = {Deploy.Q("Copied to " + dest)}"), run, out_, tmp);
    }

    /// <summary>Delete one file (never a folder; a missing file is not an error).</summary>
    public static string DeleteScript(string path, string run, string out_, string tmp) => Frame(string.Join("\n",
        $"  $p = {Deploy.Q(path)}",
        "  if (Test-Path -LiteralPath $p -PathType Container) { throw ('is a folder, not a file: ' + $p) }",
        "  if (Test-Path -LiteralPath $p -PathType Leaf) { Remove-Item -LiteralPath $p -Force; $out = 'Deleted ' + $p } else { $out = 'Not present: ' + $p }",
        "  $code = 0"), run, out_, tmp);

    /// <summary>Run the uploaded script file (PowerShell or cmd) and keep its output and exit code.</summary>
    public static string ScriptRunner(string kind, string userFile, string run, string out_, string tmp)
    {
        var call = kind == "cmd"
            ? $"  $out = (& cmd.exe /d /c {Deploy.Q(userFile)} 2>&1 | Out-String)"
            : $"  $out = (& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {Deploy.Q(userFile)} 2>&1 | Out-String)";
        return Frame(string.Join("\n", "  $ErrorActionPreference = 'Continue'", call, "  $code = $LASTEXITCODE",
                                 "  if ($code -eq $null) { $code = 0 }"), run, out_, tmp);
    }

    /// <summary>Show the message in <paramref name="textFile"/> (UTF-8) to every user logged on to the computer
    /// (msg.exe *, for <paramref name="seconds"/>). No logged-on user is not an error: there is nobody to tell.</summary>
    public static string MessageScript(string textFile, int seconds, string run, string out_, string tmp) => Frame(string.Join("\n",
        $"  $m = [IO.File]::ReadAllText({Deploy.Q(textFile)}, [Text.Encoding]::UTF8).Trim()",
        "  $s = @(Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\" -ErrorAction SilentlyContinue)",
        "  if ($s.Count -eq 0) { $code = 0; $out = 'No user is logged on: the message was not shown' }",
        "  else {",
        "    $ErrorActionPreference = 'Continue'",
        $"    $r = (& \"$env:SystemRoot\\System32\\msg.exe\" '*' '/TIME:{Math.Clamp(seconds, 10, 86400).ToString(CultureInfo.InvariantCulture)}' $m 2>&1 | Out-String).Trim()",
        "    $code = $LASTEXITCODE; if ($code -eq $null) { $code = 0 }",
        "    $out = 'Shown in ' + $s.Count + ' session(s)' + $(if ($r) { ': ' + $r } else { '' })",
        "  }"), run, out_, tmp);

    /// <summary>The message as the file sent along (UTF-8, no BOM).</summary>
    public static byte[] MessageFileBytes(string text) => new UTF8Encoding(false).GetBytes(text);

    /// <summary>shutdown.exe /r or /s after <paramref name="seconds"/> (planned, with a message), forced.</summary>
    public static string PowerScript(bool reboot, int seconds, string run, string out_, string tmp) => Frame(string.Join("\n",
        $"  $out = (& shutdown.exe {(reboot ? "/r" : "/s")} /f /t {Math.Clamp(seconds, MinPowerDelay, 3600).ToString(CultureInfo.InvariantCulture)} /d p:4:1 /c 'ADmiral' 2>&1 | Out-String)",
        "  $code = $LASTEXITCODE"), run, out_, tmp);

    /// <summary>The user's cmd script as a file: no echo, UTF-8 code page, CRLF line ends.</summary>
    public static byte[] CmdFileBytes(string script) =>
        Encoding.UTF8.GetBytes("@echo off\r\nchcp 65001 >nul\r\n" + script.Replace("\r\n", "\n").Replace("\n", "\r\n") + "\r\n");

    /// <summary>A file to send along: the local file (hashed while sent and checked against <paramref name="Sha256"/>) or bytes.</summary>
    public sealed record Payload(string Suffix, string? LocalPath = null, byte[]? Bytes = null, string? Sha256 = null);

    /// <summary>Run one PowerShell <paramref name="buildScript"/> as SYSTEM on <paramref name="host"/> with the
    /// <paramref name="payloads"/> next to it (their remote paths are passed to the builder by suffix). The flow and the
    /// cleanup are the installer's (<see cref="Deploy.DeployOne"/>). Throws <see cref="Unreachable"/> /
    /// <see cref="DeployError"/>; a script that ran is a result (exit code, error, output).</summary>
    public static RemoteRunResult RunRemote(string host, SmbCreds creds, CollectSettings cfg, IReadOnlyList<Payload> payloads,
                                            Func<IReadOnlyDictionary<string, string>, string, string, string, string> buildScript,
                                            Action<string, int?> onStep, int timeoutSeconds = 600, PdqBackend? backend = null,
                                            IReadOnlyList<string>? scratch = null, string? progressSuffix = null, Action<string>? onProgress = null)
    {
        try { Remote.ValidateHost(host); }
        catch (CollectError exc) { throw new DeployError(exc.Message, exc); }
        try { backend ??= PdqBackend.Default(); }
        catch (CollectError exc) { throw new DeployError(exc.Message, exc); }

        var tag = Remote.NewTag();
        var svc = $"ADmiral_{tag}";
        var names = new Dictionary<string, string>();
        foreach (var s in new[] { "ps1", "out", "tmp", "run", "log" }) names[s] = Pdq.SharePath(tag, "." + s);
        var shared = payloads.ToDictionary(p => p.Suffix, p => Pdq.SharePath(tag, p.Suffix));
        // files the script itself creates (progress, logs): their paths are passed like the payloads' and removed at the end
        foreach (var sfx in scratch ?? []) shared.TryAdd(sfx, Pdq.SharePath(tag, sfx));
        var remote = shared.ToDictionary(kv => kv.Key, kv => Pdq.RemotePath(kv.Value));
        var script = buildScript(remote, Pdq.RemotePath(names["run"]), Pdq.RemotePath(names["out"]), Pdq.RemotePath(names["tmp"]));
        var inner = $"powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"{Pdq.RemotePath(names["ps1"])}\" " +
                    $"> \"{Pdq.RemotePath(names["log"])}\" 2>&1 < nul";
        var command = Pdq.StartIn(tag, inner);
        string[] files = [.. shared.Values, .. names.Values];

        onStep("connecting", null);
        IRemoteSession sess;
        try
        {
            sess = backend.Files.Connect(host, creds, cfg.SmbTimeout);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            if (Deploy.IsUnreachable(exc)) throw new Unreachable($"SMB {exc.GetType().Name}: {exc.Message}", exc);
            throw new DeployError($"SMB {exc.GetType().Name}: {exc.Message}", exc);
        }
        var started = false;
        JsonObject? got = null;
        var logText = "";
        try
        {
            try
            {
                onStep("copying", 0);
                Pdq.MakeRunDir(sess, tag);
                foreach (var p in payloads)
                {
                    if (p.LocalPath is { } local)
                    {
                        using var source = new FileStream(local, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
                        using var hashing = new HashingReadStream(source);
                        var last = -1;
                        sess.PutLocal(shared[p.Suffix], hashing, (sent, total) =>
                        {
                            var pct = total > 0 ? (int)(sent * 100 / total) : 100;
                            if (pct != last) onStep("copying", last = pct);
                        });
                        if (!string.IsNullOrEmpty(p.Sha256) && !string.Equals(hashing.HashHex(), p.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw new DeployError(I18n.T("err.dep_hash", ("file", Path.GetFileName(local))));
                    }
                    else sess.PutFile(shared[p.Suffix], p.Bytes ?? []);
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
            var clock = backend.Clock;
            var deadline = clock.Elapsed + TimeSpan.FromSeconds(Math.Max(30, timeoutSeconds));
            var seenRun = false;
            var nextProgress = TimeSpan.Zero;
            void ReadProgress()
            {
                if (onProgress is null || progressSuffix is null || !shared.TryGetValue(progressSuffix, out var prg)) return;
                try
                {
                    var data = sess.ReadFile(prg, Deploy.MaxResultBytes);
                    if (data.Length > 0) onProgress(Encoding.UTF8.GetString(data));
                }
                catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: no progress yet"); }
            }
            while (clock.Elapsed < deadline)
            {
                if (!seenRun)
                {
                    try { seenRun = sess.FileExists(names["run"]); }
                    catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: ignored error"); }
                    if (seenRun) onStep("running", null);
                }
                if (seenRun && clock.Elapsed >= nextProgress)
                {
                    ReadProgress();
                    nextProgress = clock.Elapsed + TimeSpan.FromSeconds(5);
                }
                try
                {
                    var data = sess.ReadFile(names["out"], Deploy.MaxResultBytes);
                    if (data.Length > 0 && Encoding.UTF8.GetString(data).Trim().Length > 0)
                    {
                        got = Collector.ParseJson(data, 8) as JsonObject ?? throw new FormatException("not a JSON object");
                        break;
                    }
                }
                catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: no result yet"); }
                clock.Sleep(TimeSpan.FromSeconds(1));
            }
            ReadProgress();                                                  // the last lines (or what there is on a timeout)
            if (got is null) throw new DeployError($"the step did not finish within {timeoutSeconds}s");
            try
            {
                var t = Encoding.UTF8.GetString(sess.ReadFile(names["log"], Deploy.MaxLogBytes)).Trim();
                logText = t.Length > 1500 ? t[^1500..] : t;
            }
            catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: no script log"); }
        }
        finally
        {
            onStep("cleanup", null);
            foreach (var path in files.Reverse())
            {
                try { sess.DeleteFile(path); }
                catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: could not delete a file"); }
            }
            Pdq.RemoveRunDir(sess, tag);
            try { sess.Dispose(); }
            catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogDebug(exc, "Chain: ignored error"); }
            if (started) Pdq.RunSelfCheck(backend, host, creds, svc, tag, files, cfg, null);
        }
        static string S(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : "";
        var output = S(got["output"]).Trim();
        if (logText.Length > 0) output = output.Length > 0 ? output + "\n" + logText : logText;
        return new RemoteRunResult(Collector.Int(got["exit"]), S(got["error"]).Trim(), output, Collector.Int(got["seconds"]), S(got["state"]).Trim());
    }
}
