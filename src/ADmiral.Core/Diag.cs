using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// Diagnostics: leave no error behind, so a production run can be debugged afterwards (port of admiral/diag.py).
//
// Install(folder) sets up three files, all next to the other ADmiral data and all sanitized:
//   admiral.log           the normal log (INFO and above);
//   admiral-debug.log     everything ADmiral logs (DEBUG, including swallowed exceptions with their stack traces),
//                         rotating (5 MB x 3);
//   admiral-errors.jsonl  the error ledger: every WARNING / ERROR / CRITICAL record of the whole process, one JSON
//                         object per line, with stack trace, logger and thread. Unhandled exceptions
//                         (AppDomain, unobserved tasks) end up here as well.
// Report() turns the ledger into a short, grouped text for a bug report. Nothing secret is ever written: passwords
// the program knows (RegisterSecret) and anything shaped like password=... / token: ... / an Authorization header
// is replaced by *** before it reaches a file.
//
// The files are written by DiagLoggerProvider. Install() points Log.Logger at it; a host with its own logging
// pipeline (ASP.NET Core) adds Diag.Provider to that pipeline (builder.Logging.AddProvider(Diag.Provider)).

/// <summary>One log file as the Settings page shows it.</summary>
public sealed record LogFileView(
    [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name,
    [property: System.Text.Json.Serialization.JsonPropertyName("exists")] bool Exists,
    [property: System.Text.Json.Serialization.JsonPropertyName("size")] long Size,
    [property: System.Text.Json.Serialization.JsonPropertyName("text")] string Text,
    [property: System.Text.Json.Serialization.JsonPropertyName("truncated")] bool Truncated);

public static partial class Diag
{
    public const string LogFile = "admiral.log";
    public const string DebugFile = "admiral-debug.log";
    public const string LedgerFile = "admiral-errors.jsonl";
    /// <summary>The log files' own folder inside the data folder.</summary>
    public const string LogDir = "logs";
    public const long DebugMaxBytes = 5 * 1024 * 1024;
    public const int DebugBackups = 3;
    /// <summary>Size at which admiral.log is rotated (admiral.log.1 .. .3 are kept): anything that makes ADmiral log
    /// a line per request - e.g. a flood of refused sync requests - can never fill the disk (settable for tests).</summary>
    public static long MainMaxBytes { get; set; } = 10 * 1024 * 1024;
    public const int MainBackups = 3;

    /// <summary>The three files the UI may show.</summary>
    public static readonly IReadOnlyList<string> LogFiles = [LogFile, DebugFile, LedgerFile];

    /// <summary>Upper bound of the ledger; past it the newest half is kept (settable for tests).</summary>
    public static long MaxLedgerBytes { get; set; } = 5 * 1024 * 1024;

    // ------------------------------------------------------------------ redaction
    private static readonly Lock SecretsLock = new();
    private static string[] _secrets = [];

    // password=..., "password": "...", token: ..., secret = ..., api_key=..., passphrase=...
    // a quoted value is masked up to its closing quote (spaces included; to the end of the line when unterminated)
    [GeneratedRegex("""\b(pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential|sync[_-]?key)s?(["']?\s*[:=]\s*)(?:"(?:[^"\\\n]|\\.)*"?|'[^'\n]*'?|[^\s,;"'}\]]+)""",
                    RegexOptions.IgnoreCase)]
    private static partial Regex KeyValueSecret();

    // Authorization: Negotiate / Basic / Bearer / Digest <blob>
    [GeneratedRegex(@"\b(Negotiate|Kerberos|Basic|Bearer|NTLM|Digest)\s+[A-Za-z0-9+/=_\-.]{16,}", RegexOptions.IgnoreCase)]
    private static partial Regex AuthBlob();

    // Authorization: <anything> / Proxy-Authorization: <anything> (the scheme is kept, the value never)
    [GeneratedRegex("""\b((?:Proxy-)?Authorization)(["']?\s*[:=]\s*["']?)(?:(Negotiate|Kerberos|Basic|Bearer|NTLM|Digest)\s+)?[^\s,;"'}\]]+""", RegexOptions.IgnoreCase)]
    private static partial Regex AuthHeader();

    /// <summary>Remember a secret value (a password): it is blanked wherever it would appear in a log line.</summary>
    public static void RegisterSecret(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 3) return;
        lock (SecretsLock)
            if (!_secrets.Contains(value))
                _secrets = [.. _secrets.Append(value).OrderByDescending(s => s.Length)];
    }

    /// <summary>Forget the registered secrets (tests).</summary>
    public static void ClearSecrets()
    {
        lock (SecretsLock) _secrets = [];
    }

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        foreach (var secret in _secrets)
            text = text.Replace(secret, "***", StringComparison.Ordinal);
        text = AuthHeader().Replace(text, m => $"{m.Groups[1].Value}{m.Groups[2].Value}{(m.Groups[3].Success ? m.Groups[3].Value + " " : "")}***");
        text = KeyValueSecret().Replace(text, m =>
        {
            var q = m.Value[m.Groups[2].Index + m.Groups[2].Length - m.Index] is var c && c is '"' or '\'' ? c.ToString() : "";
            return $"{m.Groups[1].Value}{m.Groups[2].Value}{q}***{q}";
        });
        return AuthBlob().Replace(text, m => $"{m.Groups[1].Value} ***");
    }

    // ------------------------------------------------------------------ install
    private static readonly Lock InstallLock = new();
    private static DiagLoggerProvider? _provider;
    private static ILogger? _previousLogger;
    private static bool _hooked;

    /// <summary>The folder the log files go to (null before <see cref="Install"/>).</summary>
    public static string? InstalledFolder => _provider?.Folder;

    /// <summary>The logger provider writing the files (null before <see cref="Install"/>); add it to a host's
    /// logging pipeline so framework messages reach the ledger too.</summary>
    public static ILoggerProvider? Provider => _provider;

    /// <summary>Whether the detailed log is being written.</summary>
    public static bool DebugEnabled => _provider?.DebugEnabled ?? false;

    /// <summary><c>&lt;data folder&gt;/logs</c>. Log files of older versions (directly in the data folder) are moved
    /// there; a file another process still holds open stays where it is.</summary>
    public static string LogDirFor(string dataFolder)
    {
        var target = Path.Combine(dataFolder, LogDir);
        Directory.CreateDirectory(target);
        var old = LogFiles.Select(n => Path.Combine(dataFolder, n))
            .Concat(LogFiles.SelectMany(n => Enumerable.Range(1, 5).Select(i => Path.Combine(dataFolder, $"{n}.{i}"))));
        foreach (var path in old)
        {
            var dest = Path.Combine(target, Path.GetFileName(path));
            if (!File.Exists(path) || File.Exists(dest)) continue;
            try
            {
                File.Move(path, dest);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
        return target;
    }

    /// <summary>Configure logging for the whole process (writes into <paramref name="folder"/>). Safe to call more
    /// than once; returns the folder.</summary>
    public static string Install(string folder, bool console = false, bool debug = true)
    {
        Directory.CreateDirectory(folder);
        lock (InstallLock)
        {
            if (_provider is not null && SamePath(_provider.Folder, folder)) return _provider.Folder;
            var previous = _provider;
            _provider = new DiagLoggerProvider(Path.GetFullPath(folder), debug, console);
            if (previous is null) _previousLogger = Log.Logger;
            Log.Configure(_provider.CreateLogger("admiral"));
            previous?.Dispose();
            if (!_hooked)
            {
                _hooked = true;
                AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                {
                    if (!Log.Logger.IsEnabled(LogLevel.Critical)) return;
                    var thread = Thread.CurrentThread.Name ?? Environment.CurrentManagedThreadId.ToString(CultureInfo.InvariantCulture);
                    Log.Logger.LogCritical(e.ExceptionObject as Exception, "Unhandled exception in thread {Thread}", thread);
                };
                TaskScheduler.UnobservedTaskException += (_, e) =>
                    Log.Logger.LogError(e.Exception, "Unobserved task exception: {Message}", e.Exception.Message);
            }
        }
        if (Log.Logger.IsEnabled(LogLevel.Information))
            Log.Logger.LogInformation("Diagnostics on: {Environment}", DescribeEnvironment());
        return _provider.Folder;
    }

    /// <summary>Stop writing the files and give <see cref="Log.Logger"/> back to what it was before (tests, shutdown).</summary>
    public static void Uninstall()
    {
        lock (InstallLock)
        {
            if (_provider is null) return;
            _provider.Dispose();
            _provider = null;
            Log.Configure(_previousLogger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            _previousLogger = null;
        }
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar),
                      OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    /// <summary>Switch the detailed log (admiral-debug.log) on or off while the program runs. A no-op before Install.</summary>
    public static void SetDebug(bool enabled)
    {
        var p = _provider;
        if (p is null || p.DebugEnabled == enabled) return;
        if (enabled)
        {
            p.SetDebug(true);
            Log.Logger.LogInformation("Debug log switched on");
        }
        else
        {
            Log.Logger.LogInformation("Debug log switched off");
            p.SetDebug(false);
        }
    }

    /// <summary>The end of one of the three log files (only those names; never another path) for the Settings page.
    /// The files are redacted when written, and once more here.</summary>
    public static LogFileView ReadLog(string name, string? folder = null, int maxBytes = 300_000)
    {
        if (!LogFiles.Contains(name)) throw new ArgumentException($"Unknown log file: {name}");
        folder ??= InstalledFolder;
        var path = folder is null ? null : Path.Combine(folder, name);
        if (path is null || !File.Exists(path)) return new LogFileView(name, false, 0, "", false);
        var (text, size) = Tail(path, maxBytes);
        if (size > maxBytes)                                // cut at a line start
        {
            var nl = text.IndexOf('\n');
            if (nl >= 0) text = text[(nl + 1)..];
        }
        return new LogFileView(name, true, size, Redact(text), size > maxBytes);
    }

    /// <summary>The last <paramref name="limit"/> bytes of a file as UTF-8 (shared read, works on a file being written).</summary>
    internal static (string Text, long Size) Tail(string path, long limit)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var size = fs.Length;
        if (size > limit) fs.Seek(size - limit, SeekOrigin.Begin);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return (Encoding.UTF8.GetString(ms.ToArray()), size);
    }

    public static string Version
    {
        get
        {
            var asm = typeof(Diag).Assembly;
            var v = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                    ?? asm.GetName().Version?.ToString() ?? "0";
            var plus = v.IndexOf('+');
            return plus >= 0 ? v[..plus] : v;
        }
    }

    public static string DescribeEnvironment() =>
        $"ADmiral {Version} (.NET {Environment.Version}), {RuntimeInformation.OSDescription}, {RuntimeInformation.OSArchitecture}";

    // ------------------------------------------------------------------ report
    private static string? LedgerPath(string? folder)
    {
        folder ??= InstalledFolder;
        return folder is null ? null : Path.Combine(folder, LedgerFile);
    }

    public static List<JsonObject> ReadLedger(string? folder = null)
    {
        var path = LedgerPath(folder);
        if (path is null || !File.Exists(path)) return [];
        var outList = new List<JsonObject>();
        var (text, _) = Tail(path, long.MaxValue);
        foreach (var line in text.Split('\n'))
        {
            if (line.Trim().Length == 0) continue;
            try
            {
                if (JsonNode.Parse(line) is JsonObject o) outList.Add(o);
            }
            catch (JsonException)
            {
            }
        }
        return outList;
    }

    /// <summary>Empty the error ledger.</summary>
    public static void Clear(string? folder = null)
    {
        var path = LedgerPath(folder);
        if (path is null || !File.Exists(path)) return;
        if (_provider is { } p && SamePath(p.Folder, Path.GetDirectoryName(path)!)) p.ClearLedger();
        else File.WriteAllText(path, "");
    }

    private static string S(JsonObject o, string key) => o[key] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : "";

    /// <summary>A grouped, redacted error list, ready to paste into a bug report.</summary>
    public static string Report(string? folder = null, int limit = 30)
    {
        folder ??= InstalledFolder;
        var lines = new List<string>
        {
            "ADmiral error report", new string('=', 20), DescribeEnvironment(),
            $"Generated: {Db.UtcNow()}",
        };
        if (folder is null) return string.Join("\n", lines.Append("").Append("Diagnostics are not active in this process."));
        var entries = ReadLedger(folder);
        lines.Add($"Log folder: {folder}   (details: {LogFile}, {DebugFile}, {LedgerFile})");
        if (entries.Count == 0) return string.Join("\n", lines.Append("").Append("No warnings or errors recorded."));

        var groups = entries.GroupBy(e => (S(e, "level"), S(e, "logger"), S(e, "template"))).Select(g => (g.Key, Items: g.ToList())).ToList();
        int Rank(string level) => level switch { "CRITICAL" => 0, "ERROR" => 1, "WARNING" => 2, _ => 3 };
        var ranked = groups.OrderBy(g => Rank(g.Key.Item1)).ThenByDescending(g => g.Items.Count).ToList();
        lines.AddRange(["", $"{entries.Count} record(s) in {groups.Count} distinct problem(s). Most serious first.", ""]);
        var i = 0;
        foreach (var ((level, logger, _), items) in ranked.Take(limit))
        {
            i++;
            var last = items[^1];
            lines.Add($"[{i}] {level} x{items.Count}  {logger}  ({S(last, "where")})");
            lines.Add($"    first {S(items[0], "ts")}   last {S(last, "ts")}");
            var msg = S(last, "message");
            lines.Add($"    {(msg.Length > 500 ? msg[..500] : msg)}");
            var distinct = items.Select(x => S(x, "message")).Select(m => m.Length > 120 ? m[..120] : m).Distinct().ToList();
            if (distinct.Count > 1)
                lines.Add($"    ({distinct.Count} different messages, e.g. '{distinct.Order(StringComparer.Ordinal).First()}')");
            var tb = S(last, "traceback");
            if (tb.Length > 0)
                lines.AddRange(tb.TrimEnd().Split('\n').TakeLast(12).Select(t => "    " + t.TrimEnd('\r')));
            lines.Add("");
        }
        if (ranked.Count > limit) lines.Add($"... and {ranked.Count - limit} more problem(s) in {LedgerFile}");
        return Redact(string.Join("\n", lines).TrimEnd() + "\n");
    }

    /// <summary>Python level names (the files keep the format of the Python version).</summary>
    internal static string LevelName(LogLevel level) => level switch
    {
        LogLevel.Trace or LogLevel.Debug => "DEBUG",
        LogLevel.Information => "INFO",
        LogLevel.Warning => "WARNING",
        LogLevel.Error => "ERROR",
        _ => "CRITICAL",
    };
}

/// <summary>Writes admiral.log (INFO+), admiral-debug.log (ADmiral's own DEBUG+, rotating) and the JSON-lines error
/// ledger (WARNING+), every line redacted. Categories other than ADmiral's are recorded from WARNING up only
/// (framework DEBUG output can contain credentials and bodies).</summary>
public sealed class DiagLoggerProvider : ILoggerProvider
{
    private readonly Lock _lock = new();
    private StreamWriter? _main;
    private StreamWriter? _debug;
    private readonly bool _console;
    private bool _disposed;
    private static readonly JsonSerializerOptions LedgerJson = new() { Encoder = JavaScriptEncoder.Create(UnicodeRanges.All) };

    public string Folder { get; }

    public bool DebugEnabled
    {
        get
        {
            lock (_lock) return _debug is not null;
        }
    }

    public DiagLoggerProvider(string folder, bool debug = true, bool console = false)
    {
        Folder = folder;
        Directory.CreateDirectory(folder);
        _console = console;
        _main = Open(Path.Combine(folder, Diag.LogFile));
        if (debug) _debug = Open(Path.Combine(folder, Diag.DebugFile));
    }

    private static StreamWriter Open(string path) =>
        new(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete), new UTF8Encoding(false))
        {
            AutoFlush = true,
        };

    public void SetDebug(bool enabled)
    {
        lock (_lock)
        {
            if (_disposed) return;
            if (enabled && _debug is null) _debug = Open(Path.Combine(Folder, Diag.DebugFile));
            else if (!enabled && _debug is not null)
            {
                _debug.Dispose();
                _debug = null;
            }
        }
    }

    public ILogger CreateLogger(string categoryName) => new DiagLogger(this, categoryName);

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            _main?.Dispose();
            _debug?.Dispose();
            _main = _debug = null;
        }
    }

    internal static bool IsOwn(string category) =>
        category == "admiral" || category.StartsWith("admiral.", StringComparison.Ordinal)
        || category.StartsWith("ADmiral", StringComparison.Ordinal);

    internal static bool Enabled(string category, LogLevel level) =>
        level != LogLevel.None && level >= (IsOwn(category) ? LogLevel.Debug : LogLevel.Warning);

    internal void ClearLedger()
    {
        lock (_lock) File.WriteAllText(Path.Combine(Folder, Diag.LedgerFile), "");
    }

    internal void Write(string category, LogLevel level, string template, string message, Exception? ex)
    {
        var now = DateTimeOffset.Now;
        var levelName = Diag.LevelName(level);
        var text = $"{now:yyyy-MM-dd HH:mm:ss,fff} {levelName} {category}: {message}";
        if (ex is not null) text += Environment.NewLine + ex;
        text = Diag.Redact(text);
        lock (_lock)
        {
            if (_disposed) return;
            try
            {
                if (level >= LogLevel.Information && _main is not null)
                {
                    _main.WriteLine(text);
                    if (_main.BaseStream.Length > Diag.MainMaxBytes) _main = Rotate(_main, Diag.LogFile, Diag.MainBackups);
                }
                if (_debug is not null)
                {
                    _debug.WriteLine(text);
                    if (_debug.BaseStream.Length > Diag.DebugMaxBytes) _debug = Rotate(_debug, Diag.DebugFile, Diag.DebugBackups);
                }
                if (_console && level >= LogLevel.Warning) Console.Error.WriteLine(text);
                if (level >= LogLevel.Warning) WriteLedger(category, levelName, template, message, ex);
            }
            catch (Exception io) when (io is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                // logging must never raise
            }
        }
    }

    /// <summary>Close <paramref name="writer"/>, shift name.1 .. name.(backups-1) up by one, move the file to name.1 and
    /// open a new, empty one.</summary>
    private StreamWriter Rotate(StreamWriter writer, string name, int backups)
    {
        writer.Dispose();
        var basePath = Path.Combine(Folder, name);
        try
        {
            for (var i = backups - 1; i >= 1; i--)
                if (File.Exists($"{basePath}.{i}")) File.Move($"{basePath}.{i}", $"{basePath}.{i + 1}", overwrite: true);
            File.Move(basePath, basePath + ".1", overwrite: true);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            // another process holds the file without delete sharing: start over in place rather than grow without end
            try { using (new FileStream(basePath, FileMode.Truncate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete)) { } }
            catch (Exception inner) when (inner is IOException or UnauthorizedAccessException) { }
        }
        return Open(basePath);
    }

    private void WriteLedger(string category, string levelName, string template, string message, Exception? ex)
    {
        var entry = new JsonObject
        {
            ["ts"] = Db.UtcNow(),
            ["level"] = levelName,
            ["logger"] = category,
            ["template"] = Cut(Diag.Redact(template), 300),          // groups the same problem on many hosts
            ["message"] = Cut(Diag.Redact(message), 2000),
            ["where"] = Where(category, ex),
            ["thread"] = Thread.CurrentThread.Name ?? $"Thread-{Environment.CurrentManagedThreadId}",
        };
        if (ex is not null)
        {
            entry["exception"] = ex.GetType().Name;
            var tb = Diag.Redact(ex.ToString());
            entry["traceback"] = tb.Length > 6000 ? tb[^6000..] : tb;
        }
        var path = Path.Combine(Folder, Diag.LedgerFile);
        Trim(path);
        File.AppendAllText(path, entry.ToJsonString(LedgerJson) + "\n", new UTF8Encoding(false));
    }

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    private static string Where(string category, Exception? ex)
    {
        var site = ex?.TargetSite;
        return site?.DeclaringType is { } t ? $"{t.FullName}.{site.Name}" : category;
    }

    /// <summary>Keep the ledger bounded: when it passes the limit, keep the newest half.</summary>
    private static void Trim(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= Diag.MaxLedgerBytes) return;
            var lines = File.ReadAllLines(path, Encoding.UTF8);
            File.WriteAllLines(path, lines[(lines.Length / 2)..], new UTF8Encoding(false));
        }
        catch (IOException)
        {
        }
    }

    private sealed class DiagLogger(DiagLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => Enabled(category, logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                                Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            string message;
            try
            {
                message = formatter(state, exception);
            }
            catch (FormatException)
            {
                message = state?.ToString() ?? "";
            }
            var template = message;
            if (state is IReadOnlyList<KeyValuePair<string, object?>> kv)
                foreach (var (k, v) in kv)
                    if (k == "{OriginalFormat}" && v is string t)
                        template = t;
            owner.Write(category, logLevel, template, message, exception);
        }
    }
}
