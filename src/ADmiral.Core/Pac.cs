using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>The PAC file cannot be read or uses something this interpreter does not support.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python PacError")]
public sealed class PacError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Proxy auto-config (PAC / WPAD) support.
/// <para>Many corporate networks publish a <c>wpad.dat</c> / <c>proxy.pac</c> file: a small JavaScript program whose
/// <c>FindProxyForURL(url, host)</c> decides, per address, between <c>DIRECT</c> and one or more proxies. ADmiral has
/// no JavaScript engine: this class is a tiny <b>interpreter</b> for the subset such files use in practice
/// (<c>if</c>/<c>else</c>/<c>return</c>/<c>var</c>, comparisons, <c>&amp;&amp; || !</c>, string helpers and the standard
/// PAC functions). The file is only ever parsed and evaluated by this interpreter; nothing in it is executed natively.
/// There are no loops, and every evaluation is bounded (source size, nesting depth, call depth, steps, string length,
/// DNS lookups, wall-clock time). Anything outside the subset raises <see cref="PacError"/>.</para></summary>
public sealed class Pac
{
    // ---------------------------------------------------------------- limits
    public const int MaxSourceBytes = 1024 * 1024;
    public const int MaxParseDepth = 200;
    public const int MaxCallDepth = 32;
    public const int MaxSteps = 1_000_000;
    public const int MaxStringLength = 64 * 1024;
    public const int MaxDnsLookups = 32;
    /// <summary>shExpMatch is O(subject x pattern): larger argument pairs are refused (a real PAC matches a host or URL of
    /// at most a few hundred characters against a short pattern, far below this).</summary>
    public const long MaxGlobWork = 1_000_000;
    /// <summary>Character comparisons inside a builtin that cost one interpreter step.</summary>
    public const int WorkPerStep = 64;
    public static readonly TimeSpan EvalTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);

    private readonly IReadOnlyDictionary<string, Function> _functions;

    private Pac(IReadOnlyDictionary<string, Function> functions) => _functions = functions;

    /// <summary>Parse a PAC script (it must define <c>FindProxyForURL</c>).</summary>
    public static Pac Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > MaxSourceBytes) throw new PacError($"the PAC file is too large (more than {MaxSourceBytes} characters)");
        var p = new Parser(Tokenizer.Tokenize(text));
        try { p.Program(); }
        catch (InsufficientExecutionStackException exc) { throw new PacError("the PAC script is nested too deeply", exc); }
        if (!p.Functions.ContainsKey("FindProxyForURL"))
            throw new PacError("the file has no FindProxyForURL function - is it a PAC / wpad.dat file?");
        return new Pac(p.Functions);
    }

    /// <summary>The raw PAC answer for <paramref name="url"/>: <c>"PROXY host:port; DIRECT"</c> and the like.
    /// <paramref name="resolve"/> replaces DNS (host -> IPv4 text or null), e.g. in tests.</summary>
    public string Find(string url, Func<string, string?>? resolve = null)
    {
        var host = "";
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
            host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']').ToLowerInvariant() : uri.Host.ToLowerInvariant();
        var fn = _functions["FindProxyForURL"];
        var run = new Run(this, resolve ?? DefaultResolve);
        var vars = new Dictionary<string, object?>(StringComparer.Ordinal);
        string[] args = [url, host];
        for (var i = 0; i < fn.Params.Length && i < args.Length; i++) vars[fn.Params[i]] = args[i];
        vars["url"] = url;
        vars["host"] = host;
        try
        {
            var env = new Env(vars, run);
            if (fn.Body(env)) return env.Ret is null ? "DIRECT" : V.Str(env.Ret);
            return "DIRECT";
        }
        catch (InsufficientExecutionStackException exc) { throw new PacError("the PAC script recurses too deeply", exc); }
    }

    /// <summary><c>"PROXY a:3128; DIRECT"</c> -> <c>["http://a:3128", null]</c> (null = DIRECT; SOCKS entries are skipped).</summary>
    public static IReadOnlyList<string?> ProxiesFromResult(string result)
    {
        var outp = new List<string?>();
        foreach (var part in (result ?? "").Split(';'))
        {
            var bits = part.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (bits.Length == 0) continue;
            var kind = bits[0].ToUpperInvariant();
            if (kind == "DIRECT") outp.Add(null);
            else if (kind is "PROXY" or "HTTP" && bits.Length > 1) outp.Add("http://" + bits[1]);
            else if (kind == "HTTPS" && bits.Length > 1) outp.Add("https://" + bits[1]);
        }
        return outp.Count > 0 ? outp : [null];
    }

    // ---------------------------------------------------------------- loading (file / URL / auto)
    private static readonly Lock CacheLock = new();
    private static readonly Dictionary<string, (bool IsFile, DateTime Stamp, long Loaded, Pac Pac)> Cache = new(StringComparer.Ordinal);
    private static readonly Lazy<HttpClient> Http = new(() => new HttpClient(new SocketsHttpHandler
    {
        UseProxy = false,                                   // the PAC itself is fetched without any proxy
        ConnectTimeout = TimeSpan.FromSeconds(5),
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
        AutomaticDecompression = DecompressionMethods.All,
    }) { Timeout = TimeSpan.FromSeconds(20) });

    private static bool IsUrl(string s) => Regex.IsMatch(s, "^https?://", RegexOptions.IgnoreCase);

    private static string LocalPath(string src)
    {
        var p = src.StartsWith("file://", StringComparison.OrdinalIgnoreCase) ? src[7..] : src;
        if (p == "~" || p.StartsWith("~/", StringComparison.Ordinal) || p.StartsWith("~\\", StringComparison.Ordinal))
            p = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + p[1..];
        return p;
    }

    /// <summary>The text of the PAC file at <paramref name="source"/>: a local path, an http(s) URL, or <c>auto</c> (WPAD).
    /// <paramref name="fetch"/> replaces the HTTP download (tests).</summary>
    public static string LoadPacText(string source, Func<string, string>? fetch = null)
    {
        var src = (source ?? "").Trim();
        if (src.Equals("auto", StringComparison.OrdinalIgnoreCase)) src = "http://wpad/wpad.dat";
        if (IsUrl(src))
        {
            string text;
            try { text = (fetch ?? Download)(src); }
            catch (PacError) { throw; }
            catch (Exception exc) { throw new PacError($"cannot download the PAC file {src}: {exc.GetType().Name}: {exc.Message}", exc); }
            if (text.Length > MaxSourceBytes) throw new PacError($"the PAC file {src} is too large");
            return text;
        }
        var path = LocalPath(src);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("no such file", path);
            if (info.Length > MaxSourceBytes) throw new PacError($"the PAC file {path} is too large");
            var bytes = File.ReadAllBytes(path);
            return Decode(bytes);
        }
        catch (PacError) { throw; }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PacError($"cannot read the PAC file {path}: {exc.Message}", exc);
        }
    }

    private static string Decode(byte[] bytes)
    {
        var span = bytes.AsSpan();
        if (span.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) span = span[3..];
        return Encoding.UTF8.GetString(span);
    }

    private static string Download(string url)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var resp = Http.Value.Send(req, HttpCompletionOption.ResponseHeadersRead);
        resp.EnsureSuccessStatusCode();
        if (resp.Content.Headers.ContentLength > MaxSourceBytes) throw new PacError($"the PAC file {url} is too large");
        using var stream = resp.Content.ReadAsStream();
        using var ms = new MemoryStream();
        var buf = new byte[16384];
        int n;
        while ((n = stream.Read(buf, 0, buf.Length)) > 0)
        {
            if (ms.Length + n > MaxSourceBytes) throw new PacError($"the PAC file {url} is too large");
            ms.Write(buf, 0, n);
        }
        return Decode(ms.ToArray());
    }

    /// <summary>The parsed PAC for <paramref name="source"/> (cached for an hour; a local file is re-read when it changes).</summary>
    public static Pac Get(string source, Func<string, string>? fetch = null)
    {
        var key = (source ?? "").Trim();
        var isFile = !IsUrl(key) && !key.Equals("auto", StringComparison.OrdinalIgnoreCase);
        var stamp = DateTime.MinValue;
        if (isFile)
        {
            try
            {
                var fi = new FileInfo(LocalPath(key));
                if (fi.Exists) stamp = fi.LastWriteTimeUtc;
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }
        var now = Stopwatch.GetTimestamp();
        lock (CacheLock)
        {
            if (Cache.TryGetValue(key, out var hit))
            {
                if (isFile && hit.IsFile && stamp != DateTime.MinValue && hit.Stamp == stamp) return hit.Pac;
                if (!isFile && Stopwatch.GetElapsedTime(hit.Loaded, now) < CacheTtl) return hit.Pac;
            }
        }
        var pac = Parse(LoadPacText(key, fetch));
        lock (CacheLock) Cache[key] = (isFile, stamp, now, pac);
        return pac;
    }

    /// <summary>The first usable proxy URL the PAC picks for <paramref name="url"/>, or null for DIRECT.</summary>
    public static string? ProxyFor(string source, string url, Func<string, string>? fetch = null)
        => ProxiesFromResult(Get(source, fetch).Find(url))[0];

    public static void ClearCache()
    {
        lock (CacheLock) Cache.Clear();
    }

    // ---------------------------------------------------------------- DNS
    private static string? DefaultResolve(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253) return null;
        if (Ipv4.TryParse(host, out var lit)) return Ipv4.Format(lit);
        try
        {
            var task = Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork);
            if (!task.Wait(DnsTimeout)) return null;
            return task.Result.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
        }
        catch (Exception exc) when (exc is AggregateException or SocketException or ArgumentException) { return null; }
    }

    private static string LocalIp()
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9));       // nothing is sent
            return (s.LocalEndPoint as IPEndPoint)?.Address.ToString() ?? "127.0.0.1";
        }
        catch (SocketException) { return "127.0.0.1"; }
    }

    // ---------------------------------------------------------------- runtime
    private delegate object? Expr(Env env);
    private delegate bool Stmt(Env env);                     // true = a return statement ran (value in env.Ret)

    private sealed record Function(string[] Params, Stmt Body);

    private sealed class Run(Pac pac, Func<string, string?> resolve)
    {
        private readonly long _start = Stopwatch.GetTimestamp();
        private readonly Dictionary<string, string?> _dns = new(StringComparer.OrdinalIgnoreCase);
        private int _steps;
        public int Depth;
        public readonly Pac Pac = pac;

        public void Step()
        {
            if (++_steps > MaxSteps) throw new PacError("the PAC script takes too many steps");
            if ((_steps & 15) == 0) CheckDeadline();
            RuntimeHelpers.EnsureSufficientExecutionStack();
        }

        /// <summary>Charge the work a builtin did (<paramref name="work"/> character operations) as steps.</summary>
        public void Charge(long work)
        {
            var steps = work / WorkPerStep;
            if (steps <= 0) return;
            if (_steps + steps > MaxSteps) throw new PacError("the PAC script takes too many steps");
            _steps += (int)steps;
            CheckDeadline();
        }

        public void CheckDeadline()
        {
            if (Stopwatch.GetElapsedTime(_start) > EvalTimeout) throw new PacError("the PAC script takes too long");
        }

        public string? Resolve(string host)
        {
            if (_dns.TryGetValue(host, out var hit)) return hit;
            if (_dns.Count >= MaxDnsLookups) return null;
            if (Stopwatch.GetElapsedTime(_start) > EvalTimeout) throw new PacError("the PAC script takes too long");
            string? ip;
            try { ip = resolve(host); }
            catch (Exception) { ip = null; }
            _dns[host] = ip;
            return ip;
        }
    }

    private sealed class Env(Dictionary<string, object?> vars, Run run)
    {
        public readonly Dictionary<string, object?> Vars = vars;
        public readonly Run Run = run;
        public object? Ret;
    }

    private object? Call(string name, object?[] args, Env env)
    {
        if (_functions.TryGetValue(name, out var fn))
        {
            if (env.Run.Depth >= MaxCallDepth) throw new PacError("the PAC script recurses too deeply");
            var inner = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var k in (string[])["url", "host"])
                if (env.Vars.TryGetValue(k, out var v)) inner[k] = v;
            for (var i = 0; i < fn.Params.Length && i < args.Length; i++) inner[fn.Params[i]] = args[i];
            var callEnv = new Env(inner, env.Run);
            env.Run.Depth++;
            try { return fn.Body(callEnv) ? callEnv.Ret : null; }
            finally { env.Run.Depth--; }
        }
        if (!Builtins.TryGetValue(name, out var b)) throw new PacError($"unsupported function '{name}'");
        if (args.Length < b.Min || args.Length > b.Max) throw new PacError($"{name}: wrong number of arguments ({args.Length})");
        env.Run.CheckDeadline();                      // every builtin call, not only every few steps
        // string builtins: their cost grows with the argument lengths
        long len = 0;
        foreach (var a in args) if (a is string str) len += str.Length;
        env.Run.Charge(len);
        return b.Fn(env.Run, args);
    }

    private static readonly Dictionary<string, (int Min, int Max, Func<Run, object?[], object?> Fn)> Builtins = new(StringComparer.Ordinal)
    {
        ["isPlainHostName"] = (1, 1, (_, a) => !V.Str(a[0]).Contains('.')),
        ["dnsDomainIs"] = (2, 2, (_, a) => V.Str(a[0]).ToLowerInvariant().EndsWith(V.Str(a[1]).ToLowerInvariant(), StringComparison.Ordinal)),
        ["localHostOrDomainIs"] = (2, 2, (_, a) =>
        {
            string h = V.Str(a[0]).ToLowerInvariant(), d = V.Str(a[1]).ToLowerInvariant();
            return h == d || (!h.Contains('.') && d.StartsWith(h + ".", StringComparison.Ordinal));
        }),
        ["isResolvable"] = (1, 1, (r, a) => r.Resolve(V.Str(a[0])) is not null),
        ["isInNet"] = (3, 3, (r, a) => IsInNet(r, a[0], a[1], a[2])),
        ["dnsResolve"] = (1, 1, (r, a) => r.Resolve(V.Str(a[0]))),
        ["myIpAddress"] = (0, 0, (_, _) => LocalIp()),
        ["dnsDomainLevels"] = (1, 1, (_, a) => (double)V.Str(a[0]).Count(c => c == '.')),
        ["shExpMatch"] = (2, 2, (r, a) => ShExpMatch(r, V.Str(a[0]), V.Str(a[1]))),
        // date / time ranges are almost never used for routing; treat them as "always true"
        ["weekdayRange"] = (0, 7, (_, _) => true),
        ["dateRange"] = (0, 7, (_, _) => true),
        ["timeRange"] = (0, 7, (_, _) => true),
        ["alert"] = (0, 16, (_, _) => null),
    };

    private static bool ShExpMatch(Run r, string subject, string pattern)
    {
        if ((long)(subject.Length + 1) * (pattern.Length + 1) > MaxGlobWork)
            throw new PacError("shExpMatch: the text or the pattern is too long");
        var pending = 0L;
        var hit = Glob.FnMatchCase(subject, pattern, brackets: false, onWork: () =>
        {
            if (++pending < 1024) return;
            r.Charge(pending);
            pending = 0;
        });
        r.Charge(pending);
        return hit;
    }

    private static bool IsInNet(Run r, object? host, object? pattern, object? mask)
    {
        var h = V.Str(host);
        uint addr;
        if (!Ipv4.TryParse(h, out addr) && !Ipv4.TryParse(r.Resolve(h) ?? "", out addr)) return false;
        if (!Ipv4.TryParse(V.Str(pattern), out var net) || !Ipv4.TryParse(V.Str(mask), out var msk)) return false;
        return (addr & msk) == (net & msk);
    }

    // ---------------------------------------------------------------- values (null, bool, double, string, string[])
    private static class V
    {
        public static bool Truthy(object? v) => v switch
        {
            null => false,
            bool b => b,
            double d => d != 0 && !double.IsNaN(d),
            string s => s.Length > 0,
            string[] l => l.Length > 0,
            _ => true,
        };

        public static double Num(object? v) => v switch
        {
            double d => d,
            bool b => b ? 1 : 0,
            string s => LooseValue.ToNumber(s) ?? double.NaN,
            _ => double.NaN,
        };

        public static string Str(object? v) => v switch
        {
            null => "null",
            bool b => b ? "true" : "false",
            string s => s,
            double d when double.IsNaN(d) => "NaN",
            double d when double.IsPositiveInfinity(d) => "Infinity",
            double d when double.IsNegativeInfinity(d) => "-Infinity",
            double d when d == Math.Floor(d) && Math.Abs(d) < 1e15 => ((long)d).ToString(CultureInfo.InvariantCulture),
            double d => d.ToString("R", CultureInfo.InvariantCulture),
            string[] l => string.Join(",", l),
            _ => v.ToString() ?? "",
        };

        public static string Cap(string s) =>
            s.Length > MaxStringLength ? throw new PacError("the PAC script builds a too long string") : s;

        public static bool Eq(object? a, object? b)
        {
            if (a is null || b is null) return a is null && b is null;
            if (a is double or bool && b is double or bool) return Num(a) == Num(b);
            if (a is string sa && b is string sb) return sa == sb;
            if (a is string[] la && b is string[] lb) return la.SequenceEqual(lb);
            return false;
        }

        public static int Compare(object? a, object? b)
        {
            if (a is double or bool && b is double or bool)
            {
                double x = Num(a), y = Num(b);
                if (double.IsNaN(x) || double.IsNaN(y)) return int.MinValue;        // every comparison is false
                return x.CompareTo(y);
            }
            if (a is string sa && b is string sb) return string.CompareOrdinal(sa, sb);
            throw new PacError("cannot compare these values");
        }

        public static object? Add(object? a, object? b) =>
            a is string || b is string ? Cap(Str(a) + Str(b)) : Num(a) + Num(b);

        public static int ToInt(double d) => double.IsNaN(d) ? 0 : (int)Math.Clamp(Math.Truncate(d), int.MinValue, int.MaxValue);

        public static object? Index(object? obj, object? idx)
        {
            long? i = idx switch
            {
                double d when double.IsFinite(d) => (long)Math.Truncate(d),
                bool b => b ? 1 : 0,
                string s when long.TryParse(s.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n) => n,
                _ => null,
            };
            if (i is not { } k) return null;
            switch (obj)
            {
                case string s:
                    if (k < 0) k += s.Length;
                    return k >= 0 && k < s.Length ? s[(int)k].ToString() : null;
                case string[] l:
                    if (k < 0) k += l.Length;
                    return k >= 0 && k < l.Length ? l[(int)k] : null;
                default:
                    return null;
            }
        }

        public static object? Prop(object? obj, string prop) => (obj, prop) switch
        {
            (string s, "length") => (double)s.Length,
            (string[] l, "length") => (double)l.Length,
            _ => throw new PacError($"unsupported property '{prop}'"),
        };

        public static object? Method(object? obj, string name, object?[] args)
        {
            if (obj is not string s) throw new PacError($"unsupported method '{name}'");
            object? Arg(int i) => i < args.Length ? args[i] : throw new PacError($"{name}: missing argument");
            switch (name)
            {
                case "toLowerCase": return s.ToLowerInvariant();
                case "toUpperCase": return s.ToUpperInvariant();
                case "indexOf": return (double)s.IndexOf(Str(Arg(0)), StringComparison.Ordinal);
                case "substring":
                case "slice":
                {
                    var a = args.Length > 0 ? ToInt(Num(args[0])) : 0;
                    var b = args.Length > 1 ? ToInt(Num(args[1])) : s.Length;
                    a = Math.Clamp(a, 0, s.Length);
                    b = Math.Clamp(b, 0, s.Length);
                    return b > a ? s[a..b] : "";
                }
                case "charAt":
                {
                    var i = ToInt(Num(Arg(0)));
                    return i >= 0 && i < s.Length ? s[i].ToString() : "";
                }
                case "replace":
                {
                    string from = Str(Arg(0)), to = Str(Arg(1));
                    var at = s.IndexOf(from, StringComparison.Ordinal);
                    return at < 0 ? s : Cap(string.Concat(s.AsSpan(0, at), to, s.AsSpan(at + from.Length)));
                }
                case "split":
                {
                    var sep = Str(Arg(0));
                    return sep.Length == 0 ? s.Select(c => c.ToString()).ToArray() : s.Split(sep);
                }
            }
            throw new PacError($"unsupported method '{name}'");
        }
    }

    // ---------------------------------------------------------------- tokenizer
    private enum K { Num, Str, Id, Op, Eof }

    private readonly record struct Tok(K Kind, string Text, double Num = 0);

    private static class Tokenizer
    {
        private static readonly string[] LongOps = ["===", "!==", "==", "!=", "<=", ">=", "&&", "||"];
        private const string SingleOps = "-+*/%<>!?:=(){}[];,.";

        public static List<Tok> Tokenize(string src)
        {
            var outp = new List<Tok>();
            var pos = 0;
            while (pos < src.Length)
            {
                var c = src[pos];
                if (char.IsWhiteSpace(c)) { pos++; continue; }
                if (c == '/' && pos + 1 < src.Length && src[pos + 1] == '/')
                {
                    var nl = src.IndexOf('\n', pos);
                    pos = nl < 0 ? src.Length : nl;
                    continue;
                }
                if (c == '/' && pos + 1 < src.Length && src[pos + 1] == '*')
                {
                    var end = src.IndexOf("*/", pos + 2, StringComparison.Ordinal);
                    if (end < 0) throw new PacError($"unterminated comment at offset {pos}");
                    pos = end + 2;
                    continue;
                }
                if (char.IsAsciiDigit(c))
                {
                    var start = pos;
                    while (pos < src.Length && char.IsAsciiDigit(src[pos])) pos++;
                    if (pos + 1 < src.Length && src[pos] == '.' && char.IsAsciiDigit(src[pos + 1]))
                    {
                        pos++;
                        while (pos < src.Length && char.IsAsciiDigit(src[pos])) pos++;
                    }
                    var text = src[start..pos];
                    outp.Add(new Tok(K.Num, text, double.Parse(text, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture)));
                    continue;
                }
                if (c is '"' or '\'')
                {
                    outp.Add(new Tok(K.Str, ReadString(src, ref pos)));
                    continue;
                }
                if (char.IsAsciiLetter(c) || c is '_' or '$')
                {
                    var start = pos;
                    while (pos < src.Length && (char.IsAsciiLetterOrDigit(src[pos]) || src[pos] is '_' or '$')) pos++;
                    outp.Add(new Tok(K.Id, src[start..pos]));
                    continue;
                }
                var op = LongOps.FirstOrDefault(o => string.CompareOrdinal(src, pos, o, 0, o.Length) == 0);
                if (op is null && SingleOps.Contains(c)) op = c.ToString();
                if (op is null) throw new PacError($"unsupported character '{c}' at offset {pos}");
                outp.Add(new Tok(K.Op, op));
                pos += op.Length;
            }
            outp.Add(new Tok(K.Eof, ""));
            return outp;
        }

        private static string ReadString(string src, ref int pos)
        {
            var quote = src[pos];
            var start = pos++;
            var sb = new StringBuilder();
            while (true)
            {
                if (pos >= src.Length || src[pos] == '\n') throw new PacError($"unterminated string at offset {start}");
                var c = src[pos++];
                if (c == quote) return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (pos >= src.Length) throw new PacError($"unterminated string at offset {start}");
                var e = src[pos++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'v': sb.Append('\v'); break;
                    case '0': sb.Append('\0'); break;
                    case '\n': break;                                    // line continuation
                    case 'x' when pos + 2 <= src.Length && IsHex(src.AsSpan(pos, 2)):
                        sb.Append((char)int.Parse(src.AsSpan(pos, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        pos += 2;
                        break;
                    case 'u' when pos + 4 <= src.Length && IsHex(src.AsSpan(pos, 4)):
                        sb.Append((char)int.Parse(src.AsSpan(pos, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        pos += 4;
                        break;
                    default: sb.Append(e); break;
                }
            }
        }

        private static bool IsHex(ReadOnlySpan<char> s)
        {
            foreach (var c in s) if (!char.IsAsciiHexDigit(c)) return false;
            return true;
        }
    }

    // ---------------------------------------------------------------- parser -> closures
    private sealed class Parser(List<Tok> tokens)
    {
        public readonly Dictionary<string, Function> Functions = new(StringComparer.Ordinal);
        private int _i;
        private int _depth;
        private Tok Peek(int ahead = 0) => tokens[Math.Min(_i + ahead, tokens.Count - 1)];

        private Tok Next()
        {
            var t = Peek();
            if (t.Kind != K.Eof) _i++;
            return t;
        }

        private bool IsOp(string text) => Peek() is { Kind: K.Op or K.Id } t && t.Text == text;

        private bool Accept(string text)
        {
            if (!IsOp(text)) return false;
            _i++;
            return true;
        }

        private void Expect(string text)
        {
            if (!Accept(text)) throw new PacError($"expected '{text}' but found '{Peek().Text}'");
        }

        private string Ident()
        {
            var t = Next();
            if (t.Kind != K.Id) throw new PacError($"expected a name but found '{t.Text}'");
            return t.Text;
        }

        private void Enter()
        {
            if (++_depth > MaxParseDepth) throw new PacError("the PAC script is nested too deeply");
            RuntimeHelpers.EnsureSufficientExecutionStack();
        }

        public void Program()
        {
            while (Peek().Kind != K.Eof)
            {
                if (Accept("function"))
                {
                    var name = Ident();
                    Expect("(");
                    var ps = new List<string>();
                    while (!Accept(")"))
                    {
                        if (Peek().Kind == K.Eof) throw new PacError("unexpected end of the file");
                        ps.Add(Ident());
                        Accept(",");
                    }
                    Functions[name] = new Function([.. ps], Block());
                }
                else
                {
                    Statement();                                  // a top-level var etc. is parsed and ignored
                }
            }
        }

        private Stmt Block()
        {
            Enter();
            try
            {
                Expect("{");
                var body = new List<Stmt>();
                while (!Accept("}"))
                {
                    if (Peek().Kind == K.Eof) throw new PacError("unexpected end of the file (missing '}')");
                    body.Add(Statement());
                }
                var arr = body.ToArray();
                return env =>
                {
                    foreach (var s in arr)
                        if (s(env)) return true;
                    return false;
                };
            }
            finally { _depth--; }
        }

        private Stmt Statement()
        {
            Enter();
            try { return StatementInner(); }
            finally { _depth--; }
        }

        private Stmt StatementInner()
        {
            if (IsOp("{")) return Block();
            if (Accept(";")) return _ => false;
            if (Accept("if"))
            {
                Expect("(");
                var cond = Expression();
                Expect(")");
                var then = Statement();
                var other = Accept("else") ? Statement() : null;
                return env =>
                {
                    env.Run.Step();
                    if (V.Truthy(cond(env))) return then(env);
                    return other is not null && other(env);
                };
            }
            if (Accept("return"))
            {
                Expr value = IsOp(";") || IsOp("}") ? _ => null : Expression();
                Accept(";");
                return env =>
                {
                    env.Run.Step();
                    env.Ret = value(env);
                    return true;
                };
            }
            if (Peek() is { Kind: K.Id, Text: "var" or "let" or "const" })
            {
                Next();
                var name = Ident();
                Expr init = Accept("=") ? Expression() : _ => null;
                Accept(";");
                return env =>
                {
                    env.Run.Step();
                    env.Vars[name] = init(env);
                    return false;
                };
            }
            if (Peek().Kind == K.Id && Peek(1) is { Kind: K.Op, Text: "=" })
            {
                var name = Next().Text;
                Next();
                var value = Expression();
                Accept(";");
                return env =>
                {
                    env.Run.Step();
                    env.Vars[name] = value(env);
                    return false;
                };
            }
            if (Peek() is { Kind: K.Id, Text: "for" or "while" or "do" or "switch" or "try" or "function" or "new" or "eval" })
                throw new PacError($"unsupported statement '{Peek().Text}'");
            var expr = Expression();
            Accept(";");
            return env =>
            {
                expr(env);
                return false;
            };
        }

        // ---- expressions (lowest precedence first)
        private Expr Expression()
        {
            Enter();
            try
            {
                var cond = Or();
                if (!Accept("?")) return cond;
                var a = Expression();
                Expect(":");
                var b = Expression();
                return env => V.Truthy(cond(env)) ? a(env) : b(env);
            }
            finally { _depth--; }
        }

        private Expr Or()
        {
            var left = And();
            while (Accept("||"))
            {
                var (l, r) = (left, And());
                left = env =>
                {
                    env.Run.Step();
                    var v = l(env);
                    return V.Truthy(v) ? v : r(env);
                };
            }
            return left;
        }

        private Expr And()
        {
            var left = Eq();
            while (Accept("&&"))
            {
                var (l, r) = (left, Eq());
                left = env =>
                {
                    env.Run.Step();
                    var v = l(env);
                    return V.Truthy(v) ? r(env) : v;
                };
            }
            return left;
        }

        private Expr Eq()
        {
            var left = Rel();
            while (Peek() is { Kind: K.Op, Text: "==" or "!=" or "===" or "!==" })
            {
                var neg = Next().Text.StartsWith('!');
                var (l, r) = (left, Rel());
                left = env =>
                {
                    env.Run.Step();
                    return V.Eq(l(env), r(env)) != neg;
                };
            }
            return left;
        }

        private Expr Rel()
        {
            var left = Add();
            while (Peek() is { Kind: K.Op, Text: "<" or ">" or "<=" or ">=" })
            {
                var op = Next().Text;
                var (l, r) = (left, Add());
                Func<int, bool> test = op switch
                {
                    "<" => c => c != int.MinValue && c < 0,
                    ">" => c => c != int.MinValue && c > 0,
                    "<=" => c => c != int.MinValue && c <= 0,
                    _ => c => c != int.MinValue && c >= 0,
                };
                left = env =>
                {
                    env.Run.Step();
                    return test(V.Compare(l(env), r(env)));
                };
            }
            return left;
        }

        private Expr Add()
        {
            var left = Mul();
            while (Peek() is { Kind: K.Op, Text: "+" or "-" })
            {
                var plus = Next().Text == "+";
                var (l, r) = (left, Mul());
                left = env =>
                {
                    env.Run.Step();
                    object? a = l(env), b = r(env);
                    return plus ? V.Add(a, b) : V.Num(a) - V.Num(b);
                };
            }
            return left;
        }

        private Expr Mul()
        {
            var left = Unary();
            while (Peek() is { Kind: K.Op, Text: "*" or "/" or "%" })
            {
                var op = Next().Text;
                var (l, r) = (left, Unary());
                Func<double, double, double> fn = op switch
                {
                    "*" => (a, b) => a * b,
                    "/" => (a, b) => b != 0 ? a / b : double.PositiveInfinity,
                    _ => (a, b) =>
                    {
                        if (b == 0) return double.NaN;
                        var m = a % b;
                        return m != 0 && (m < 0) != (b < 0) ? m + b : m;   // Python's floored modulo
                    },
                };
                left = env =>
                {
                    env.Run.Step();
                    return fn(V.Num(l(env)), V.Num(r(env)));
                };
            }
            return left;
        }

        private Expr Unary()
        {
            Enter();
            try
            {
                if (Accept("!"))
                {
                    var e = Unary();
                    return env => !V.Truthy(e(env));
                }
                if (Accept("-"))
                {
                    var e = Unary();
                    return env => -V.Num(e(env));
                }
                return Postfix();
            }
            finally { _depth--; }
        }

        private Expr Postfix()
        {
            var e = Primary();
            while (true)
            {
                if (Accept("."))
                {
                    var prop = Ident();
                    var obj = e;
                    if (Accept("("))
                    {
                        var args = Args();
                        e = env =>
                        {
                            env.Run.Step();
                            var o = obj(env);
                            return V.Method(o, prop, Eval(args, env));
                        };
                    }
                    else
                    {
                        e = env =>
                        {
                            env.Run.Step();
                            return V.Prop(obj(env), prop);
                        };
                    }
                }
                else if (Accept("["))
                {
                    var idx = Expression();
                    Expect("]");
                    var obj = e;
                    e = env =>
                    {
                        env.Run.Step();
                        var o = obj(env);
                        return V.Index(o, idx(env));
                    };
                }
                else
                {
                    return e;
                }
            }
        }

        private static object?[] Eval(Expr[] args, Env env)
        {
            var vals = new object?[args.Length];
            for (var i = 0; i < args.Length; i++) vals[i] = args[i](env);
            return vals;
        }

        private Expr[] Args()
        {
            var outp = new List<Expr>();
            while (!Accept(")"))
            {
                if (Peek().Kind == K.Eof) throw new PacError("unexpected end of the file (missing ')')");
                outp.Add(Expression());
                Accept(",");
            }
            return [.. outp];
        }

        private Expr Primary()
        {
            var t = Next();
            switch (t.Kind)
            {
                case K.Num:
                {
                    object? v = t.Num;
                    return _ => v;
                }
                case K.Str:
                {
                    object? v = t.Text;
                    return _ => v;
                }
                case K.Op when t.Text == "(":
                {
                    var e = Expression();
                    Expect(")");
                    return e;
                }
                case K.Id:
                {
                    var name = t.Text;
                    switch (name)
                    {
                        case "true": return _ => true;
                        case "false": return _ => false;
                        case "null" or "undefined": return _ => null;
                    }
                    if (Accept("("))
                    {
                        var args = Args();
                        return env =>
                        {
                            env.Run.Step();
                            return env.Run.Pac.Call(name, Eval(args, env), env);
                        };
                    }
                    // functions are looked up at run time (through env.Run.Pac): one may call another defined further down
                    return env => env.Vars.TryGetValue(name, out var v) ? v : throw new PacError($"unknown variable '{name}'");
                }
            }
            throw new PacError(t.Kind == K.Eof ? "unexpected end of the file" : $"unexpected '{t.Text}'");
        }
    }
}

/// <summary>Strict dotted-quad IPv4 parsing (four decimal octets, no leading zeros), like Python's <c>IPv4Address</c>.</summary>
internal static class Ipv4
{
    public static bool TryParse(string? s, out uint value)
    {
        value = 0;
        if (string.IsNullOrEmpty(s) || s.Length > 15) return false;
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
        {
            if (p.Length is 0 or > 3 || (p.Length > 1 && p[0] == '0')) return false;
            var n = 0;
            foreach (var c in p)
            {
                if (!char.IsAsciiDigit(c)) return false;
                n = n * 10 + (c - '0');
            }
            if (n > 255) return false;
            value = (value << 8) | (uint)n;
        }
        return true;
    }

    public static string Format(uint v) =>
        string.Create(CultureInfo.InvariantCulture, $"{v >> 24}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}");
}
