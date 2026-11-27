// Port of admiral/updates.py: the shared internet client (proxy / PAC / system proxy) and the MSRC security-update data.
//
// Security-update monitoring: is each computer up to date with Microsoft's latest security release?
// Microsoft publishes every monthly security release in the MSRC Security Update Guide API
// (https://api.msrc.microsoft.com/cvrf/v3.0). Each fix lists the Windows build that contains it (FixedBuild,
// e.g. 10.0.22631.4460). ADmiral downloads the last few releases, keeps the newest fixed build per Windows build
// number and product family (client / server: one build number can be two update lines, see ParseReleaseRefs) and
// compares it with the build each computer reported in its inventory. Nothing is sent about the
// computers: the download is a plain public GET and the comparison happens locally.
//
// Differences to the Python version:
// * .NET's own HTTP stack does integrated proxy authentication (Negotiate / Kerberos / NTLM with the logged-on
//   account) itself, so the pyspnego token adapter and the Windows PowerShell fallback are gone.
// * One HttpClient per proxy setting is cached and shared (no socket exhaustion, connection reuse); TLS
//   certificate validation is never switched off; every response has a size cap and every request a timeout.
// * The proxy password is handed to the handler as a credential (ProxyAccount), never put into a URL.

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>The merged MSRC reference: newest fixed revision per Windows build and family (keys as
/// <see cref="Updates.RefKey"/>: "10.0.26100", "10.0.26100/server"), and the months read.</summary>
public sealed record UpdateReferenceData(
    [property: JsonPropertyName("builds")] Dictionary<string, UpdateRef> Builds,
    [property: JsonPropertyName("months")] List<string> Months)
{
    /// <summary>The KB number of the newest release per build ("10.0.26100" -&gt; "KB5043080"), where the data names it.</summary>
    [JsonPropertyName("kbs")] public Dictionary<string, string> Kbs { get; init; } = [];
}

/// <summary>Security-update state of one computer: current | missing | pending | unknown.</summary>
public sealed record SecurityState(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("installed"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Installed = null,
    [property: JsonPropertyName("latest"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Latest = null,
    [property: JsonPropertyName("month"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Month = null,
    [property: JsonPropertyName("released"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Released = null)
{
    public static readonly SecurityState Unknown = new("unknown");
}

/// <summary>A response was larger than the cap for that kind of download.</summary>
public sealed class ResponseTooLargeException(string message) : IOException(message);

/// <summary>A proxy chosen by the PAC file, per destination (the PAC is interpreted, never executed).
/// Credentials (the explicit proxy account, or with no account the Windows logon's integrated Kerberos / NTLM
/// authentication) are only given to a proxy chosen by a <i>trusted</i> PAC file (<see cref="Updates.PacTrusted"/>: a local
/// file or an https URL). A proxy picked by WPAD (<c>auto</c>) or a PAC fetched over plain http could be chosen by
/// anyone on the network (a spoofed wpad name / answer), and offering it integrated authentication would hand them a
/// NetNTLM response to crack or relay; such a proxy gets no credentials at all - unless the administrator explicitly
/// accepted that risk with <see cref="ProxySettings.AllowUntrustedPac"/> (<see cref="Updates.PacCredentialsAllowed"/>).</summary>
internal sealed class PacWebProxy(ProxySettings settings) : IWebProxy
{
    private readonly string _pac = settings.Pac.Trim();

    public ICredentials? Credentials { get; set; } = PacCredentials(settings);

    internal static ICredentials? PacCredentials(ProxySettings settings)
    {
        if (!Updates.PacCredentialsAllowed(settings)) return null;
        return settings.User.Length == 0 ? CredentialCache.DefaultCredentials : new ProxyAccount(settings.User, settings.Password);
    }

    private string? Chosen(Uri destination)
    {
        var p = global::ADmiral.Core.Pac.ProxyFor(_pac, destination.AbsoluteUri);
        if (p is null) return null;
        return p.Contains("://", StringComparison.Ordinal) ? p : "http://" + p;
    }

    public Uri? GetProxy(Uri destination) => Chosen(destination) is { } p ? new Uri(p) : null;

    public bool IsBypassed(Uri host) => Chosen(host) is null;
}

/// <summary>The proxy account. Password logins (Basic, Digest) get the user name exactly as typed - <c>user@domain</c>
/// or <c>DOMAIN\user</c>, whichever the proxy's user list holds. Windows authentication (NTLM, Negotiate, Kerberos) gets
/// it split into user name + domain, the way SSPI expects it. .NET asks for the credential per challenge scheme.</summary>
public sealed class ProxyAccount(string user, string password) : ICredentials
{
    public string User { get; } = user;

    public NetworkCredential GetCredential(Uri uri, string authType) =>
        IsWindowsAuth(authType) ? Split(User, password) : new NetworkCredential(User, password);

    public static bool IsWindowsAuth(string? authType) =>
        authType is not null && (authType.Equals("NTLM", StringComparison.OrdinalIgnoreCase)
                                 || authType.Equals("Negotiate", StringComparison.OrdinalIgnoreCase)
                                 || authType.Equals("Kerberos", StringComparison.OrdinalIgnoreCase));

    /// <summary><c>DOMAIN\user</c> and <c>user@domain</c> -> user name + domain; anything else unchanged.</summary>
    public static NetworkCredential Split(string user, string password)
    {
        var bs = user.IndexOf('\\');
        if (bs > 0 && bs < user.Length - 1) return new NetworkCredential(user[(bs + 1)..], password, user[..bs]);
        var at = user.LastIndexOf('@');
        if (at > 0 && at < user.Length - 1) return new NetworkCredential(user[..at], password, user[(at + 1)..]);
        return new NetworkCredential(user, password);
    }
}

public static partial class Updates
{
    public const string Msrc = "https://api.msrc.microsoft.com/cvrf/v3.0";

    /// <summary>Largest JSON document accepted from the internet (an NVD page of 2000 CVEs is a few tens of MB).</summary>
    public const long MaxJsonBytes = 128L * 1024 * 1024;

    /// <summary>Largest file <see cref="MakeDownloader"/> writes.</summary>
    public const long MaxDownloadBytes = 2L * 1024 * 1024 * 1024;

    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);

    [GeneratedRegex(@"^(\d+\.\d+\.\d+)\.(\d+)$")]
    private static partial Regex BuildRe();

    // ------------------------------------------------------------------ proxy helpers
    /// <summary>The error text, with a hint when the proxy asked for authentication (HTTP 407).</summary>
    public static string ExplainError(Exception exc)
    {
        var text = $"{exc.GetType().Name}: {exc.Message}";
        if (text.Contains("407", StringComparison.Ordinal)
            || exc is HttpRequestException { StatusCode: HttpStatusCode.ProxyAuthenticationRequired })
            text += " - " + I18n.T("err.proxy_407");
        return text;
    }

    // ------------------------------------------------------------------ the proxy test (Settings → Proxy)
    /// <summary>The address the proxy test opens (the CISA list the vulnerability job downloads lives there too).</summary>
    public const string ProxyTestTarget = "https://www.cisa.gov/";

    /// <summary>Which proxy a request to <paramref name="target"/> goes through: source "explicit" (the proxy address
    /// setting), "pac", "system" (Windows' proxy settings) or "none" (direct), and the proxy (no account in it).</summary>
    public static (string Source, Uri? Proxy) ResolveProxy(ProxySettings p, Uri target, IWebProxy? systemProxy = null)
    {
        ArgumentNullException.ThrowIfNull(p);
        ArgumentNullException.ThrowIfNull(target);
        if (p.Url.Trim().Length > 0)
            return ("explicit", ((WebProxy)WebProxyFor(p)!).Address);
        if ((p.Pac ?? "").Trim().Length > 0)
        {
            var chosen = global::ADmiral.Core.Pac.ProxyFor(p.Pac!, target.AbsoluteUri);          // throws PacError
            if (chosen is null) return ("none", null);
            return ("pac", new Uri(chosen.Contains("://", StringComparison.Ordinal) ? chosen : "http://" + chosen));
        }
        var sys = systemProxy ?? HttpClient.DefaultProxy;
        if (sys.IsBypassed(target)) return ("none", null);
        var px = sys.GetProxy(target);
        return px is null || px == target ? ("none", null) : ("system", px);
    }

    /// <summary>What the proxy is given: "account" (the user name, shown), "windows" (integrated Kerberos / NTLM) or
    /// "none" (a proxy from an untrusted PAC file gets nothing).</summary>
    public static (string Kind, string? User) ProxyCredentialKind(ProxySettings p, string source)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (source == "pac" && !PacCredentialsAllowed(p)) return ("none", null);
        if (p.User.Length > 0) return ("account", p.User);
        if (source == "explicit")
        {
            var url = p.Url.Trim();
            var uri = new Uri(url.Contains("://", StringComparison.Ordinal) ? url : "http://" + url);
            if (uri.UserInfo.Length > 0) return ("account", Uri.UnescapeDataString(Partition(uri.UserInfo, ':').Item1));
        }
        return ("windows", null);
    }

    /// <summary>The authentication schemes the proxy offers (its Proxy-Authenticate header), read from a plain-http
    /// request sent through it without any credentials; empty = it let the request through without a login.</summary>
    public static List<string> ProbeProxySchemes(Uri proxy, Uri target)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(target);
        using var h = new SocketsHttpHandler
        {
            UseProxy = true, Proxy = new WebProxy(proxy) { Credentials = null }, ConnectTimeout = ConnectTimeout,
            AllowAutoRedirect = false, PreAuthenticate = false,
        };
        using var c = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(20) };
        var probe = new UriBuilder(target) { Scheme = "http", Port = -1 }.Uri;       // http: the 407 comes back as a response
        using var req = Request(HttpMethod.Get, probe.AbsoluteUri, "*/*", null);
        using var resp = c.Send(req, HttpCompletionOption.ResponseHeadersRead);
        if (resp.StatusCode != HttpStatusCode.ProxyAuthenticationRequired) return [];
        return [.. resp.Headers.ProxyAuthenticate.Select(a => a.Scheme).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>True when every scheme the proxy offers needs a password typed in (Basic / Digest): the Windows logon
    /// cannot be used for them, so without a proxy account every request ends in 407.</summary>
    public static bool NeedsProxyAccount(IReadOnlyList<string>? schemes) =>
        schemes is { Count: > 0 } && schemes.All(s => !ProxyAccount.IsWindowsAuth(s));

    /// <summary>The proxy test: where the traffic goes, what the proxy asks for, what ADmiral gives it, and whether an
    /// https request through it works. Never throws; the text is shown on the settings page (no password in it).</summary>
    public static (bool Ok, string Message) TestProxy(ProxySettings p, string target = ProxyTestTarget,
                                                    Func<Uri, Uri, IReadOnlyList<string>>? probe = null, HttpClient? client = null,
                                                    IWebProxy? systemProxy = null)
    {
        ArgumentNullException.ThrowIfNull(p);
        var uri = new Uri(target);
        var lines = new List<string>();
        string source;
        Uri? proxy;
        try
        {
            (source, proxy) = ResolveProxy(p, uri, systemProxy);
        }
        catch (Exception exc) when (exc is PacError or UriFormatException or ArgumentException or IOException or HttpRequestException)
        {
            return (false, "✗ " + ExplainError(exc));
        }
        IReadOnlyList<string>? schemes = null;
        if (proxy is null)
        {
            lines.Add(I18n.T("proxy.none"));
        }
        else
        {
            lines.Add(I18n.T("proxy.source_" + source, ("proxy", proxy.GetLeftPart(UriPartial.Authority))));
            try
            {
                schemes = (probe ?? ProbeProxySchemes)(proxy, uri);
                lines.Add(schemes.Count == 0 ? I18n.T("proxy.no_auth") : I18n.T("proxy.schemes", ("schemes", string.Join(", ", schemes))));
            }
            catch (Exception exc) when (exc is HttpRequestException or IOException or TaskCanceledException or InvalidOperationException)
            {
                lines.Add(I18n.T("proxy.schemes_unknown", ("err", exc.Message)));
            }
            // the administrator chose to trust an untrusted PAC file: say so every time the proxy is tested
            if (source == "pac" && !PacTrusted(p) && p.AllowUntrustedPac) lines.Add(I18n.T("proxy.untrusted_pac_on"));
            var (kind, user) = ProxyCredentialKind(p, source);
            lines.Add(kind == "account" ? I18n.T("proxy.cred_account", ("user", user)) : I18n.T("proxy.cred_" + kind));
            if (kind != "account" && NeedsProxyAccount(schemes))
                lines.Add(I18n.T("proxy.need_account", ("schemes", string.Join(", ", schemes!))));
        }
        var ok = false;
        try
        {
            Prepare(p, direct: false, target);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var req = Request(HttpMethod.Get, target, "*/*", null);
            using var resp = (client ?? Client(p)).SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
            if (resp.StatusCode == HttpStatusCode.ProxyAuthenticationRequired)
                throw new HttpRequestException("407 Proxy Authentication Required", null, HttpStatusCode.ProxyAuthenticationRequired);
            ok = true;
            lines.Add(I18n.T("proxy.ok", ("target", uri.Host), ("code", (int)resp.StatusCode)));
        }
        catch (Exception exc) when (exc is HttpRequestException or IOException or TaskCanceledException or OperationCanceledException
                                        or PacError or InvalidOperationException)
        {
            lines.Add(I18n.T("proxy.failed", ("err", ExplainError(exc))));
        }
        return (ok, string.Join("\n", lines));
    }

    /// <summary>True if a proxy address or a PAC file is configured (else the system proxy is used).</summary>
    public static bool UsesProxySetting(ProxySettings p) => p.Url.Trim().Length > 0 || (p.Pac ?? "").Trim().Length > 0;

    /// <summary>A PAC file from a local / network path or an https address. <c>auto</c> (WPAD: http://wpad/wpad.dat)
    /// and plain http can be answered by anyone on the network (LLMNR / NBNS spoofing), who would then pick the
    /// proxy: the proxy account's password is never sent to a proxy chosen by such a file.</summary>
    public static bool PacTrusted(ProxySettings p)
    {
        var src = (p.Pac ?? "").Trim().ToLowerInvariant();
        return src.Length > 0 && src != "auto" && !src.StartsWith("http://", StringComparison.Ordinal);
    }

    /// <summary>May a proxy chosen by the PAC file get credentials? Yes for a trusted PAC (<see cref="PacTrusted"/>);
    /// for an untrusted one (auto / http) only when the administrator turned on
    /// <see cref="ProxySettings.AllowUntrustedPac"/> and confirmed the risk on the settings screen.</summary>
    public static bool PacCredentialsAllowed(ProxySettings p)
    {
        ArgumentNullException.ThrowIfNull(p);
        return PacTrusted(p) || p.AllowUntrustedPac;
    }

    /// <summary><c>http://user:pass@host:port</c> (credentials URL-encoded), or null for the system proxy / DIRECT.
    /// With no address but a PAC file, the proxy the PAC picks for <paramref name="target"/> is used.
    /// (For display and checks: the HTTP client itself gets the account as a credential, not in a URL.)</summary>
    public static string? ProxyUrl(ProxySettings p, string target = "https://www.microsoft.com/")
    {
        var url = p.Url.Trim();
        var fromPac = false;
        if (url.Length == 0 && (p.Pac ?? "").Trim().Length > 0)
        {
            url = global::ADmiral.Core.Pac.ProxyFor(p.Pac!, target) ?? "";
            fromPac = true;
        }
        if (url.Length == 0) return null;
        if (!url.Contains("://", StringComparison.Ordinal)) url = "http://" + url;
        var uri = new Uri(url);
        var hostPort = uri.IsDefaultPort && !HasExplicitPort(url) ? uri.Host : $"{uri.Host}:{uri.Port.ToString(CultureInfo.InvariantCulture)}";
        if (p.User.Length > 0 && fromPac && !PacCredentialsAllowed(p))
        {
            Log.Logger.LogWarning("Proxy {Host} comes from an untrusted PAC file ({Pac}): the proxy account is not sent to it", uri.Host, p.Pac);
        }
        else if (p.User.Length > 0)
        {
            var cred = Uri.EscapeDataString(p.User) + (p.Password.Length > 0 ? ":" + Uri.EscapeDataString(p.Password) : "");
            return $"{uri.Scheme}://{cred}@{hostPort}{PathOf(uri)}";
        }
        var userInfo = uri.UserInfo.Length > 0 ? uri.UserInfo + "@" : "";
        return $"{uri.Scheme}://{userInfo}{hostPort}{PathOf(uri)}";
    }

    private static bool HasExplicitPort(string url)
    {
        var rest = url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var end = rest.IndexOfAny(['/', '?', '#']);
        var authority = end < 0 ? rest : rest[..end];
        authority = authority[(authority.LastIndexOf('@') + 1)..];
        return authority.LastIndexOf(':') > authority.LastIndexOf(']');
    }

    private static string PathOf(Uri uri) => uri.PathAndQuery == "/" && !uri.OriginalString.EndsWith('/') ? "" : uri.PathAndQuery;

    /// <summary><c>ADmiral/&lt;version&gt;</c>: nothing else.</summary>
    public static string UserAgent() => "ADmiral/" + Diag.Version;

    // ------------------------------------------------------------------ the shared HTTP clients
    private static readonly ConcurrentDictionary<string, HttpClient> Clients = new(StringComparer.Ordinal);
    private const int MaxCachedClients = 16;

    /// <summary>The IWebProxy for the settings: an explicit proxy, the PAC file, or null (= the system proxy).</summary>
    public static IWebProxy? WebProxyFor(ProxySettings p)
    {
        var url = p.Url.Trim();
        if (url.Length == 0)
            return (p.Pac ?? "").Trim().Length > 0 ? new PacWebProxy(p) : null;
        if (!url.Contains("://", StringComparison.Ordinal)) url = "http://" + url;
        var uri = new Uri(url);
        ICredentials cred;
        if (p.User.Length > 0) cred = new ProxyAccount(p.User, p.Password);
        else if (uri.UserInfo.Length > 0)
        {
            var (u, _, pw) = Partition(uri.UserInfo, ':');
            cred = new ProxyAccount(Uri.UnescapeDataString(u), Uri.UnescapeDataString(pw));
        }
        else cred = CredentialCache.DefaultCredentials;      // integrated (Kerberos / NTLM) proxy authentication
        var clean = new UriBuilder(uri) { UserName = "", Password = "" }.Uri;
        return new WebProxy(clean, BypassOnLocal: false) { Credentials = cred };
    }

    private static (string, string, string) Partition(string s, char sep)
    {
        var i = s.IndexOf(sep);
        return i < 0 ? (s, "", "") : (s[..i], sep.ToString(), s[(i + 1)..]);
    }

    /// <summary>A new handler for the settings (<paramref name="direct"/>: never through any proxy). TLS validation
    /// stays at the platform default (always on); redirects never go from https to http (the .NET default).</summary>
    public static SocketsHttpHandler CreateHandler(ProxySettings? p, bool direct = false)
    {
        var h = new SocketsHttpHandler
        {
            ConnectTimeout = ConnectTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.All,     // the size caps apply to the decompressed bytes
            MaxResponseHeadersLength = 64,                         // KB
        };
        if (direct || p is null)
        {
            h.UseProxy = false;
            return h;
        }
        var proxy = WebProxyFor(p);
        h.UseProxy = true;
        if (proxy is not null) h.Proxy = proxy;
        // the system proxy: the proxy account when one is set (the proxy address field left empty), else integrated auth
        else h.DefaultProxyCredentials = p.User.Length > 0 ? new ProxyAccount(p.User, p.Password) : CredentialCache.DefaultCredentials;
        return h;
    }

    /// <summary>The one shared HttpClient for these proxy settings (<paramref name="direct"/>: no proxy at all).
    /// Its <see cref="HttpClient.Timeout"/> is a 10-minute backstop; callers pass their own, shorter timeout.</summary>
    public static HttpClient Client(ProxySettings? p, bool direct = false)
    {
        var key = direct || p is null ? "direct" : ClientKey(p);
        if (Clients.TryGetValue(key, out var hit)) return hit;
        if (Clients.Count >= MaxCachedClients) Clients.Clear();   // settings changed many times: start over (old clients are left to the GC)
        return Clients.GetOrAdd(key, _ => new HttpClient(CreateHandler(p, direct), disposeHandler: true)
        {
            Timeout = TimeSpan.FromMinutes(10),
        });
    }

    private static string ClientKey(ProxySettings p)
    {
        // the trust switch changes what the proxy is given, so it gets its own client (and connection pool)
        var raw = string.Join("\n", p.Url.Trim(), (p.Pac ?? "").Trim(), p.User, p.Password, p.AllowUntrustedPac ? "1" : "0");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    /// <summary>Evaluates the PAC file for <paramref name="url"/> before a request: .NET treats an exception thrown by
    /// an IWebProxy as "no proxy", but a broken PAC file must be an error shown to the user, not a silent DIRECT.</summary>
    private static void Prepare(ProxySettings? p, bool direct, string url)
    {
        if (direct || p is null || p.Url.Trim().Length > 0 || (p.Pac ?? "").Trim().Length == 0) return;
        global::ADmiral.Core.Pac.ProxyFor(p.Pac!, url);       // throws PacError
    }

    private static HttpRequestMessage Request(HttpMethod method, string url, string accept, IReadOnlyDictionary<string, string>? headers)
    {
        var uri = new Uri(url, UriKind.Absolute);
        if (uri.Scheme is not ("https" or "http")) throw new ArgumentException($"not an http(s) address: {url}");
        var req = new HttpRequestMessage(method, uri);
        req.Headers.TryAddWithoutValidation("User-Agent", UserAgent());
        req.Headers.Accept.ParseAdd(accept);
        foreach (var (k, v) in headers ?? new Dictionary<string, string>())
        {
            if (k.Equals("accept", StringComparison.OrdinalIgnoreCase))
            {
                req.Headers.Accept.Clear();
                req.Headers.Accept.ParseAdd(v);
            }
            else req.Headers.TryAddWithoutValidation(k, v);
        }
        return req;
    }

    /// <summary>Copy the response body into <paramref name="dest"/> (at most <paramref name="maxBytes"/>), hashing it
    /// with <paramref name="hash"/> when given. Throws <see cref="ResponseTooLargeException"/>.</summary>
    public static async Task<long> CopyCappedAsync(HttpResponseMessage resp, Stream dest, long maxBytes, IncrementalHash? hash, CancellationToken ct)
    {
        if (resp.Content.Headers.ContentLength is long len && len > maxBytes)
            throw new ResponseTooLargeException($"the response is too large ({len} bytes, at most {maxBytes})");
        await using var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[256 * 1024];
        long total = 0;
        int n;
        while ((n = await src.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            total += n;
            if (total > maxBytes) throw new ResponseTooLargeException($"the response is too large (more than {maxBytes} bytes)");
            hash?.AppendData(buf, 0, n);
            await dest.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
        }
        return total;
    }

    /// <summary>GET <paramref name="url"/> and return the body (at most <paramref name="maxBytes"/>).</summary>
    public static async Task<byte[]> GetBytesAsync(HttpClient client, string url, long maxBytes, TimeSpan timeout,
                                                   IReadOnlyDictionary<string, string>? headers = null, string accept = "*/*",
                                                   CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var req = Request(HttpMethod.Get, url, accept, headers);
        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        using var ms = new MemoryStream();
        await CopyCappedAsync(resp, ms, maxBytes, null, cts.Token).ConfigureAwait(false);
        return ms.ToArray();
    }

    /// <summary>Parse JSON text from the internet (bounded depth; a UTF-8 BOM is accepted).</summary>
    public static JsonNode? ParseJson(ReadOnlySpan<byte> utf8)
    {
        if (utf8.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) utf8 = utf8[3..];
        return JsonNode.Parse(utf8, documentOptions: new JsonDocumentOptions { MaxDepth = 128 });
    }

    /// <summary>A function <c>url -&gt; parsed JSON</c> that goes through the configured proxy (or the system's).
    /// <paramref name="client"/> replaces the shared client (tests: a fake handler).</summary>
    public static Func<string, JsonNode?> MakeGetter(ProxySettings p, int timeoutSeconds = 120,
                                                     IReadOnlyDictionary<string, string>? headers = null,
                                                     HttpClient? client = null, bool direct = false)
    {
        var http = client ?? Client(p, direct);
        var timeout = TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds) + ConnectTimeout.TotalSeconds);
        return url =>
        {
            Prepare(p, direct, url);
            var bytes = GetBytesAsync(http, url, MaxJsonBytes, timeout, headers, "application/json").GetAwaiter().GetResult();
            return ParseJson(bytes);
        };
    }

    /// <summary>A downloader <c>(url, dest, sha256?) -&gt; dest</c>: streams the file to <c>dest</c> (created new; an
    /// existing file is replaced) through the proxy; with <c>sha256</c> the file must match it, otherwise it is
    /// deleted and an <see cref="InvalidDataException"/> raised.</summary>
    public static Func<string, string, string?, string> MakeDownloader(ProxySettings p, int timeoutSeconds = 300, bool direct = false,
                                                                       IReadOnlyDictionary<string, string>? headers = null,
                                                                       HttpClient? client = null, long maxBytes = MaxDownloadBytes)
    {
        var http = client ?? Client(p, direct);
        var timeout = TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds) + ConnectTimeout.TotalSeconds);
        return (url, dest, sha256) =>
        {
            Prepare(p, direct, url);
            string hex;
            try
            {
                using var cts = new CancellationTokenSource(timeout);
                using var req = Request(HttpMethod.Get, url, "*/*", headers);
                using var resp = http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
                resp.EnsureSuccessStatusCode();
                using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using (var f = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None))
                    CopyCappedAsync(resp, f, maxBytes, h, cts.Token).GetAwaiter().GetResult();
                hex = Convert.ToHexStringLower(h.GetHashAndReset());
            }
            catch
            {
                TryDelete(dest);
                throw;
            }
            if (sha256 is { Length: > 0 } && !string.Equals(hex, sha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(dest);
                throw new InvalidDataException($"SHA-256 mismatch for {Path.GetFileName(dest)}");
            }
            return dest;
        };
    }

    internal static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>A JSON number as a double (null for anything else), whatever .NET type backs the node.</summary>
    public static double? Number(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.Number
        && double.TryParse(v.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d : null;

    // ------------------------------------------------------------------ MSRC data
    private static string Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s
        : n is JsonValue v2 && v2.GetValueKind() == JsonValueKind.Number ? v2.ToJsonString() : "";

    private static IEnumerable<JsonNode?> Items(JsonNode? n) => n as JsonArray ?? [];

    // ------------------------------------------------------------------ product families
    // One Windows build number is shared by several products: 10.0.26100 is Windows 11 24H2 (and LTSC 2024) and
    // Windows Server 2025, whose cumulative updates have very different revisions (26100.9974 vs 26100.33822). The
    // reference is therefore kept per build *and* family; a computer is only compared with its own family's line.
    // Hotpatch releases (SubType "Security Hotpatch Update", or a product named "... (Hotpatch)") are a separate line
    // and never count: a computer on the normal monthly line would otherwise look out of date or up to date wrongly.

    public const string FamilyClient = "client";
    public const string FamilyServer = "server";
    /// <summary>The suffix of a server build's reference key: "10.0.26100/server" (a client build's key is the build alone).</summary>
    public const string ServerSuffix = "/" + FamilyServer;

    /// <summary>The reference key of <paramref name="build"/> ("10.0.26100") for <paramref name="family"/>.</summary>
    public static string RefKey(string build, string family) => family == FamilyServer ? build + ServerSuffix : build;

    /// <summary>The build and family of a reference key: ("10.0.26100", "server") of "10.0.26100/server".</summary>
    public static (string Build, string Family) SplitRefKey(string key) =>
        key.EndsWith(ServerSuffix, StringComparison.Ordinal) ? (key[..^ServerSuffix.Length], FamilyServer) : (key, FamilyClient);

    [GeneratedRegex(@"^Windows (?:10|11)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ClientProductRe();

    /// <summary>The family of an MSRC product name: client (Windows 10 / 11), server (Windows Server), or null for
    /// anything else (Office, a hotpatch product ...).</summary>
    public static string? ProductFamily(string? name)
    {
        var n = (name ?? "").Trim();
        if (n.Length == 0 || n.Contains("hotpatch", StringComparison.OrdinalIgnoreCase)) return null;
        if (n.StartsWith("Windows Server", StringComparison.OrdinalIgnoreCase)) return FamilyServer;
        return ClientProductRe().IsMatch(n) ? FamilyClient : null;
    }

    /// <summary>The family of a computer from its inventory: server when the OS caption says so, else client.</summary>
    public static string ComputerFamily(JsonObject? inv) => OsNameFamily(Str(inv?["os_caption"]));

    /// <summary>The family of an operating system name (the inventory caption or AD's operatingSystem): server when it
    /// says so, else client.</summary>
    public static string OsNameFamily(string? os) =>
        (os ?? "").Contains("Server", StringComparison.OrdinalIgnoreCase) ? FamilyServer : FamilyClient;

    /// <summary>ProductID -&gt; name, from the document's ProductTree (FullProductName and the nested Branch items).</summary>
    private static Dictionary<string, string> ProductNames(JsonNode? doc)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        void Add(JsonNode? p)
        {
            var id = Str(p?["ProductID"]);
            var name = Str(p?["Value"]);
            if (id.Length > 0 && name.Length > 0) names.TryAdd(id, name);
        }
        var tree = doc?["ProductTree"];
        foreach (var p in Items(tree?["FullProductName"])) Add(p);
        var stack = new Stack<(JsonNode? Node, int Depth)>();
        foreach (var b in Items(tree?["Branch"])) stack.Push((b, 0));
        while (stack.Count > 0)
        {
            var (n, depth) = stack.Pop();
            if (n is not JsonObject || depth > 16) continue;
            foreach (var it in Items(n["Items"]))
            {
                Add(it);
                if (it?["Items"] is JsonArray) stack.Push((it, depth + 1));
            }
        }
        return names;
    }

    /// <summary>One reference entry read from a release: the newest fixed revision, its KB ("" when not named) and the
    /// product it was read from ("" without a ProductTree).</summary>
    public sealed record ReleaseRef(long Ubr, string Kb, string Product);

    /// <summary>One monthly CVRF document -&gt; {"10.0.26100": client entry, "10.0.26100/server": server entry, ...}.
    /// Only Windows client / server products count, hotpatch remediations are skipped. A document without a
    /// ProductTree (hand-made data) counts every fixed build as client.</summary>
    public static Dictionary<string, ReleaseRef> ParseReleaseRefs(JsonNode? doc)
    {
        var best = new Dictionary<string, ReleaseRef>(StringComparer.Ordinal);
        var names = ProductNames(doc);
        foreach (var vuln in Items(doc?["Vulnerability"]))
            foreach (var rem in Items(vuln?["Remediations"]))
            {
                if (Str(rem?["SubType"]).Contains("hotpatch", StringComparison.OrdinalIgnoreCase)) continue;
                if (rem?["Type"] is JsonValue tv && tv.GetValueKind() == JsonValueKind.Number && Str(tv) != "2") continue;   // 2 = vendor fix
                var m = BuildRe().Match(Str(rem?["FixedBuild"]));
                if (!m.Success || !long.TryParse(m.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var ubr)) continue;
                var kb = WinUpdate.ValidKb(Str(rem?["Description"]?["Value"])) ?? "";
                var build = m.Groups[1].Value;
                // family -> a product name of it (x64 preferred: it is what the computers mostly run)
                var families = new Dictionary<string, string>(StringComparer.Ordinal);
                if (names.Count == 0) families[FamilyClient] = "";
                else
                    foreach (var pid in Items(rem?["ProductID"]))
                    {
                        if (!names.TryGetValue(Str(pid), out var name) || ProductFamily(name) is not { } fam) continue;
                        if (!families.TryGetValue(fam, out var had)
                            || (!had.Contains("x64", StringComparison.OrdinalIgnoreCase) && name.Contains("x64", StringComparison.OrdinalIgnoreCase)))
                            families[fam] = name;
                    }
                foreach (var (fam, product) in families)
                {
                    var key = RefKey(build, fam);
                    if (!best.TryGetValue(key, out var cur) || ubr > cur.Ubr || (ubr == cur.Ubr && cur.Kb.Length == 0 && kb.Length > 0))
                        best[key] = new ReleaseRef(ubr, kb, product);
                }
            }
        return best;
    }

    /// <summary>One monthly CVRF document -&gt; {"10.0.22631": newest fixed revision, ...} (keys as <see cref="RefKey"/>).</summary>
    public static Dictionary<string, long> ParseRelease(JsonNode? doc) =>
        ParseReleaseRefs(doc).ToDictionary(kv => kv.Key, kv => kv.Value.Ubr, StringComparer.Ordinal);

    /// <summary>One monthly CVRF document -&gt; {"10.0.22631": (newest fixed revision, its KB number or "")}.</summary>
    public static Dictionary<string, (long Ubr, string Kb)> ParseReleaseKbs(JsonNode? doc) =>
        ParseReleaseRefs(doc).ToDictionary(kv => kv.Key, kv => (kv.Value.Ubr, kv.Value.Kb), StringComparer.Ordinal);

    /// <summary>A text fetcher <c>(url, form or null) -&gt; body</c> through the configured proxy: GET, or a POST of the
    /// form fields (application/x-www-form-urlencoded). The body is at most <see cref="MaxJsonBytes"/>.</summary>
    public static Func<string, IReadOnlyDictionary<string, string>?, string> MakeTextFetcher(ProxySettings p, int timeoutSeconds = 60,
                                                                                         HttpClient? client = null, bool direct = false)
    {
        var http = client ?? Client(p, direct);
        var timeout = TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds) + ConnectTimeout.TotalSeconds);
        return (url, form) =>
        {
            Prepare(p, direct, url);
            using var cts = new CancellationTokenSource(timeout);
            using var req = Request(form is null ? HttpMethod.Get : HttpMethod.Post, url, "text/html, */*", null);
            if (form is not null) req.Content = new FormUrlEncodedContent(form);
            using var resp = http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();
            using var ms = new MemoryStream();
            CopyCappedAsync(resp, ms, MaxJsonBytes, null, cts.Token).GetAwaiter().GetResult();
            return Encoding.UTF8.GetString(ms.ToArray());
        };
    }

    /// <summary>Download the newest <paramref name="months"/> security releases and merge them.</summary>
    public static UpdateReferenceData FetchReference(ProxySettings p, int months = 3, Func<string, JsonNode?>? get = null,
                                                     Action<int, int, string>? progress = null)
    {
        get ??= MakeGetter(p);
        var listing = Items(get($"{Msrc}/updates")?["value"]).OfType<JsonObject>()
            .OrderByDescending(u => Str(u["InitialReleaseDate"]), StringComparer.Ordinal).ToList();
        var wanted = listing.Take(Math.Max(1, months)).ToList();
        if (wanted.Count == 0) throw new InvalidDataException("The Microsoft security update list is empty");
        var builds = new Dictionary<string, UpdateRef>(StringComparer.Ordinal);
        var kbs = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < wanted.Count; i++)
        {
            var upd = wanted[i];
            var month = Str(upd["ID"]) is { Length: > 0 } id ? id : "?";
            progress?.Invoke(i, wanted.Count, month);
            var cvrf = Str(upd["CvrfUrl"]) is { Length: > 0 } u ? u : $"{Msrc}/cvrf/{Uri.EscapeDataString(month)}";
            var doc = get(cvrf);
            var released = Str(doc?["DocumentTracking"]?["InitialReleaseDate"]) is { Length: > 0 } r ? r : Str(upd["InitialReleaseDate"]);
            if (released.Length > 10) released = released[..10];
            foreach (var (key, rr) in ParseReleaseRefs(doc))
                if (!builds.TryGetValue(key, out var cur) || rr.Ubr > cur.Ubr)
                {
                    builds[key] = new UpdateRef(rr.Ubr, month, released)
                    {
                        Kb = rr.Kb.Length > 0 ? rr.Kb : null, Product = rr.Product.Length > 0 ? rr.Product : null,
                    };
                    if (rr.Kb.Length > 0) kbs[key] = rr.Kb;
                    else kbs.Remove(key);
                }
        }
        progress?.Invoke(wanted.Count, wanted.Count, "OK");
        if (builds.Count == 0) throw new InvalidDataException("No Windows build numbers found in the Microsoft security releases");
        return new UpdateReferenceData(builds, [.. wanted.Select(u => Str(u["ID"]))]) { Kbs = kbs };
    }

    /// <summary>State of one computer: current | missing | pending (newer release within the grace period) | unknown.</summary>
    public static SecurityState GetSecurityState(JsonObject? inv, IReadOnlyDictionary<string, UpdateRef> builds, int graceDays = 0,
                                                 DateTimeOffset? now = null)
    {
        if (inv is null) return SecurityState.Unknown;
        var ver = Str(inv["os_version"]);
        var parts = Str(inv["os_build"]).Split('.');
        // only the computer's own family: a Windows 11 is never compared with Windows Server's line of the same build
        if (!builds.TryGetValue(RefKey(ver, ComputerFamily(inv)), out var reference)) return SecurityState.Unknown;
        if (parts.Length < 2 || !long.TryParse(parts[1].Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var ubr))
            return SecurityState.Unknown;
        var state = "current";
        if (ubr < reference.Ubr)
        {
            state = "missing";
            if (graceDays > 0 && !string.IsNullOrEmpty(reference.Released)
                && DateTime.TryParse(reference.Released, CultureInfo.InvariantCulture,
                                     DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var rel)
                && ((now ?? DateTimeOffset.UtcNow) - new DateTimeOffset(rel, TimeSpan.Zero)).TotalDays < graceDays)
                state = "pending";
        }
        return new SecurityState(state, $"{ver}.{ubr}", $"{ver}.{reference.Ubr}", reference.Month, reference.Released);
    }
}
