using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using ADmiral.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("ADmiral.Tests")]

namespace ADmiral.Web;

/// <summary>How <see cref="WebApp.Create"/> builds the local web UI / JSON API.</summary>
public sealed class WebAppOptions
{
    /// <summary>The per-launch API token: every API call must send it in the X-ADmiral-Token header (required).</summary>
    public string Token { get; set; } = "";

    /// <summary>Address Kestrel listens on (127.0.0.1, localhost or ::1 unless <see cref="AllowRemote"/>).</summary>
    public string Host { get; set; } = "127.0.0.1";

    /// <summary>TCP port; 0 = any free port (see <see cref="WebApp.BoundAddress"/>).</summary>
    public int Port { get; set; }

    /// <summary>Allow a non-loopback <see cref="Host"/> (only behind an authenticating TLS reverse proxy). The Host-header
    /// check is then off, as in the Python version.</summary>
    public bool AllowRemote { get; set; }

    /// <summary>Folder of the UI files (default: wwwroot next to the program).</summary>
    public string? StaticRoot { get; set; }

    /// <summary>Additional log sink of the web host (e.g. the diagnostics provider); not disposed by the app.</summary>
    public ILoggerProvider? ExtraLogger { get; set; }

    /// <summary>"desktop" in /api/status: true for the desktop shell (default), false for <c>admiral serve</c>.</summary>
    public bool Desktop { get; set; } = true;

    /// <summary>Largest JSON request body (the package upload has its own, larger cap).</summary>
    public long MaxBodyBytes { get; set; } = 32L * 1024 * 1024;

    /// <summary>Host the sync listener (POST /sync/v1/{op}) on its own port when the service wants it.</summary>
    public bool SyncListener { get; set; } = true;

    /// <summary>Address the sync listener binds (Python: 0.0.0.0; peers connect over the network).</summary>
    public IPAddress SyncBindAddress { get; set; } = IPAddress.Any;
}

/// <summary>Port of admiral/web.py: the JSON API plus the single-page UI, on ASP.NET Core minimal APIs.</summary>
public static partial class WebApp
{
    public const string CsrfHeader = "X-ADmiral";
    public const string TokenHeader = "X-ADmiral-Token";

    /// <summary>Host names accepted in the Host header while listening on loopback (blocks DNS rebinding).</summary>
    public static readonly IReadOnlySet<string> LoopbackNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "localhost", "::1" };

    private static readonly string[] AllowedHostHeaders = ["localhost", "127.0.0.1", "[::1]"];

    /// <summary>Defence in depth against injected markup: only ADmiral's own scripts run, nothing is sent anywhere else.</summary>
    public static readonly IReadOnlyDictionary<string, string> SecurityHeaders = new Dictionary<string, string>
    {
        ["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                      + "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
                                      + "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; "
                                      // no frames / workers at all; every innerHTML passes the default Trusted Types
                                      // policy (tt.js), which defuses <meta http-equiv=refresh> and friends - CSP itself
                                      // cannot stop a meta refresh from navigating the window
                                      + "frame-src 'none'; child-src 'none'; worker-src 'none'; "
                                      + "require-trusted-types-for 'script'; trusted-types default",
        ["X-Content-Type-Options"] = "nosniff",
        ["Referrer-Policy"] = "no-referrer",
        ["X-Frame-Options"] = "DENY",
    };

    /// <summary>How API responses are written: the keys exactly as the service returns them (snake_case).</summary>
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = null,
        DictionaryKeyPolicy = null,
        NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        MaxDepth = 128,
    };

    internal sealed class State(AdmiralService service, WebAppOptions options, byte[] tokenHash)
    {
        public AdmiralService Service { get; } = service;
        public WebAppOptions Options { get; } = options;
        public byte[] TokenHash { get; } = tokenHash;
        public bool CheckHost { get; set; }
        public int BoundPort { get; set; }
        public SyncListenerHost? Sync { get; set; }
    }

    /// <summary>Build the app (not started). Every API call needs <see cref="WebAppOptions.Token"/>, so other local users /
    /// processes can't use the port; the page itself and /static need none (the token reaches the page in the
    /// <c>?token=</c> address the host opens, app.js keeps it in sessionStorage and removes it from the address bar).</summary>
    public static WebApplication Create(AdmiralService service, WebAppOptions options)
    {
        ArgumentNullException.ThrowIfNull(service);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Token)) throw new ArgumentException("An API token is required.", nameof(options));
        var loopback = LoopbackNames.Contains(options.Host);
        if (!loopback && !options.AllowRemote)
            throw new ArgumentException($"Refusing to listen on {options.Host}: use a loopback address, or AllowRemote behind an authenticating reverse proxy with TLS.", nameof(options));
        var bind = BindAddress(options.Host);
        var staticRoot = Path.GetFullPath(options.StaticRoot ?? Path.Combine(AppContext.BaseDirectory, "wwwroot"));

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(WebApp).Assembly.GetName().Name,
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production,
            Args = [],
        });
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        if (options.ExtraLogger is { } extra) builder.Logging.AddProvider(new NonOwningProvider(extra));
        builder.WebHost.UseKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = options.MaxBodyBytes;
            k.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
            k.Limits.MaxRequestLineSize = 16 * 1024;
            k.Listen(bind, options.Port, l => l.Protocols = HttpProtocols.Http1);
        });
        builder.Services.Configure<HostOptions>(h => h.ShutdownTimeout = TimeSpan.FromSeconds(5));

        var state = new State(service, options, SHA256.HashData(Encoding.UTF8.GetBytes(options.Token))) { CheckHost = loopback };
        builder.Services.AddSingleton(state);
        var app = builder.Build();

        app.Use((ctx, next) => Guard(state, ctx, next));
        app.Use((ctx, next) => Errors(ctx, next));
        if (System.IO.Directory.Exists(staticRoot))
        {
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(staticRoot),
                RequestPath = "/static",
                ServeUnknownFileTypes = false,
            });
        }
        else
        {
            Log.Logger.LogWarning("Web UI folder not found: {Folder}", staticRoot);
        }
        app.MapGet("/", (HttpContext ctx) =>
        {
            var index = Path.Combine(staticRoot, "index.html");
            if (!File.Exists(index)) return Results.NotFound(new { detail = "Not Found" });
            ctx.Response.Headers.CacheControl = "no-cache";
            return Results.File(index, "text/html; charset=utf-8");
        });
        MapApi(app, state);
        app.MapFallback((HttpContext _) => Results.Json(new { detail = "Not Found" }, Json, statusCode: 404));

        var lifetime = app.Lifetime;
        lifetime.ApplicationStarted.Register(() =>
        {
            state.BoundPort = BoundAddress(app).Port;
            if (options.SyncListener)
            {
                state.Sync = new SyncListenerHost(service, options.SyncBindAddress, options.ExtraLogger);
                state.Sync.Attach();
            }
        });
        lifetime.ApplicationStopping.Register(() => state.Sync?.Dispose());
        return app;
    }

    /// <summary>The address the started app listens on (http://127.0.0.1:port).</summary>
    public static Uri BoundAddress(WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses;
        var first = addresses?.FirstOrDefault() ?? throw new InvalidOperationException("The web app is not started.");
        return new Uri(first);
    }

    /// <summary>The sync listener's address while it runs (null when it does not).</summary>
    public static Uri? SyncAddress(WebApplication app) => app.Services.GetRequiredService<State>().Sync?.Address;

    internal static IPAddress BindAddress(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return IPAddress.Loopback;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return ip;
        var resolved = Dns.GetHostAddresses(host);
        return resolved.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? resolved.FirstOrDefault()
               ?? throw new ArgumentException($"Cannot resolve {host}");
    }

    // ------------------------------------------------------------------ security guard
    private static bool IsPublic(PathString path) =>
        path == "/" || path.StartsWithSegments("/static", StringComparison.OrdinalIgnoreCase);

    private static bool SafeMethod(string m) => HttpMethods.IsGet(m) || HttpMethods.IsHead(m) || HttpMethods.IsOptions(m);

    internal static bool TokenMatches(State state, string? sent)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sent ?? ""));
        return CryptographicOperations.FixedTimeEquals(hash, state.TokenHash) && !string.IsNullOrEmpty(sent);
    }

    private static bool HostAllowed(State state, HttpRequest req)
    {
        var values = req.Headers.Host;
        if (values.Count != 1) return false;
        var host = req.Host;
        if (!host.HasValue) return false;
        if (!AllowedHostHeaders.Contains(host.Host, StringComparer.OrdinalIgnoreCase)) return false;
        return host.Port is null || state.BoundPort == 0 || host.Port == state.BoundPort;
    }

    /// <summary>A request a browser sent on behalf of another site (Origin / Sec-Fetch-Site of another origin).</summary>
    private static bool CrossOrigin(HttpRequest req)
    {
        var site = req.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0 && site is not ("same-origin" or "none")) return true;
        var origin = req.Headers.Origin.ToString();
        if (origin.Length == 0) return false;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var o) || o.Scheme is not ("http" or "https")) return true;   // also "null"
        var expected = req.Host;
        var originHost = o.IsDefaultPort ? o.Host : $"{o.Host}:{o.Port}";
        var originHost2 = o.HostNameType == UriHostNameType.IPv6 ? (o.IsDefaultPort ? $"[{o.DnsSafeHost}]" : $"[{o.DnsSafeHost}]:{o.Port}") : originHost;
        return !string.Equals(originHost, expected.Value, StringComparison.OrdinalIgnoreCase)
               && !string.Equals(originHost2, expected.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static Task Refuse(HttpContext ctx, int status, string detail)
    {
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsJsonAsync(new Dictionary<string, string> { ["detail"] = detail }, Json);
    }

    private static Task Guard(State state, HttpContext ctx, RequestDelegate next)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        var api = !IsPublic(req.Path);
        res.OnStarting(() =>
        {
            foreach (var (k, v) in SecurityHeaders)
                if (!res.Headers.ContainsKey(k)) res.Headers[k] = v;
            if (api && !res.Headers.ContainsKey("Cache-Control")) res.Headers.CacheControl = "no-store";
            return Task.CompletedTask;
        });
        if (state.CheckHost && !HostAllowed(state, req)) return Refuse(ctx, 400, "Invalid host header");
        if (api)
        {
            if (CrossOrigin(req)) return Refuse(ctx, 403, "Cross-origin request refused");
            // Browsers cannot attach custom headers to cross-site requests without a CORS preflight (which this app
            // never approves), so this blocks drive-by POSTs from other web pages to the local admin API.
            if (!SafeMethod(req.Method) && req.Headers[CsrfHeader].ToString() != "1")
                return Refuse(ctx, 403, "Missing x-admiral header");
            var sent = req.Headers[TokenHeader];
            if (sent.Count != 1 || !TokenMatches(state, sent.ToString())) return Refuse(ctx, 401, "Invalid session token");
        }
        return next(ctx);
    }

    // ------------------------------------------------------------------ error contract
    private static string ArgMessage(ArgumentException exc)
    {
        var msg = exc.Message;
        if (exc.ParamName is { } p)
        {
            var suffix = $" (Parameter '{p}')";
            if (msg.EndsWith(suffix, StringComparison.Ordinal)) msg = msg[..^suffix.Length];
        }
        return msg;
    }

    /// <summary>Status and JSON body of an exception (the exception handlers of web.py).</summary>
    internal static (int Status, object Body) Describe(Exception exc, HttpContext ctx)
    {
        var where = $"{ctx.Request.Method} {ctx.Request.Path}";
        object D(string s) => new Dictionary<string, object?> { ["detail"] = s };
        switch (exc)
        {
            case RequestValidationException v:
                return (422, new Dictionary<string, object?> { ["detail"] = v.Detail });
            case ApiErrorException h:
                return (h.Status, D(h.Message));
            case Microsoft.AspNetCore.Http.BadHttpRequestException b:
                return (b.StatusCode, D(b.StatusCode == 413 ? "Request body too large" : "Bad request"));
            case NotFound:
                return (404, D(exc.Message));
            case KeyNotFoundException:
                Log.Logger.LogWarning(exc, "API {Where}: KeyError {Error}", where, exc.Message);
                return (400, D(exc.Message.Trim('\'', '"')));
            case JobBusy or RetryServiceError:
                return (409, D(exc.Message));
            case ArgumentException a:
                Log.Logger.LogWarning("API {Where}: {Error}", where, ArgMessage(a));
                return (400, D(ArgMessage(a)));
            case RuleError or PackageError or PacError or PrinterError or SyncError or SnmpError:
                Log.Logger.LogWarning("API {Where}: {Error}", where, exc.Message);
                return (400, D(exc.Message));
            default:
                Log.Logger.LogError(exc, "API {Where}: unexpected {Type}", where, exc.GetType().Name);
                return (500, D($"{exc.GetType().Name}: {Diag.Redact(exc.Message)}"));
        }
    }

    private static async Task Errors(HttpContext ctx, RequestDelegate next)
    {
        try
        {
            await next(ctx).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ctx.RequestAborted.IsCancellationRequested)
        {
            // the client went away
        }
        catch (Exception exc) when (!ctx.Response.HasStarted)
        {
            var (status, body) = Describe(exc, ctx);
            ctx.Response.Clear();
            ctx.Response.StatusCode = status;
            await ctx.Response.WriteAsJsonAsync(body, Json).ConfigureAwait(false);
        }
    }

    /// <summary>The body size cap of this one request (the upload raises it; Kestrel enforces it while reading).</summary>
    internal static void SetBodyLimit(HttpContext ctx, long max)
    {
        var f = ctx.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (f is { IsReadOnly: false }) f.MaxRequestBodySize = max;
    }

    /// <summary>Hands a host's provider to the web host without letting the web host dispose it.</summary>
    private sealed class NonOwningProvider(ILoggerProvider inner) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => inner.CreateLogger(categoryName);

        public void Dispose()
        {
        }
    }

    internal static ILoggerProvider Wrap(ILoggerProvider p) => new NonOwningProvider(p);
}
