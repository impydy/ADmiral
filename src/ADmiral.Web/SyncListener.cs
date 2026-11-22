#pragma warning disable CA1873 // log arguments are cheap here
using System.Net;
using ADmiral.Core;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ADmiral.Web;

/// <summary>The sync listener (sync.py create_sync_app + SyncManager._start_server): its own Kestrel on
/// [sync] port, only <c>POST /sync/v1/{op}</c>, started / stopped whenever the service's sync settings say so
/// (<see cref="AdmiralService.SyncReconfigured"/>). Every message is AES-GCM sealed; the checks are SyncServer's.</summary>
public sealed class SyncListenerHost : IDisposable
{
    private readonly AdmiralService _service;
    private readonly IPAddress _bind;
    private readonly ILoggerProvider? _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private WebApplication? _app;
    private bool _disposed;

    public SyncListenerHost(AdmiralService service, IPAddress? bind = null, ILoggerProvider? logger = null)
    {
        _service = service;
        _bind = bind ?? IPAddress.Any;
        _logger = logger;
    }

    /// <summary>Address while listening.</summary>
    public Uri? Address { get; private set; }

    /// <summary>Follow the service: start now if it wants the listener, and on every reconfiguration.</summary>
    public void Attach()
    {
        _service.SyncReconfigured += OnReconfigured;
        if (_service.SyncListenerWanted) OnReconfigured(true);
    }

    private void OnReconfigured(bool wanted)
    {
        // never block the settings request that triggered it; apply the changes one after another
        _ = Task.Run(async () =>
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed) return;
                await StopAsync().ConfigureAwait(false);       // as Python: stop, then start with the new settings
                if (wanted) await StartAsync().ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }
        });
    }

    /// <summary>Wait until pending start / stop work is done (tests, shutdown).</summary>
    public async Task SettleAsync()
    {
        await Task.Delay(50).ConfigureAwait(false);
        await _gate.WaitAsync().ConfigureAwait(false);
        _gate.Release();
    }

    private async Task StartAsync()
    {
        var port = _service.Settings.Sync.Port;
        var app = Build(_service.Sync, _bind, port, _logger);
        try
        {
            await app.StartAsync().ConfigureAwait(false);
        }
        catch (Exception exc) when (exc is IOException or System.Net.Sockets.SocketException or InvalidOperationException)
        {
            Log.Logger.LogWarning("Sync listener could not start on port {Port} (already in use?)", port);
            await app.DisposeAsync().ConfigureAwait(false);
            _service.Sync.Listening = false;
            return;
        }
        _app = app;
        Address = WebApp.BoundAddress(app);
        _service.Sync.Listening = true;
        Log.Logger.LogInformation("Sync listener on {Address}", Address);
    }

    private async Task StopAsync()
    {
        var app = _app;
        _app = null;
        try
        {
            if (app is not null) await app.StopAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        finally
        {
            if (app is not null) await app.DisposeAsync().ConfigureAwait(false);
            Address = null;                                    // only once the port is really closed
            _service.Sync.Listening = false;
        }
    }

    /// <summary>The listener's app: POST /sync/v1/{op}; everything else 404. Precheck (operation, allowed network, a
    /// Content-Length within the cap, key) runs before the body is read; then one of <see cref="SyncServer.MaxConcurrent"/>
    /// slots is taken (busy: 503, body not read) and the body is read into one pooled buffer of exactly the declared size
    /// and decrypted in place. Kestrel limits connections, header time and slow bodies, so neither memory nor
    /// connections can be exhausted by clients that do not know the key.</summary>
    /// <summary>Most open connections to the sync port.</summary>
    public const int MaxConnections = 16;

    /// <summary>Most open connections from one address: one client cannot hold every slot (a peer needs one).</summary>
    public const int MaxConnectionsPerIp = 2;

    /// <summary>Runs before HTTP is parsed: a client outside the allowed network is disconnected at once (it never
    /// holds a slot, not even while it sends headers slowly), and one address may hold at most
    /// <see cref="MaxConnectionsPerIp"/> connections.</summary>
    internal static Func<ConnectionDelegate, ConnectionDelegate> ConnectionGate(SyncManager mgr, int perIp = MaxConnectionsPerIp)
    {
        var open = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        var refused = new LogThrottle(TimeSpan.FromMinutes(1));
        return next => async conn =>
        {
            var ip = (conn.RemoteEndPoint as IPEndPoint)?.Address;
            var key = ip is null ? "?" : SyncNet.Normalize(ip).ToString();
            if (!mgr.IpAllowed(ip))
            {
                if (refused.Allow(key, out var held))
                    Log.Logger.LogWarning("Sync: closed a connection from {Ip} (outside the allowed network {Net}); {Held} more held back",
                                          ip, mgr.NetworkText(), held);
                conn.Abort();
                return;
            }
            if (open.AddOrUpdate(key, 1, (_, n) => n + 1) > perIp)
            {
                Release(open, key);
                if (refused.Allow(key, out var held))
                    Log.Logger.LogWarning("Sync: {Ip} already has {Max} connections open; closed another; {Held} more held back", ip, perIp, held);
                conn.Abort();
                return;
            }
            try
            {
                await next(conn).ConfigureAwait(false);
            }
            finally
            {
                Release(open, key);
            }
        };
    }

    private static void Release(ConcurrentDictionary<string, int> open, string key)
    {
        while (true)
        {
            if (!open.TryGetValue(key, out var n)) return;
            if (n <= 1 ? open.TryRemove(KeyValuePair.Create(key, n)) : open.TryUpdate(key, n - 1, n)) return;
        }
    }

    public static WebApplication Build(SyncManager mgr, IPAddress bind, int port, ILoggerProvider? logger = null,
                                       int perIpConnections = MaxConnectionsPerIp)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(SyncListenerHost).Assembly.GetName().Name,
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production,
            Args = [],
        });
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        if (logger is not null) builder.Logging.AddProvider(WebApp.Wrap(logger));
        builder.WebHost.UseKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = mgr.Server.MaxBody;
            k.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            k.Limits.MaxRequestHeaderCount = 32;
            k.Limits.MaxRequestLineSize = 1024;
            k.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            k.Limits.MaxConcurrentConnections = MaxConnections;
            k.Limits.MaxConcurrentUpgradedConnections = 0;
            // a peer on the LAN sends a few MB in well under a second; a trickling client is cut off
            k.Limits.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: 64 * 1024, gracePeriod: TimeSpan.FromSeconds(5));
            k.Limits.MinResponseDataRate = new MinDataRate(bytesPerSecond: 64 * 1024, gracePeriod: TimeSpan.FromSeconds(5));
            k.Listen(bind, port, l =>
            {
                l.Protocols = HttpProtocols.Http1;
                l.Use(ConnectionGate(mgr, perIpConnections));
            });
        });
        var app = builder.Build();
        app.Use((ctx, next) =>
        {
            ctx.Response.OnStarting(() =>
            {
                ctx.Response.Headers.XContentTypeOptions = "nosniff";
                ctx.Response.Headers.CacheControl = "no-store";
                return Task.CompletedTask;
            });
            return next(ctx);
        });
        app.MapPost("/sync/v1/{op}", async (HttpContext ctx) =>
        {
            var op = ctx.Request.RouteValues["op"] as string ?? "";
            var server = mgr.Server;
            var remote = ctx.Connection.RemoteIpAddress;
            var length = ctx.Request.ContentLength;
            if (server.Precheck(op, remote, length) is int early)
            {
                ctx.Response.StatusCode = early;
                ctx.Response.Headers.Connection = "close";              // the body is not read: do not reuse the connection
                return;
            }
            if (!server.TryEnter())
            {
                ctx.Response.StatusCode = 503;
                ctx.Response.Headers.RetryAfter = "1";
                ctx.Response.Headers.Connection = "close";
                return;
            }
            SyncReply reply;
            try
            {
                SyncServer.Body? body;
                try
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    deadline.CancelAfter(TimeSpan.FromSeconds(60));
                    body = await server.ReadBodyAsync(ctx.Request.Body, length!.Value, deadline.Token).ConfigureAwait(false);
                }
                catch (Microsoft.AspNetCore.Http.BadHttpRequestException b)
                {
                    ctx.Response.StatusCode = b.StatusCode;
                    return;
                }
                catch (Exception exc) when (exc is OperationCanceledException or IOException)
                {
                    ctx.Abort();
                    return;
                }
                if (body is null)
                {
                    ctx.Response.StatusCode = 400;
                    return;
                }
                using (body)
                    reply = await Task.Run(() => server.HandleInPlace(op, body.Buffer, body.Length, remote), ctx.RequestAborted).ConfigureAwait(false);
            }
            finally
            {
                server.Exit();
            }
            ctx.Response.StatusCode = reply.Status;
            if (reply.Body.Length > 0)
            {
                ctx.Response.ContentType = "application/octet-stream";
                ctx.Response.ContentLength = reply.Body.Length;
                await ctx.Response.Body.WriteAsync(reply.Body, ctx.RequestAborted).ConfigureAwait(false);
            }
        });
        app.MapFallback((HttpContext ctx) =>
        {
            ctx.Response.StatusCode = 404;
            return Task.CompletedTask;
        });
        return app;
    }

    public void Dispose()
    {
        _service.SyncReconfigured -= OnReconfigured;
        _gate.Wait(TimeSpan.FromSeconds(10));
        try
        {
            _disposed = true;
            StopAsync().GetAwaiter().GetResult();
        }
        finally
        {
            _gate.Release();
        }
    }
}
