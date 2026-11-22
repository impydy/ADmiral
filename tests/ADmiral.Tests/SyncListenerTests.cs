using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ADmiral.Core;
using ADmiral.Web;

namespace ADmiral.Tests;

/// <summary>The sync listener the web host runs on its own port (sync.py create_sync_app; test_security's chunked cap).</summary>
public sealed class SyncListenerTests
{
    private const string Key = "a-shared-secret-that-is-long-enough-0123456";

    private static HttpResponseMessage Post(HttpClient c, string path, HttpContent? body) =>
        c.Send(new HttpRequestMessage(HttpMethod.Post, path) { Content = body });

    private static void Start(Microsoft.AspNetCore.Builder.WebApplication app) => app.StartAsync().GetAwaiter().GetResult();

    private static void Stop(Microsoft.AspNetCore.Builder.WebApplication app)
    {
        app.StopAsync().GetAwaiter().GetResult();
        app.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static void Configure(AdmiralService app, int port, string peer = "")
    {
        var s = app.Settings.Sync;
        s.Enabled = true;
        s.Key = Key;
        s.Network = "127.0.0.0/8";
        s.Port = port;
        s.Peer = peer;
    }

    private static Uri? WaitFor(Func<Uri?> address, bool running)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(15))
        {
            var a = address();
            if ((a is not null) == running) return a;
            Thread.Sleep(50);
        }
        throw new TimeoutException("the sync listener did not " + (running ? "start" : "stop"));
    }

    [Fact]
    public void Listener_follows_the_settings_and_answers_a_peer()
    {
        using var w = new WebFixture();
        var port = FreePort();
        Configure(w.App, port);
        Assert.True(w.App.ReconfigureSync());
        var address = WaitFor(() => WebApp.SyncAddress(w.Web), running: true)!;
        Assert.Equal(port, address.Port);
        Assert.True(w.App.Sync.Listening);
        Assert.True((bool)w.GetJson("/api/sync")["listening"]!);

        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
        Assert.Equal(403, Post(http, "/sync/v1/bogus", new ByteArrayContent([1])).Code());
        Assert.Equal(401, Post(http, "/sync/v1/hello", new ByteArrayContent([1, 2, 3, 4])).Code());   // not sealed with the key
        Assert.True(http.Send(new HttpRequestMessage(HttpMethod.Get, "/sync/v1/hello")).Code() is 404 or 405);
        Assert.Equal(404, Post(http, "/api/status", null).Code());                          // the API is not on this port

        // a second instance talks to it over real HTTP
        using var peer = new ServiceFixture();
        Configure(peer.App, FreePort(), peer: $"127.0.0.1:{port}");
        var hello = peer.App.Sync.Test();
        Assert.Single(hello["peers"]!.AsArray());
        Assert.True((bool)hello["peers"]![0]!["ok"]!);

        // switched off: the port is closed again
        w.App.Settings.Sync.Enabled = false;
        Assert.False(w.App.ReconfigureSync());
        WaitFor(() => WebApp.SyncAddress(w.Web), running: false);
        Assert.False(w.App.Sync.Listening);
        Assert.ThrowsAny<HttpRequestException>(() => Post(http, "/sync/v1/hello", new ByteArrayContent([1])));
    }

    [Fact]
    public void Listener_caps_bodies_and_refuses_chunked_ones()
    {
        using var fx = new ServiceFixture();
        Configure(fx.App, 0);
        fx.App.Sync.Server.MaxBody = 1000;
        var app = SyncListenerHost.Build(fx.App.Sync, IPAddress.Loopback, 0);
        Start(app);
        try
        {
            using var http = new HttpClient { BaseAddress = WebApp.BoundAddress(app) };
            var chunked = new StreamContent(new MemoryStream(new byte[1200]));
            var req = new HttpRequestMessage(HttpMethod.Post, "/sync/v1/hello") { Content = chunked };
            req.Headers.TransferEncodingChunked = true;
            Assert.Equal(411, http.Send(req).Code());                                       // a length is required
            Assert.Equal(413, Post(http, "/sync/v1/hello", new ByteArrayContent(new byte[2000])).Code());
            Assert.Equal(401, Post(http, "/sync/v1/hello", new ByteArrayContent(new byte[100])).Code());
            Assert.Equal(403, Post(http, "/sync/v1/pul", new ByteArrayContent(new byte[100])).Code());   // unknown operation
            fx.App.Settings.Sync.Key = "";
            Assert.Equal(503, Post(http, "/sync/v1/hello", new ByteArrayContent(new byte[100])).Code());
        }
        finally
        {
            Stop(app);
        }
    }

    [Fact]
    public async Task Connections_from_outside_the_network_or_too_many_from_one_address_are_closed_before_http()
    {
        using var fx = new ServiceFixture();
        Configure(fx.App, 0);
        fx.App.Settings.Sync.Network = "10.1.2.0/24";
        var hold = new TaskCompletionSource();
        var served = 0;
        var gate = SyncListenerHost.ConnectionGate(fx.App.Sync, perIp: 2)(async _ =>
        {
            Interlocked.Increment(ref served);
            await hold.Task;
        });
        static Microsoft.AspNetCore.Connections.DefaultConnectionContext From(string ip) =>
            new(Guid.NewGuid().ToString()) { RemoteEndPoint = new IPEndPoint(IPAddress.Parse(ip), 40000) };

        await gate(From("192.168.5.5"));                                 // outside: dropped, never reaches HTTP
        Assert.Equal(0, served);
        var first = gate(From("10.1.2.7"));
        var second = gate(From("::ffff:10.1.2.7"));                      // the same address, IPv4-mapped
        await gate(From("10.1.2.7"));                                    // a third one: closed at once
        Assert.Equal(2, served);
        await gate(From("10.1.2.8")).WaitAsync(TimeSpan.Zero).ContinueWith(_ => { });   // another peer still gets in
        Assert.Equal(3, served);
        hold.SetResult();
        await Task.WhenAll(first, second);
        var again = gate(From("10.1.2.7"));                              // slots are given back
        await again;
        Assert.Equal(4, served);
        Assert.True(SyncListenerHost.MaxConnectionsPerIp * 4 <= SyncListenerHost.MaxConnections);
    }
}

/// <summary>Unauthenticated memory exhaustion of the sync port (runs alone: it measures the process' allocations).</summary>
[CollectionDefinition("SyncMemory", DisableParallelization = true)]
public sealed class SyncMemoryCollection;

[Collection("SyncMemory")]
public sealed class SyncListenerMemoryTests
{
    [Fact]
    public async Task Many_concurrent_oversize_or_garbage_requests_keep_memory_bounded()
    {
        using var fx = new ServiceFixture();
        var s = fx.App.Settings.Sync;
        s.Enabled = true;
        s.Key = "a-shared-secret-that-is-long-enough-0123456";
        s.Network = "127.0.0.0/8";
        var server = fx.App.Sync.Server;
        Assert.Equal(SyncManager.MaxBody, server.MaxBody);
        Assert.True(SyncManager.MaxBody <= 8 * 1024 * 1024);
        // every client here is 127.0.0.1: the per-address connection cap is lifted to exercise the request slots
        var app = SyncListenerHost.Build(fx.App.Sync, IPAddress.Loopback, 0, perIpConnections: 64);
        await app.StartAsync();
        try
        {
            var baseAddress = WebApp.BoundAddress(app);
            var garbage = new byte[SyncManager.MaxBody];
            Random.Shared.NextBytes(garbage);
            garbage[0] = SyncCrypto.WireVersion;

            // two clients that send their headers and then trickle: they hold both request slots
            var held = new[] { new HeldContent(garbage), new HeldContent(garbage) };
            var slow = held.Select(h => Task.Run(() => SyncListenerTestsAccess.Post(baseAddress, h))).ToArray();
            var sw = Stopwatch.StartNew();
            while (server.InFlight < SyncServer.MaxConcurrent && sw.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(10);
            Assert.Equal(SyncServer.MaxConcurrent, server.InFlight);

            GC.Collect();
            var before = GC.GetTotalAllocatedBytes(precise: true);
            // a burst: full-size garbage (busy -> 503 before the body is read), too large (413), chunked (411)
            var burst = new List<Task<int>>();
            for (var i = 0; i < 8; i++) burst.Add(SyncListenerTestsAccess.Post(baseAddress, new ByteArrayContent(garbage)));
            for (var i = 0; i < 2; i++)
            {
                burst.Add(SyncListenerTestsAccess.Post(baseAddress, new ByteArrayContent(new byte[SyncManager.MaxBody + 1])));
            }
            for (var i = 0; i < 2; i++) burst.Add(SyncListenerTestsAccess.Post(baseAddress, new StreamContent(new MemoryStream(garbage, 0, 4096)), chunked: true));
            var codes = await Task.WhenAll(burst);
            Assert.All(codes[..8], c => Assert.True(c is 503 or -1, $"busy: {c}"));
            Assert.Contains(503, codes[..8]);
            Assert.All(codes[8..10], c => Assert.True(c is 413 or -1, $"too large: {c}"));
            Assert.All(codes[10..], c => Assert.Equal(411, c));

            // the held ones finish: read into the pooled buffer, decrypted in place, refused (wrong key / garbage)
            foreach (var h in held) h.Release();
            Assert.All(await Task.WhenAll(slow), c => Assert.Equal(401, c));
            for (var round = 0; round < 3; round++)
            {
                var pair = await Task.WhenAll(SyncListenerTestsAccess.Post(baseAddress, new ByteArrayContent(garbage)),
                                              SyncListenerTestsAccess.Post(baseAddress, new ByteArrayContent(garbage)));
                Assert.All(pair, c => Assert.True(c is 401 or 503, $"garbage: {c}"));
            }
            var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
            // the old reader allocated ~4 x the body per request (MemoryStream growth + ToArray + decrypt copy):
            // > 250 MB here. Now: the pooled buffers and small change.
            Assert.True(allocated < 64L * 1024 * 1024, $"allocated {allocated / (1024 * 1024)} MB");
            Assert.Equal(0, server.InFlight);
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }
}

internal static class SyncListenerTestsAccess
{
    public static async Task<int> Post(Uri baseAddress, HttpContent content, bool chunked = false)
    {
        using var http = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(60) };
        var req = new HttpRequestMessage(HttpMethod.Post, "/sync/v1/push") { Content = content };
        if (chunked) req.Headers.TransferEncodingChunked = true;
        try
        {
            using var r = await http.SendAsync(req);
            return (int)r.StatusCode;
        }
        catch (HttpRequestException)
        {
            return -1;                                     // the listener answered early and closed: refused too
        }
    }
}

/// <summary>A body of a declared length that sends 1 KB, then waits for <see cref="Release"/>.</summary>
internal sealed class HeldContent(byte[] data) : HttpContent
{
    private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Release() => _gate.TrySetResult();

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        await stream.WriteAsync(data.AsMemory(0, 1024));
        await stream.FlushAsync();
        await _gate.Task;
        await stream.WriteAsync(data.AsMemory(1024));
    }

    protected override bool TryComputeLength(out long length)
    {
        length = data.Length;
        return true;
    }
}
