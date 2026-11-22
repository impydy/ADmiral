using System.IO.Compression;
using System.Net;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>sync.py: sealing, replay / timestamp protection, size caps, allowed networks, the server handler and two
/// (or more) instances synchronising through an in-memory "network" (test_misc.py, test_security.py).</summary>
public class SyncTests
{
    private const string Key = "correct horse battery staple";

    private sealed class Host(SyncSettings settings, Store store) : ISyncHost
    {
        public SyncSettings Settings { get; } = settings;
        public Store Store { get; } = store;
        public bool ServiceOwnsSync { get; set; }
        public int Changed { get; private set; }
        public void DataChanged() => Changed++;
    }

    /// <summary>Routes http://127.0.0.1:{port}/sync/v1/{op} to the manager listening on that port.</summary>
    private sealed class Net : HttpMessageHandler
    {
        public Dictionary<int, SyncManager> Peers { get; } = [];
        public IPAddress From { get; set; } = IPAddress.Loopback;
        public List<Uri> Seen { get; } = [];
        public Func<HttpResponseMessage, HttpResponseMessage>? Tamper { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Seen.Add(request.RequestUri!);
            if (!Peers.TryGetValue(request.RequestUri!.Port, out var mgr)) throw new HttpRequestException("connection refused");
            var op = request.RequestUri.AbsolutePath["/sync/v1/".Length..];
            var body = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
            var r = mgr.Server.Handle(op, body, From);
            var resp = new HttpResponseMessage((HttpStatusCode)r.Status) { Content = new ByteArrayContent(r.Body) };
            return Task.FromResult(Tamper?.Invoke(resp) ?? resp);
        }
    }

    private static (SyncManager Mgr, Host Host) Instance(Net net, int port, string peers, string key = Key, Store? store = null)
    {
        var settings = new SyncSettings { Enabled = true, Port = port, Key = key, Peer = peers, Network = "127.0.0.0/8" };
        var host = new Host(settings, store ?? new Store(":memory:"));
        var mgr = new SyncManager(host, net);
        net.Peers[port] = mgr;
        return (mgr, host);
    }

    private static byte[] Request(string op, JsonObject body, double? ts = null, string? id = null, string key = Key, bool responseKey = false)
    {
        var keys = SyncCrypto.DeriveKeys(key);
        var msg = new JsonObject
        {
            ["v"] = 2, ["ts"] = ts ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
            ["id"] = id ?? Guid.NewGuid().ToString("N"), ["body"] = body,
        };
        return SyncCrypto.Seal(responseKey ? keys.Response : keys.Request, SyncCrypto.Aad("req", op), msg);
    }

    private static SyncManager Listener(string network = "127.0.0.0/8", string key = Key, int replayCapacity = 100_000)
    {
        var host = new Host(new SyncSettings { Enabled = true, Key = key, Network = network }, new Store(":memory:"));
        return new SyncManager(host, new Net(), replayCapacity: replayCapacity);
    }

    // ------------------------------------------------------------------ crypto
    [Fact]
    public void SealRoundtripAndTamperedCiphertext()
    {
        var k = SyncCrypto.DeriveKeys(Key);
        Assert.Same(k, SyncCrypto.DeriveKeys(Key));                                   // cached
        Assert.NotEqual(k.Request, k.Response);                                       // separate keys per direction
        Assert.Equal(32, k.Request.Length);
        var aad = SyncCrypto.Aad("req", "pull");
        var blob = SyncCrypto.Seal(k.Request, aad, new JsonObject { ["x"] = "hello" });
        Assert.Equal("hello", (string)SyncCrypto.Unseal(k.Request, aad, blob)["x"]!);
        for (var i = 0; i < blob.Length; i += Math.Max(1, blob.Length / 7))
        {
            var bad = (byte[])blob.Clone();
            bad[i] ^= 0x40;
            Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, aad, bad));
        }
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, aad, blob.AsSpan(0, blob.Length - 1)));
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, aad, blob.AsSpan(0, 10)));
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, SyncCrypto.Aad("req", "push"), blob));    // another operation
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, SyncCrypto.Aad("resp", "pull"), blob));   // another direction
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Response, aad, blob));                            // a reflected message
    }

    [Fact]
    public void WrongKeyIsRefused()
    {
        var other = SyncCrypto.DeriveKeys("another key, also long enough");
        var k = SyncCrypto.DeriveKeys(Key);
        var blob = SyncCrypto.Seal(k.Request, SyncCrypto.Aad("req", "hello"), []);
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(other.Request, SyncCrypto.Aad("req", "hello"), blob));
        using var srv = Listener();
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], key: "another key, also long enough"), IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], responseKey: true), IPAddress.Loopback).Status);
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", []), IPAddress.Loopback).Status);
    }

    [Fact]
    public void DecompressionBombIsCapped()
    {
        var k = SyncCrypto.DeriveKeys(Key);
        var aad = SyncCrypto.Aad("req", "push");
        var bomb = SyncCrypto.Seal(k.Request, aad, new JsonObject { ["x"] = new string('0', 8 * 1024 * 1024) });
        Assert.True(bomb.Length < 100_000);
        var ex = Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, aad, bomb, maxPlain: 1024 * 1024));
        Assert.Contains("too large", ex.Message);
        using var srv = Listener();
        srv.Server.MaxBody = 1024 * 1024;
        var msg = new JsonObject { ["v"] = 2, ["ts"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["id"] = Guid.NewGuid().ToString("N"),
                                   ["body"] = new JsonObject { ["x"] = new string('0', 8 * 1024 * 1024) } };
        Assert.Equal(401, srv.Server.Handle("push", SyncCrypto.Seal(k.Request, aad, msg), IPAddress.Loopback).Status);
        // an encrypted stream that is not zlib data
        var raw = new byte[1 + 12 + 50 + 16];
        Assert.Throws<SyncError>(() => SyncCrypto.Unseal(k.Request, aad, raw));
    }

    [Fact]
    public async Task OversizeBodiesAreRefusedAlsoWhenChunked()
    {
        using var srv = Listener();
        srv.Server.MaxBody = 1000;
        Assert.Equal(413, srv.Server.Handle("hello", new byte[1200], IPAddress.Loopback).Status);
        Assert.Equal(413, srv.Server.Precheck("hello", IPAddress.Loopback, 5000));
        Assert.Equal(411, srv.Server.Precheck("hello", IPAddress.Loopback, null));        // no length header: refused
        Assert.Null(await srv.Server.ReadBodyAsync(new ChunkedStream(600, 1200), 1200));    // above the cap
        Assert.Null(await srv.Server.ReadBodyAsync(new ChunkedStream(300, 800), 900));      // shorter than declared
        Assert.Null(await srv.Server.ReadBodyAsync(new ChunkedStream(300, 800), 700));      // longer than declared
        using (var body = await srv.Server.ReadBodyAsync(new ChunkedStream(300, 800), 800))
            Assert.Equal(800, body!.Length);
        Assert.Null(srv.Server.Precheck("hello", IPAddress.Loopback, 800));
    }

    // ------------------------------------------------------------------ replay / timestamps
    [Fact]
    public void ReplayedMessageIsRefused()
    {
        using var srv = Listener();
        var blob = Request("hello", []);
        Assert.Equal(200, srv.Server.Handle("hello", blob, IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", blob, IPAddress.Loopback).Status);
        var id = Guid.NewGuid().ToString("N");                                       // a new seal of the same id
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", [], id: id), IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], id: id), IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], id: "short"), IPAddress.Loopback).Status);
    }

    [Fact]
    public void ExpiredOrFutureTimestampIsRefused()
    {
        using var srv = Listener();
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], ts: now - SyncManager.Window - 5), IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", [], ts: now + SyncManager.Window + 5), IPAddress.Loopback).Status);
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", [], ts: now - 60), IPAddress.Loopback).Status);
        var k = SyncCrypto.DeriveKeys(Key);
        var noTs = SyncCrypto.Seal(k.Request, SyncCrypto.Aad("req", "hello"), new JsonObject { ["v"] = 2, ["id"] = Guid.NewGuid().ToString("N") });
        Assert.Equal(401, srv.Server.Handle("hello", noTs, IPAddress.Loopback).Status);
    }

    [Fact]
    public void ReplayCacheIsBoundedAndForgetsOldIds()
    {
        var c = new ReplayCache(capacity: 2, horizonSeconds: 600);
        c.Add("a", 1000);
        Assert.Throws<SyncError>(() => c.Add("a", 1001));
        c.Add("b", 1002);
        Assert.Throws<SyncError>(() => c.Add("c", 1003));                            // full: fail closed
        c.Add("c", 1601);                                                             // "a" is too old now, "b" is not
        Assert.Equal(2, c.Count);
        c.Add("a", 1700);                                                             // a forgotten id passes the cache (the timestamp check stops it)
        using var srv = Listener(replayCapacity: 1);
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", []), IPAddress.Loopback).Status);
        Assert.Equal(401, srv.Server.Handle("hello", Request("hello", []), IPAddress.Loopback).Status);
    }

    // ------------------------------------------------------------------ networks
    [Fact]
    public void ForbiddenNetworkUnknownOperationAndNoKey()
    {
        using var srv = Listener(network: "192.168.50.0/24");
        Assert.Equal(403, srv.Server.Handle("hello", Request("hello", []), IPAddress.Parse("10.1.2.3")).Status);
        Assert.Equal(403, srv.Server.Handle("hello", Request("hello", []), null).Status);
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", []), IPAddress.Parse("192.168.50.7")).Status);
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", []), IPAddress.Parse("::ffff:192.168.50.8")).Status);  // dual-stack socket
        Assert.Equal(200, srv.Server.Handle("hello", Request("hello", []), IPAddress.IPv6Loopback).Status);
        Assert.Equal(403, srv.Server.Handle("settings", Request("settings", []), IPAddress.Parse("192.168.50.7")).Status);
        using var noKey = Listener(key: "");
        Assert.Equal(503, noKey.Server.Handle("hello", [1, 2, 3], IPAddress.Loopback).Status);
        Assert.True(SyncNet.Allowed(IPAddress.Parse("192.168.1.200"), SyncNet.AllowedNetwork("192.168.1.77/24")));
        Assert.False(SyncNet.Allowed(IPAddress.Parse("192.168.2.1"), SyncNet.AllowedNetwork("192.168.1.0/24")));
        Assert.Throws<SyncError>(() => SyncNet.AllowedNetwork("nonsense"));
        Assert.True(SyncNet.AllowedNetwork("").Contains(SyncNet.LocalIp()));
    }

    [Fact]
    public void ClientRefusesAPeerOutsideTheNetwork()
    {
        var net = new Net();
        var host = new Host(new SyncSettings { Enabled = true, Key = Key, Peer = "pc.corp:8766", Network = "127.0.0.0/8" }, new Store(":memory:"));
        using var mgr = new SyncManager(host, net, resolve: (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.9.9.9") }));
        var ex = Assert.Throws<SyncError>(() => mgr.Call("hello", []));
        Assert.Contains("10.9.9.9", I18n.T("sync.err_network", ("peer", "10.9.9.9"), ("net", "x")));
        Assert.Contains("pc.corp", ex.Message);
        Assert.Empty(net.Seen);
        // a name with an allowed address among others: the request goes to exactly that address
        using var mgr2 = new SyncManager(host, net, resolve: (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.9.9.9"), IPAddress.Parse("127.0.0.7") }));
        Assert.Throws<SyncError>(() => mgr2.Call("hello", []));                      // nobody listens there
        Assert.Equal("127.0.0.7", net.Seen.Single().Host);
        var noKeyHost = new Host(new SyncSettings { Peer = "127.0.0.1" }, new Store(":memory:"));
        using var mgr3 = new SyncManager(noKeyHost, net);
        Assert.Throws<SyncError>(() => mgr3.Call("hello", []));
    }

    [Fact]
    public void PeersAreParsed()
    {
        Assert.Equal(["a", "b:1", "c"], SyncNet.SplitPeers("a, b:1;c\n a"));
        Assert.Equal(("host", 9000), SyncNet.ParsePeer("host:9000", 8766));
        Assert.Equal(("host", 8766), SyncNet.ParsePeer(" host ", 8766));
        Assert.Equal(("fe80::1", 8766), SyncNet.ParsePeer("fe80::1", 8766));
        Assert.Equal(("fe80::1", 9), SyncNet.ParsePeer("[fe80::1]:9", 8766));
        Assert.Throws<SyncError>(() => SyncNet.ParsePeer("", 8766));
        Assert.Throws<SyncError>(() => SyncNet.ParsePeer("host:99999", 8766));
    }

    // ------------------------------------------------------------------ instances
    [Fact]
    public void TwoInstancesSync()
    {
        var net = new Net();
        using var storeA = SyncDataTests.StoreWith("PC-1", "PC-2", "PC-3");
        storeA.SaveAdUsers(new Dictionary<string, JsonObject> { ["bob"] = new() { ["displayName"] = "Bob" } });
        var (a, hostA) = Instance(net, 9001, "127.0.0.1:9002", store: storeA);
        var (b, hostB) = Instance(net, 9002, "127.0.0.1:9001");
        using (a)
        using (b)
        {
            Assert.True(a.Reconfigure());
            var info = a.Test();
            Assert.Equal(Environment.MachineName, (string)info["host"]!);
            var r = a.Run();
            Assert.Equal(4, r.Pulled + r.Pushed);                                    // 3 computers + 1 user went to B
            Assert.Equal(3, (long)hostB.Store.Scalar("SELECT COUNT(*) FROM computers")!);
            Assert.Equal(1, (long)hostB.Store.Scalar("SELECT COUNT(*) FROM users")!);
            Assert.True(hostB.Changed > 0);
            Assert.True((bool)a.Last["ok"]!);
            Assert.Contains("sync", hostA.Store.Activity().Select(x => (string)x["action"]!));
            var r2 = a.Run();                                                         // nothing left to exchange
            Assert.Equal(0, r2.Pulled + r2.Pushed);
            hostB.Settings.Key = "a different key that does not match";             // wrong key: refused
            var ex = Assert.Throws<SyncError>(() => a.Run());
            Assert.Contains(I18n.T("sync.err_key"), ex.Message);
            Assert.False((bool)a.Last["ok"]!);
            a.Stop();
        }
    }

    [Fact]
    public void SyncWithSeveralPeersSurvivesADeadOne()
    {
        var net = new Net();
        using var storeA = SyncDataTests.StoreWith("PC-1");
        var (a, _) = Instance(net, 9101, "127.0.0.1:9102, 127.0.0.1:9199 127.0.0.1:9103", store: storeA);
        var (b, hb) = Instance(net, 9102, "");
        var (c, hc) = Instance(net, 9103, "");
        using (a)
        using (b)
        using (c)
        {
            var r = a.Run();
            Assert.Equal(1, (long)hb.Store.Scalar("SELECT COUNT(*) FROM computers")!);
            Assert.Equal(1, (long)hc.Store.Scalar("SELECT COUNT(*) FROM computers")!);
            Assert.Equal(2, r.Pushed);
            var errors = (JsonArray)a.Last["errors"]!;
            Assert.Single(errors);
            Assert.Contains("9199", (string)errors[0]!);                             // the dead peer is reported
            var info = a.Test();
            Assert.Equal(3, ((JsonArray)info["peers"]!).Count);
            Assert.Equal(new[] { true, false, true }, ((JsonArray)info["peers"]!).Select(p => (bool)p!["ok"]!));
        }
    }

    [Fact]
    public void AnswerMustBelongToTheRequest()
    {
        var net = new Net();
        var (a, _) = Instance(net, 9201, "127.0.0.1:9202");
        var (b, _) = Instance(net, 9202, "");
        using (a)
        using (b)
        {
            HttpResponseMessage? first = null;
            byte[]? firstBody = null;
            net.Tamper = resp =>
            {
                var body = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                if (first is null)
                {
                    first = resp;
                    firstBody = body;
                    return new HttpResponseMessage(resp.StatusCode) { Content = new ByteArrayContent(body) };
                }
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(firstBody!) };   // an old answer
            };
            a.Call("hello", []);
            var ex = Assert.Throws<SyncError>(() => a.Call("hello", []));
            Assert.Contains("different request", ex.Message);
            net.Tamper = resp => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([2, 1, 2, 3]) };
            Assert.Throws<SyncError>(() => a.Call("hello", []));
            net.Tamper = _ => new HttpResponseMessage(HttpStatusCode.Forbidden);
            Assert.Contains(I18n.T("sync.err_forbidden"), Assert.Throws<SyncError>(() => a.Call("hello", [])).Message);
        }
    }

    private static void Bulk(Store store, string guid, int bytes) =>
        store.Execute("INSERT INTO computer_items (guid, kind, pos, data) VALUES (?, 'apps', 0, ?)", guid,
                      "\"" + string.Concat(Enumerable.Range(0, bytes / 8).Select(i => i.ToString("x8", System.Globalization.CultureInfo.InvariantCulture))) + "\"");

    [Fact]
    public void LargeRecordsAreSplitBelowTheMessageCapBothWays()
    {
        Assert.True(SyncManager.MaxBody <= 8 * 1024 * 1024);
        var net = new Net();
        using var storeA = SyncDataTests.StoreWith("PC-1", "PC-2", "PC-3", "HUGE");
        using var storeB = SyncDataTests.StoreWith("PC-4", "PC-5");
        foreach (var n in new[] { "pc-1", "pc-2", "pc-3" }) Bulk(storeA, "g-" + n, 3 * 1024 * 1024);
        Bulk(storeA, "g-huge", 9 * 1024 * 1024);                                   // can never fit one message
        foreach (var n in new[] { "pc-4", "pc-5" }) Bulk(storeB, "g-" + n, 3 * 1024 * 1024);
        var (a, _) = Instance(net, 9401, "127.0.0.1:9402", store: storeB);         // a = B's side pulls from / pushes to A
        var (b, _) = Instance(net, 9402, "127.0.0.1:9401", store: storeA);
        using (a)
        using (b)
        {
            var r = a.Run();
            Assert.Equal(3, r.Pulled);                                              // PC-1..3; HUGE is skipped, not fatal
            Assert.Equal(2, r.Pushed);
            Assert.Equal(5, (long)storeB.Scalar("SELECT COUNT(*) FROM computers WHERE guid <> 'g-huge'")!);
            Assert.Equal(6, (long)storeA.Scalar("SELECT COUNT(*) FROM computers")!);
            Assert.True(net.Seen.Count(u => u.AbsolutePath.EndsWith("/pull", StringComparison.Ordinal)) >= 2);   // split
            Assert.Contains(net.Seen, u => u.AbsolutePath.EndsWith("/push", StringComparison.Ordinal));
        }
        // the packing rule itself
        var recs = Enumerable.Range(0, 30).Select(i => new JsonObject { ["x"] = new string('a', 100) }).ToList();
        var packs = SyncManager.PackRecords(recs, budget: 1000, max: 25);
        Assert.All(packs, p => Assert.True(p.Sum(SyncManager.RecordSize) <= 1000 && p.Count <= 25));
        Assert.Equal(30, packs.Sum(p => p.Count));
        Assert.Empty(SyncManager.PackRecords([new JsonObject { ["x"] = new string('a', 2000) }], budget: 1000));
    }

    [Fact]
    public void ClientRetriesABusyPeer()
    {
        var net = new Net();
        var (a, _) = Instance(net, 9501, "127.0.0.1:9502");
        var (b, _) = Instance(net, 9502, "127.0.0.1:9501");
        using (a)
        using (b)
        {
            var busy = 2;
            static HttpResponseMessage Busy()
            {
                var r = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(1));
                return r;
            }
            net.Tamper = resp => busy-- > 0 ? Busy() : resp;
            var old = SyncManager.BusyDelay;
            SyncManager.BusyDelay = TimeSpan.FromMilliseconds(1);
            try
            {
                Assert.Equal(SyncManager.Protocol, (int)a.Call("hello", [])["protocol"]!);
                busy = 10;
                var ex = Assert.Throws<SyncError>(() => a.Call("hello", []));
                Assert.Contains("503", ex.Message);
            }
            finally
            {
                SyncManager.BusyDelay = old;
            }
        }
    }

    [Fact]
    public void ServerServesOnlyEnabledCategoriesAndBoundedBatches()
    {
        var net = new Net();
        using var store = SyncDataTests.StoreWith("PC-1");
        var (a, ha) = Instance(net, 9301, "", store: store);
        using (a)
        {
            ha.Settings.Categories = ["users"];
            Assert.Empty((JsonObject)a.Handle("manifest", new JsonObject { ["cats"] = new JsonArray("computers") }));
            Assert.Empty((JsonArray)a.Handle("pull", new JsonObject { ["cat"] = "computers", ["keys"] = new JsonArray("g-pc-1") })["records"]!);
            Assert.Equal(0, (int)a.Handle("push", new JsonObject { ["cat"] = "computers", ["records"] = new JsonArray() })["applied"]!);
            ha.Settings.Categories = ["computers"];
            var keys = new JsonArray([.. Enumerable.Range(0, 100).Select(i => (JsonNode)"g-pc-1")]);
            Assert.Equal(SyncManager.Batch, ((JsonArray)a.Handle("pull", new JsonObject { ["cat"] = "computers", ["keys"] = keys })["records"]!).Count);
            var many = new JsonArray([.. Enumerable.Range(0, SyncManager.Batch * 4 + 1).Select(_ => (JsonNode)new JsonObject())]);
            Assert.Throws<SyncError>(() => a.Handle("push", new JsonObject { ["cat"] = "computers", ["records"] = many }));
            Assert.Throws<SyncError>(() => a.Handle("delete", []));
            var hello = a.Handle("hello", []);
            Assert.Equal(SyncManager.Protocol, (int)hello["protocol"]!);
            Assert.False(a.KeyWeak());
            ha.Settings.Key = "short";
            Assert.True(a.KeyWeak());
            ha.ServiceOwnsSync = true;
            Assert.False(a.Reconfigure());                                           // the service owns the listener
            Assert.True(a.Reconfigure(force: true));
            Assert.True((bool)a.Status()["by_service"]!);
            _ = ZLibStream.Null;
        }
    }

    [Fact]
    public void RefusedRequestsAreLoggedOncePerAddressAndMinute()
    {
        long now = 0;
        var t = new LogThrottle(TimeSpan.FromMinutes(1), capacity: 3, clockMs: () => now);
        Assert.True(t.Allow("10.0.0.9", out var held));
        Assert.Equal(0, held);
        for (var i = 0; i < 1000; i++) Assert.False(t.Allow("10.0.0.9", out _));   // a flood: one line, not a thousand
        Assert.True(t.Allow("10.0.0.10", out _));                                   // another client still shows up
        now += 60_000;
        Assert.True(t.Allow("10.0.0.9", out held));
        Assert.Equal(1000, held);                                                   // ...and the count is not lost
        // a flood of many addresses cannot grow the table: past the capacity they share one slot
        Assert.True(t.Allow("a", out _));
        Assert.True(t.Allow("b", out _));
        Assert.True(t.Allow("c", out _));                                           // the shared slot's first line
        Assert.False(t.Allow("d", out _));
        Assert.False(t.Allow("e", out _));
    }
}
