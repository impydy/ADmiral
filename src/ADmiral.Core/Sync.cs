// Port of admiral/sync.py: synchronisation between ADmiral instances on the same network (any number of peers).
//
// * Every message is compressed and sealed with AES-256-GCM. The keys come from the shared key the administrator
//   types into every instance: PBKDF2-HMAC-SHA256 (600 000 iterations, protocol salt) stretches it once, HKDF-SHA256
//   then derives separate request and response keys. The additional authenticated data binds the protocol version,
//   the direction and the operation, so a wrong key, a modified message, a message for another operation or a
//   reflected answer all fail authentication.
// * A timestamp window (5 minutes) and a one-time 128-bit id stop replays; the replay cache is bounded (fails closed
//   when full) and forgets ids once they are too old to pass the timestamp check anyway.
// * Decompression is capped (no zip bombs), as is the body itself.
// * The listener accepts only addresses inside the allowed network (default: this machine's own /24), and the client
//   refuses a peer outside it - "same IP range" is enforced on both ends. The client connects to the address it
//   checked (no second DNS lookup), never through a proxy, and does not follow redirects.
// * What is exchanged: computers (with inventory and tags), collections, AD users and printers - never the settings.
//   Merge: the newer record wins; nothing is deleted (see SyncData).
//
// The HTTP listener itself belongs to the web layer: it passes the raw body to SyncServer.Handle and returns the
// status / body it gets. Wire format version 2 (Python peers used version 1 and are not compatible).

using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>A synchronisation problem that is explained to the user.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python SyncError")]
public sealed class SyncError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>What the sync side needs from the ADmiral service (implemented by the service).</summary>
public interface ISyncHost
{
    /// <summary>The current [sync] settings (Key = the shared secret from the encrypted store).</summary>
    SyncSettings Settings { get; }

    /// <summary>The inventory database.</summary>
    Store Store { get; }

    /// <summary>True while the background (Windows) service runs: it then hosts the listener and the schedule.</summary>
    bool ServiceOwnsSync { get; }

    /// <summary>Records from a peer were merged into the database: drop derived caches.</summary>
    void DataChanged();
}

/// <summary>The request and response keys derived from the shared key.</summary>
public sealed class SyncKeys(byte[] request, byte[] response)
{
    public byte[] Request { get; } = request;
    public byte[] Response { get; } = response;
}

/// <summary>Status code and body for the HTTP layer.</summary>
public readonly record struct SyncReply(int Status, byte[] Body)
{
    public static SyncReply Empty(int status) => new(status, []);
}

/// <summary>Key derivation and message sealing.</summary>
public static class SyncCrypto
{
    public const byte WireVersion = 2;
    public const int Pbkdf2Iterations = 600_000;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Pbkdf2Salt = "ADmiral-sync/2 pbkdf2-sha256 shared-key"u8.ToArray();
    private static readonly byte[] HkdfSalt = "ADmiral-sync/2 hkdf"u8.ToArray();

    private static readonly Lock CacheLock = new();
    private static readonly Dictionary<string, SyncKeys> Cache = new(StringComparer.Ordinal);

    /// <summary>Stretch the typed key (slow on purpose: it is guessable by people) and derive the two message keys.
    /// The last few results are cached (keyed by a hash, not the secret itself).</summary>
    public static SyncKeys DeriveKeys(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var pw = Encoding.UTF8.GetBytes(secret.Normalize(NormalizationForm.FormC));
        var id = Convert.ToHexString(SHA256.HashData([.. "ADmiral-sync-cache"u8, .. pw]));
        lock (CacheLock)
            if (Cache.TryGetValue(id, out var hit)) return hit;
        var master = Rfc2898DeriveBytes.Pbkdf2(pw, Pbkdf2Salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        CryptographicOperations.ZeroMemory(pw);
        var keys = new SyncKeys(HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, HkdfSalt, "request key"u8.ToArray()),
                                HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, HkdfSalt, "response key"u8.ToArray()));
        CryptographicOperations.ZeroMemory(master);
        lock (CacheLock)
        {
            if (Cache.Count >= 4) Cache.Clear();
            Cache[id] = keys;
        }
        return keys;
    }

    /// <summary>Additional authenticated data: protocol version, direction ("req" / "resp") and operation.</summary>
    public static byte[] Aad(string direction, string op) => Encoding.ASCII.GetBytes($"ADmiral-sync/{WireVersion} {direction} {op}");

    /// <summary>version byte | 12-byte nonce | AES-256-GCM(zlib(JSON)) | 16-byte tag.</summary>
    public static byte[] Seal(byte[] key, byte[] aad, JsonObject payload)
    {
        byte[] plain;
        using (var ms = new MemoryStream())
        {
            using (var z = new ZLibStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            using (var w = new Utf8JsonWriter(z))
                payload.WriteTo(w);
            plain = ms.ToArray();
        }
        var outp = new byte[1 + NonceSize + plain.Length + TagSize];
        outp[0] = WireVersion;
        var nonce = outp.AsSpan(1, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plain, outp.AsSpan(1 + NonceSize, plain.Length), outp.AsSpan(outp.Length - TagSize), aad);
        return outp;
    }

    /// <summary>Authenticate, decrypt, decompress (at most <paramref name="maxPlain"/> bytes) and parse a message.
    /// Throws <see cref="SyncError"/> for anything wrong. Works on a pooled copy of <paramref name="blob"/>.</summary>
    public static JsonObject Unseal(byte[] key, byte[] aad, ReadOnlySpan<byte> blob, long maxPlain = SyncManager.MaxBody)
    {
        var buf = ArrayPool<byte>.Shared.Rent(Math.Max(1, blob.Length));
        try
        {
            blob.CopyTo(buf);
            return UnsealInPlace(key, aad, buf, blob.Length, maxPlain);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf, clearArray: true);
        }
    }

    /// <summary><see cref="Unseal"/> on the first <paramref name="length"/> bytes of <paramref name="buffer"/>, decrypting
    /// in place (the buffer is overwritten): no second full-size copy of a request is ever made, and the plaintext is
    /// parsed straight from the decompressor.</summary>
    public static JsonObject UnsealInPlace(byte[] key, byte[] aad, byte[] buffer, int length, long maxPlain = SyncManager.MaxBody)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (length < 1 + NonceSize + TagSize + 1 || length > buffer.Length) throw new SyncError("message too short");
        var blob = buffer.AsSpan(0, length);
        if (blob[0] != WireVersion) throw new SyncError("unsupported message version");
        var cipherLength = length - 1 - NonceSize - TagSize;
        var cipher = blob.Slice(1 + NonceSize, cipherLength);
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(blob.Slice(1, NonceSize), cipher, blob[^TagSize..], cipher, aad);
        }
        catch (AuthenticationTagMismatchException exc) { throw new SyncError("message authentication failed", exc); }
        catch (CryptographicException exc) { throw new SyncError("message authentication failed", exc); }
        try
        {
            using var z = new ZLibStream(new MemoryStream(buffer, 1 + NonceSize, cipherLength, writable: false), CompressionMode.Decompress);
            using var capped = new CappedReadStream(z, maxPlain);
            return JsonNode.Parse(capped, documentOptions: new JsonDocumentOptions { MaxDepth = 64 }) as JsonObject
                   ?? throw new SyncError("message is not a JSON object");
        }
        catch (InvalidDataException exc) { throw new SyncError("message is not compressed correctly", exc); }
        catch (JsonException exc) { throw new SyncError("message is not valid JSON", exc); }
    }

    /// <summary>Reads at most a fixed number of bytes from the inner stream, then throws "message too large".</summary>
    private sealed class CappedReadStream(Stream inner, long max) : Stream
    {
        private long _total;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            _total += n;
            if (_total > max) throw new SyncError("message too large");
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(buffer.Span));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer.AsSpan(offset, count)));
    }
}

/// <summary>One-time message ids seen within the replay horizon. Bounded: when full of still-valid ids, new messages
/// are refused (fail closed) instead of forgetting ids that could then be replayed.</summary>
public sealed class ReplayCache(int capacity = 100_000, double horizonSeconds = 2 * SyncManager.Window)
{
    private readonly Lock _lock = new();
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly Queue<(string Id, double At)> _order = new();

    public int Count
    {
        get { lock (_lock) return _seen.Count; }
    }

    /// <summary>Record <paramref name="id"/>; throws <see cref="SyncError"/> for a replay or when the cache is full.</summary>
    public void Add(string id, double now)
    {
        lock (_lock)
        {
            while (_order.TryPeek(out var head) && now - head.At >= horizonSeconds)
            {
                _order.Dequeue();
                _seen.Remove(head.Id);
            }
            if (_seen.Contains(id)) throw new SyncError("replayed message");
            if (_seen.Count >= capacity) throw new SyncError("too many messages; try again later");
            _seen.Add(id);
            _order.Enqueue((id, now));
        }
    }
}

/// <summary>At most one log line per key (a client address) and window: requests the listener refuses before any key
/// is known are logged, but a client sending thousands of them cannot flood the log. Lines that were held back are
/// counted and reported with the next line for that key. Bounded: past <c>capacity</c> keys every new key shares one
/// slot.</summary>
public sealed class LogThrottle(TimeSpan window, int capacity = 1024, Func<long>? clockMs = null)
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, (long At, int Held)> _keys = new(StringComparer.Ordinal);
    private readonly Func<long> _clock = clockMs ?? (() => Environment.TickCount64);
    private const string Overflow = "*";

    /// <summary>True when a line for <paramref name="key"/> may be written now; <paramref name="held"/> = lines
    /// suppressed for it since the last one written.</summary>
    public bool Allow(string key, out int held)
    {
        var now = _clock();
        lock (_lock)
        {
            if (_keys.Count >= capacity && !_keys.ContainsKey(key))
            {
                foreach (var (k, v) in _keys.Where(kv => now - kv.Value.At >= (long)window.TotalMilliseconds).ToList()) _keys.Remove(k);
                if (_keys.Count >= capacity) key = Overflow;
            }
            if (_keys.TryGetValue(key, out var e) && now - e.At < (long)window.TotalMilliseconds)
            {
                _keys[key] = (e.At, e.Held + 1);
                held = 0;
                return false;
            }
            held = e.Held;
            _keys[key] = (now, 0);
            return true;
        }
    }
}

/// <summary>Network rules and peer parsing.</summary>
public static partial class SyncNet
{
    /// <summary>The address of the interface with the default route (no packet is sent), or 127.0.0.1.</summary>
    public static IPAddress LocalIp()
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9));
            return (s.LocalEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        }
        catch (SocketException) { return IPAddress.Loopback; }
    }

    /// <summary>The allowed network: the CIDR from the settings (host bits may be set), or this machine's /24.</summary>
    public static IPNetwork AllowedNetwork(string? cidr = "")
    {
        var text = (cidr ?? "").Trim();
        if (text.Length == 0) text = LocalIp() + "/24";
        if (!IPNetwork.TryParse(Config.NormalizeCidr(text), out var net)) throw new SyncError($"not a valid network: {text}");
        return net;
    }

    /// <summary>An address as compared with the network: IPv4-mapped IPv6 becomes IPv4, the scope id is dropped.</summary>
    public static IPAddress Normalize(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) return a.MapToIPv4();
        if (a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId != 0) return new IPAddress(a.GetAddressBytes());
        return a;
    }

    public static bool Allowed(IPAddress? address, IPNetwork network)
    {
        if (address is null) return false;
        var a = Normalize(address);
        return IPAddress.IsLoopback(a) || network.Contains(a);
    }

    [GeneratedRegex(@"[,;\s]+")]
    private static partial Regex PeerSep();

    /// <summary>The peers typed into the settings: separated by commas, semicolons, spaces or new lines.</summary>
    public static List<string> SplitPeers(string? text)
    {
        var outp = new List<string>();
        foreach (var p in PeerSep().Split(text ?? ""))
            if (p.Length > 0 && !outp.Contains(p)) outp.Add(p);
        return outp;
    }

    /// <summary>"host", "host:port", "[v6]:port" or a bare IPv6 address -&gt; (host, port).</summary>
    public static (string Host, int Port) ParsePeer(string? peer, int defaultPort)
    {
        var p = (peer ?? "").Trim();
        if (p.Length == 0) throw new SyncError(I18n.T("sync.err_no_peer"));
        static int Port(string s) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 1 and <= 65535
            ? n : throw new SyncError($"not a valid port: {s}");
        if (p.StartsWith('['))
        {
            var end = p.IndexOf(']', StringComparison.Ordinal);
            if (end < 0) throw new SyncError($"not a valid address: {p}");
            var host = p[1..end];
            var rest = p[(end + 1)..];
            return (host, rest.Length == 0 ? defaultPort : rest.StartsWith(':') ? Port(rest[1..]) : throw new SyncError($"not a valid address: {p}"));
        }
        var colon = p.LastIndexOf(':');
        if (colon > 0 && p.IndexOf(':') == colon && p[(colon + 1)..].All(char.IsAsciiDigit) && colon < p.Length - 1)
            return (p[..colon], Port(p[(colon + 1)..]));
        return (p, defaultPort);
    }
}

/// <summary>The listener's request handler, independent of any web framework.</summary>
public sealed class SyncServer
{
    public static readonly IReadOnlySet<string> Operations = new HashSet<string>(StringComparer.Ordinal) { "hello", "manifest", "pull", "push" };

    private readonly SyncManager _mgr;

    internal SyncServer(SyncManager mgr) => _mgr = mgr;

    /// <summary>Refused / unauthenticated requests: one warning per client address and minute.</summary>
    internal LogThrottle Throttle { get; set; } = new(TimeSpan.FromMinutes(1));

    private static string Key(IPAddress? remote) => remote is null ? "?" : SyncNet.Normalize(remote).ToString();

    /// <summary>Largest request body (compressed and decompressed); tests may lower it.</summary>
    public long MaxBody { get; set; } = SyncManager.MaxBody;

    /// <summary>Requests read / handled at the same time; more are answered 503 before their body is read, so the
    /// memory an unauthenticated client can make the listener hold is at most MaxConcurrent x MaxBody.</summary>
    public const int MaxConcurrent = 2;

    private int _busy;

    /// <summary>Take one of the <see cref="MaxConcurrent"/> request slots (false: answer 503 now).</summary>
    public bool TryEnter()
    {
        if (Interlocked.Increment(ref _busy) <= MaxConcurrent) return true;
        Interlocked.Decrement(ref _busy);
        return false;
    }

    /// <summary>Give the slot back.</summary>
    public void Exit() => Interlocked.Decrement(ref _busy);

    /// <summary>Requests holding a slot right now.</summary>
    public int InFlight => Volatile.Read(ref _busy);

    /// <summary>The checks that need no body: 403 (unknown operation / outside the allowed network), 411 (no
    /// Content-Length: chunked bodies are not accepted), 413 (declared length too large), 503 (no key set) - or null
    /// to go on and read the body.</summary>
    public int? Precheck(string op, IPAddress? remote, long? contentLength)
    {
        var known = Operations.Contains(op);
        if (!known || !_mgr.IpAllowed(remote))
        {
            if (Throttle.Allow(Key(remote), out var held))
            {
                if (known)
                    Log.Logger.LogWarning("Sync: refused a request from {Ip} (outside the allowed network {Net}); {Held} more held back",
                                          remote, _mgr.NetworkText(), held);
                else
                    Log.Logger.LogWarning("Sync: refused a request from {Ip} (unknown operation); {Held} more held back", remote, held);
            }
            return 403;
        }
        if (contentLength is null) return 411;
        if (contentLength > MaxBody || contentLength < 0) return 413;
        if (_mgr.Keys() is null) return 503;
        return null;
    }

    /// <summary>A request body in a pooled buffer (returned, cleared, on dispose).</summary>
    public sealed class Body : IDisposable
    {
        internal Body(byte[] buffer, int length)
        {
            Buffer = buffer;
            Length = length;
        }

        public byte[] Buffer { get; private set; }
        public int Length { get; }

        public void Dispose()
        {
            var b = Buffer;
            Buffer = [];
            if (b.Length > 0) ArrayPool<byte>.Shared.Return(b, clearArray: true);
        }
    }

    /// <summary>Read exactly <paramref name="length"/> bytes (the checked Content-Length) into one pooled buffer - one
    /// allocation of the final size, no growing copies. Null when the body is shorter or longer (answer 400).</summary>
    public async Task<Body?> ReadBodyAsync(Stream body, long length, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (length < 0 || length > MaxBody) return null;
        var n = (int)length;
        var buf = ArrayPool<byte>.Shared.Rent(Math.Max(1, n));
        var ok = false;
        try
        {
            var read = n == 0 ? 0 : await body.ReadAtLeastAsync(buf.AsMemory(0, n), n, throwOnEndOfStream: false, ct).ConfigureAwait(false);
            if (read != n) return null;
            var extra = new byte[1];
            if (await body.ReadAsync(extra, ct).ConfigureAwait(false) != 0) return null;    // more than declared
            ok = true;
            return new Body(buf, n);
        }
        finally
        {
            if (!ok) ArrayPool<byte>.Shared.Return(buf, clearArray: true);
        }
    }

    /// <summary>Handle one POST /sync/v1/{op}. Wrong key, tampering, replay or an expired message: 401, telling nothing.</summary>
    public SyncReply Handle(string op, ReadOnlySpan<byte> body, IPAddress? remote)
    {
        if (Precheck(op, remote, body.Length) is int early) return SyncReply.Empty(early);
        var buf = ArrayPool<byte>.Shared.Rent(Math.Max(1, body.Length));
        try
        {
            body.CopyTo(buf);
            return HandleInPlace(op, buf, body.Length, remote);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf, clearArray: true);
        }
    }

    /// <summary><see cref="Handle"/> on a body read with <see cref="ReadBodyAsync"/>; decrypts it in place.</summary>
    public SyncReply HandleInPlace(string op, byte[] buffer, int length, IPAddress? remote)
    {
        if (Precheck(op, remote, length) is int early) return SyncReply.Empty(early);
        var keys = _mgr.Keys()!;
        JsonObject msg;
        string id;
        try
        {
            msg = SyncCrypto.UnsealInPlace(keys.Request, SyncCrypto.Aad("req", op), buffer, length, MaxBody);
            id = _mgr.CheckReplay(msg);
        }
        catch (SyncError exc)
        {
            if (Throttle.Allow(Key(remote), out var held))
                Log.Logger.LogWarning("Sync: rejected a message from {Ip}: {Reason}; {Held} more held back", remote, exc.Message, held);
            return SyncReply.Empty(401);
        }
        JsonObject answer;
        try
        {
            answer = _mgr.Handle(op, msg["body"] as JsonObject ?? []);
        }
        catch (Exception exc)
        {
            Log.Logger.LogWarning(exc, "Sync: {Op} failed", op);
            return SyncReply.Empty(500);
        }
        var reply = new JsonObject { ["v"] = SyncCrypto.WireVersion, ["ts"] = _mgr.Now(), ["re"] = id, ["body"] = answer };
        var sealedReply = SyncCrypto.Seal(keys.Response, SyncCrypto.Aad("resp", op), reply);
        if (sealedReply.Length > SyncManager.MaxBody)
        {
            Log.Logger.LogWarning("Sync: the answer to {Op} is too large ({Bytes} bytes)", op, sealedReply.Length);
            return SyncReply.Empty(500);
        }
        return new SyncReply(200, sealedReply);
    }
}

/// <summary>Result of one synchronisation run.</summary>
public sealed record SyncResult(
    [property: JsonPropertyName("peer")] string Peer,
    [property: JsonPropertyName("pulled")] int Pulled,
    [property: JsonPropertyName("pushed")] int Pushed,
    [property: JsonPropertyName("categories")] List<string> Categories);

/// <summary>Owns the server handler, the client, the automatic schedule and the last result.</summary>
public sealed partial class SyncManager : IDisposable
{
    /// <summary>Largest message on the wire and after decompression, both directions. A batch is at most
    /// <see cref="Batch"/> records whose JSON together stays under <see cref="RecordBudget"/> (the sender splits
    /// batches, see <see cref="PackRecords"/>): a computer with its full inventory is typically 50-300 KB of JSON, so
    /// 25 of them fit; anything larger goes in smaller batches. 8 MB (Python allowed 64 MB) keeps what an
    /// unauthenticated client can make the listener buffer small (<see cref="SyncServer.MaxConcurrent"/> x 8 MB).</summary>
    public const long MaxBody = 8L * 1024 * 1024;
    /// <summary>JSON bytes of the records in one message; the rest of MaxBody is room for the envelope.</summary>
    public const long RecordBudget = MaxBody - 256 * 1024;
    /// <summary>Seconds a message stays valid.</summary>
    public const int Window = 300;
    /// <summary>Records per request.</summary>
    public const int Batch = 25;
    public const int Protocol = SyncCrypto.WireVersion;
    public const int MinKeyLength = 16;
    /// <summary>Retries of a request the peer answered 503 (busy).</summary>
    public const int BusyRetries = 3;
    internal static TimeSpan BusyDelay { get; set; } = TimeSpan.FromSeconds(1);

    private readonly ISyncHost _host;
    private readonly HttpClient _http;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private readonly TimeProvider _time;
    private readonly ReplayCache _seen;
    private readonly SemaphoreSlim _runLock = new(1, 1);
    private readonly Lock _autoLock = new();
    private CancellationTokenSource? _autoStop;
    private Thread? _auto;

    public SyncData Data { get; }
    public SyncServer Server { get; }

    /// <summary>Set by the web layer while its listener runs.</summary>
    public bool Listening { get; set; }

    /// <summary>The last run's outcome (shown in the settings).</summary>
    public JsonObject Last { get; private set; } = [];

    /// <param name="host">the service</param>
    /// <param name="handler">HTTP handler for the client (tests: a fake that calls another instance's server)</param>
    /// <param name="resolve">DNS lookup (tests)</param>
    /// <param name="time">clock (tests)</param>
    /// <param name="transaction">atomic runner for merges (see <see cref="SyncData"/>)</param>
    /// <param name="replayCapacity">most remembered message ids</param>
    public SyncManager(ISyncHost host, HttpMessageHandler? handler = null, Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
                       TimeProvider? time = null, Func<Func<int>, int>? transaction = null, int replayCapacity = 100_000)
    {
        _host = host;
        _time = time ?? TimeProvider.System;
        _resolve = resolve ?? ((h, ct) => Dns.GetHostAddressesAsync(h, ct));
        _seen = new ReplayCache(replayCapacity);
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            UseProxy = false,                                 // peers are on the local network: never via a proxy
            AllowAutoRedirect = false,                        // a redirect could point anywhere
            ConnectTimeout = TimeSpan.FromSeconds(5),
            AutomaticDecompression = DecompressionMethods.None,
        }, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        Data = new SyncData(host.Store, transaction);
        Server = new SyncServer(this);
    }

    public void Dispose()
    {
        Stop();
        _http.Dispose();
        _runLock.Dispose();
    }

    // -- settings
    public SyncSettings Cfg => _host.Settings;

    internal double Now() => _time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;

    public SyncKeys? Keys() => string.IsNullOrEmpty(Cfg.Key) ? null : SyncCrypto.DeriveKeys(Cfg.Key);

    public bool KeyWeak() => !string.IsNullOrEmpty(Cfg.Key) && Cfg.Key.Length < MinKeyLength;

    public List<string> Peers() => SyncNet.SplitPeers(Cfg.Peer);

    public List<string> EnabledCategories() => [.. SyncData.Categories.Where(c => Cfg.Categories.Contains(c))];

    public string NetworkText()
    {
        try { return SyncNet.AllowedNetwork(Cfg.Network).ToString(); }
        catch (SyncError) { return Cfg.Network; }
    }

    public bool IpAllowed(IPAddress? ip)
    {
        try { return SyncNet.Allowed(ip, SyncNet.AllowedNetwork(Cfg.Network)); }
        catch (SyncError) { return false; }
    }

    // -- schedule
    /// <summary>Restart the automatic schedule to match the settings; true when the listener should run. Unless
    /// <paramref name="force"/> (the service itself), nothing runs while the background service owns the sync.</summary>
    public bool Reconfigure(bool force = false)
    {
        Stop();
        if (!(Cfg.Enabled && !string.IsNullOrEmpty(Cfg.Key))) return false;
        if (!force && _host.ServiceOwnsSync) return false;
        if (Cfg.IntervalMinutes > 0 && Peers().Count > 0)
        {
            lock (_autoLock)
            {
                var stop = new CancellationTokenSource();
                _autoStop = stop;
                _auto = new Thread(() => AutoLoop(stop.Token)) { IsBackground = true, Name = "admiral-sync-auto" };
                _auto.Start();
            }
        }
        return true;
    }

    public void Stop()
    {
        Thread? th;
        lock (_autoLock)
        {
            _autoStop?.Cancel();
            th = _auto;
            _auto = null;
            _autoStop = null;
        }
        if (th is not null && th != Thread.CurrentThread) th.Join(TimeSpan.FromSeconds(5));
    }

    private void AutoLoop(CancellationToken stop)
    {
        while (!stop.WaitHandle.WaitOne(TimeSpan.FromSeconds(Math.Max(60, Cfg.IntervalMinutes * 60))))
        {
            try { Run(); }
            catch (Exception exc)       // recorded in Last; never kills the schedule
            {
                Log.Logger.LogWarning("Automatic sync failed: {Error}", exc.Message);
            }
        }
    }

    // -- status
    public Dictionary<string, object?> Status() => new()
    {
        ["enabled"] = Cfg.Enabled, ["listening"] = Listening, ["port"] = Cfg.Port, ["local_ip"] = SyncNet.LocalIp().ToString(),
        ["network"] = NetworkText(), ["peer"] = Cfg.Peer, ["key_set"] = !string.IsNullOrEmpty(Cfg.Key), ["key_weak"] = KeyWeak(),
        ["last"] = Last, ["by_service"] = Cfg.Enabled && _host.ServiceOwnsSync,
    };

    // -- server side: what a peer may ask for
    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex IdRe();

    /// <summary>Check the timestamp window and the one-time id; returns the id.</summary>
    internal string CheckReplay(JsonObject msg)
    {
        if (Updates.Number(msg["v"]) != SyncCrypto.WireVersion)
            throw new SyncError("unsupported message version");
        var ts = Updates.Number(msg["ts"]) ?? double.NaN;
        var now = Now();
        if (!double.IsFinite(ts) || Math.Abs(now - ts) > Window)
            throw new SyncError("message expired (are the two computers' clocks within 5 minutes?)");
        var id = msg["id"] is JsonValue iv && iv.TryGetValue<string>(out var s) ? s : "";
        if (!IdRe().IsMatch(id)) throw new SyncError("bad message id");
        _seen.Add(id, now);
        return id;
    }

    private static List<string> Strings(JsonNode? n) =>
        [.. (n as JsonArray ?? []).Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>()];

    /// <summary>The answer to one authenticated request.</summary>
    public JsonObject Handle(string op, JsonObject body)
    {
        var mine = EnabledCategories();
        if (op == "hello")
            return new JsonObject
            {
                ["app"] = "ADmiral", ["version"] = Diag.Version, ["protocol"] = Protocol, ["host"] = Environment.MachineName,
                ["categories"] = new JsonArray([.. mine.Order(StringComparer.Ordinal).Select(c => (JsonNode)c)]),
            };
        var asked = body["cats"] is JsonArray ? Strings(body["cats"]) : body["cat"] is JsonValue cv && cv.TryGetValue<string>(out var one) ? [one] : [];
        var cats = asked.Where(mine.Contains).Distinct().ToList();
        switch (op)
        {
            case "manifest":
                var m = new JsonObject();
                foreach (var c in cats)
                {
                    var o = new JsonObject();
                    foreach (var (k, val) in Data.Manifest(c)) o[k] = val;
                    m[c] = o;
                }
                return m;
            case "pull":
            {
                // records for the asked keys in order while they fit the budget; "consumed" tells the client how
                // many keys this answer covers (it asks again for the rest). A single record above the budget can
                // never be sent: it is skipped (consumed, logged) so the exchange always makes progress.
                var outRecs = new JsonArray();
                var consumed = 0;
                if (cats.Count > 0)
                {
                    long size = 0;
                    foreach (var key in Strings(body["keys"]).Take(Batch))
                    {
                        var found = Data.Export(cats[0], [key]);
                        var bytes = found.Sum(RecordSize);
                        if (outRecs.Count > 0 && size + bytes > RecordBudget) break;
                        consumed++;
                        if (bytes > RecordBudget)
                        {
                            Log.Logger.LogWarning("Sync: {Cat} record {Key} is too large to send ({Bytes} bytes)", cats[0], key, bytes);
                            continue;
                        }
                        foreach (var r in found) outRecs.Add(r);
                        size += bytes;
                    }
                }
                return new JsonObject { ["records"] = outRecs, ["consumed"] = consumed };
            }
            case "push":
                if (cats.Count == 0) return new JsonObject { ["applied"] = 0 };
                var recs = body["records"] as JsonArray ?? [];
                if (recs.Count > Batch * 4) throw new SyncError("too many records in one request");
                var applied = Data.Apply(cats[0], [.. recs]);
                if (applied > 0) _host.DataChanged();
                return new JsonObject { ["applied"] = applied };
            default:
                throw new SyncError($"unknown operation '{op}'");
        }
    }

    /// <summary>JSON bytes of one record as it is sealed.</summary>
    public static long RecordSize(JsonNode? record) => record is null ? 4 : Encoding.UTF8.GetByteCount(record.ToJsonString()) + 1;

    /// <summary>Split records into batches of at most <paramref name="max"/> records and <paramref name="budget"/> JSON
    /// bytes (so every sealed message stays under <see cref="MaxBody"/>). A record that alone exceeds the budget cannot
    /// be sent and is left out (logged).</summary>
    public static List<List<JsonObject>> PackRecords(IEnumerable<JsonObject> records, long budget = RecordBudget, int max = Batch)
    {
        var outp = new List<List<JsonObject>>();
        var cur = new List<JsonObject>();
        long size = 0;
        foreach (var r in records)
        {
            var bytes = RecordSize(r);
            if (bytes > budget)
            {
                Log.Logger.LogWarning("Sync: a record is too large to send ({Bytes} bytes); skipped", bytes);
                continue;
            }
            if (cur.Count > 0 && (cur.Count >= max || size + bytes > budget))
            {
                outp.Add(cur);
                cur = [];
                size = 0;
            }
            cur.Add(r);
            size += bytes;
        }
        if (cur.Count > 0) outp.Add(cur);
        return outp;
    }

    // -- client side
    /// <summary>Resolve the peer and pick an address inside the allowed network (connecting to exactly that address).</summary>
    private IPAddress PeerAddress(string host, int port)
    {
        IPAddress[] addrs;
        if (IPAddress.TryParse(host, out var lit)) addrs = [lit];
        else
        {
            try { addrs = _resolve(host, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (Exception exc) when (exc is SocketException or ArgumentException)
            {
                throw new SyncError(I18n.T("sync.err_resolve", ("peer", host), ("err", exc.Message)), exc);
            }
        }
        var net = SyncNet.AllowedNetwork(Cfg.Network);
        var ok = addrs.Select(SyncNet.Normalize).FirstOrDefault(a => SyncNet.Allowed(a, net));
        return ok ?? throw new SyncError(I18n.T("sync.err_network", ("peer", host), ("net", net.ToString())));
    }

    /// <summary>One sealed request to a peer and its verified answer body.</summary>
    public JsonObject Call(string op, JsonObject body, int timeoutSeconds = 120, string? peer = null)
    {
        var keys = Keys() ?? throw new SyncError(I18n.T("sync.err_no_key"));
        var (host, port) = SyncNet.ParsePeer(peer ?? Peers().FirstOrDefault() ?? "", Cfg.Port);
        var addr = PeerAddress(host, port);
        var hostText = addr.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{addr}]" : addr.ToString();
        var url = new Uri($"http://{hostText}:{port.ToString(CultureInfo.InvariantCulture)}/sync/v1/{op}");
        string mid = "";
        int status = 0;
        var busy = false;
        using var answer = new MemoryStream();
        for (var attempt = 0; ; attempt++)
        {
            // a fresh id / timestamp per attempt; 503 = the peer is busy with other requests (or has no key yet)
            mid = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var envelope = new JsonObject { ["v"] = SyncCrypto.WireVersion, ["ts"] = Now(), ["id"] = mid, ["body"] = body };
            var blob = SyncCrypto.Seal(keys.Request, SyncCrypto.Aad("req", op), envelope);
            envelope.Remove("body");                                  // detach: the next attempt wraps it again
            if (blob.Length > MaxBody) throw new SyncError($"the {op} request is too large ({blob.Length} bytes)");
            answer.SetLength(0);
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds + 5));
                using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(blob) };
                req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                using var resp = _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
                status = (int)resp.StatusCode;
                busy = status == 503 && resp.Headers.RetryAfter is not null;     // busy listener (not: no key set)
                if (status == 200) Updates.CopyCappedAsync(resp, answer, MaxBody, null, cts.Token).GetAwaiter().GetResult();
            }
            catch (Exception exc) when (exc is HttpRequestException or OperationCanceledException or IOException)
            {
                var why = exc is OperationCanceledException ? I18n.T("sync.err_timeout") : exc.GetType().Name;
                throw new SyncError(I18n.T("sync.err_connect", ("peer", $"{host}:{port}"), ("err", why)), exc);
            }
            if (!busy || attempt >= BusyRetries) break;
            Thread.Sleep(BusyDelay * (attempt + 1));
        }
        switch (status)
        {
            case 401: throw new SyncError(I18n.T("sync.err_key"));
            case 403: throw new SyncError(I18n.T("sync.err_forbidden"));
            case not 200: throw new SyncError(I18n.T("sync.err_http", ("code", status)));
        }
        JsonObject msg;
        try { msg = SyncCrypto.UnsealInPlace(keys.Response, SyncCrypto.Aad("resp", op), answer.GetBuffer(), (int)answer.Length, MaxBody); }
        catch (SyncError exc) { throw new SyncError(I18n.T("sync.err_key"), exc); }
        if (!(msg["re"] is JsonValue re && re.TryGetValue<string>(out var r) && r == mid))
            throw new SyncError("answer to a different request");
        return msg["body"] as JsonObject ?? [];
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>Say hello to every peer; the result lists each one (host, version or the error).</summary>
    public JsonObject Test()
    {
        var peers = Peers();
        if (peers.Count == 0) throw new SyncError(I18n.T("sync.err_no_peer"));
        var outp = new JsonArray();
        JsonObject? first = null;
        var errors = new List<string>();
        foreach (var peer in peers)
        {
            try
            {
                var info = Call("hello", [], 15, peer);
                var row = new JsonObject
                {
                    ["peer"] = peer, ["ok"] = true, ["host"] = Str(info["host"]), ["version"] = Str(info["version"]),
                    ["categories"] = info["categories"]?.DeepClone(),
                };
                first ??= row;
                outp.Add(row);
            }
            catch (SyncError exc)
            {
                outp.Add(new JsonObject { ["peer"] = peer, ["ok"] = false, ["error"] = exc.Message });
                errors.Add($"{peer}: {exc.Message}");
            }
        }
        if (first is null) throw new SyncError(string.Join("; ", errors));
        return new JsonObject
        {
            ["host"] = first["host"]?.DeepClone(), ["version"] = first["version"]?.DeepClone(),
            ["categories"] = first["categories"]?.DeepClone(), ["peers"] = outp,
        };
    }

    /// <summary>Local time like Python's %Y-%m-%dT%H:%M:%S%z (e.g. 2026-11-21T10:00:00+0100).</summary>
    private string LocalTime()
    {
        var t = _time.GetLocalNow();
        return t.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture)
               + t.ToString("zzz", CultureInfo.InvariantCulture).Replace(":", "", StringComparison.Ordinal);
    }

    /// <summary>Exchange the enabled categories with every peer, one after the other: pull what a peer has newer, push
    /// what we have newer. A peer that cannot be reached does not stop the others.</summary>
    public SyncResult Run(Progress? progress = null)
    {
        if (!_runLock.Wait(0)) throw new SyncError(I18n.T("sync.err_busy"));
        var started = Stopwatch.GetTimestamp();
        try
        {
            var peers = Peers();
            if (peers.Count == 0) throw new SyncError(I18n.T("sync.err_no_peer"));
            var names = new List<string>();
            var errors = new List<string>();
            int pulled = 0, pushed = 0;
            var done = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var peer in peers)
            {
                SyncResult r;
                try { r = RunPeer(peer, progress); }
                catch (SyncError exc)
                {
                    errors.Add($"{peer}: {exc.Message}");
                    Log.Logger.LogWarning("Sync with {Peer} failed: {Error}", peer, exc.Message);
                    continue;
                }
                names.Add(r.Peer);
                pulled += r.Pulled;
                pushed += r.Pushed;
                done.UnionWith(r.Categories);
            }
            if (names.Count == 0) throw new SyncError(string.Join("; ", errors));
            var result = new SyncResult(string.Join(", ", names), pulled, pushed, [.. done]);
            Last = new JsonObject
            {
                ["ok"] = true, ["time"] = LocalTime(), ["peer"] = result.Peer, ["pulled"] = pulled, ["pushed"] = pushed,
                ["categories"] = new JsonArray([.. result.Categories.Select(c => (JsonNode)c)]),
                ["seconds"] = Math.Round(Stopwatch.GetElapsedTime(started).TotalSeconds, 1),
                ["errors"] = new JsonArray([.. errors.Select(e => (JsonNode)e)]),
            };
            _host.Store.Log("sync", I18n.T("log.sync", ("peer", result.Peer), ("pulled", pulled), ("pushed", pushed)));
            _host.DataChanged();
            return result;
        }
        catch (Exception exc)
        {
            Last = new JsonObject { ["ok"] = false, ["time"] = LocalTime(), ["error"] = exc.Message };
            throw;
        }
        finally
        {
            _runLock.Release();
        }
    }

    private SyncResult RunPeer(string peer, Progress? progress)
    {
        var info = Call("hello", [], 15, peer);
        var theirs = Strings(info["categories"]);
        var cats = EnabledCategories().Where(theirs.Contains).ToList();
        if (cats.Count == 0) throw new SyncError(I18n.T("sync.err_no_common"));
        var remote = Call("manifest", new JsonObject { ["cats"] = new JsonArray([.. cats.Select(c => (JsonNode)c)]) }, peer: peer);
        var steps = new List<(bool Pull, string Cat, List<string> Keys)>();
        foreach (var cat in cats)
        {
            var rm = new Dictionary<string, string>(StringComparer.Ordinal);
            if (remote[cat] is JsonObject ro)
                foreach (var (k, v) in ro)
                    if (Str(v) is { } s) rm[k] = s;
            var (pull, push) = SyncData.Plan(Data.Manifest(cat), rm);
            steps.Add((true, cat, pull));
            steps.Add((false, cat, push));
        }
        var total = steps.Sum(s => s.Keys.Count);
        int done = 0, pulled = 0, pushed = 0;
        var label = Str(info["host"]) is { Length: > 0 } h ? h : peer;
        progress?.Report(0, Math.Max(total, 1), label);
        foreach (var (isPull, cat, keys) in steps)
        {
            for (var i = 0; i < keys.Count; i += Batch)
            {
                var chunk = keys.Skip(i).Take(Batch).ToList();
                if (isPull)
                {
                    // the peer answers as many keys as fit one message ("consumed"); ask again for the rest
                    var pending = chunk;
                    while (pending.Count > 0)
                    {
                        var ans = Call("pull", new JsonObject { ["cat"] = cat, ["keys"] = new JsonArray([.. pending.Select(k => (JsonNode)k)]) }, peer: peer);
                        var recs = ans["records"] as JsonArray ?? [];
                        if (recs.Count > pending.Count) throw new SyncError("the peer sent more records than asked for");
                        pulled += Data.Apply(cat, [.. recs]);
                        var consumed = Updates.Number(ans["consumed"]) is double c && double.IsFinite(c)
                            ? (int)Math.Clamp(c, 0, pending.Count) : pending.Count;
                        if (consumed == 0) break;                    // no progress: leave the rest for the next run
                        pending = pending.Skip(consumed).ToList();
                    }
                }
                else
                {
                    foreach (var part in PackRecords(Data.Export(cat, chunk)))
                    {
                        var ans = Call("push", new JsonObject { ["cat"] = cat, ["records"] = new JsonArray([.. part.Cast<JsonNode>()]) }, peer: peer);
                        pushed += Updates.Number(ans["applied"]) is double a ? (int)a : 0;
                    }
                }
                done += chunk.Count;
                progress?.Report(done, total, $"{label}: {cat} {done}/{total}");
            }
        }
        return new SyncResult(label, pulled, pushed, cats);
    }
}
