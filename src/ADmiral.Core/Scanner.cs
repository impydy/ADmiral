using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>The result of one reachability probe: the resolved IPv4 address (null = name not resolvable) and the
/// TCP ports that accepted a connection.</summary>
public sealed record ProbeResult(string? Ip, IReadOnlyList<int> OpenPorts)
{
    public static readonly ProbeResult None = new(null, []);
}

/// <summary>Reachability scanning via TCP connect probes.
/// <para>ICMP needs raw sockets (admin rights) and is often blocked by Windows Firewall, so ADmiral instead probes the
/// ports that matter for management: 135 (RPC/WMI), 445 (SMB), 3389 (RDP), 5985/5986 (WinRM).</para></summary>
public static class Scanner
{
    public static readonly IReadOnlyDictionary<int, string> PortNames = new Dictionary<int, string>
    {
        [135] = "RPC", [139] = "NetBIOS", [445] = "SMB", [3389] = "RDP", [5985] = "WinRM", [5986] = "WinRM-S", [22] = "SSH",
    };

    public const int MaxWorkers = 256;

    /// <summary>The first IPv4 address of <paramref name="host"/>, or null. An empty name never resolves: on Windows
    /// it would return this machine's own address, so a computer without a name would probe the admin's PC.</summary>
    public static string? Resolve(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        var h = host.Trim();
        if (Ipv4.TryParse(h, out var lit)) return Ipv4.Format(lit);
        try
        {
            var addrs = Dns.GetHostAddresses(h, AddressFamily.InterNetwork);
            return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
        }
        catch (Exception exc) when (exc is SocketException or ArgumentException) { return null; }
    }

    /// <summary>Resolve <paramref name="host"/> and try a TCP connection to every port (one after the other).</summary>
    public static ProbeResult Probe(string? host, IEnumerable<int> ports, double timeout = 1.0)
    {
        var ip = Resolve(host);
        if (ip is null) return ProbeResult.None;
        var addr = IPAddress.Parse(ip);
        var wait = TimeSpan.FromSeconds(Math.Clamp(timeout, 0.01, 60));
        var open = new List<int>();
        foreach (var port in ports)
        {
            if (port is < 1 or > 65535) continue;
            if (TryConnect(addr, port, wait)) open.Add(port);
        }
        return new ProbeResult(ip, open);
    }

    private static bool TryConnect(IPAddress addr, int port, TimeSpan timeout)
    {
        using var sock = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            sock.ConnectAsync(new IPEndPoint(addr, port), cts.Token).AsTask().GetAwaiter().GetResult();
            return sock.Connected;
        }
        catch (Exception exc) when (exc is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            return false;
        }
    }

    public delegate ProbeResult ProbeFn(string host, IReadOnlyList<int> ports, double timeout);

    /// <summary>Probe <paramref name="targets"/> = [(key, hostname), ...] concurrently with up to
    /// <paramref name="workers"/> threads. The callbacks are never called concurrently (one at a time, in completion
    /// order); a probe that throws counts as unreachable.</summary>
    public static Dictionary<string, ProbeResult> ScanMany(
        IReadOnlyList<(string Key, string Host)> targets, IReadOnlyList<int> ports, double timeout, int workers,
        ProbeFn? probeFn = null,
        Action<string, ProbeResult>? onResult = null,
        Action<int, int, string>? progress = null,
        Action<string>? onStart = null)
    {
        var results = new Dictionary<string, ProbeResult>(StringComparer.Ordinal);
        var total = targets.Count;
        if (total == 0) return results;
        var probe = probeFn ?? ((h, p, t) => Probe(h, p, t));
        var queue = new ConcurrentQueue<(string Key, string Host)>(targets);
        var gate = new Lock();
        var done = 0;
        var threads = Math.Clamp(Math.Min(workers, total), 1, MaxWorkers);
        Exception? callbackError = null;

        void Worker()
        {
            while (Volatile.Read(ref callbackError) is null && queue.TryDequeue(out var t))
            {
                ProbeResult res;
                try
                {
                    if (onStart is not null)
                        lock (gate) onStart(t.Key);                         // this computer is being probed right now
                    res = probe(t.Host, ports, timeout);
                }
                catch (Exception exc)                                       // a single bad host must not kill the scan
                {
                    Log.Logger.LogWarning(exc, "Reachability probe of {Host} failed", t.Host);
                    res = ProbeResult.None;
                }
                lock (gate)
                {
                    try
                    {
                        results[t.Key] = res;
                        done++;
                        onResult?.Invoke(t.Key, res);
                        progress?.Invoke(done, total, t.Host);
                    }
                    catch (Exception exc)
                    {
                        callbackError ??= exc;
                    }
                }
            }
        }

        var pool = Enumerable.Range(0, threads).Select(_ => new Thread(Worker) { IsBackground = true, Name = "admiral-scan" }).ToList();
        pool.ForEach(t => t.Start());
        pool.ForEach(t => t.Join());
        if (callbackError is not null) throw new AggregateException("A scan callback failed", callbackError);
        return results;
    }
}
