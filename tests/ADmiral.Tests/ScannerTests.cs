using System.Net;
using System.Net.Sockets;
using ADmiral.Core;

namespace ADmiral.Tests;

public class ScannerTests
{
    [Fact]
    public void Probe_real_sockets()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var open = ((IPEndPoint)listener.LocalEndpoint).Port;
        int closed;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        {
            tmp.Start();
            closed = ((IPEndPoint)tmp.LocalEndpoint).Port;
            tmp.Stop();
        }
        var r = Scanner.Probe("localhost", [open, closed], timeout: 0.5);
        Assert.Equal("127.0.0.1", r.Ip);
        Assert.Equal([open], r.OpenPorts);
        Assert.Equal(ProbeResult.None, Scanner.Probe("no-such-host.invalid", [80], timeout: 0.2));
        Assert.Null(Scanner.Resolve(""));
        Assert.Null(Scanner.Resolve("   "));
        Assert.Equal(ProbeResult.None, Scanner.Probe("", [445], timeout: 0.2));
    }

    [Fact]
    public void Scan_many_survives_errors_and_reports_progress()
    {
        ProbeResult Flaky(string host, IReadOnlyList<int> ports, double timeout) =>
            host == "bad" ? throw new InvalidOperationException("boom") : new ProbeResult("10.0.0.1", [445]);
        var seen = new Dictionary<string, ProbeResult>();
        var prog = new List<(int, int)>();
        var started = new List<string>();
        var res = Scanner.ScanMany([("a", "good"), ("b", "bad")], [445], 0.1, 4, Flaky,
            onResult: (k, r) => seen[k] = r, progress: (d, t, _) => prog.Add((d, t)), onStart: started.Add);
        Assert.Equal("10.0.0.1", res["a"].Ip);
        Assert.Equal([445], res["a"].OpenPorts);
        Assert.Equal(ProbeResult.None, res["b"]);
        Assert.Equal(res.Keys.Order(), seen.Keys.Order());
        Assert.Equal([(1, 2), (2, 2)], prog.Order());
        Assert.Equal(["a", "b"], started.Order());
        Assert.Empty(Scanner.ScanMany([], [445], 0.1, 4));
    }

    [Fact]
    public void Scan_many_runs_concurrently()
    {
        var targets = Enumerable.Range(0, 20).Select(i => ($"k{i}", $"h{i}")).ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var res = Scanner.ScanMany(targets, [445], 0.1, 20, (h, p, t) =>
        {
            Thread.Sleep(200);
            return new ProbeResult("10.0.0.1", []);
        });
        Assert.Equal(20, res.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3));
    }
}
