using System.Diagnostics;
using System.Net;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>The counterpart of the <c>admiral</c> pytest fixture (tests/conftest.py): a demo-mode service with an
/// in-memory database, the demo directory already synchronised. Process-wide settings (language, debug log) are left
/// alone so the tests can run in parallel; demo deployments run without pauses.</summary>
internal sealed class ServiceFixture : IDisposable
{
    public CoreTemp Temp { get; } = new();
    public AdmiralService App { get; }
    public DemoDirectory Directory { get; }

    public ServiceFixture(bool editable = false, Settings? settings = null, HttpMessageHandler? syncHandler = null, Store? store = null)
    {
        Directory = new DemoDirectory();
        settings ??= new Settings { Mode = "demo", DbPath = ":memory:", Language = "en" };
        App = new AdmiralService(settings, store ?? new Store(":memory:"), Directory,
                                 configPath: editable ? Temp.File("admiral.toml") : null,
                                 syncHandler: syncHandler, applyProcessSettings: false)
        {
            DemoDelayScale = 0,
            RetryService = new UnsupportedRetryService(),
        };
        App.SyncAd();
    }

    public string Guid(string name) => App.Store.ResolveNames([name])[0];

    public Row Computer(string name) => App.Computer(Guid(name));

    /// <summary>Wait for a background job to finish (max ~30 s).</summary>
    public JobInfo WaitJob(int id)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(30))
        {
            var j = App.Jobs.Get(id)!;
            if (j.Status != "running") return j;
            Thread.Sleep(20);
        }
        throw new TimeoutException($"job {id} did not finish");
    }

    public void Dispose()
    {
        App.Dispose();
        Temp.Dispose();
    }
}

/// <summary>Routes http://127.0.0.1:{port}/sync/v1/{op} to the service whose sync listens on that port (an in-memory
/// "network" between service instances).</summary>
internal sealed class ServiceSyncNet : HttpMessageHandler
{
    public Dictionary<int, SyncManager> Peers { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!Peers.TryGetValue(request.RequestUri!.Port, out var mgr)) throw new HttpRequestException("connection refused");
        var op = request.RequestUri.AbsolutePath["/sync/v1/".Length..];
        var body = request.Content!.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
        var r = mgr.Server.Handle(op, body, IPAddress.Loopback);
        return Task.FromResult(new HttpResponseMessage((HttpStatusCode)r.Status) { Content = new ByteArrayContent(r.Body) });
    }
}

/// <summary>Records the processes the service would start.</summary>
internal sealed class FakeStarter : IProcessStarter
{
    public List<ProcessStartInfo> Started { get; } = [];

    public void Start(ProcessStartInfo info) => Started.Add(info);
}
