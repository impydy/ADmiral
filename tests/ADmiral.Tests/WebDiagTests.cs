using ADmiral.Core;
using Microsoft.Extensions.Logging;

namespace ADmiral.Tests;

/// <summary>The web cases of test_diag.py and test_logreport.py (process-wide diagnostics: run alone).</summary>
[Collection("Diagnostics")]
public sealed class WebDiagTests : IDisposable
{
    private readonly DiagFolder _diag = new();
    private readonly WebFixture W = new();

    public void Dispose()
    {
        W.Dispose();
        _diag.Dispose();
    }

    [Fact]
    public void Api_exposes_and_clears_the_list()
    {
        Log.Logger.LogWarning("api visible problem");
        var r = W.GetJson("/api/diagnostics");
        Assert.Contains("api visible problem", (string)r["text"]!);
        Assert.True((int)r["records"]! >= 1);
        Assert.True((bool)WebFixture.Json(W.Post("/api/diagnostics/clear"))["ok"]!);
        Assert.Equal(0, (int)W.GetJson("/api/diagnostics")["records"]!);
    }

    [Fact]
    public void Unexpected_api_error_is_logged_and_returns_500()
    {
        W.App.Store.Close();
        Assert.Equal(500, W.Get("/api/summary").Code());
        Assert.Contains(_diag.Ledger(), e => e.ToJsonString().Contains("/api/summary", StringComparison.Ordinal) && e.ContainsKey("exception"));
    }

    [Fact]
    public void Expected_errors_are_warnings_with_the_route()
    {
        Assert.Equal(400, W.Post("/api/tags", new { ids = new[] { "NOPE" }, add = new[] { "x" } }).Code());
        Assert.Contains(_diag.Ledger(), e => e.ToJsonString().Contains("/api/tags", StringComparison.Ordinal));
    }

    [Fact]
    public void Logs_api_and_debug_setting()
    {
        var r = W.GetJson("/api/logs");
        Assert.Equal(["admiral.log", "admiral-debug.log", "admiral-errors.jsonl"], r["files"]!.AsArray().Select(f => (string)f!["name"]!));
        Assert.True((bool)r["debug"]!);
        Assert.Equal(200, W.Get("/api/logs/admiral.log").Code());
        Assert.True(W.Get("/api/logs/passwd").Code() >= 400);
        Assert.True(W.Get("/api/logs/..%2f..%2fadmiral.toml").Code() >= 400);
    }

    [Fact]
    public void Api_writes_the_log_package()
    {
        Log.Logger.LogWarning("something for the package");
        using var r = W.Post("/api/logs/package");
        Assert.Equal(200, r.Code());
        var body = WebFixture.Json(r).AsObject();
        Assert.False(body.ContainsKey("zip"));
        Assert.False(body.ContainsKey("password"));
        Assert.True(File.Exists(Path.Combine((string)body["folder"]!, "README.txt")));
        Assert.StartsWith("https://github.com/impydy/ADmiral/issues/new", (string)body["issue_url"]!);
        Assert.False(string.IsNullOrEmpty((string?)body["version"]));
    }
}
