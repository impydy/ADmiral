using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>The settings screen over the API with an editable admiral.toml (test_desktop.py's API part).</summary>
public sealed class WebSettingsTests : IDisposable
{
    private readonly WebFixture W = new(editable: true);

    public void Dispose() => W.Dispose();

    [Fact]
    public void Settings_are_saved_and_passwords_never_returned()
    {
        var cfg = W.GetJson("/api/settings");
        Assert.True((bool)cfg["editable"]!);
        Assert.True((bool)W.GetJson("/api/status")["settings_editable"]!);
        using var ok = W.Put("/api/settings", new { theme = "dark" });
        Assert.Equal(200, ok.Code());
        Assert.Equal("dark", (string?)WebFixture.Json(ok)["theme"]);
        Assert.Equal("dark", W.App.Settings.Theme);
        using var bad = W.Put("/api/settings", new { mode = "ldap", ldap = new { port = 389 } });
        Assert.Equal(400, bad.Code());
        Assert.Contains("ldap.server", WebFixture.Detail(bad));
        using var saved = W.Put("/api/settings", new
        {
            mode = "ldap", stale_days = "30",
            ldap = new { server = "dc01.corp.local", base_dn = "DC=corp,DC=local", user = "CORP\\svc", password = "s3cret" },
            scan = new { ports = new[] { 445, 5985 } },
        });
        Assert.Equal(200, saved.Code());
        var view = WebFixture.Json(saved);
        Assert.Equal("ldap", (string?)view["mode"]);
        Assert.True((bool)view["ldap"]!["password_set"]!);
        Assert.Equal(30, (int)view["stale_days"]!);
        Assert.DoesNotContain("s3cret", WebFixture.Text(saved));
        Assert.DoesNotContain("s3cret", File.ReadAllText(W.App.ConfigPath!));
        Assert.Equal("corp.local", (string?)W.GetJson("/api/status")["domain"]);
        // testing an unsaved demo setting works without saving
        var r = WebFixture.Json(W.Post("/api/test-connection", new { mode = "demo" }));
        Assert.True((bool)r["ok"]!);
        Assert.Contains("Demo", (string)r["message"]!);
        Assert.Equal(422, W.Put("/api/settings", new[] { 1 }).Code());
    }

    [Fact]
    public void Sync_settings_reconfigure_the_listener_through_the_api()
    {
        var port = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        port.Start();
        var p = ((System.Net.IPEndPoint)port.LocalEndpoint).Port;
        port.Stop();
        using var r = W.Put("/api/settings", new { sync = new { enabled = true, port = p, network = "127.0.0.0/8", key = new string('k', 43) } });
        Assert.Equal(200, r.Code());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (ADmiral.Web.WebApp.SyncAddress(W.Web) is null && sw.Elapsed < TimeSpan.FromSeconds(15)) Thread.Sleep(50);
        Assert.Equal(p, ADmiral.Web.WebApp.SyncAddress(W.Web)!.Port);
        Assert.True((bool)W.GetJson("/api/sync")["listening"]!);
    }
}
