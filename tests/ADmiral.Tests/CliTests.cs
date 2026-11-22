using System.Net;
using System.Text.Json.Nodes;
using ADmiral.Cli;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>tests/test_cli.py: every command, run in-process against a demo config in a temporary folder. The CLI sets
/// the process-wide language and diagnostics, so these run alone.</summary>
[Collection("Diagnostics")]
public sealed class CliTests : IDisposable
{
    private readonly CoreTemp _tmp = new();
    private readonly string _lang = I18n.Language;
    private readonly Func<IDirectory>? _demoFactory = DirectoryFactory.DemoFactory;
    private readonly string _cfg;

    public CliTests()
    {
        _cfg = _tmp.File("admiral.toml");
        WriteConfig("mode = \"demo\"\nlanguage = \"en\"\n");
    }

    private void WriteConfig(string text) =>
        File.WriteAllText(_cfg, text + $"db_path = '{_tmp.File("admiral.db")}'\n");

    public void Dispose()
    {
        Diag.Uninstall();
        Diag.ClearSecrets();
        I18n.SetLanguage(_lang);
        DirectoryFactory.DemoFactory = _demoFactory;        // the CLI registers the demo directory process-wide
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        _tmp.Dispose();
    }

    private (int Code, string Out, string Err) Run(params string[] args) => RunWith(null, args);

    private (int Code, string Out, string Err) RunWith(Func<Microsoft.AspNetCore.Builder.WebApplication, Uri, string, Task>? serve, params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var argv = args.Length > 0 && args[0] is "init" or "offline-script" or "--version" ? args : ["-c", _cfg, .. args];
        var code = Cli.Cli.Run(argv, new CliHost { Out = o, Err = e, Env = new Dictionary<string, string>(), Serve = serve, BackgroundLoops = false });
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public void Init_writes_example_and_refuses_overwrite()
    {
        var path = _tmp.File("new.toml");
        Assert.Equal(0, Run("init", "-c", path).Code);
        Assert.Contains("mode = \"ldap\"", File.ReadAllText(path));
        Assert.Equal(1, Run("init", "-c", path).Code);
    }

    [Fact]
    public void Full_workflow()
    {
        Assert.Contains("Demo domain", Run("test").Out);
        var (code, outp, _) = Run("sync");
        Assert.Equal(0, code);
        Assert.Contains("190 computers in AD: 190 new", outp);
        (code, outp, _) = Run("scan");
        Assert.Equal(0, code);
        Assert.Contains("online", outp);
        (code, outp, _) = Run("collect");
        Assert.Equal(0, code);
        Assert.Contains("Collected", outp);
        (code, outp, _) = Run("refresh");
        Assert.Equal(0, code);
        Assert.Equal(3, outp.Split("== ").Length - 1);
        outp = Run("summary").Out;
        Assert.Contains("Computers: 190", outp);
        Assert.Contains("By OS:", outp);
        outp = Run("list").Out;
        Assert.Contains("LT-001", outp);
        Assert.Contains("190 computer(s)", outp);
        Assert.Equal(190, JsonNode.Parse(Run("list", "--json").Out)!.AsArray().Count);
        Assert.StartsWith("Updated tags on 2", Run("tag", "LT-001", "LT-002", "--add", "pilot").Out);
        Assert.Contains("pilot", Run("list").Out);
    }

    [Fact]
    public void Collections_export_and_compare()
    {
        Run("sync");
        using (var app = new AdmiralService(Config.LoadSettings(_cfg, new Dictionary<string, string>()), syncAutostart: false))
            app.CreateFleet("Pilot", "static", members: ["LT-001", "LT-005"], adGroupDn: "CN=Deploy-Office-Pilot,OU=Groups,DC=contoso,DC=local");
        var outp = Run("fleets").Out;
        Assert.Contains("Pilot", outp);
        Assert.Contains("static", outp);
        Assert.Contains("2 computer(s)", Run("list", "--fleet", "Pilot").Out);
        Assert.Equal(["lt-001.contoso.local", "lt-005.contoso.local"], Run("export", "Pilot", "-f", "txt").Out.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')));
        var csv = _tmp.File("out.csv");
        Assert.Equal(0, Run("export", "Pilot", "-f", "csv", "-o", csv).Code);
        Assert.StartsWith("name,", File.ReadAllText(csv));
        var (code, cmp, _) = Run("group-compare", "Pilot");
        Assert.Equal(0, code);
        Assert.Contains("read-only comparison", cmp);
        Assert.Contains("missing from group: LT-005", cmp);
        Assert.Contains("in group, not in collection: LT-002", cmp);
        Assert.Contains("1 other member(s)", cmp);
        // only the collection's two computers (the demo data of this port marks one of them as not to be scanned)
        Assert.Matches(@"^Scanned [12]: ", Run("scan", "--fleet", "Pilot").Out);
        Assert.Equal(2, Run("export", "Pilot", "-f", "bogus").Code);                     // argparse choices
    }

    [Fact]
    public void Errors()
    {
        Run("sync");
        var (code, _, err) = Run("export", "Nope");
        Assert.Equal(1, code);
        Assert.Contains("not found", err);
        (code, _, err) = Run("tag", "NOPE-1", "--add", "x");
        Assert.Equal(1, code);
        Assert.Contains("NOPE-1", err);
        WriteConfig("mode = \"ldap\"\n");
        (code, _, err) = Run("summary");
        Assert.Equal(2, code);
        Assert.Contains("Configuration error", err);
        var o = new StringWriter();
        var e = new StringWriter();
        Assert.Equal(2, Cli.Cli.Run(["-c", _tmp.File("missing.toml"), "summary"], new CliHost { Out = o, Err = e, Env = new Dictionary<string, string>() }));
        Assert.Equal(2, Run("bogus").Code);
        Assert.Equal(2, Run("list", "--nope").Code);
        Assert.Equal(2, Run("tag").Code);                                                // computers are required
        Assert.Equal(2, Run().Code);
    }

    [Fact]
    public void Env_overrides_the_file()
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var code = Cli.Cli.Run(["-c", _cfg, "summary"], new CliHost { Out = o, Err = e, Env = new Dictionary<string, string> { ["ADMIRAL_MODE"] = "ldap" } });
        Assert.Equal(2, code);                                                            // ldap without a server
        Assert.Contains("Configuration error", e.ToString());
    }

    [Fact]
    public void No_ad_write_commands()
    {
        Assert.DoesNotContain(CliArgs.Commands, c => c.Name == "group-sync");
        Assert.All(CliArgs.Commands, c => Assert.DoesNotContain(c.Options, o => o.Long == "--apply"));
    }

    [Fact]
    public void Version_help_offline_script_and_diag()
    {
        var (code, outp, _) = Run("--version");
        Assert.Equal(0, code);
        Assert.StartsWith("ADmiral ", outp);
        Assert.Contains("group-compare", Run("--help").Out);
        Assert.Contains("--online-only", Run("export", "--help").Out);
        var script = _tmp.File("collect.ps1");
        Assert.Equal(0, Run("offline-script", "-o", script).Code);
        Assert.Contains("\r\n", File.ReadAllText(script));
        (code, outp, _) = Run("diag", "--clear");
        Assert.Equal(0, code);
        Assert.NotEmpty(outp);
        Assert.True(Directory.Exists(_tmp.File("logs")));
    }

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("0.0.0.0", true)]
    public void Serve(string host, bool remote)
    {
        var seen = new List<int>();
        string? csp = null;
        bool? desktop = null;
        var args = new List<string> { "serve", "--host", host, "--port", "0" };
        if (remote) args.Add("--allow-remote");
        var (code, outp, err) = RunWith(async (app, bound, token) =>
        {
            using var c = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{bound.Port}") };
            seen.Add((int)(await c.GetAsync("/api/status")).StatusCode);                 // no token: refused
            var req = new HttpRequestMessage(HttpMethod.Get, "/api/status");
            req.Headers.Add("X-ADmiral-Token", token);
            using var r = await c.SendAsync(req);
            seen.Add((int)r.StatusCode);
            csp = r.Headers.GetValues("Content-Security-Policy").Single();
            desktop = (bool)JsonNode.Parse(await r.Content.ReadAsStringAsync())!["desktop"]!;
            var evil = new HttpRequestMessage(HttpMethod.Get, "/api/status");
            evil.Headers.Add("X-ADmiral-Token", token);
            evil.Headers.Host = "evil.example";
            seen.Add((int)(await c.SendAsync(evil)).StatusCode);                          // Host check only on loopback
        }, [.. args]);
        Assert.Equal(0, code);
        var token = outp.Split("?token=", 2)[1].Split((char[])['\r', '\n', ' '])[0];
        Assert.True(token.Length >= 40);
        Assert.Contains($"on http://{host}:", outp);
        Assert.Equal(new[] { 401, 200, remote ? 200 : 400 }, seen);
        Assert.Contains("script-src 'self'", csp);
        Assert.False(desktop);
        Assert.Equal(remote, err.Contains("WARNING", StringComparison.Ordinal));
    }

    [Fact]
    public void Serve_uses_the_token_from_the_environment()
    {
        var o = new StringWriter();
        var code = Cli.Cli.Run(["-c", _cfg, "serve", "--port", "0"], new CliHost
        {
            Out = o, Err = new StringWriter(), BackgroundLoops = false,
            Env = new Dictionary<string, string> { ["ADMIRAL_API_TOKEN"] = "fixed-token-for-the-test" },
            Serve = (_, _, token) =>
            {
                Assert.Equal("fixed-token-for-the-test", token);
                return Task.CompletedTask;
            },
        });
        Assert.Equal(0, code);
        Assert.Contains("?token=fixed-token-for-the-test", o.ToString());
    }

    [Fact]
    public void Serve_refuses_a_remote_address_without_the_flag()
    {
        var (code, _, err) = RunWith((_, _, _) => throw new InvalidOperationException("must not start"), "serve", "--host", "0.0.0.0", "--port", "9999");
        Assert.Equal(2, code);
        Assert.Contains("Refusing", err);
    }

    [Fact]
    public void Table_layout()
    {
        Assert.Equal("A    BB\n---  --\nxyz  1 ", Cli.Cli.Table([["xyz", "1"]], ["A", "BB"]));
    }

    [Fact]
    public void Loopback_names()
    {
        Assert.Contains("::1", Cli.Cli.Loopback);
        Assert.DoesNotContain("0.0.0.0", Cli.Cli.Loopback);
        Assert.True(IPAddress.IsLoopback(ADmiral.Web.WebApp.BindAddress("localhost")));
    }
}
