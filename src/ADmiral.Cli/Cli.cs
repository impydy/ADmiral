using System.Collections;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ADmiral.Core;
using ADmiral.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Cli;

/// <summary>What the CLI needs from its surroundings (tests replace it).</summary>
public sealed class CliHost
{
    public TextWriter Out { get; init; } = Console.Out;
    public TextWriter Err { get; init; } = Console.Error;

    /// <summary>The environment (ADMIRAL_* settings, ADMIRAL_API_TOKEN); null = the process environment.</summary>
    public IReadOnlyDictionary<string, string>? Env { get; init; }

    /// <summary>Runs the started web app of <c>serve</c> (default: until Ctrl+C / SIGTERM).</summary>
    public Func<WebApplication, Uri, string, Task>? Serve { get; init; }

    /// <summary>Install the diagnostics logging (log files next to the database) - process-wide.</summary>
    public bool InstallDiagnostics { get; init; } = true;

    /// <summary>Start the service's background loops in <c>serve</c>.</summary>
    public bool BackgroundLoops { get; init; } = true;

    internal IReadOnlyDictionary<string, string> Environment => Env ?? System.Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
        .ToDictionary(e => (string)e.Key, e => e.Value as string ?? "");
}

/// <summary>Port of admiral/cli.py: <c>admiral &lt;command&gt;</c>. Exit codes: 0 ok, 1 error (unknown fleet / computer, file
/// exists), 2 usage or configuration error.</summary>
public static class Cli
{
    public static readonly IReadOnlySet<string> Loopback = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "localhost", "::1" };

    private static readonly JsonSerializerOptions Indented = new(WebApp.Json) { WriteIndented = true };

    public static int RunProcess(string[] args) => Run(args, new CliHost());

    public static int Run(IReadOnlyList<string> argv, CliHost? host = null)
    {
        host ??= new CliHost();
        CliArgs args;
        try
        {
            args = CliArgs.Parse(argv, CliArgs.Commands);
        }
        catch (UsageException exc)
        {
            host.Err.WriteLine(CliArgs.Usage);
            host.Err.WriteLine($"admiral: error: {exc.Message}");
            return 2;
        }
        if (args.Command == "--version")
        {
            host.Out.WriteLine($"ADmiral {Diag.Version}");
            return 0;
        }
        if (args.Command is "-h" or "--help")
        {
            host.Out.WriteLine(CliArgs.Help());
            return 0;
        }
        if (args.Flag("help"))
        {
            host.Out.WriteLine(CliArgs.Help(CliArgs.Commands.First(c => c.Name == args.Command)));
            return 0;
        }
        return RunCommand(args, host);
    }

    private static int RunCommand(CliArgs args, CliHost host)
    {
        if (args.Command == "init")
        {
            var path = args.Config ?? "admiral.toml";
            if (File.Exists(path))
            {
                host.Err.WriteLine($"{path} already exists; not overwriting");
                return 1;
            }
            File.WriteAllText(path, Config.ExampleConfig, new UTF8Encoding(false));
            host.Out.WriteLine($"Wrote {path}. Set ADMIRAL_LDAP_PASSWORD / ADMIRAL_WINRM_PASSWORD in the environment.");
            return 0;
        }
        if (args.Command == "offline-script")
        {
            var output = args.Opt("output") ?? Offline.ScriptName;
            Offline.WriteScript(output);
            host.Out.WriteLine($"Wrote {output}");
            return 0;
        }

        Demo.Register();                       // mode = "demo" works without a domain
        Settings settings;
        try
        {
            settings = Config.LoadSettings(args.Config, host.Environment);
        }
        catch (Exception exc) when (exc is ArgumentException or FileNotFoundException or IOException)
        {
            host.Err.WriteLine($"Configuration error: {exc.Message}");
            return 2;
        }

        if (host.InstallDiagnostics)
        {
            var folder = settings.DbPath != ":memory:"
                ? Path.GetDirectoryName(Path.GetFullPath(settings.DbPath)) ?? System.Environment.CurrentDirectory
                : System.Environment.CurrentDirectory;
            Diag.Install(Diag.LogDirFor(folder));
        }
        if (args.Command == "diag")
        {
            host.Out.WriteLine(Diag.Report());
            if (args.Flag("clear")) Diag.Clear();
            return 0;
        }
        if (args.Command == "serve") return Serve(args, settings, host).GetAwaiter().GetResult();

        AdmiralService app;
        try
        {
            app = new AdmiralService(settings, syncAutostart: false);
        }
        catch (ArgumentException exc)
        {
            host.Err.WriteLine($"Configuration error: {exc.Message}");
            return 2;
        }
        try
        {
            return Execute(app, args.Command, args, host);
        }
        catch (Exception exc) when (exc is NotFound or KeyNotFoundException or ArgumentException or RuleError)
        {
            host.Err.WriteLine($"Error: {exc.Message.Trim('\'')}");
            return 1;
        }
        finally
        {
            app.Dispose();
        }
    }

    private static Progress MakeProgress(TextWriter err) => new((done, total, msg) =>
    {
        if (total == 0) return;
        var m = msg.Length > 50 ? msg[..50] : msg;
        err.Write($"\r  [{done}/{total}] {m,-50}");
        if (done >= total) err.Write("\n");
        err.Flush();
    });

    private static long? FleetId(AdmiralService app, string? reference) =>
        reference is null ? null : (long)app.GetFleet(reference)["id"]!;

    /// <summary>Plain text table (header, dashes, rows), as cli.py's _table.</summary>
    public static string Table(IReadOnlyList<IReadOnlyList<string>> rows, IReadOnlyList<string> headers)
    {
        var widths = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length))).ToList();
        string Line(IEnumerable<string> cells) => string.Join("  ", cells.Select((c, i) => c.PadRight(widths[i])));
        var lines = new List<string> { Line(headers), Line(widths.Select(w => new string('-', w))) };
        lines.AddRange(rows.Select(Line));
        return string.Join("\n", lines);
    }

    private static string S(object? v) => v switch
    {
        null => "",
        bool b => b ? "True" : "False",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };

    private static int Execute(AdmiralService app, string cmd, CliArgs args, CliHost host)
    {
        var o = host.Out;
        switch (cmd)
        {
            case "test":
                o.WriteLine(app.Directory.Test());
                break;
            case "sync":
            {
                var r = app.SyncAd(MakeProgress(host.Err));
                o.WriteLine($"{r["total"]} computers in AD: {r["added"]} new, {r["updated"]} updated, {r["removed"]} removed");
                break;
            }
            case "scan":
            {
                var r = app.Scan(FleetId(app, args.Opt("fleet")), MakeProgress(host.Err));
                o.WriteLine($"Scanned {r["scanned"]}: {r["online"]} online, {r["offline"]} offline");
                break;
            }
            case "collect":
            {
                var r = app.Collect(FleetId(app, args.Opt("fleet")), MakeProgress(host.Err));
                o.WriteLine($"Collected {r["collected"]}/{r["attempted"]} ({r["failed"]} failed)");
                break;
            }
            case "refresh":
                foreach (var step in new[] { "sync", "scan", "collect" })
                {
                    o.WriteLine($"== {step}");
                    Execute(app, step, new CliArgs { Command = step }, host);
                }
                break;
            case "summary":
            {
                var s = app.Summary();
                o.WriteLine($"Computers: {s["total"]}  (enabled {s["enabled"]}, disabled {s["disabled"]}, stale {s["stale"]})");
                o.WriteLine($"Reachable: {s["online"]} online, {s["offline"]} offline, {s["unscanned"]} never scanned, {s["winrm"]} WinRM");
                o.WriteLine($"Inventory: {s["inventoried"]} collected, {s["pending_reboot"]} pending reboot, {s["low_disk"]} low on disk");
                o.WriteLine("\nBy OS:");
                foreach (var pair in (IEnumerable<object[]>)s["by_os"]!)
                    o.WriteLine($"  {S(pair[1]),5}  {S(pair[0])}");
                break;
            }
            case "list":
            {
                var fleet = args.Opt("fleet");
                var comps = fleet is not null ? app.FleetMembers(fleet) : app.Computers();
                if (args.Flag("json"))
                {
                    o.WriteLine(JsonSerializer.Serialize(comps, Indented));
                }
                else
                {
                    var rows = comps.Select(c => (IReadOnlyList<string>)
                    [
                        S(c["name"]), c["online"] switch { true => "up", false => "down", _ => "?" }, S(c["ip"]), S(c["os"]), S(c["ou"]),
                        string.Join(",", (c.GetValueOrDefault("tags") as IEnumerable<string>) ?? []),
                    ]).ToList();
                    o.WriteLine(Table(rows, ["NAME", "STATE", "IP", "OS", "OU", "TAGS"]));
                    o.WriteLine($"\n{comps.Count} computer(s)");
                }
                break;
            }
            case "fleets":
            {
                var rows = app.Fleets().Select(f => (IReadOnlyList<string>)
                    [S(f["id"]), S(f["name"]), S(f["kind"]), S(f["count"]), S(f["online"]), S(f.GetValueOrDefault("ad_group_dn"))]).ToList();
                o.WriteLine(Table(rows, ["ID", "NAME", "KIND", "MEMBERS", "ONLINE", "AD GROUP"]));
                break;
            }
            case "tag":
            {
                var n = app.Tag(args.PosAll("computers"), args.All("add"), args.All("remove"));
                o.WriteLine($"Updated tags on {n} computer(s)");
                break;
            }
            case "export":
            {
                var (body, _, _) = app.ExportFleet(args.Pos("fleet"), args.Opt("format") ?? "txt", args.Flag("online-only"));
                if (args.Opt("output") is { } path)
                {
                    File.WriteAllText(path, body, new UTF8Encoding(false));
                    host.Err.WriteLine($"Wrote {path}");
                }
                else
                {
                    o.Write(body);
                }
                break;
            }
            case "group-compare":
            {
                var r = app.GroupCompare(args.Pos("fleet"));
                o.WriteLine($"Collection '{r["fleet"]}' vs {r["group_dn"]} (read-only comparison)");
                var missing = (IEnumerable<Row>)r["missing"]!;
                var extra = (IEnumerable<Row>)r["extra"]!;
                foreach (var c in missing) o.WriteLine($"  missing from group: {c["name"]}");
                foreach (var c in extra) o.WriteLine($"  in group, not in collection: {c["name"]}");
                var others = ((IEnumerable)r["other_members"]!).Cast<object?>().Count();
                if (others > 0) o.WriteLine($"  ({others} other member(s): users, groups, out-of-scope computers)");
                o.WriteLine($"{missing.Count()} missing, {extra.Count()} extra, {r["matching"]} matching");
                break;
            }
            default:
                throw new UsageException($"unknown command {cmd}");
        }
        return 0;
    }

    /// <summary>A URL-safe random token (secrets.token_urlsafe(32)).</summary>
    public static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<int> Serve(CliArgs args, Settings settings, CliHost host)
    {
        var bindHost = args.Opt("host") ?? settings.Host;
        var port = args.Opt("port") is { } p ? int.Parse(p, CultureInfo.InvariantCulture) : settings.Port;
        var loopback = Loopback.Contains(bindHost);
        if (!loopback && !args.Flag("allow-remote"))
        {
            host.Err.WriteLine($"Refusing to listen on {bindHost}: the API can deploy software to every computer. Use a "
                               + "loopback address, or --allow-remote behind an authenticating reverse proxy with TLS.");
            return 2;
        }
        // every API call needs this token (other local users / processes must not use the port)
        var token = host.Environment.TryGetValue("ADMIRAL_API_TOKEN", out var t) && !string.IsNullOrEmpty(t) ? t : NewToken();
        if (!loopback)
            host.Err.WriteLine("WARNING: listening on a non-loopback address. Every API call needs the token, but the "
                               + "traffic is plain HTTP: put ADmiral behind a TLS reverse proxy.");
        using var service = new AdmiralService(settings);
        if (host.BackgroundLoops)
        {
            service.StartBackground();
            _ = Task.Run(() =>
            {
                try { service.ImportOffline(); }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or ArgumentException) { }
            });
        }
        var app = WebApp.Create(service, new WebAppOptions
        {
            Token = token, Host = bindHost, Port = port, AllowRemote = !loopback, Desktop = false, ExtraLogger = Diag.Provider,
        });
        await using (app.ConfigureAwait(false))
        {
            try
            {
                await app.StartAsync().ConfigureAwait(false);
            }
            catch (IOException exc)
            {
                host.Err.WriteLine($"Cannot listen on {bindHost}:{port}: {exc.Message}");
                return 1;
            }
            var bound = WebApp.BoundAddress(app);
            var shown = loopback ? "localhost" : bindHost;
            host.Out.WriteLine($"ADmiral {Diag.Version} ({settings.Mode} mode) on http://{bindHost}:{bound.Port}");
            host.Out.WriteLine($"Open: http://{shown}:{bound.Port}/?token={token}");
            host.Out.Flush();
            if (host.Serve is { } run) await run(app, bound, token).ConfigureAwait(false);
            else await app.WaitForShutdownAsync().ConfigureAwait(false);
            await app.StopAsync().ConfigureAwait(false);
        }
        return 0;
    }
}
