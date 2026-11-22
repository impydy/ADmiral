using ADmiral.Core;

namespace ADmiral.Cli;

/// <summary>A command line that argparse would refuse (exit code 2, "admiral: error: ...").</summary>
public sealed class UsageException(string message) : Exception(message);

/// <summary>One sub-command: its options (name -> takes a value / is repeatable) and positional arguments.</summary>
public sealed record CommandSpec(string Name, string Help, IReadOnlyList<OptionSpec> Options, IReadOnlyList<PositionalSpec> Positionals);

public sealed record OptionSpec(string Long, string? Short, bool TakesValue, string Help, bool Repeat = false, IReadOnlyList<string>? Choices = null, bool IsInt = false);

public sealed record PositionalSpec(string Name, string Help, bool Many = false);

/// <summary>The parsed command line.</summary>
public sealed class CliArgs
{
    public string? Config { get; set; }
    public string Command { get; set; } = "";
    public Dictionary<string, List<string>> Options { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, List<string>> Positionals { get; } = new(StringComparer.Ordinal);

    public string? Opt(string name) => Options.TryGetValue(name, out var v) && v.Count > 0 ? v[^1] : null;

    public bool Flag(string name) => Options.ContainsKey(name);

    public List<string> All(string name) => Options.TryGetValue(name, out var v) ? v : [];

    public string Pos(string name) => Positionals[name][0];

    public List<string> PosAll(string name) => Positionals.TryGetValue(name, out var v) ? v : [];

    /// <summary>argparse-like parsing of <c>admiral [-c FILE] &lt;command&gt; [options]</c>.</summary>
    public static CliArgs Parse(IReadOnlyList<string> argv, IReadOnlyList<CommandSpec> commands)
    {
        var result = new CliArgs();
        var i = 0;
        // global options before the command
        for (; i < argv.Count; i++)
        {
            var a = argv[i];
            if (a is "-c" or "--config")
            {
                if (i + 1 >= argv.Count) throw new UsageException($"argument --config/-c: expected one argument");
                result.Config = argv[++i];
            }
            else if (a.StartsWith("--config=", StringComparison.Ordinal)) result.Config = a["--config=".Length..];
            else if (a is "--version" or "-h" or "--help") { result.Command = a; return result; }
            else if (a.StartsWith('-')) throw new UsageException($"unrecognized arguments: {a}");
            else break;
        }
        if (i >= argv.Count)
            throw new UsageException("the following arguments are required: cmd");
        var name = argv[i++];
        var spec = commands.FirstOrDefault(c => c.Name == name)
                   ?? throw new UsageException($"argument cmd: invalid choice: '{name}' (choose from {string.Join(", ", commands.Select(c => $"'{c.Name}'"))})");
        result.Command = name;
        var positionals = new List<string>();
        var onlyPositional = false;
        for (; i < argv.Count; i++)
        {
            var a = argv[i];
            if (!onlyPositional && a == "--") { onlyPositional = true; continue; }
            if (!onlyPositional && a is "-h" or "--help") { result.Options["help"] = []; return result; }
            if (!onlyPositional && a.Length > 1 && a.StartsWith('-') && !IsNumber(a))
            {
                var key = a;
                string? inline = null;
                var eq = a.IndexOf('=');
                if (a.StartsWith("--", StringComparison.Ordinal) && eq > 0) (key, inline) = (a[..eq], a[(eq + 1)..]);
                if (key is "-c" or "--config")                   // tolerated after the command too
                {
                    result.Config = inline ?? (i + 1 < argv.Count ? argv[++i] : throw new UsageException("argument --config/-c: expected one argument"));
                    continue;
                }
                var opt = spec.Options.FirstOrDefault(o => o.Long == key || o.Short == key)
                          ?? throw new UsageException($"unrecognized arguments: {a}");
                var label = opt.Short is null ? opt.Long : $"{opt.Long}/{opt.Short}";
                var optName = opt.Long[2..];
                if (!opt.TakesValue)
                {
                    if (inline is not null) throw new UsageException($"argument {label}: ignored explicit argument '{inline}'");
                    result.Options[optName] = [];
                    continue;
                }
                var value = inline ?? (i + 1 < argv.Count ? argv[++i] : throw new UsageException($"argument {label}: expected one argument"));
                if (opt.Choices is { } choices && !choices.Contains(value))
                    throw new UsageException($"argument {label}: invalid choice: '{value}' (choose from {string.Join(", ", choices.Select(c => $"'{c}'"))})");
                if (opt.IsInt && !int.TryParse(value, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out _))
                    throw new UsageException($"argument {label}: invalid int value: '{value}'");
                if (!result.Options.TryGetValue(optName, out var list) || !opt.Repeat) result.Options[optName] = list = [];
                list.Add(value);
                continue;
            }
            positionals.Add(a);
        }
        var p = 0;
        foreach (var pos in spec.Positionals)
        {
            if (pos.Many)
            {
                if (p >= positionals.Count) throw new UsageException($"the following arguments are required: {pos.Name}");
                result.Positionals[pos.Name] = positionals[p..];
                p = positionals.Count;
            }
            else
            {
                if (p >= positionals.Count) throw new UsageException($"the following arguments are required: {pos.Name}");
                result.Positionals[pos.Name] = [positionals[p++]];
            }
        }
        if (p < positionals.Count) throw new UsageException($"unrecognized arguments: {string.Join(" ", positionals[p..])}");
        return result;
    }

    private static bool IsNumber(string s) => double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _);

    // ------------------------------------------------------------------ the commands of cli.py
    public static IReadOnlyList<CommandSpec> Commands { get; } = Build();

    private static List<CommandSpec> Build()
    {
        var fleet = new OptionSpec("--fleet", null, true, "Limit to a fleet (name or id)");
        return
        [
            new("serve", "Run the web UI",
                [new("--host", null, true, "Address to listen on"), new("--port", null, true, "Port", IsInt: true),
                 new("--allow-remote", null, false, "Allow a non-loopback address (only behind an authenticating reverse proxy / TLS)")], []),
            new("init", "Write an example admiral.toml", [], []),
            new("offline-script", "Write ADmiral-Collect.ps1 (inventory file for computers that cannot reach this machine; run it from a Group Policy script)",
                [new("--output", "-o", true, "Where to write the script (default: ADmiral-Collect.ps1)")], []),
            new("test", "Test the directory connection", [], []),
            new("diag", "Print the grouped error report (warnings and errors of every run)",
                [new("--clear", null, false, "Empty the error ledger afterwards")], []),
            new("sync", "Pull computer objects from Active Directory", [], []),
            new("scan", "Probe machines for reachability", [fleet], []),
            new("collect", "Collect inventory (PDQ-style over SMB; WinRM fallback). Needs an administrative AD account", [fleet], []),
            new("refresh", "sync + scan + collect, in that order (good for a scheduled task)", [], []),
            new("summary", "Print fleet health summary", [], []),
            new("list", "List computers", [new("--fleet", null, true, "Only members of this fleet"), new("--json", null, false, "JSON output")], []),
            new("fleets", "List fleets", [], []),
            new("tag", "Add/remove tags on computers",
                [new("--add", null, true, "Tag to add", Repeat: true), new("--remove", null, true, "Tag to remove", Repeat: true)],
                [new("computers", "Computer names or GUIDs", Many: true)]),
            new("export", "Export a fleet's targets",
                [new("--format", "-f", true, "Output format (default: txt)", Choices: [.. Exporters.Formats.Keys]),
                 new("--online-only", null, false, "Only computers that answered the last scan"),
                 new("--output", "-o", true, "Write to file instead of stdout")],
                [new("fleet", "Fleet name or id")]),
            new("group-compare", "Compare a collection with its AD group (read-only; AD is never changed)", [], [new("fleet", "Fleet name or id")]),
        ];
    }

    public static string Usage =>
        "usage: admiral [-h] [--config CONFIG] [--version] {" + string.Join(",", Commands.Select(c => c.Name)) + "} ...";

    public static string Help()
    {
        var lines = new List<string>
        {
            Usage, "",
            "ADmiral - scan, collect, and organize on-prem Windows machines from Active Directory. Read-only: never changes AD or the scanned computers.",
            "", "options:",
            "  -h, --help            show this help message and exit",
            "  --config, -c CONFIG   Path to admiral.toml (default: ./admiral.toml)",
            "  --version             show program's version number and exit",
            "", "commands:",
        };
        lines.AddRange(Commands.Select(c => $"    {c.Name,-16}  {c.Help}"));
        return string.Join(Environment.NewLine, lines);
    }

    public static string Help(CommandSpec c)
    {
        var lines = new List<string>
        {
            $"usage: admiral {c.Name} [-h]" + string.Concat(c.Options.Select(o => o.TakesValue ? $" [{o.Long} {o.Long[2..].ToUpperInvariant()}]" : $" [{o.Long}]"))
                + string.Concat(c.Positionals.Select(p => p.Many ? $" {p.Name} [{p.Name} ...]" : $" {p.Name}")),
            "", c.Help,
        };
        if (c.Positionals.Count > 0)
        {
            lines.Add("");
            lines.Add("positional arguments:");
            lines.AddRange(c.Positionals.Select(p => $"  {p.Name,-20}  {p.Help}"));
        }
        lines.Add("");
        lines.Add("options:");
        lines.Add("  -h, --help              show this help message and exit");
        foreach (var o in c.Options)
        {
            var names = (o.Short is null ? "" : o.Short + ", ") + o.Long + (o.TakesValue ? " " + o.Long[2..].ToUpperInvariant() : "");
            var choices = o.Choices is null ? "" : $" {{{string.Join(",", o.Choices)}}}";
            lines.Add($"  {names,-22}  {o.Help}{choices}");
        }
        return string.Join(Environment.NewLine, lines);
    }
}
