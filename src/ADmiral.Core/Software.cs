using System.Globalization;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

// Software inventory: the installed programs of all computers, grouped by program with their versions
// (port of admiral/software.py). The same program shows up under many display names ("7-Zip 24.09 (x64)",
// "7-Zip 23.01 (x64)"), so the name is reduced to its base name (version numbers removed) and computers are
// counted per version.

/// <summary>One program across the fleet: the devices that have it and the devices per version.</summary>
public sealed class SoftwareEntry
{
    public required string Key { get; init; }
    public string Name { get; set; } = "";
    public string Publisher { get; set; } = "";
    public HashSet<string> Devices { get; } = [];
    /// <summary>version ("?" when unknown) -> device guids; in first-seen order.</summary>
    public Dictionary<string, HashSet<string>> Versions { get; } = [];
}

public sealed record SoftwareVersionCount(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("devices")] int Devices);

/// <summary>A row of the software list (the JSON the UI gets).</summary>
public sealed record SoftwareListRow(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("publisher")] string Publisher,
    [property: JsonPropertyName("devices")] int Devices,
    [property: JsonPropertyName("version_count")] int VersionCount,
    [property: JsonPropertyName("versions")] IReadOnlyList<SoftwareVersionCount> Versions);

public static partial class Software
{
    [GeneratedRegex(@"(?<![\w.])v?\d+(?:\.\d+)+(?![\w])", RegexOptions.IgnoreCase)]
    private static partial Regex VersionToken();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Spaces();

    [GeneratedRegex(@"\s*[-–]\s*$")]
    private static partial Regex TrailingDash();

    [GeneratedRegex(@"\(\s*\)")]
    private static partial Regex EmptyParens();

    [GeneratedRegex(@"\d+")]
    private static partial Regex Digits();

    /// <summary>"7-Zip 24.09 (x64)" -> "7-Zip (x64)". The program's own version and any dotted number are removed.</summary>
    public static string BaseName(string? name, string? version = null)
    {
        var n = name ?? "";
        if (!string.IsNullOrEmpty(version)) n = n.Replace(version, " ", StringComparison.Ordinal);
        n = VersionToken().Replace(n, " ");
        n = Spaces().Replace(n, " ");
        n = TrailingDash().Replace(n.Trim(), "");
        n = EmptyParens().Replace(n, "");               // a pair of parentheses left empty
        n = Spaces().Replace(n, " ").Trim(' ', '-', '–');
        return n.Length > 0 ? n : (name ?? "").Trim();
    }

    public static string SoftwareKey(string baseName) => Spaces().Replace(baseName.Trim().ToLowerInvariant(), " ");

    /// <summary>rows = (computer guid, display name, version, publisher) -> {key: entry}. The entry's name is the most
    /// common spelling of the base name, its publisher the most common publisher (ties: the first seen).</summary>
    public static Dictionary<string, SoftwareEntry> Aggregate(IEnumerable<(string Guid, string Name, string Version, string Publisher)> rows)
    {
        var outMap = new Dictionary<string, SoftwareEntry>();
        var names = new Dictionary<string, Dictionary<string, int>>();
        var pubs = new Dictionary<string, Dictionary<string, int>>();
        foreach (var (guid, name, version, publisher) in rows)
        {
            if (string.IsNullOrEmpty(name)) continue;
            var b = BaseName(name, version);
            var key = SoftwareKey(b);
            if (!outMap.TryGetValue(key, out var e)) outMap[key] = e = new SoftwareEntry { Key = key, Name = b };
            e.Devices.Add(guid);
            var v = (version ?? "").Trim();
            if (v.Length == 0) v = "?";
            if (!e.Versions.TryGetValue(v, out var set)) e.Versions[v] = set = [];
            set.Add(guid);
            Count(names, key, b);
            if (!string.IsNullOrEmpty(publisher)) Count(pubs, key, publisher.Trim());
        }
        foreach (var (key, e) in outMap)
        {
            e.Name = MostCommon(names[key]);
            e.Publisher = pubs.TryGetValue(key, out var p) ? MostCommon(p) : "";
        }
        return outMap;

        static void Count(Dictionary<string, Dictionary<string, int>> map, string key, string value)
        {
            if (!map.TryGetValue(key, out var c)) map[key] = c = [];
            c[value] = c.GetValueOrDefault(value) + 1;
        }

        // like Counter.most_common(1): the highest count, the first inserted on a tie
        static string MostCommon(Dictionary<string, int> counts)
        {
            var best = default(KeyValuePair<string, int>);
            var first = true;
            foreach (var kv in counts)
                if (first || kv.Value > best.Value)
                {
                    best = kv;
                    first = false;
                }
            return best.Key;
        }
    }

    /// <summary>"131.0.6778.86" -> [131, 0, 6778, 86]; text parts are ignored, at most 8 numbers. Unparsable -> [].</summary>
    public static long[] VersionKey(string? v) =>
        [.. Digits().Matches(v ?? "").Take(8).Select(m => long.TryParse(m.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : long.MaxValue)];

    /// <summary>Compare two version keys like Python tuples (element-wise, a prefix is smaller).</summary>
    public static int CompareKeys(IReadOnlyList<long> a, IReadOnlyList<long> b)
    {
        for (var i = 0; i < Math.Min(a.Count, b.Count); i++)
        {
            var c = a[i].CompareTo(b[i]);
            if (c != 0) return c;
        }
        return a.Count.CompareTo(b.Count);
    }

    /// <summary>Compare two version strings by <see cref="VersionKey"/>.</summary>
    public static int CompareVersions(string? a, string? b) => CompareKeys(VersionKey(a), VersionKey(b));

    /// <summary>Versions with their device counts, most used first (then the newest first).</summary>
    public static List<(string Version, int Devices)> SortedVersions(IReadOnlyDictionary<string, HashSet<string>> versions)
    {
        var items = versions.Select(kv => (Version: kv.Key, Devices: kv.Value.Count, Neg: VersionKey(kv.Key).Select(n => -n).ToArray())).ToList();
        // stable sort by (-devices, [-n for n in version_key]) like the Python version
        return [.. items.Order(Comparer<(string Version, int Devices, long[] Neg)>.Create((x, y) =>
            {
                var c = y.Devices.CompareTo(x.Devices);
                return c != 0 ? c : CompareKeys(x.Neg, y.Neg);
            }))
            .Select(x => (x.Version, x.Devices))];
    }

    public static SoftwareListRow ListRow(SoftwareEntry e)
    {
        var vs = SortedVersions(e.Versions);
        return new SoftwareListRow(e.Key, e.Name, e.Publisher, e.Devices.Count, vs.Count,
                                   [.. vs.Take(5).Select(v => new SoftwareVersionCount(v.Version, v.Devices))]);
    }
}
