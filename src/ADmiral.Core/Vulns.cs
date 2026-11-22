// Port of admiral/vulns.py: CVE matching - which installed programs have known vulnerabilities?
//
// Data (public, downloaded through the optional proxy): the NIST National Vulnerability Database (NVD 2.0 API)
// for the CVEs of a product, and CISA's list of Known Exploited Vulnerabilities (KEV).
// Matching is deliberately conservative: only programs in Catalog (a curated map from the program's name to its
// NVD vendor/product) are looked up, so a name that merely looks similar cannot produce a false alarm. The result
// means "probably affected": NVD ranges and Windows' DisplayVersion are not always exact.

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>A stored range with its version keys computed once (null = open bound).</summary>
public sealed record CompiledMatch(long[]? StartIncl, long[]? StartExcl, long[]? EndIncl, long[]? EndExcl, long[]? Exact, bool HasExact);

public static class Vulns
{
    public const string Nvd = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    public const string KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public const int Page = 2000;
    private const int MaxSummary = 600;

    /// <summary>(regex on the lower-case base name, NVD vendor, NVD product). Curated; extend as needed.</summary>
    public static readonly IReadOnlyList<(string Pattern, string Vendor, string Product)> Catalog =
    [
        (@"^google chrome", "google", "chrome"),
        (@"^mozilla firefox", "mozilla", "firefox"),
        (@"^mozilla thunderbird", "mozilla", "thunderbird"),
        (@"^microsoft edge$", "microsoft", "edge_chromium"),
        (@"^7-zip", "7-zip", "7-zip"),
        (@"^notepad\+\+", "notepad-plus-plus", @"notepad\+\+"),
        (@"^vlc media player", "videolan", "vlc_media_player"),
        (@"^adobe acrobat reader", "adobe", "acrobat_reader_dc"),
        (@"^adobe acrobat( \(64-bit\))?$", "adobe", "acrobat_dc"),
        (@"^java( se)? (\d|development kit|runtime)|^java\b.*update", "oracle", "jre"),
        (@"^zoom( workplace| meetings)?\b", "zoom", "zoom"),
        (@"^putty", "putty", "putty"),
        (@"^winrar", "rarlab", "winrar"),
        (@"^vmware tools", "vmware", "tools"),
        (@"^wireshark", "wireshark", "wireshark"),
        (@"^git\b", "git-scm", "git"),
        (@"^python\b", "python", "python"),
        (@"^node\.?js", "nodejs", "node.js"),
        (@"^filezilla", "filezilla-project", "filezilla"),
        (@"^gimp", "gimp", "gimp"),
        (@"^libreoffice", "libreoffice", "libreoffice"),
        (@"^teamviewer", "teamviewer", "teamviewer"),
        (@"^openvpn", "openvpn", "openvpn"),
        (@"^winscp", "winscp", "winscp"),
        (@"^keepass", "keepass", "keepass"),
        (@"^sumatrapdf", "sumatrapdfreader", "sumatrapdf"),
        (@"^anydesk", "anydesk", "anydesk"),
        (@"^itunes", "apple", "itunes"),
        (@"^foxit (pdf )?reader", "foxitsoftware", "foxit_reader"),
        (@"^cisco secure client|^cisco anyconnect", "cisco", "anyconnect_secure_mobility_client"),
    ];

    private static readonly (Regex Rx, string Vendor, string Product)[] Compiled =
        [.. Catalog.Select(c => (new Regex(c.Pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)), c.Vendor, c.Product))];

    /// <summary>The NVD (vendor, product) of a program, or null when it is not in the curated catalog.</summary>
    public static (string Vendor, string Product)? CpeFor(string? baseName)
    {
        var n = (baseName ?? "").ToLowerInvariant().Trim();
        foreach (var (rx, vendor, product) in Compiled)
            if (rx.IsMatch(n)) return (vendor, product);
        return null;
    }

    public static string Severity(double? score) => score switch
    {
        null => "unknown",
        >= 9 => "critical",
        >= 7 => "high",
        >= 4 => "medium",
        _ => "low",
    };

    // ---------------------------------------------------------------------- parsing + matching
    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static double? Cvss(JsonNode? metrics)
    {
        foreach (var k in (string[])["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])
            foreach (var m in metrics?[k] as JsonArray ?? [])
                if (Updates.Number(m?["cvssData"]?["baseScore"]) is double s)
                    return s;
        return null;
    }

    private static bool Truthy(JsonNode? n) => n is JsonValue v && v.GetValueKind() switch
    {
        JsonValueKind.True => true,
        JsonValueKind.String => v.GetValue<string>().Length > 0,
        JsonValueKind.Number => Updates.Number(v) is double d && d != 0,
        _ => false,
    };

    /// <summary>One NVD vulnerability entry -&gt; compact record with only the version ranges of our product.</summary>
    public static CveRecord? ParseCve(JsonNode? item, string vendor, string product)
    {
        var cve = item?["cve"];
        var matches = new List<string?[]>();
        foreach (var conf in cve?["configurations"] as JsonArray ?? [])
            foreach (var node in conf?["nodes"] as JsonArray ?? [])
                foreach (var m in node?["cpeMatch"] as JsonArray ?? [])
                {
                    if (!Truthy(m?["vulnerable"])) continue;
                    var parts = (Str(m?["criteria"]) ?? "").Split(':');
                    if (parts.Length < 6 || parts[3].ToLowerInvariant() != vendor || parts[4].ToLowerInvariant() != product) continue;
                    var ver = parts[5];
                    if (ver == "-") continue;                        // "not applicable": no version information
                    matches.Add([Str(m?["versionStartIncluding"]), Str(m?["versionStartExcluding"]),
                                 Str(m?["versionEndIncluding"]), Str(m?["versionEndExcluding"]), ver == "*" ? null : ver]);
                }
        if (matches.Count == 0) return null;
        var desc = (cve?["descriptions"] as JsonArray ?? []).FirstOrDefault(d => Str(d?["lang"]) == "en") is { } d0 ? Str(d0["value"]) ?? "" : "";
        if (desc.Length > MaxSummary) desc = desc[..MaxSummary];
        var published = Str(cve?["published"]) ?? "";
        return new CveRecord(Str(cve?["id"]) ?? "", published.Length > 10 ? published[..10] : published,
                             Cvss(cve?["metrics"]), desc, matches);
    }

    private static long[]? Key(string? x) => string.IsNullOrEmpty(x) ? null : Software.VersionKey(x);

    private static int Cmp(long[] a, long[] b) => Software.CompareKeys(a, b);

    /// <summary>Is <paramref name="version"/> inside one stored range [start_incl, start_excl, end_incl, end_excl, exact]?</summary>
    public static bool InRange(string? version, IReadOnlyList<string?> match)
    {
        var v = Software.VersionKey(version);
        return v.Length > 0 && InRangeC(v, Compile(match));
    }

    /// <summary>Stored range -&gt; version keys once, so matching thousands of CVEs stays fast.</summary>
    public static CompiledMatch Compile(IReadOnlyList<string?> m)
    {
        string? At(int i) => i < m.Count ? m[i] : null;
        var exact = At(4);
        return new CompiledMatch(Key(At(0)), Key(At(1)), Key(At(2)), Key(At(3)), exact is null ? null : Software.VersionKey(exact), exact is not null);
    }

    public static bool InRangeC(long[] v, CompiledMatch cm)
    {
        if (cm.HasExact) return cm.Exact is not null && Cmp(cm.Exact, v) == 0 && cm.Exact.Length == v.Length;
        // an empty key (unparsable bound) is "falsy" in Python and does not limit the range
        static bool Set(long[]? k) => k is { Length: > 0 };
        return !((Set(cm.StartIncl) && Cmp(v, cm.StartIncl!) < 0) || (Set(cm.StartExcl) && Cmp(v, cm.StartExcl!) <= 0)
                 || (Set(cm.EndIncl) && Cmp(v, cm.EndIncl!) > 0) || (Set(cm.EndExcl) && Cmp(v, cm.EndExcl!) >= 0));
    }

    public static bool Affected(string? version, IEnumerable<IReadOnlyList<string?>> matches) => matches.Any(m => InRange(version, m));

    /// <summary>Human text of the range, e.g. "&lt; 131.0.6778.85" (the highest bound NVD names).</summary>
    public static string FixedIn(IEnumerable<IReadOnlyList<string?>> matches)
    {
        var ends = new List<(long[] Key, string Text)>();
        foreach (var m in matches)
        {
            if (m.Count > 3 && !string.IsNullOrEmpty(m[3])) ends.Add((Software.VersionKey(m[3]), "< " + m[3]));
            if (m.Count > 2 && !string.IsNullOrEmpty(m[2])) ends.Add((Software.VersionKey(m[2]), "<= " + m[2]));
        }
        if (ends.Count == 0) return "";
        var best = ends[0];
        foreach (var e in ends.Skip(1))
        {
            var c = Cmp(e.Key, best.Key);
            if (c > 0 || (c == 0 && string.CompareOrdinal(e.Text, best.Text) > 0)) best = e;
        }
        return best.Text;
    }

    // ---------------------------------------------------------------------- downloading
    /// <summary>Like Python's <c>urllib.parse.quote(s, safe)</c>: UTF-8, upper-case hex, unreserved characters kept.</summary>
    public static string Quote(string s, string safe = "/")
    {
        var sb = new StringBuilder(s.Length * 3);
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            var c = (char)b;
            if (b < 0x80 && (char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-' or '~' || safe.Contains(c))) sb.Append(c);
            else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>All NVD CVEs of one product (paged). <paramref name="pause"/> keeps within NVD's rate limit (6 s
    /// without an API key, ~1 s with one); a throttled / failed page is retried.</summary>
    public static List<CveRecord> FetchProduct(string vendor, string product, Func<string, JsonNode?> get, double pause = 6.0,
                                               Action<double>? sleep = null, int retries = 3, int pageSize = Page)
    {
        sleep ??= s => Thread.Sleep(TimeSpan.FromSeconds(s));
        var outp = new List<CveRecord>();
        long start = 0;
        long? total = null;
        var cpe = $"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*";
        while (total is null || start < total)
        {
            var url = $"{Nvd}?virtualMatchString={Quote(cpe, ":*")}&resultsPerPage={pageSize}&startIndex={start}";
            JsonNode? doc = null;
            for (var attempt = 0; attempt < retries; attempt++)
            {
                try
                {
                    doc = get(url);
                    break;
                }
                catch (Exception exc) when (attempt < retries - 1)       // HTTP 403/429/503 = throttled; try again
                {
                    if (Log.Logger.IsEnabled(LogLevel.Information)) Log.Logger.LogInformation("NVD request failed ({Error}); waiting before retry", exc.Message);
                    sleep(pause * (attempt + 2));
                }
            }
            total = Updates.Number(doc?["totalResults"]) is double t ? (long)t : 0;
            foreach (var item in doc?["vulnerabilities"] as JsonArray ?? [])
                if (ParseCve(item, vendor, product) is { } rec) outp.Add(rec);
            start += pageSize;
            if (start < total) sleep(pause);
        }
        return outp;
    }

    /// <summary>CISA's Known Exploited Vulnerabilities as a set of CVE ids.</summary>
    public static HashSet<string> FetchKev(Func<string, JsonNode?> get) =>
        [.. (get(KevUrl)?["vulnerabilities"] as JsonArray ?? []).Select(v => Str(v?["cveID"])).OfType<string>().Where(s => s.Length > 0)];
}
