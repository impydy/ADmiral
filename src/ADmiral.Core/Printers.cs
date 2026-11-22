using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

[SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python PrinterError")]
public sealed class PrinterError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>One toner of a reading: raw level, max capacity and percentage (null = unknown).</summary>
public sealed record TonerValue(
    [property: JsonPropertyName("oid")] string Oid,
    [property: JsonPropertyName("level")] long? Level,
    [property: JsonPropertyName("max")] long? Max,
    [property: JsonPropertyName("pct")] int? Pct);

/// <summary>One daily reading of a printer (input of <see cref="Printers.Forecast"/>).</summary>
public sealed record PrinterDay(
    [property: JsonPropertyName("day")] string Day,
    [property: JsonPropertyName("pages")] long? Pages,
    [property: JsonPropertyName("toner")] IReadOnlyList<double?> Toner);

public sealed record TonerForecast(
    [property: JsonPropertyName("index")] int Index,
    [property: JsonPropertyName("points")] int Points,
    [property: JsonPropertyName("per_day")] double? PerDay,
    [property: JsonPropertyName("days_left")] long? DaysLeft,
    [property: JsonPropertyName("empty_on")] string? EmptyOn,
    [property: JsonPropertyName("last")] double? Last);

public sealed record PrinterForecast(
    [property: JsonPropertyName("toner")] IReadOnlyList<TonerForecast> Toner,
    [property: JsonPropertyName("pages_per_day")] double? PagesPerDay);

/// <summary>Network printers: what to ask (OIDs per parameter), how to read the answer, a poll of one printer,
/// a network scan and the toner forecast.
/// <para>Every printer has its own OID for each parameter, so models that deviate from the standard Printer MIB
/// (RFC 3805) can be set up by hand. Several toners are entered as a comma-separated list of OIDs.</para>
/// <para>A printer is a loose dictionary (<c>ip</c>, <c>community</c>, <c>version</c>, <c>oid_*</c>, ...), as stored
/// and as the UI sends it; readings come back as dictionaries with the field names the UI expects.</para></summary>
public static partial class Printers
{
    public static readonly IReadOnlyList<(string Field, string Oid)> DefaultOidList =
    [
        ("oid_model", "1.3.6.1.2.1.25.3.2.1.3.1"),                  // hrDeviceDescr
        ("oid_toner", "1.3.6.1.2.1.43.11.1.1.9.1.1"),               // prtMarkerSuppliesLevel
        ("oid_toner_max", "1.3.6.1.2.1.43.11.1.1.8.1.1"),           // prtMarkerSuppliesMaxCapacity
        ("oid_pages", "1.3.6.1.2.1.43.10.2.1.4.1.1"),               // prtMarkerLifeCount
        ("oid_serial", "1.3.6.1.2.1.43.5.1.1.17.1"),                // prtGeneralSerialNumber
        ("oid_status", "1.3.6.1.2.1.25.3.5.1.1.1"),                 // hrPrinterStatus
    ];

    public static readonly IReadOnlyDictionary<string, string> DefaultOids = DefaultOidList.ToDictionary(x => x.Field, x => x.Oid);

    /// <summary>A colour printer: black, cyan, magenta, yellow (the order of the supply table differs per model).</summary>
    public static readonly IReadOnlyDictionary<string, string> ColorPreset = new Dictionary<string, string>
    {
        ["oid_toner"] = string.Join(",", new[] { 1, 2, 3, 4 }.Select(i => $"1.3.6.1.2.1.43.11.1.1.9.1.{i}")),
        ["oid_toner_max"] = string.Join(",", new[] { 1, 2, 3, 4 }.Select(i => $"1.3.6.1.2.1.43.11.1.1.8.1.{i}")),
    };

    public static readonly IReadOnlyList<string> OidFields = DefaultOidList.Select(x => x.Field).ToList();
    public static readonly IReadOnlySet<string> ListFields = new HashSet<string> { "oid_toner", "oid_toner_max" };
    public static readonly IReadOnlyDictionary<long, string> Status = new Dictionary<long, string>
    {
        [1] = "other", [2] = "unknown", [3] = "idle", [4] = "printing", [5] = "warmup",
    };

    /// <summary>At most this many OIDs per list field (a colour printer has 4-6 toners).</summary>
    public const int MaxOidsPerField = 16;

    [GeneratedRegex(@"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")]
    private static partial Regex HostRe();

    [GeneratedRegex(@"[,\s;]+")]
    private static partial Regex OidSplit();

    [GeneratedRegex(@"[,;\s]+")]
    private static partial Regex RangeSplit();

    /// <summary>An IP address (normalised) or a DNS host name; <see cref="PrinterError"/> otherwise.</summary>
    public static string ValidHost(string? host)
    {
        var h = (host ?? "").Trim();
        if (Ipv4.TryParse(h, out var v4)) return Ipv4.Format(v4);
        if (h.Contains(':') && IPAddress.TryParse(h, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6) return ip.ToString();
        if (!HostRe().IsMatch(h)) throw new PrinterError($"Not a valid IP address or host name: '{host}'");
        return h;
    }

    /// <summary>Normalise one OID field ("" = not queried); the toner fields take a comma/space separated list.</summary>
    public static string CleanOids(string field, string? value)
    {
        var parts = OidSplit().Split(value ?? "").Where(p => p.Length > 0).ToList();
        if (!ListFields.Contains(field) && parts.Count > 1) throw new PrinterError($"{field}: only one OID is allowed");
        if (parts.Count > MaxOidsPerField) throw new PrinterError($"{field}: at most {MaxOidsPerField} OIDs are allowed");
        try { return string.Join(",", parts.Select(Snmp.ValidOid)); }
        catch (SnmpError exc) { throw new PrinterError(exc.Message, exc); }
    }

    public static Dictionary<string, object?> Clean(JsonObject data, IReadOnlyDictionary<string, object?>? current = null)
        => Clean((IReadOnlyDictionary<string, object?>)LooseValue.Normalize(data)!, current);

    /// <summary>Validated printer fields from the UI (only the keys present are returned; with no
    /// <paramref name="current"/> printer, a new one: every field, with defaults).</summary>
    public static Dictionary<string, object?> Clean(IReadOnlyDictionary<string, object?> data, IReadOnlyDictionary<string, object?>? current = null)
    {
        string Text(string k) => data.TryGetValue(k, out var v) && LooseValue.Truthy(v) ? LooseValue.ToText(v) : "";
        var outp = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (data.ContainsKey("ip") || current is null) outp["ip"] = ValidHost(Text("ip"));
        foreach (var k in (string[])["model", "location", "note"])
            if (data.ContainsKey(k)) outp[k] = LooseValue.Cut(Text(k).Trim(), k == "note" ? 4000 : 200);
        if (data.ContainsKey("community") || current is null)
        {
            var c = data.TryGetValue("community", out var cv) && LooseValue.Normalize(cv) is { } cn ? LooseValue.ToText(cn) : "public";
            c = LooseValue.Cut(c.Trim(), 100);
            outp["community"] = c.Length > 0 ? c : "public";
        }
        if (data.ContainsKey("version") || current is null)
        {
            var v = Text("version");
            if (v == "") v = "2c";
            if (v is not ("1" or "2c")) throw new PrinterError("SNMP version must be 1 or 2c.");
            outp["version"] = v;
        }
        foreach (var f in OidFields)
        {
            if (data.ContainsKey(f)) outp[f] = CleanOids(f, Text(f));
            else if (current is null) outp[f] = DefaultOids[f];
        }
        return outp;
    }

    // ---------------------------------------------------------------------- reading the answers
    private static long? Num(object? v) => v switch
    {
        long l => l,
        int i => i,
        _ => null,
    };

    private static string Str(IReadOnlyDictionary<string, object?> d, string k) =>
        d.TryGetValue(k, out var v) && v is not null ? LooseValue.ToText(v) : "";

    private static List<string> Oids(IReadOnlyDictionary<string, object?> printer, string field) =>
        Str(printer, field).Split(',').Where(o => o.Length > 0).ToList();

    /// <summary>One entry per toner OID. Printer MIB: level -1 'other', -2 'unknown', -3 'some toner left'.
    /// Without a max the level is taken as percent.</summary>
    public static List<TonerValue> TonerValues(IReadOnlyDictionary<string, object?> printer, IReadOnlyDictionary<string, object?> values)
    {
        long? Val(string oid) => values.TryGetValue(oid, out var v) ? Num(v) : null;
        var levels = Oids(printer, "oid_toner");
        var maxes = Oids(printer, "oid_toner_max");
        var outp = new List<TonerValue>();
        for (var i = 0; i < levels.Count; i++)
        {
            var lvl = Val(levels[i]);
            var mx = i < maxes.Count ? Val(maxes[i]) : maxes.Count == 1 ? Val(maxes[0]) : null;
            int? pct = null;
            if (lvl is >= 0)
            {
                if (mx is > 0) pct = (int)Math.Clamp(Math.Round(lvl.Value * 100.0 / mx.Value), 0, 100);
                else if (maxes.Count == 0) pct = (int)Math.Clamp(lvl.Value, 0, 100);
            }
            outp.Add(new TonerValue(levels[i], lvl, mx, pct));
        }
        return outp;
    }

    /// <summary>Ask the printer for everything its OIDs name -> the state fields to store (never throws for network
    /// problems: then only <c>error</c> is set).</summary>
    public static Dictionary<string, object?> Read(IReadOnlyDictionary<string, object?> printer, double timeout = 2.0, int retries = 1, int port = 161)
    {
        var oids = OidFields.SelectMany(f => Oids(printer, f)).ToList();
        var state = new Dictionary<string, object?>(StringComparer.Ordinal) { ["error"] = "" };
        if (oids.Count == 0)
        {
            state["toner"] = new List<TonerValue>();
            state["pages"] = null;
            return state;
        }
        IReadOnlyDictionary<string, object?> vals;
        try
        {
            var community = Str(printer, "community");
            var version = Str(printer, "version");
            vals = Snmp.Get(Str(printer, "ip"), oids.Distinct(), community.Length > 0 ? community : "public",
                version.Length > 0 ? version : "2c", port, timeout, retries);
        }
        catch (SnmpError exc)
        {
            return new Dictionary<string, object?>(StringComparer.Ordinal) { ["error"] = exc.Message };
        }
        object? Get(string oid) => vals.GetValueOrDefault(oid);
        state["toner"] = TonerValues(printer, vals);
        if (Str(printer, "oid_pages") is { Length: > 0 } po) state["pages"] = Num(Get(po));
        if (Str(printer, "oid_model") is { Length: > 0 } mo && LooseValue.Truthy(Get(mo)))
            state["model"] = LooseValue.Cut(LooseValue.ToText(Get(mo)).Trim(), 200);
        if (Str(printer, "oid_serial") is { Length: > 0 } so && LooseValue.Truthy(Get(so)))
            state["serial"] = LooseValue.Cut(LooseValue.ToText(Get(so)).Trim(), 100);
        if (Str(printer, "oid_status") is { Length: > 0 } sto)
            state["status"] = Num(Get(sto)) is { } s ? Status.GetValueOrDefault(s, "") : "";
        var missing = oids.Where(o => Get(o) is null).ToList();
        if (missing.Count > 0 && missing.Count == oids.Distinct().Count())
            state["error"] = "The printer answered, but has none of the OIDs.";
        else if (missing.Count > 0)
            state["error"] = "No value for: " + string.Join(", ", missing.Distinct());
        return state;
    }

    // ---------------------------------------------------------------------- network scan
    public const int ScanMax = 1024;

    public static readonly IReadOnlyDictionary<string, string> ScanOids = new Dictionary<string, string>
    {
        ["sys_descr"] = "1.3.6.1.2.1.1.1.0",                       // sysDescr: every SNMP agent has it
        ["sys_name"] = "1.3.6.1.2.1.1.5.0",                        // sysName
        ["sys_location"] = "1.3.6.1.2.1.1.6.0",                    // sysLocation
        ["model"] = DefaultOids["oid_model"],
        ["serial"] = DefaultOids["oid_serial"],
        ["pages"] = DefaultOids["oid_pages"],
        ["status"] = DefaultOids["oid_status"],
        ["colorant2"] = "1.3.6.1.2.1.43.12.1.1.4.1.2",             // prtMarkerColorantValue of the 2nd colorant (colour printer)
    };

    private static string TooMany => $"Too many addresses: at most {ScanMax} can be scanned at once.";

    /// <summary>IPv4 addresses from '192.168.1.0/24', '192.168.1.10-192.168.1.50', '192.168.1.10-50' or single
    /// addresses, several separated by commas or spaces. At most <see cref="ScanMax"/> addresses, in order, without repeats.</summary>
    public static List<string> ParseRange(string? text)
    {
        var outp = new List<string>();
        var seen = new HashSet<uint>();
        var parts = RangeSplit().Split((text ?? "").Trim()).Where(p => p.Length > 0).ToList();
        if (parts.Count == 0) throw new PrinterError("Enter an IP range, e.g. 192.168.1.0/24 or 192.168.1.10-192.168.1.50.");

        void Add(uint ip)
        {
            if (!seen.Add(ip)) return;
            outp.Add(Ipv4.Format(ip));
            if (outp.Count > ScanMax) throw new PrinterError(TooMany);
        }
        PrinterError Bad(string part) => new($"Not a valid IPv4 address or range: {part}");

        foreach (var part in parts)
        {
            if (part.Contains('/'))
            {
                var bits = part.Split('/', 2);
                if (!Ipv4.TryParse(bits[0], out var addr)) throw Bad(part);
                int prefix;
                if (Ipv4.TryParse(bits[1], out var mask))
                {
                    prefix = System.Numerics.BitOperations.PopCount(mask);
                    if (mask != (prefix == 0 ? 0u : uint.MaxValue << (32 - prefix))) throw Bad(part);   // not contiguous
                }
                else if (!int.TryParse(bits[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > 32
                         || bits[1].Length is 0 or > 2)
                {
                    throw Bad(part);
                }
                var size = 1L << (32 - prefix);
                if (size > ScanMax + 2) throw new PrinterError(TooMany);
                var netMask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                var net = addr & netMask;
                if (prefix < 31)
                    for (var i = 1L; i < size - 1; i++) Add((uint)(net + i));
                else
                    for (var i = 0L; i < size; i++) Add((uint)(net + i));
            }
            else if (part.Contains('-'))
            {
                var ab = part.Split('-', 2);
                if (!Ipv4.TryParse(ab[0], out var start)) throw Bad(part);
                uint end;
                if (Regex.IsMatch(ab[1], "^[0-9]{1,3}$"))
                {
                    var prefix3 = string.Join('.', ab[0].Split('.').Take(3));
                    if (!Ipv4.TryParse(prefix3 + "." + ab[1], out end)) throw Bad(part);
                }
                else if (!Ipv4.TryParse(ab[1], out end))
                {
                    throw Bad(part);
                }
                if (end < start) throw new PrinterError($"The range ends before it starts: {part}");
                if ((long)end - start >= ScanMax) throw new PrinterError(TooMany);
                for (var ip = (long)start; ip <= end; ip++) Add((uint)ip);
            }
            else
            {
                if (!Ipv4.TryParse(part, out var one)) throw Bad(part);
                Add(one);
            }
        }
        return outp;
    }

    /// <summary>Ask one address whether it is an SNMP device (and a printer) -> null when it does not answer.
    /// First only sysDescr (a quick answer or a quick timeout), then the details from the devices that answered.</summary>
    public static Dictionary<string, object?>? Probe(string ip, string community = "public", string version = "2c", int port = 161, double timeout = 1.0)
    {
        IReadOnlyDictionary<string, object?> first;
        try { first = Snmp.Get(ip, [ScanOids["sys_descr"]], community, version, port, timeout, 0); }
        catch (SnmpError) { return null; }
        IReadOnlyDictionary<string, object?> vals;
        try { vals = Snmp.Get(ip, ScanOids.Values, community, version, port, timeout * 2, 1); }
        catch (SnmpError) { vals = first; }

        string Txt(string k, int n = 200) =>
            vals.GetValueOrDefault(ScanOids[k]) is string s ? LooseValue.Cut(s.Trim(), n) : "";
        var pages = Num(vals.GetValueOrDefault(ScanOids["pages"]));
        var status = Num(vals.GetValueOrDefault(ScanOids["status"]));
        var model = Txt("model");
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ip"] = ip,
            ["name"] = Txt("sys_name"),
            ["model"] = model.Length > 0 ? model : Txt("sys_descr"),
            ["location"] = Txt("sys_location"),
            ["serial"] = Txt("serial", 100),
            ["pages"] = pages,
            ["status"] = status is { } st ? Status.GetValueOrDefault(st, "") : "",
            ["printer"] = Txt("serial").Length > 0 || pages is not null || status is not null,
            ["color"] = Txt("colorant2").Length > 0,
        };
    }

    // ---------------------------------------------------------------------- history forecast
    private static int Ordinal(string day) => DateOnly.ParseExact(day, "yyyy-MM-dd", CultureInfo.InvariantCulture).DayNumber;

    /// <summary>From the daily readings: per toner the use per day and when it runs out, and the pages printed per day.
    /// A least-squares line through the last readings; after a toner change (the level jumps up by 15 points or more)
    /// only the readings since the change count. Needs at least 2 readings on 2 different days that really fall.</summary>
    public static PrinterForecast Forecast(IReadOnlyList<PrinterDay> history, int window = 90)
    {
        var hist = history.Skip(Math.Max(0, history.Count - window)).ToList();
        var toners = new List<TonerForecast>();
        var nToner = hist.Count == 0 ? 0 : hist.Max(h => h.Toner?.Count ?? 0);
        for (var i = 0; i < nToner; i++)
        {
            var pts = hist.Where(h => h.Toner is not null && i < h.Toner.Count && h.Toner[i] is not null)
                .Select(h => (X: (double)Ordinal(h.Day), Y: h.Toner[i]!.Value)).ToList();
            for (var j = pts.Count - 1; j > 0; j--)                          // cut at the last refill
            {
                if (pts[j].Y - pts[j - 1].Y >= 15)
                {
                    pts = pts.Skip(j).ToList();
                    break;
                }
            }
            double? perDay = null;
            long? daysLeft = null;
            string? emptyOn = null;
            if (pts.Count >= 2 && pts[^1].X > pts[0].X)
            {
                double mx = pts.Average(p => p.X), my = pts.Average(p => p.Y);
                var variance = pts.Sum(p => (p.X - mx) * (p.X - mx));
                var slope = variance != 0 ? pts.Sum(p => (p.X - mx) * (p.Y - my)) / variance : 0.0;
                if (slope < 0)
                {
                    perDay = Math.Round(-slope, 3);
                    var now = my + slope * (pts[^1].X - mx);                // the fitted line's value on the last day
                    var left = Math.Max(0.0, now) / -slope;
                    daysLeft = (long)Math.Min(Math.Round(left), int.MaxValue);
                    var target = pts[^1].X + Math.Round(left);
                    if (target <= DateOnly.MaxValue.DayNumber)           // a nearly flat line: no date in reach
                        emptyOn = DateOnly.FromDayNumber((int)target).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                }
            }
            toners.Add(new TonerForecast(i, pts.Count, perDay, daysLeft, emptyOn, pts.Count > 0 ? pts[^1].Y : null));
        }
        var pp = hist.Where(h => h.Pages is not null).Select(h => (X: Ordinal(h.Day), Y: h.Pages!.Value)).ToList();
        double? ppd = null;
        if (pp.Count >= 2 && pp[^1].X > pp[0].X && pp[^1].Y >= pp[0].Y)
            ppd = Math.Round((double)(pp[^1].Y - pp[0].Y) / (pp[^1].X - pp[0].X), 1);
        return new PrinterForecast(toners, ppd);
    }
}
