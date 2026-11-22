using System.Collections;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>A rule set is invalid (the message is translated, ready for the UI).</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python RuleError")]
public sealed class RuleError(string message) : Exception(message);

/// <summary>One validated condition. <see cref="Value"/> is a <c>string</c>, <c>double</c>, <c>bool</c> or null
/// (null only for the operators that take no value).</summary>
public sealed record RuleCondition(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("op")] string Op,
    [property: JsonPropertyName("value")] object? Value);

/// <summary>A validated rule set: <c>{"match": "all"|"any", "conditions": [...]}</c>.</summary>
public sealed record RuleSet(
    [property: JsonPropertyName("match")] string Match,
    [property: JsonPropertyName("conditions")] IReadOnlyList<RuleCondition> Conditions)
{
    public string ToJson() => JsonSerializer.Serialize(this);
}

public sealed record RuleField(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("label")] string Label);

public sealed record RuleSchema(
    [property: JsonPropertyName("fields")] IReadOnlyList<RuleField> Fields,
    [property: JsonPropertyName("ops")] IReadOnlyDictionary<string, IReadOnlyList<string>> Ops,
    [property: JsonPropertyName("no_value_ops")] IReadOnlyList<string> NoValueOps);

/// <summary>Rule engine for dynamic fleets.
/// <code>{"match": "all", "conditions": [{"field": "ou", "op": "contains", "value": "Workstations"},
///   {"field": "os", "op": "glob", "value": "Windows 11*"}, {"field": "online", "op": "is", "value": true}]}</code>
/// A computer is a loose dictionary (as the UI sees it): <c>name</c>, <c>ou</c>, <c>tags</c>, <c>apps</c>,
/// <c>member_of</c>, <c>open_ports</c>, <c>uptime_s</c>, <c>inventory</c> {...}, ...</summary>
public static class Rules
{
    public const string Str = "string", Bool = "bool", Num = "number", List = "list";

    /// <summary>Upper bound for one regular-expression condition (ReDoS protection).</summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    public const int MaxConditions = 200;
    public const int MaxValueLength = 1000;

    public static readonly IReadOnlyList<(string Field, string Type, string Label)> FieldList =
    [
        ("name", Str, "Name"),
        ("dns_hostname", Str, "DNS hostname"),
        ("ou", Str, "OU path"),
        ("dn", Str, "Distinguished name"),
        ("os", Str, "Operating system"),
        ("os_version", Str, "OS version"),
        ("description", Str, "Description"),
        ("ip", Str, "IP address"),
        ("tag", List, "Tag"),
        ("enabled", Bool, "Enabled in AD"),
        ("online", Bool, "Online"),
        ("stale", Bool, "Stale"),
        ("winrm", Bool, "WinRM reachable"),
        ("last_logon_days", Num, "Days since last logon"),
        ("location", Str, "AD location"),
        ("ad_group", List, "AD group"),
        ("allow_scan", Bool, "Scanning allowed"),
        ("scan_status", Str, "Scan status (ok/failed/partial/offline)"),
        ("app", List, "Installed application"),
        ("manufacturer", Str, "Manufacturer"),
        ("model", Str, "Model"),
        ("serial", Str, "Serial number"),
        ("chassis", Str, "Chassis"),
        ("bios_version", Str, "BIOS version"),
        ("os_display_version", Str, "OS release (e.g. 23H2)"),
        ("logged_on_user", Str, "Current user"),
        ("powershell_version", Str, "PowerShell version"),
        ("smb1_server", Bool, "SMBv1 server enabled"),
        ("smb1_client", Bool, "SMBv1 client enabled"),
        ("memory_gb", Num, "Memory (GB)"),
        ("c_free_gb", Num, "C: free (GB)"),
        ("uptime_days", Num, "Uptime (days)"),
        ("pending_reboot", Bool, "Pending reboot"),
    ];

    public static readonly IReadOnlyDictionary<string, string> Fields =
        FieldList.ToDictionary(f => f.Field, f => f.Type, StringComparer.Ordinal);

    public static readonly IReadOnlySet<string> InventoryFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "manufacturer", "model", "os_display_version", "memory_gb", "c_free_gb", "pending_reboot", "serial", "chassis",
        "bios_version", "logged_on_user", "powershell_version", "smb1_server", "smb1_client",
    };

    public static readonly IReadOnlySet<string> NoValueOps = new HashSet<string>(StringComparer.Ordinal) { "empty", "not_empty" };

    private delegate bool Op(object? actual, object? expected);

    // ordered: the UI lists the operators in this order
    private static readonly (string Type, (string Name, Op Fn)[] Ops)[] OpTable =
    [
        (Str, [
            ("equals", (a, e) => S(a) == S(e)),
            ("not_equals", (a, e) => S(a) != S(e)),
            ("contains", (a, e) => S(a).Contains(S(e), StringComparison.Ordinal)),
            ("not_contains", (a, e) => !S(a).Contains(S(e), StringComparison.Ordinal)),
            ("startswith", (a, e) => S(a).StartsWith(S(e), StringComparison.Ordinal)),
            ("endswith", (a, e) => S(a).EndsWith(S(e), StringComparison.Ordinal)),
            ("glob", (a, e) => Glob.FnMatchCase(S(a), S(e))),
            ("regex", RegexOp),
            ("empty", (a, _) => S(a) == ""),
            ("not_empty", (a, _) => S(a) != ""),
        ]),
        (List, [
            ("has", (a, e) => Items(a).Any(x => S(x) == S(e))),
            ("not_has", (a, e) => !Items(a).Any(x => S(x) == S(e))),
            ("any_contains", (a, e) => Items(a).Any(x => S(x).Contains(S(e), StringComparison.Ordinal))),
            ("none_contains", (a, e) => !Items(a).Any(x => S(x).Contains(S(e), StringComparison.Ordinal))),
            ("empty", (a, _) => !LooseValue.Truthy(a)),
            ("not_empty", (a, _) => LooseValue.Truthy(a)),
        ]),
        (Bool, [
            ("is", (a, e) => LooseValue.Truthy(a) == TruthyText(e)),
        ]),
        (Num, [
            ("lt", (a, e) => LooseValue.ToNumber(a) is { } x && x < LooseValue.ToNumber(e)),
            ("lte", (a, e) => LooseValue.ToNumber(a) is { } x && x <= LooseValue.ToNumber(e)),
            ("gt", (a, e) => LooseValue.ToNumber(a) is { } x && x > LooseValue.ToNumber(e)),
            ("gte", (a, e) => LooseValue.ToNumber(a) is { } x && x >= LooseValue.ToNumber(e)),
            ("eq", (a, e) => LooseValue.ToNumber(a) is { } x && x == LooseValue.ToNumber(e)),
            ("empty", (a, _) => LooseValue.ToNumber(a) is null),
        ]),
    ];

    private static readonly Dictionary<string, Dictionary<string, Op>> Ops =
        OpTable.ToDictionary(t => t.Type, t => t.Ops.ToDictionary(o => o.Name, o => o.Fn, StringComparer.Ordinal), StringComparer.Ordinal);

    private static string S(object? v) => v is null ? "" : LooseValue.ToText(v).ToLowerInvariant();

    private static IEnumerable<object?> Items(object? v) => LooseValue.AsList(v) ?? [];

    private static bool RegexOp(object? actual, object? expected)
    {
        try
        {
            return Regex.IsMatch(actual is null ? "" : LooseValue.ToText(actual), LooseValue.ToText(expected),
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
        }
        catch (ArgumentException) { return false; }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>Python's <c>_truthy</c>: "1"/"true"/"yes"/"on" for text, the usual truthiness otherwise.</summary>
    private static bool TruthyText(object? v)
    {
        v = LooseValue.Normalize(v);
        if (v is string s) return s.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
        return LooseValue.Truthy(v);
    }

    /// <summary>Validate a rule set from the UI (a JSON object, <see cref="JsonNode"/>, <see cref="JsonElement"/>,
    /// dictionary, or an earlier <see cref="RuleSet"/>) and return its clean form.</summary>
    public static RuleSet Validate(object? rules)
    {
        if (rules is RuleSet rs) rules = JsonSerializer.SerializeToElement(rs);
        if (LooseValue.Normalize(rules) is not IReadOnlyDictionary<string, object?> d) throw new RuleError(I18n.T("rule.object"));
        var match = d.TryGetValue("match", out var m) ? LooseValue.Normalize(m) : "all";
        if (match is not ("all" or "any")) throw new RuleError(I18n.T("rule.match"));
        var conds = d.TryGetValue("conditions", out var c) ? LooseValue.Normalize(c) as IReadOnlyList<object?> : null;
        if (conds is null || conds.Count == 0) throw new RuleError(I18n.T("rule.empty"));
        if (conds.Count > MaxConditions) throw new RuleError($"at most {MaxConditions} conditions are allowed");
        var clean = new List<RuleCondition>(conds.Count);
        for (var idx = 0; idx < conds.Count; idx++)
        {
            var i = idx + 1;
            if (LooseValue.Normalize(conds[idx]) is not IReadOnlyDictionary<string, object?> cd)
                throw new RuleError(I18n.T("rule.cond_object", ("i", i)));
            var field = cd.TryGetValue("field", out var f) ? LooseValue.Normalize(f) as string : null;
            var op = cd.TryGetValue("op", out var o) ? LooseValue.Normalize(o) as string : null;
            var value = cd.TryGetValue("value", out var v) ? LooseValue.Normalize(v) : null;
            if (field is null || !Fields.TryGetValue(field, out var ftype))
                throw new RuleError(I18n.T("rule.field", ("i", i), ("field", field ?? LooseValue.ToText(cd.GetValueOrDefault("field")))));
            if (op is null || !Ops[ftype].ContainsKey(op))
                throw new RuleError(I18n.T("rule.op", ("i", i), ("op", op ?? "None"), ("field", field)));
            if (!NoValueOps.Contains(op))
            {
                if (value is null || (value is string sv && sv.Trim() == "")) throw new RuleError(I18n.T("rule.value", ("i", i)));
                if (value is IReadOnlyList<object?> or IReadOnlyDictionary<string, object?>) throw new RuleError(I18n.T("rule.value", ("i", i)));
                if (ftype == Num)
                {
                    if (LooseValue.ToNumber(value) is not { } num) throw new RuleError(I18n.T("rule.number", ("i", i)));
                    value = num;
                }
                else if (ftype == Bool)
                {
                    value = TruthyText(value);
                }
                else
                {
                    var text = LooseValue.ToText(value);
                    if (text.Length > MaxValueLength) throw new RuleError(I18n.T("rule.value", ("i", i)));
                    if (op == "regex")
                    {
                        try { _ = new Regex(text, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout); }
                        catch (ArgumentException exc) { throw new RuleError(I18n.T("rule.regex", ("i", i), ("err", exc.Message))); }
                    }
                    value = value is string ? value : text;
                }
            }
            clean.Add(new RuleCondition(field, op, value));
        }
        return new RuleSet((string)match, clean);
    }

    /// <summary>Parse and validate a stored rule set (JSON text).</summary>
    public static RuleSet Parse(string json)
    {
        try { return Validate(JsonNode.Parse(json)); }
        catch (JsonException) { throw new RuleError(I18n.T("rule.object")); }
    }

    /// <summary>The value of a rule field for a computer (some are derived: tags, groups, WinRM, inventory...).</summary>
    public static object? FieldValue(IReadOnlyDictionary<string, object?> computer, string field)
    {
        object? Get(string k) => computer.TryGetValue(k, out var v) ? LooseValue.Normalize(v) : null;
        switch (field)
        {
            case "tag": return Get("tags") ?? new List<object?>();
            case "app": return Get("apps") ?? new List<object?>();
            case "ad_group":
                return (LooseValue.AsList(Get("member_of")) ?? [])
                    .Select(g =>
                    {
                        var first = LooseValue.ToText(g).Split(',')[0];
                        var eq = first.IndexOf('=');
                        return (object?)(eq >= 0 ? first[(eq + 1)..] : first);
                    }).ToList();
            case "uptime_days":
                return LooseValue.ToNumber(Get("uptime_s")) is { } up ? up / 86400 : null;
            case "winrm":
                return (LooseValue.AsList(Get("open_ports")) ?? []).Any(p => LooseValue.ToNumber(p) is 5985 or 5986);
        }
        if (InventoryFields.Contains(field))
            return Get("inventory") is IReadOnlyDictionary<string, object?> inv && inv.TryGetValue(field, out var iv)
                ? LooseValue.Normalize(iv) : null;
        return Get(field);
    }

    /// <summary>Whether <paramref name="computer"/> satisfies the (validated) rule set.</summary>
    public static bool Matches(IReadOnlyDictionary<string, object?> computer, RuleSet rules)
    {
        bool Eval(RuleCondition c)
        {
            if (!Fields.TryGetValue(c.Field, out var t) || !Ops[t].TryGetValue(c.Op, out var fn)) return false;
            return fn(FieldValue(computer, c.Field), LooseValue.Normalize(c.Value));
        }
        return rules.Match == "any" ? rules.Conditions.Any(Eval) : rules.Conditions.All(Eval);
    }

    public static RuleSchema Schema() => new(
        FieldList.Select(f => new RuleField(f.Field, f.Type, f.Label)).ToList(),
        OpTable.ToDictionary(t => t.Type, t => (IReadOnlyList<string>)t.Ops.Select(o => o.Name).ToList()),
        NoValueOps.Order(StringComparer.Ordinal).ToList());
}

/// <summary><c>fnmatch.fnmatchcase</c>: <c>*</c>, <c>?</c>, <c>[seq]</c>, <c>[!seq]</c> (without brackets: PAC's
/// <c>shExpMatch</c>); matched without regular expressions
/// (iterative, O(n·m), so no pattern can make it backtrack exponentially).</summary>
internal static class Glob
{
    /// <param name="onWork">called once per comparison step (lets a caller meter and abort the O(n·m) worst case).</param>
    public static bool FnMatchCase(string s, string pattern, bool brackets = true, Action? onWork = null)
    {
        int si = 0, pi = 0, starP = -1, starS = 0;
        while (si < s.Length)
        {
            onWork?.Invoke();
            if (pi < pattern.Length && pattern[pi] == '*')
            {
                starP = pi++;
                starS = si;
                continue;
            }
            if (pi < pattern.Length && MatchOne(s[si], pattern, pi, brackets, out var next))
            {
                si++;
                pi = next;
                continue;
            }
            if (starP < 0) return false;
            pi = starP + 1;
            si = ++starS;
        }
        while (pi < pattern.Length && pattern[pi] == '*') pi++;
        return pi == pattern.Length;
    }

    /// <summary>Does <paramref name="c"/> match the pattern element at <paramref name="pi"/>?</summary>
    private static bool MatchOne(char c, string p, int pi, bool brackets, out int next)
    {
        next = pi + 1;
        if (p[pi] == '?') return true;
        if (brackets && p[pi] == '[')
        {
            var j = pi + 1;
            if (j < p.Length && p[j] == '!') j++;
            if (j < p.Length && p[j] == ']') j++;
            while (j < p.Length && p[j] != ']') j++;
            if (j >= p.Length) return c == '[';             // no closing bracket: a literal '['
            var body = p.AsSpan(pi + 1, j - pi - 1);
            next = j + 1;
            var negate = body.Length > 0 && body[0] == '!';
            if (negate) body = body[1..];
            var hit = false;
            for (var k = 0; k < body.Length; k++)
            {
                if (k + 2 < body.Length && body[k + 1] == '-')
                {
                    if (c >= body[k] && c <= body[k + 2]) hit = true;
                    k += 2;
                }
                else if (body[k] == c) hit = true;
            }
            return hit != negate;
        }
        return p[pi] == c;
    }
}

/// <summary>Python-like handling of loosely typed values (JSON from the UI, dictionaries from the store).</summary>
internal static class LooseValue
{
    /// <summary>JSON values become .NET ones: string, double, bool, null, <c>List&lt;object?&gt;</c>,
    /// <c>Dictionary&lt;string, object?&gt;</c>. Everything else is returned unchanged.</summary>
    public static object? Normalize(object? v) => v switch
    {
        null => null,
        JsonElement e => FromElement(e),
        JsonNode n => FromElement(JsonSerializer.SerializeToElement(n)),
        _ => v,
    };

    private static object? FromElement(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Array => e.EnumerateArray().Select(x => FromElement(x)).ToList(),
        JsonValueKind.Object => e.EnumerateObject().GroupBy(p => p.Name)
            .ToDictionary(g => g.Key, g => FromElement(g.Last().Value), StringComparer.Ordinal),
        _ => null,
    };

    public static bool IsNumber(object? v) => v is double or float or decimal or int or long or short or byte or sbyte or uint or ulong or ushort;

    /// <summary>Python <c>bool(v)</c> (NaN counts as true there; here too).</summary>
    public static bool Truthy(object? v)
    {
        v = Normalize(v);
        return v switch
        {
            null => false,
            bool b => b,
            string s => s.Length > 0,
            _ when IsNumber(v) => Convert.ToDouble(v, CultureInfo.InvariantCulture) != 0,
            ICollection c => c.Count > 0,
            IEnumerable en => en.GetEnumerator().MoveNext(),
            _ => true,
        };
    }

    /// <summary>Python <c>None if v is None or v == "" else float(v)</c>, with null instead of an error.</summary>
    public static double? ToNumber(object? v)
    {
        v = Normalize(v);
        switch (v)
        {
            case null: return null;
            case bool b: return b ? 1 : 0;
            case string s:
                s = s.Trim();
                if (s.Length == 0) return null;
                if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)) return d;
                return s.ToLowerInvariant() switch
                {
                    "inf" or "+inf" or "infinity" or "+infinity" => double.PositiveInfinity,
                    "-inf" or "-infinity" => double.NegativeInfinity,
                    "nan" or "+nan" or "-nan" => double.NaN,
                    _ => null,
                };
        }
        return IsNumber(v) ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;
    }

    public static string ToText(object? v)
    {
        v = Normalize(v);
        return v switch
        {
            null => "",
            string s => s,
            bool b => b ? "True" : "False",
            double d when double.IsFinite(d) && d == Math.Floor(d) && Math.Abs(d) < 1e15 => ((long)d).ToString(CultureInfo.InvariantCulture),
            double d => d.ToString("R", CultureInfo.InvariantCulture),
            float f => ((double)f).ToString("R", CultureInfo.InvariantCulture),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => v.ToString() ?? "",
        };
    }

    /// <summary>A list-like value (not a string) as items, or null.</summary>
    public static IEnumerable<object?>? AsList(object? v)
    {
        v = Normalize(v);
        if (v is null or string or IDictionary or IReadOnlyDictionary<string, object?>) return null;
        return v is IEnumerable en ? en.Cast<object?>().Select(Normalize) : null;
    }

    /// <summary>Python slicing <c>s[:n]</c>.</summary>
    public static string Cut(string s, int n) => s.Length <= n ? s : s[..n];

    internal static string Hex(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }
}
