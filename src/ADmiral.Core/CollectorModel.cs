using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>Pure data normalisation of collected inventory that the store needs (ported from admiral/collector.py):
/// cleaning the logon history. The collection itself (scripts, WinRM, SMB) lives elsewhere.</summary>
public static partial class CollectorModel
{
    /// <summary>Logon types kept in the history (event 4624 LogonType).</summary>
    public static readonly IReadOnlyDictionary<int, string> LogonTypes = new Dictionary<int, string>
    {
        [2] = "interactive", [7] = "unlock", [10] = "remote", [11] = "cached",
    };

    public const int MaxLogons = 300;

    private static readonly HashSet<string> SystemUsers =
        ["system", "local service", "network service", "anonymous logon", "guest", "defaultaccount", "wdagutilityaccount"];

    private static readonly HashSet<string> SystemDomains =
        ["nt authority", "nt service", "window manager", "font driver host", "iis apppool"];

    [GeneratedRegex(@"^(dwm|umfd)-\d+\z", RegexOptions.IgnoreCase)]
    private static partial Regex VirtualAccount();

    /// <summary>True for a person's account; false for machine ($), service and virtual system accounts
    /// (SYSTEM, DWM-1, UMFD-0, LOCAL SERVICE, ANONYMOUS LOGON, ...).</summary>
    public static bool RealUser(string? domain, string? user)
    {
        var u = (user ?? "").Trim();
        var d = (domain ?? "").Trim().ToLowerInvariant();
        if (u.Length == 0 || u.EndsWith('$') || SystemUsers.Contains(u.ToLowerInvariant()) || SystemDomains.Contains(d))
            return false;
        return !VirtualAccount().IsMatch(u);
    }

    /// <summary>Is <paramref name="domain"/> the account database of the computer itself (a local account)? Only known
    /// with the computer's name; without it nothing counts as local.</summary>
    public static bool IsLocalDomain(string? domain, string? computerName)
    {
        if (string.IsNullOrWhiteSpace(computerName)) return false;
        var d = (domain ?? "").Trim();
        return d == "." || string.Equals(d, computerName.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"COMPUTER\\user" / ".\\user" of that computer's own (local) account?</summary>
    public static bool IsLocalAccountName(string? account, string? computerName)
    {
        var a = (account ?? "").Trim();
        var i = a.IndexOf('\\', StringComparison.Ordinal);
        return i > 0 && IsLocalDomain(a[..i], computerName);
    }

    /// <summary>Keep real users' interactive logons, newest first, without duplicates, at most <see cref="MaxLogons"/>.
    /// Each result is <c>{time, user, domain, type, ip}</c>. With <paramref name="computerName"/>, the logons of that
    /// computer's local accounts (domain = the computer name, or ".") are dropped too.</summary>
    public static List<JsonObject> CleanLogons(IEnumerable<JsonNode?>? rows, string? computerName = null)
    {
        var seen = new HashSet<(string, string, string, int)>();
        var outList = new List<JsonObject>();
        foreach (var node in rows ?? [])
        {
            if (node is not JsonObject r) continue;
            var user = Str(r["user"]);
            var domain = Str(r["domain"]);
            if (!RealUser(domain, user) || IsLocalDomain(domain, computerName)) continue;
            if (Int(r["type"]) is not { } typ || !LogonTypes.ContainsKey(typ)) continue;
            var time = Str(r["time"]);
            if (string.IsNullOrEmpty(time)) continue;
            var ip = (Str(r["ip"]) ?? "").Trim();
            var rec = new JsonObject
            {
                ["time"] = time,
                ["user"] = user!.Trim(),
                ["domain"] = (domain ?? "").Trim(),
                ["type"] = typ,
                ["ip"] = ip is "-" or "::1" or "127.0.0.1" ? "" : ip,
            };
            var key = (time, user.Trim().ToLowerInvariant(), (domain ?? "").Trim().ToLowerInvariant(), typ);
            if (seen.Add(key)) outList.Add(rec);
        }
        // newest first (ISO timestamps sort as text); OrderByDescending is stable like Python's sort
        return [.. outList.OrderByDescending(x => (string)x["time"]!, StringComparer.Ordinal).Take(MaxLogons)];
    }

    private static string? Str(JsonNode? n) => n switch
    {
        null => null,
        JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
        JsonValue v when v.GetValueKind() is JsonValueKind.True or JsonValueKind.False => v.GetValue<bool>() ? "True" : "False",
        _ => n.ToJsonString(),
    };

    private static int? Int(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        switch (v.GetValueKind())
        {
            case JsonValueKind.Number:
                return double.TryParse(v.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d)
                       && d is >= int.MinValue and <= int.MaxValue ? (int)Math.Truncate(d) : null;
            case JsonValueKind.String:
                return int.TryParse(v.GetValue<string>().Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var p) ? p : null;
            case JsonValueKind.True:
                return 1;
            case JsonValueKind.False:
                return 0;
            default:
                return null;
        }
    }
}
