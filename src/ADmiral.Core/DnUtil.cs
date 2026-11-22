using System.Text;

namespace ADmiral.Core;

/// <summary>Pure string helpers for LDAP distinguished names (ported from admiral/directory.py).</summary>
public static class DnUtil
{
    /// <summary>Split at the unescaped commas (a backslash escapes the next character).</summary>
    private static List<string> SplitRaw(string dn)
    {
        var parts = new List<string>();
        var buf = new StringBuilder();
        for (var i = 0; i < dn.Length; i++)
        {
            var ch = dn[i];
            if (ch == '\\' && i + 1 < dn.Length)
            {
                buf.Append(ch).Append(dn[i + 1]);
                i++;
            }
            else if (ch == ',')
            {
                parts.Add(buf.ToString());
                buf.Clear();
            }
            else
            {
                buf.Append(ch);
            }
        }
        if (buf.Length > 0) parts.Add(buf.ToString());
        return parts;
    }

    /// <summary>Lower-case, spaces around the RDNs removed: "OU=X, DC=c" -> "ou=x,dc=c".</summary>
    public static string NormDn(string? dn)
    {
        dn ??= "";
        // like Python's re.split(r"(?<!\\),", dn): only a comma preceded by a backslash is escaped
        var parts = new List<string>();
        var start = 0;
        for (var i = 0; i < dn.Length; i++)
            if (dn[i] == ',' && (i == 0 || dn[i - 1] != '\\'))
            {
                parts.Add(dn[start..i]);
                start = i + 1;
            }
        parts.Add(dn[start..]);
        return string.Join(",", parts.Select(p => p.Trim().ToLowerInvariant()));
    }

    /// <summary>True if <paramref name="dn"/> is <paramref name="baseDn"/> itself or lives anywhere below it
    /// (case/space-insensitive). An empty base contains nothing.</summary>
    public static bool IsUnder(string? dn, string? baseDn)
    {
        var d = NormDn(dn);
        var b = NormDn(baseDn);
        return b.Length > 0 && (d == b || d.EndsWith("," + b, StringComparison.Ordinal));
    }

    /// <summary>The container (OU) a DN lives in: everything after its first unescaped comma.</summary>
    public static string ParentDn(string? dn)
    {
        dn ??= "";
        var i = 0;
        while (i < dn.Length)
        {
            if (dn[i] == '\\')
            {
                i += 2;
                continue;
            }
            if (dn[i] == ',') return dn[(i + 1)..].Trim();
            i++;
        }
        return "";
    }

    /// <summary>Split a DN into (TYPE, value) RDNs, honouring backslash escapes ("\," becomes ",").</summary>
    public static List<(string Type, string Value)> SplitDn(string? dn)
    {
        var outList = new List<(string, string)>();
        foreach (var p in SplitRaw(dn ?? ""))
        {
            var s = p.Trim();
            var eq = s.IndexOf('=');
            var key = eq < 0 ? s : s[..eq];
            var val = eq < 0 ? "" : s[(eq + 1)..];
            outList.Add((key.Trim().ToUpperInvariant(), val.Trim().Replace("\\,", ",")));
        }
        return outList;
    }

    /// <summary>"CN=PC1,OU=Laptops,OU=Workstations,DC=corp,DC=local" -> "corp.local/Workstations/Laptops".</summary>
    public static string OuPath(string? dn)
    {
        var rdns = SplitDn(dn);
        var domain = string.Join(".", rdns.Where(r => r.Type == "DC").Select(r => r.Value));
        var containers = rdns.Skip(1).Where(r => r.Type is "OU" or "CN").Select(r => r.Value).Reverse().ToList();
        return domain.Length > 0 ? string.Join("/", new[] { domain }.Concat(containers)) : string.Join("/", containers);
    }
}
