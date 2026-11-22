using System.Text;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>RFC 4515 helpers for building LDAP search filters. Every value that goes into a filter (a name, a DN,
/// a SID, user input) must pass through <see cref="Escape(string?)"/> or one of the builders here, so that it can
/// never change the structure of the filter (LDAP injection).</summary>
public static partial class LdapFilter
{
    /// <summary>Escape an assertion value (RFC 4515 section 3): <c>\</c>, <c>*</c>, <c>(</c>, <c>)</c> and NUL become
    /// <c>\5c</c>, <c>\2a</c>, <c>\28</c>, <c>\29</c>, <c>\00</c>; other control characters are escaped too.
    /// Non-ASCII characters are kept as they are (the filter is sent as UTF-8).</summary>
    public static string Escape(string? value)
    {
        var s = value ?? "";
        var sb = new StringBuilder(s.Length + 8);
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*': sb.Append(@"\2a"); break;
                case '(': sb.Append(@"\28"); break;
                case ')': sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default:
                    if (ch < 0x20 || ch == 0x7f) sb.Append('\\').Append(((int)ch).ToString("x2"));
                    else sb.Append(ch);
                    break;
            }
        }
        return sb.ToString();
    }

    /// <summary>Escape every byte of a binary value (objectGUID, objectSid): <c>\01\05\00...</c>.</summary>
    public static string EscapeBytes(ReadOnlySpan<byte> value)
    {
        var sb = new StringBuilder(value.Length * 3);
        foreach (var b in value) sb.Append('\\').Append(b.ToString("x2"));
        return sb.ToString();
    }

    [GeneratedRegex(@"^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)$")]
    private static partial Regex AttributeName();

    /// <summary>Attribute descriptions are code, never data; reject anything that is not a plain name or OID.</summary>
    public static string Attribute(string name)
    {
        if (string.IsNullOrEmpty(name) || !AttributeName().IsMatch(name))
            throw new ArgumentException($"Not an LDAP attribute name: '{name}'", nameof(name));
        return name;
    }

    /// <summary><c>(attr=escaped value)</c></summary>
    public static string Eq(string attribute, string? value) => $"({Attribute(attribute)}={Escape(value)})";

    /// <summary><c>(attr:matchingRuleOid:=escaped value)</c>, e.g. LDAP_MATCHING_RULE_IN_CHAIN.</summary>
    public static string Extensible(string attribute, string matchingRule, string? value) =>
        $"({Attribute(attribute)}:{Attribute(matchingRule)}:={Escape(value)})";

    /// <summary><c>(&amp;f1f2...)</c> of already-built filters.</summary>
    public static string And(params IEnumerable<string> filters) => "(&" + string.Concat(filters) + ")";

    /// <summary><c>(|f1f2...)</c> of already-built filters.</summary>
    public static string Or(params IEnumerable<string> filters) => "(|" + string.Concat(filters) + ")";
}
