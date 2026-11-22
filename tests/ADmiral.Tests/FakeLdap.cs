using System.Net;
using System.Text;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>An in-memory directory for AdDirectory tests (no domain controller): evaluates the RFC 4515 filters
/// AdDirectory builds (and/or/not, equality, presence, the IN_CHAIN extensible match), the search scopes, the
/// requested attributes and ranged retrieval of 'member'. It only answers searches: like the real session it has
/// no write operation at all.</summary>
internal sealed class FakeDit : ILdapBinder
{
    public List<LdapEntry> Entries { get; } = [];
    public List<(LdapEndpoint Endpoint, LdapBindMethod Method, NetworkCredential? Credential)> Binds { get; } = [];
    public List<LdapQuery> Queries { get; } = [];
    public List<FakeSession> Sessions { get; } = [];
    /// <summary>Scripted bind failures: return an exception to throw for that attempt.</summary>
    public Func<LdapBindMethod, Exception?>? FailBind { get; set; }
    /// <summary>Override answers for a query (null = evaluate against <see cref="Entries"/>).</summary>
    public Func<LdapQuery, IEnumerable<LdapEntry>?>? Handler { get; set; }
    public string? WhoAmIValue { get; set; } = "u:CORP\\svc";
    /// <summary>&gt; 0: the 'member' attribute comes back in ranges of this size.</summary>
    public int RangeSize { get; set; }

    public FakeDit Add(string dn, Dictionary<string, object?> attrs)
    {
        Entries.Add(LdapEntry.Of(dn, attrs));
        return this;
    }

    public ILdapSession Bind(LdapEndpoint endpoint, LdapBindMethod method, NetworkCredential? credential)
    {
        Binds.Add((endpoint, method, credential));
        if (FailBind?.Invoke(method) is { } exc) throw exc;
        var s = new FakeSession(this);
        Sessions.Add(s);
        return s;
    }

    internal IEnumerable<LdapEntry> Answer(LdapQuery q)
    {
        Queries.Add(q);
        if (Handler?.Invoke(q) is { } custom) return custom.ToList();
        var filter = FilterNode.Parse(q.Filter);
        return Entries.Where(e => InScope(e.Dn, q) && filter.Matches(e, this)).Select(e => Project(e, q.Attributes)).ToList();
    }

    private static bool InScope(string dn, LdapQuery q) => q.Scope switch
    {
        LdapScope.Base => DnUtil.NormDn(dn) == DnUtil.NormDn(q.BaseDn),
        LdapScope.OneLevel => DnUtil.NormDn(DnUtil.ParentDn(dn)) == DnUtil.NormDn(q.BaseDn),
        _ => DnUtil.IsUnder(dn, q.BaseDn),
    };

    private LdapEntry Project(LdapEntry e, IReadOnlyList<string> attrs)
    {
        if (attrs.Count == 0) return e;
        var outAttrs = new List<KeyValuePair<string, IReadOnlyList<byte[]>>>();
        foreach (var a in attrs)
        {
            var semi = a.IndexOf(";range=", StringComparison.OrdinalIgnoreCase);
            var name = semi < 0 ? a : a[..semi];
            if (!e.Attributes.TryGetValue(name, out var values)) continue;
            if (RangeSize > 0 && name.Equals("member", StringComparison.OrdinalIgnoreCase))
            {
                var start = semi < 0 ? 0 : int.Parse(a[(semi + 7)..].Split('-')[0]);
                if (semi < 0 && values.Count <= RangeSize)
                {
                    outAttrs.Add(new(name, values));
                    continue;
                }
                var slice = values.Skip(start).Take(RangeSize).ToList();
                var last = start + slice.Count >= values.Count ? "*" : (start + slice.Count - 1).ToString();
                outAttrs.Add(new($"{name};range={start}-{last}", slice));
                continue;
            }
            outAttrs.Add(new(name, values));
        }
        return new LdapEntry(e.Dn, outAttrs);
    }

    /// <summary>Is <paramref name="dn"/> a (nested) member of the group entry <paramref name="group"/>?</summary>
    internal bool MemberInChain(LdapEntry group, string dn, int depth = 0)
    {
        if (depth > 20) return false;
        foreach (var m in group.Strings("member"))
        {
            if (DnUtil.NormDn(m) == DnUtil.NormDn(dn)) return true;
            var inner = Entries.FirstOrDefault(x => DnUtil.NormDn(x.Dn) == DnUtil.NormDn(m));
            if (inner is not null && MemberInChain(inner, dn, depth + 1)) return true;
        }
        return false;
    }
}

internal sealed class FakeSession(FakeDit dit) : ILdapSession
{
    public bool Disposed { get; private set; }

    public IEnumerable<LdapEntry> Search(LdapQuery query)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);
        return dit.Answer(query);
    }

    public string? WhoAmI() => dit.WhoAmIValue;

    public void Dispose() => Disposed = true;
}

/// <summary>A tiny RFC 4515 filter parser / evaluator (enough for the filters ADmiral sends).</summary>
internal abstract class FilterNode
{
    public abstract bool Matches(LdapEntry e, FakeDit dit);

    public static FilterNode Parse(string filter)
    {
        var i = 0;
        var node = ParseOne(filter, ref i);
        if (i != filter.Length) throw new FormatException($"trailing characters in filter: {filter}");
        return node;
    }

    private static FilterNode ParseOne(string f, ref int i)
    {
        if (i >= f.Length || f[i] != '(') throw new FormatException($"'(' expected at {i}: {f}");
        i++;
        var op = f[i];
        if (op is '&' or '|' or '!')
        {
            i++;
            var kids = new List<FilterNode>();
            while (i < f.Length && f[i] == '(') kids.Add(ParseOne(f, ref i));
            if (i >= f.Length || f[i] != ')') throw new FormatException($"')' expected at {i}: {f}");
            i++;
            return op == '&' ? new AndNode(kids) : op == '|' ? new OrNode(kids) : new NotNode(kids.Single());
        }
        var start = i;
        while (i < f.Length && f[i] != ')')
        {
            if (f[i] == '(') throw new FormatException($"unescaped '(' in a value: {f}");
            i++;
        }
        if (i >= f.Length) throw new FormatException($"unterminated item: {f}");
        var item = f[start..i];
        i++;
        var eq = item.IndexOf('=');
        var lhs = item[..eq];
        var raw = item[(eq + 1)..];
        if (lhs.EndsWith(':'))
        {
            var parts = lhs.TrimEnd(':').Split(':');
            return new ExtNode(parts[0], parts[1], Unescape(raw));
        }
        if (raw == "*") return new PresentNode(lhs);
        if (raw.Contains('*')) throw new FormatException($"unexpected unescaped '*' (substring filter) in: {f}");
        return new EqNode(lhs, Unescape(raw));
    }

    public static string Unescape(string v)
    {
        var bytes = new List<byte>();
        for (var i = 0; i < v.Length; i++)
        {
            if (v[i] == '\\')
            {
                bytes.Add(Convert.ToByte(v.Substring(i + 1, 2), 16));
                i += 2;
            }
            else bytes.AddRange(Encoding.UTF8.GetBytes(v[i].ToString()));
        }
        return Encoding.UTF8.GetString([.. bytes]);
    }

    private sealed class AndNode(List<FilterNode> kids) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit) => kids.All(k => k.Matches(e, dit));
    }

    private sealed class OrNode(List<FilterNode> kids) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit) => kids.Any(k => k.Matches(e, dit));
    }

    private sealed class NotNode(FilterNode kid) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit) => !kid.Matches(e, dit);
    }

    private sealed class PresentNode(string attr) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit) =>
            attr.Equals("objectClass", StringComparison.OrdinalIgnoreCase) || e.Raw(attr).Count > 0;
    }

    private sealed class EqNode(string attr, string value) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit)
        {
            if (attr.Equals("objectSid", StringComparison.OrdinalIgnoreCase))
                return e.Raw(attr).Any(b => AdDirectory.SidToString(b) == value);
            return e.Strings(attr).Any(s => s.Equals(value, StringComparison.OrdinalIgnoreCase));
        }
    }

    private sealed class ExtNode(string attr, string rule, string value) : FilterNode
    {
        public override bool Matches(LdapEntry e, FakeDit dit)
        {
            if (rule == AdDirectory.InChain && attr.Equals("member", StringComparison.OrdinalIgnoreCase)) return dit.MemberInChain(e, value);
            throw new NotSupportedException($"matching rule {rule}");
        }
    }
}

internal static class SidBytes
{
    /// <summary>'S-1-5-21-1-2-3-512' -> binary objectSid.</summary>
    public static byte[] Of(string sid)
    {
        var parts = sid[2..].Split('-').Select(ulong.Parse).ToArray();
        var outBytes = new List<byte> { (byte)parts[0], (byte)(parts.Length - 2) };
        for (var i = 5; i >= 0; i--) outBytes.Add((byte)(parts[1] >> (8 * i)));
        foreach (var sub in parts.Skip(2)) outBytes.AddRange(BitConverter.GetBytes((uint)sub));
        return [.. outBytes];
    }

    public static byte[] Of(params uint[] subs) => Of("S-1-5-" + string.Join("-", subs));
}
