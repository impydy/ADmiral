using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Text.RegularExpressions;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>tests/test_readonly.py (the LDAP part): ADmiral only QUERIES Active Directory. These tests fail if write
/// code ever creeps in anywhere under src/, or if the gate lets anything but a search through.</summary>
public partial class ReadOnlyTests
{
    // ------------------------------------------------------------------ the gate
    public static TheoryData<string, Func<DirectoryRequest>> Writes => new()
    {
        { "add", () => new AddRequest("CN=x,DC=y", "computer") },
        { "modify", () => new ModifyRequest("CN=x,DC=y", DirectoryAttributeOperation.Replace, "member", "CN=a,DC=y") },
        { "modify member add", () => new ModifyRequest("CN=g,DC=y", DirectoryAttributeOperation.Add, "member", "CN=a,DC=y") },
        { "modify member delete", () => new ModifyRequest("CN=g,DC=y", DirectoryAttributeOperation.Delete, "member", "CN=a,DC=y") },
        { "password", () => new ModifyRequest("CN=a,DC=y", DirectoryAttributeOperation.Replace, "unicodePwd", new byte[] { 1 }) },
        { "delete", () => new DeleteRequest("CN=x,DC=y") },
        { "modify dn", () => new ModifyDNRequest("CN=x,DC=y", "DC=y", "CN=z") },
        { "compare", () => new CompareRequest("CN=x,DC=y", "cn", "x") },
        { "password modify", () => new ExtendedRequest("1.3.6.1.4.1.4203.1.11.1") },
        { "start tls", () => new ExtendedRequest("1.3.6.1.4.1.1466.20037") },
        { "who-am-i with a payload", () => new ExtendedRequest(ReadOnlyGuard.WhoAmIOid, [1, 2]) },
        { "dsml", () => new DsmlAuthRequest("x") },
        { "search with tree-delete control", () => WithControl(new TreeDeleteControl()) },
        { "search with permissive-modify control", () => WithControl(new PermissiveModifyControl()) },
        { "search with an unknown control", () => WithControl(new DirectoryControl("1.2.840.113556.1.4.805", null, true, true)) },
    };

    private static SearchRequest WithControl(DirectoryControl c)
    {
        var r = new SearchRequest("DC=y", "(objectClass=*)", SearchScope.Base);
        r.Controls.Add(c);
        return r;
    }

    [Theory]
    [MemberData(nameof(Writes))]
    public void Guard_refuses_every_write(string what, Func<DirectoryRequest> make)
    {
        Assert.NotNull(what);
        Assert.Throws<ReadOnlyViolationException>(() => ReadOnlyGuard.Check(make()));
    }

    [Fact]
    public void Guard_allows_search_paging_sd_flags_and_who_am_i()
    {
        var search = new SearchRequest("DC=y", "(objectClass=*)", SearchScope.Subtree, "cn");
        search.Controls.Add(new PageResultRequestControl(500));
        search.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
        ReadOnlyGuard.Check(search);
        ReadOnlyGuard.Check(new ExtendedRequest(ReadOnlyGuard.WhoAmIOid));
    }

    [Theory]
    [MemberData(nameof(Writes))]
    public void Session_refuses_every_write_before_sending(string what, Func<DirectoryRequest> make)
    {
        Assert.NotNull(what);
        // an unbound connection to a host that does not exist: the refusal happens before anything is sent
        using var session = new ReadOnlyLdapSession(new LdapConnection(new LdapDirectoryIdentifier("dc.invalid", 389)));
        Assert.Throws<ReadOnlyViolationException>(() => session.Send(make()));
    }

    // ------------------------------------------------------------------ no write members
    [GeneratedRegex("^_?(add|remove|modify|delete|move|rename|set|update|reset|unlock|enable|disable|write|commit|create|save)", RegexOptions.IgnoreCase)]
    private static partial Regex WriteName();

    [Theory]
    [InlineData(typeof(IDirectory))]
    [InlineData(typeof(AdDirectory))]
    [InlineData(typeof(ILdapSession))]
    [InlineData(typeof(ReadOnlyLdapSession))]
    public void Directory_types_have_no_write_methods(Type type)
    {
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                          .Where(m => !m.IsSpecialName).Select(m => m.Name).ToList();
        Assert.NotEmpty(methods);
        Assert.DoesNotContain(methods, n => WriteName().IsMatch(n));
        Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance), p => p.SetMethod?.IsPublic == true);
        if (type == typeof(ILdapSession)) Assert.Equal(["Search", "WhoAmI"], methods.Order());
    }

    // ------------------------------------------------------------------ source scan of src/
    private static string RepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "ADmiral.slnx"))) return d.FullName;
        throw new InvalidOperationException("repository root (ADmiral.slnx) not found");
    }

    private static IEnumerable<string> SourceFiles() =>
        Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src"), "*.cs", System.IO.SearchOption.AllDirectories)
                 .Where(p => !p.Split(Path.DirectorySeparatorChar).Any(s => s is "bin" or "obj"));

    /// <summary>Directory-write APIs: S.DS.P write requests and controls, ADSI / AccountManagement (which can write),
    /// the password-modify extended operation and AD password attributes.</summary>
    private static readonly (string Name, Regex Pattern)[] Forbidden =
    [
        .. new[]
        {
            "AddRequest", "ModifyRequest", "DeleteRequest", "ModifyDNRequest", "CompareRequest", "DirectoryAttributeModification",
            "DirectoryAttributeOperation", "DsmlRequestDocument", "DsmlSoapHttpConnection", "TreeDeleteControl", "PermissiveModifyControl",
            "DirectoryEntry", "DirectoryEntries", "CommitChanges", "DirectorySynchronization", "UserPrincipal", "GroupPrincipal",
            "ComputerPrincipal", "PrincipalContext", "BeginSendRequest",
        }.Select(n => (n, new Regex($@"\b{n}\b"))),
        ("System.DirectoryServices.AccountManagement", new Regex(@"System\.DirectoryServices\.AccountManagement")),
        ("System.DirectoryServices (ADSI)", new Regex(@"using\s+System\.DirectoryServices\s*;")),
        ("password modify OID", new Regex(@"1\.3\.6\.1\.4\.1\.4203\.1\.11\.1\b")),
        ("unicodePwd", new Regex("unicodePwd", RegexOptions.IgnoreCase)),
    ];

    [Fact]
    public void No_ldap_write_code_in_source()
    {
        var files = SourceFiles().ToList();
        Assert.Contains(files, f => f.EndsWith("Directory.cs", StringComparison.Ordinal));
        var hits = new List<string>();
        foreach (var f in files)
        {
            var lines = File.ReadAllLines(f);
            for (var i = 0; i < lines.Length; i++)
                foreach (var (name, re) in Forbidden)
                    if (re.IsMatch(lines[i])) hits.Add($"{Path.GetRelativePath(RepoRoot(), f)}:{i + 1} uses {name}");
        }
        Assert.Empty(hits);
    }

    [Fact]
    public void All_ldap_traffic_goes_through_the_read_only_session()
    {
        var core = Path.Combine(RepoRoot(), "src", "ADmiral.Core", "Directory.cs");
        var sends = new List<string>();
        var connections = new List<string>();
        var extended = new List<string>();
        foreach (var f in SourceFiles())
        {
            var text = File.ReadAllText(f);
            var rel = Path.GetRelativePath(RepoRoot(), f);
            sends.AddRange(Regex.Matches(text, @"\.SendRequest\s*\(").Select(_ => rel));
            if (f != core && Regex.IsMatch(text, @"new\s+LdapConnection\b|\bLdapConnection\s*\(")) connections.Add(rel);
            extended.AddRange(Regex.Matches(text, @"new\s+ExtendedRequest\s*\(([^)]*)\)").Select(m => $"{rel}: {m.Groups[1].Value}"));
        }
        Assert.Equal([Path.GetRelativePath(RepoRoot(), core)], sends);                           // exactly one Send
        Assert.Empty(connections);                                                               // nobody else opens LDAP
        Assert.All(extended, e => Assert.EndsWith("ReadOnlyGuard.WhoAmIOid", e));                // only who-am-i
        var text2 = File.ReadAllText(core);
        var send = text2[text2.IndexOf("public DirectoryResponse Send(", StringComparison.Ordinal)..];
        Assert.True(send.IndexOf("ReadOnlyGuard.Check(request)", StringComparison.Ordinal) < send.IndexOf(".SendRequest(", StringComparison.Ordinal));
    }

    [Fact]
    public void Certificate_validation_is_never_disabled_silently()
    {
        // the only "accept any certificate" callback sits behind an explicit verify_cert = false
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "src", "ADmiral.Core", "Directory.cs"));
        var accepts = Regex.Matches(text, @"VerifyServerCertificate\s*=\s*\(_,\s*_\)\s*=>\s*true");
        Assert.Single(accepts);
        var before = text[..accepts[0].Index];
        Assert.Contains("if (!ep.VerifyCert)", before[before.LastIndexOf("if (", StringComparison.Ordinal)..]);
        foreach (var f in SourceFiles().Where(f => !f.EndsWith(Path.Combine("ADmiral.Core", "Directory.cs"), StringComparison.Ordinal)))
            Assert.DoesNotContain("VerifyServerCertificate", File.ReadAllText(f));
    }
}
