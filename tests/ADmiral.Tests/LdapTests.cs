using System.DirectoryServices.Protocols;
using System.Net.Sockets;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>tests/test_ldap.py, the LDAP bind order of tests/test_kerberos.py / test_md4.py and the admin check of
/// tests/test_pdq.py: AdDirectory against an in-memory fake directory (no domain controller).</summary>
public class LdapTests
{
    private const string Base = "DC=corp,DC=local";
    private static readonly Guid[] Guids = [.. Enumerable.Range(0, 5).Select(_ => Guid.NewGuid())];

    private static FakeDit MakeDit()
    {
        var dit = new FakeDit();
        dit.Add($"CN=svc,{Base}", new() { ["objectClass"] = "person" });
        dit.Add($"CN=PC-01,OU=Laptops,OU=Workstations,{Base}", new()
        {
            ["objectClass"] = new[] { "top", "computer" }, ["objectCategory"] = "computer", ["name"] = "PC-01",
            ["objectGUID"] = Guids[0].ToByteArray(), ["userAccountControl"] = 4096, ["dNSHostName"] = "pc-01.corp.local",
            ["operatingSystem"] = "Windows 11 Enterprise", ["operatingSystemVersion"] = "10.0 (22631)",
            ["lastLogonTimestamp"] = 133000000000000000L, ["whenCreated"] = "20240131120000.0Z",
            ["description"] = "Pénzügy", ["location"] = "Budapest, 3. emelet",
            ["memberOf"] = new[] { $"CN=Deploy-B,OU=Groups,{Base}", $"CN=deploy-a,OU=Groups,{Base}" },
        });
        dit.Add($"CN=PC-02,OU=Desktops,OU=Workstations,{Base}", new()
        {
            ["objectClass"] = new[] { "top", "computer" }, ["objectCategory"] = "computer", ["name"] = "PC-02",
            ["objectGUID"] = Guids[1].ToByteArray(), ["userAccountControl"] = 4098,           // disabled, minimal
        });
        for (var i = 2; i < 5; i++)
            dit.Add($"CN=SRV-0{i},OU=Servers,{Base}", new()
            {
                ["objectClass"] = new[] { "top", "computer" }, ["objectCategory"] = "computer", ["name"] = $"SRV-0{i}",
                ["objectGUID"] = Guids[i].ToByteArray(), ["userAccountControl"] = 4096,
            });
        dit.Add($"CN=Jane,OU=Users,{Base}", new()
        {
            ["objectClass"] = new[] { "top", "person", "user" }, ["objectCategory"] = "person", ["sAMAccountName"] = "jane",
            ["objectGUID"] = Guid.NewGuid().ToByteArray(), ["mail"] = "jane@corp.local",
        });
        dit.Add($"CN=O(Brien)*,OU=Users,{Base}", new()
        {
            ["objectClass"] = new[] { "top", "person", "user" }, ["objectCategory"] = "person", ["sAMAccountName"] = "o(brien)*",
            ["objectGUID"] = Guid.NewGuid().ToByteArray(),
        });
        dit.Add($"OU=Workstations,{Base}", new() { ["objectClass"] = "organizationalUnit", ["name"] = "Workstations" });
        dit.Add($"OU=Servers,{Base}", new() { ["objectClass"] = "organizationalUnit", ["name"] = "Servers" });
        dit.Add($"OU=Laptops,OU=Workstations,{Base}", new() { ["objectClass"] = "organizationalUnit", ["name"] = "Laptops" });
        dit.Add($"CN=Computers,{Base}", new() { ["objectClass"] = "container", ["cn"] = "Computers" });
        dit.Add($"CN=Users,{Base}", new() { ["objectClass"] = "container", ["cn"] = "Users" });
        dit.Add($"CN=Deploy-B,OU=Groups,{Base}", new()
        {
            ["objectClass"] = new[] { "top", "group" },
            ["member"] = new[] { $"CN=PC-01,OU=Laptops,OU=Workstations,{Base}", $"CN=Jane,OU=Users,{Base}" },
        });
        return dit;
    }

    private static AdDirectory Dir(FakeDit dit, Action<LdapSettings>? tweak = null)
    {
        var s = new LdapSettings { Server = "dc01.corp.local", BaseDn = Base, PageSize = 2, UseSsl = false };
        tweak?.Invoke(s);
        return new AdDirectory(s, dit);
    }

    [Fact]
    public void Fetch_computers_decodes()
    {
        var dit = MakeDit();
        var comps = Dir(dit).FetchComputers().ToDictionary(c => (string)c["name"]!);
        Assert.Equal(["PC-01", "PC-02", "SRV-02", "SRV-03", "SRV-04"], comps.Keys.Order());    // users excluded
        var pc = comps["PC-01"];
        Assert.Equal(Guids[0].ToString(), pc["guid"]);
        Assert.Equal($"CN=PC-01,OU=Laptops,OU=Workstations,{Base}", pc["dn"]);
        Assert.Equal("corp.local/Workstations/Laptops", pc["ou"]);
        Assert.Equal(true, pc["enabled"]);
        Assert.Equal(false, comps["PC-02"]["enabled"]);
        Assert.Equal("2022-06-18T04:26:40+00:00", pc["last_logon"]);
        Assert.Equal("2024-01-31T12:00:00+00:00", pc["created"]);
        Assert.Equal("Pénzügy", pc["description"]);
        Assert.Equal("Budapest, 3. emelet", pc["location"]);
        Assert.Equal(new List<string> { $"CN=deploy-a,OU=Groups,{Base}", $"CN=Deploy-B,OU=Groups,{Base}" }, pc["member_of"]);
        Assert.Equal("Windows 11 Enterprise", pc["os"]);
        Assert.Equal("pc-01.corp.local", pc["dns_hostname"]);
        Assert.Null(comps["PC-02"]["last_logon"]);
        Assert.Equal(new List<string>(), comps["PC-02"]["member_of"]);
        // one paged subtree search with the configured filter, page size and attribute list; session closed
        var q = Assert.Single(dit.Queries);
        Assert.Equal((Base, "(objectCategory=computer)", LdapScope.Subtree, 2), (q.BaseDn, q.Filter, q.Scope, q.PageSize));
        Assert.Equal(AdDirectory.ComputerAttrs, q.Attributes);
        Assert.All(dit.Sessions, s => Assert.True(s.Disposed));
    }

    [Fact]
    public void Fetch_computers_scoped_to_an_ou()
    {
        var comps = Dir(MakeDit()).FetchComputers($"OU=Workstations,{Base}");
        Assert.Equal(["PC-01", "PC-02"], comps.Select(c => (string)c["name"]!).Order());
    }

    [Fact]
    public void List_ous_one_level_sorted()
    {
        var dit = MakeDit();
        var ous = Dir(dit).ListOus();
        Assert.Equal(["Computers", "Servers", "Workstations"], ous.Select(o => o.Name));
        Assert.Equal($"OU=Servers,{Base}", ous[1].Dn);
        Assert.Equal(LdapScope.OneLevel, dit.Queries.Single().Scope);
        Assert.Equal(AdDirectory.OuBrowserFilter, dit.Queries.Single().Filter);
        Assert.Equal(["Laptops"], Dir(dit).ListOus($"OU=Workstations,{Base}").Select(o => o.Name));
    }

    [Fact]
    public void Group_members()
    {
        var d = Dir(MakeDit());
        Assert.Equal(new HashSet<string> { $"CN=PC-01,OU=Laptops,OU=Workstations,{Base}", $"CN=Jane,OU=Users,{Base}" },
                     d.GroupMembers($"CN=Deploy-B,OU=Groups,{Base}").ToHashSet());
        Assert.Throws<KeyNotFoundException>(() => d.GroupMembers($"CN=Nope,OU=Groups,{Base}"));
    }

    [Fact]
    public void Group_members_follows_ranged_retrieval()
    {
        var dit = MakeDit();
        var members = Enumerable.Range(0, 7).Select(i => $"CN=M{i},{Base}").ToArray();
        dit.Add($"CN=Big,OU=Groups,{Base}", new() { ["objectClass"] = "group", ["member"] = members });
        dit.RangeSize = 3;
        Assert.Equal(members, Dir(dit).GroupMembers($"CN=Big,OU=Groups,{Base}"));
        Assert.Equal(["member", "member;range=3-*", "member;range=6-*"], dit.Queries.Select(q => q.Attributes.Single()));
    }

    [Fact]
    public void Fetch_users_escapes_names_and_chunks()
    {
        var dit = MakeDit();
        var users = Dir(dit).FetchUsers(["jane", " JANE ", "o(brien)*", "nobody", "", "  "], chunk: 2);
        Assert.Equal(["jane", "o(brien)*"], users.Keys.Order());
        Assert.Equal("jane@corp.local", users["jane"]["mail"]);
        Assert.Equal(2, dit.Queries.Count);                                     // 4 distinct names, 2 per query
        Assert.Contains(@"(sAMAccountName=o\28brien\29\2a)", dit.Queries.SelectMany(q => new[] { q.Filter }).First(f => f.Contains("brien")));
        Assert.Empty(Dir(new FakeDit()).FetchUsers([]));
    }

    [Fact]
    public void Fetch_ou_users()
    {
        var users = Dir(MakeDit()).FetchOuUsers($"OU=Users,{Base}");
        Assert.Equal(["jane", "o(brien)*"], users.Select(u => (string)u["sam"]!).Order());
    }

    // ------------------------------------------------------------------ connect parameters
    [Theory]
    [InlineData("dc01.corp.local", true, @"CORP\svc", "kerberos", 636, true, LdapBindMethod.Kerberos)]
    [InlineData("dc01.corp.local", false, "svc@corp.local", "kerberos", 389, false, LdapBindMethod.Kerberos)]
    [InlineData("dc01.corp.local", false, "svc@corp.local", "simple", 389, false, LdapBindMethod.Simple)]
    [InlineData("ldaps://dc01.corp.local", false, "CN=svc,DC=corp,DC=local", "simple", 636, true, LdapBindMethod.Simple)]
    [InlineData("ldap://dc01.corp.local", false, @"CORP\svc", "kerberos", 389, false, LdapBindMethod.Kerberos)]
    public void Connect_parameters(string server, bool useSsl, string user, string auth, int port, bool ssl, LdapBindMethod method)
    {
        var dit = new FakeDit();
        var d = new AdDirectory(new LdapSettings { Server = server, BaseDn = Base, UseSsl = useSsl, User = user, Password = "pw", Auth = auth, VerifyCert = true }, dit);
        d.Connect().Dispose();
        var (ep, m, cred) = Assert.Single(dit.Binds);
        Assert.Equal("dc01.corp.local", ep.Host);
        Assert.Equal(port, ep.Port);
        Assert.Equal(ssl, ep.UseSsl);
        Assert.Equal(method, m);
        Assert.True(ep.VerifyCert);                                   // never silently disabled
        if (method == LdapBindMethod.Kerberos)
        {
            Assert.Equal(("svc", "CORP.LOCAL", "pw"), (cred!.UserName, cred.Domain, cred.Password));
        }
        else
        {
            Assert.Equal(user, cred!.UserName);
            Assert.Equal("Simple", d.AuthUsed);
        }
    }

    [Fact]
    public void Endpoint_honours_explicit_port_and_cert_settings()
    {
        var ep = LdapEndpoint.From(new LdapSettings { Server = "LDAPS://dc01.corp.local/", Port = 3269, UseSsl = false, VerifyCert = false, CaFile = "/x/ca.pem" });
        Assert.Equal(new LdapEndpoint("dc01.corp.local", 3269, true, false, "/x/ca.pem"), ep);
    }

    [Fact]
    public void Not_configured()
    {
        var dit = new FakeDit();
        Assert.Throws<InvalidOperationException>(() => new AdDirectory(new LdapSettings { Server = "", BaseDn = Base }, dit).Connect());
        Assert.Throws<InvalidOperationException>(() => new AdDirectory(new LdapSettings { Server = "dc1" }, dit).Connect());
        Assert.Empty(dit.Binds);
    }

    // ------------------------------------------------------------------ bind order (test_kerberos.py)
    private static AdDirectory Ldap(FakeDit dit, bool ntlmFallback = false, string auth = "kerberos") =>
        new(new LdapSettings { Server = "dc01.corp.local", BaseDn = Base, User = @"CORP\svc", Password = "pw", NtlmFallback = ntlmFallback, Auth = auth }, dit);

    [Fact]
    public void Kerberos_is_tried_first_with_mapped_principal()
    {
        var dit = new FakeDit();
        var d = Ldap(dit);
        d.Connect().Dispose();
        Assert.Equal("Kerberos", d.AuthUsed);
        var b = Assert.Single(dit.Binds);
        Assert.Equal(LdapBindMethod.Kerberos, b.Method);
        Assert.Equal(("svc", "CORP.LOCAL", "pw"), (b.Credential!.UserName, b.Credential.Domain, b.Credential.Password));   // DOMAIN\user -> user@REALM
    }

    [Fact]
    public void Current_logon_when_no_user()
    {
        var dit = new FakeDit();
        new AdDirectory(new LdapSettings { Server = "dc01.corp.local", BaseDn = Base }, dit).Connect().Dispose();
        Assert.Null(Assert.Single(dit.Binds).Credential);
    }

    public static TheoryData<Exception> AuthErrors => new() { new KerberosError("no ticket"), new LdapException(49, "invalidCredentials") };

    public static TheoryData<Exception> NetworkErrors => new()
    {
        new LdapException(81, "server down"), new SocketException((int)SocketError.ConnectionRefused), new TimeoutException(),
    };

    [Theory]
    [MemberData(nameof(AuthErrors))]
    public void No_ntlm_when_fallback_disabled(Exception exc)
    {
        var dit = new FakeDit { FailBind = m => m == LdapBindMethod.Kerberos ? exc : null };
        Assert.Same(exc, Assert.ThrowsAny<Exception>(() => Ldap(dit).Connect()));
        Assert.Equal([LdapBindMethod.Kerberos], dit.Binds.Select(b => b.Method));      // NTLM never attempted
    }

    [Theory]
    [MemberData(nameof(AuthErrors))]
    public void Ntlm_after_kerberos_auth_failure_when_enabled(Exception exc)
    {
        var dit = new FakeDit { FailBind = m => m == LdapBindMethod.Kerberos ? exc : null };
        var d = Ldap(dit, ntlmFallback: true);
        d.Connect().Dispose();
        Assert.Equal("NTLMv2 (fallback)", d.AuthUsed);
        Assert.Equal([LdapBindMethod.Kerberos, LdapBindMethod.Ntlm], dit.Binds.Select(b => b.Method));
        var c = dit.Binds[1].Credential!;
        Assert.Equal(("svc", "CORP", "pw"), (c.UserName, c.Domain, c.Password));
    }

    [Theory]
    [MemberData(nameof(NetworkErrors))]
    public void No_fallback_on_network_errors(Exception exc)
    {
        var dit = new FakeDit { FailBind = m => m == LdapBindMethod.Kerberos ? exc : null };
        Assert.Same(exc, Assert.ThrowsAny<Exception>(() => Ldap(dit, ntlmFallback: true).Connect()));
        Assert.Equal([LdapBindMethod.Kerberos], dit.Binds.Select(b => b.Method));
    }

    public static TheoryData<Exception> LocalErrors => new()
    {
        new LdapException(82, "Local error (KDC unreachable)"), new System.ComponentModel.Win32Exception(5, "SSPI"),
        new InvalidOperationException("something else"),
    };

    [Theory]
    [MemberData(nameof(LocalErrors))]
    public void No_ntlm_downgrade_on_local_kerberos_errors(Exception exc)
    {
        var dit = new FakeDit { FailBind = m => m == LdapBindMethod.Kerberos ? exc : null };
        Assert.Same(exc, Assert.ThrowsAny<Exception>(() => Ldap(dit, ntlmFallback: true).Connect()));
        Assert.Equal([LdapBindMethod.Kerberos], dit.Binds.Select(b => b.Method));
        Assert.True(Kerberos.IsNtlmFallbackTrigger(new LdapException(8, "strongerAuthRequired")));
        Assert.True(Kerberos.IsNtlmFallbackTrigger(new LdapException(48, "inappropriateAuthentication")));
    }

    [Fact]
    public void Simple_is_an_explicit_choice()
    {
        var dit = new FakeDit();
        var d = Ldap(dit, ntlmFallback: true, auth: "simple");
        d.Connect().Dispose();
        Assert.Equal([LdapBindMethod.Simple], dit.Binds.Select(b => b.Method));
        Assert.Equal("Simple", d.AuthUsed);
    }

    [Fact]
    public void Ntlm_failure_after_fallback_is_reported()
    {
        var bad = new LdapException(49, "bad");
        var dit = new FakeDit { FailBind = m => m == LdapBindMethod.Kerberos ? new KerberosError("x") : bad };
        Assert.Same(bad, Assert.Throws<LdapException>(() => Ldap(dit, ntlmFallback: true).Connect()));
        Assert.Equal([LdapBindMethod.Kerberos, LdapBindMethod.Ntlm], dit.Binds.Select(b => b.Method));
    }

    [Fact]
    public void Ip_address_is_refused_for_kerberos_before_any_bind()
    {
        var dit = new FakeDit();
        var s = new LdapSettings { Server = "127.0.0.1", Port = 1, BaseDn = Base, User = @"CORP\svc", Password = "x" };
        Assert.Contains("FQDN", Assert.Throws<KerberosError>(() => new AdDirectory(s, dit).Connect()).Message);
        Assert.Empty(dit.Binds);
        s.NtlmFallback = true;                                   // a Kerberos (auth) failure: NTLM is tried
        new AdDirectory(s, dit).Connect().Dispose();
        Assert.Equal([LdapBindMethod.Ntlm], dit.Binds.Select(b => b.Method));
    }

    [Fact]
    public void Test_message_names_the_method()
    {
        var d = new AdDirectory(new LdapSettings { Server = "dc01.corp.local", BaseDn = Base }, new FakeDit { WhoAmIValue = @"u:CORP\svc" });
        var msg = d.Test();
        Assert.EndsWith("[Kerberos]", msg);
        Assert.Contains(@"CORP\svc", msg);
        var anon = new AdDirectory(new LdapSettings { Server = "dc01.corp.local", BaseDn = Base }, new FakeDit { WhoAmIValue = "" });
        Assert.Contains("current logon", anon.Test());
    }

    [Fact]
    public void Real_binder_fails_cleanly_without_a_server()
    {
        // test_misc.py test-connection against 127.0.0.1:1: a network error, reported, never an NTLM retry
        var s = new LdapSettings { Server = "127.0.0.1", Port = 1, BaseDn = "DC=x", UseSsl = false, Auth = "simple", User = "u", Password = "p" };
        var exc = Assert.ThrowsAny<Exception>(() => new AdDirectory(s).Test());
        Assert.True(Kerberos.IsNetworkError(exc), exc.ToString());
    }

    // ------------------------------------------------------------------ admin account (test_pdq.py)
    private static FakeDit AdminDit(string userSid, params (string Sid, string Cn)[] groupsOfUser)
    {
        var dit = new FakeDit();
        dit.Add($"CN=svc,OU=Admins,{Base}", new() { ["objectClass"] = "user", ["sAMAccountName"] = "svc", ["objectSid"] = SidBytes.Of(userSid) });
        var nested = $"CN=Nested,OU=Groups,{Base}";
        dit.Add(nested, new() { ["objectClass"] = "group", ["cn"] = "Nested", ["objectSid"] = SidBytes.Of("S-1-5-21-1-2-3-3000"), ["member"] = $"CN=svc,OU=Admins,{Base}" });
        foreach (var (sid, cn) in groupsOfUser)
            dit.Add($"CN={cn},CN=Users,{Base}", new() { ["objectClass"] = "group", ["cn"] = cn, ["objectSid"] = SidBytes.Of(sid), ["member"] = nested });
        return dit;
    }

    [Fact]
    public void Is_admin_account_true_for_nested_domain_admin()
    {
        var dit = AdminDit("S-1-5-21-1-2-3-1105", ("S-1-5-21-1-2-3-512", "Domain Admins"));
        var (ok, detail) = Dir(dit).IsAdminAccount(@"CORP\svc");
        Assert.True(ok);
        Assert.Contains("Domain Admins", detail);
        var f = dit.Queries[1].Filter;                       // the recursive membership rule against the admin SIDs
        Assert.Contains(AdDirectory.InChain, f);
        Assert.Contains("S-1-5-32-544", f);
        Assert.Contains("S-1-5-21-1-2-3-512", f);
        Assert.Contains("S-1-5-21-1-2-3-519", f);
        Assert.All(dit.Sessions, s => Assert.True(s.Disposed));
    }

    [Fact]
    public void Is_admin_account_false_for_plain_user()
    {
        var dit = AdminDit("S-1-5-21-1-2-3-1200", ("S-1-5-21-1-2-3-513", "Domain Users"));
        var (ok, detail) = Dir(dit).IsAdminAccount(@"CORP\svc");
        Assert.False(ok);
        Assert.Contains("not a member", detail);
    }

    [Fact]
    public void Is_admin_account_unknown_account_and_whoami()
    {
        var dit = AdminDit("S-1-5-21-1-2-3-1105");
        var (ok, detail) = Dir(dit).IsAdminAccount(@"CORP\ghost");
        Assert.False(ok);
        Assert.Contains("not found", detail);
        // no account configured: the bound identity (who-am-i) is checked
        dit.WhoAmIValue = @"u:CORP\svc";
        Assert.Contains("'svc' is not a member", Dir(dit).IsAdminAccount("").Detail);
        dit.WhoAmIValue = "";
        Assert.Equal((false, "no account configured to check"), Dir(dit).IsAdminAccount(""));
    }

    [Fact]
    public void Is_admin_account_escapes_the_account_name()
    {
        var dit = AdminDit("S-1-5-21-1-2-3-1105");
        Dir(dit).IsAdminAccount(@"CORP\*)(objectClass=*");
        Assert.Contains(@"(sAMAccountName=\2a\29\28objectClass=\2a)", dit.Queries[0].Filter);
        FilterNode.Parse(dit.Queries[0].Filter);              // still one well-formed filter
    }
}
