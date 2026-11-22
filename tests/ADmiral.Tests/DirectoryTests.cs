using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>tests/test_directory.py plus the pure helpers of admiral/directory.py (SIDs, account names, factory).</summary>
public class DirectoryTests
{
    [Fact]
    public void Filetime()
    {
        Assert.Equal("2022-06-18T04:26:40+00:00", AdDirectory.FiletimeToIso("133000000000000000"));
        Assert.Equal("2022-06-18T04:26:40+00:00", AdDirectory.FiletimeToIso(133000000000000000L));
        Assert.Equal("2022-06-18T04:26:40+00:00", AdDirectory.FiletimeToIso(new List<object?> { "133000000000000005" }));
        Assert.Null(AdDirectory.FiletimeToIso("0"));
        Assert.Null(AdDirectory.FiletimeToIso(null));
        Assert.Null(AdDirectory.FiletimeToIso(""));
        Assert.Null(AdDirectory.FiletimeToIso(new List<object?>()));
        Assert.Null(AdDirectory.FiletimeToIso("9223372036854775807"));      // "never"
        Assert.Equal("2024-01-31T12:00:00+00:00", AdDirectory.FiletimeToIso("20240131120000.0Z"));   // not a number
        Assert.Null(AdDirectory.FiletimeToIso(new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
        Assert.Equal("2024-05-01T10:00:00+00:00", AdDirectory.FiletimeToIso(new DateTimeOffset(2024, 5, 1, 12, 0, 0, 500, TimeSpan.FromHours(2))));
    }

    [Fact]
    public void GeneralizedTime()
    {
        Assert.Equal("2024-01-31T12:00:00+00:00", AdDirectory.GeneralizedTimeToIso("20240131120000.0Z"));
        Assert.Equal("2024-01-31T12:00:00+00:00", AdDirectory.GeneralizedTimeToIso("20240131120000Z"u8.ToArray()));
        Assert.Null(AdDirectory.GeneralizedTimeToIso(new List<object?> { "bogus" }));
        Assert.Null(AdDirectory.GeneralizedTimeToIso(null));
    }

    [Fact]
    public void NormalizeComputer()
    {
        var g = Guid.NewGuid();
        var rec = AdDirectory.NormalizeComputer(new Dictionary<string, object?>
        {
            ["objectGUID"] = new List<object?> { g.ToByteArray() },
            ["name"] = new List<object?> { "WS01" },
            ["distinguishedName"] = new List<object?> { "CN=WS01,OU=Desktops,DC=corp,DC=local" },
            ["dNSHostName"] = new List<object?> { "ws01.corp.local" },
            ["userAccountControl"] = new List<object?> { "4098" },          // WORKSTATION_TRUST_ACCOUNT | ACCOUNTDISABLE
            ["lastLogonTimestamp"] = new List<object?> { "133000000000000000" },
            ["operatingSystem"] = new List<object?> { "Windows 11 Enterprise" },
            // S-1-5-21-1-2-3-1105
            ["objectSid"] = new List<object?> { new byte[] { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x51, 4, 0, 0 } },
        });
        Assert.Equal(g.ToString(), rec["guid"]);
        Assert.Equal("S-1-5-21-1-2-3-1105", rec["sid"]);
        Assert.Equal(false, rec["enabled"]);
        Assert.Equal("corp.local/Desktops", rec["ou"]);
        Assert.StartsWith("2022-06-18", (string)rec["last_logon"]!);
        Assert.Equal("ws01.corp.local", rec["dns_hostname"]);
        Assert.Null(rec["description"]);
        Assert.Equal(new List<string>(), rec["member_of"]);
        foreach (var f in Db.AdFields) Assert.True(rec.ContainsKey(f), f);
    }

    [Fact]
    public void NormalizeComputer_name_from_dn_and_string_guid()
    {
        var rec = AdDirectory.NormalizeComputer(new Dictionary<string, object?>
        {
            ["objectGUID"] = "{0A1B2C3D-0000-0000-0000-000000000001}",
            ["distinguishedName"] = new List<object?> { "CN=PC9,OU=X,DC=c,DC=l" },
        });
        Assert.Equal("0a1b2c3d-0000-0000-0000-000000000001", rec["guid"]);
        Assert.Equal("PC9", rec["name"]);
        Assert.Equal(true, rec["enabled"]);
        Assert.Throws<ArgumentException>(() => AdDirectory.NormalizeComputer(new Dictionary<string, object?> { ["name"] = "x" }));
    }

    [Fact]
    public void NormalizeUser()
    {
        var g = Guid.NewGuid();
        var rec = AdDirectory.NormalizeUser(new Dictionary<string, object?>
        {
            ["objectGUID"] = new List<object?> { g.ToByteArray() },
            ["sAMAccountName"] = new List<object?> { "jane" },
            ["displayName"] = new List<object?> { "Jane Doe" },
            ["manager"] = new List<object?> { @"CN=Boss\, Big,OU=Users,DC=corp,DC=local" },
            ["userAccountControl"] = new List<object?> { "512" },
            ["pwdLastSet"] = new List<object?> { "133000000000000000" },
            ["whenCreated"] = new List<object?> { "20240131120000.0Z" },
            ["distinguishedName"] = new List<object?> { "CN=Jane,OU=Users,DC=corp,DC=local" },
            ["memberOf"] = new List<object?> { "CN=b,DC=x", "CN=A,DC=x" },
        });
        Assert.Equal(g.ToString(), rec["guid"]);
        Assert.Equal("jane", rec["sam"]);
        Assert.Equal("Jane Doe", rec["display_name"]);
        Assert.Equal("Boss, Big", rec["manager"]);
        Assert.Equal(true, rec["enabled"]);
        Assert.Equal("2022-06-18T04:26:40+00:00", rec["password_set"]);
        Assert.Equal("2024-01-31T12:00:00+00:00", rec["created"]);
        Assert.Equal("corp.local/Users", rec["ou"]);
        Assert.Equal(new List<string> { "CN=A,DC=x", "CN=b,DC=x" }, rec["member_of"]);
        Assert.Null(rec["mail"]);
    }

    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-1-2-3-512")]
    [InlineData("S-1-5-21-9-9-9-1105")]
    [InlineData("S-1-5-21-4294967295-2-3-1105")]
    public void Sid_roundtrip(string sid) => Assert.Equal(sid, AdDirectory.SidToString(SidBytes.Of(sid)));

    [Fact]
    public void Sid_rejects_garbage()
    {
        Assert.Throws<ArgumentException>(() => AdDirectory.SidToString([]));
        Assert.Throws<ArgumentException>(() => AdDirectory.SidToString([1, 5, 0, 0, 0, 0, 0, 5, 1]));   // truncated
    }

    [Theory]
    [InlineData(@"CORP\svc", "svc")]
    [InlineData("svc@corp.local", "svc")]
    [InlineData(@"u:CORP\svc", "svc")]
    [InlineData("svc", "svc")]
    [InlineData("  svc ", "svc")]
    [InlineData("CN=svc,DC=corp,DC=local", "")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Account_name(string? user, string expected) => Assert.Equal(expected, AdDirectory.AccountName(user));

    [Fact]
    public void Factory_picks_ldap_or_demo()
    {
        var ldap = DirectoryFactory.Make(new Settings { Mode = "ldap", Ldap = new LdapSettings { Server = "dc1", BaseDn = "DC=x" } });
        Assert.IsType<AdDirectory>(ldap);
        var demo = new FakeDirectory();
        Assert.Same(demo, DirectoryFactory.Make(new Settings { Mode = "demo" }, () => demo));
        Assert.Throws<InvalidOperationException>(() => DirectoryFactory.Make(new Settings { Mode = "demo" }, null));
    }

    [Fact]
    public void Scope_rejects_ou_outside_base()
    {
        var d = new AdDirectory(new LdapSettings { Server = "dc", BaseDn = "DC=corp,DC=local" }, new FakeDit());
        Assert.Contains("not inside", Assert.Throws<ArgumentException>(() => d.ListOus("OU=X,DC=evil,DC=com")).Message);
        Assert.Contains("not inside", Assert.Throws<ArgumentException>(() => d.FetchComputers("DC=other,DC=local")).Message);
        Assert.Contains("not inside", Assert.Throws<ArgumentException>(() => d.FetchOuUsers("DC=local")).Message);
        Assert.Equal("DC=corp,DC=local", d.Scope(null));
        Assert.Equal("ou=x, dc=corp,dc=local", d.Scope("ou=x, dc=corp,dc=local"));
    }

    /// <summary>A stand-in for a demo directory: the interface is implementable without LDAP.</summary>
    private sealed class FakeDirectory : IDirectory
    {
        public string Test() => "demo";
        public List<Dictionary<string, object?>> FetchComputers(string? baseDn = null) => [];
        public List<AdOu> ListOus(string? parent = null) => [];
        public List<string> GroupMembers(string groupDn) => [];
        public Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names) => [];
        public List<Dictionary<string, object?>> FetchOuUsers(string? baseDn = null) => [];
        public (bool Ok, string Detail) IsAdminAccount(string user) => (true, "demo");
        public Dictionary<string, (bool Ok, string Detail)> OuAdminScope(string user, IEnumerable<string> ouDns) => [];
    }
}
