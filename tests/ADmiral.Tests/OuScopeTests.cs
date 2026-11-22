using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>tests/test_ou_scope.py (directory parts): DACL parsing and the OU-scoped admin check against a fake DC.
/// parent_dn / is_under are covered by DnUtilTests; the demo / service / web cases belong to those modules.</summary>
public class OuScopeTests
{
    private static byte[] Sid(params uint[] subs) => SidBytes.Of(subs);

    private static byte[] Ace(byte type, uint mask, byte[] sid, uint? objFlags = null)
    {
        var body = new List<byte>(BitConverter.GetBytes(mask));
        if (objFlags is { } f)
        {
            body.AddRange(BitConverter.GetBytes(f));
            if ((f & 1) != 0) body.AddRange(new byte[16]);
        }
        body.AddRange(sid);
        var size = (ushort)(4 + body.Count);
        return [type, 0, .. BitConverter.GetBytes(size), .. body];
    }

    private static byte[] Sd(params byte[][] aces)
    {
        var acl = new List<byte> { 4, 0 };
        acl.AddRange(BitConverter.GetBytes((ushort)(8 + aces.Sum(a => a.Length))));
        acl.AddRange(BitConverter.GetBytes((ushort)aces.Length));
        acl.AddRange(BitConverter.GetBytes((ushort)0));
        foreach (var a in aces) acl.AddRange(a);
        var head = new List<byte> { 1, 0 };
        head.AddRange(BitConverter.GetBytes((ushort)0x8004));
        head.AddRange(BitConverter.GetBytes(0u));     // owner
        head.AddRange(BitConverter.GetBytes(0u));     // group
        head.AddRange(BitConverter.GetBytes(0u));     // sacl
        head.AddRange(BitConverter.GetBytes(20u));    // dacl offset
        return [.. head, .. acl];
    }

    [Fact]
    public void Dacl_full_control_and_generic_all_count()
    {
        byte[] ouAdmins = Sid(21, 1, 1, 1, 1100), helpdesk = Sid(21, 1, 1, 1, 1200), other = Sid(21, 1, 1, 1, 1300), dacl = Sid(21, 1, 1, 1, 1400);
        var sd = Sd(Ace(0, 0x000F01FF, ouAdmins),              // Full Control
                    Ace(0, 0x10000000, helpdesk),              // GenericAll
                    Ace(0, 0x00040000, dacl),                  // WriteDacl
                    Ace(0, 0x00000020, other));                // one narrow right
        Assert.Equal(new HashSet<string> { "S-1-5-21-1-1-1-1100", "S-1-5-21-1-1-1-1200", "S-1-5-21-1-1-1-1400" }, AdDirectory.DaclAdminSids(sd));
    }

    [Fact]
    public void Dacl_ignores_deny_and_property_specific_grants()
    {
        byte[] a = Sid(21, 7), b = Sid(21, 8), c = Sid(21, 9);
        var sd = Sd(Ace(1, 0x10000000, a),                     // deny ACE
                    Ace(5, 0x10000000, b, objFlags: 1),        // object ACE limited to one property
                    Ace(5, 0x10000000, c, objFlags: 0));       // object ACE without object type: counts
        Assert.Equal(new HashSet<string> { "S-1-5-21-9" }, AdDirectory.DaclAdminSids(sd));
        Assert.Empty(AdDirectory.DaclAdminSids([]));
    }

    [Fact]
    public void Dacl_survives_truncated_and_hostile_input()
    {
        var sd = Sd(Ace(0, 0x10000000, Sid(21, 5)));
        for (var n = 0; n < sd.Length; n++) AdDirectory.DaclAdminSids(sd.AsSpan(0, n));     // never throws
        var bogus = (byte[])sd.Clone();
        bogus[16] = 0xff; bogus[17] = 0xff; bogus[18] = 0xff; bogus[19] = 0x7f;              // DACL offset far outside
        Assert.Empty(AdDirectory.DaclAdminSids(bogus));
        var zeroSize = (byte[])sd.Clone();
        zeroSize[20 + 8 + 2] = 0; zeroSize[20 + 8 + 3] = 0;                                  // ACE size 0: stop
        Assert.Empty(AdDirectory.DaclAdminSids(zeroSize));
    }

    // ------------------------------------------------------------------ ou_admin_scope against a fake DC
    private const string UserDn = "CN=svc,OU=Admins,DC=corp,DC=local";

    [Fact]
    public void Ou_admin_scope_per_ou()
    {
        const string mine = "OU=Mine,DC=corp,DC=local", other = "OU=Other,DC=corp,DC=local", broken = "OU=Broken,DC=corp,DC=local";
        var ouAdmins = Sid(21, 1, 2, 3, 1500);               // a group the service account belongs to
        var stranger = Sid(21, 1, 2, 3, 1999);
        var acls = new Dictionary<string, object>
        {
            [mine] = Sd(Ace(0, 0x000F01FF, ouAdmins)),       // delegated Full Control on this OU only
            [other] = Sd(Ace(0, 0x000F01FF, stranger)),
            [broken] = new UnauthorizedAccessException("insufficient access"),
        };
        var dit = new FakeDit();
        dit.Handler = q =>
        {
            if (q.Filter.Contains("member:" + AdDirectory.InChain)) return [];                   // not a global admin
            if (q.Filter.Contains("sAMAccountName"))
                return [LdapEntry.Of(UserDn, new Dictionary<string, object?> { ["objectSid"] = Sid(21, 1, 2, 3, 1105) })];
            if (q.Attributes.Contains("tokenGroups"))
                return [LdapEntry.Of(q.BaseDn, new Dictionary<string, object?> { ["tokenGroups"] = new[] { ouAdmins } })];
            if (acls.TryGetValue(q.BaseDn, out var acl))
            {
                Assert.Equal(0x04, q.SdFlags);                                                   // DACL via the SD-flags control
                Assert.Equal(LdapScope.Base, q.Scope);
                if (acl is Exception e) throw e;
                return [LdapEntry.Of(q.BaseDn, new Dictionary<string, object?> { ["nTSecurityDescriptor"] = acl })];
            }
            return [];
        };
        var d = new AdDirectory(new LdapSettings { Server = "dc.corp.local", BaseDn = "DC=corp,DC=local", User = @"CORP\svc" }, dit);
        var r = d.OuAdminScope(@"CORP\svc", [mine, other, broken, mine]);
        Assert.Equal(3, r.Count);
        Assert.True(r[mine].Ok);                                           // admin of *this* OU: allowed
        Assert.False(r[other].Ok);                                         // not admin there: refused
        Assert.Contains("OU=Other", r[other].Detail);
        Assert.True(r[broken].Ok);                                         // ACL unreadable: target decides
        Assert.Contains("unreadable", r[broken].Detail);
        Assert.All(dit.Sessions, s => Assert.True(s.Disposed));
    }

    [Fact]
    public void Ou_admin_scope_global_admin_and_empty()
    {
        var dit = new FakeDit();
        dit.Add(UserDn, new() { ["objectClass"] = "user", ["sAMAccountName"] = "svc", ["objectSid"] = Sid(21, 1, 2, 3, 1105) });
        dit.Add("CN=Domain Admins,CN=Users,DC=corp,DC=local", new() { ["objectClass"] = "group", ["cn"] = "Domain Admins", ["objectSid"] = Sid(21, 1, 2, 3, 512), ["member"] = UserDn });
        var d = new AdDirectory(new LdapSettings { Server = "dc.corp.local", BaseDn = "DC=corp,DC=local" }, dit);
        Assert.Empty(d.OuAdminScope(@"CORP\svc", ["", ""]));
        Assert.Empty(dit.Binds);                                          // nothing to check: no connection
        var r = d.OuAdminScope(@"CORP\svc", ["OU=A,DC=corp,DC=local"]);
        Assert.True(r["OU=A,DC=corp,DC=local"].Ok);
        Assert.Contains("Domain Admins", r["OU=A,DC=corp,DC=local"].Detail);
        Assert.DoesNotContain(dit.Queries, q => q.SdFlags != 0);          // no ACL read needed
    }

    [Fact]
    public void Ou_admin_scope_unknown_account_is_refused()
    {
        var d = new AdDirectory(new LdapSettings { Server = "dc.corp.local", BaseDn = "DC=corp,DC=local" }, new FakeDit());
        var r = d.OuAdminScope(@"CORP\ghost", ["OU=A,DC=corp,DC=local"]);
        Assert.False(r["OU=A,DC=corp,DC=local"].Ok);
        Assert.Contains("not found", r["OU=A,DC=corp,DC=local"].Detail);
    }
}
