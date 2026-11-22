using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using ADmiral.Core;

namespace ADmiral.Tests;

public class KerberosTests
{
    private const string Base = "DC=corp,DC=local";

    [Fact]
    public void Realm_and_principal_mapping()
    {
        Assert.Equal("CORP.LOCAL", Kerberos.RealmFromBaseDn("OU=x,DC=corp,DC=local"));
        Assert.Equal("", Kerberos.RealmFromBaseDn("OU=x"));
        Assert.Equal("CORP.LOCAL", Kerberos.RealmFromHost("pc-01.corp.local"));
        Assert.Equal("", Kerberos.RealmFromHost("pc-01"));
        Assert.Equal("", Kerberos.RealmFromHost("10.0.0.5"));
        Assert.Equal("svc@CORP.LOCAL", Kerberos.KerberosPrincipal("CORP\\svc", "CORP.LOCAL"));
        Assert.Equal("svc@CORP.LOCAL", Kerberos.KerberosPrincipal("corp.local\\svc", "OTHER.LOCAL"));
        Assert.Equal("svc@CORP.LOCAL", Kerberos.KerberosPrincipal("svc@corp.local"));
        Assert.Equal("svc@CORP.LOCAL", Kerberos.KerberosPrincipal("svc", "CORP.LOCAL"));
        Assert.Null(Kerberos.KerberosPrincipal("", "CORP.LOCAL"));
        Assert.Throws<KerberosError>(() => Kerberos.KerberosPrincipal("CORP\\svc", ""));                 // realm unknown
        Assert.Throws<KerberosError>(() => Kerberos.KerberosPrincipal("CN=svc,DC=corp,DC=local", "CORP.LOCAL"));
    }

    [Fact]
    public void Ntlm_user_forms()
    {
        Assert.Equal("CORP\\svc", Kerberos.NtlmUser("CORP\\svc"));
        Assert.Equal("CORP\\svc", Kerberos.NtlmUser("svc@corp.local"));
        Assert.Equal("CORP\\svc", Kerberos.NtlmUser("svc", Base));
        Assert.Throws<ArgumentException>(() => Kerberos.NtlmUser("svc"));
    }

    [Fact]
    public void Ip_address_is_rejected_for_kerberos()
    {
        Assert.Contains("FQDN", Assert.Throws<KerberosError>(() => Kerberos.RequireFqdn("10.1.2.3", "domain controller")).Message);
        Assert.Throws<KerberosError>(() => Kerberos.RequireFqdn("::1", "x"));
        Assert.Throws<KerberosError>(() => Kerberos.RequireFqdn("[fe80::1]", "x"));
        Assert.Throws<KerberosError>(() => Kerberos.RequireFqdn("", "x"));
        Kerberos.RequireFqdn("dc01.corp.local", "x");
        Assert.True(Kerberos.IsIpAddress("10.0.0.1"));
        Assert.False(Kerberos.IsIpAddress("dc01"));
        Assert.Equal("ldap/dc01.corp.local", Kerberos.Spn("ldap", "DC01.corp.local."));
    }

    [Fact]
    public void Credentials_for_negotiate()
    {
        Assert.Null(Kerberos.Credential(null, "pw"));                                                   // current logon
        var c = Kerberos.Credential("svc@CORP.LOCAL", "pw")!;
        Assert.Equal(("svc", "pw", "CORP.LOCAL"), (c.UserName, c.Password, c.Domain));
    }

    [Fact]
    public void Auth_and_network_error_classification()
    {
        Assert.True(Kerberos.IsAuthError(new KerberosError("x")));
        Assert.True(Kerberos.IsAuthError(new LdapException(49, "invalidCredentials")));
        Assert.True(Kerberos.IsAuthError(new HttpRequestException("401", null, HttpStatusCode.Unauthorized)));
        Assert.True(Kerberos.IsAuthError(new InvalidCredentialException("bad")));
        Assert.False(Kerberos.IsAuthError(new HttpRequestException("500", null, HttpStatusCode.InternalServerError)));
        Assert.False(Kerberos.IsAuthError(new HttpRequestException("refused", new SocketException((int)SocketError.ConnectionRefused))));
        Assert.True(Kerberos.IsNetworkError(new HttpRequestException("refused", new SocketException((int)SocketError.ConnectionRefused))));
        Assert.True(Kerberos.IsNetworkError(new TimeoutException()));
        Assert.True(Kerberos.IsNetworkError(new LdapException(81, "server down")));
        Assert.True(Kerberos.IsNetworkError(new AggregateException(new SocketException((int)SocketError.TimedOut))));
        Assert.False(Kerberos.IsNetworkError(new KerberosError("x")));
        Assert.False(Kerberos.IsNetworkError(new LdapException(49, "invalidCredentials")));
        Assert.False(Kerberos.IsNetworkError(new InvalidCredentialException("bad")));
    }
}
