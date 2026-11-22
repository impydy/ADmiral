using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>RFC 4515 filter escaping (LdapFilter.cs) and the LDAPS CA-file certificate check.</summary>
public class LdapFilterTests
{
    [Theory]
    [InlineData("jane", "jane")]
    [InlineData("a*b", @"a\2ab")]
    [InlineData("(x)", @"\28x\29")]
    [InlineData(@"CORP\svc", @"CORP\5csvc")]
    [InlineData("nul\0", @"nul\00")]
    [InlineData("tab\t", @"tab\09")]
    [InlineData("Pénzügy", "Pénzügy")]
    [InlineData(@"CN=O\, B,DC=x", @"CN=O\5c, B,DC=x")]
    [InlineData("*)(objectClass=*", @"\2a\29\28objectClass=\2a")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Escape(string? value, string expected) => Assert.Equal(expected, LdapFilter.Escape(value));

    [Fact]
    public void Escape_roundtrips_through_a_filter_parser()
    {
        foreach (var v in new[] { "a*b", "(x)", @"\", "*)(|(cn=*))", "x\0y", "Árvíztűrő tükörfúrógép" })
        {
            var f = LdapFilter.Eq("cn", v);
            FilterNode.Parse(f);                                          // one item, structure unchanged
            Assert.Equal(v, FilterNode.Unescape(f[4..^1]));
        }
    }

    [Fact]
    public void Escape_bytes()
    {
        Assert.Equal(@"\01\05\00\ff", LdapFilter.EscapeBytes([1, 5, 0, 255]));
        Assert.Equal("", LdapFilter.EscapeBytes([]));
    }

    [Fact]
    public void Builders()
    {
        Assert.Equal("(&(objectClass=user)(sAMAccountName=a\\2a))", LdapFilter.And("(objectClass=user)", LdapFilter.Eq("sAMAccountName", "a*")));
        Assert.Equal("(|(cn=a)(cn=b))", LdapFilter.Or(new[] { "a", "b" }.Select(x => LdapFilter.Eq("cn", x))));
        Assert.Equal(@"(member:1.2.840.113556.1.4.1941:=CN=x\28y\29,DC=c)", LdapFilter.Extensible("member", "1.2.840.113556.1.4.1941", "CN=x(y),DC=c"));
        Assert.Throws<ArgumentException>(() => LdapFilter.Eq("cn=*)(x", "v"));         // attribute names are never data
        Assert.Throws<ArgumentException>(() => LdapFilter.Eq("", "v"));
        Assert.Throws<ArgumentException>(() => LdapFilter.Extensible("member", "1.2:=x", "v"));
    }

    // ------------------------------------------------------------------ CA-file validation
    private static X509Certificate2 MakeCa(string name)
    {
        var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 Issue(X509Certificate2 ca, string dns)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={dns}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dns);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        return req.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(30), [1, 2, 3, 4]);
    }

    [Fact]
    public void Ca_file_validation_checks_chain_and_host_name()
    {
        using var tmp = new CoreTemp();
        using var ca = MakeCa("Corp Root");
        using var otherCa = MakeCa("Evil Root");
        var path = tmp.File("ca.pem");
        File.WriteAllText(path, ca.ExportCertificatePem());
        var roots = LdapCertificates.LoadCaFile(path);
        Assert.Single(roots);

        using var good = Issue(ca, "dc01.corp.local");
        Assert.True(LdapCertificates.Validate(good, "dc01.corp.local", roots, out var why), why);
        Assert.False(LdapCertificates.Validate(good, "dc02.corp.local", roots, out why));               // wrong host
        Assert.Contains("dc02.corp.local", why);
        using var forged = Issue(otherCa, "dc01.corp.local");
        Assert.False(LdapCertificates.Validate(forged, "dc01.corp.local", roots, out why));             // other CA
        Assert.NotEqual("", why);

        var der = tmp.File("ca.cer");
        File.WriteAllBytes(der, ca.RawData);
        Assert.Single(LdapCertificates.LoadCaFile(der));
        var empty = tmp.File("empty.pem");
        File.WriteAllText(empty, "");
        Assert.ThrowsAny<Exception>(() => LdapCertificates.LoadCaFile(empty));
    }
}
