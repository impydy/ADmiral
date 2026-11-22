using System.Runtime.Versioning;
using System.Text;
using ADmiral.Core;

namespace ADmiral.Tests;

public class PersistTests
{
    /// <summary>Stands in for DPAPI (the Python test's fake_dpapi): XOR with 0x5A.</summary>
    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => [.. data.Select(b => (byte)(b ^ 0x5A))];

        public byte[] Unprotect(byte[] data) => Protect(data);
    }

    /// <summary>Cannot decrypt anything (a blob of another Windows user).</summary>
    private sealed class ForeignProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;

        public byte[] Unprotect(byte[] data) => throw new System.Security.Cryptography.CryptographicException("not yours");
    }

    [Fact]
    public void SecretStorePersistsEncrypted()
    {
        using var tmp = new CoreTemp();
        var path = tmp.File("secrets.json");
        var fake = new XorProtector();
        var s = new SecretStore(path, fake);
        Assert.True(s.Persistent);
        s.Set("ldap_password", "Titok-123!é");
        var raw = File.ReadAllText(path);
        Assert.DoesNotContain("Titok", raw);
        Assert.Contains("ldap_password", raw);
        var again = new SecretStore(path, fake);
        Assert.Equal("Titok-123!é", again.Get("ldap_password"));
        again.Set("ldap_password", "");
        Assert.Equal("", new SecretStore(path, fake).Get("ldap_password"));
        var cfg = new Settings();
        s.Set("winrm_password", "w");
        s.Apply(cfg);
        Assert.Equal("w", cfg.Winrm.Password);
        File.WriteAllText(path, "{not json");
        Assert.Equal("", new SecretStore(path, fake).Get("winrm_password"));      // unreadable -> re-enter, no crash
    }

    [Fact]
    public void ApplyKeepsSecretsFromTheEnvironment()
    {
        var s = new SecretStore(null);
        s.Set("ldap_password", "stored");
        s.Set("sync_key", "k");
        var cfg = new Settings();
        cfg.Ldap.Password = "from-env";
        s.Apply(cfg);
        Assert.Equal("from-env", cfg.Ldap.Password);
        Assert.Equal("k", cfg.Sync.Key);
    }

    [Fact]
    public void ForeignEntriesSurviveARewrite()
    {
        using var tmp = new CoreTemp();
        var path = tmp.File("secrets.json");
        File.WriteAllText(path, """{"ldap_password": "b3RoZXI="}""");
        var s = new SecretStore(path, new ForeignProtector());
        Assert.Equal("", s.Get("ldap_password"));
        s.Set("winrm_password", "w");
        var raw = File.ReadAllText(path);
        Assert.Contains("b3RoZXI=", raw);           // the other user's entry is kept as it was
        Assert.Contains("winrm_password", raw);
    }

    [Fact]
    public void SecretStoreMemoryOnlyOffWindows()
    {
        if (OperatingSystem.IsWindows()) return;
        using var tmp = new CoreTemp();
        var s = new SecretStore(tmp.File("secrets.json"));
        s.Set("ldap_password", "x");
        Assert.False(s.Persistent);
        Assert.Equal("x", s.Get("ldap_password"));
        Assert.False(File.Exists(tmp.File("secrets.json")));
    }

    [WindowsFact]
    public void RealDpapiRoundtrip()
    {
        if (!OperatingSystem.IsWindows()) return;
        Roundtrip();
    }

    [SupportedOSPlatform("windows")]
    private static void Roundtrip()
    {
        var p = new DpapiProtector();
        var plain = Encoding.UTF8.GetBytes("árvíztűrő");
        var enc = p.Protect(plain);
        Assert.NotEqual(plain, enc);
        Assert.Equal("árvíztűrő", Encoding.UTF8.GetString(p.Unprotect(enc)));
    }

    [Fact]
    public void SettingsTomlHasNoSecretsAndRoundTrips()
    {
        using var tmp = new CoreTemp();
        var s = new Settings { Mode = "demo", Language = "en" };
        s.Ldap.Password = "ldap-secret";
        s.Vulns.ApiKey = "nvd-key-123";
        s.Sync.Key = "sync-secret";
        s.Ldap.User = "CORP\\svc \"quoted\"\nnext";
        s.Ldap.BaseDn = "DC=kovács,DC=hu";
        s.Scan.Ports = [445, 135];
        s.Scan.Timeout = 2;
        var text = Persist.SettingsToToml(s);
        foreach (var secret in new[] { "ldap-secret", "nvd-key-123", "sync-secret" })
            Assert.DoesNotContain(secret, text);
        Assert.Contains("timeout = 2.0", text);
        var path = tmp.File("sub/admiral.toml");
        Persist.SaveSettings(s, path);
        var back = Config.LoadSettings(path, new Dictionary<string, string>());
        Assert.Equal(s.Ldap.User, back.Ldap.User);
        Assert.Equal(s.Ldap.BaseDn, back.Ldap.BaseDn);
        Assert.Equal([445, 135], back.Scan.Ports);
        Assert.Equal(2.0, back.Scan.Timeout);
        Assert.Equal("en", back.Language);
        Assert.Equal("", back.Ldap.Password);
        Assert.False(File.Exists(tmp.File("sub/admiral.tmp")));
    }

    [Fact]
    public void SecretNames()
    {
        Assert.Equal(["ldap_password", "winrm_password", "proxy_password", "vulns_api_key", "sync_key"], Persist.SecretNames);
    }
}
