using System.Text.Json;
using ADmiral.Core;

namespace ADmiral.Tests;

public class ConfigTests
{
    private static readonly Dictionary<string, string> NoEnv = [];

    [Fact]
    public void EnvOverrides()
    {
        using var tmp = new CoreTemp();
        var cfg = tmp.File("a.toml");
        File.WriteAllText(cfg, Config.ExampleConfig);
        var s = Config.LoadSettings(cfg, new Dictionary<string, string>
        {
            ["ADMIRAL_LDAP_PASSWORD"] = "pw", ["ADMIRAL_SCAN_PORTS"] = "445,5985",
            ["ADMIRAL_STALE_DAYS"] = "30", ["ADMIRAL_WINRM_USE_HTTPS"] = "yes",
        });
        Assert.Equal("ldap", s.Mode);
        Assert.Equal("CORP\\svc-admiral", s.Ldap.User);
        Assert.Equal("pw", s.Ldap.Password);
        Assert.Equal([445, 5985], s.Scan.Ports);
        Assert.Equal(30, s.StaleDays);
        Assert.True(s.Winrm.UseHttps);
        Assert.Equal(1.0, s.Scan.Timeout);
        Assert.Equal("dc01.corp.local", s.Ldap.Server);
    }

    [Fact]
    public void DefaultsAreAd()
    {
        Assert.Equal("ldap", new Settings().Mode);
        Config.ValidateSettings(new Settings(), requireLdap: false);
        Assert.Throws<ConfigError>(() => Config.ValidateSettings(new Settings()));   // ldap needs server + base_dn
    }

    [Fact]
    public void BadConfig()
    {
        using var tmp = new CoreTemp();
        var cfg = tmp.File("a.toml");
        File.WriteAllText(cfg, "mode = \"ldap\"\n");
        Assert.Throws<ConfigError>(() => Config.LoadSettings(cfg, NoEnv));            // no server / base_dn
        File.WriteAllText(cfg, "nonsense = 1\n");
        Assert.Throws<ConfigError>(() => Config.LoadSettings(cfg, NoEnv));
        File.WriteAllText(cfg, "mode = \"demo\"\n[ldap]\nport = \"x\"\n");
        Assert.Throws<ConfigError>(() => Config.LoadSettings(cfg, NoEnv));            // wrong type
        File.WriteAllText(cfg, "mode = \"demo\"\nldap = 3\n");
        Assert.Throws<ConfigError>(() => Config.LoadSettings(cfg, NoEnv));            // a section must be a table
        File.WriteAllText(cfg, "mode = = 1\n");
        Assert.Throws<ConfigError>(() => Config.LoadSettings(cfg, NoEnv));            // TOML syntax
    }

    [Fact]
    public void ExplicitMissingConfigIsAnError()
    {
        using var tmp = new CoreTemp();
        Assert.Throws<FileNotFoundException>(() => Config.LoadSettings(tmp.File("missing.toml"), NoEnv));
        Assert.Throws<FileNotFoundException>(() => Config.LoadSettings(null, new Dictionary<string, string>
        {
            ["ADMIRAL_CONFIG"] = tmp.File("none.toml"),
        }));
    }

    [Fact]
    public void LegacyKeysAreIgnoredAndUpdateLocationIsFixed()
    {
        using var tmp = new CoreTemp();
        var cfg = tmp.File("a.toml");
        File.WriteAllText(cfg, "mode = \"demo\"\n[appupdate]\nurl = \"https://evil.example/\"\npublic_key = \"x\"\n"
                               + "[packages]\nwinget_source = \"y\"\n");
        var s = Config.LoadSettings(cfg, new Dictionary<string, string> { ["ADMIRAL_APPUPDATE_URL"] = "https://evil2.example/" });
        Assert.Equal(Config.AppUpdateUrl, s.AppUpdate.Url);
    }

    [Theory]
    [InlineData("ADMIRAL_LDAP_AUTH", "ntlm")]
    [InlineData("ADMIRAL_WINRM_TRANSPORT", "basic")]           // clear text without HTTPS
    [InlineData("ADMIRAL_WINRM_TRANSPORT", "ssl")]             // also Basic: clear text without HTTPS
    [InlineData("ADMIRAL_SCAN_PORTS", "0")]
    [InlineData("ADMIRAL_SCAN_PORTS", "x")]
    [InlineData("ADMIRAL_LANGUAGE", "de")]
    [InlineData("ADMIRAL_SYNC_NETWORK", "10.0.0.0/99")]
    [InlineData("ADMIRAL_SYNC_CATEGORIES", "computers,secrets")]
    [InlineData("ADMIRAL_STALE_DAYS", "0")]
    [InlineData("ADMIRAL_COLLECT_RESPONSE_TIMEOUT", "4")]
    [InlineData("ADMIRAL_LDAP_UNKNOWN", "1")]
    public void InvalidValuesAreRejected(string key, string value)
    {
        Assert.Throws<ConfigError>(() => Config.LoadSettings(null, new Dictionary<string, string>
        {
            ["ADMIRAL_MODE"] = "demo", ["ADMIRAL_CONFIG"] = "", [key] = value,
        }));
    }

    [Fact]
    public void EnvListsAndUnknownTopLevelNames()
    {
        var s = Config.LoadSettings(null, new Dictionary<string, string>
        {
            ["ADMIRAL_MODE"] = "demo", ["ADMIRAL_SYNC_CATEGORIES"] = "computers, users", ["ADMIRAL_SOMETHING_ELSE"] = "ignored",
            ["ADMIRAL_DB_PATH"] = "x.db",
        }, requireLdap: false);
        Assert.Equal(["computers", "users"], s.Sync.Categories);
        Assert.Equal("x.db", s.DbPath);
    }

    [Fact]
    public void SimpleBindNeedsLdaps()
    {
        var s = new Settings { Mode = "demo" };
        s.Ldap.Auth = "simple";
        s.Ldap.UseSsl = false;
        Assert.Throws<ConfigError>(() => Config.ValidateSettings(s));
        s.Ldap.Server = "ldaps://dc01";
        Config.ValidateSettings(s);
    }

    [Fact]
    public void SyncNetworkAcceptsHostBits()
    {
        var s = new Settings { Mode = "demo" };
        s.Sync.Network = "192.168.1.77/24";
        Config.ValidateSettings(s);
        Assert.Equal("192.168.1.0/24", Config.NormalizeCidr("192.168.1.77/24"));
        Assert.Equal("10.1.2.3/32", Config.NormalizeCidr("10.1.2.3"));
    }

    [Fact]
    public void JsonUsesTheUiFieldNames()
    {
        var json = JsonSerializer.Serialize(new Settings());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("ldap", root.GetProperty("mode").GetString());
        Assert.True(root.GetProperty("debug_log").GetBoolean());
        Assert.Equal("", root.GetProperty("ldap").GetProperty("base_dn").GetString());
        Assert.Equal(30, root.GetProperty("collect").GetProperty("smb_timeout").GetInt32());
        Assert.Equal(5, root.GetProperty("scan").GetProperty("ports").GetArrayLength());
        Assert.Equal(Config.AppUpdateUrl, root.GetProperty("appupdate").GetProperty("url").GetString());
        Assert.True(root.TryGetProperty("filecollect", out _));
        var back = JsonSerializer.Deserialize<Settings>("""{"ldap": {"base_dn": "DC=x"}, "scan": {"interval_minutes": 5}}""")!;
        Assert.Equal("DC=x", back.Ldap.BaseDn);
        Assert.Equal(5, back.Scan.IntervalMinutes);
    }

    [Fact]
    public void EditableAndSecretFieldsExist()
    {
        var s = new Settings();
        foreach (var (section, keys) in Config.Editable)
        {
            var target = section.Length == 0 ? s : Config.Section(s, section)!;
            foreach (var key in keys) Assert.NotNull(Config.Field(target.GetType(), key));
        }
        foreach (var (section, key) in Config.SecretFields)
            Assert.Equal("", Config.GetValue(Config.Section(s, section)!, key));
    }

    [Fact]
    public void ApplyCoercesJsonValues()
    {
        var s = new Settings();
        using var doc = JsonDocument.Parse("""{"port": 9000, "use_ssl": false, "user": "u"}""");
        Config.Apply(s.Ldap, doc.RootElement.EnumerateObject().Select(p => KeyValuePair.Create(p.Name, (object?)p.Value)), "test");
        Assert.Equal(9000, s.Ldap.Port);
        Assert.False(s.Ldap.UseSsl);
        Assert.Equal("u", s.Ldap.User);
    }
}
