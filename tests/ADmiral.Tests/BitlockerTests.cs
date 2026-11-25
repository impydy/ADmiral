using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>BitLocker: the recovery keys are encrypted on the computer, stored only as ciphertext, never part of the
/// inventory, and shown only after the administrator's password was checked again (with a lockout).</summary>
public sealed class BitlockerTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => [.. data.Select(b => (byte)(b ^ 0x5A))];
        public byte[] Unprotect(byte[] data) => Protect(data);
    }

    private sealed class ForeignProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;
        public byte[] Unprotect(byte[] data) => throw new CryptographicException("another user");
    }

    [Fact]
    public void KeyPairIsMadeOnlyWhereItCanBeKept()
    {
        using var tmp = new CoreTemp();
        var path = tmp.File("secrets.json");
        var store = new SecretStore(path, new XorProtector());
        var vault = new BitlockerVault(store, () => false);
        var pub = vault.PublicKeyXml;
        Assert.NotNull(pub);
        Assert.DoesNotContain("<D>", pub);                                 // never the private part
        Assert.NotEmpty(store.Get(BitlockerVault.SecretName));
        // a second instance (restart) uses the saved key: what the first one encrypted, it decrypts
        var c = vault.Encrypt("111111-222222-333333-444444-555555-666666-777777-888888");
        var again = new BitlockerVault(new SecretStore(path, new XorProtector()), () => false);
        Assert.Equal("111111-222222-333333-444444-555555-666666-777777-888888", again.Decrypt(c));
        // memory-only store: no key pair (it would be lost at the next start)
        Assert.Null(new BitlockerVault(new SecretStore(null), () => false).PublicKeyXml);
        // saved by another Windows account: never replaced, nothing collected
        var foreign = new SecretStore(path, new ForeignProtector());
        Assert.True(foreign.IsForeign(BitlockerVault.SecretName));
        Assert.Null(new BitlockerVault(foreign, () => false).PublicKeyXml);
        Assert.Contains(BitlockerVault.SecretName, File.ReadAllText(path));
    }

    [Fact]
    public void ScriptEncryptsOnTheComputerAndOnlyWhenAsked()
    {
        var xml = new BitlockerVault(new SecretStore(null), () => true).PublicKeyXml!;
        var with = Collector.CombinedScript(xml);
        Assert.Contains("$r.bitlocker_keys = ", with);
        Assert.Contains("$rsa.Encrypt(", with);
        Assert.Contains(xml, with);
        var without = Collector.CombinedScript();
        Assert.Contains("$r.bitlocker = ", without);                       // the state is always read
        Assert.DoesNotContain("RecoveryPassword", without);                // the keys only with a public key
        Assert.DoesNotContain("bitlocker_keys", Offline.RenderScript());    // never into the shared folder files
        Assert.ThrowsAny<ArgumentException>(() => Collector.CombinedScript("<RSAKeyValue>'; calc; '</RSAKeyValue>"));
    }

    [PwshFact]
    public void ScriptWithTheKeyIsValidPowerShell()
    {
        using var tmp = new CoreTemp();
        PowerShellTests.AssertParses(Collector.CombinedScript(new BitlockerVault(new SecretStore(null), () => true).PublicKeyXml), tmp);
    }

    [PwshFact]
    public void WhatPowerShellEncryptsWithTheXmlKeyTheServerDecrypts()
    {
        // RSACryptoServiceProvider.Encrypt(data, $true) on Windows = RSA OAEP-SHA1; emulated here with RSA (cross-platform)
        var vault = new BitlockerVault(new SecretStore(null), () => true);
        const string pw = "482306-115247-660154-218900-057321-394411-702185-669548";
        var (code, stdout, stderr, _) = Pwsh.Run($"$rsa = [System.Security.Cryptography.RSA]::Create(); $rsa.FromXmlString({Deploy.Q(vault.PublicKeyXml!)}); " +
            $"[Convert]::ToBase64String($rsa.Encrypt([Text.Encoding]::UTF8.GetBytes('{pw}'), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1))");
        Assert.True(code == 0, stderr);
        Assert.Equal(pw, vault.Decrypt(stdout.Trim()));
    }

    [Fact]
    public void KeysNeverReachTheInventory()
    {
        var s = new Store(":memory:");
        s.UpsertFromAd([new Dictionary<string, object?> { ["guid"] = "g1", ["name"] = "PC1", ["dn"] = "CN=PC1,DC=x", ["ou"] = "x", ["enabled"] = true }]);
        s.RecordInventory("g1", new JsonObject
        {
            ["model"] = "M", ["bitlocker_keys"] = new JsonArray(new JsonObject { ["drive"] = "C:", ["id"] = "{1}", ["plain"] = "123456-123456-123456-123456-123456-123456-123456-123456" }),
            ["bitlocker"] = new JsonArray(new JsonObject { ["drive"] = "C:", ["protection"] = "On" }),
        });
        var inv = (JsonObject)s.Computer("g1")!["inventory"]!;
        Assert.False(inv.ContainsKey("bitlocker_keys"));
        Assert.DoesNotContain("123456-", s.Query("SELECT inventory FROM computers").Single()["inventory"] as string);
        Assert.Single(s.Items("g1")["bitlocker"]);
    }

    private (Row Computer, string KeyId) Encrypted()
    {
        App.FullScan();
        var lt = App.Computers().First(c => ((string)c["name"]!).StartsWith("LT-", StringComparison.Ordinal) && c["inventory"] is not null);
        var detail = App.Computer((string)lt["guid"]!);
        var keys = (List<Row>)detail["bitlocker_keys"]!;
        Assert.NotEmpty(keys);
        Assert.All(keys, k => Assert.False(k.ContainsKey("cipher") || k.ContainsKey("key")));   // the list never carries a key
        return (detail, (string)keys[0]["id"]!);
    }

    [Fact]
    public void KeyIsShownOnlyWithTheAdminPasswordAndIsLogged()
    {
        var (c, id) = Encrypted();
        var guid = (string)c["guid"]!;
        var cipher = App.Store.BitlockerCipher(guid, id)!;
        Assert.DoesNotMatch(@"\d{6}-\d{6}", cipher);                       // stored as ciphertext only
        Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey(guid, id, "wrong"));
        Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey(guid, id, ""));
        var r = App.RevealBitlockerKey(guid, id, "demo");
        Assert.True(BitlockerVault.ValidRecoveryPassword((string)r["key"]!));
        var entries = App.Activity().Where(a => (string?)a["action"] == "bitlocker").ToList();
        Assert.Equal(3, entries.Count);                                     // two refusals + one view
        var log = string.Join("\n", App.Activity().Select(a => a["detail"]));
        Assert.Contains(id, log);
        Assert.DoesNotContain((string)r["key"]!, log);                     // the key itself is never logged
        Assert.Throws<NotFound>(() => App.RevealBitlockerKey(guid, "{no-such-key}", "demo"));
    }

    [Fact]
    public void TooManyWrongPasswordsLockEvenTheRightOne()
    {
        var (c, id) = Encrypted();
        var guid = (string)c["guid"]!;
        for (var i = 0; i < AdmiralService.BitlockerMaxFailures; i++)
            Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey(guid, id, "guess" + i));
        var ex = Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey(guid, id, "demo"));
        Assert.Contains("15", ex.Message);
    }

    [Fact]
    public void RealModeChecksThePasswordWithAFreshBind()
    {
        var (c, id) = Encrypted();
        var seen = new List<string>();
        App.AdminPasswordCheck = pw => { seen.Add(pw); return pw == "S3cret!"; };
        Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey((string)c["guid"]!, id, "demo"));
        Assert.NotNull(App.RevealBitlockerKey((string)c["guid"]!, id, "S3cret!")["key"]);
        Assert.Equal(["demo", "S3cret!"], seen);
    }

    [Fact]
    public void AnotherKeyPairCannotOpenStoredKeys()
    {
        var (c, id) = Encrypted();
        var guid = (string)c["guid"]!;
        // a key encrypted with some other key pair (e.g. the secret store was reset) is refused, not mangled
        var other = new BitlockerVault(new SecretStore(null), () => true);
        App.Store.SetBitlockerKeys(guid, [("C:", id, other.Encrypt("123456-123456-123456-123456-123456-123456-123456-123456"))]);
        Assert.Throws<ArgumentException>(() => App.RevealBitlockerKey(guid, id, "demo"));
    }
}
