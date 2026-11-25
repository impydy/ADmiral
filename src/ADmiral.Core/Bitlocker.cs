using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>ADmiral's RSA key pair for the BitLocker recovery passwords.
/// <para>The inventory script gets the <i>public</i> key and encrypts every recovery password on the computer itself
/// (RSA-OAEP), so the result file, the network and the database only ever hold ciphertext. The <i>private</i> key lives
/// in the <see cref="SecretStore"/> (DPAPI, bound to the Windows user running ADmiral) and is used only to show one key
/// after the administrator's password was checked again.</para>
/// <para>No key pair is made when it could not be kept (a memory-only secret store, except in demo mode), and one saved
/// by another Windows account is never replaced (that account would lose its keys): then recovery keys are simply not
/// collected.</para></summary>
public sealed partial class BitlockerVault(SecretStore secrets, Func<bool> ephemeralAllowed)
{
    public const string SecretName = "bitlocker_rsa";
    public const int KeyBits = 3072;

    private readonly Lock _lock = new();
    private RSA? _rsa;
    private bool _failed;

    [GeneratedRegex(@"\A\d{6}(-\d{6}){7}\z")]
    private static partial Regex RecoveryRe();

    /// <summary>The shape of a BitLocker recovery password: 8 groups of 6 digits.</summary>
    public static bool ValidRecoveryPassword(string? s) => RecoveryRe().IsMatch(s ?? "");

    private RSA? Key()
    {
        lock (_lock)
        {
            if (_rsa is not null || _failed) return _rsa;
            var saved = secrets.Get(SecretName);
            if (saved.Length > 0)
            {
                try
                {
                    var rsa = RSA.Create();
                    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(saved), out _);
                    return _rsa = rsa;
                }
                catch (Exception exc) when (exc is CryptographicException or FormatException)
                {
                    Log.Logger.LogError("The BitLocker key pair in the secret store cannot be read ({Error}); recovery keys are not collected", exc.Message);
                    _failed = true;                                    // never overwrite it: the stored keys need it
                    return null;
                }
            }
            if (secrets.IsForeign(SecretName) || (!secrets.Persistent && !ephemeralAllowed())) return null;
            var fresh = RSA.Create(KeyBits);
            secrets.Set(SecretName, Convert.ToBase64String(fresh.ExportPkcs8PrivateKey()));
            if (Log.Logger.IsEnabled(LogLevel.Information))
                Log.Logger.LogInformation("New BitLocker key pair made ({Bits} bit RSA) and saved in the secret store", KeyBits);
            return _rsa = fresh;
        }
    }

    /// <summary>The public key for the inventory script (.NET XML form, read by RSACryptoServiceProvider.FromXmlString),
    /// or null when recovery keys cannot be kept.</summary>
    public string? PublicKeyXml => Key()?.ToXmlString(false);

    /// <summary>Encrypt like the computer does (demo data, tests).</summary>
    public string Encrypt(string plain) =>
        Convert.ToBase64String((Key() ?? throw new InvalidOperationException("no BitLocker key pair")).Encrypt(Encoding.UTF8.GetBytes(plain), RSAEncryptionPadding.OaepSHA1));

    /// <summary>Decrypt one stored recovery password. Throws <see cref="CryptographicException"/> (e.g. the key pair
    /// changed since it was collected) or <see cref="FormatException"/>.</summary>
    public string Decrypt(string cipherBase64)
    {
        var key = Key() ?? throw new CryptographicException("no BitLocker key pair");
        return Encoding.UTF8.GetString(key.Decrypt(Convert.FromBase64String(cipherBase64), RSAEncryptionPadding.OaepSHA1));
    }
}
