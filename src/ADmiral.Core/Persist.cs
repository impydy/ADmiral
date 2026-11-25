using System.Collections;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// Saving settings from the UI, and storing passwords safely (port of admiral/persist.py).
//
// Passwords never go into admiral.toml. On Windows they are encrypted with DPAPI (ProtectedData, CurrentUser
// scope), which ties the ciphertext to the current Windows user account, and saved in secrets.json next to the
// config. On other platforms they are kept in memory for the session only (use the ADMIRAL_*_PASSWORD
// environment variables) - exactly like the Python version; nothing is ever written in clear text.

/// <summary>Encrypts / decrypts secret values for <see cref="SecretStore"/> (DPAPI in production, a fake in tests).</summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] data);
    byte[] Unprotect(byte[] data);
}

/// <summary>Windows DPAPI bound to the current Windows user (CryptProtectData, UI forbidden).</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiProtector : ISecretProtector
{
    // Extra entropy: a blob is only usable by ADmiral, not by any other program running as the same user that
    // simply calls CryptUnprotectData on it.
    private static readonly byte[] Entropy = "ADmiral secret store v1"u8.ToArray();

    public byte[] Protect(byte[] data) => ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] data) => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser);
}

/// <summary>Named secrets (ldap_password, winrm_password, proxy_password, vulns_api_key, sync_key).</summary>
public sealed class SecretStore
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, string> _mem = new(StringComparer.Ordinal);
    // entries this Windows user cannot decrypt (saved by another user of the shared data folder): kept as they are
    // when the file is written again, so starting ADmiral as someone else never wipes them
    private readonly Dictionary<string, string> _foreign = new(StringComparer.Ordinal);
    private readonly ISecretProtector? _protector;
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public string? Path { get; }

    /// <summary>True when the secrets are saved (encrypted) to <see cref="Path"/>; false = memory only.</summary>
    public bool Persistent { get; }

    /// <param name="path">secrets.json; null = memory only.</param>
    /// <param name="protector">The encryption to use; null = DPAPI on Windows, memory only elsewhere.</param>
    public SecretStore(string? path, ISecretProtector? protector = null)
    {
        Path = path;
        _protector = protector ?? (OperatingSystem.IsWindows() ? new DpapiProtector() : null);
        Persistent = _protector is not null && path is not null;
        if (!Persistent || !File.Exists(path)) return;

        Dictionary<string, string>? raw = null;
        try
        {
            raw = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path!, Encoding.UTF8));
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            Log.Logger.LogWarning(ex, "Saved passwords in {Path} cannot be read", path);
        }
        foreach (var (k, v) in raw ?? [])
        {
            try
            {
                _mem[k] = Encoding.UTF8.GetString(_protector!.Unprotect(Convert.FromBase64String(v)));
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
            {
                _foreign[k] = v;
            }
        }
        if (_foreign.Count > 0)
            Log.Logger.LogWarning("Saved passwords in {Path} ({Names}) could not be decrypted (another Windows user or "
                                  + "profile?); they must be entered again", path, string.Join(", ", _foreign.Keys.Order(StringComparer.Ordinal)));
    }

    /// <summary>True when the saved file holds <paramref name="name"/> but this Windows user cannot decrypt it (it was
    /// saved by another account): it must not be replaced, or the other account loses it.</summary>
    public bool IsForeign(string name)
    {
        lock (_lock) return _foreign.ContainsKey(name);
    }

    public string Get(string name)
    {
        lock (_lock) return _mem.GetValueOrDefault(name, "");
    }

    /// <summary>Set (or with an empty value remove) a secret; a persistent store rewrites secrets.json at once.</summary>
    public void Set(string name, string? value)
    {
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(value)) _mem[name] = value;
            else _mem.Remove(name);
            _foreign.Remove(name);
            if (!Persistent) return;
            var enc = new SortedDictionary<string, string>(_foreign, StringComparer.Ordinal);
            foreach (var (k, v) in _mem)
                enc[k] = Convert.ToBase64String(_protector!.Protect(Encoding.UTF8.GetBytes(v)));
            var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path!));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = Path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(enc, Indented), new UTF8Encoding(false));
            File.Move(tmp, Path!, overwrite: true);
        }
    }

    /// <summary>Fill the secrets of <paramref name="settings"/> from the store unless the environment already supplied them.</summary>
    public void Apply(Settings settings)
    {
        foreach (var (sect, key) in Config.SecretFields)
        {
            var target = Config.Section(settings, sect)!;
            var field = Config.Field(target.GetType(), key)!;
            if (string.IsNullOrEmpty((string?)field.Get(target)))
                field.Property.SetValue(target, Get($"{sect}_{key}"));
        }
    }
}

public static class Persist
{
    /// <summary>The names of the secrets in the store: ldap_password, winrm_password, proxy_password, vulns_api_key, sync_key.</summary>
    public static readonly IReadOnlyList<string> SecretNames = [.. Config.SecretFields.Select(kv => $"{kv.Key}_{kv.Value}")];

    /// <summary>A TOML value (string, bool, integer, float or list of them).</summary>
    public static string TomlValue(object? v) => v switch
    {
        null => "\"\"",
        bool b => b ? "true" : "false",
        int or long or short or byte or uint or ulong => Convert.ToString(v, CultureInfo.InvariantCulture)!,
        double d => TomlFloat(d),
        float f => TomlFloat(f),
        string s => TomlString(s),
        IEnumerable e => "[" + string.Join(", ", e.Cast<object?>().Select(TomlValue)) + "]",
        _ => TomlString(Convert.ToString(v, CultureInfo.InvariantCulture) ?? ""),
    };

    private static string TomlFloat(double d)
    {
        if (double.IsNaN(d)) return "nan";
        if (double.IsInfinity(d)) return d > 0 ? "inf" : "-inf";
        var s = d.ToString("R", CultureInfo.InvariantCulture);
        return s.Contains('.') || s.Contains('E') || s.Contains('e') ? s : s + ".0";
    }

    /// <summary>A TOML basic string with every character that needs it escaped.</summary>
    public static string TomlString(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (char.IsControl(c)) sb.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    /// <summary>admiral.toml text of <paramref name="settings"/>, without any secret.</summary>
    public static string SettingsToToml(Settings settings)
    {
        var lines = new List<string> { "# Written by ADmiral. Passwords are stored separately (encrypted), not here.", "" };
        var fields = Config.Fields(typeof(Settings));
        foreach (var f in fields.Where(f => !f.IsSection))
            lines.Add($"{f.Name} = {TomlValue(f.Get(settings))}");
        foreach (var f in fields.Where(f => f.IsSection))
        {
            var section = f.Get(settings)!;
            Config.SecretFields.TryGetValue(f.Name, out var secret);
            lines.Add("");
            lines.Add($"[{f.Name}]");
            foreach (var g in Config.Fields(section.GetType()))
                if (g.Name != secret)
                    lines.Add($"{g.Name} = {TomlValue(g.Get(section))}");
        }
        return string.Join("\n", lines) + "\n";
    }

    /// <summary>Write admiral.toml atomically (temporary file, then rename).</summary>
    public static void SaveSettings(Settings settings, string path)
    {
        var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = System.IO.Path.ChangeExtension(path, ".tmp");
        File.WriteAllText(tmp, SettingsToToml(settings), new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }
}
