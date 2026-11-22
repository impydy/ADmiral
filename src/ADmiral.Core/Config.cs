using System.Collections;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text.Json.Serialization;
using Tomlyn;
using Tomlyn.Model;

namespace ADmiral.Core;

// Configuration loading (port of admiral/config.py).
//
// Settings come from (lowest to highest precedence):
//   1. built-in defaults
//   2. a TOML file (admiral.toml in the working directory, or ADMIRAL_CONFIG)
//   3. environment variables (ADMIRAL_*)
//
// Secrets (bind / WinRM passwords) should be supplied through environment variables (or the encrypted
// secret store, see Persist.cs) rather than written to the TOML file.
//
// Every settings property carries a [JsonPropertyName] with its snake_case name: the same name is the TOML key,
// the ADMIRAL_* environment suffix and the field name of the settings JSON the web UI reads and writes.

/// <summary>A setting is invalid (unknown key, wrong type, value out of range). Counterpart of Python's
/// <c>ValueError</c> raised by config.py; derives from <see cref="ArgumentException"/>, which the job runner treats
/// as an expected, explained failure.</summary>
public sealed class ConfigError(string message, Exception? inner = null) : ArgumentException(message, inner);

public sealed class LdapSettings
{
    /// <summary>e.g. "dc01.corp.local" or "ldaps://dc01.corp.local"</summary>
    [JsonPropertyName("server")] public string Server { get; set; } = "";
    /// <summary>0 = default (389 / 636)</summary>
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("use_ssl")] public bool UseSsl { get; set; } = true;
    /// <summary>e.g. "DC=corp,DC=local"</summary>
    [JsonPropertyName("base_dn")] public string BaseDn { get; set; } = "";
    /// <summary>kerberos (primary) | simple (explicit choice only, needs LDAPS)</summary>
    [JsonPropertyName("auth")] public string Auth { get; set; } = "kerberos";
    /// <summary>after a Kerberos *authentication* failure try NTLMv2</summary>
    [JsonPropertyName("ntlm_fallback")] public bool NtlmFallback { get; set; }
    /// <summary>"CORP\svc-admiral" or UPN; empty = current Windows logon (Kerberos)</summary>
    [JsonPropertyName("user")] public string User { get; set; } = "";
    [JsonPropertyName("password")] public string Password { get; set; } = "";
    [JsonPropertyName("search_filter")] public string SearchFilter { get; set; } = "(objectCategory=computer)";
    [JsonPropertyName("page_size")] public int PageSize { get; set; } = 500;
    [JsonPropertyName("verify_cert")] public bool VerifyCert { get; set; } = true;
    [JsonPropertyName("ca_file")] public string CaFile { get; set; } = "";
}

public sealed class WinRMSettings
{
    [JsonPropertyName("user")] public string User { get; set; } = "";
    [JsonPropertyName("password")] public string Password { get; set; } = "";
    /// <summary>kerberos | ntlm | credssp | basic | ssl</summary>
    [JsonPropertyName("transport")] public string Transport { get; set; } = "kerberos";
    /// <summary>kerberos transport only: retry with NTLMv2 after an auth failure</summary>
    [JsonPropertyName("ntlm_fallback")] public bool NtlmFallback { get; set; }
    [JsonPropertyName("use_https")] public bool UseHttps { get; set; }
    [JsonPropertyName("verify_cert")] public bool VerifyCert { get; set; } = true;
    [JsonPropertyName("timeout")] public int Timeout { get; set; } = 20;
    [JsonPropertyName("workers")] public int Workers { get; set; } = 16;
}

/// <summary>How inventory is gathered from the targets. "pdq": agentless over SMB (ADMIN$ + a temporary
/// LocalSystem service), the primary method; "winrm": PowerShell remoting, also the per-host fallback.</summary>
public sealed class CollectSettings
{
    /// <summary>pdq | winrm</summary>
    [JsonPropertyName("method")] public string Method { get; set; } = "pdq";
    /// <summary>pdq method: if SMB collection fails on a host, try WinRM</summary>
    [JsonPropertyName("winrm_fallback")] public bool WinrmFallback { get; set; } = true;
    /// <summary>seconds for each SMB / RPC connection to a host</summary>
    [JsonPropertyName("smb_timeout")] public int SmbTimeout { get; set; } = 30;
    /// <summary>seconds to wait for the computer's answer after the service started</summary>
    [JsonPropertyName("response_timeout")] public int ResponseTimeout { get; set; } = 300;
    /// <summary>seconds after the answer (or the timeout) before the self-check runs</summary>
    [JsonPropertyName("cleanup_delay")] public int CleanupDelay { get; set; } = 10;
}

public sealed class ScanSettings
{
    [JsonPropertyName("ports")] public List<int> Ports { get; set; } = [135, 445, 3389, 5985, 5986];
    [JsonPropertyName("timeout")] public double Timeout { get; set; } = 1.0;
    [JsonPropertyName("workers")] public int Workers { get; set; } = 64;
    /// <summary>reachability check (ping) of all computers every N minutes; 0 = only by hand</summary>
    [JsonPropertyName("interval_minutes")] public int IntervalMinutes { get; set; }
}

/// <summary>Background retry service (a Windows service on the machine running ADmiral).</summary>
public sealed class RetrySettings
{
    [JsonPropertyName("interval_minutes")] public int IntervalMinutes { get; set; } = 30;
    /// <summary>retry computers that were offline when queried</summary>
    [JsonPropertyName("offline")] public bool Offline { get; set; } = true;
    /// <summary>retry computers whose inventory collection failed</summary>
    [JsonPropertyName("failed")] public bool Failed { get; set; } = true;
}

/// <summary>Proxy (and its account) for the internet access ADmiral itself needs. Empty url = the system /
/// environment proxy settings.</summary>
public sealed class ProxySettings
{
    /// <summary>e.g. "http://proxy.corp.local:8080"</summary>
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    /// <summary>proxy auto-config (wpad.dat): file path, http(s) URL or "auto"; used when url is empty</summary>
    [JsonPropertyName("pac")] public string Pac { get; set; } = "";
    [JsonPropertyName("user")] public string User { get; set; } = "";
    /// <summary>kept in the encrypted secret store, never in admiral.toml</summary>
    [JsonPropertyName("password")] public string Password { get; set; } = "";
}

/// <summary>Monitoring of the security-update state of the computers.</summary>
public sealed class UpdatesSettings
{
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    /// <summary>how often the Microsoft release data is re-downloaded</summary>
    [JsonPropertyName("refresh_hours")] public int RefreshHours { get; set; } = 24;
    /// <summary>a newer release only counts as missing after this many days</summary>
    [JsonPropertyName("grace_days")] public int GraceDays { get; set; }
    /// <summary>how many monthly releases to read</summary>
    [JsonPropertyName("months")] public int Months { get; set; } = 3;
}

/// <summary>ADmiral's own updates: a signed manifest and the installers, only from the official release location
/// (<see cref="Config.AppUpdateUrl"/>). The location is not a setting: admiral.toml, the environment and the
/// settings screen cannot change it, and the signing key is built into the program.</summary>
public sealed class AppUpdateSettings
{
    /// <summary>look for a new version at start-up and every 24 hours</summary>
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    /// <summary>fixed (ignored in admiral.toml / the environment)</summary>
    [JsonPropertyName("url")] public string Url => Config.AppUpdateUrl;
    /// <summary>go through the proxy settings</summary>
    [JsonPropertyName("use_proxy")] public bool UseProxy { get; set; } = true;
}

/// <summary>Login tracking: a fallback for the logon history when the computers' event logs cannot be read.</summary>
public sealed class LoginSettings
{
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
    /// <summary>shared folder the logon script writes to, e.g. \\server\logins$</summary>
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    /// <summary>how often the folder is read; the files are deleted after reading</summary>
    [JsonPropertyName("interval_minutes")] public int IntervalMinutes { get; set; } = 5;
}

/// <summary>Inventory files delivered by computers that cannot reach this machine (ADmiral-Collect.ps1).</summary>
public sealed class OfflineSettings
{
    /// <summary>shared folder the script writes to, e.g. \\server\admiral-inbox</summary>
    [JsonPropertyName("inbox")] public string Inbox { get; set; } = "";
    /// <summary>also accept files owned by a user account (logon scripts / copied by hand), not only by the computer
    /// account the file names; off by default because any user who can write the folder could forge them</summary>
    [JsonPropertyName("offline_allow_users")] public bool OfflineAllowUsers { get; set; }
}

/// <summary>CVE matching of the installed software (NVD data, downloaded through the optional proxy).</summary>
public sealed class VulnSettings
{
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    /// <summary>how often a program's CVE list is re-downloaded</summary>
    [JsonPropertyName("refresh_days")] public int RefreshDays { get; set; } = 7;
    /// <summary>optional NVD API key; saved encrypted</summary>
    [JsonPropertyName("api_key")] public string ApiKey { get; set; } = "";
}

/// <summary>Package library: installers added by hand into one folder.</summary>
public sealed class PackagesSettings
{
    /// <summary>empty = "packages" next to the database</summary>
    [JsonPropertyName("folder")] public string Folder { get; set; } = "";
}

/// <summary>Software deployment (Deployments page).</summary>
public sealed class DeploySettings
{
    /// <summary>an installer that runs longer than this on a computer counts as failed</summary>
    [JsonPropertyName("timeout_minutes")] public int TimeoutMinutes { get; set; } = 10;
}

/// <summary>Data synchronisation between ADmiral instances on the same network (encrypted, shared key).</summary>
public sealed class SyncSettings
{
    /// <summary>listen for the peer (and allow syncing)</summary>
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
    /// <summary>TCP port this instance listens on for the peer</summary>
    [JsonPropertyName("port")] public int Port { get; set; } = 8766;
    /// <summary>the other instances: "host" or "host:port", comma-separated</summary>
    [JsonPropertyName("peer")] public string Peer { get; set; } = "";
    /// <summary>CIDR the peer must be in; empty = this machine's own /24</summary>
    [JsonPropertyName("network")] public string Network { get; set; } = "";
    /// <summary>automatic sync every N minutes; 0 = only when started by hand</summary>
    [JsonPropertyName("interval_minutes")] public int IntervalMinutes { get; set; }
    [JsonPropertyName("categories")] public List<string> Categories { get; set; } = [.. Config.SyncCategories];
    /// <summary>the shared key (encrypted secret store, never in admiral.toml)</summary>
    [JsonPropertyName("key")] public string Key { get; set; } = "";
}

public sealed class Settings
{
    /// <summary>ldap (Active Directory, default) | demo</summary>
    [JsonPropertyName("mode")] public string Mode { get; set; } = "ldap";
    [JsonPropertyName("db_path")] public string DbPath { get; set; } = "admiral.db";
    [JsonPropertyName("stale_days")] public int StaleDays { get; set; } = 45;
    [JsonPropertyName("host")] public string Host { get; set; } = "127.0.0.1";
    [JsonPropertyName("port")] public int Port { get; set; } = 8765;
    /// <summary>hu | en (UI + log messages)</summary>
    [JsonPropertyName("language")] public string Language { get; set; } = "hu";
    /// <summary>system | light | dark</summary>
    [JsonPropertyName("theme")] public string Theme { get; set; } = "system";
    /// <summary>write admiral-debug.log; off = only admiral.log + the error ledger</summary>
    [JsonPropertyName("debug_log")] public bool DebugLog { get; set; } = true;
    [JsonPropertyName("ldap")] public LdapSettings Ldap { get; set; } = new();
    [JsonPropertyName("winrm")] public WinRMSettings Winrm { get; set; } = new();
    [JsonPropertyName("collect")] public CollectSettings Collect { get; set; } = new();
    [JsonPropertyName("scan")] public ScanSettings Scan { get; set; } = new();
    [JsonPropertyName("retry")] public RetrySettings Retry { get; set; } = new();
    [JsonPropertyName("proxy")] public ProxySettings Proxy { get; set; } = new();
    [JsonPropertyName("updates")] public UpdatesSettings Updates { get; set; } = new();
    [JsonPropertyName("appupdate")] public AppUpdateSettings AppUpdate { get; set; } = new();
    [JsonPropertyName("logins")] public LoginSettings Logins { get; set; } = new();
    [JsonPropertyName("filecollect")] public OfflineSettings FileCollect { get; set; } = new();
    [JsonPropertyName("vulns")] public VulnSettings Vulns { get; set; } = new();
    [JsonPropertyName("packages")] public PackagesSettings Packages { get; set; } = new();
    [JsonPropertyName("deploy")] public DeploySettings Deploy { get; set; } = new();
    [JsonPropertyName("sync")] public SyncSettings Sync { get; set; } = new();
}

/// <summary>One setting of a settings object: its snake_case name and the CLR property behind it.</summary>
public sealed record SettingField(string Name, PropertyInfo Property)
{
    public Type Type => Property.PropertyType;
    public bool IsSection => Config.SectionTypes.Contains(Property.PropertyType);
    public bool IsWritable => Property.CanWrite;
    public object? Get(object owner) => Property.GetValue(owner);
}

public static class Config
{
    /// <summary>The only place ADmiral updates itself from.</summary>
    public const string AppUpdateUrl = "https://tidecrestlabs.com/admiral/releases/";

    public static readonly IReadOnlyList<string> SyncCategories = ["computers", "fleets", "users", "printers"];

    /// <summary>section -> the setting that is a secret (kept in the encrypted store, never in admiral.toml).</summary>
    public static readonly IReadOnlyDictionary<string, string> SecretFields = new Dictionary<string, string>
    {
        ["ldap"] = "password", ["winrm"] = "password", ["proxy"] = "password", ["vulns"] = "api_key", ["sync"] = "key",
    };

    /// <summary>Fields the settings screen may change, per section ("" = top level). Passwords are handled separately.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Editable = new Dictionary<string, IReadOnlyList<string>>
    {
        [""] = ["mode", "stale_days", "language", "theme", "debug_log"],
        ["ldap"] = ["server", "port", "use_ssl", "base_dn", "auth", "ntlm_fallback", "user", "search_filter", "verify_cert", "ca_file"],
        ["winrm"] = ["user", "transport", "ntlm_fallback", "use_https", "verify_cert", "timeout", "workers"],
        ["collect"] = ["method", "winrm_fallback", "smb_timeout", "response_timeout", "cleanup_delay"],
        ["scan"] = ["ports", "timeout", "workers", "interval_minutes"],
        ["retry"] = ["interval_minutes", "offline", "failed"],
        ["proxy"] = ["url", "pac", "user"],
        ["updates"] = ["enabled", "refresh_hours", "grace_days"],
        ["appupdate"] = ["enabled", "use_proxy"],
        ["logins"] = ["enabled", "path", "interval_minutes"],
        ["filecollect"] = ["inbox", "offline_allow_users"],
        ["vulns"] = ["enabled", "refresh_days"],
        ["packages"] = ["folder"],
        ["deploy"] = ["timeout_minutes"],
        ["sync"] = ["enabled", "port", "peer", "network", "interval_minutes", "categories"],
    };

    /// <summary>Section name -> settings class.</summary>
    public static readonly IReadOnlyDictionary<string, Type> Sections = new Dictionary<string, Type>
    {
        ["ldap"] = typeof(LdapSettings), ["winrm"] = typeof(WinRMSettings), ["collect"] = typeof(CollectSettings),
        ["scan"] = typeof(ScanSettings), ["retry"] = typeof(RetrySettings), ["proxy"] = typeof(ProxySettings),
        ["updates"] = typeof(UpdatesSettings), ["appupdate"] = typeof(AppUpdateSettings), ["logins"] = typeof(LoginSettings),
        ["filecollect"] = typeof(OfflineSettings), ["vulns"] = typeof(VulnSettings), ["packages"] = typeof(PackagesSettings),
        ["deploy"] = typeof(DeploySettings), ["sync"] = typeof(SyncSettings),
    };

    internal static readonly HashSet<Type> SectionTypes = [.. Sections.Values];

    /// <summary>Settings of older versions that are accepted in admiral.toml / the environment and ignored.</summary>
    private static readonly Dictionary<Type, HashSet<string>> LegacyKeys = new()
    {
        [typeof(PackagesSettings)] = ["winget_auto_update", "winget_source"],
        [typeof(AppUpdateSettings)] = ["public_key", "url"],       // the update location is fixed (AppUpdateUrl)
    };

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, IReadOnlyList<SettingField>> FieldCache = new();

    /// <summary>The settings of a settings class in declaration order (the counterpart of dataclasses.fields).</summary>
    public static IReadOnlyList<SettingField> Fields(Type type) => FieldCache.GetOrAdd(type, t =>
        t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
         .Where(p => p.GetCustomAttribute<JsonPropertyNameAttribute>() is not null)
         .OrderBy(p => p.MetadataToken)
         .Select(p => new SettingField(p.GetCustomAttribute<JsonPropertyNameAttribute>()!.Name, p))
         .ToList());

    public static SettingField? Field(Type type, string name) => Fields(type).FirstOrDefault(f => f.Name == name);

    /// <summary>The section object by name ("ldap", "sync", ...); null for an unknown name.</summary>
    public static object? Section(Settings settings, string name)
        => Sections.ContainsKey(name) ? Field(typeof(Settings), name)!.Get(settings) : null;

    /// <summary>Read a setting by its snake_case name.</summary>
    public static object? GetValue(object owner, string name)
        => (Field(owner.GetType(), name) ?? throw new ConfigError($"Unknown setting '{name}'")).Get(owner);

    /// <summary>Apply <paramref name="data"/> (TOML table, JSON-like dictionary or environment strings) to a settings
    /// object, coercing each value to the type of the setting. Unknown keys raise; legacy keys are ignored.</summary>
    public static void Apply(object obj, IEnumerable<KeyValuePair<string, object?>> data, string where)
    {
        var type = obj.GetType();
        LegacyKeys.TryGetValue(type, out var legacy);
        foreach (var (key, value) in data)
        {
            if (legacy is not null && legacy.Contains(key)) continue;    // setting of an older version: ignored
            var field = Field(type, key) ?? throw new ConfigError($"Unknown setting '{key}' in {where}");
            if (field.IsSection)
            {
                var table = AsTable(value) ?? throw new ConfigError($"[{key}] must be a table in {where}");
                Apply(field.Get(obj)!, table, $"{where} [{key}]");
            }
            else if (!field.IsWritable)
            {
                continue;                                                // computed (fixed) value
            }
            else
            {
                field.Property.SetValue(obj, Coerce(value, field.Type, $"{key} in {where}"));
            }
        }
    }

    private static IEnumerable<KeyValuePair<string, object?>>? AsTable(object? value) => value switch
    {
        TomlTable t => t.Select(kv => new KeyValuePair<string, object?>(kv.Key, kv.Value)),
        IDictionary<string, object?> d => d,
        IReadOnlyDictionary<string, object?> d => d,
        _ => null,
    };

    /// <summary>Coerce a value (a string from the environment, or a TOML / JSON value) to <paramref name="type"/>.</summary>
    public static object Coerce(object? value, Type type, string what)
    {
        if (value is System.Text.Json.JsonElement je) value = FromJson(je);
        else if (value is System.Text.Json.Nodes.JsonNode jn) value = FromJson(System.Text.Json.JsonSerializer.SerializeToElement(jn));
        try
        {
            if (type == typeof(string))
                return value as string ?? throw Bad();
            if (type == typeof(bool))
                return value switch
                {
                    bool b => b,
                    string s => s.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on",
                    _ => throw Bad(),
                };
            if (type == typeof(int))
                return value switch
                {
                    string s => int.Parse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture),
                    long l => checked((int)l),
                    int i => i,
                    double d when d == Math.Floor(d) => checked((int)d),
                    _ => throw Bad(),
                };
            if (type == typeof(double))
                return value switch
                {
                    string s => double.Parse(s.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture),
                    double d => d,
                    long l => (double)l,
                    int i => (double)i,
                    _ => throw Bad(),
                };
            if (type == typeof(List<int>))
                return value switch
                {
                    string s => s.Replace(" ", "").Split(',', StringSplitOptions.RemoveEmptyEntries)
                                 .Select(p => int.Parse(p, NumberStyles.Integer, CultureInfo.InvariantCulture)).ToList(),
                    IEnumerable e => e.Cast<object?>().Select(x => (int)Coerce(x, typeof(int), what)).ToList(),
                    _ => throw Bad(),
                };
            if (type == typeof(List<string>))
                return value switch
                {
                    string s => s.Replace(" ", "").Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
                    IEnumerable e => e.Cast<object?>().Select(x => (string)Coerce(x, typeof(string), what)).ToList(),
                    _ => throw Bad(),
                };
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or InvalidCastException)
        {
            throw new ConfigError($"Invalid value for {what}: {ex.Message}", ex);
        }
        throw Bad();

        ConfigError Bad() => new($"Invalid value for {what}: expected {TypeName(type)}, got {Describe(value)}");
    }

    private static string TypeName(Type t) => t == typeof(int) ? "an integer" : t == typeof(double) ? "a number"
        : t == typeof(bool) ? "true / false" : t == typeof(string) ? "a string" : "a list";

    private static string Describe(object? v) => v is null ? "nothing" : v is string ? "a string" : v.GetType().Name;

    private static object? FromJson(System.Text.Json.JsonElement e) => e.ValueKind switch
    {
        System.Text.Json.JsonValueKind.String => e.GetString(),
        System.Text.Json.JsonValueKind.True => true,
        System.Text.Json.JsonValueKind.False => false,
        System.Text.Json.JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
        System.Text.Json.JsonValueKind.Array => e.EnumerateArray().Select(FromJson).ToList(),
        System.Text.Json.JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => FromJson(p.Value)),
        _ => null,
    };

    /// <summary>Parse TOML text into a table; a syntax error becomes a <see cref="ConfigError"/>.</summary>
    public static TomlTable ParseToml(string text, string where)
    {
        try
        {
            return TomlSerializer.Deserialize<TomlTable>(text) ?? new TomlTable();
        }
        catch (TomlException ex)
        {
            throw new ConfigError($"{where} is not valid TOML: {ex.Message}", ex);
        }
    }

    /// <summary>Load the settings: defaults, then the TOML file (<paramref name="path"/>, ADMIRAL_CONFIG or
    /// ./admiral.toml), then the ADMIRAL_* environment variables; then validate.</summary>
    public static Settings LoadSettings(string? path = null, IReadOnlyDictionary<string, string>? env = null,
                                        bool requireLdap = true)
    {
        env ??= Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
            .ToDictionary(e => (string)e.Key, e => e.Value as string ?? "");
        var settings = new Settings();

        env.TryGetValue("ADMIRAL_CONFIG", out var envCfg);
        var explicitPath = !string.IsNullOrEmpty(path) ? path : !string.IsNullOrEmpty(envCfg) ? envCfg : null;
        var cfgPath = explicitPath ?? "admiral.toml";
        if (File.Exists(cfgPath))
            Apply(settings, AsTable(ParseToml(File.ReadAllText(cfgPath), cfgPath))!, cfgPath);
        else if (explicitPath is not null)
            throw new FileNotFoundException($"Config file not found: {cfgPath}", cfgPath);

        // ADMIRAL_MODE, ADMIRAL_LDAP_PASSWORD, ADMIRAL_WINRM_USER, ADMIRAL_SCAN_PORTS ...
        var topLevel = Fields(typeof(Settings)).Where(f => !f.IsSection).Select(f => f.Name).ToHashSet();
        foreach (var (key, value) in env.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (!key.StartsWith("ADMIRAL_", StringComparison.Ordinal) || key == "ADMIRAL_CONFIG") continue;
            var rest = key["ADMIRAL_".Length..].ToLowerInvariant();
            var parts = rest.Split('_', 2);
            var one = new[] { KeyValuePair.Create(parts.Length == 2 ? parts[1] : "", (object?)value) };
            if (parts.Length == 2 && Sections.ContainsKey(parts[0]))
                Apply(Section(settings, parts[0])!, one, $"env {key}");
            else if (topLevel.Contains(rest))
                Apply(settings, [KeyValuePair.Create(rest, (object?)value)], $"env {key}");
        }

        ValidateSettings(settings, requireLdap);
        return settings;
    }

    public static void ValidateSettings(Settings settings, bool requireLdap = true)
    {
        static void Check(bool ok, string message)
        {
            if (!ok) throw new ConfigError(message);
        }

        Check(settings.Mode is "demo" or "ldap", "mode must be 'demo' or 'ldap'");
        Check(!(requireLdap && settings.Mode == "ldap" && (settings.Ldap.Server.Length == 0 || settings.Ldap.BaseDn.Length == 0)),
              "ldap mode requires ldap.server and ldap.base_dn");
        Check(settings.Ldap.Auth is "kerberos" or "simple", "ldap.auth must be 'kerberos' or 'simple'");
        Check(settings.Winrm.Transport is "ntlm" or "kerberos" or "credssp" or "basic" or "ssl",
              "winrm.transport must be ntlm, kerberos, credssp, basic or ssl");
        // passwords never travel in clear text
        Check(!(settings.Ldap.Auth == "simple" && !(settings.Ldap.UseSsl
                  || settings.Ldap.Server.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase))),
              "ldap.auth = 'simple' sends the password in clear text: turn on LDAPS (use_ssl)");
        // "ssl" is Basic authentication too (PowerShell -Authentication Basic): only ever inside HTTPS
        Check(!(settings.Winrm.Transport is "basic" or "ssl" && !settings.Winrm.UseHttps),
              $"winrm.transport = '{settings.Winrm.Transport}' sends the password in clear text: turn on HTTPS (use_https)");
        Check(settings.Collect.Method is "pdq" or "winrm", "collect.method must be 'pdq' or 'winrm'");
        Check(settings.Collect.ResponseTimeout is >= 5 and <= 3600, "collect.response_timeout must be between 5 and 3600 seconds");
        Check(settings.Collect.CleanupDelay is >= 0 and <= 600, "collect.cleanup_delay must be between 0 and 600 seconds");
        Check(settings.Scan.IntervalMinutes is >= 0 and <= 1440, "scan.interval_minutes must be between 0 and 1440");
        Check(settings.Scan.Ports is { Count: > 0 } && settings.Scan.Ports.All(p => p is > 0 and < 65536),
              "scan.ports must be a list of TCP ports");
        Check(settings.Language is "hu" or "en", "language must be 'hu' or 'en'");
        Check(settings.Theme is "system" or "light" or "dark", "theme must be 'system', 'light' or 'dark'");
        Check(settings.Retry.IntervalMinutes is >= 1 and <= 1440, "retry.interval_minutes must be between 1 and 1440");
        Check(settings.Updates.RefreshHours is >= 1 and <= 720, "updates.refresh_hours must be between 1 and 720");
        Check(settings.Updates.GraceDays is >= 0 and <= 90, "updates.grace_days must be between 0 and 90");
        Check(settings.Updates.Months is >= 1 and <= 12, "updates.months must be between 1 and 12");
        Check(settings.Vulns.RefreshDays is >= 1 and <= 90, "vulns.refresh_days must be between 1 and 90");
        Check(settings.Deploy.TimeoutMinutes is >= 1 and <= 1440, "deploy.timeout_minutes must be between 1 and 1440");
        Check(settings.Logins.IntervalMinutes is >= 1 and <= 1440, "logins.interval_minutes must be between 1 and 1440");
        var sy = settings.Sync;
        Check(sy.Port is >= 1 and <= 65535, "sync.port must be between 1 and 65535");
        Check(sy.IntervalMinutes is >= 0 and <= 1440, "sync.interval_minutes must be between 0 and 1440");
        Check(sy.Categories is not null && sy.Categories.All(SyncCategories.Contains),
              "sync.categories may only contain: " + string.Join(", ", SyncCategories));
        if (!string.IsNullOrEmpty(sy.Network))
            Check(IPNetwork.TryParse(NormalizeCidr(sy.Network), out _), $"sync.network is not a valid CIDR: {sy.Network}");
        Check(settings.StaleDays >= 1, "stale_days must be at least 1");
    }

    /// <summary>Like Python's <c>ip_network(x, strict=False)</c>: host bits may be set, a bare address is a /32 (/128).</summary>
    public static string NormalizeCidr(string network)
    {
        var s = network.Trim();
        var slash = s.IndexOf('/');
        var addrText = slash < 0 ? s : s[..slash];
        if (!IPAddress.TryParse(addrText, out var addr)) return s;
        var bits = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        if (slash >= 0 && !(int.TryParse(s[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out bits)
                            && bits >= 0 && bits <= (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32)))
            return s;
        var bytes = addr.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(bits - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - keep));
        }
        return $"{new IPAddress(bytes)}/{bits}";
    }

    public const string ExampleConfig = """
        # ADmiral configuration. Put secrets in environment variables instead:
        #   ADMIRAL_LDAP_PASSWORD, ADMIRAL_WINRM_PASSWORD
        mode = "ldap"            # Active Directory
        db_path = "admiral.db"
        stale_days = 45          # no AD logon for this many days => stale
        language = "hu"          # hu | en
        theme = "system"         # system | light | dark
        debug_log = true         # write admiral-debug.log (detailed log); false = off
        host = "127.0.0.1"       # web UI bind address
        port = 8765

        [ldap]
        server = "dc01.corp.local"
        use_ssl = true           # LDAPS (636), recommended.
        base_dn = "DC=corp,DC=local"
        auth = "kerberos"        # kerberos (default; needs the DC's FQDN) | simple (explicit choice, use LDAPS)
        ntlm_fallback = false    # true: after a Kerberos auth failure retry with NTLMv2 (off by default)
        user = "CORP\\svc-admiral" # DOMAIN\\user -> user@CORP.LOCAL (realm from base_dn); empty = current Windows logon
        search_filter = "(objectCategory=computer)"
        verify_cert = true
        # ca_file = "C:/certs/corp-root.pem"

        [winrm]
        user = "CORP\\svc-admiral"
        transport = "kerberos"   # kerberos (default) | ntlm | credssp
        ntlm_fallback = false    # true: retry with NTLMv2 after a Kerberos auth failure (off by default)
        use_https = false
        timeout = 20
        workers = 16

        [collect]
        # How inventory is gathered. "pdq" (default, primary) works like PDQ Inventory: agentless,
        # over SMB to the target's ADMIN$ share, running a read-only inventory script once as
        # LocalSystem via a temporary service (Service Control Manager). It MANDATORILY requires an
        # administrative Active Directory account (Domain Admins / Enterprise Admins / Administrators);
        # ADmiral verifies this read-only against AD before collecting and refuses otherwise.
        method = "pdq"           # pdq (primary, PDQ-style, needs an admin AD account) | winrm
        winrm_fallback = true    # pdq method: if SMB collection fails on a host, fall back to WinRM
        smb_timeout = 30         # seconds for each SMB / RPC connection to a host
        response_timeout = 300   # wait at most this long (5 min) for the computer's answer after the service started
        cleanup_delay = 10       # then, after this many seconds, self-check: service, script and output gone? remove / stop leftovers

        [scan]
        ports = [135, 445, 3389, 5985, 5986]
        timeout = 1.0
        workers = 64
        interval_minutes = 0     # automatic reachability check (ping) of all computers every N minutes; 0 = only by hand

        [appupdate]
        # ADmiral's own updates, always from https://tidecrestlabs.com/admiral/releases/ (not configurable).
        enabled = true           # look for a new version at start-up and every 24 hours
        use_proxy = true         # use the [proxy] settings
        # the manifest must be signed with the release key built into ADmiral (not configurable)

        [logins]
        # Login tracking: fallback for the logon history when the event log cannot be read (see Settings).
        enabled = false
        path = ""                # shared folder the GPO startup script (ADmiral-Logins.ps1) writes the log files to
        interval_minutes = 5     # how often ADmiral reads (and deletes) the files

        [proxy]
        # Only needed when this machine reaches the internet (Microsoft security-update data) through a proxy.
        # Empty url = the system proxy. The proxy password is saved encrypted (ADMIRAL_PROXY_PASSWORD also works).
        url = ""
        # Or a proxy auto-config file (wpad.dat / proxy.pac): a file path, an http(s) address, or "auto" (http://wpad/wpad.dat).
        # Used when url is empty; the proxy is then chosen per address by the PAC script.
        pac = ""
        user = ""

        [updates]
        # Monitoring of the security-update state: ADmiral compares each computer's Windows build with the
        # newest build in Microsoft's monthly security releases (downloaded from api.msrc.microsoft.com).
        enabled = true
        refresh_hours = 24
        grace_days = 0           # a new release counts as "missing" only after this many days
        months = 3

        [filecollect]
        # Computers that cannot reach this machine run ADmiral-Collect.ps1 (e.g. from a Group Policy script),
        # which saves their inventory as a file into this shared folder. ADmiral imports and deletes the files
        # at every start, from Settings, and in every round of the retry service.
        inbox = ""
        # Only files owned by the computer account they name (written by the computer's SYSTEM account, e.g. a
        # Group Policy startup script) are accepted. true also accepts files owned by a user account (logon
        # scripts, copied by hand) - any user who can write the folder could then forge an inventory.
        offline_allow_users = false

        [vulns]
        # CVE matching of the installed software: programs known to ADmiral are looked up in the NIST NVD
        # (and CISA's exploited-vulnerabilities list), through the proxy above if set. An NVD API key is optional
        # (ADMIRAL_VULNS_API_KEY or Settings) and makes the download much faster.
        enabled = true
        refresh_days = 7

        [packages]
        # Package library: installers (.msi / .exe) added by hand on the Packages page, with their versions. The
        # folder gets a packages.json with the SHA-256 of every file. Empty = a "packages" folder next to the database.
        folder = ""

        [deploy]
        # Deployments page: an installer still running on a computer after this many minutes counts as failed.
        timeout_minutes = 10

        [retry]
        # The "ADmiral retry" Windows service (installed from Settings) re-queries computers that were
        # offline or whose inventory collection failed, at this interval.
        interval_minutes = 30
        offline = true
        failed = true

        """;
}
