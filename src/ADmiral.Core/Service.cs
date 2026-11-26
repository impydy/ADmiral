#pragma warning disable CA1873 // log arguments are cheap here (strings already at hand)
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Core;

// Core operations shared by the desktop UI, the web UI, the CLI and the Windows service (port of admiral/service.py,
// the Admiral class). Returned dictionaries use the snake_case keys the UI (wwwroot/*.js) reads.
//
// Error contract (what the web layer maps to HTTP):
//   ArgumentException (incl. ConfigError)   -> 400  bad input / not possible now (Python ValueError)
//   NotFound                                 -> 404
//   KeyNotFoundException                     -> 400  unknown computer names (Store.ResolveNames, Python KeyError)
//   JobBusy                                  -> 409
//   RetryServiceError                        -> 409

/// <summary>The requested object (computer, collection, user, CVE, deployment, printer ...) does not exist.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python NotFound")]
public sealed class NotFound(string message) : Exception(message);

/// <summary>Starts a process (Remote Assistance); a fake in tests.</summary>
public interface IProcessStarter
{
    void Start(ProcessStartInfo info);
}

/// <summary>Starts processes through the Windows shell (so an elevation prompt can appear).</summary>
public sealed class ShellProcessStarter : IProcessStarter
{
    public void Start(ProcessStartInfo info)
    {
        using var p = Process.Start(info);
    }
}

/// <summary>Which background loops <see cref="AdmiralService.StartBackground"/> runs.</summary>
[Flags]
public enum BackgroundLoops
{
    None = 0,
    Ping = 1,
    AppUpdate = 2,
    Logins = 4,
    Printers = 8,
    All = Ping | AppUpdate | Logins | Printers,
}

public sealed partial class AdmiralService : ISyncHost, IDisposable
{
    public static readonly IReadOnlyList<int> WinRMPorts = [5985, 5986];
    public static readonly IReadOnlyList<int> SmbPorts = [445];

    /// <summary>Characters of a new shared sync key (the generated ones have 43).</summary>
    public const int MinSyncKey = SyncManager.MinKeyLength;

    /// <summary>section -> the settings a saved password is tied to (see <see cref="Merge"/>).</summary>
    public static readonly IReadOnlyDictionary<string, string[]> PasswordBinding = new Dictionary<string, string[]>
    {
        ["ldap"] = ["server", "port", "use_ssl", "auth", "user"],
        ["winrm"] = ["user", "transport", "use_https"],
        ["proxy"] = ["url", "pac", "user"],
    };

    private readonly bool _applyProcessSettings;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Thread> _loops = [];
    private readonly Lock _cacheLock = new();
    private readonly Lock _appUpdateLock = new();
    private (long Ticks, VulnState State)? _vulnCache;
    private (int Version, Dictionary<string, UserAgg> Users)? _userCache;
    private Dictionary<string, object?> _appUpdate = NewAppUpdateState(null);
    private bool _disposed;

    public Settings Settings { get; private set; }
    public Store Store { get; }
    public IDirectory Directory { get; private set; }
    public JobManager Jobs { get; } = new();
    public SyncManager Sync { get; }

    /// <summary>admiral.toml; set = the settings screen may save changes.</summary>
    public string? ConfigPath { get; set; }

    public SecretStore Secrets { get; }

    // ------------------------------------------------------------------ replaceable collaborators (hosts / tests)
    /// <summary>Controls the Windows retry service (default: <see cref="Retry.DefaultControl"/>).</summary>
    public IRetryServiceControl RetryService { get; set; } = Retry.DefaultControl;

    /// <summary>Starts msra.exe (Remote Assistance), eventvwr.exe (Event Viewer) and mmc.exe (Computer Management).</summary>
    public IProcessStarter ProcessStarter { get; set; } = new ShellProcessStarter();

    /// <summary>Owner checks of the shared-folder files (null = the real Windows check).</summary>
    public IFileSecurity? FileSecurity { get; set; }

    /// <summary>Replaces the reachability probe (tests); null = demo or real TCP probe.</summary>
    public Scanner.ProbeFn? ProbeOverride { get; set; }

    /// <summary>Reads the update manifest (tests replace it; default: <see cref="AppUpdate.Check"/>).</summary>
    public Func<AppUpdateSettings, ProxySettings, string, (JsonObject Manifest, AppUpdateInfo Info)> AppUpdateChecker { get; set; } =
        (cfg, proxy, current) => AppUpdate.Check(cfg, proxy, current);

    /// <summary>Called after an update installer started (default: exit the process 2.5 s later).</summary>
    public Action ExitAfterUpdate { get; set; } = () =>
        new Thread(() =>
        {
            Thread.Sleep(2500);
            Environment.Exit(0);
        }) { IsBackground = true, Name = "admiral-update-exit" }.Start();

    /// <summary>UDP port of the printers' SNMP agents (tests).</summary>
    public int SnmpPort { get; set; } = 161;

    /// <summary>Pause factor of the demo deployment (0 = none; tests).</summary>
    public double DemoDelayScale { get; set; } = 1.0;

    /// <summary>Replaces the deployment run (tests: a failure outside the per-computer work).</summary>
    internal Func<long, object?>? RunDeploymentHook { get; set; }

    /// <summary>Raised after the sync settings were applied: true = the sync listener should run (the web host starts
    /// or stops its listener accordingly).</summary>
    public event Action<bool>? SyncReconfigured;

    /// <summary>The result of the last sync reconfiguration (true = the listener should run).</summary>
    public bool SyncListenerWanted { get; private set; }

    /// <param name="settings">the settings (secrets already applied)</param>
    /// <param name="store">the database (default: <see cref="Settings.DbPath"/>); closed by <see cref="Dispose"/></param>
    /// <param name="directory">the directory (default: from the settings)</param>
    /// <param name="configPath">admiral.toml; null = settings are read-only</param>
    /// <param name="secrets">the encrypted secret store (default: memory only)</param>
    /// <param name="syncAutostart">apply the sync settings at once (the schedule; the listener is the web host's)</param>
    /// <param name="syncHandler">HTTP handler of the sync client (tests)</param>
    /// <param name="applyProcessSettings">set the process-wide language and debug log from the settings (tests: false)</param>
    public AdmiralService(Settings settings, Store? store = null, IDirectory? directory = null, string? configPath = null,
                          SecretStore? secrets = null, bool syncAutostart = true, HttpMessageHandler? syncHandler = null,
                          bool applyProcessSettings = true)
    {
        Settings = settings;
        _applyProcessSettings = applyProcessSettings;
        Store = store ?? new Store(settings.DbPath);
        Store.LogonRetentionDays = settings.Logins.RetentionDays;
        Store.PruneLogons();                                                 // the history is kept for logins.retention_days
        Directory = directory ?? MakeDirectory(settings);
        ConfigPath = configPath;
        Secrets = secrets ?? new SecretStore(null);
        Store.FailInterruptedDeployments();
        ApplyProcessSettings(settings);
        RegisterSecrets(settings);
        Sync = new SyncManager(this, syncHandler, transaction: body => Store.InTransaction(body));
        if (syncAutostart) ReconfigureSync();
    }

    public bool IsDemo => Settings.Mode == "demo";

    private void ApplyProcessSettings(Settings s)
    {
        if (!_applyProcessSettings) return;
        I18n.SetLanguage(s.Language);
        Diag.SetDebug(s.DebugLog);
    }

    /// <summary>Passwords must never reach a log file, whatever a library puts into its messages.</summary>
    private static void RegisterSecrets(Settings settings)
    {
        foreach (var (sect, key) in Config.SecretFields)
            Diag.RegisterSecret(Config.GetValue(Config.Section(settings, sect)!, key) as string);
    }

    private static string T(string key, params (string Name, object? Value)[] args) => I18n.T(key, args);

    // ------------------------------------------------------------------ ISyncHost
    SyncSettings ISyncHost.Settings => Settings.Sync;

    /// <summary>True while the background (Windows) service runs: it then owns the sync listener and schedule.</summary>
    public bool ServiceOwnsSync
    {
        get
        {
            try
            {
                return RetryService.Status() is { Supported: true, Running: true };
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)     // unknown -> behave as if there is no service
            {
                return false;
            }
        }
    }

    /// <summary>Records from a peer were merged (or the data changed otherwise): drop the derived caches.</summary>
    public void DataChanged()
    {
        lock (_cacheLock)
        {
            _vulnCache = null;
            _userCache = null;
        }
    }

    /// <summary>Apply the [sync] settings (schedule); raises <see cref="SyncReconfigured"/>.</summary>
    public bool ReconfigureSync(bool force = false)
    {
        SyncListenerWanted = Sync.Reconfigure(force);
        SyncReconfigured?.Invoke(SyncListenerWanted);
        return SyncListenerWanted;
    }

    // ------------------------------------------------------------------ lifecycle
    /// <summary>Start the background loops (automatic reachability check, update check, login-tracking import, daily
    /// printer reading). They stop on <see cref="Dispose"/>.</summary>
    public void StartBackground(BackgroundLoops loops = BackgroundLoops.All)
    {
        void Spawn(string name, Action<CancellationToken> body)
        {
            var t = new Thread(() =>
            {
                try { body(_stop.Token); }
                catch (Exception exc) when (exc is ObjectDisposedException or OperationCanceledException) { }
            }) { IsBackground = true, Name = name };
            lock (_loops) _loops.Add(t);
            t.Start();
        }
        if (loops.HasFlag(BackgroundLoops.Ping)) Spawn("admiral-ping", ct => PingLoop(ct));
        if (loops.HasFlag(BackgroundLoops.AppUpdate)) Spawn("admiral-appupdate", ct => AppUpdateLoop(ct));
        if (loops.HasFlag(BackgroundLoops.Logins)) Spawn("admiral-logins", ct => LoginsLoop(ct));
        if (loops.HasFlag(BackgroundLoops.Printers)) Spawn("admiral-printers", ct => PrinterDailyLoop(ct));
    }

    /// <summary>Stop the background loops and the sync schedule and close the database.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stop.Cancel();
        List<Thread> loops;
        lock (_loops) loops = [.. _loops];
        foreach (var t in loops) t.Join(TimeSpan.FromSeconds(5));
        Sync.Dispose();
        Store.Close();
        _stop.Dispose();
    }

    // ------------------------------------------------------------------ settings
    private static object? CopyValue(object? v) => v switch
    {
        List<int> l => new List<int>(l),
        List<string> l => new List<string>(l),
        _ => v,
    };

    /// <summary>The editable settings (secrets only as "&lt;key&gt;_set" flags) plus editable / paths / persistence.</summary>
    public Dictionary<string, object?> SettingsView()
    {
        var outp = new Dictionary<string, object?>();
        foreach (var (sect, keys) in Config.Editable)
        {
            object src = sect.Length > 0 ? Config.Section(Settings, sect)! : Settings;
            var dst = outp;
            if (sect.Length > 0) outp[sect] = dst = new Dictionary<string, object?>();
            foreach (var k in keys) dst[k] = CopyValue(Config.GetValue(src, k));
        }
        foreach (var (sect, key) in Config.SecretFields)
            ((Dictionary<string, object?>)outp[sect]!)[$"{key}_set"] =
                !string.IsNullOrEmpty(Config.GetValue(Config.Section(Settings, sect)!, key) as string);
        outp["editable"] = ConfigPath is not null;
        outp["config_path"] = ConfigPath;
        outp["db_path"] = Settings.DbPath;
        outp["passwords_persist"] = Secrets.Persistent;
        return outp;
    }

    private static Settings Clone(Settings s) => JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(s))!;

    private static string Fingerprint(object section) => JsonSerializer.Serialize(section, section.GetType());

    private static JsonObject AsObject(object? changes) => changes switch
    {
        null => [],
        JsonObject o => o,
        JsonNode n => throw new ConfigError("settings must be an object"),
        JsonElement e => JsonNode.Parse(e.GetRawText()) as JsonObject ?? throw new ConfigError("settings must be an object"),
        _ => JsonSerializer.SerializeToNode(changes) as JsonObject ?? throw new ConfigError("settings must be an object"),
    };

    private static string? SecretFrom(JsonObject changes, string sect, string key)
    {
        if (changes[sect] is not JsonObject o || !o.TryGetPropertyValue(key, out var v) || v is null) return null;
        if (v is JsonValue jv && jv.GetValueKind() == JsonValueKind.String) return jv.GetValue<string>();
        throw new ConfigError($"{sect}.{key} must be a string");
    }

    /// <summary>A copy of the current settings with <paramref name="changes"/> (untrusted, from the UI) applied and validated.
    /// Only the <see cref="Config.Editable"/> fields and the secrets are taken; everything else is ignored.</summary>
    public Settings Merge(object? changes)
    {
        var ch = AsObject(changes);
        var next = Clone(Settings);
        foreach (var (sect, keys) in Config.Editable)
        {
            JsonObject src;
            if (sect.Length == 0) src = ch;
            else if (!ch.TryGetPropertyValue(sect, out var node) || node is null) continue;
            else src = node as JsonObject ?? throw new ConfigError($"'{sect}' must be an object");
            var picked = keys.Where(src.ContainsKey).Select(k => KeyValuePair.Create(k, (object?)src[k])).ToList();
            if (picked.Count > 0) Config.Apply(sect.Length > 0 ? Config.Section(next, sect)! : next, picked, "settings");
        }
        foreach (var (sect, key) in Config.SecretFields)
        {
            var pw = SecretFrom(ch, sect, key);
            if (pw is not null) Config.Field(Config.Section(next, sect)!.GetType(), key)!.Property.SetValue(Config.Section(next, sect), pw);   // "" clears, missing keeps
        }
        // A saved password belongs to the server / account it was entered for: when one of those changes and no new
        // password is typed, it is not reused (else a changed address would receive the old password).
        foreach (var (sect, fields) in PasswordBinding)
        {
            var key = Config.SecretFields[sect];
            object old = Config.Section(Settings, sect)!, cur = Config.Section(next, sect)!;
            if (SecretFrom(ch, sect, key) is null && !string.IsNullOrEmpty(Config.GetValue(cur, key) as string)
                && fields.Any(f => !Equals(Config.GetValue(old, f), Config.GetValue(cur, f))))
                Config.Field(cur.GetType(), key)!.Property.SetValue(cur, "");
        }
        var newKey = SecretFrom(ch, "sync", "key");
        if (!string.IsNullOrEmpty(newKey) && newKey.Length < MinSyncKey)
            throw new ConfigError(T("err.sync_key_short", ("n", MinSyncKey)));
        // an unconfigured AD (fresh install) must not block unrelated changes such as the theme
        Config.ValidateSettings(next, requireLdap: next.Mode != Settings.Mode || Fingerprint(next.Ldap) != Fingerprint(Settings.Ldap));
        RegisterSecrets(next);
        return next;
    }

    /// <summary>Apply and save changes from the settings screen; returns the new <see cref="SettingsView"/>.</summary>
    public Dictionary<string, object?> UpdateSettings(object? changes)
    {
        if (ConfigPath is null) throw new ArgumentException(T("err.settings_readonly"));
        var ch = AsObject(changes);
        var next = Merge(ch);
        foreach (var (sect, key) in Config.SecretFields)
        {
            var pw = SecretFrom(ch, sect, key);
            if (pw is null && !string.IsNullOrEmpty(Config.GetValue(Config.Section(Settings, sect)!, key) as string)
                && string.IsNullOrEmpty(Config.GetValue(Config.Section(next, sect)!, key) as string))
                pw = "";                                   // dropped by Merge: the server / account changed
            if (pw is not null) Secrets.Set($"{sect}_{key}", pw);
        }
        Persist.SaveSettings(next, ConfigPath);
        var modeChanged = next.Mode != Settings.Mode;
        var directoryChanged = modeChanged || Fingerprint(next.Ldap) != Fingerprint(Settings.Ldap);
        var retentionChanged = next.Logins.RetentionDays != Settings.Logins.RetentionDays;
        Settings = next;
        Store.LogonRetentionDays = next.Logins.RetentionDays;
        if (retentionChanged) Store.PruneLogons();
        ApplyProcessSettings(next);
        if (directoryChanged) Directory = MakeDirectory(next);
        ReconfigureSync();
        DataChanged();
        Store.Log("settings", T("log.settings", ("mode", next.Mode)) + (modeChanged ? T("log.settings_mode") : ""));
        return SettingsView();
    }

    /// <summary>Test the saved settings, or unsaved ones from the settings form (with the saved passwords where allowed).</summary>
    public string TestSettings(object? changes) => MakeDirectory(Merge(changes)).Test();

    /// <summary>The directory for these settings: AD, or the demo directory (the registered factory, else the built-in one).</summary>
    private static IDirectory MakeDirectory(Settings s) => DirectoryFactory.Make(s, DirectoryFactory.DemoFactory ?? (() => new DemoDirectory()));

    // ------------------------------------------------------------------ queries
    private Dictionary<string, UpdateRef> Builds() =>
        Settings.Updates.Enabled ? Store.UpdateReference().Builds : [];

    /// <summary>The visible computers (Store rows) with "security" (<see cref="SecurityState"/>) and, with
    /// <paramref name="withApps"/>, "apps" (installed program names, for rules).</summary>
    public List<Row> Computers(bool withApps = false)
    {
        var comps = Store.Computers(Settings.StaleDays);
        var builds = Builds();
        foreach (var c in comps)
            c["security"] = Updates.GetSecurityState(c["inventory"] as JsonObject, builds, Settings.Updates.GraceDays);
        if (withApps)
        {
            var apps = Store.AppIndex();
            foreach (var c in comps) c["apps"] = apps.GetValueOrDefault((string)c["guid"]!) ?? [];
        }
        return comps;
    }

    /// <summary>Everything known about one computer: AD, scan, inventory, "items" (list sections), "apps", "fleets".</summary>
    public Row Computer(string guid)
    {
        var c = Store.Computer(guid, Settings.StaleDays) ?? throw new NotFound(T("err.computer_not_found", ("ref", guid)));
        c["security"] = Updates.GetSecurityState(c["inventory"] as JsonObject, Builds(), Settings.Updates.GraceDays);
        var items = Store.Items(guid);
        c["items"] = items;
        c["apps"] = items.GetValueOrDefault("apps")?.Select(a => Str(a["name"])).ToList() ?? [];
        c["bitlocker_keys"] = Store.BitlockerKeyList(guid);              // which keys are stored - never the key
        var comps = Computers(withApps: true);
        c["fleets"] = Store.Fleets().Where(f => Resolve(f, comps).Any(m => (string)m["guid"]! == guid))
                           .Select(f => new Row { ["id"] = f["id"], ["name"] = f["name"] }).ToList();
        return c;
    }

    private static string Str(object? v) => v switch
    {
        null => "",
        string s => s,
        JsonValue jv when jv.GetValueKind() == JsonValueKind.String => jv.GetValue<string>(),
        JsonNode n => n.ToJsonString(),
        _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    private static double? Num(JsonNode? n) => Updates.Number(n);

    // ------------------------------------------------------------------ software inventory
    private Dictionary<string, SoftwareEntry> SoftwareIndex() => Software.Aggregate(Store.AppRows());

    private static Row ListRow(SoftwareEntry e)
    {
        var r = Software.ListRow(e);
        return new Row
        {
            ["key"] = r.Key, ["name"] = r.Name, ["publisher"] = r.Publisher, ["devices"] = r.Devices,
            ["version_count"] = r.VersionCount, ["versions"] = r.Versions,
        };
    }

    /// <summary>Every installed program, grouped (version numbers removed from the name), with its versions.</summary>
    public List<SoftwareListRow> SoftwareList() =>
        [.. SoftwareIndex().Values.Select(Software.ListRow).OrderBy(r => r.Name.ToLowerInvariant(), StringComparer.Ordinal)];

    private Dictionary<string, string> ComputerNames() =>
        Store.Computers(Settings.StaleDays).ToDictionary(c => (string)c["guid"]!, c => Str(c["name"]));

    private static List<Row> DeviceList(IEnumerable<string> guids, Dictionary<string, string> names) =>
        [.. guids.Select(g => new Row { ["guid"] = g, ["name"] = names.GetValueOrDefault(g, "") })
                 .OrderBy(d => ((string)d["name"]!).ToLowerInvariant(), StringComparer.Ordinal)];

    /// <summary>One program: the list row + "all_versions" [{version, devices: [{guid, name}]}], "cpe", "vulnerabilities".</summary>
    public Row SoftwareDetail(string key)
    {
        var e = SoftwareIndex().GetValueOrDefault((key ?? "").ToLowerInvariant()) ?? throw new NotFound(T("err.software_not_found", ("ref", key)));
        var names = ComputerNames();
        var versions = Software.SortedVersions(e.Versions)
            .Select(v => new Row { ["version"] = v.Version, ["devices"] = DeviceList(e.Versions[v.Version], names) }).ToList();
        var state = VulnStateNow();
        var cpe = Vulns.CpeFor(e.Name);
        var row = ListRow(e);
        row["all_versions"] = versions;
        row["cpe"] = cpe is { } c ? $"{c.Vendor}:{c.Product}" : null;
        row["vulnerabilities"] = (state.PerSoftware.GetValueOrDefault(e.Key) ?? []).Select(v => VulnRow(v, e.Key)).ToList();
        return row;
    }

    // ------------------------------------------------------------------ vulnerabilities (CVE matching)
    private sealed class VulnSoftware(string name)
    {
        public string Name { get; } = name;
        public Dictionary<string, HashSet<string>> Versions { get; } = [];
    }

    private sealed class VulnItem
    {
        public required string Cve { get; init; }
        public string? Summary { get; init; }
        public double? Score { get; init; }
        public required string Severity { get; init; }
        public bool Kev { get; init; }
        public string? Published { get; init; }
        public required string Range { get; init; }
        public SortedDictionary<string, VulnSoftware> Software { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Devices { get; } = [];
    }

    private sealed record VulnState(Dictionary<string, VulnItem> Items, Dictionary<string, List<VulnItem>> PerSoftware, int Mapped, int Total);

    /// <summary>Match the installed versions against the stored CVE ranges. Cached for a few seconds.</summary>
    private VulnState VulnStateNow()
    {
        lock (_cacheLock)
            if (_vulnCache is { } c && Stopwatch.GetElapsedTime(c.Ticks) < TimeSpan.FromSeconds(15))
                return c.State;
        var index = SoftwareIndex();
        var kev = Store.KevSet();
        var byProduct = new Dictionary<(string, string), List<(CveRecord Rec, List<CompiledMatch> C)>>();
        var items = new Dictionary<string, VulnItem>(StringComparer.Ordinal);
        var perSoftware = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var mapped = 0;
        foreach (var e in index.Values)
        {
            if (Vulns.CpeFor(e.Name) is not { } cpe) continue;
            mapped++;
            if (!byProduct.TryGetValue(cpe, out var recs))
                byProduct[cpe] = recs = [.. Store.CvesFor(cpe.Vendor, cpe.Product).Select(r => (r, r.Matches.Select(m => Vulns.Compile(m)).ToList()))];
            foreach (var (version, guids) in e.Versions)
            {
                var vk = Software.VersionKey(version);
                if (vk.Length == 0) continue;
                foreach (var (r, compiled) in recs)
                {
                    if (!compiled.Any(cm => Vulns.InRangeC(vk, cm))) continue;
                    if (!items.TryGetValue(r.Cve, out var it))
                        items[r.Cve] = it = new VulnItem
                        {
                            Cve = r.Cve, Summary = r.Summary, Score = r.Score, Severity = Vulns.Severity(r.Score), Kev = kev.Contains(r.Cve),
                            Published = r.Published, Range = Vulns.FixedIn(r.Matches),
                        };
                    if (!it.Software.TryGetValue(e.Key, out var sw)) it.Software[e.Key] = sw = new VulnSoftware(e.Name);
                    sw.Versions[version] = guids;
                    it.Devices.UnionWith(guids);
                    if (!perSoftware.TryGetValue(e.Key, out var list)) perSoftware[e.Key] = list = [];
                    if (!list.Contains(r.Cve)) list.Add(r.Cve);
                }
            }
        }
        var state = new VulnState(items, perSoftware.ToDictionary(kv => kv.Key, kv => kv.Value.Select(x => items[x]).ToList()), mapped, index.Count);
        lock (_cacheLock) _vulnCache = (Stopwatch.GetTimestamp(), state);
        return state;
    }

    /// <summary>Why a CVE is hidden by default and left out of the counts: "no_range" (NVD names no affected version
    /// bound, so every version "matches"), "old" (published more than 10 years ago), or null when it is shown.</summary>
    internal static string? VulnHiddenReason(string range, string? published, DateTime? today = null)
    {
        if (string.IsNullOrWhiteSpace(range)) return "no_range";
        if (DateTime.TryParseExact(published, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var p)
            && p < (today ?? DateTime.UtcNow).Date.AddYears(-10)) return "old";
        return null;
    }

    private static Row VulnRow(VulnItem it, string? only = null)
    {
        var devices = only is null ? it.Devices : it.Software[only].Versions.Values.SelectMany(g => g).ToHashSet();
        var hidden = VulnHiddenReason(it.Range, it.Published);
        return new Row
        {
            ["hidden"] = hidden is not null, ["hidden_reason"] = hidden,
            ["cve"] = it.Cve, ["software"] = string.Join(", ", it.Software.Values.Select(s => s.Name).Order(StringComparer.Ordinal)),
            ["range"] = it.Range, ["score"] = it.Score, ["severity"] = it.Severity, ["kev"] = it.Kev, ["published"] = it.Published,
            ["devices"] = devices.Count,
        };
    }

    /// <summary>{items: [rows], counts: {critical, high, medium, low, kev}, coverage: {mapped, total},
    /// status: {enabled, products, fetched_at, error}}.</summary>
    public Row Vulnerabilities()
    {
        var state = VulnStateNow();
        var rows = state.Items.Values.Select(it => VulnRow(it))
            .OrderBy(r => (bool)r["kev"]! ? 0 : 1).ThenBy(r => -((double?)r["score"] ?? 0)).ThenBy(r => (string)r["cve"]!, StringComparer.Ordinal)
            .ToList();
        // hidden CVEs (no affected version / older than 10 years) are not counted; the page can still list them
        var counted = rows.Where(r => r["hidden"] is false).ToList();
        var counts = new Row();
        foreach (var k in new[] { "critical", "high", "medium", "low" }) counts[k] = counted.Count(r => (string)r["severity"]! == k);
        counts["kev"] = counted.Count(r => (bool)r["kev"]!);
        counts["hidden"] = rows.Count - counted.Count;
        var meta = Store.UpdateReference().Meta;
        var fetched = Store.CveFetched();
        return new Row
        {
            ["items"] = rows, ["counts"] = counts,
            ["coverage"] = new Row { ["mapped"] = state.Mapped, ["total"] = state.Total },
            ["status"] = new Row
            {
                ["enabled"] = Settings.Vulns.Enabled, ["products"] = fetched.Count,
                ["fetched_at"] = fetched.Count > 0 ? fetched.Values.Max(StringComparer.Ordinal) : null,
                ["error"] = meta.GetValueOrDefault("vuln_error") is { Length: > 0 } err ? err : null,
            },
        };
    }

    /// <summary>One CVE: the row + "summary" and "affected" [{key, name, fixes, versions: [{version, devices}]}].</summary>
    public Row Vulnerability(string cve)
    {
        var it = VulnStateNow().Items.GetValueOrDefault((cve ?? "").ToUpperInvariant()) ?? throw new NotFound(T("err.cve_not_found", ("ref", cve)));
        var names = ComputerNames();
        List<PackageRow> pkgs;
        try { pkgs = Library().Rows(); }
        catch (Exception exc) when (exc is PackageError or ArgumentException or IOException) { pkgs = []; }   // no package folder / unreadable library
        var row = VulnRow(it);
        row["summary"] = it.Summary;
        row["affected"] = it.Software.Select(kv => new Row
        {
            ["key"] = kv.Key, ["name"] = kv.Value.Name, ["fixes"] = PackageFixes(kv.Value, names, pkgs),
            ["versions"] = kv.Value.Versions.OrderByDescending(x => Software.VersionKey(x.Key), Comparer<long[]>.Create((a, b) => Software.CompareKeys(a, b)))
                .Select(x => new Row { ["version"] = x.Key, ["devices"] = DeviceList(x.Value, names) }).ToList(),
        }).ToList();
        return row;
    }

    [GeneratedRegex(@"\([^)]*\)|\b(x64|x86|64-bit|32-bit|msi|setup|installer)\b|\d+(\.\d+)*")]
    private static partial Regex NoiseRe();

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonAlnumRe();

    private static string NormProgram(string? x) => NonAlnumRe().Replace(NoiseRe().Replace((x ?? "").ToLowerInvariant(), " "), "");

    /// <summary>Is the installed program <paramref name="swName"/> the program of a library package (name / id)?</summary>
    internal static bool SameProgram(string swName, string pkgName, string pkgId)
    {
        var swCpe = Vulns.CpeFor(swName);
        var swNorm = NormProgram(swName);
        string[] cands = [pkgName, pkgId];
        var cpes = cands.Select(Vulns.CpeFor).Where(c => c is not null).ToHashSet();
        return (swCpe is not null && cpes.Contains(swCpe))
               || cands.Select(NormProgram).Any(n => n.Length >= 4 && swNorm.Length > 0 && (swNorm.Contains(n, StringComparison.Ordinal) || n.Contains(swNorm, StringComparison.Ordinal)));
    }

    /// <summary>GUIDs of the computers whose inventory already shows this program at exactly this version.</summary>
    private HashSet<string> AlreadyInstalled(string pkgName, string pkgId, string version)
    {
        var want = Software.VersionKey(version);
        var outp = new HashSet<string>();
        if (want.Length == 0) return outp;
        foreach (var e in SoftwareIndex().Values)
            if (SameProgram(e.Name, pkgName, pkgId))
                foreach (var (v, gs) in e.Versions)
                    if (Software.CompareKeys(Software.VersionKey(v), want) == 0) outp.UnionWith(gs);
        return outp;
    }

    /// <summary>Library packages of this program that hold a newer version than some affected computers run.</summary>
    private static List<Row> PackageFixes(VulnSoftware sw, Dictionary<string, string> names, List<PackageRow> pkgs)
    {
        var outp = new List<Row>();
        foreach (var p in pkgs)
        {
            if (!SameProgram(sw.Name, p.Name, p.Id)) continue;
            var vers = p.Files.Where(f => f.Kind == "installer" && Deploy.InstallerKind(f.Path) is not null
                                          && Software.VersionKey(f.Version).Length > 0).ToList();
            if (vers.Count == 0) continue;
            var best = vers.Select(f => Software.VersionKey(f.Version)).Aggregate((a, b) => Software.CompareKeys(a, b) >= 0 ? a : b);
            var files = vers.Where(f => Software.CompareKeys(Software.VersionKey(f.Version), best) == 0).ToList();
            var devices = new List<Row>();
            foreach (var (v, gs) in sw.Versions)
            {
                var vk = Software.VersionKey(v);
                if (vk.Length == 0 || Software.CompareKeys(vk, best) >= 0) continue;
                foreach (var g in gs.Order(StringComparer.Ordinal))
                    devices.Add(new Row { ["guid"] = g, ["name"] = names.GetValueOrDefault(g, ""), ["version"] = v });
            }
            if (devices.Count > 0)
                outp.Add(new Row
                {
                    ["package_id"] = p.Id, ["package_name"] = p.Name, ["version"] = files[0].Version,
                    ["files"] = files.Select(f => new Row { ["path"] = f.Path, ["name"] = f.Path.Split('/')[^1] }).ToList(),
                    ["devices"] = devices.OrderBy(d => ((string)d["name"]!).ToLowerInvariant(), StringComparer.Ordinal).ToList(),
                });
        }
        return outp;
    }

    private static bool IsNetworkFailure(Exception exc) =>
        exc is HttpRequestException { StatusCode: null } || Kerberos.IsNetworkError(exc);

    /// <summary>Download the CVE data of the installed programs that are in the curated catalog (+ CISA KEV).
    /// Returns {products, mapped, errors}.</summary>
    public Dictionary<string, int> RefreshVulns(Progress? progress = null)
    {
        var v = Settings.Vulns;
        var wanted = SoftwareIndex().Values.Select(e => Vulns.CpeFor(e.Name)).OfType<(string Vendor, string Product)>()
            .Distinct().OrderBy(p => p.Vendor, StringComparer.Ordinal).ThenBy(p => p.Product, StringComparer.Ordinal).ToList();
        var fetched = Store.CveFetched();
        var limit = DateTimeOffset.UtcNow.AddDays(-v.RefreshDays);
        var todo = wanted.Where(p => !fetched.TryGetValue(p, out var at) || (Db.ParseIso(at) ?? DateTimeOffset.MinValue) < limit).ToList();
        var errors = new List<string>();
        if (IsDemo)
        {
            var data = Demo.Cves();
            foreach (var (vendor, product) in todo) Store.SaveCves(vendor, product, data.GetValueOrDefault((vendor, product)) ?? []);
            Store.SaveKev(Demo.Kev);
        }
        else
        {
            var hdr = v.ApiKey.Length > 0 ? new Dictionary<string, string> { ["apiKey"] = v.ApiKey } : null;
            var get = Updates.MakeGetter(Settings.Proxy, headers: hdr);
            var netFailures = 0;
            for (var i = 0; i < todo.Count; i++)
            {
                var (vendor, product) = todo[i];
                progress?.Report(i, todo.Count + 1, $"{vendor}:{product}");
                try
                {
                    Store.SaveCves(vendor, product, Vulns.FetchProduct(vendor, product, get, pause: v.ApiKey.Length > 0 ? 0.8 : 6.0));
                    netFailures = 0;
                }
                catch (Exception exc)            // keep the other products; report at the end
                {
                    Log.Logger.LogWarning("CVE download for {Vendor}:{Product} failed: {Error}", vendor, product, Updates.ExplainError(exc));
                    errors.Add($"{vendor}:{product}: {Updates.ExplainError(exc)}");
                    netFailures = IsNetworkFailure(exc) ? netFailures + 1 : 0;
                    if (netFailures >= 2) break;                   // the connection itself is the problem: stop early
                }
            }
            if (netFailures >= 2) throw new ArgumentException(T("err.vulns_fetch", ("err", errors[0])));
            try
            {
                Store.SaveKev(Vulns.FetchKev(get));
            }
            catch (Exception exc)
            {
                Log.Logger.LogWarning("CISA KEV download failed: {Error}", Updates.ExplainError(exc));
                errors.Add($"KEV: {Updates.ExplainError(exc)}");
            }
        }
        var joined = string.Join("; ", errors);
        Store.SetUpdateMeta(new Dictionary<string, string> { ["vuln_error"] = joined.Length > 400 ? joined[..400] : joined });
        lock (_cacheLock) _vulnCache = null;
        progress?.Report(todo.Count + 1, todo.Count + 1, "OK");
        Store.Log("vulns", T("log.vulns", ("n", todo.Count), ("mapped", wanted.Count), ("errors", errors.Count)));
        if (errors.Count > 0 && errors.Count >= todo.Count + 1) throw new ArgumentException(T("err.vulns_fetch", ("err", errors[0])));
        return new Dictionary<string, int> { ["products"] = todo.Count, ["mapped"] = wanted.Count, ["errors"] = errors.Count };
    }

    // ------------------------------------------------------------------ package library
    /// <summary>The package library (the configured folder, or "packages" next to the database).</summary>
    public PackageLibrary Library()
    {
        var f = (Settings.Packages.Folder ?? "").Trim();
        if (f.Length == 0)
        {
            if (Settings.DbPath == ":memory:") throw new ArgumentException(T("err.pkg_folder"));
            f = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(Settings.DbPath)) ?? ".", "packages");
        }
        return new PackageLibrary(f);
    }

    private static T Pkg<T>(Func<T> body)
    {
        try { return body(); }
        catch (PackageError exc) { throw new ArgumentException(exc.Message, exc); }
    }

    /// <summary>{folder, manifest, packages: [PackageRow]}.</summary>
    public Row PackagesStatus()
    {
        var lib = Library();
        return new Row { ["folder"] = lib.Folder, ["manifest"] = lib.ManifestPath, ["packages"] = Pkg(lib.Rows) };
    }

    /// <summary>Start an upload into the library (write chunks, then Commit; dispose to abort).</summary>
    public PackageUpload UploadPackage(string pkgId, string filename, string version = "", string title = "", string sha256 = "")
    {
        var lib = Library();
        var up = Pkg(() => lib.Upload(pkgId, filename, version, title, sha256));
        Store.Log("packages", T("log.pkg_upload", ("id", pkgId), ("file", filename)));
        return up;
    }

    public void PackageRemove(string pkgId)
    {
        Pkg(() => { Library().Remove(pkgId); return 0; });
        Store.Log("packages", T("log.pkg_remove", ("id", pkgId)));
    }

    public PackageEntry PackageVendorCheck(string pkgId, string path, string sha256)
    {
        var lib = Library();
        var wu = Pkg(() => lib.Get(pkgId))?.Kind == "winupdate";
        var entry = Pkg(() => lib.CheckVendorHash(pkgId, path, sha256, wu ? "catalog" : "vendor"));
        Store.Log("packages", T(wu ? "log.pkg_catalog" : "log.pkg_vendor", ("id", pkgId), ("file", path)));
        return entry;
    }

    /// <summary>Start an upload of a Windows update (.msu / .cab) for one Windows build (see <see cref="PackageLibrary.UploadWinUpdate"/>).</summary>
    public PackageUpload UploadWinUpdate(string osBuild, string kb, string version, string filename, string digest = "")
    {
        var up = Pkg(() => Library().UploadWinUpdate(osBuild, kb, version, filename, digest));
        Store.Log("packages", T("log.wu_upload", ("kb", kb), ("build", osBuild), ("file", filename)));
        return up;
    }

    /// <summary>Replaces the Windows Update Catalog requests (tests / demo): (url, form or null) -> body.</summary>
    internal Func<string, IReadOnlyDictionary<string, string>?, string>? CatalogFetch { get; set; }

    /// <summary>Look a stored Windows update up in the Windows Update Catalog (through the proxy): the file counts as
    /// checked when the catalog lists a file of its KB with the same SHA-1 / SHA-256. Returns {ok, title, file, url}.</summary>
    public Row PackageCatalogCheck(string pkgId, string path)
    {
        var lib = Library();
        var pkg = Pkg(() => lib.Get(pkgId)) ?? throw new ArgumentException($"{pkgId} is not in the library.");
        if (pkg.Kind != "winupdate" || pkg.Kb is null) throw new ArgumentException(T("err.wu_not_update"));
        var rec = pkg.Files.FirstOrDefault(f => f.Path == path) ?? throw new ArgumentException($"{pkgId}: no such file in the package.");
        var local = Pkg(() => lib.File(rec.Path));
        if (!File.Exists(local)) throw new ArgumentException($"{rec.Path} is missing from the library.");
        var (sha256, sha1) = PackageLibrary.HashesFile(local);
        if (sha256 != rec.Sha256) throw new ArgumentException(T("err.dep_hash", ("file", rec.Path)));
        CatalogMatch m;
        try
        {
            var fetch = CatalogFetch ?? (IsDemo ? Demo.CatalogFetch(sha1, sha256) : Updates.MakeTextFetcher(Settings.Proxy));
            m = WinUpdate.CatalogLookup(pkg.Kb, sha1, sha256, fetch);
        }
        catch (Exception exc) when (exc is HttpRequestException or IOException or TaskCanceledException or OperationCanceledException
                                        or InvalidOperationException or PacError or UriFormatException)
        {
            throw new ArgumentException(T("err.catalog_fetch", ("err", Updates.ExplainError(exc))), exc);
        }
        if (!m.Found) throw new ArgumentException(T("err.catalog_none", ("kb", pkg.Kb), ("n", m.Searched)));
        Pkg(() => lib.CheckVendorHash(pkgId, path, sha1, "catalog", m.Title));
        Store.Log("packages", T("log.pkg_catalog", ("id", pkgId), ("file", path)));
        return new Row { ["ok"] = true, ["title"] = m.Title, ["file"] = m.FileName, ["url"] = m.Url };
    }

    public PackageEntry PackageRemoveFile(string pkgId, string path)
    {
        var entry = Pkg(() => Library().RemoveFile(pkgId, path));
        Store.Log("packages", T("log.pkg_remove_file", ("id", pkgId), ("file", path)));
        return entry;
    }

    public List<PackageVerifyResult> PackageVerify(string? pkgId = null)
    {
        var res = Pkg(() => Library().Verify(pkgId));
        Store.Log("packages", T("log.pkg_verify", ("n", res.Count), ("bad", res.Count(r => !r.Ok))));
        return res;
    }

    // ------------------------------------------------------------------ deployments
    private void UpdateTarget(long dep, string guid, params (string Key, object? Value)[] fields) =>
        Store.UpdateTarget(dep, guid, fields.ToDictionary(f => f.Key, f => f.Value));

    /// <summary>Check the choice, record the deployment and run it in the background job. Returns {id, job}.</summary>
    /// <summary>Most peer-added tags listed in <see cref="DeploymentPreview"/> (the total is always given).</summary>
    public const int PreviewPeerTags = 50;

    /// <summary>What a deployment to <paramref name="names"/> (computers) plus the members of <paramref name="fleetIds"/>
    /// would reach, read fresh from the database (not the page's cached lists): {ids, names, refused, peer_collections:
    /// [{name, at}], peer_tags: [{computer, tag, at}], peer_tags_total}. The peer_* lists are what a sync peer created or
    /// changed and nobody here has edited since - they may have moved computers into the selection.</summary>
    public Row DeploymentPreview(IReadOnlyList<string> names, IReadOnlyList<long> fleetIds)
    {
        var guids = new List<string>(names.Count > 0 ? Store.ResolveNames(names) : []);
        var peerCollections = new List<Row>();
        foreach (var fid in fleetIds.Distinct())
        {
            var fleet = GetFleet(fid);
            guids.AddRange(Members(fleet).Select(c => (string)c["guid"]!));
            if (fleet["peer_changed"] is string { Length: > 0 } at) peerCollections.Add(new Row { ["name"] = fleet["name"], ["at"] = at });
        }
        var comps = Computers().ToDictionary(c => (string)c["guid"]!);
        var unconfirmed = SyncUnconfirmed();
        var known = guids.Distinct().Where(comps.ContainsKey).ToList();
        var targets = known.Where(g => !unconfirmed.Contains(g)).OrderBy(g => Str(comps[g]["name"]), StringComparer.OrdinalIgnoreCase).ToList();
        var set = targets.ToHashSet(StringComparer.Ordinal);
        var peerTags = Store.Query("SELECT t.guid, t.tag, t.peer_added FROM tags t WHERE t.peer_added IS NOT NULL ORDER BY t.peer_added DESC")
            .Where(r => set.Contains((string)r["guid"]!))
            .Select(r => new Row { ["computer"] = Str(comps[(string)r["guid"]!]["name"]), ["tag"] = r["tag"], ["at"] = r["peer_added"] })
            .ToList();
        return new Row
        {
            ["ids"] = targets,
            ["names"] = targets.Select(g => Str(comps[g]["name"])).ToList(),
            ["refused"] = known.Where(unconfirmed.Contains).Select(g => Str(comps[g]["name"])).ToList(),
            ["peer_collections"] = peerCollections,
            ["peer_tags"] = peerTags.Take(PreviewPeerTags).ToList(),
            ["peer_tags_total"] = peerTags.Count,
        };
    }

    public Row StartDeployment(string packageId, string file, string? args, IReadOnlyList<string> names, int? timeoutSeconds = null,
                               long? retryOf = null)
    {
        if (names is null || names.Count == 0) throw new ArgumentException(T("err.dep_no_targets"));
        if (WinUpdate.IsUpdateFile(file)) return StartWinUpdateDeployment(packageId, file, names, timeoutSeconds, retryOf);
        var timeout = timeoutSeconds is > 0 ? timeoutSeconds.Value : Settings.Deploy.TimeoutMinutes * 60;
        var lib = Library();
        var pkg = Pkg(() => lib.Get(packageId)) ?? throw new ArgumentException($"{packageId} is not in the library.");
        var rec = pkg.Files.FirstOrDefault(f => f.Path == file && f.Kind == "installer");
        var kind = Deploy.InstallerKind(file ?? "");
        if (rec is null || kind is null) throw new ArgumentException(T("err.dep_file"));
        string cleanArgs;
        try { cleanArgs = Deploy.ValidArgs(args); }
        catch (DeployError exc) { throw new ArgumentException(exc.Message, exc); }
        var local = Pkg(() => lib.File(rec.Path));
        if (!File.Exists(local) || !string.Equals(PackageLibrary.Sha256File(local), rec.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(T("err.dep_hash", ("file", rec.Path)));        // integrity before anything is sent
        var guids = Store.ResolveNames(names);
        var comps = Computers().ToDictionary(c => (string)c["guid"]!);
        var unconfirmed = SyncUnconfirmed();
        var refused = guids.Distinct().Where(g => comps.ContainsKey(g) && unconfirmed.Contains(g)).Select(g => Str(comps[g]["name"])).ToList();
        var targets = guids.Distinct().Where(g => comps.ContainsKey(g) && !unconfirmed.Contains(g)).Select(g => (g, Str(comps[g]["name"]))).ToList();
        if (targets.Count == 0 && refused.Count > 0)
            throw new ArgumentException($"Not confirmed by this instance's AD sync yet (received from a sync peer): {string.Join(", ", refused)}");
        var dep = Store.CreateDeployment(pkg.Id, pkg.Name, pkg.Version, file!, kind, cleanArgs, targets);
        Store.Log("deploy", T("log.dep_start", ("id", dep), ("pkg", pkg.Id), ("n", targets.Count)));
        void Ev(string msg) => Store.AddDeploymentEvent(dep, msg);
        Ev($"Deployment #{dep} started" + (retryOf is { } r ? $" (repeat of #{r}, failed computers only)" : ""));
        Ev($"Package: {(pkg.Name.Length > 0 ? pkg.Name : pkg.Id)} ({pkg.Id}) version {(pkg.Version.Length > 0 ? pkg.Version : "-")}");
        Ev($"Installer: {rec.Path} ({kind}), {rec.Size} bytes, SHA-256 {rec.Sha256} (re-checked before sending)");
        if (rec.VendorChecked) Ev("The SHA-256 was compared with the vendor's published value");
        Ev($"Switches: {(cleanArgs.Length > 0 ? cleanArgs : "(none)")}; timeout {timeout} s");
        Ev($"Targets ({targets.Count}): " + string.Join(", ", targets.Select(t => t.Item2)));
        if (refused.Count > 0)
            Ev($"Skipped ({refused.Count}, received from a sync peer and not yet confirmed by this instance's AD sync): " + string.Join(", ", refused));
        JobInfo job;
        try
        {
            job = Jobs.Start("deploy", "deploy", p => RunDeploymentSafe(dep, () => RunDeployment(dep, local, rec.Path, rec.Sha256, kind, cleanArgs, timeout, p)));
        }
        catch (Exception)
        {
            foreach (var (g, _) in targets)
                UpdateTarget(dep, g, ("step", "done"), ("outcome", "failed"), ("error", "not started: another deployment is running"));
            Ev("Not started: another deployment is running");
            Store.FinishDeployment(dep);
            throw;
        }
        return new Row { ["id"] = dep, ["job"] = job };
    }

    /// <summary>Run the same installer again on the computers where this deployment failed. Returns {id, job}.</summary>
    public Row RetryDeployment(long depId)
    {
        var d = Store.Deployment(depId) ?? throw new NotFound($"Deployment {depId} not found");
        if ((string?)d["status"] == "running") throw new ArgumentException(T("err.dep_running"));
        var bad = ((List<Row>)d["targets"]!).Where(t => t["outcome"] as string is "failed" or "unreachable").Select(t => (string)t["guid"]!).ToList();
        if (bad.Count == 0) throw new ArgumentException(T("err.dep_no_failed"));
        if ((string?)d["kind"] == "chain")
        {
            // a repeat runs the same steps as the original: refused when the package's chain was changed since
            var was = Store.DeploymentEvents(depId).Select(e => e["message"] as string ?? "")
                .FirstOrDefault(m => m.StartsWith(ChainFingerprintPrefix, StringComparison.Ordinal))?[ChainFingerprintPrefix.Length..];
            var pkg = Pkg(() => Library().Get((string)d["package_id"]!)) ?? throw new ArgumentException($"{d["package_id"]} is not in the library.");
            if (was is null || was != ChainFingerprint(Chain.ValidateSteps(pkg, pkg.Steps))) throw new ArgumentException(T("err.chain_changed"));
            return StartChainDeployment((string)d["package_id"]!, bad, retryOf: depId);
        }
        return StartDeployment((string)d["package_id"]!, (string)d["file"]!, d["args"] as string ?? "", bad, retryOf: depId);
    }

    // ------------------------------------------------------------------ BitLocker recovery keys
    /// <summary>ADmiral's key pair for the recovery keys (see <see cref="BitlockerVault"/>).</summary>
    public BitlockerVault Bitlocker => _bitlocker ??= new BitlockerVault(Secrets, () => IsDemo);
    private BitlockerVault? _bitlocker;

    /// <summary>Replaces the administrator password check (tests): password -> correct?</summary>
    internal Func<string, bool>? AdminPasswordCheck { get; set; }

    public const int BitlockerMaxFailures = 5;
    public static readonly TimeSpan BitlockerLockout = TimeSpan.FromMinutes(15);
    private readonly Lock _blGate = new();
    private readonly List<DateTime> _blFailures = [];
    private DateTime _blLockedUntil = DateTime.MinValue;

    /// <summary>Take the encrypted recovery keys out of a collected record and store them (only when this run asked for
    /// them: the record then carries them, and an empty list means none). Each entry is checked; nothing readable is
    /// accepted from a computer - except the demo, whose fake keys are encrypted here.</summary>
    private void SaveBitlockerKeys(string guid, JsonObject rec, bool requested)
    {
        if (!rec.Remove("bitlocker_keys", out var node) || !requested || node is not JsonArray arr) return;
        var keys = new List<(string, string, string)>();
        foreach (var n in arr.Take(32))
        {
            if (n is not JsonObject o) continue;
            string S(string k) => o[k] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>().Trim() : "";
            var (drive, id, cipher) = (S("drive"), S("id"), S("cipher"));
            if (IsDemo && cipher.Length == 0 && BitlockerVault.ValidRecoveryPassword(S("plain"))) cipher = Bitlocker.Encrypt(S("plain"));
            if (drive.Length is 0 or > 64 || id.Length is 0 or > 80 || cipher.Length is 0 or > 4096) continue;
            try { _ = Convert.FromBase64String(cipher); }
            catch (FormatException) { continue; }
            keys.Add((drive, id, cipher));
        }
        Store.SetBitlockerKeys(guid, keys);
    }

    /// <summary>Is <paramref name="password"/> the administrator's (the configured AD account's) password now? Checked
    /// with a fresh LDAP bind, so a stale saved password does not count. Demo: "demo".</summary>
    private bool CheckAdminPassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length > 256) return false;
        if (AdminPasswordCheck is { } check) return check(password);
        if (IsDemo) return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(password), "demo"u8);
        if (string.IsNullOrWhiteSpace(Settings.Ldap.User)) throw new ArgumentException(T("err.bl_no_account"));
        var s = Clone(Settings);
        s.Ldap.Password = password;
        try
        {
            MakeDirectory(s).Test();
            return true;
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogInformation("BitLocker key: the administrator password check failed ({Type})", exc.GetType().Name);
            return false;
        }
    }

    /// <summary>One recovery key in clear text, after the administrator's password was entered again. Wrong passwords
    /// are counted: after <see cref="BitlockerMaxFailures"/> within the lockout time no key is shown for
    /// <see cref="BitlockerLockout"/>. Every look (and every refusal) goes to the activity log - never the key.</summary>
    public Row RevealBitlockerKey(string guid, string id, string password)
    {
        var c = Store.Computer(guid) ?? throw new NotFound(T("err.computer_not_found", ("ref", guid)));
        var name = Str(c["name"]);
        var meta = Store.BitlockerKeyList(guid).FirstOrDefault(k => (string?)k["id"] == id)
                   ?? throw new NotFound(T("err.bl_none"));
        lock (_blGate)
        {
            var now = DateTime.UtcNow;
            if (now < _blLockedUntil)
                throw new ArgumentException(T("err.bl_locked", ("min", (int)Math.Ceiling((_blLockedUntil - now).TotalMinutes))));
        }
        if (!CheckAdminPassword(password ?? ""))
        {
            lock (_blGate)
            {
                var now = DateTime.UtcNow;
                _blFailures.RemoveAll(t => now - t > BitlockerLockout);
                _blFailures.Add(now);
                if (_blFailures.Count >= BitlockerMaxFailures)
                {
                    _blLockedUntil = now + BitlockerLockout;
                    _blFailures.Clear();
                }
            }
            Store.Log("bitlocker", T("log.bl_denied", ("name", name), ("drive", meta["drive"])));
            throw new ArgumentException(T("err.bl_password"));
        }
        lock (_blGate) _blFailures.Clear();
        string key;
        try
        {
            key = Bitlocker.Decrypt(Store.BitlockerCipher(guid, id) ?? "");
        }
        catch (Exception exc) when (exc is CryptographicException or FormatException or InvalidOperationException)
        {
            throw new ArgumentException(T("err.bl_decrypt"), exc);
        }
        if (!BitlockerVault.ValidRecoveryPassword(key)) throw new ArgumentException(T("err.bl_decrypt"));
        Store.Log("bitlocker", T("log.bl_view", ("name", name), ("drive", meta["drive"]), ("id", id)));
        return new Row { ["drive"] = meta["drive"], ["id"] = id, ["key"] = key, ["collected_at"] = meta["collected_at"] };
    }

    // ------------------------------------------------------------------ package chains
    /// <summary>A new package without files: its chain is put together afterwards.</summary>
    public PackageEntry PackageCreate(string pkgId, string name, string version = "", string publisher = "", string? kind = null)
    {
        var e = Pkg(() => Library().Create(pkgId, name, version, publisher, kind));
        Store.Log("packages", T("log.pkg_create", ("id", e.Id)));
        return e;
    }

    /// <summary>Replace the chain (steps) of a package.</summary>
    public PackageEntry PackageSetSteps(string pkgId, IReadOnlyList<PackageStep> steps)
    {
        var e = Pkg(() => Library().SetSteps(pkgId, steps));
        Store.Log("packages", T("log.pkg_steps", ("id", e.Id), ("n", e.Steps.Count)));
        return e;
    }

    /// <summary>Replaces sending the Wake-on-LAN packet (tests): (host, packet, addresses).</summary>
    internal Action<string, byte[], IReadOnlyList<string>>? WolSender { get; set; }

    /// <summary>Deploy the whole chain of a package: every step on every computer, in order. Returns {id, job}.</summary>
    public Row StartChainDeployment(string packageId, IReadOnlyList<string> names, int? timeoutSeconds = null, long? retryOf = null)
    {
        if (names is null || names.Count == 0) throw new ArgumentException(T("err.dep_no_targets"));
        var lib = Library();
        var data = Pkg(lib.Load);
        var pkg = data.Packages.FirstOrDefault(p => string.Equals(p.Id, packageId, StringComparison.OrdinalIgnoreCase))
                  ?? throw new ArgumentException($"{packageId} is not in the library.");
        var steps = Chain.ValidateSteps(pkg, pkg.Steps, data.Packages);     // checked again: the register may have changed
        if (steps.Count == 0) throw new ArgumentException(T("err.chain_empty"));
        return StartChainRun(lib, data, pkg, steps, names, timeoutSeconds, retryOf, single: null);
    }

    /// <summary>Install one Windows update (.msu / .cab) of the library on the computers: a one-step chain with the
    /// Windows update flow (<see cref="WinUpdate"/>), in its own job ("wuinstall"), so a long update installation does not
    /// hold up other deployments. Returns {id, job}.</summary>
    public Row StartWinUpdateDeployment(string packageId, string file, IReadOnlyList<string> names, int? timeoutSeconds = null, long? retryOf = null)
    {
        if (names is null || names.Count == 0) throw new ArgumentException(T("err.dep_no_targets"));
        var lib = Library();
        var data = Pkg(lib.Load);
        var pkg = data.Packages.FirstOrDefault(p => string.Equals(p.Id, packageId, StringComparison.OrdinalIgnoreCase))
                  ?? throw new ArgumentException($"{packageId} is not in the library.");
        if (pkg.Files.All(f => f.Path != file) || !WinUpdate.IsUpdateFile(file)) throw new ArgumentException(T("err.dep_file"));
        var steps = Chain.ValidateSteps(pkg, [new PackageStep { Type = "install", File = file }]);
        return StartChainRun(lib, data, pkg, steps, names, timeoutSeconds, retryOf, single: file);
    }

    /// <summary>A file a chain sends: the local copy, its registered SHA-256 and - for a Windows update - its KB / build.</summary>
    private sealed record ChainFile(string Local, string Sha, string? Kb, string? OsBuild);

    private Row StartChainRun(PackageLibrary lib, PackageManifest data, PackageEntry pkg, List<PackageStep> steps, IReadOnlyList<string> names,
                              int? timeoutSeconds, long? retryOf, string? single)
    {
        var timeout = timeoutSeconds is > 0 ? timeoutSeconds.Value : Settings.Deploy.TimeoutMinutes * 60;
        // every file the chain sends: present and unchanged before anything starts
        var files = new Dictionary<string, ChainFile>();
        foreach (var s in steps.Where(s => s.File is not null))
        {
            var rec = Chain.FindFile(pkg, data.Packages, s.File)!;
            var owner = data.Packages.FirstOrDefault(p => p.Files.Contains(rec)) ?? pkg;
            var local = Pkg(() => lib.File(rec.Path));
            if (!File.Exists(local) || !string.Equals(PackageLibrary.Sha256File(local), rec.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(T("err.dep_hash", ("file", rec.Path)));
            files[rec.Path] = new ChainFile(local, rec.Sha256, owner.Kind == "winupdate" ? owner.Kb : null, owner.Kind == "winupdate" ? owner.OsBuild : null);
        }
        var guids = Store.ResolveNames(names);
        var comps = Computers().ToDictionary(c => (string)c["guid"]!);
        var unconfirmed = SyncUnconfirmed();
        var refused = guids.Distinct().Where(g => comps.ContainsKey(g) && unconfirmed.Contains(g)).Select(g => Str(comps[g]["name"])).ToList();
        var targets = guids.Distinct().Where(g => comps.ContainsKey(g) && !unconfirmed.Contains(g)).Select(g => (g, Str(comps[g]["name"]))).ToList();
        if (targets.Count == 0 && refused.Count > 0)
            throw new ArgumentException($"Not confirmed by this instance's AD sync yet (received from a sync peer): {string.Join(", ", refused)}");
        var wu = steps.Any(s => s.Type == "install" && WinUpdate.IsUpdateFile(s.File));
        var dep = single is not null
            ? Store.CreateDeployment(pkg.Id, pkg.Name, pkg.Version, single, "msu", "", targets)
            : Store.CreateDeployment(pkg.Id, pkg.Name, pkg.Version, "", "chain", string.Join(" → ", steps.Select(s => s.Type)), targets);
        Store.Log("deploy", T("log.dep_start", ("id", dep), ("pkg", pkg.Id), ("n", targets.Count)));
        void Ev(string msg) => Store.AddDeploymentEvent(dep, msg);
        Ev($"Deployment #{dep} started" + (single is not null ? " (Windows update)" : $" (chain of {steps.Count} steps)")
           + (retryOf is { } r ? $" (repeat of #{r}, failed computers only)" : ""));
        Ev($"Package: {(pkg.Name.Length > 0 ? pkg.Name : pkg.Id)} ({pkg.Id}) version {(pkg.Version.Length > 0 ? pkg.Version : "-")}"
           + (pkg.Kind == "winupdate" ? $", Windows build {pkg.OsBuild}" : ""));
        for (var i = 0; i < steps.Count; i++) Ev($"Step {i + 1}: {Chain.Describe(steps[i])}");
        foreach (var (path, f) in files) Ev($"File: {path}, SHA-256 {f.Sha} (re-checked before sending)" + (f.Kb is not null ? $", {f.Kb} for {f.OsBuild}" : ""));
        Ev($"Timeout per step: {timeout} s" + (wu ? $" (a Windows update step: at least {WinUpdate.MinTimeoutSeconds} s)" : ""));
        if (single is null) Ev(ChainFingerprintPrefix + ChainFingerprint(steps));
        Ev($"Targets ({targets.Count}): " + string.Join(", ", targets.Select(t => t.Item2)));
        if (refused.Count > 0)
            Ev($"Skipped ({refused.Count}, received from a sync peer and not yet confirmed by this instance's AD sync): " + string.Join(", ", refused));
        JobInfo job;
        try
        {
            // a Windows update runs long: its own job kind, so it does not block the other deployments
            job = Jobs.Start(wu ? "wuinstall" : "deploy", wu ? "wuinstall" : "deploy", p => RunDeploymentSafe(dep, () => RunChain(dep, steps, files, timeout, p)));
        }
        catch (Exception)
        {
            var why = wu ? "not started: another Windows update installation is running" : "not started: another deployment is running";
            foreach (var (g, _) in targets)
                UpdateTarget(dep, g, ("step", "done"), ("outcome", "failed"), ("error", why));
            Ev(char.ToUpperInvariant(why[0]) + why[1..]);
            Store.FinishDeployment(dep);
            throw;
        }
        return new Row { ["id"] = dep, ["job"] = job };
    }

    private const string ChainFingerprintPrefix = "Chain SHA-256: ";

    /// <summary>SHA-256 of the checked steps (with the hashes of the files they send): what exactly a deployment ran.</summary>
    private string ChainFingerprint(List<PackageStep> steps)
    {
        var pkgFiles = new Dictionary<string, string>();
        try
        {
            foreach (var p in Library().Load().Packages) foreach (var f in p.Files) pkgFiles[f.Path] = f.Sha256;
        }
        catch (PackageError) { }
        var text = System.Text.Json.JsonSerializer.Serialize(steps) + "|" +
                   string.Join("|", steps.Where(s => s.File is not null).Select(s => s.File + "=" + pkgFiles.GetValueOrDefault(s.File!, "")));
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
    }

    /// <summary>Is the computer up (SMB or RPC answers)?</summary>
    private bool Reachable(string host)
    {
        Scanner.ProbeFn probe = ProbeOverride ?? (IsDemo ? new Scanner.ProbeFn(Demo.Probe) : (h, p, t) => Scanner.Probe(h, p, t));
        return probe(host, [445, 135], 1.5).OpenPorts.Count > 0;
    }

    /// <summary>Poll <see cref="Reachable"/> until it equals <paramref name="up"/> or <paramref name="seconds"/> pass.</summary>
    private bool WaitReachable(string host, bool up, int seconds)
    {
        var until = DateTime.UtcNow.AddSeconds(Math.Max(0, seconds));
        while (true)
        {
            if (Reachable(host) == up) return true;
            if (DateTime.UtcNow >= until) return false;
            Thread.Sleep(IsDemo ? TimeSpan.FromSeconds(0.2 * Math.Max(DemoDelayScale, 0.05)) : TimeSpan.FromSeconds(5));
        }
    }

    private void SendWol(string host, byte[] packet, IReadOnlyList<string> addresses)
    {
        if (WolSender is { } fake) { fake(host, packet, addresses); return; }
        if (IsDemo) return;
        using var udp = new System.Net.Sockets.UdpClient { EnableBroadcast = true };
        foreach (var a in addresses)
            foreach (var port in new[] { 9, 7 })
                for (var k = 0; k < 3; k++) udp.Send(packet, packet.Length, new System.Net.IPEndPoint(System.Net.IPAddress.Parse(a), port));
    }

    private Row RunChain(long dep, List<PackageStep> steps, Dictionary<string, ChainFile> files, int timeout, Progress progress)
    {
        var d = Store.Deployment(dep)!;
        var targets = ((List<Row>)d["targets"]!).ToDictionary(t => (string)t["guid"]!);
        var comps = Computers().Where(c => targets.ContainsKey((string)c["guid"]!)).ToDictionary(c => (string)c["guid"]!);
        var col = Settings.Collect;
        SmbCreds? creds = null;
        var denied = new Dictionary<string, string>();
        if (!IsDemo)
        {
            var realm = Kerberos.RealmFromBaseDn(Settings.Ldap.BaseDn);
            var ous = comps.Values.Select(c => DnUtil.ParentDn(c["dn"] as string ?? "")).ToHashSet();
            var scope = ous.Count > 0 ? Directory.OuAdminScope(Settings.Ldap.User, ous) : [];
            foreach (var (g, c) in comps)
            {
                var ou = DnUtil.ParentDn(c["dn"] as string ?? "");
                var (okay, detail) = scope.TryGetValue(ou, out var s) ? s : (true, "");
                if (!okay)
                {
                    var msg = T("err.not_admin_ou", ("ou", ou), ("detail", detail));
                    denied[g] = msg.Length > 500 ? msg[..500] : msg;
                }
            }
            creds = Pdq.CredsFromLdap(Settings.Ldap, realm);
            if (!creds.HasExplicitCredential) throw new ArgumentException(T("err.pdq_creds"));
        }
        var total = targets.Count;
        var finished = 0;
        var gate = new Lock();
        void Ev(string msg, string guid) => Store.AddDeploymentEvent(dep, msg, Str(targets[guid]["name"]));
        void DemoSleep(double s) { if (DemoDelayScale > 0) Thread.Sleep(TimeSpan.FromSeconds(s * DemoDelayScale)); }

        // the remote steps as a demo: same steps and timing feel, no network
        RemoteRunResult DemoRemote(PackageStep s, Action<string, int?> onStep)
        {
            onStep("connecting", null); DemoSleep(0.3);
            if (s.File is not null) for (var pct = 0; pct <= 100; pct += 25) { onStep("copying", pct); DemoSleep(0.1); }
            onStep("running", null); DemoSleep(0.6);
            onStep("cleanup", null); DemoSleep(0.2);
            return s.Type switch
            {
                "copy" => new RemoteRunResult(0, "", $"Copied to {s.Path}\\{Path.GetFileName(s.File)}", 1),
                "delete" => new RemoteRunResult(0, "", $"Deleted {s.Path}", 0),
                "reboot" or "shutdown" => new RemoteRunResult(0, "", "", 0),
                "message" => new RemoteRunResult(0, "", "demo: shown in 1 session(s)", 0),
                _ => new RemoteRunResult(0, "", $"demo: {s.Type} ran ({(s.Script ?? "").Split('\n').Length} line(s))", 1),
            };
        }

        // a Windows update as a demo: the progress file grows like DISM's would
        RemoteRunResult DemoWinUpdate(string host, ChainFile f, Action<string, int?> onStep, Action<string> onProgress)
        {
            onStep("connecting", null); DemoSleep(0.3);
            for (var pct = 0; pct <= 100; pct += 20) { onStep("copying", pct); DemoSleep(0.15); }
            onStep("running", null);
            var sb = new StringBuilder();
            void Line(string l)
            {
                sb.Append(DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture)).Append(' ').Append(l).Append('\n');
                onProgress(sb.ToString());
            }
            Line($"Windows build {f.OsBuild ?? "10.0.26100"}.1000");
            if (host.Length % 4 == 0)
            {
                Line($"{f.Kb} is already installed (2026-11-12)");
                onStep("cleanup", null);
                return new RemoteRunResult(0, "", $"{f.Kb} is already installed", 1, "current");
            }
            Line("Free space on C: 48.2 GB, update 650 MB");
            Line($"Installing {f.Kb} with DISM");
            for (var p = 0; p <= 100; p += 10) { Line($"PROGRESS {p}%"); DemoSleep(0.25); }
            Line("Installed; a restart is needed");
            onStep("cleanup", null); DemoSleep(0.2);
            return new RemoteRunResult(3010, "", "The operation completed successfully.\nRestart Windows to complete this operation.", 40, "reboot");
        }

        RemoteRunResult Remote(string host, PackageStep s, Action<string, int?> onStep)
        {
            if (IsDemo) return DemoRemote(s, onStep);
            switch (s.Type)
            {
                case "copy":
                {
                    var (local, sha, _, _) = files[s.File!];
                    return Chain.RunRemote(host, creds!, col, [new Chain.Payload("-f1.bin", local, Sha256: sha)],
                        (p, run, o, tmp) => Chain.CopyScript(p["-f1.bin"], s.Path!, Path.GetFileName(local), sha, run, o, tmp), onStep, timeout);
                }
                case "delete":
                    return Chain.RunRemote(host, creds!, col, [], (_, run, o, tmp) => Chain.DeleteScript(s.Path!, run, o, tmp), onStep, timeout);
                case "powershell":
                    return Chain.RunRemote(host, creds!, col, [new Chain.Payload("-user.ps1", Bytes: Pdq.ScriptBytes(s.Script!))],
                        (p, run, o, tmp) => Chain.ScriptRunner("powershell", p["-user.ps1"], run, o, tmp), onStep, timeout);
                case "cmd":
                    return Chain.RunRemote(host, creds!, col, [new Chain.Payload("-user.cmd", Bytes: Chain.CmdFileBytes(s.Script!))],
                        (p, run, o, tmp) => Chain.ScriptRunner("cmd", p["-user.cmd"], run, o, tmp), onStep, timeout);
                case "message":
                    return Chain.RunRemote(host, creds!, col, [new Chain.Payload("-user.txt", Bytes: Chain.MessageFileBytes(s.Text!))],
                        (p, run, o, tmp) => Chain.MessageScript(p["-user.txt"], s.Seconds ?? Chain.DefaultMessageSeconds, run, o, tmp), onStep, timeout);
                default:                                                         // reboot / shutdown
                    return Chain.RunRemote(host, creds!, col, [],
                        (_, run, o, tmp) => Chain.PowerScript(s.Type == "reboot", s.Seconds ?? Chain.DefaultPowerDelay, run, o, tmp), onStep, timeout);
            }
        }

        void Work(string guid)
        {
            var now = Db.UtcNow();
            if (denied.ContainsKey(guid) || !comps.TryGetValue(guid, out var c))
            {
                var why = denied.GetValueOrDefault(guid) ?? "computer not found";
                UpdateTarget(dep, guid, ("step", "done"), ("outcome", "failed"), ("started", now), ("finished", now), ("error", why));
                Ev("Failed before start: " + why, guid);
                return;
            }
            var host = c["dns_hostname"] is string { Length: > 0 } dns ? dns : Str(c["name"]);
            Ev($"Start on {host}", guid);
            Jobs_Track(progress, guid, "deploy");
            UpdateTarget(dep, guid, ("step", "connecting"), ("started", now));
            string outcome = "ok", error = "";
            int? lastCode = null;
            var needReboot = false;
            var alreadyCurrent = 0;
            try
            {
                for (var i = 0; i < steps.Count; i++)
                {
                    var s = steps[i];
                    var label = $"chain:{i + 1}:{steps.Count}:{s.Type}";
                    var basePct = i * 100 / steps.Count;
                    UpdateTarget(dep, guid, ("step", label), ("percent", basePct));
                    Ev($"Step {i + 1}/{steps.Count}: {Chain.Describe(s)}", guid);
                    Action<string, int?> onStep = (sub, pct) =>
                        UpdateTarget(dep, guid, ("step", label), ("percent", basePct + (sub == "copying" && pct is { } p ? p / steps.Count / 2 : 0)));
                    string? fail = null;
                    var unreachable = false;
                    try
                    {
                        switch (s.Type)
                        {
                            case "install" when WinUpdate.IsUpdateFile(s.File):
                            {
                                var f = files[s.File!];
                                var have = Str((c["inventory"] as JsonObject)?["os_version"]);
                                if (f.OsBuild is { Length: > 0 } want && have.Length > 0 && have != want)
                                {
                                    fail = $"the update is for Windows build {want}, the computer runs {have} (not copied)";
                                    break;
                                }
                                var seen = 0;
                                var logged = -100;                               // the log gets a line every 25% at most
                                void OnProgress(string text)
                                {
                                    var lines = text.Replace("\r\n", "\n").Split('\n');
                                    var complete = lines.Length - 1;                 // the last line may still be being written
                                    for (; seen < complete; seen++)
                                    {
                                        if (WinUpdate.ParseProgress(lines[seen]) is not { } pl) continue;
                                        if (pl.Percent is { } pc)
                                        {
                                            UpdateTarget(dep, guid, ("step", label), ("percent", basePct + pc / steps.Count));
                                            if (pc == 100 ? logged < 100 : pc >= logged + 25)
                                            {
                                                logged = pc;
                                                Ev($"Windows update: {pl.Time} installing {pc}%", guid);
                                            }
                                        }
                                        else if (pl.Text.Length > 0) Ev($"Windows update: {pl.Time} {pl.Text}", guid);
                                    }
                                }
                                RemoteRunResult res;
                                if (IsDemo) res = DemoWinUpdate(host, f, onStep, OnProgress);
                                else
                                {
                                    var ext = Path.GetExtension(f.Local).ToLowerInvariant();
                                    res = Chain.RunRemote(host, creds!, col, [new Chain.Payload("-wu" + ext, f.Local, Sha256: f.Sha)],
                                        (p, run, o, tmp) => WinUpdate.InstallScript(p["-wu" + ext], f.Kb ?? "", f.OsBuild, p, run, o, tmp), onStep,
                                        Math.Max(timeout, WinUpdate.MinTimeoutSeconds), scratch: WinUpdate.Scratch,
                                        progressSuffix: WinUpdate.ProgressSuffix, onProgress: OnProgress);
                                }
                                lastCode = res.ExitCode;
                                var wuOutcome = WinUpdate.Outcome(res);
                                Ev($"Windows update result: {wuOutcome}, exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"}"
                                   + (res.Error.Length > 0 ? $", error: {res.Error}" : ""), guid);
                                if (res.Output.Trim().Length > 0) Ev("Output:\n" + Cap(res.Output.Trim(), 20000), guid);
                                if (wuOutcome == "reboot") needReboot = true;
                                if (wuOutcome == "current") alreadyCurrent++;
                                if (wuOutcome == "failed") fail = $"Windows update failed (exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"})" + (res.Error.Length > 0 ? $": {res.Error}" : "");
                                break;
                            }
                            case "wait":
                            {
                                var sec = s.Seconds ?? Chain.DefaultWait;
                                Ev($"Waiting {sec}s", guid);
                                if (IsDemo) DemoSleep(Math.Min(sec, 5) * 0.2);
                                else Thread.Sleep(TimeSpan.FromSeconds(sec));
                                break;
                            }
                            case "install":
                            {
                                var (local, sha, _, _) = files[s.File!];
                                var kind = Deploy.InstallerKind(s.File!)!;
                                var res = IsDemo
                                    ? Demo.Deploy(host, local, kind, s.Args ?? "", onStep, DemoDelayScale)
                                    : Deploy.DeployOne(host, creds!, Library(), s.File!, kind, s.Args ?? "", col, onStep, timeout, expectedSha256: sha);
                                lastCode = res.ExitCode;
                                Ev($"Install result: {res.Outcome}, exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"}"
                                   + (res.Error.Length > 0 ? $", error: {res.Error}" : ""), guid);
                                if (res.Log.Length > 0) Ev("Installer output:\n" + Cap(res.Log.Trim(), 20000), guid);
                                if (res.Outcome == "reboot") needReboot = true;
                                if (res.Outcome == "failed") fail = $"install failed (exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"})" + (res.Error.Length > 0 ? $": {res.Error}" : "");
                                break;
                            }
                            case "scan":
                            {
                                FullScan(guids: [guid]);
                                var st = Store.Computer(guid);
                                Ev($"Scan: online {(st?["online"] is true ? "yes" : "no")}, inventory {st?["scan_status"] ?? "-"}", guid);
                                if (st?["online"] is not true) fail = "scan: the computer did not answer";
                                break;
                            }
                            case "wol":
                            {
                                if (Reachable(host)) { Ev("Wake on LAN: the computer is already on", guid); break; }
                                var mac = (c["inventory"] as JsonObject)?["mac_address"] is JsonValue mv && mv.TryGetValue<string>(out var ms) ? ms : null;
                                var packet = Chain.MagicPacket(mac);
                                if (packet is null) { fail = "wake on LAN: no MAC address known (collect the inventory once while it is on)"; break; }
                                var addrs = Chain.WolAddresses(c["ip"] as string);
                                SendWol(host, packet, addrs);
                                Ev($"Wake on LAN sent to {mac} via {string.Join(", ", addrs)}; waiting up to {s.Seconds}s", guid);
                                if ((s.Seconds ?? 0) > 0 && !WaitReachable(host, true, s.Seconds!.Value))
                                    fail = $"wake on LAN: the computer did not come up within {s.Seconds}s";
                                break;
                            }
                            default:                                             // remote steps
                            {
                                var res = Remote(host, s, onStep);
                                lastCode = res.ExitCode;
                                Ev($"Result: exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"}"
                                   + (res.Error.Length > 0 ? $", error: {res.Error}" : ""), guid);
                                if (res.Output.Length > 0) Ev("Output:\n" + Cap(res.Output, 20000), guid);
                                if (res.Error.Length > 0 || res.ExitCode is not 0)
                                {
                                    fail = $"{s.Type} failed (exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"})" + (res.Error.Length > 0 ? $": {res.Error}" : "");
                                    break;
                                }
                                if (s.Type is "reboot" or "shutdown") needReboot = false;
                                if (s.Type == "reboot" && s.Wait == true)
                                {
                                    var delay = s.Seconds ?? Chain.DefaultPowerDelay;
                                    Ev($"Waiting for the restart (down within {delay + 300}s, back within {timeout}s)", guid);
                                    if (IsDemo) DemoSleep(1.0);
                                    else if (!WaitReachable(host, false, delay + 300)) fail = "reboot: the computer did not go down";
                                    else if (!WaitReachable(host, true, timeout)) fail = $"reboot: the computer did not come back within {timeout}s";
                                    else Thread.Sleep(TimeSpan.FromSeconds(30));         // let the services start
                                    if (fail is null) Ev("The computer is back", guid);
                                }
                                if (s.Type == "shutdown" && i < steps.Count - 1) Ev("NOTE: the computer is shutting down; the next steps need it on (e.g. a wake on LAN step)", guid);
                                break;
                            }
                        }
                    }
                    catch (Unreachable exc)
                    {
                        unreachable = true;
                        fail = $"{s.Type}: {exc.Message}";
                    }
                    catch (Exception exc) when (exc is DeployError or ArgumentException or CollectError or IOException or InvalidOperationException
                                                    or System.Net.Sockets.SocketException or UnauthorizedAccessException)
                    {
                        fail = $"{s.Type}: {exc.GetType().Name}: {exc.Message}";
                    }
                    if (fail is null) continue;
                    Ev($"Step {i + 1} failed: {fail}", guid);
                    if (error.Length == 0) error = $"step {i + 1}: {fail}";
                    outcome = unreachable && outcome == "ok" && i == 0 ? "unreachable" : "failed";
                    if (s.ContinueOnError != true) { Ev("Chain stopped", guid); break; }
                    Ev("Continuing with the next step (continue on error)", guid);
                }
                if (outcome == "ok" && needReboot) outcome = "reboot";
                if (outcome == "ok" && steps.Count == 1 && alreadyCurrent == 1) outcome = "current";   // a single update that was already there
                UpdateTarget(dep, guid, ("step", "done"), ("percent", null), ("outcome", outcome), ("exit_code", lastCode),
                             ("error", Cap(error, 500)), ("finished", Db.UtcNow()));
                Ev($"Result: {outcome}", guid);
            }
            catch (Exception exc)          // one computer's failure must not stop the others
            {
                Log.Logger.LogWarning(exc, "Chain on {Host} failed: {Error}", host, exc.Message);
                var err = $"{exc.GetType().Name}: {exc.Message}";
                UpdateTarget(dep, guid, ("step", "done"), ("percent", null), ("outcome", "failed"), ("error", Cap(err, 500)), ("finished", Db.UtcNow()));
                Ev(Cap("Failed: " + err, 1000), guid);
            }
            finally
            {
                Jobs_Track(progress, guid, null);
            }
        }

        Parallel.ForEach(targets.Keys.ToList(), new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(8, total)) }, g =>
        {
            Work(g);
            lock (gate)
            {
                finished++;
                progress.Report(finished, total, "");
            }
        });
        var status = Store.FinishDeployment(dep);
        var done = (List<Row>)Store.Deployment(dep)!["targets"]!;
        var ok = done.Count(t => t["outcome"] as string is "ok" or "reboot");
        var failedN = done.Count(t => t["outcome"] as string == "failed");
        Store.AddDeploymentEvent(dep, $"Deployment finished: {status} (ok {ok}, failed {failedN})");
        Store.Log("deploy", T("log.dep_done", ("id", dep), ("status", status)));
        return new Row { ["id"] = dep, ["status"] = status, ["ok"] = ok, ["failed"] = failedN };
    }

    private static string Cap(string s, int n) => s.Length > n ? s[..n] : s;

    // ------------------------------------------------------------------ messages to the computers
    /// <summary>Replaces showing the message on a computer (tests): (host, text, seconds) -> result.</summary>
    internal Func<string, string, int, RemoteRunResult>? MessageSender { get; set; }

    /// <summary>Show <paramref name="text"/> to the users logged on to the computers (<paramref name="names"/> plus the
    /// members of <paramref name="fleetIds"/>), with msg.exe as SYSTEM, like the chain's message step. Runs as the
    /// "message" job; its result is {total, ok, nobody, failed, unreachable, results: [{name, outcome, detail}]}.</summary>
    public JobInfo SendMessage(IReadOnlyList<string> names, IReadOnlyList<long> fleetIds, string text, int? seconds = null)
    {
        var msg = Chain.ValidMessage(text);
        var secs = Math.Clamp(seconds ?? Chain.DefaultMessageSeconds, 10, 86400);
        var pv = DeploymentPreview(names ?? [], fleetIds ?? []);
        var ids = (List<string>)pv["ids"]!;
        if (ids.Count == 0) throw new ArgumentException(T("err.dep_no_targets"));
        var comps = Computers().ToDictionary(c => (string)c["guid"]!);
        var targets = ids.Where(comps.ContainsKey).Select(g => comps[g]).ToList();
        return Jobs.Start("message", "message", progress => RunMessage(targets, msg, secs, progress));
    }

    private Row RunMessage(List<Row> targets, string text, int seconds, Progress progress)
    {
        SmbCreds? creds = null;
        if (!IsDemo && MessageSender is null)
        {
            creds = Pdq.CredsFromLdap(Settings.Ldap, Kerberos.RealmFromBaseDn(Settings.Ldap.BaseDn));
            if (!creds.HasExplicitCredential) throw new ArgumentException(T("err.pdq_creds"));
        }
        var results = new List<Row>();
        var gate = new Lock();
        var done = 0;
        Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(8, targets.Count)) }, c =>
        {
            var name = Str(c["name"]);
            var host = c["dns_hostname"] is string { Length: > 0 } dns ? dns : name;
            string outcome, detail;
            try
            {
                RemoteRunResult r;
                if (MessageSender is { } fake) r = fake(host, text, seconds);
                else if (IsDemo)
                {
                    if (DemoDelayScale > 0) Thread.Sleep(TimeSpan.FromSeconds(0.4 * DemoDelayScale));
                    if (c["online"] is not true) throw new Unreachable("demo: the computer is offline");
                    r = name.Length % 3 == 0 ? new RemoteRunResult(0, "", "No user is logged on: the message was not shown", 0)
                                             : new RemoteRunResult(0, "", "Shown in 1 session(s)", 0);
                }
                else
                    r = Chain.RunRemote(host, creds!, Settings.Collect, [new Chain.Payload("-user.txt", Bytes: Chain.MessageFileBytes(text))],
                        (p, run, o, tmp) => Chain.MessageScript(p["-user.txt"], seconds, run, o, tmp), (_, _) => { }, 120);
                detail = (r.Error.Length > 0 ? r.Error : r.Output).Trim();
                outcome = r.Error.Length > 0 || r.ExitCode is not 0 ? "failed"
                    : r.Output.StartsWith("No user is logged on", StringComparison.Ordinal) ? "nobody" : "ok";
            }
            catch (Unreachable exc) { (outcome, detail) = ("unreachable", exc.Message); }
            catch (Exception exc) when (exc is DeployError or ArgumentException or CollectError or IOException or InvalidOperationException
                                            or System.Net.Sockets.SocketException or UnauthorizedAccessException)
            {
                (outcome, detail) = ("failed", $"{exc.GetType().Name}: {exc.Message}");
            }
            lock (gate)
            {
                results.Add(new Row { ["name"] = name, ["outcome"] = outcome, ["detail"] = Cap(detail, 300) });
                progress.Report(++done, targets.Count, name);
            }
        });
        results.Sort((a, b) => string.Compare((string)a["name"]!, (string)b["name"]!, StringComparison.OrdinalIgnoreCase));
        int N(string o) => results.Count(r => (string)r["outcome"]! == o);
        var bad = results.Where(r => r["outcome"] as string is "failed" or "unreachable").Select(r => $"{r["name"]} ({r["outcome"]})").ToList();
        Store.Log("message", T("log.message", ("n", targets.Count), ("ok", N("ok")), ("nobody", N("nobody")), ("bad", bad.Count), ("text", Cap(text, 120)))
                             + (bad.Count > 0 ? " – " + Cap(string.Join(", ", bad), 600) : ""));
        return new Row
        {
            ["total"] = targets.Count, ["ok"] = N("ok"), ["nobody"] = N("nobody"), ["failed"] = N("failed"), ["unreachable"] = N("unreachable"),
            ["results"] = results,
        };
    }

    // ------------------------------------------------------------------ firewall rule for the sync listener
    /// <summary>The rule script for this instance's sync settings: {filename, content, port, network}.</summary>
    public Row FirewallScript()
    {
        var sy = Settings.Sync;
        string net;
        try { net = SyncNet.AllowedNetwork(sy.Network).ToString(); }
        catch (SyncError exc) { throw new ArgumentException(exc.Message, exc); }
        return new Row
        {
            ["filename"] = Firewall.ScriptName, ["content"] = Firewall.RuleScript(sy.Port, net, Firewall.ProgramPath()),
            ["port"] = sy.Port, ["network"] = net,
        };
    }

    /// <summary>Replaces running the firewall script (tests): script -> output.</summary>
    internal Func<string, string>? FirewallRunner { get; set; }

    /// <summary>Add the sync firewall rule on this computer (the desktop app runs elevated). {ok, message}.</summary>
    public Row FirewallApply()
    {
        var s = FirewallScript();
        var script = (string)s["content"]!;
        string outp;
        if (FirewallRunner is { } fake) outp = fake(script);
        else if (IsDemo) outp = $"demo: firewall rule '{Firewall.RuleName}' would be added (TCP {s["port"]} from {s["network"]})";
        else
        {
            try { outp = Firewall.Apply(script); }
            catch (Exception exc) when (exc is InvalidOperationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
            {
                throw new ArgumentException(T("err.firewall", ("err", exc.Message)), exc);
            }
        }
        Store.Log("sync", T("log.firewall", ("port", s["port"]), ("net", s["network"])));
        return new Row { ["ok"] = true, ["message"] = outp };
    }

    /// <summary>The full event log of a deployment as text.</summary>
    public string DeploymentLog(long depId)
    {
        _ = Store.Deployment(depId) ?? throw new NotFound($"Deployment {depId} not found");
        var lines = Store.DeploymentEvents(depId).Select(e =>
            $"{e["ts"]}  " + (e["name"] is string { Length: > 0 } n ? $"[{n}] " : "") + e["message"]).ToList();
        return lines.Count > 0 ? string.Join("\n", lines) : "(no log)";
    }

    /// <summary>Computers of running deployments that have not finished yet (0 = nothing to lose by closing).</summary>
    public int UnfinishedDeployments()
    {
        if (!Jobs.List().Any(j => j.Kind is "deploy" or "wuinstall" && j.Status == "running")) return 0;
        var n = 0L;
        foreach (var d in Store.Deployments(20))
            if ((string?)d["status"] == "running")
                n += Convert.ToInt64(d["total"], CultureInfo.InvariantCulture) - Convert.ToInt64(d["ok"], CultureInfo.InvariantCulture)
                     - Convert.ToInt64(d["reboot"], CultureInfo.InvariantCulture) - Convert.ToInt64(d["failed"], CultureInfo.InvariantCulture);
        return (int)Math.Max(n, 1);
    }

    /// <summary>Like <see cref="RunDeployment"/>, but a failure before / outside the per-computer work (directory lookup,
    /// missing credentials, ...) must not leave the computers 'queued' forever: they are marked failed with the reason.</summary>
    private object? RunDeploymentSafe(long dep, Func<object?> run)
    {
        try
        {
            return RunDeploymentHook is { } hook ? hook(dep) : run();
        }
        catch (Exception exc)
        {
            var reason = $"{exc.GetType().Name}: {exc.Message}";
            if (reason.Length > 500) reason = reason[..500];
            if (exc is ArgumentException) Log.Logger.LogWarning("Deployment {Id} aborted: {Reason}", dep, reason);
            else Log.Logger.LogWarning(exc, "Deployment {Id} aborted: {Reason}", dep, reason);
            if (Store.Deployment(dep)?["targets"] is List<Row> targets)
                foreach (var t in targets.Where(t => (string?)t["step"] != "done"))
                    UpdateTarget(dep, (string)t["guid"]!, ("step", "done"), ("percent", null), ("outcome", "failed"), ("error", reason),
                                 ("finished", Db.UtcNow()));
            Store.AddDeploymentEvent(dep, $"Deployment aborted before / during the run: {reason}");
            Store.FinishDeployment(dep);
            throw;
        }
    }

    private Row RunDeployment(long dep, string local, string relPath, string sha256, string kind, string args, int timeout, Progress progress)
    {
        var d = Store.Deployment(dep)!;
        var targets = ((List<Row>)d["targets"]!).ToDictionary(t => (string)t["guid"]!);
        var comps = Computers().Where(c => targets.ContainsKey((string)c["guid"]!)).ToDictionary(c => (string)c["guid"]!);
        var col = Settings.Collect;
        SmbCreds? creds = null;
        var denied = new Dictionary<string, string>();
        if (!IsDemo)
        {
            var realm = Kerberos.RealmFromBaseDn(Settings.Ldap.BaseDn);
            var ous = comps.Values.Select(c => DnUtil.ParentDn(c["dn"] as string ?? "")).ToHashSet();
            var scope = ous.Count > 0 ? Directory.OuAdminScope(Settings.Ldap.User, ous) : [];
            foreach (var (g, c) in comps)
            {
                var ou = DnUtil.ParentDn(c["dn"] as string ?? "");
                var (okay, detail) = scope.TryGetValue(ou, out var s) ? s : (true, "");
                if (!okay)
                {
                    var msg = T("err.not_admin_ou", ("ou", ou), ("detail", detail));
                    denied[g] = msg.Length > 500 ? msg[..500] : msg;
                }
            }
            creds = Pdq.CredsFromLdap(Settings.Ldap, realm);
            if (!creds.HasExplicitCredential) throw new ArgumentException(T("err.pdq_creds"));
        }
        PackageEntry? pkg = null;
        try { pkg = Library().Get((string)d["package_id"]!); }
        catch (PackageError) { }
        HashSet<string> current;
        try
        {
            current = AlreadyInstalled(pkg?.Name ?? d["package_name"] as string ?? "", pkg?.Id ?? (string)d["package_id"]!, d["version"] as string ?? "");
        }
        catch (Exception exc)              // the inventory check must never block a deployment
        {
            Log.Logger.LogDebug(exc, "Deployment {Id}: could not check the installed versions", dep);
            current = [];
        }
        var total = targets.Count;
        var finished = 0;
        var gate = new Lock();
        void Ev(string msg, string? guid = null) => Store.AddDeploymentEvent(dep, msg, guid is null ? "" : Str(targets[guid]["name"]));

        Action<string, int?> StepCb(string guid)
        {
            string? last = null;
            return (step, percent) =>
            {
                UpdateTarget(dep, guid, ("step", step), ("percent", percent));
                if (step != last)
                {
                    last = step;
                    Ev($"Step: {step}", guid);
                }
                else if (step == "copying" && percent == 100)
                {
                    Ev("Copy complete (100%)", guid);
                }
            };
        }

        void Work(string guid)
        {
            var now = Db.UtcNow();
            if (denied.ContainsKey(guid) || !comps.TryGetValue(guid, out var c))
            {
                var why = denied.GetValueOrDefault(guid) ?? "computer not found";
                UpdateTarget(dep, guid, ("step", "done"), ("outcome", "failed"), ("started", now), ("finished", now), ("error", why));
                Ev("Failed before start: " + why, guid);
                return;
            }
            if (current.Contains(guid))
            {
                var msg = $"The same version ({d["version"]}) is already installed: not installed again";
                UpdateTarget(dep, guid, ("step", "done"), ("percent", null), ("outcome", "current"), ("started", now), ("finished", now), ("log", msg));
                Ev(msg, guid);
                return;
            }
            var host = c["dns_hostname"] is string { Length: > 0 } dns ? dns : Str(c["name"]);
            Ev($"Start on {host}", guid);
            Jobs_Track(progress, guid, "deploy");
            UpdateTarget(dep, guid, ("step", "connecting"), ("started", now));
            try
            {
                var res = IsDemo
                    ? Demo.Deploy(host, local, kind, args, StepCb(guid), DemoDelayScale)
                    : Deploy.DeployOne(host, creds!, Library(), relPath, kind, args, col, StepCb(guid), timeout, expectedSha256: sha256);
                UpdateTarget(dep, guid, ("step", "done"), ("percent", null), ("outcome", res.Outcome), ("exit_code", res.ExitCode),
                             ("error", res.Error), ("log", res.Log), ("finished", Db.UtcNow()));
                Ev($"Result: {res.Outcome}, exit code {res.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "None"}"
                   + (res.Error.Length > 0 ? $", error: {res.Error}" : ""), guid);
                if (res.Log.Length > 0)
                {
                    var text = res.Log.Trim();
                    Ev("Installer output:\n" + (text.Length > 20000 ? text[..20000] : text), guid);
                }
            }
            catch (Exception exc)          // one computer's failure must not stop the others
            {
                var unreachable = exc is Unreachable;
                if (unreachable) Log.Logger.LogWarning("Deploy {Host} failed: {Error}", host, exc.Message);
                else Log.Logger.LogWarning(exc, "Deploy {Host} failed: {Error}", host, exc.Message);
                var err = $"{exc.GetType().Name}: {exc.Message}";
                UpdateTarget(dep, guid, ("step", "done"), ("percent", null), ("outcome", unreachable ? "unreachable" : "failed"),
                             ("error", err.Length > 500 ? err[..500] : err), ("finished", Db.UtcNow()));
                Ev(("Failed: " + err).Length > 1000 ? ("Failed: " + err)[..1000] : "Failed: " + err, guid);
            }
            finally
            {
                Jobs_Track(progress, guid, null);
            }
        }

        Parallel.ForEach(targets.Keys.ToList(), new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(8, total)) }, g =>
        {
            Work(g);
            lock (gate)
            {
                finished++;
                progress.Report(finished, total, "");
            }
        });
        var status = Store.FinishDeployment(dep);
        var done = (List<Row>)Store.Deployment(dep)!["targets"]!;
        var ok = done.Count(t => t["outcome"] as string is "ok" or "reboot");
        var failed = done.Count(t => t["outcome"] as string == "failed");
        Store.AddDeploymentEvent(dep, $"Deployment finished: {status} (ok {ok}, failed {failed})");
        Store.Log("deploy", T("log.dep_done", ("id", dep), ("status", status)));
        return new Row { ["id"] = dep, ["status"] = status, ["ok"] = ok, ["failed"] = failed };
    }

    private static void Jobs_Track(Progress? progress, string key, string? phase) => ADmiral.Core.Jobs.Track(progress, key, phase);

    // ------------------------------------------------------------------ background loops
    private static bool Wait(TimeSpan t, CancellationToken stop) => stop.WaitHandle.WaitOne(t);

    /// <summary>Every scan.interval_minutes (0 = off) check which computers answer. The interval is read again each
    /// round, so a change in the settings takes effect at once.</summary>
    public void PingLoop(CancellationToken stop, double tickSeconds = 30.0)
    {
        var last = Stopwatch.GetTimestamp();
        while (!Wait(TimeSpan.FromSeconds(tickSeconds), stop))
        {
            var minutes = Settings.Scan.IntervalMinutes;
            if (minutes <= 0)
            {
                last = Stopwatch.GetTimestamp();
                continue;
            }
            if (Stopwatch.GetElapsedTime(last) < TimeSpan.FromMinutes(minutes)) continue;
            last = Stopwatch.GetTimestamp();
            if (Jobs.List().Any(j => j.Status == "running" && j.Kind is "scan" or "collect" or "full" or "ad-sync"))
                continue;                                  // a scan is already going: try again next interval
            try
            {
                Jobs.Start("scan", "scan", p => Scan(null, p));
            }
            catch (Exception exc)          // never ends the loop
            {
                Log.Logger.LogWarning(exc, "Automatic reachability check could not start");
            }
        }
    }

    /// <summary>At start-up (after a short pause) and then every 24 hours: look for a new version.</summary>
    public void AppUpdateLoop(CancellationToken stop, double firstDelaySeconds = 20)
    {
        if (Wait(TimeSpan.FromSeconds(firstDelaySeconds), stop)) return;
        while (true)
        {
            if (Settings.AppUpdate.Enabled && Settings.AppUpdate.Url.Trim().Length > 0)
            {
                try { AppUpdateCheck(); }
                catch (Exception exc) { Log.Logger.LogError(exc, "Update check failed"); }
            }
            if (Wait(TimeSpan.FromHours(AppUpdate.CheckHours), stop)) return;
        }
    }

    /// <summary>Every logins.interval_minutes read the login-tracking folder (when the option is on).</summary>
    public void LoginsLoop(CancellationToken stop, double tickSeconds = 30.0)
    {
        long? last = null;
        while (!Wait(TimeSpan.FromSeconds(tickSeconds), stop))
        {
            var cfg = Settings.Logins;
            if (!(cfg.Enabled && cfg.Path.Trim().Length > 0)
                || (last is { } l && Stopwatch.GetElapsedTime(l) < TimeSpan.FromMinutes(cfg.IntervalMinutes)))
                continue;
            last = Stopwatch.GetTimestamp();
            try { ImportLogins(); }
            catch (Exception exc) { Log.Logger.LogWarning(exc, "Reading the login-tracking folder failed"); }
        }
    }

    /// <summary>Once a day (checked every half hour) read the printers, so the history fills without anyone opening the page.</summary>
    public void PrinterDailyLoop(CancellationToken stop, double checkSeconds = 1800.0)
    {
        if (Wait(TimeSpan.FromSeconds(30), stop)) return;
        while (true)
        {
            try { PrinterCollectDaily(); }
            catch (Exception exc) when (exc is not ObjectDisposedException) { Log.Logger.LogError(exc, "Daily printer reading failed"); }
            if (Wait(TimeSpan.FromSeconds(checkSeconds), stop)) return;
        }
    }

    // ------------------------------------------------------------------ ADmiral's own updates
    private static Dictionary<string, object?> NewAppUpdateState(string? checkedAt) => new()
    {
        ["checked"] = checkedAt, ["error"] = null, ["latest"] = null, ["available"] = false, ["previous"] = null, ["notes"] = "",
    };

    /// <summary>{checked, error, latest, available, previous, notes, current, enabled, url, can_install, has_key}.</summary>
    public Row AppUpdateState()
    {
        Row st;
        lock (_appUpdateLock) st = new Row(_appUpdate);
        if (st["checked"] is null)                     // the last check of an earlier run (kept in the database)
            st["checked"] = Store.UpdateReference().Meta.GetValueOrDefault("app_checked") is { Length: > 0 } c ? c : null;
        var cfg = Settings.AppUpdate;
        st["current"] = Diag.Version;
        st["enabled"] = cfg.Enabled;
        st["url"] = cfg.Url;
        st["can_install"] = AppUpdate.CanInstall();
        st["has_key"] = AppUpdate.BuiltinPublicKey.Length > 0;
        return st;
    }

    /// <summary>Forget the in-memory result of the last check (as after a restart; tests).</summary>
    internal void ForgetAppUpdateCheck()
    {
        lock (_appUpdateLock) _appUpdate["checked"] = null;
    }

    /// <summary>A fresh, verified manifest that is not older than the newest one accepted before (replay floor kept in
    /// update_meta: app_seen_version / app_seen_signed).</summary>
    private (JsonObject Manifest, AppUpdateInfo Info) CheckedAppManifest(AppUpdateSettings cfg)
    {
        var (manifest, info) = AppUpdateChecker(cfg, Settings.Proxy, Diag.Version);
        var seenVersion = Store.Scalar("SELECT v FROM update_meta WHERE k = 'app_seen_version'") as string;
        DateTimeOffset? seenSigned = Store.Scalar("SELECT v FROM update_meta WHERE k = 'app_seen_signed'") is string ss
            && DateTimeOffset.TryParse(ss, System.Globalization.CultureInfo.InvariantCulture,
                   System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
        var (version, signed) = AppUpdate.CheckReplay(info.Latest, AppUpdate.Time(manifest, "signed"), seenVersion, seenSigned);
        var keep = new Dictionary<string, string> { ["app_seen_version"] = version };
        if (signed is { } sg) keep["app_seen_signed"] = sg.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        Store.SetUpdateMeta(keep);
        return (manifest, info);
    }

    /// <summary>Read and verify the manifest at the update location. Never throws: the outcome is in the state.</summary>
    public Row AppUpdateCheck()
    {
        lock (_appUpdateLock)
        {
            var st = NewAppUpdateState(Db.UtcNow());
            try
            {
                var (_, info) = CheckedAppManifest(Settings.AppUpdate);
                st["latest"] = info.Latest;
                st["notes"] = info.Notes;
                st["available"] = info.Available;
                st["previous"] = info.Previous;
            }
            catch (Exception exc)          // shown in the settings, not fatal
            {
                var err = $"{exc.GetType().Name}: {exc.Message}";
                st["error"] = err.Length > 300 ? err[..300] : err;
                Log.Logger.LogWarning("Update check failed: {Error}", exc.Message);
            }
            _appUpdate = st;
            try
            {
                Store.SetUpdateMeta(new Dictionary<string, string> { ["app_checked"] = (string)st["checked"]! });
            }
            catch (Exception exc)          // only the "last checked" note
            {
                Log.Logger.LogDebug(exc, "Could not store the time of the update check");
            }
            if (st["available"] is true) Store.Log("appupdate", T("log.app_update_found", ("version", st["latest"])));
        }
        return AppUpdateState();
    }

    /// <summary>Download the (signed) installer of the newest - or, for a rollback, the previous - version and run it.
    /// Returns {version, rollback}.</summary>
    public Row AppUpdateInstall(bool rollback = false)
    {
        if (!AppUpdate.CanInstall()) throw new ArgumentException(T("err.upd_not_installed"));
        if (Jobs.List().Any(j => j.Status == "running")) throw new ArgumentException(T("err.upd_busy"));
        var cfg = Settings.AppUpdate;
        UpdateEntry entry;
        VerifiedInstaller installer;
        try
        {
            var (manifest, info) = CheckedAppManifest(cfg);    // always against a fresh, verified manifest
            if (rollback && info.Previous is null) throw new ArgumentException(T("err.upd_no_prev"));
            if (!rollback && !info.Available) throw new ArgumentException(T("err.upd_none"));
            entry = AppUpdate.Pick(manifest, rollback, Diag.Version);
            installer = AppUpdate.Download(cfg, Settings.Proxy, entry, AppUpdate.PrivateFolder());
        }
        catch (UpdateError exc)
        {
            throw new ArgumentException(exc.Message, exc);
        }
        Store.Log("appupdate", T("log.app_update_run", ("version", entry.Version), ("rollback", rollback ? "rollback" : "update")));
        using (installer)
        {
            try
            {
                AppUpdate.Launch(installer, WinSec.Supported ? WinSec.CurrentUserSid() : "");
            }
            catch (UpdateError exc)
            {
                throw new ArgumentException(exc.Message, exc);
            }
        }
        ExitAfterUpdate();                         // the installer closes ADmiral too; do not leave it to chance
        return new Row { ["version"] = entry.Version, ["rollback"] = rollback };
    }

    // ------------------------------------------------------------------ network printers (SNMP, read-only)
    public List<Row> PrinterList() => Store.Printers();

    private Row PrinterOr404(long pid) => Store.Printer(pid) ?? throw new NotFound($"Printer {pid} not found");

    private static Dictionary<string, object?> CleanPrinter(JsonObject data, IReadOnlyDictionary<string, object?>? current)
    {
        try { return Printers.Clean(data, current); }
        catch (PrinterError exc) { throw new ArgumentException(exc.Message, exc); }
    }

    private static bool IsUniqueViolation(SqliteException exc) => exc.SqliteErrorCode == 19;

    /// <summary>Add a printer (untrusted fields from the UI) and read it at once; returns the stored row.</summary>
    public Row PrinterAdd(JsonObject data)
    {
        var fields = CleanPrinter(data, null);
        long pid;
        try { pid = Store.AddPrinter(fields); }
        catch (SqliteException exc) when (IsUniqueViolation(exc)) { throw new ArgumentException(T("err.printer_dup", ("ip", fields["ip"]))); }
        Store.Log("printers", T("log.printer_add", ("ip", fields["ip"])));
        return PrinterPoll([pid])[0];
    }

    public Row PrinterUpdate(long pid, JsonObject data)
    {
        var cur = PrinterOr404(pid);
        var fields = CleanPrinter(data, cur);
        try { Store.UpdatePrinter(pid, fields); }
        catch (SqliteException exc) when (IsUniqueViolation(exc)) { throw new ArgumentException(T("err.printer_dup", ("ip", fields.GetValueOrDefault("ip") ?? ""))); }
        // a changed address or OID makes the old readings meaningless: read again
        string[] readKeys = ["ip", "community", "version", .. Printers.OidFields];
        if (readKeys.Any(k => fields.ContainsKey(k) && Str(fields[k]) != Str(cur.GetValueOrDefault(k))))
            return PrinterPoll([pid])[0];
        return PrinterOr404(pid);
    }

    public void PrinterDelete(long pid)
    {
        var p = PrinterOr404(pid);
        Store.DeletePrinter(pid);
        Store.Log("printers", T("log.printer_delete", ("ip", p["ip"])));
    }

    /// <summary>Read the given printers (default: all) in parallel and store the readings.</summary>
    public List<Row> PrinterPoll(IReadOnlyCollection<long>? ids = null)
    {
        var todo = Store.Printers().Where(p => ids is null || ids.Contains((long)p["id"]!)).ToList();
        if (todo.Count > 0)
        {
            var results = new Dictionary<string, object?>[todo.Count];
            Parallel.For(0, todo.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(64, todo.Count) }, i =>
            {
                var st = Printers.Read(todo[i], port: SnmpPort);        // unreachable: only the error is set, the last readings stay
                st["polled"] = Db.UtcNow();
                results[i] = st;
            });
            for (var i = 0; i < todo.Count; i++)
            {
                Store.UpdatePrinter((long)todo[i]["id"]!, results[i]);
                PrinterSample((string)todo[i]["ip"]!, results[i]);
            }
        }
        return [.. Store.Printers().Where(p => ids is null || ids.Contains((long)p["id"]!))];
    }

    private static string Today() => DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>Keep today's reading (page count, toner percentages) for the history, when the poll got data.</summary>
    private void PrinterSample(string ip, Dictionary<string, object?> st)
    {
        var toner = (st.GetValueOrDefault("toner") as IEnumerable<TonerValue> ?? []).Select(t => t.Pct).ToList();
        var pages = st.GetValueOrDefault("pages") switch
        {
            null => (long?)null,
            long l => l,
            int i => i,
            double d => (long)d,
            var o => Convert.ToInt64(o, CultureInfo.InvariantCulture),
        };
        if (pages is null && toner.All(t => t is null)) return;
        Store.SavePrinterSample(ip, Today(), pages, toner);
    }

    /// <summary>Read every printer that has no reading of today yet (called by the background loops).</summary>
    public int PrinterCollectDaily()
    {
        var today = Today();
        var seen = Store.PrinterSampleDays();
        var ids = Store.Printers().Where(p => seen.GetValueOrDefault(((string)p["ip"]!).ToLowerInvariant()) != today).Select(p => (long)p["id"]!).ToList();
        if (ids.Count > 0) PrinterPoll(ids);
        return ids.Count;
    }

    /// <summary>{ip, days: [{day, pages, toner}], forecast: <see cref="PrinterForecast"/>}.</summary>
    public Row PrinterHistory(long pid)
    {
        var p = PrinterOr404(pid);
        var hist = Store.PrinterHistory((string)p["ip"]!);
        var days = hist.Select(h => new PrinterDay((string)h["day"]!, h["pages"] is null ? null : Convert.ToInt64(h["pages"], CultureInfo.InvariantCulture),
                                                   (h["toner"] as JsonArray ?? []).Select(Num).ToList())).ToList();
        return new Row { ["ip"] = p["ip"], ["days"] = hist, ["forecast"] = Printers.Forecast(days) };
    }

    /// <summary>Look for SNMP devices in an IP range (nothing is saved): {scanned, found: [{ip, name, model, location,
    /// serial, pages, status, printer, color, known}]} (known = the id of the printer already in the list).</summary>
    public Row PrinterScan(string text, string community = "public", string version = "2c", int port = 161, double timeout = 1.0)
    {
        List<string> ips;
        try { ips = Printers.ParseRange(text); }
        catch (PrinterError exc) { throw new ArgumentException(exc.Message, exc); }
        community = (community ?? "").Trim();
        if (community.Length > 100) community = community[..100];
        if (community.Length == 0) community = "public";
        if (version is not ("1" or "2c")) throw new ArgumentException(T("err.printer_ver"));
        var known = Store.Printers().ToDictionary(p => ((string)p["ip"]!).ToLowerInvariant(), p => (long)p["id"]!);
        var results = new Dictionary<string, object?>?[ips.Count];
        Parallel.For(0, ips.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(64, ips.Count)) }, i =>
            results[i] = Printers.Probe(ips[i], community, version, port, timeout));
        var found = results.OfType<Dictionary<string, object?>>().ToList();
        foreach (var r in found) r["known"] = known.TryGetValue(((string)r["ip"]!).ToLowerInvariant(), out var id) ? id : null;
        var range = text.Trim();
        Store.Log("printers", T("log.printer_scan", ("range", range.Length > 200 ? range[..200] : range), ("n", ips.Count),
                                ("found", found.Count(r => r["printer"] is true))));
        return new Row { ["scanned"] = ips.Count, ["found"] = found };
    }

    /// <summary>Try the entered address / community / OIDs without saving anything.</summary>
    public Dictionary<string, object?> PrinterTest(JsonObject data)
    {
        var copy = (JsonObject)data.DeepClone();
        copy["ip"] ??= "";
        return Printers.Read(CleanPrinter(copy, null), timeout: 3.0, retries: 0, port: SnmpPort);
    }

    // ------------------------------------------------------------------ offline (file) collection + login tracking
    /// <summary>Import the inventory files that computers left in the shared folder (and delete them).</summary>
    public OfflineImportResult ImportOffline() => Offline.ImportInbox(Store, Settings, FileSecurity);

    /// <summary>Read the logon files of the login-tracking folder into the history (and delete them).</summary>
    public LoginImportResult ImportLogins()
    {
        var outp = Logins.ImportFolder(Store, Settings, FileSecurity);
        if (outp.Imported > 0) DataChanged();
        return outp;
    }

    /// <summary>{filename, content} of the logon script for the configured folder.</summary>
    public Dictionary<string, string> LoginsScript()
    {
        var path = (Settings.Logins.Path ?? "").Trim();
        if (path.Length == 0) throw new ArgumentException(T("err.logins_no_path"));
        return new Dictionary<string, string> { ["filename"] = Logins.ScriptName, ["content"] = Logins.RenderScript(path) };
    }

    // ------------------------------------------------------------------ security-update monitoring
    /// <summary>{enabled, builds, fetched_at, error, months}.</summary>
    /// <summary>Settings → Proxy → "Test proxy" with the saved proxy settings: {ok, message}.</summary>
    public Row TestProxy()
    {
        var (ok, message) = Updates.TestProxy(Settings.Proxy);
        return new Row { ["ok"] = ok, ["message"] = Diag.Redact(message) };
    }

    public Row UpdatesStatus()
    {
        var (builds, meta) = Store.UpdateReference();
        return new Row
        {
            ["enabled"] = Settings.Updates.Enabled, ["builds"] = builds.Count,
            ["fetched_at"] = meta.GetValueOrDefault("fetched_at") is { Length: > 0 } f ? f : null,
            ["error"] = meta.GetValueOrDefault("error") is { Length: > 0 } e ? e : null,
            ["months"] = (meta.GetValueOrDefault("months") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
        };
    }

    /// <summary>Download Microsoft's newest security-release data (via the configured proxy) and store it. {builds, months}.</summary>
    public Row RefreshUpdates(Progress? progress = null)
    {
        Store.SetUpdateMeta(new Dictionary<string, string> { ["attempted_at"] = Db.UtcNow() });
        UpdateReferenceData reference;
        try
        {
            reference = IsDemo ? Demo.Reference()
                : Updates.FetchReference(Settings.Proxy, Settings.Updates.Months, progress: progress is null ? null : (Action<int, int, string>)progress.Report);
        }
        catch (Exception exc)              // shown to the user; the old data stays in use
        {
            Log.Logger.LogWarning(exc, "Security-update data could not be downloaded");
            var err = $"{exc.GetType().Name}: {exc.Message}";
            Store.SetUpdateMeta(new Dictionary<string, string> { ["error"] = err.Length > 400 ? err[..400] : err });
            throw new ArgumentException(T("err.updates_fetch", ("err", err)), exc);
        }
        Store.SaveUpdateReference(reference.Builds, new Dictionary<string, string>
        {
            ["fetched_at"] = Db.UtcNow(), ["error"] = "", ["months"] = string.Join(",", reference.Months),
            ["kbs"] = System.Text.Json.JsonSerializer.Serialize(reference.Kbs),
        });
        Store.Log("updates", T("log.updates", ("builds", reference.Builds.Count), ("months", string.Join(", ", reference.Months))));
        return new Row { ["builds"] = reference.Builds.Count, ["months"] = reference.Months };
    }

    /// <summary>The Windows updates page: {status, reference: [{build, ubr, month, released}], computers: [...]}.</summary>
    public Row WinUpdates()
    {
        var (builds, meta) = Store.UpdateReference();
        Dictionary<string, string> kbs;
        try { kbs = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(meta.GetValueOrDefault("kbs") is { Length: > 0 } k ? k : "{}") ?? []; }
        catch (System.Text.Json.JsonException) { kbs = []; }
        var reference = builds.OrderByDescending(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => new Row { ["build"] = kv.Key, ["ubr"] = kv.Value.Ubr, ["month"] = kv.Value.Month, ["released"] = kv.Value.Released,
                                    ["kb"] = kbs.GetValueOrDefault(kv.Key) }).ToList();
        var comps = new List<Row>();
        foreach (var c in Computers())
        {
            var inv = c["inventory"] as JsonObject;
            var sec = (SecurityState)c["security"]!;
            var ver = Str(inv?["os_version"]);
            var parts = Str(inv?["os_build"]).Split('.');
            var installed = sec.Installed is { Length: > 0 } ins ? ins : ver.Length > 0 && parts.Length > 1 ? $"{ver}.{parts[1]}" : "";
            comps.Add(new Row
            {
                ["guid"] = c["guid"], ["name"] = c["name"], ["os"] = c["os"] as string ?? "", ["ou"] = c["ou"] as string ?? "",
                ["build"] = ver, ["installed"] = installed, ["state"] = sec.State, ["latest"] = sec.Latest ?? "",
                ["collected_at"] = c.GetValueOrDefault("collected_at"),
            });
        }
        return new Row { ["status"] = UpdatesStatus(), ["reference"] = reference, ["computers"] = comps };
    }

    /// <summary>Re-download the reference data when it is older than updates.refresh_hours (never fatal).</summary>
    public void EnsureUpdatesFresh()
    {
        var u = Settings.Updates;
        if (!u.Enabled) return;
        var st = UpdatesStatus();
        var tried = Db.ParseIso(Store.UpdateReference().Meta.GetValueOrDefault("attempted_at"));
        if (tried is { } t)        // successful: every refresh_hours; failed (no internet / proxy): at most hourly
        {
            var wait = TimeSpan.FromHours(st["error"] is not null ? 1 : u.RefreshHours);
            if (DateTimeOffset.UtcNow - t < wait) return;
        }
        try { RefreshUpdates(); }
        catch (ArgumentException) { }                  // already logged; the previous data stays in use
    }

    // ------------------------------------------------------------------ users (from the logon history)
    private sealed class CompAgg
    {
        public required string Guid { get; init; }
        public required string Name { get; init; }
        public int Count { get; set; }
        public required string First { get; set; }
        public required string Last { get; set; }
        public SortedSet<long> Types { get; } = [];
    }

    private sealed class UserAgg
    {
        public required string Key { get; init; }
        public required string Name { get; init; }
        public required string Domain { get; init; }
        public bool Local { get; init; }
        public JsonObject? Ad { get; init; }
        public Dictionary<string, CompAgg> Computers { get; } = [];
        public List<JsonObject> Events { get; } = [];
    }

    /// <summary>The logon events grouped by user; cached until the data changes (Store.Version).</summary>
    private Dictionary<string, UserAgg> UserIndex()
    {
        lock (_cacheLock)
            if (_userCache is { } c && c.Version == Store.Version) return c.Users;
        var version = Store.Version;
        var users = BuildUserIndex();
        lock (_cacheLock) _userCache = (version, users);
        return users;
    }

    private Dictionary<string, UserAgg> BuildUserIndex()
    {
        var names = ComputerNames();
        var ad = Store.AdUsers();
        var users = new Dictionary<string, UserAgg>(StringComparer.Ordinal);
        foreach (var (guid, ev) in Store.LogonRows())
        {
            var host = names.GetValueOrDefault(guid, "");
            var domain = Str(ev["domain"]);
            var user = Str(ev["user"]);
            var time = Str(ev["time"]);
            var local = string.Equals(domain, host, StringComparison.OrdinalIgnoreCase);      // a local account of that computer
            var key = $"{domain.ToLowerInvariant()}\\{user.ToLowerInvariant()}";
            if (!users.TryGetValue(key, out var u))
            {
                var rec = local ? null : ad.GetValueOrDefault(user.ToLowerInvariant());
                if (rec is not null && Db.Truthy(rec["missing"])) rec = null;
                users[key] = u = new UserAgg { Key = key, Name = user, Domain = domain, Local = local, Ad = rec };
            }
            if (!u.Computers.TryGetValue(guid, out var c))
                u.Computers[guid] = c = new CompAgg { Guid = guid, Name = host, First = time, Last = time };
            c.Count++;
            if (string.CompareOrdinal(time, c.First) < 0) c.First = time;
            if (string.CompareOrdinal(time, c.Last) > 0) c.Last = time;
            if (Num(ev["type"]) is { } typ) c.Types.Add((long)typ);
            var e = (JsonObject)ev.DeepClone();
            e["guid"] = guid;
            e["computer"] = host;
            u.Events.Add(e);
        }
        // users imported from an Active Directory OU who never logged on to a collected computer
        var seen = users.Values.Where(u => !u.Local).Select(u => u.Name.ToLowerInvariant()).ToHashSet();
        var netbios = IsDemo ? "CONTOSO" : Kerberos.RealmFromBaseDn(Settings.Ldap.BaseDn).Split('.')[0].ToUpperInvariant();
        foreach (var (sam, rec) in ad)
        {
            if (Db.Truthy(rec["missing"]) || !Db.Truthy(rec["imported"]) || seen.Contains(sam)) continue;
            var key = $"{netbios.ToLowerInvariant()}\\{sam}";
            users[key] = new UserAgg { Key = key, Name = Str(rec["sam"]) is { Length: > 0 } s ? s : sam, Domain = netbios, Local = false, Ad = rec };
        }
        return users;
    }

    private static object? AdValue(JsonObject? ad, string key) => ad?[key] switch
    {
        null => null,
        // (object?) casts: without them the arms would be converted to JsonNode (implicit string / bool -> JsonNode)
        JsonValue v when v.GetValueKind() == JsonValueKind.String => (object?)v.GetValue<string>(),
        JsonValue v when v.GetValueKind() is JsonValueKind.True or JsonValueKind.False => (object?)v.GetValue<bool>(),
        JsonValue v when v.GetValueKind() == JsonValueKind.Null => null,
        var n => (object?)n.DeepClone(),
    };

    private static Row UserRow(UserAgg u)
    {
        var ad = u.Ad;
        var comps = u.Computers.Values.OrderByDescending(c => c.Last, StringComparer.Ordinal).ToList();
        string Text(string k) => AdValue(ad, k) is string s ? s : "";
        return new Row
        {
            ["key"] = u.Key, ["name"] = u.Name, ["domain"] = u.Domain, ["local"] = u.Local,
            ["display_name"] = Text("display_name"), ["department"] = Text("department"), ["title"] = Text("title"), ["mail"] = Text("mail"),
            ["enabled"] = AdValue(ad, "enabled"),
            ["in_ad"] = ad is { Count: > 0 }, ["computers"] = comps.Count, ["logons"] = comps.Sum(c => c.Count),
            ["last_logon"] = comps.Count > 0 ? comps[0].Last : Text("last_logon") is { Length: > 0 } l ? l : null,
            ["last_computer"] = comps.Count > 0 ? comps[0].Name : "",
        };
    }

    /// <summary>Every user seen in the logon history (or imported from AD), by display name.</summary>
    public List<Row> Users() =>
        [.. UserIndex().Values.Select(UserRow)
            .OrderBy(r => ((string)r["display_name"]! is { Length: > 0 } d ? d : (string)r["name"]!).ToLowerInvariant(), StringComparer.Ordinal)];

    /// <summary>One user: the row + "ad" (attributes), "computer_list" [{guid, name, count, first, last, types}], "events".</summary>
    public Row User(string key)
    {
        var u = UserIndex().GetValueOrDefault((key ?? "").ToLowerInvariant()) ?? throw new NotFound(T("err.user_not_found", ("ref", key)));
        var row = UserRow(u);
        row["ad"] = u.Ad?.DeepClone() ?? new JsonObject();
        row["computer_list"] = u.Computers.Values.OrderByDescending(c => c.Last, StringComparer.Ordinal).Select(c => new Row
        {
            ["guid"] = c.Guid, ["name"] = c.Name, ["count"] = c.Count, ["first"] = c.First, ["last"] = c.Last, ["types"] = c.Types.ToList(),
        }).ToList();
        row["events"] = u.Events.OrderByDescending(e => Str(e["time"]), StringComparer.Ordinal).Take(1000).ToList();
        return row;
    }

    private static JsonObject ToJsonObject(Dictionary<string, object?> d) =>
        JsonSerializer.SerializeToNode(d, Db.Json) as JsonObject ?? [];

    /// <summary>Read the AD attributes of the users seen in the logon history (read-only LDAP; AD is never changed). Only
    /// users not looked up yet, or looked up more than a day ago, unless <paramref name="force"/>. Returns the number found.</summary>
    public int SyncUsers(bool force = false)
    {
        var index = UserIndex();
        var known = Store.AdUsers();
        var limit = DateTimeOffset.UtcNow.AddDays(-1);
        var need = new List<string>();
        foreach (var u in index.Values)
        {
            if (u.Local) continue;
            var fresh = known.TryGetValue(u.Name.ToLowerInvariant(), out var old) && Db.ParseIso(Str(old["synced_at"])) is { } at && at > limit;
            if (force || !fresh) need.Add(u.Name);
        }
        if (need.Count == 0) return 0;
        var found = Directory.FetchUsers(need);
        var records = new Dictionary<string, JsonObject>();
        foreach (var n in need.Select(x => x.ToLowerInvariant()).Distinct())
        {
            var rec = found.TryGetValue(n, out var f) ? ToJsonObject(f) : new JsonObject { ["missing"] = true };
            if (known.TryGetValue(n, out var k) && Db.Truthy(k["imported"]) && !Db.Truthy(rec["missing"]))
                rec["imported"] = true;                 // stays in the list although nobody logged on yet
            records[n] = rec;
        }
        Store.SaveAdUsers(records);
        return records.Values.Count(r => !Db.Truthy(r["missing"]));
    }

    /// <summary>Read the user accounts of the whole domain, or of <paramref name="baseDn"/> (an OU) and below (read-only
    /// LDAP). They appear in the Users list even if they never logged on to a known computer. {total, added}.</summary>
    public Dictionary<string, int> SyncAdUsers(Progress? progress = null, string? baseDn = null)
    {
        progress?.Report(0, 1, "Active Directory…");
        var records = Directory.FetchOuUsers(string.IsNullOrEmpty(baseDn) ? null : baseDn);
        var known = Store.AdUsers();
        var added = 0;
        var batch = new Dictionary<string, JsonObject>();
        foreach (var rec in records)
        {
            var key = Str(rec.GetValueOrDefault("sam")).ToLowerInvariant();
            if (key.Length == 0) continue;
            if (!known.TryGetValue(key, out var k) || Db.Truthy(k["missing"]) || !Db.Truthy(k["imported"])) added++;
            var o = ToJsonObject(rec);
            o["imported"] = true;
            batch[key] = o;
        }
        progress?.Report(0, 1, $"{records.Count}…");
        Store.SaveAdUsers(batch);
        Store.Log("ad-users", T("log.ad_users", ("total", records.Count), ("added", added))
                              + (string.IsNullOrEmpty(baseDn) ? "" : T("log.ad_scope", ("ou", baseDn))));
        progress?.Report(1, 1, "OK");
        return new Dictionary<string, int> { ["total"] = records.Count, ["added"] = added };
    }

    /// <summary>The dashboard counters.</summary>
    public Row Summary()
    {
        var comps = Computers();
        static List<object[]> MostCommon(IEnumerable<string> keys) =>
            [.. keys.GroupBy(k => k).Select((g, i) => (g.Key, Count: g.Count(), i)).OrderByDescending(x => x.Count).ThenBy(x => x.i)
                    .Select(x => new object[] { x.Key, x.Count })];
        var inv = comps.Select(c => c["inventory"] as JsonObject ?? []).ToList();
        string? MaxOf(string k) => comps.Select(c => c.GetValueOrDefault(k) as string ?? "").DefaultIfEmpty("").Max(StringComparer.Ordinal) is { Length: > 0 } m ? m : null;
        return new Row
        {
            ["total"] = comps.Count,
            ["enabled"] = comps.Count(c => c["enabled"] is true),
            ["disabled"] = comps.Count(c => c["enabled"] is not true),
            ["online"] = comps.Count(c => c["online"] is true),
            ["offline"] = comps.Count(c => c["online"] is false),
            ["unscanned"] = comps.Count(c => c["online"] is null),
            ["stale"] = comps.Count(c => c["stale"] is true),
            ["winrm"] = comps.Count(c => ((List<int>)c["open_ports"]!).Any(WinRMPorts.Contains)),
            ["inventoried"] = comps.Count(c => c["inventory"] is not null),
            ["scan_failed"] = comps.Count(c => c["scan_status"] as string == "failed"),
            ["pending_reboot"] = inv.Count(i => Db.Truthy(i["pending_reboot"])),
            ["low_disk"] = inv.Count(i => Num(i["c_free_gb"]) is { } f && f < 15),
            ["smb1"] = inv.Count(i => Db.Truthy(i["smb1_server"]) || Db.Truthy(i["smb1_client"])),
            ["by_os"] = MostCommon(comps.Select(c => c["os"] as string is { Length: > 0 } os ? os : "Unknown")),
            ["by_ou"] = MostCommon(comps.Select(c =>
            {
                var ou = c["ou"] as string ?? "";
                var i = ou.IndexOf('/');
                var rest = i < 0 ? ou : ou[(i + 1)..];
                return rest.Length > 0 ? rest : "(root)";
            })),
            ["fleets"] = Store.Fleets().Count,
            ["last_ad_sync"] = MaxOf("ad_synced_at"),
            ["last_scan"] = MaxOf("scanned_at"),
        };
    }

    // ------------------------------------------------------------------ AD sync
    /// <summary>For the AD browser: {root, parent, children: [{dn, name}]} - the OUs directly below <paramref name="parent"/>.</summary>
    public Row AdOus(string? parent = null)
    {
        var root = IsDemo ? Demo.Domain : Settings.Ldap.BaseDn;
        var kids = Directory.ListOus(string.IsNullOrEmpty(parent) ? null : parent);
        return new Row { ["root"] = root, ["parent"] = string.IsNullOrEmpty(parent) ? root : parent, ["children"] = kids };
    }

    /// <summary>Read computers from AD: the whole domain, or only <paramref name="baseDn"/> (an OU) and below.
    /// {added, updated, removed, total}.</summary>
    public Dictionary<string, int> SyncAd(Progress? progress = null, string? baseDn = null)
    {
        progress?.Report(0, 1, "Active Directory…");
        var scope = string.IsNullOrEmpty(baseDn) ? null : baseDn;
        var records = Directory.FetchComputers(scope);
        progress?.Report(0, 1, $"{records.Count}…");
        var result = Store.UpsertFromAd(records, scope);
        result["total"] = records.Count;
        DataChanged();
        Store.Log("ad-sync", T("log.ad_sync", ("total", records.Count), ("added", result["added"]), ("removed", result["removed"]))
                             + (scope is null ? "" : T("log.ad_scope", ("ou", scope))));
        progress?.Report(1, 1, "OK");
        return result;
    }

    // ------------------------------------------------------------------ targets
    /// <summary>Machines to scan: enabled, and with scanning allowed. Returns (targets, scope, skipped).</summary>
    private (List<Row> Targets, string Scope, int Skipped) Targets(long? fleetId, IReadOnlyList<string>? guids)
    {
        List<Row> comps;
        string scope;
        if (guids is { Count: > 0 })
        {
            var wanted = Store.ResolveNames(guids).ToHashSet();
            comps = [.. Computers().Where(c => wanted.Contains((string)c["guid"]!))];
            scope = T("scope.selection", ("n", comps.Count));
        }
        else if (fleetId is { } fid and > 0)
        {
            var fleet = GetFleet(fid);
            comps = Resolve(fleet, Computers(withApps: true));
            scope = T("scope.fleet", ("name", fleet["name"]));
        }
        else
        {
            comps = Computers();
            scope = T("scope.all");
        }
        var ok = comps.Where(c => c["enabled"] is true && c["allow_scan"] is true).ToList();
        return (ok, scope, comps.Count - ok.Count);
    }

    /// <summary>GUIDs of computers that only a sync peer reported (see SyncData): never deployment targets, because their
    /// host names are the peer's word, not this instance's AD.</summary>
    private HashSet<string> SyncUnconfirmed()
    {
        if (Store.Scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sync_unconfirmed'") is long n && n > 0)
            return [.. Store.Query("SELECT guid FROM sync_unconfirmed").Select(r => (string)r["guid"]!)];
        return [];
    }

    private static string HostOf(Row c) => c["dns_hostname"] is string { Length: > 0 } d ? d : Str(c["name"]);

    private static List<int> PortsOf(Row c) => c["open_ports"] as List<int> ?? [];

    // ------------------------------------------------------------------ scan
    /// <summary>Reachability probe. {scanned, online, offline, skipped}.</summary>
    public Dictionary<string, int> Scan(long? fleetId = null, Progress? progress = null, IReadOnlyList<string>? guids = null)
    {
        var (comps, scope, skipped) = Targets(fleetId, guids);
        var targets = comps.Select(c => ((string)c["guid"]!, HostOf(c))).ToList();
        var s = Settings.Scan;
        Scanner.ProbeFn probe = ProbeOverride ?? (IsDemo ? new Scanner.ProbeFn(Demo.Probe) : (h, p, t) => Scanner.Probe(h, p, t));
        var results = Scanner.ScanMany(targets, s.Ports, s.Timeout, s.Workers, probe,
            onResult: (guid, res) =>
            {
                Store.RecordScan(guid, res.Ip, res.OpenPorts);
                Jobs_Track(progress, guid, null);
            },
            progress: progress is null ? null : (Action<int, int, string>)progress.Report,
            onStart: guid => Jobs_Track(progress, guid, "scan"));
        var online = results.Values.Count(r => r.OpenPorts.Count > 0);
        Store.Log("scan", T("log.scan", ("scanned", results.Count), ("scope", scope), ("online", online), ("offline", results.Count - online)));
        return new Dictionary<string, int>
        {
            ["scanned"] = results.Count, ["online"] = online, ["offline"] = results.Count - online, ["skipped"] = skipped,
        };
    }

    // ------------------------------------------------------------------ collect
    /// <summary>Inventory collection (PDQ-style over SMB, or WinRM). {attempted, collected, failed, skipped}.</summary>
    public Dictionary<string, int> Collect(long? fleetId = null, Progress? progress = null, IReadOnlyList<string>? guids = null)
    {
        var (allTargets, _, skipped) = Targets(fleetId, guids);
        var col = Settings.Collect;
        var cfg = Settings.Winrm;
        var realm = Kerberos.RealmFromBaseDn(Settings.Ldap.BaseDn);
        var usePdq = !IsDemo && col.Method == "pdq";
        var wantWinrm = col.Method == "winrm" || (usePdq && col.WinrmFallback);

        // candidate hosts: SMB-reachable for the PDQ collector, WinRM-reachable for WinRM
        List<Row> comps;
        if (IsDemo)
        {
            comps = [.. allTargets.Where(c => PortsOf(c).Any(WinRMPorts.Contains))];
        }
        else
        {
            var reach = new HashSet<int>();
            if (usePdq) reach.UnionWith(SmbPorts);
            if (wantWinrm) reach.UnionWith(WinRMPorts);
            comps = [.. allTargets.Where(c => PortsOf(c).Any(reach.Contains))];
        }

        SmbCreds? smbCreds = null;
        var denied = new List<(Row C, string Why)>();
        if (!IsDemo)
        {
            // MANDATORY: checked per organizational unit of each target, not domain-wide
            var ous = comps.Select(c => DnUtil.ParentDn(c["dn"] as string ?? "")).ToHashSet();
            var scope = ous.Count > 0 ? Directory.OuAdminScope(Settings.Ldap.User, ous) : [];
            var allowed = new List<Row>();
            foreach (var c in comps)
            {
                var ou = DnUtil.ParentDn(c["dn"] as string ?? "");
                var (okay, detail) = scope.TryGetValue(ou, out var sc) ? sc : (true, "");
                if (okay) allowed.Add(c);
                else denied.Add((c, T("err.not_admin_ou", ("ou", ou), ("detail", detail))));
            }
            if (comps.Count > 0 && allowed.Count == 0)
            {
                var msg = T("err.not_admin", ("detail", denied[0].Why));
                Store.Log("collect", msg);
                throw new ArgumentException(msg);
            }
            comps = allowed;
            Log.Logger.LogInformation("Collect: admin rights verified on {Allowed} of {Total} computer(s); method={Method}",
                                      allowed.Count, allowed.Count + denied.Count, col.Method);
            if (usePdq)
            {
                smbCreds = Pdq.CredsFromLdap(Settings.Ldap, realm);
                if (!smbCreds.HasExplicitCredential)
                {
                    // the SMB / SCM collector needs an explicit account + password
                    if (!col.WinrmFallback) throw new ArgumentException(T("err.pdq_creds"));
                    Log.Logger.LogWarning("PDQ collection needs the LDAP account and password; no password configured, using WinRM for this run");
                    usePdq = false;
                    smbCreds = null;
                }
            }
            if (col.Method == "winrm" && cfg.User.Length == 0 && cfg.Transport != "kerberos")
                throw new ArgumentException(T("err.winrm_creds"));          // kerberos: empty = current Windows logon
        }
        var ok = 0;
        var failed = 0;
        foreach (var (c, why) in denied)                  // no admin rights on their OU: reported, not collected
        {
            Store.RecordInventory((string)c["guid"]!, null, why.Length > 500 ? why[..500] : why);
            failed++;
        }
        var total = comps.Count;
        // the public key for the recovery keys (null: they are not collected, e.g. no protected secret store)
        string? blKey = null;
        try { blKey = Bitlocker.PublicKeyXml; }
        catch (CryptographicException exc) { Log.Logger.LogWarning(exc, "BitLocker key pair unavailable; recovery keys are not collected"); }

        JsonObject WorkInner(Row c)
        {
            var host = HostOf(c);
            if (IsDemo) return Demo.Collect(host, c);
            var ports = PortsOf(c).ToHashSet();
            var started = Stopwatch.GetTimestamp();
            if (usePdq && ports.Overlaps(SmbPorts))
            {
                try
                {
                    var rec = Pdq.Collect(host, smbCreds!, col, onCleanup: LogCleanup, bitlockerKey: blKey);
                    Log.Logger.LogInformation("Collect {Host}: PDQ ok in {Seconds:F1}s", host, Stopwatch.GetElapsedTime(started).TotalSeconds);
                    return rec;
                }
                catch (CollectError exc) when (col.WinrmFallback && ports.Overlaps(WinRMPorts))
                {
                    Log.Logger.LogWarning(exc, "PDQ collection of {Host} failed ({Error}); falling back to WinRM", host, exc.Message);
                    var rec = Collector.WinrmCollect(host, cfg, realm, bitlockerKey: blKey);
                    Log.Logger.LogInformation("Collect {Host}: WinRM fallback ok in {Seconds:F1}s", host, Stopwatch.GetElapsedTime(started).TotalSeconds);
                    return rec;
                }
            }
            if (ports.Overlaps(WinRMPorts))
            {
                var rec = Collector.WinrmCollect(host, cfg, realm, bitlockerKey: blKey);
                Log.Logger.LogInformation("Collect {Host}: WinRM ok in {Seconds:F1}s", host, Stopwatch.GetElapsedTime(started).TotalSeconds);
                return rec;
            }
            throw new CollectError("no SMB (445) or WinRM (5985/5986) port reachable");
        }

        var gate = new Lock();
        var done = 0;
        Parallel.ForEach(comps, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Math.Min(cfg.Workers, Math.Max(total, 1))) }, c =>
        {
            var guid = (string)c["guid"]!;
            JsonObject? rec = null;
            Exception? error = null;
            Jobs_Track(progress, guid, "collect");
            try { rec = WorkInner(c); }
            catch (Exception exc) { error = exc; }
            finally { Jobs_Track(progress, guid, null); }
            lock (gate)
            {
                if (rec is not null)
                {
                    if (Db.Truthy(rec["section_errors"]))
                        Log.Logger.LogWarning("Collect {Host}: partial inventory, failed sections: {Errors}", HostOf(c), rec["section_errors"]?.ToJsonString());
                    SaveBitlockerKeys(guid, rec, requested: blKey is not null);
                    Store.RecordInventory(guid, rec);
                    ok++;
                }
                else
                {
                    Log.Logger.LogWarning(error, "Collect {Host} failed: {Type}: {Error}", HostOf(c), error!.GetType().Name, error.Message);
                    var msg = error.Message;
                    Store.RecordInventory(guid, null, msg.Length > 500 ? msg[..500] : msg);
                    failed++;
                }
                done++;
                progress?.Report(done, total, Str(c["name"]));
            }
        });
        DataChanged();
        Store.Log("collect", total > 0 ? T("log.collect", ("ok", ok), ("failed", failed), ("skipped", skipped)) : T("log.collect_none"));
        new Thread(() =>
        {
            try { EnsureUpdatesFresh(); }
            catch (Exception exc) { Log.Logger.LogDebug(exc, "Security-update refresh after the collection failed"); }
        }) { IsBackground = true, Name = "admiral-updates" }.Start();
        try
        {
            SyncUsers();
        }
        catch (Exception exc)              // the user details are a bonus; the collection itself succeeded
        {
            Log.Logger.LogWarning(exc, "Could not read the users' Active Directory data");
        }
        return new Dictionary<string, int> { ["attempted"] = total, ["collected"] = ok, ["failed"] = failed, ["skipped"] = skipped };
    }

    /// <summary>Activity-log the self-check of a computer, but only when it found something to clean up or could not
    /// verify; a clean computer would just be noise.</summary>
    private void LogCleanup(CleanupReport rep)
    {
        if (rep.Clean && !rep.Acted) return;
        Store.Log("collect", T("log.cleanup", ("host", rep.Host), ("service", T($"cleanup.service.{rep.Service}")),
                               ("removed", rep.FilesRemoved.Count), ("left", rep.FilesLeft.Count),
                               ("killed", T(rep.ProcessKilled ? "state.yes" : "state.no")),
                               ("errors", rep.Errors.Count > 0 ? T("cleanup.errors", ("errors", string.Join("; ", rep.Errors))) : "")));
    }

    /// <summary>Reachability probe followed by inventory collection of everything that answered.</summary>
    public Dictionary<string, int> FullScan(long? fleetId = null, Progress? progress = null, IReadOnlyList<string>? guids = null)
    {
        Progress Stage(int offset, string label) => new(
            (d, t, m) => progress?.Report(d + offset * t, t * 2, $"{label}: {m}"),
            (k, ph) => progress?.Track(k, ph));
        var s = Scan(fleetId, Stage(0, "1/2"), guids);
        var c = Collect(fleetId, Stage(1, "2/2"), guids);
        foreach (var (k, v) in c)
            if (k != "skipped") s[k] = v;
        return s;
    }

    // ------------------------------------------------------------------ retry service
    /// <summary>Status of the Windows retry service (<paramref name="action"/> null), or install / enable / disable / delete it.</summary>
    public RetryServiceStatus RetryServiceAction(string? action = null, string account = "", string password = "")
    {
        if (action is null) return RetryService.Status();
        if (ConfigPath is null) throw new ArgumentException(T("err.settings_readonly"));
        RetryServiceStatus st;
        string what;
        switch (action)
        {
            case "install":
                // default: the saved LDAP account (its password is already stored, DPAPI-readable by it)
                account = (string.IsNullOrEmpty(account) ? Settings.Ldap.User : account).Trim();
                password = string.IsNullOrEmpty(password) ? Settings.Ldap.Password : password;
                if (account.Length == 0 || account.StartsWith("u:", StringComparison.OrdinalIgnoreCase)
                    || account.StartsWith("dn:", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(password))
                    throw new ArgumentException(T("err.service_account"));
                st = RetryService.Install(Path.GetDirectoryName(Path.GetFullPath(ConfigPath)) ?? ".", account, password);
                what = $"installed + started ({account})";
                break;
            case "enable":
                st = RetryService.SetEnabled(true);
                what = "enabled";
                break;
            case "disable":
                st = RetryService.SetEnabled(false);
                what = "disabled";
                break;
            case "delete":
                st = RetryService.Delete();
                what = "deleted";
                break;
            default:
                throw new ArgumentException($"unknown action '{action}'");
        }
        Store.Log("service", T("log.service", ("what", what)));
        return st;
    }

    // ------------------------------------------------------------------ computers: hide / allow / tag
    /// <summary>Take computers off the list. They stay hidden (also across AD syncs) until restored.</summary>
    public int RemoveComputers(IReadOnlyList<string> ids)
    {
        var guids = Store.ResolveNames(ids);
        Store.SetHidden(guids, true);
        DataChanged();
        Store.Log("remove", T("log.remove", ("n", guids.Count)));
        return guids.Count;
    }

    public int RestoreComputers()
    {
        var n = Store.RestoreHidden();
        DataChanged();
        Store.Log("restore", T("log.restore", ("n", n)));
        return n;
    }

    public int SetAllowScan(IReadOnlyList<string> ids, bool allow)
    {
        var guids = Store.ResolveNames(ids);
        Store.SetAllowScan(guids, allow);
        Store.Log("allow-scan", T("log.allow_scan", ("n", guids.Count), ("state", T(allow ? "state.enabled" : "state.disabled"))));
        return guids.Count;
    }

    public int Tag(IReadOnlyList<string> ids, IEnumerable<string>? add, IEnumerable<string>? remove)
    {
        var guids = Store.ResolveNames(ids);
        var a = (add ?? []).Select(t => t.Trim()).Where(t => t.Length > 0).Distinct().Order(StringComparer.Ordinal).ToList();
        var r = (remove ?? []).Select(t => t.Trim()).Where(t => t.Length > 0).Distinct().Order(StringComparer.Ordinal).ToList();
        if (a.Any(t => t.Length > 100) || r.Any(t => t.Length > 100)) throw new ArgumentException("a tag is at most 100 characters");
        Store.Tag(guids, a, r);
        var parts = new List<string>();
        if (a.Count > 0) parts.Add("+" + string.Join(", +", a));
        if (r.Count > 0) parts.Add("-" + string.Join(", -", r));
        Store.Log("tag", T("log.tag", ("changes", string.Join(" ", parts)), ("n", guids.Count)));
        return guids.Count;
    }

    // ------------------------------------------------------------------ fleets (collections)
    /// <summary>A collection by id or (case-insensitive) name.</summary>
    public Row GetFleet(string reference)
    {
        Row? fleet = null;
        reference ??= "";
        if (reference.Length > 0 && reference.All(char.IsAsciiDigit) && long.TryParse(reference, CultureInfo.InvariantCulture, out var id))
            fleet = Store.Fleet(id);
        fleet ??= Store.FleetByName(reference);
        return fleet ?? throw new NotFound(T("err.fleet_not_found", ("ref", reference)));
    }

    public Row GetFleet(long id) => Store.Fleet(id) ?? throw new NotFound(T("err.fleet_not_found", ("ref", id)));

    /// <summary>Every collection with "count", "online" and "guids" of its members.</summary>
    public List<Row> Fleets()
    {
        var comps = Computers(withApps: true);
        var outp = new List<Row>();
        foreach (var f in Store.Fleets())
        {
            var members = Resolve(f, comps);
            f["count"] = members.Count;
            f["online"] = members.Count(c => c["online"] is true);
            f["guids"] = members.Select(c => (string)c["guid"]!).ToList();
            outp.Add(f);
        }
        return outp;
    }

    private List<Row> Resolve(Row fleet, List<Row> comps)
    {
        if ((string?)fleet["kind"] == "static")
        {
            var ids = Store.StaticMembers((long)fleet["id"]!);
            return [.. comps.Where(c => ids.Contains((string)c["guid"]!))];
        }
        RuleSet rules;
        try { rules = Rules.Validate(fleet["rules"]); }
        catch (RuleError exc)
        {
            Log.Logger.LogWarning("Collection {Name} has invalid rules: {Error}", fleet["name"], exc.Message);
            return [];
        }
        return [.. comps.Where(c => Rules.Matches(c, rules))];
    }

    public List<Row> FleetMembers(string reference) => Members(GetFleet(reference));

    public List<Row> FleetMembers(long id) => Members(GetFleet(id));

    private List<Row> Members(Row fleet)
    {
        var members = Resolve(fleet, Computers(withApps: true));
        foreach (var c in members) c.Remove("apps");
        return members;
    }

    private static RuleSet ValidRules(object? ruleSet)
    {
        try { return Rules.Validate(ruleSet); }
        catch (RuleError exc) { throw new ArgumentException(exc.Message, exc); }
    }

    /// <summary>The computers a (not yet saved) rule set would match.</summary>
    public List<Row> PreviewRules(object? ruleSet)
    {
        var clean = ValidRules(ruleSet);
        return [.. Computers(withApps: true).Where(c => Rules.Matches(c, clean))];
    }

    public Row CreateFleet(string name, string kind, string description = "", object? ruleSet = null, string? adGroupDn = null,
                           IReadOnlyList<string>? members = null)
    {
        name = (name ?? "").Trim();
        if (name.Length == 0) throw new ArgumentException(T("err.fleet_name_required"));
        if (name.Length > 200) throw new ArgumentException("the collection name is at most 200 characters");
        if (kind is not ("static" or "dynamic")) throw new ArgumentException(T("err.fleet_kind"));
        if (Store.FleetByName(name) is not null) throw new ArgumentException(T("err.fleet_exists", ("name", name)));
        var clean = kind == "dynamic" ? ValidRules(ruleSet) : null;
        var guids = kind == "static" ? Store.ResolveNames(members ?? []) : [];
        var fid = Store.CreateFleet(name, kind, description ?? "", clean is null ? null : JsonSerializer.SerializeToNode(clean), (adGroupDn ?? "").Trim());
        if (guids.Count > 0) Store.SetStaticMembers(fid, add: guids);
        Store.Log("fleet-create", T("log.fleet_create", ("kind", T($"kind.{kind}")), ("name", name)));
        return GetFleet(fid);
    }

    /// <summary>Change name / description / rules (dynamic only) / AD group of a collection; null = unchanged.</summary>
    public Row UpdateFleet(string reference, string? name = null, string? description = null, object? rules = null, string? adGroupDn = null)
    {
        var fleet = GetFleet(reference);
        var changes = new Dictionary<string, object?>();
        if (name is not null)
        {
            name = name.Trim();
            if (name.Length == 0) throw new ArgumentException(T("err.fleet_name_required"));
            if (name.Length > 200) throw new ArgumentException("the collection name is at most 200 characters");
            if (Store.FleetByName(name) is { } other && (long)other["id"]! != (long)fleet["id"]!)
                throw new ArgumentException(T("err.fleet_exists", ("name", name)));
            changes["name"] = name;
        }
        if (description is not null) changes["description"] = description;
        if (rules is not null)
        {
            if ((string?)fleet["kind"] != "dynamic") throw new ArgumentException(T("err.only_dynamic_rules"));
            changes["rules"] = ValidRules(rules);
        }
        if (adGroupDn is not null) changes["ad_group_dn"] = adGroupDn.Trim();
        Store.UpdateFleet((long)fleet["id"]!, changes);
        Store.Log("fleet-update", T("log.fleet_update", ("name", fleet["name"]), ("fields", changes.Count > 0 ? string.Join(", ", changes.Keys) : "-")));
        return GetFleet((long)fleet["id"]!);
    }

    public Row UpdateFleet(long id, string? name = null, string? description = null, object? rules = null, string? adGroupDn = null) =>
        UpdateFleet(id.ToString(CultureInfo.InvariantCulture), name, description, rules, adGroupDn);

    public void DeleteFleet(string reference)
    {
        var fleet = GetFleet(reference);
        Store.DeleteFleet((long)fleet["id"]!);
        Store.Log("fleet-delete", T("log.fleet_delete", ("name", fleet["name"])));
    }

    /// <summary>Add / remove members of a static collection; returns the new member count.</summary>
    public int ChangeStaticMembers(string reference, IReadOnlyList<string>? add = null, IReadOnlyList<string>? remove = null)
    {
        var fleet = GetFleet(reference);
        if ((string?)fleet["kind"] != "static") throw new ArgumentException(T("err.static_only"));
        var addG = Store.ResolveNames(add ?? []);
        var remG = Store.ResolveNames(remove ?? []);
        var id = (long)fleet["id"]!;
        Store.SetStaticMembers(id, addG, remG);
        Store.Log("fleet-members", T("log.fleet_members", ("name", fleet["name"]), ("added", addG.Count), ("removed", remG.Count)));
        return Store.StaticMembers(id).Count;
    }

    /// <summary>(body, content type, file name) of a collection export.</summary>
    public (string Body, string ContentType, string FileName) ExportFleet(string reference, string fmt, bool onlineOnly = false)
    {
        if (!Exporters.Formats.TryGetValue(fmt ?? "", out var format)) throw new ArgumentException(T("err.format", ("fmt", fmt)));
        var fleet = GetFleet(reference);
        var members = Members(fleet);
        if (onlineOnly) members = [.. members.Where(c => c["online"] is true)];
        var name = (string)fleet["name"]!;
        var body = Exporters.Export(members, fmt!, name);
        var ext = fmt == "ansible" ? "ini" : fmt;
        var safe = new string([.. name.Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '_')]);
        Store.Log("export", T("log.export", ("name", name), ("fmt", fmt), ("n", members.Count)));
        return (body, format.ContentType, $"{safe}.{ext}");
    }

    // ------------------------------------------------------------------ AD group comparison
    /// <summary>READ-ONLY comparison of a collection with an AD group's current members. Nothing is written to Active
    /// Directory: ADmiral only reports which computers are in the collection but missing from the group, and which known
    /// computers are in the group but not in the collection. {fleet, group_dn, collection_count, group_count, missing,
    /// extra, matching, other_members}.</summary>
    public Row GroupCompare(string reference)
    {
        var fleet = GetFleet(reference);
        var groupDn = fleet["ad_group_dn"] as string;
        if (string.IsNullOrEmpty(groupDn)) throw new ArgumentException(T("err.no_group", ("name", fleet["name"])));
        var members = Members(fleet);
        var known = new Dictionary<string, Row>(StringComparer.Ordinal);
        foreach (var c in Computers())
            if (c["dn"] is string { Length: > 0 } dn) known[dn.ToLowerInvariant()] = c;
        var desired = new Dictionary<string, Row>(StringComparer.Ordinal);
        foreach (var c in members)
            if (c["dn"] is string { Length: > 0 } dn) desired.TryAdd(dn.ToLowerInvariant(), c);
        var current = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            foreach (var dn in Directory.GroupMembers(groupDn)) current.TryAdd(dn.ToLowerInvariant(), dn);
        }
        catch (KeyNotFoundException)
        {
            throw new NotFound(T("err.group_not_found", ("dn", groupDn)));
        }
        static Row Brief(Row c) => new() { ["name"] = c["name"], ["dn"] = c["dn"] };
        return new Row
        {
            ["fleet"] = fleet["name"], ["group_dn"] = groupDn,
            ["collection_count"] = desired.Count, ["group_count"] = current.Count,
            ["missing"] = desired.Where(kv => !current.ContainsKey(kv.Key)).Select(kv => Brief(kv.Value)).ToList(),
            ["extra"] = current.Keys.Where(k => known.ContainsKey(k) && !desired.ContainsKey(k)).Select(k => Brief(known[k])).ToList(),
            ["matching"] = desired.Keys.Count(current.ContainsKey),
            ["other_members"] = current.Where(kv => !known.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList(),
        };
    }

    // ------------------------------------------------------------------ remote assistance
    [GeneratedRegex(@"\A[\p{L}\p{N}]([\p{L}\p{N}._-]{0,253}[\p{L}\p{N}])?\z")]
    private static partial Regex HostnameRe();

    /// <summary>The validated host name for <c>msra /offerra</c> (a stray trailing "-" / "." is dropped). Throws
    /// <see cref="ArgumentException"/> for anything that is not a plain computer name.</summary>
    public static string ValidRemoteHost(string? host)
    {
        var h = (host ?? "").Trim().TrimEnd('-', '.');
        if (!HostnameRe().IsMatch(h)) throw new ArgumentException($"invalid computer name: '{host}'");
        return h;
    }

    /// <summary>The process to start: msra.exe with the arguments as separate items (never one command line).</summary>
    /// <summary>Full path of msra.exe in the System directory: never resolved through PATH or the current folder,
    /// so a planted msra.exe cannot be started elevated.</summary>
    public static string MsraPath => Path.Combine(OperatingSystem.IsWindows() ? Environment.SystemDirectory : "C:\\Windows\\System32", "msra.exe");

    public static ProcessStartInfo RemoteAssistStartInfo(string host)
    {
        var info = new ProcessStartInfo(MsraPath) { UseShellExecute = true, Verb = "runas" };   // msra needs elevation (UAC prompt)
        info.ArgumentList.Add("/offerra");
        info.ArgumentList.Add(ValidRemoteHost(host));
        return info;
    }

    /// <summary>Offer Windows Remote Assistance to <paramref name="host"/> (<c>msra /offerra &lt;host&gt;</c>).</summary>
    public void RemoteAssist(string host)
    {
        var info = RemoteAssistStartInfo(host);
        if (ProcessStarter is ShellProcessStarter && !OperatingSystem.IsWindows())
            throw new InvalidOperationException("Remote Assistance (msra.exe) is only available on Windows");
        Log.Logger.LogInformation("Remote Assistance offer: msra.exe /offerra {Host}", info.ArgumentList[1]);
        try
        {
            ProcessStarter.Start(info);
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            throw new InvalidOperationException($"msra.exe could not be started ({exc.Message})", exc);
        }
    }

    /// <summary>Full path of eventvwr.exe in the System directory (never resolved through PATH or the current folder).</summary>
    public static string EventViewerPath => Path.Combine(OperatingSystem.IsWindows() ? Environment.SystemDirectory : "C:\\Windows\\System32", "eventvwr.exe");

    /// <summary>The Event Viewer pointed at <paramref name="host"/> (<c>eventvwr.exe &lt;host&gt;</c>; the name validated and
    /// passed as a separate argument). It runs as the signed-in user: reading the remote logs needs that user's rights there.</summary>
    public static ProcessStartInfo EventViewerStartInfo(string host)
    {
        var info = new ProcessStartInfo(EventViewerPath) { UseShellExecute = true };
        info.ArgumentList.Add(ValidRemoteHost(host));
        return info;
    }

    /// <summary>Open the target computer's event logs in the Windows Event Viewer (read-only for ADmiral: it only starts
    /// the viewer).</summary>
    public void EventViewer(string host)
    {
        var info = EventViewerStartInfo(host);
        if (ProcessStarter is ShellProcessStarter && !OperatingSystem.IsWindows())
            throw new InvalidOperationException("The Event Viewer (eventvwr.exe) is only available on Windows");
        Log.Logger.LogInformation("Event Viewer opened for {Host}", info.ArgumentList[0]);
        try
        {
            ProcessStarter.Start(info);
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            throw new InvalidOperationException($"eventvwr.exe could not be started ({exc.Message})", exc);
        }
    }

    private static string SystemDir => OperatingSystem.IsWindows() ? Environment.SystemDirectory : "C:\\Windows\\System32";

    /// <summary>Full paths of mmc.exe and the Computer Management snap-in in the System directory (never PATH / current folder).</summary>
    public static string MmcPath => Path.Combine(SystemDir, "mmc.exe");
    public static string CompMgmtPath => Path.Combine(SystemDir, "compmgmt.msc");

    /// <summary>Computer Management (MMC) connected to <paramref name="host"/>: <c>mmc.exe compmgmt.msc /computer=&lt;host&gt;</c>,
    /// each argument a separate item and the name validated.</summary>
    public static ProcessStartInfo ComputerManagementStartInfo(string host)
    {
        var info = new ProcessStartInfo(MmcPath) { UseShellExecute = true };
        info.ArgumentList.Add(CompMgmtPath);
        info.ArgumentList.Add("/computer=" + ValidRemoteHost(host));
        return info;
    }

    /// <summary>Open Computer Management (event logs, services, shares, local users and groups, disks...) for the
    /// target computer. ADmiral only starts the console; whatever is done there is the admin's own action.</summary>
    public void ComputerManagement(string host)
    {
        var info = ComputerManagementStartInfo(host);
        if (ProcessStarter is ShellProcessStarter && !OperatingSystem.IsWindows())
            throw new InvalidOperationException("Computer Management (mmc.exe) is only available on Windows");
        Log.Logger.LogInformation("Computer Management opened for {Host}", info.ArgumentList[1]);
        try
        {
            ProcessStarter.Start(info);
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            throw new InvalidOperationException($"mmc.exe could not be started ({exc.Message})", exc);
        }
    }

    // ------------------------------------------------------------------ activity / diagnostics
    /// <summary>[{id, ts, action, detail}], newest first (1..1000).</summary>
    public List<Row> Activity(int limit = 200) => Store.Activity(Math.Clamp(limit, 1, 1000));

    /// <summary>{text, records}: the grouped, redacted list of every warning / error since the ledger was cleared.</summary>
    public Row Diagnostics() => new() { ["text"] = Diag.Report(), ["records"] = Diag.ReadLedger().Count };

    public void ClearDiagnostics() => Diag.Clear();

    /// <summary>{files: [{name, exists, size}], debug}.</summary>
    public Row LogFiles() => new()
    {
        ["files"] = Diag.LogFiles.Select(n => Diag.ReadLog(n, maxBytes: 1)).Select(v => new Row { ["name"] = v.Name, ["exists"] = v.Exists, ["size"] = v.Size }).ToList(),
        ["debug"] = Settings.DebugLog,
    };

    /// <summary>The end of one log file (only the three known names).</summary>
    public LogFileView ReadLog(string name) => Diag.ReadLog(name);

    /// <summary>Anonymized copies of the logs for a GitHub issue.</summary>
    public LogPackage BuildLogPackage() => LogReport.Build(Settings, Store);
}
