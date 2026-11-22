#pragma warning disable CA1873 // log arguments are cheap here
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// The retry loop behind the "ADmiral retry" Windows service (port of admiral/retry.py), host-agnostic.
//
// Every retry.interval_minutes it picks the computers that were offline when they were last queried (retry.offline) or
// whose inventory collection failed (retry.failed) and runs a normal scan + collect for just those. Settings are re-read
// before every pass, so changes made in the program apply without restarting the service. It changes nothing in Active
// Directory; on the computers it does exactly what a manual collection does.

/// <summary>State of the Windows retry service (the JSON the settings page reads).</summary>
public sealed record RetryServiceStatus(
    [property: JsonPropertyName("supported")] bool Supported,
    [property: JsonPropertyName("installed")] bool Installed = false,
    [property: JsonPropertyName("running")] bool Running = false,
    [property: JsonPropertyName("state")] string State = "",
    [property: JsonPropertyName("enabled")] bool Enabled = false,
    [property: JsonPropertyName("account")] string Account = "");

/// <summary>The service manager could not do what was asked (not installed, access denied, not Windows ...).</summary>
public sealed class RetryServiceError(string message, Exception? inner = null) : InvalidOperationException(message, inner);

/// <summary>Installs / controls the "ADmiral retry" Windows service (implemented by the Windows host).</summary>
public interface IRetryServiceControl
{
    RetryServiceStatus Status();

    /// <summary>Install and start the service for the data folder <paramref name="home"/>, running as <paramref name="account"/>.</summary>
    RetryServiceStatus Install(string home, string account, string password);

    RetryServiceStatus SetEnabled(bool enabled);

    RetryServiceStatus Delete();
}

/// <summary>No service manager (not Windows, or no host registered).</summary>
public sealed class UnsupportedRetryService : IRetryServiceControl
{
    public RetryServiceStatus Status() => new(false);

    public RetryServiceStatus Install(string home, string account, string password) => throw Fail();

    public RetryServiceStatus SetEnabled(bool enabled) => throw Fail();

    public RetryServiceStatus Delete() => throw Fail();

    private static RetryServiceError Fail() => new("The retry service is only available on Windows");
}

public static class Retry
{
    /// <summary>The service control new <see cref="AdmiralService"/> instances use (the Windows host replaces it).</summary>
    public static IRetryServiceControl DefaultControl { get; set; } = new UnsupportedRetryService();

    /// <summary>GUIDs worth another try: enabled, scanning allowed, and offline / failed last time.</summary>
    public static List<string> Candidates(IEnumerable<IReadOnlyDictionary<string, object?>> computers, Settings settings)
    {
        var r = settings.Retry;
        var outp = new List<string>();
        foreach (var c in computers)
        {
            if (!(c.GetValueOrDefault("enabled") is true && c.GetValueOrDefault("allow_scan") is true)) continue;
            var status = c.GetValueOrDefault("scan_status") as string;
            var offline = status == "offline" || c.GetValueOrDefault("online") is false;
            var failed = status == "failed";
            if ((r.Offline && offline) || (r.Failed && failed)) outp.Add((string)c["guid"]!);
        }
        return outp;
    }

    /// <summary>One retry pass over everything that qualifies. Returns the scan / collect counters.</summary>
    public static Dictionary<string, int> RetryPass(AdmiralService admiral)
    {
        var guids = Candidates(admiral.Computers(), admiral.Settings);
        if (guids.Count == 0)
        {
            Log.Logger.LogInformation("Retry: nothing to retry");
            return new Dictionary<string, int> { ["candidates"] = 0 };
        }
        Log.Logger.LogInformation("Retry: {Count} computer(s) to try again", guids.Count);
        var res = admiral.FullScan(guids: guids);
        admiral.Store.Log("retry", I18n.T("log.retry", ("n", guids.Count), ("online", res.GetValueOrDefault("online")),
                                          ("collected", res.GetValueOrDefault("collected")), ("failed", res.GetValueOrDefault("failed"))));
        var outp = new Dictionary<string, int> { ["candidates"] = guids.Count };
        foreach (var (k, v) in res) outp[k] = v;
        return outp;
    }

    /// <summary>Fresh settings + passwords of the data folder (the program may have changed them since the last pass).</summary>
    public static Settings LoadSettings(string home)
    {
        var settings = Config.LoadSettings(Path.Combine(home, "admiral.toml"), requireLdap: false);
        if (!Path.IsPathRooted(settings.DbPath) && settings.DbPath != ":memory:")
            settings.DbPath = Path.Combine(home, settings.DbPath);
        new SecretStore(Path.Combine(home, "secrets.json")).Apply(settings);
        return settings;
    }

    /// <summary>A service instance for one pass (no sync autostart: the sync loop owns that).</summary>
    public static AdmiralService Load(string home)
    {
        var settings = Config.LoadSettings(Path.Combine(home, "admiral.toml"), requireLdap: false);
        if (!Path.IsPathRooted(settings.DbPath) && settings.DbPath != ":memory:")
            settings.DbPath = Path.Combine(home, settings.DbPath);
        var secrets = new SecretStore(Path.Combine(home, "secrets.json"));
        secrets.Apply(settings);
        return new AdmiralService(settings, secrets: secrets, syncAutostart: false);
    }

    /// <summary>Host the synchronisation with the other ADmiral instances inside the service: the automatic sync (and,
    /// through <paramref name="onInstance"/>, the listener the host runs). It runs only while [sync] is enabled; the settings
    /// are re-read every <paramref name="checkSeconds"/>, so turning it on / off or changing the key in the program applies
    /// without restarting the service. <paramref name="onInstance"/> gets the hosting instance (or null when it stops).</summary>
    public static void SyncLoop(string home, CancellationToken stop, double checkSeconds = 60.0, Action<AdmiralService?>? onInstance = null)
    {
        AdmiralService? current = null;
        string? signature = null;
        void Drop()
        {
            if (current is null) return;
            onInstance?.Invoke(null);
            current.Dispose();
            current = null;
        }
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var settings = LoadSettings(home);
                var sig = JsonSerializer.Serialize(settings.Sync);
                if (sig != signature)
                {
                    Drop();
                    signature = sig;
                    if (settings.Sync.Enabled && settings.Sync.Key.Length > 0)
                    {
                        current = Load(home);
                        current.ReconfigureSync(force: true);
                        onInstance?.Invoke(current);
                        Log.Logger.LogInformation("Sync: service is hosting the synchronisation (port {Port}, every {Minutes} min)",
                                                  settings.Sync.Port, settings.Sync.IntervalMinutes > 0 ? settings.Sync.IntervalMinutes : "manual");
                    }
                }
            }
            catch (Exception exc)              // never stop the service because of the sync
            {
                Log.Logger.LogError(exc, "Sync setup failed");
            }
            stop.WaitHandle.WaitOne(TimeSpan.FromSeconds(checkSeconds));
        }
        Drop();
    }

    /// <summary>Retry until <paramref name="stop"/> is cancelled. A failing pass is logged and tried again next time.
    /// Also starts <see cref="SyncLoop"/> on a background thread.</summary>
    public static void RunLoop(string home, CancellationToken stop, double firstDelaySeconds = 5.0, Action<AdmiralService?>? onSyncInstance = null)
    {
        Log.Logger.LogInformation("Retry loop started (data dir {Home})", home);
        var syncThread = new Thread(() => SyncLoop(home, stop, onInstance: onSyncInstance)) { IsBackground = true, Name = "admiral-sync-service" };
        syncThread.Start();
        stop.WaitHandle.WaitOne(TimeSpan.FromSeconds(firstDelaySeconds));
        while (!stop.IsCancellationRequested)
        {
            var interval = 30;
            AdmiralService? admiral = null;
            try
            {
                admiral = Load(home);
                interval = admiral.Settings.Retry.IntervalMinutes;
                if (admiral.Settings.Mode == "ldap" && admiral.Settings.Ldap.Server.Length == 0)
                {
                    Log.Logger.LogWarning("Retry: Active Directory is not configured yet");
                }
                else
                {
                    try { admiral.ImportOffline(); }                 // files left by computers that cannot reach us
                    catch (Exception exc) { Log.Logger.LogError(exc, "Offline folder import failed"); }
                    RetryPass(admiral);
                    try { admiral.PrinterCollectDaily(); }           // the printers' daily reading (toner / page count history)
                    catch (Exception exc) { Log.Logger.LogError(exc, "Daily printer reading failed"); }
                    admiral.EnsureUpdatesFresh();                    // keep the security-update reference current
                }
            }
            catch (Exception exc)              // the service must survive any single failing pass
            {
                Log.Logger.LogError(exc, "Retry pass failed");
            }
            finally
            {
                admiral?.Dispose();
            }
            Log.Logger.LogInformation("Retry: next pass in {Minutes} minute(s)", interval);
            stop.WaitHandle.WaitOne(TimeSpan.FromMinutes(interval));
        }
        syncThread.Join(TimeSpan.FromSeconds(10));
        Log.Logger.LogInformation("Retry loop stopped");
    }
}
