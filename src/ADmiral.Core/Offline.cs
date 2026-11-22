#pragma warning disable CA1873 // log arguments are cheap here
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>Result of <see cref="Offline.ImportInbox"/> (field names as the UI expects).</summary>
public sealed class OfflineImportResult
{
    [JsonPropertyName("configured")] public bool Configured { get; set; }
    [JsonPropertyName("found")] public int Found { get; set; }
    [JsonPropertyName("imported")] public int Imported { get; set; }
    [JsonPropertyName("unknown")] public List<string> Unknown { get; set; } = [];
    [JsonPropertyName("failed")] public List<string> Failed { get; set; } = [];
    [JsonPropertyName("error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Error { get; set; }
}

/// <summary>Shared-folder ("inbox") helpers of the offline collection and the login tracking: the folder is writable by
/// every computer of the domain, so everything in it is untrusted.</summary>
internal static partial class Inbox
{
    /// <summary>The regular files directly in <paramref name="folder"/> whose name ends with <paramref name="suffix"/>
    /// (case-insensitive), sorted. Links / junctions (reparse points) and sub-folders are never followed; names with
    /// anything but letters, digits, '_', '-', '.' are skipped (logged), so no name can address another folder.</summary>
    public static List<string> List(string folder, string suffix)
    {
        var outList = new List<string>();
        foreach (var info in new DirectoryInfo(folder).EnumerateFileSystemInfos("*", new EnumerationOptions
                 {
                     RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = true, ReturnSpecialDirectories = false,
                     MatchCasing = MatchCasing.CaseInsensitive,
                 }))
        {
            if (info is not FileInfo f || !f.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) continue;
            if ((f.Attributes & FileAttributes.ReparsePoint) != 0 || f.LinkTarget is not null)
            {
                Log.Logger.LogWarning("Inbox {Folder}: {Name} is a link; ignored", folder, f.Name);
                continue;
            }
            if (!SafeName().IsMatch(f.Name))
            {
                Log.Logger.LogWarning("Inbox {Folder}: unexpected file name {Name}; ignored", folder, Pdq.Cut(f.Name, 80));
                continue;
            }
            outList.Add(f.FullName);
        }
        outList.Sort(StringComparer.Ordinal);
        return outList;
    }

    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}$")]
    private static partial Regex SafeName();

    /// <summary>Read at most <paramref name="maxBytes"/> (a larger file is refused without reading it all).</summary>
    public static byte[] ReadCapped(string path, long maxBytes)
    {
        using var f = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.SequentialScan,
        });
        if (f.Length > maxBytes) throw new InvalidDataException("file too large");
        var buf = new byte[f.Length];
        f.ReadExactly(buf);
        if (f.ReadByte() != -1) throw new InvalidDataException("file too large");      // grew while being read
        return buf;
    }

    /// <summary>computer name / DNS name / short DNS name (lower-case) -> guid of the visible computers. Computer names
    /// win over DNS names: another computer's DNS label can never shadow a computer's own name.</summary>
    public static Dictionary<string, string> ComputerIndex(Store store, int staleDays)
    {
        var index = new Dictionary<string, string>(StringComparer.Ordinal);
        var computers = store.Computers(staleDays);
        foreach (var c in computers)
            if (c.GetValueOrDefault("name") is string { Length: > 0 } n) index.TryAdd(n.ToLowerInvariant(), c["guid"] as string ?? "");
        foreach (var c in computers)
        {
            var dns = c.GetValueOrDefault("dns_hostname") as string ?? "";
            foreach (var key in new[] { dns, dns.Split('.')[0] })
                if (key.Length > 0) index.TryAdd(key.ToLowerInvariant(), c["guid"] as string ?? "");
        }
        return index;
    }

    /// <summary>guid -> account SID of the computers AD reported one for.</summary>
    public static Dictionary<string, string> SidIndex(Store store)
    {
        var outp = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in store.Query("SELECT guid, sid FROM computers WHERE sid IS NOT NULL AND sid <> ''"))
            if (r["guid"] is string g && r["sid"] is string sid) outp[g] = sid;
        return outp;
    }

    /// <summary>Delete the script's temporary files (<c>&lt;name&gt;&lt;suffix&gt;[.&lt;id&gt;].tmp</c>) older than
    /// <paramref name="maxAge"/>; links and other names are never touched. Best effort.</summary>
    public static void CleanStaleTemp(string folder, string suffix, TimeSpan maxAge)
    {
        try
        {
            foreach (var f in new DirectoryInfo(folder).EnumerateFiles("*.tmp", new EnumerationOptions
                     {
                         RecurseSubdirectories = false, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true,
                         MatchCasing = MatchCasing.CaseInsensitive,
                     }))
            {
                if (f.LinkTarget is not null || !SafeName().IsMatch(f.Name) || f.Name.IndexOf(suffix, StringComparison.OrdinalIgnoreCase) <= 0
                    || DateTime.UtcNow - f.LastWriteTimeUtc < maxAge) continue;
                try
                {
                    f.Delete();
                    Log.Logger.LogInformation("Inbox {Folder}: deleted the stale temporary file {Name}", folder, f.Name);
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                {
                    Log.Logger.LogWarning("Inbox {Folder}: could not delete {Name}: {Error}", folder, f.Name, exc.Message);
                }
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Log.Logger.LogDebug(exc, "Inbox {Folder}: temporary files not cleaned", folder);
        }
    }

    /// <summary>Why the drop folder must not be imported from (null = fine, or not checkable here): every computer
    /// writes into it, so only the creator of a file may change it (see <see cref="WinSec.InboxAclProblems"/>).
    /// Fails closed on Windows when the ACL cannot be read.</summary>
    public static string? FolderProblem(string folder, IFileSecurity security)
    {
        if (!security.Supported) return null;
        PathSecurity? sec;
        try
        {
            sec = security.ReadSecurity(folder);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or SystemException)
        {
            return $"the permissions of {folder} cannot be read ({exc.GetType().Name}); nothing is imported";
        }
        if (sec is null) return null;
        var problems = WinSec.InboxAclProblems(sec, security.CurrentUserSid());
        if (problems.Count == 0) return null;
        return $"unsafe permissions on {folder}: {string.Join("; ", problems)}. Give the computers only 'Create files / write data' "
               + "on this folder (this folder only) and CREATOR OWNER 'Modify' on files; nothing is imported until then";
    }
}

/// <summary>File-based inventory for computers that cannot reach the machine running ADmiral (ported from
/// admiral/offline.py). <c>ADmiral-Collect.ps1</c> (rendered here from <see cref="Collector.CombinedScript"/>, so it can
/// never drift from the collector) runs on such a computer and writes <c>&lt;COMPUTER&gt;.admiral.json</c> into a shared
/// folder; each file that belongs to a known computer is imported like a normal collection and deleted. The file is data
/// only: nothing in it is ever executed.</summary>
public static class Offline
{
    public const string Suffix = ".admiral.json";
    /// <summary>Largest inbox file read: the envelope holds one base64 inventory, so the same bound as a remote result
    /// (<see cref="Collector.MaxOutputBytes"/>, about 3x a large real inventory).</summary>
    public const long MaxBytes = Collector.MaxOutputBytes;
    public const string ScriptName = "ADmiral-Collect.ps1";

    private const int EnvelopeDepth = 8;

    private const string OfflineTemplate = """"
<#
.SYNOPSIS
  ADmiral offline collector: saves this computer's inventory as a file in a shared folder.

.DESCRIPTION
  For computers that cannot be reached from the machine running ADmiral. Run it as a Group Policy
  computer Startup script: it then runs as SYSTEM and the file it writes is owned by the computer
  account (DOMAIN\COMPUTER$), which is how ADmiral knows which computer delivered it. A user Logon
  script writes user-owned files, which ADmiral refuses unless offline_allow_users is on (any user
  could then report for any computer).
  It runs the same read-only queries as ADmiral itself, writes <COMPUTERNAME>.admiral.json into
  -OutputPath and does nothing else. ADmiral imports the file from that folder and deletes it.

  Security:
  - Keep THIS SCRIPT where only administrators can change it (the GPO folder in SYSVOL), never in
    the output folder: it runs as SYSTEM on every computer.
  - Output folder NTFS permissions: Domain Computers "Create files / write data" on this folder
    only; CREATOR OWNER "Modify" on files only; ADmiral's account and administrators full control;
    nobody else. ADmiral refuses to import from a folder where computers may change or delete
    each other's files. Turn on SMB signing (or encryption) for the share.
  Generated by ADmiral - do not edit; save a fresh copy from ADmiral (Settings) after updates.

.PARAMETER OutputPath
  The folder (e.g. \\server\admiral-inbox) the file is written to. Required.

.PARAMETER MinIntervalHours
  Skip the run if this computer already delivered a file less than this many hours ago (default 12).
  Use 0 to collect on every run.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File ADmiral-Collect.ps1 -OutputPath \\server\admiral-inbox
#>
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$OutputPath,
  [int]$MinIntervalHours = 12
)

$ErrorActionPreference = 'Stop'
$name = $env:COMPUTERNAME
if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
  Write-Warning "ADmiral: the output folder '$OutputPath' is not reachable."
  exit 2
}

$stateDir = Join-Path $env:LOCALAPPDATA 'ADmiral'
if (-not $env:LOCALAPPDATA) { $stateDir = Join-Path $env:TEMP 'ADmiral' }
$stateFile = Join-Path $stateDir 'offline-last-run.txt'
if ($MinIntervalHours -gt 0 -and (Test-Path -LiteralPath $stateFile)) {
  $age = (Get-Date) - (Get-Item -LiteralPath $stateFile).LastWriteTime
  if ($age.TotalHours -lt $MinIntervalHours) { exit 0 }
}

# ---- the same inventory queries as the main program (generated from admiral/collector.py) ----
$collect = {
@@COLLECTOR@@
}
$b64 = @(& $collect) | Select-Object -Last 1

$fqdn = $name
try { $fqdn = [System.Net.Dns]::GetHostEntry($name).HostName } catch { }

$envelope = [ordered]@{
  format       = 1
  tool         = 'ADmiral-Collect'
  host         = $name
  fqdn         = $fqdn
  collected_at = (Get-Date).ToUniversalTime().ToString('o')
  data         = [string]$b64
}
$json = ConvertTo-Json -InputObject $envelope -Compress
$final = Join-Path $OutputPath ($name + '@@SUFFIX@@')
$tmp = Join-Path $OutputPath ($name + '@@SUFFIX@@.' + [guid]::NewGuid().ToString('N') + '.tmp')   # unpredictable: nobody can plant it
[System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath $tmp -Destination $final -Force    # appears complete or not at all

try {
  New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
  Set-Content -LiteralPath $stateFile -Value (Get-Date).ToString('o')
} catch { }
"""";

    /// <summary>The text of ADmiral-Collect.ps1 for this version of the collector (LF line ends, ASCII).</summary>
    public static string RenderScript()
    {
        var body = Collector.CombinedScript().Trim();
        return OfflineTemplate.Replace("@@COLLECTOR@@", body).Replace("@@SUFFIX@@", Suffix).Replace("\r\n", "\n").TrimEnd('\n') + "\n";
    }

    /// <summary>Write the script (CRLF, as Windows tools expect; ASCII so Windows PowerShell 5.1 reads it right).</summary>
    public static void WriteScript(string path) =>
        File.WriteAllText(path, RenderScript().Replace("\n", "\r\n"), new UTF8Encoding(false));

    /// <summary>Temporary files of the script older than this are left-overs (or planted to block a computer's next
    /// delivery under the old fixed .tmp name) and are deleted.</summary>
    public static readonly TimeSpan StaleTempAge = TimeSpan.FromHours(1);

    /// <summary>Delete a refused file and fail with <paramref name="why"/> (the caller reports it).</summary>
    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Drop(string path, string why)
    {
        try { File.Delete(path); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            throw new FormatException($"{why}; could not be deleted ({exc.Message})", exc);
        }
        throw new FormatException($"{why}; deleted");
    }

    /// <summary>How far in the future a file's collected_at may be (the computer's clock may run ahead a little).</summary>
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromHours(1);

    private static bool TryTime(JsonNode? n, out DateTimeOffset at) => TryTime(Str(n), out at);

    private static bool TryTime(string? s, out DateTimeOffset at)
    {
        at = default;
        return s is { Length: > 0 } && DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out at);
    }

    /// <summary>When the computer's current inventory was taken: for an earlier file its own collected_at, otherwise
    /// the time ADmiral stored it (a WinRM / PDQ collection, or a peer's). Null when it has none.</summary>
    internal static DateTimeOffset? LastCollected(IReadOnlyDictionary<string, object?>? computer)
    {
        if (computer is null) return null;
        if (computer.GetValueOrDefault("inventory") is JsonObject inv && (string?)inv["collected_via"] == "file"
            && TryTime(inv["file_collected_at"], out var fileAt))
            return fileAt;
        return TryTime(computer.GetValueOrDefault("collected_at") as string, out var at) ? at : null;
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    /// <summary>File bytes -> (envelope, normalized inventory record). Throws <see cref="FormatException"/> for anything odd.</summary>
    public static (JsonObject Envelope, JsonObject Record) ParseFile(byte[] raw)
    {
        if (raw.LongLength > MaxBytes) throw new FormatException("file too large");
        JsonObject env, data;
        try
        {
            env = Collector.ParseJson(raw, EnvelopeDepth) as JsonObject ?? throw new FormatException("missing host or data");
            var b64 = Str(env["data"]) ?? throw new FormatException("missing data");
            data = Collector.ParseJson(Convert.FromBase64String(b64)) as JsonObject ?? throw new FormatException("missing data");
        }
        catch (Exception exc) when (exc is JsonException or FormatException or DecoderFallbackException or ArgumentException
                                        or InvalidOperationException)
        {
            throw new FormatException($"not an ADmiral collection file ({exc.GetType().Name})", exc);
        }
        var host = (Str(env["host"]) ?? "").Trim();
        if (host.Length == 0) throw new FormatException("not an ADmiral collection file (missing host or data)");
        if (!Remote.IsValidHost(host)) throw new FormatException("not an ADmiral collection file (bad host name)");
        foreach (var kind in Collector.ListKinds)          // lists must be lists of objects, nothing else
        {
            var v = data[kind];
            if (v is not null && v is not JsonArray && v is not JsonObject) throw new FormatException($"bad '{kind}' section");
        }
        Collector.LogScriptErrors(host, "offline file", data);
        var rec = Collector.Normalize(data);
        rec["collected_via"] = "file";
        rec["file_collected_at"] = env["collected_at"] is JsonValue ca ? Str(ca) ?? ca.ToJsonString() : "";
        return (env, rec);
    }

    /// <summary>Import (and delete) every file in the configured folder that belongs to a known computer. A file of an
    /// unknown computer stays (it may be added later); a broken or untrusted one stays and is reported.</summary>
    public static OfflineImportResult ImportInbox(Store store, Settings settings, IFileSecurity? security = null)
    {
        var inbox = (settings.FileCollect.Inbox ?? "").Trim();
        var outp = new OfflineImportResult { Configured = inbox.Length > 0 };
        if (!outp.Configured) return outp;
        List<string> files;
        try
        {
            files = Inbox.List(inbox, Suffix);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
        {
            Log.Logger.LogWarning("Offline folder {Folder} is not readable: {Error}", inbox, exc.Message);
            outp.Error = $"{exc.GetType().Name}: {exc.Message}";
            return outp;
        }
        outp.Found = files.Count;
        var sec = security ?? WinSec.Default;
        if (files.Count > 0 && Inbox.FolderProblem(inbox, sec) is { } bad)
        {
            Log.Logger.LogError("Offline folder: {Problem}", bad);
            outp.Error = bad;
            return outp;
        }
        Inbox.CleanStaleTemp(inbox, Suffix, StaleTempAge);
        var index = Inbox.ComputerIndex(store, settings.StaleDays);
        var sids = Inbox.SidIndex(store);
        var latest = DateTimeOffset.UtcNow.Add(MaxFutureSkew);
        var allowUsers = settings.FileCollect.OfflineAllowUsers;
        foreach (var path in files)
        {
            var name = Path.GetFileName(path);
            // the script writes <COMPUTERNAME>.admiral.json: the name says whose file it is, the owner proves it
            var nameHost = name[..^Suffix.Length];
            try
            {
                var guid = index.GetValueOrDefault(nameHost.ToLowerInvariant());
                var sid = guid is null ? null : sids.GetValueOrDefault(guid);
                // only the computer account the file names may have written it (by SID once AD reported it); a
                // user-owned file only with [filecollect] offline_allow_users
                var why = WinSec.CheckFileOwner(path, nameHost, allowUsers: false, sec, sid);
                if (why is not null && allowUsers && WinSec.CheckFileOwner(path, nameHost, allowUsers: true, sec, sid) is null)
                {
                    Log.Logger.LogWarning("Offline file {Name}: accepted although it is owned by a user account, not by {Host} "
                                          + "(offline_allow_users is on): {Why}", name, nameHost, why);
                    why = null;
                }
                if (why is not null)
                {
                    // someone else's file under this computer's name: removed, or the real computer could never deliver
                    // (it may not overwrite a file it does not own); an unreadable owner proves nothing, so it stays
                    if (!string.IsNullOrEmpty(sec.Owner(path).Sid)) Drop(path, $"not trusted: {why}");
                    throw new FormatException($"not trusted: {why}");
                }
                JsonObject env, rec;
                try
                {
                    (env, rec) = ParseFile(Inbox.ReadCapped(path, MaxBytes));
                }
                catch (Exception exc) when (exc is FormatException or InvalidDataException)
                {
                    // the script writes a temporary file and renames it: a broken file is never one still being written
                    Drop(path, exc.Message);
                    throw;
                }
                var host = Str(env["host"])!.Trim();
                if (!string.Equals(host, nameHost, StringComparison.OrdinalIgnoreCase))
                    Drop(path, $"not trusted: the file of {nameHost} says it comes from {Pdq.Cut(host, 80)}");
                var fqdn = (Str(env["fqdn"]) ?? "").Trim();
                if (fqdn.Length > 0 && !string.Equals(fqdn.Split('.')[0], host.Split('.')[0], StringComparison.OrdinalIgnoreCase))
                    Drop(path, $"not trusted: fqdn {Pdq.Cut(fqdn, 80)} does not belong to {host}");
                if (!TryTime(rec["file_collected_at"], out var at)) Drop(path, "missing or bad collected_at");
                if (at > latest) throw new FormatException($"collected_at {at:o} is in the future");
                if (guid is null)
                {
                    outp.Unknown.Add(name);
                    Log.Logger.LogWarning("Offline file {Name}: no computer named {Host} in the list; left in place", name, host);
                    continue;
                }
                // an old file (a copy kept and put back, a clock set back, or simply older than the last WinRM / PDQ
                // collection) must not replace newer data
                if (LastCollected(store.Computer(guid, settings.StaleDays)) is { } last && at <= last)
                    Drop(path, $"not newer than the inventory already stored ({last:o})");
                store.RecordInventory(guid, rec);
                File.Delete(path);
                outp.Imported++;
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)   // one bad file must not stop the others
            {
                outp.Failed.Add($"{name}: {exc.Message}");
                Log.Logger.LogWarning(exc, "Offline file {Name} could not be imported: {Error}", name, exc.Message);
            }
        }
        if (outp.Imported > 0 || outp.Failed.Count > 0 || outp.Unknown.Count > 0)
            store.Log("offline", I18n.T("log.offline", ("imported", outp.Imported), ("found", outp.Found),
                                        ("unknown", outp.Unknown.Count), ("failed", outp.Failed.Count)));
        return outp;
    }
}
