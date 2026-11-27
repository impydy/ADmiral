using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>A remote inventory collection failed (nothing usable came back).</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python CollectError")]
public class CollectError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>The outcome of one PowerShell process: exit code, raw stdout (capped), stderr text (capped).</summary>
public sealed record PowerShellResult(int ExitCode, byte[] Stdout, string Stderr);

/// <summary>Runs a PowerShell process whose whole input (script and any credential) is <paramref name="stdin"/>.
/// The real implementation starts Windows PowerShell; tests substitute a fake.</summary>
public interface IPowerShellRunner
{
    /// <summary>Run once. Throws <see cref="CollectError"/> when the process cannot start, exceeds
    /// <paramref name="timeout"/> or writes more than <paramref name="maxOutputBytes"/> to stdout.</summary>
    PowerShellResult Run(string stdin, TimeSpan timeout, long maxOutputBytes);
}

/// <summary>Starts a fixed executable with a fixed argument list (<see cref="ProcessStartInfo.ArgumentList"/>, never a
/// command line built from strings), writes <c>stdin</c>, enforces a wall-clock timeout (the whole process tree is
/// killed) and a stdout size cap. Nothing secret is ever on the command line or in the environment.</summary>
public sealed class PowerShellProcessRunner(string executable, IReadOnlyList<string> arguments) : IPowerShellRunner
{
    public const int MaxStderrChars = 64 * 1024;

    public string Executable { get; } = executable;
    public IReadOnlyList<string> Arguments { get; } = arguments;

    /// <summary>Windows PowerShell 5.1 from the System directory (never resolved through PATH) running the fixed
    /// <see cref="Collector.Loader"/>, which reads its real input from stdin.</summary>
    [SupportedOSPlatform("windows")]
    public static PowerShellProcessRunner WindowsPowerShell() =>
        new(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), Collector.LoaderArguments());

    public PowerShellResult Run(string stdin, TimeSpan timeout, long maxOutputBytes)
    {
        var psi = new ProcessStartInfo(Executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetTempPath(),
        };
        foreach (var a in Arguments) psi.ArgumentList.Add(a);
        // a PowerShell 7 PSModulePath inherited by Windows PowerShell 5.1 breaks its module autoloading
        psi.Environment.Remove("PSModulePath");
        using var proc = new Process { StartInfo = psi };
        try
        {
            if (!proc.Start()) throw new CollectError($"could not start {Path.GetFileName(Executable)}");
        }
        catch (Exception exc) when (exc is Win32Exception or InvalidOperationException or IOException)
        {
            throw new CollectError($"could not start {Path.GetFileName(Executable)}: {exc.Message}", exc);
        }
        var overflow = 0;
        var stdout = new MemoryStream();
        var outTask = Task.Run(() =>
        {
            var buf = new byte[81920];
            var s = proc.StandardOutput.BaseStream;
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0)
            {
                if (stdout.Length + n > maxOutputBytes)
                {
                    Interlocked.Exchange(ref overflow, 1);
                    Kill(proc);
                    return;
                }
                stdout.Write(buf, 0, n);
            }
        });
        var stderr = new StringBuilder();
        var errTask = Task.Run(() =>
        {
            var buf = new char[8192];
            int n;
            while ((n = proc.StandardError.Read(buf, 0, buf.Length)) > 0)
                if (stderr.Length < MaxStderrChars) stderr.Append(buf, 0, Math.Min(n, MaxStderrChars - stderr.Length));
        });
        // written in the background: a process that never reads stdin must not block the timeout below
        _ = Task.Run(() =>
        {
            try
            {
                proc.StandardInput.Write(stdin);
                proc.StandardInput.Close();
            }
            catch (Exception exc) when (exc is IOException or ObjectDisposedException or InvalidOperationException)
            {
                // the process ended before reading everything: its exit code / stderr tell why
            }
        });
        if (!proc.WaitForExit(timeout))
        {
            Kill(proc);
            throw new CollectError($"PowerShell did not finish within {(int)timeout.TotalSeconds}s");
        }
        proc.WaitForExit();
        Task.WaitAll([outTask, errTask], TimeSpan.FromSeconds(10));
        if (Volatile.Read(ref overflow) == 1)
            throw new CollectError($"PowerShell wrote more than {maxOutputBytes} bytes; output discarded");
        return new PowerShellResult(proc.ExitCode, stdout.ToArray(), stderr.ToString());
    }

    private static void Kill(Process p)
    {
        try
        {
            if (!p.HasExited) p.Kill(entireProcessTree: true);
        }
        catch (Exception exc) when (exc is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // already gone
        }
    }
}

/// <summary>Inventory collection (ported from admiral/collector.py): the read-only PowerShell inventory scripts, the
/// decoding / normalisation of their output, and collection over WinRM (PowerShell remoting).
/// <para>One remoting session is opened per computer and each section runs separately in it, so one failing section
/// does not lose the rest. Every script returns UTF-8 JSON wrapped in base64, which survives any console code page.</para>
/// <para>WinRM: instead of pywinrm the Windows' own WinRM client is used. ADmiral starts Windows PowerShell
/// (<c>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe</c>) with a fixed argument list whose only script is
/// the constant <see cref="Loader"/>; the loader reads a base64 JSON request from stdin (driver script, inventory
/// scripts, host, port, authentication, user name, password) and runs the driver, which opens <c>New-PSSession</c> and
/// <c>Invoke-Command</c>s each section. The target name and the credential are therefore data, never script text or
/// command-line text, and the password never appears in a process command line or environment block.</para></summary>
public static partial class Collector
{
    public static readonly IReadOnlyList<string> ListKinds = Db.ListKinds;

    /// <summary>The inventory sections in run order.</summary>
    public static readonly IReadOnlyList<string> SectionNames = ["general", "hardware", "apps", "services", "logons"];

    public static readonly IReadOnlyDictionary<int, string> Chassis = new Dictionary<int, string>
    {
        [1] = "Other", [2] = "Unknown", [3] = "Desktop", [4] = "Low Profile Desktop", [5] = "Pizza Box", [6] = "Mini Tower",
        [7] = "Tower", [8] = "Portable", [9] = "Laptop", [10] = "Notebook", [11] = "Hand Held", [12] = "Docking Station",
        [13] = "All in One", [14] = "Sub Notebook", [15] = "Space-Saving", [16] = "Lunch Box", [17] = "Main System Chassis",
        [23] = "Rack Mount", [24] = "Sealed-Case PC", [30] = "Tablet", [31] = "Convertible", [32] = "Detachable",
        [35] = "Mini PC", [36] = "Stick PC",
    };

    /// <summary>Largest record accepted from a target (remote output is untrusted input). A real inventory is well under
    /// 2 MB of JSON even on a server (a few thousand programs / hotfixes / services of a few hundred bytes each); with
    /// base64 (x1.33) 8 MB still leaves about 3x headroom while bounding what one hostile target can make ADmiral parse.</summary>
    public const long MaxOutputBytes = 8L * 1024 * 1024;

    /// <summary>Most entries kept per list section (apps, services, hotfixes...). Real machines have at most a few thousand;
    /// the rest is dropped with a warning so a hostile target cannot fill the database.</summary>
    public const int MaxItemsPerSection = 10_000;

    /// <summary>Longest string kept per field (names, versions, paths are far shorter); longer ones are cut.</summary>
    public const int MaxFieldChars = 4096;

    /// <summary>Cap every list section to <see cref="MaxItemsPerSection"/> entries and every string (at any depth) to
    /// <see cref="MaxFieldChars"/> characters, in place. Returns what was cut (for the log).</summary>
    public static (int ItemsDropped, int StringsCut) CapInventory(JsonObject o)
    {
        ArgumentNullException.ThrowIfNull(o);
        var dropped = 0;
        foreach (var k in ListKinds)
        {
            if (o[k] is not JsonArray a || a.Count <= MaxItemsPerSection) continue;
            dropped += a.Count - MaxItemsPerSection;
            while (a.Count > MaxItemsPerSection) a.RemoveAt(a.Count - 1);
            Log.Logger.LogWarning("Inventory: the '{Section}' section has more than {Max} entries; the rest was dropped", k, MaxItemsPerSection);
        }
        var cut = CapStrings(o, 0);
        if (cut > 0) Log.Logger.LogWarning("Inventory: {Count} value(s) longer than {Max} characters were shortened", cut, MaxFieldChars);
        return (dropped, cut);
    }

    private static int CapStrings(JsonNode? node, int depth)
    {
        if (depth > MaxJsonDepth) return 0;
        var cut = 0;
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(kv => kv.Key).ToList())
                {
                    if (obj[key] is JsonValue v && v.GetValueKind() == JsonValueKind.String && v.GetValue<string>() is { Length: > MaxFieldChars } str)
                    {
                        obj[key] = str[..MaxFieldChars];
                        cut++;
                    }
                    else cut += CapStrings(obj[key], depth + 1);
                }
                break;
            case JsonArray arr:
                for (var i = 0; i < arr.Count; i++)
                {
                    if (arr[i] is JsonValue v && v.GetValueKind() == JsonValueKind.String && v.GetValue<string>() is { Length: > MaxFieldChars } str)
                    {
                        arr[i] = str[..MaxFieldChars];
                        cut++;
                    }
                    else cut += CapStrings(arr[i], depth + 1);
                }
                break;
        }
        return cut;
    }

    /// <summary>JSON nesting accepted from a target (ConvertTo-Json -Depth 4 produces far less).</summary>
    public const int MaxJsonDepth = 32;

    private const string Wrap = """"
$ErrorActionPreference = 'SilentlyContinue'
function D($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { $null } }
$r = [ordered]@{}
{body}
$r.ps_errors = @($Error | Select-Object -First 15 | ForEach-Object { "$($_.CategoryInfo.Activity): $($_.Exception.Message)" })
$j = ConvertTo-Json -InputObject $r -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
"""";
    private const string PsGeneral = """"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$csp = Get-CimInstance Win32_ComputerSystemProduct
$bios = Get-CimInstance Win32_BIOS
$enc = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
$cpu = @(Get-CimInstance Win32_Processor)
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$lui = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
$gp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
$nic = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Sort-Object { -not $_.DefaultIPGateway } | Select-Object -First 1
$ie = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer'
$smbS = $null; try { $smbS = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}
$m10 = Get-Service mrxsmb10
$rb = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$sd = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'"
$r.os_caption = $os.Caption
$r.os_version = $os.Version
$r.os_build = "$($os.BuildNumber).$($cv.UBR)"
$r.os_display_version = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
$r.os_service_pack = $os.ServicePackMajorVersion
$r.os_architecture = $os.OSArchitecture
$r.os_installed = D $os.InstallDate
$r.os_serial = $os.SerialNumber
$r.system_drive = $os.SystemDrive
$r.last_boot = D $os.LastBootUpTime
$r.time_zone = (Get-CimInstance Win32_TimeZone).Caption
$r.powershell_version = $PSVersionTable.PSVersion.ToString()
$r.smb1_server = $smbS
$r.smb1_client = if ($m10) { $m10.StartType -ne 'Disabled' } else { $false }
$r.ie_version = if ($ie.svcVersion) { $ie.svcVersion } else { $ie.Version }
$r.pending_reboot = [bool]$rb
# local accounts of this computer (COMPUTER\user, .\user) are not recorded as the logged-on user
$isLocal = { param($n) $n -and (($n -split '\\')[0] -in @($env:COMPUTERNAME, '.')) }
$r.logged_on_user = if (& $isLocal $cs.UserName) { $null } else { $cs.UserName }
$r.user_display_name = if (& $isLocal $lui.LastLoggedOnSAMUser) { $null } else { $lui.LastLoggedOnDisplayName }
$r.domain = $cs.Domain
$r.domain_controller = ($gp.DCName -replace '^\\\\', '')
$r.ip_address = @($nic.IPAddress | Where-Object { $_ -match '^\d+\.' })[0]
$r.mac_address = $nic.MACAddress
$r.manufacturer = $cs.Manufacturer
$r.model = $cs.Model
$r.family = $cs.SystemFamily
$r.sku = $cs.SystemSKUNumber
$r.product_version = $csp.Version
$r.serial = $bios.SerialNumber
$r.bios_version = $bios.SMBIOSBIOSVersion
$r.bios_manufacturer = $bios.Manufacturer
$r.bios_asset_tag = $enc.SMBIOSAssetTag
$r.chassis_type = @($enc.ChassisTypes)[0]
$r.cpu = ($cpu | Select-Object -First 1).Name.Trim()
$r.cpu_count = $cpu.Count
$r.cpu_cores = ($cpu | Measure-Object NumberOfCores -Sum).Sum
$r.memory_bytes = [int64]$cs.TotalPhysicalMemory
$r.c_size_gb = [math]::Round($sd.Size / 1GB, 1)
$r.c_free_gb = [math]::Round($sd.FreeSpace / 1GB, 1)
"""";
    private const string PsHardware = """"
$r.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  [ordered]@{ drive = $_.DeviceID; label = $_.VolumeName; file_system = $_.FileSystem;
    size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } })
$r.nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
  [ordered]@{ name = $_.Description; mac = $_.MACAddress; ip = ($_.IPAddress -join ', ');
    gateway = ($_.DefaultIPGateway -join ', '); dns = ($_.DNSServerSearchOrder -join ', '); dhcp = [bool]$_.DHCPEnabled } })
$r.hotfixes = @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
  # the raw WMI value: PowerShell's own InstalledOn property throws for empty / some values (into $Error)
  $raw = if ($_.PSObject.Properties['CimInstanceProperties']) { [string]$_.CimInstanceProperties['InstalledOn'].Value } else { [string]$_.InstalledOn }
  $d = $null; $p = [datetime]::MinValue
  if ($raw -match '^[0-9A-Fa-f]{16}$') { $t = [Convert]::ToInt64($raw, 16); if ($t -gt 0 -and $t -lt 2650467743999999999) { $d = [datetime]::FromFileTimeUtc($t).ToString('yyyy-MM-dd') } }
  elseif ($raw -and [datetime]::TryParseExact($raw, [string[]]@('M/d/yyyy', 'MM/dd/yyyy', 'yyyyMMdd', 'yyyy-MM-dd', 'yyyy.MM.dd', 'yyyy. MM. dd.'),
      [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$p)) { $d = $p.ToString('yyyy-MM-dd') }
  [ordered]@{ id = $_.HotFixID; description = $_.Description; installed_on = $d; installed_by = $_.InstalledBy } })
# BitLocker: state of every volume (no secret here; the recovery keys are a separate, encrypted part)
$blv = @()
try { $blv = @(Get-BitLockerVolume -ErrorAction Stop) } catch {}
if ($blv.Count) {
  $r.bitlocker = @($blv | ForEach-Object { [ordered]@{ drive = [string]$_.MountPoint; volume_type = [string]$_.VolumeType;
    status = [string]$_.VolumeStatus; protection = [string]$_.ProtectionStatus; percent = $_.EncryptionPercentage;
    method = [string]$_.EncryptionMethod; lock = [string]$_.LockStatus; auto_unlock = $_.AutoUnlockEnabled;
    protectors = ((@($_.KeyProtector) | ForEach-Object { [string]$_.KeyProtectorType }) -join ', ') } })
} else {
  $r.bitlocker = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' Win32_EncryptableVolume | ForEach-Object {
    [ordered]@{ drive = [string]$_.DriveLetter; volume_type = ''; status = ''; protection = $(switch ([int]$_.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } });
      percent = $null; method = ''; lock = ''; auto_unlock = $null; protectors = '' } })
}
# connected displays (EDID through WMI): maker code, model, serial, manufacture date, size, connection
$txt = { param($a) if ($a) { -join ($a | Where-Object { $_ -ne 0 } | ForEach-Object { [char][int]$_ }) } else { '' } }
$bp = @{}; Get-CimInstance -Namespace root\wmi WmiMonitorBasicDisplayParams | ForEach-Object { $bp[[string]$_.InstanceName] = $_ }
$cn = @{}; Get-CimInstance -Namespace root\wmi WmiMonitorConnectionParams | ForEach-Object { $cn[[string]$_.InstanceName] = $_.VideoOutputTechnology }
$r.monitors = @(Get-CimInstance -Namespace root\wmi WmiMonitorID | ForEach-Object {
  $b = $bp[[string]$_.InstanceName]
  $w = if ($b) { [int]$b.MaxHorizontalImageSize } else { 0 }; $h = if ($b) { [int]$b.MaxVerticalImageSize } else { 0 }
  [ordered]@{ manufacturer = (& $txt $_.ManufacturerName); name = (& $txt $_.UserFriendlyName); product_code = (& $txt $_.ProductCodeID);
    serial = (& $txt $_.SerialNumberID); year = $_.YearOfManufacture; week = $_.WeekOfManufacture; width_cm = $w; height_cm = $h;
    size_in = $(if ($w -and $h) { [math]::Round([math]::Sqrt($w * $w + $h * $h) / 2.54, 1) } else { $null });
    connection = $cn[[string]$_.InstanceName]; active = [bool]$_.Active; instance = [string]$_.InstanceName } })
"""";
    private const string PsApps = """"
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$r.apps = @(Get-ItemProperty $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  Sort-Object DisplayName, DisplayVersion -Unique | ForEach-Object {
  [ordered]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher;
    installed = $_.InstallDate; arch = $(if ($_.PSPath -match 'WOW6432Node') { 'x86' } else { 'x64' }) } })
"""";
    private const string PsServices = """"
$r.services = @(Get-CimInstance Win32_Service | ForEach-Object {
  [ordered]@{ name = $_.Name; display_name = $_.DisplayName; state = $_.State; start_mode = $_.StartMode; account = $_.StartName } })
$adm = @()
try { $adm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [ordered]@{ name = $_.Name; type = "$($_.ObjectClass)"; source = "$($_.PrincipalSource)" } }) }
catch { $adm = @(net localgroup Administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'completed successfully|sikeresen' } | ForEach-Object { [ordered]@{ name = $_.Trim(); type = ''; source = '' } }) }
$r.local_admins = $adm
# every local group of the computer with its members
$lg = @()
try {
  $lg = @(Get-LocalGroup -ErrorAction Stop | ForEach-Object {
    $g = $_; $m = @()
    try { $m = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {}
    [ordered]@{ name = $g.Name; description = $g.Description; sid = [string]$g.SID; members = ($m -join ', '); member_count = $m.Count } })
} catch {
  $lg = @(Get-CimInstance Win32_Group -Filter 'LocalAccount=True' | ForEach-Object {
    [ordered]@{ name = $_.Name; description = $_.Description; sid = [string]$_.SID; members = ''; member_count = $null } })
}
$r.local_groups = $lg
"""";
    private const string PsLogons = """"
$xp = '*[System[(EventID=4624)]] and *[EventData[Data[@Name="LogonType"]="2" or Data[@Name="LogonType"]="7" or Data[@Name="LogonType"]="10" or Data[@Name="LogonType"]="11"]]'
$r.logons = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 3000 | Where-Object {
    $u = [string]$_.Properties[5].Value; $d = [string]$_.Properties[6].Value
    $u -and $u -notmatch '\$$' -and $u -notmatch '^(DWM|UMFD)-\d+$' -and
    $d -notin @('NT AUTHORITY', 'NT SERVICE', 'Window Manager', 'Font Driver Host', 'MicrosoftAccount', $env:COMPUTERNAME, '.') -and
    $u -notin @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON') } |
  Select-Object -First 300 | ForEach-Object {
  [ordered]@{ time = D $_.TimeCreated; user = [string]$_.Properties[5].Value; domain = [string]$_.Properties[6].Value;
    type = [int]$_.Properties[8].Value; ip = [string]$_.Properties[18].Value } })
# every user account of the computer: its local accounts, and the (domain) accounts that have a profile on it
$prof = @{}
Get-CimInstance Win32_UserProfile -Filter 'Special=False' | ForEach-Object { $prof[[string]$_.SID] = $_ }
$seenSid = @{}
$loc = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
  $p = $prof[[string]$_.SID]; $seenSid[[string]$_.SID] = 1
  [ordered]@{ name = $_.Name; domain = $_.Domain; full_name = $_.FullName; type = 'local'; enabled = -not $_.Disabled;
    last_use = $(if ($p) { D $p.LastUseTime } else { $null }); profile = $(if ($p) { $p.LocalPath } else { '' }); sid = [string]$_.SID } })
$oth = @($prof.Values | Where-Object { -not $seenSid.ContainsKey([string]$_.SID) } | ForEach-Object {
  $n = ''; try { $n = ([Security.Principal.SecurityIdentifier][string]$_.SID).Translate([Security.Principal.NTAccount]).Value } catch {}
  $parts = if ($n -like '*\*') { $n.Split('\', 2) } else { @('', $n) }
  [ordered]@{ name = $(if ($parts[1]) { $parts[1] } else { [string]$_.SID }); domain = $parts[0]; full_name = ''; type = 'domain'; enabled = $null;
    last_use = D $_.LastUseTime; profile = $_.LocalPath; sid = [string]$_.SID } })
$r.user_accounts = @($loc + $oth)
"""";

    /// <summary>The recovery passwords, encrypted on the computer with ADmiral's RSA public key (OAEP) before they
    /// leave it: neither the result file, the network nor the database ever holds one readable. Only when BitLocker
    /// answered (an empty list then means "no recovery password", and replaces the stored ones).</summary>
    private const string PsBitlockerKeys = """"
if ($blv.Count) {
  $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
  $rsa.FromXmlString(@@BLKEY@@)
  $r.bitlocker_keys = @(foreach ($v in $blv) { foreach ($p in @($v.KeyProtector)) {
    if ([string]$p.KeyProtectorType -eq 'RecoveryPassword' -and $p.RecoveryPassword) {
      [ordered]@{ drive = [string]$v.MountPoint; id = [string]$p.KeyProtectorId;
        cipher = [Convert]::ToBase64String($rsa.Encrypt([Text.Encoding]::UTF8.GetBytes([string]$p.RecoveryPassword), $true)) } } } })
}
"""";

    [System.Text.RegularExpressions.GeneratedRegex(@"\A<RSAKeyValue><Modulus>[A-Za-z0-9+/=]{100,2000}</Modulus><Exponent>[A-Za-z0-9+/=]{1,16}</Exponent></RSAKeyValue>\z")]
    private static partial System.Text.RegularExpressions.Regex RsaPublicXml();

    /// <summary>The section's body; the hardware section also reads the BitLocker recovery keys when
    /// <paramref name="bitlockerKey"/> (ADmiral's RSA public key, XML) is given.</summary>
    private static string SectionBody(string section, string? bitlockerKey = null) => section switch
    {
        "general" => PsGeneral,
        "hardware" => bitlockerKey is null ? PsHardware
            : PsHardware.TrimEnd() + "\n" + PsBitlockerKeys.Replace("@@BLKEY@@",
                Deploy.Q(RsaPublicXml().IsMatch(bitlockerKey) ? bitlockerKey : throw new ArgumentException("not an RSA public key"))),
        "apps" => PsApps,
        "services" => PsServices,
        "logons" => PsLogons,
        _ => throw new ArgumentException($"unknown inventory section '{section}'", nameof(section)),
    };

    private static string WrapText => "\n" + Wrap + "\n";

    /// <summary>The script of one section: the body inside the common wrapper (errors collected, base64 JSON output).</summary>
    public static string Script(string section, string? bitlockerKey = null) => WrapText.Replace("{body}", SectionBody(section, bitlockerKey).Trim());

    /// <summary>Every section as one script producing a single base64 JSON record (the PDQ-style collector and the
    /// offline script run it); exactly the same read-only <c>Get-*</c> inventory as the per-section scripts.</summary>
    public static string CombinedScript(string? bitlockerKey = null) =>
        WrapText.Replace("{body}", string.Join("\n", SectionNames.Select(s => SectionBody(s, bitlockerKey).Trim())));

    /// <summary>Remove the PowerShell <c>$Error</c> list (<c>ps_errors</c>) from a decoded record and log it.</summary>
    public static void LogScriptErrors(string host, string where, JsonObject record)
    {
        if (!record.Remove("ps_errors", out var errs) || errs is null) return;
        var list = (errs is JsonArray a ? a.Select(x => NodeText(x)) : [NodeText(errs)])
            .Where(e => !string.IsNullOrEmpty(e) && !e.Contains("No events were found", StringComparison.Ordinal)).ToList();
        if (list.Count == 0) return;
        Log.Logger.LogWarning("Inventory script on {Host} ({Where}) swallowed {Count} error(s): {Errors}", host, where, list.Count,
            string.Join(" | ", list.Take(5).Select(e => e.Length > 160 ? e[..160] : e)));
    }

    /// <summary>A JSON number as double (whatever CLR type backs the node); null for anything else.</summary>
    internal static double? Number(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.Number
        && double.TryParse(v.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    /// <summary>A JSON integer that fits an int; null otherwise.</summary>
    internal static int? Int(JsonNode? n) => Number(n) is { } d && d == Math.Floor(d) && d is >= int.MinValue and <= int.MaxValue ? (int)d : null;

    private static string NodeText(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : n?.ToJsonString() ?? "";

    private static readonly JsonDocumentOptions DocOptions = new() { MaxDepth = MaxJsonDepth };

    /// <summary>Parse untrusted JSON (UTF-8 BOM tolerated, invalid UTF-8 refused) with the depth limit.</summary>
    public static JsonNode? ParseJson(ReadOnlySpan<byte> utf8, int maxDepth = MaxJsonDepth)
    {
        if (utf8.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) utf8 = utf8[3..];
        var text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(utf8);
        return JsonNode.Parse(text, documentOptions: maxDepth == MaxJsonDepth ? DocOptions : new JsonDocumentOptions { MaxDepth = maxDepth });
    }

    /// <summary>The record of a script's stdout: its last line is base64 of UTF-8 JSON (anything before is noise).</summary>
    public static JsonObject DecodeOutput(byte[] stdout)
    {
        var text = Encoding.ASCII.GetString(stdout).Trim();
        var lines = text.Split('\n');
        var payload = lines.Length > 0 ? lines[^1].Trim() : "";
        try
        {
            var raw = Convert.FromBase64String(payload);
            if (raw.LongLength > MaxOutputBytes) throw new CollectError("output too large");
            return ParseJson(raw) as JsonObject ?? throw new FormatException("not a JSON object");
        }
        catch (Exception exc) when (exc is FormatException or JsonException or DecoderFallbackException or ArgumentException)
        {
            throw new CollectError($"Unexpected output: '{(payload.Length > 200 ? payload[..200] : payload)}'", exc);
        }
    }

    /// <summary>Fix up types PowerShell may hand back (single-item lists, null lists, ints as strings); derive
    /// <c>chassis</c>, <c>memory_gb</c> and <c>os_short</c>; clean the logon history.</summary>
    public static JsonObject Normalize(JsonObject raw)
    {
        var o = (JsonObject)raw.DeepClone();
        foreach (var k in ListKinds)
        {
            if (!o.TryGetPropertyValue(k, out var v) || v is null) continue;
            if (v is not JsonArray) o[k] = new JsonArray(v.DeepClone());
        }
        CapInventory(o);
        if (o.TryGetPropertyValue("logons", out var logons) && logons is JsonArray la)
            o["logons"] = new JsonArray([.. CollectorModel.CleanLogons(la)]);
        if (o.TryGetPropertyValue("chassis_type", out var ct) && ct is JsonValue cv)
        {
            int? code = cv.GetValueKind() switch
            {
                JsonValueKind.Number when Number(cv) is { } l && l is >= 0 and <= int.MaxValue && l == Math.Floor(l) => (int)l,
                JsonValueKind.String when cv.GetValue<string>() is var s && s.Length > 0 && s.All(char.IsAsciiDigit)
                                          && int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var p) => p,
                _ => null,
            };
            if (code is { } c) o["chassis"] = Chassis.TryGetValue(c, out var name) ? name : $"Type {NodeText(ct)}";
        }
        o.Remove("chassis_type");
        if (o.Remove("memory_bytes", out var mb) && mb is JsonValue mv && mv.GetValueKind() == JsonValueKind.Number
            && Number(mv) is { } bytes && bytes > 0)
            o["memory_gb"] = Math.Round(bytes / (1024.0 * 1024 * 1024), 1, MidpointRounding.ToEven);
        var caption = o["os_caption"] is JsonValue oc && oc.GetValueKind() == JsonValueKind.String ? oc.GetValue<string>() : "";
        o["os_short"] = OsShort(caption);
        return o;
    }

    [GeneratedRegex(@"Server (\d{4}(?: R2)?)")]
    private static partial Regex ServerVersion();

    [GeneratedRegex(@"Windows (\d+(?:\.\d)?)")]
    private static partial Regex ClientVersion();

    /// <summary>'Microsoft Windows Server 2012 R2 Standard' -> '2012 R2', 'Windows 11 Pro' -> '11'.</summary>
    public static string? OsShort(string? caption)
    {
        var m = ServerVersion().Match(caption ?? "");
        if (m.Success) return m.Groups[1].Value;
        m = ClientVersion().Match(caption ?? "");
        return m.Success ? m.Groups[1].Value : null;
    }

    // ===================================================================================== WinRM
    /// <summary>The fixed bootstrap passed with <c>-EncodedCommand</c>: it contains no data at all. It reads one line
    /// of base64 (UTF-8 JSON) from stdin and runs the request's driver with the request as its argument.</summary>
    public const string Loader =
        "$ErrorActionPreference = 'Stop'; $b = [Console]::In.ReadToEnd(); " +
        "$r = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b.Trim()))); " +
        "$b = $null; & ([scriptblock]::Create([string]$r.driver)) $r";

    /// <summary>The complete, constant argument list of the local PowerShell process.</summary>
    public static IReadOnlyList<string> LoaderArguments() =>
    [
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-InputFormat", "Text", "-OutputFormat", "Text",
        "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(Loader)),
    ];

    /// <summary>Runs locally in Windows PowerShell: opens one remoting session and runs every section in it. All
    /// inputs come from <c>$r</c> (parsed JSON), so nothing is ever spliced into script text.</summary>
    public const string Driver = """"
param($r)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$out = [ordered]@{ open_error = $null; open_code = 0; sections = [ordered]@{} }
function Emit($o) {
  $j = ConvertTo-Json -InputObject $o -Depth 5 -Compress
  [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j)))
}
$s = $null
try {
  $skip = -not [bool]$r.verify_cert
  $opt = New-PSSessionOption -OpenTimeout ([int]$r.timeout * 1000) -SkipCACheck:$skip -SkipCNCheck:$skip -NoMachineProfile
  $p = @{ ComputerName = [string]$r.host; Port = [int]$r.port; Authentication = [string]$r.auth; SessionOption = $opt }
  if ([bool]$r.use_https) { $p.UseSSL = $true }
  if ([string]$r.user) {
    $sec = ConvertTo-SecureString -String ([string]$r.password) -AsPlainText -Force
    $p.Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ([string]$r.user), $sec
  }
  $r.password = $null
  $s = New-PSSession @p
} catch {
  $e = $_.Exception
  $code = 0
  if ($e -is [System.Management.Automation.Remoting.PSRemotingTransportException]) { $code = [int]$e.ErrorCode }
  $out.open_error = '' + $e.GetType().Name + ': ' + $e.Message
  $out.open_code = $code
  Emit $out
  exit 0
}
try {
  foreach ($name in @($r.order)) {
    $src = '$Error.Clear()' + "`n" + [string]$r.sections.$name
    try {
      $res = @(Invoke-Command -Session $s -ScriptBlock ([scriptblock]::Create($src)) -ErrorAction Stop)
      $last = ''
      if ($res.Count) { $last = [string]$res[$res.Count - 1] }
      $out.sections[$name] = [ordered]@{ out = $last; error = '' }
    } catch {
      $out.sections[$name] = [ordered]@{ out = ''; error = '' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
    }
  }
} finally {
  Remove-PSSession -Session $s -ErrorAction SilentlyContinue
}
Emit $out
"""";

    /// <summary>How a failed session open is classified for the NTLM fallback decision.</summary>
    public enum WinRMFailure { Other, Auth, Network }

    /// <summary>The session could not be opened (carries the classification of the WinRM / Win32 error).</summary>
    public sealed class WinRMOpenError(string message, WinRMFailure kind, int code = 0) : CollectError(message)
    {
        public WinRMFailure Kind { get; } = kind;
        public int Code { get; } = code;
    }

    private static readonly HashSet<int> AuthCodes =
    [
        5, 1326, 1327, 1330, 1331, 1909, 86,                     // access denied, logon failure, restrictions, expired, locked
        unchecked((int)0x8009030C), unchecked((int)0x8009030E), unchecked((int)0x80090311), unchecked((int)0x80090322),
        unchecked((int)0x8009030D), unchecked((int)0x80090308), unchecked((int)0x80090302), unchecked((int)0x80090303),
        unchecked((int)0x803380E4), unchecked((int)0x80338005),
    ];

    private static readonly HashSet<int> NetworkCodes =
    [
        53, 64, 67, 121, 1214, 1231, 1232, 1460, 1722, 10060, 10061, 10065, 11001, 12002, 12007, 12029,
        unchecked((int)0x80338012), unchecked((int)0x80338126), unchecked((int)0x803381A6),
    ];

    [GeneratedRegex(@"access is denied|logon failure|user name or password|unknown user name|kerberos|authenticat|credential|" +
                    @"trustedhosts|no authority could be contacted|target principal name|security package|401", RegexOptions.IgnoreCase)]
    private static partial Regex AuthText();

    [GeneratedRegex(@"cannot connect|could not connect|cannot be reached|timed out|timeout|not accessible over the network|" +
                    @"firewall|network path was not found|no such host|cannot be resolved|name resolution|refused|unreachable",
                    RegexOptions.IgnoreCase)]
    private static partial Regex NetworkText();

    /// <summary>Classify a session-open failure from the WinRM/Win32 error code (first) and the message.</summary>
    public static WinRMFailure ClassifyWinRMError(int code, string? message)
    {
        if (NetworkCodes.Contains(code)) return WinRMFailure.Network;
        if (AuthCodes.Contains(code)) return WinRMFailure.Auth;
        var m = message ?? "";
        if (NetworkText().IsMatch(m)) return WinRMFailure.Network;
        return AuthText().IsMatch(m) ? WinRMFailure.Auth : WinRMFailure.Other;
    }

    /// <summary>The <c>-Authentication</c> value of New-PSSession for a configured transport.</summary>
    public static string PsAuthentication(string transport) => (transport ?? "").ToLowerInvariant() switch
    {
        "kerberos" => "Kerberos",
        "ntlm" => "Negotiate",
        "credssp" => "Credssp",
        "basic" or "ssl" => "Basic",
        _ => throw new CollectError($"unsupported WinRM transport '{transport}'"),
    };

    private static readonly HashSet<string> Warned = [];

    private static void WarnOnce(string key, string message)
    {
        lock (Warned)
            if (!Warned.Add(key)) return;
        Log.Logger.LogWarning("{Message}", message);
    }

    /// <summary>Wall-clock limit of one collection process: opening plus every section.</summary>
    public static TimeSpan TotalTimeout(WinRMSettings cfg) =>
        TimeSpan.FromSeconds(Math.Max(5, cfg.Timeout) + 15 + SectionNames.Count * Math.Max(120, cfg.Timeout * 3));

    /// <summary>The stdin request for one session (exposed for tests; contains the password - never log it).</summary>
    internal static string BuildRequest(string host, WinRMSettings cfg, string transport, string realm, string? bitlockerKey = null)
    {
        string user = cfg.User ?? "", password = cfg.Password ?? "";
        if (transport == "kerberos")
        {
            Kerberos.RequireFqdn(host, "WinRM target");
            // DOMAIN\user -> user@REALM; realm from the caller (search base DN) or the target's DNS suffix
            user = Kerberos.KerberosPrincipal(user, string.IsNullOrEmpty(realm) ? Kerberos.RealmFromHost(host) : realm) ?? "";
            if (user.Length == 0) password = "";
        }
        var req = new JsonObject
        {
            ["driver"] = Driver,
            ["host"] = host,
            ["port"] = cfg.UseHttps ? 5986 : 5985,
            ["use_https"] = cfg.UseHttps,
            ["verify_cert"] = cfg.VerifyCert,
            ["auth"] = PsAuthentication(transport),
            ["timeout"] = Math.Max(5, cfg.Timeout),
            ["user"] = user,
            ["password"] = password,
            ["order"] = new JsonArray([.. SectionNames.Select(s => (JsonNode)s)]),
            ["sections"] = new JsonObject(SectionNames.Select(s => KeyValuePair.Create(s, (JsonNode?)Script(s, bitlockerKey)))),
        };
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(req.ToJsonString()));
    }

    private static JsonObject RunSession(string host, WinRMSettings cfg, string transport, string realm, IPowerShellRunner runner, string? bitlockerKey = null)
    {
        if (transport == "credssp")
            WarnOnce("credssp", "WinRM CredSSP hands the account's password to every target computer: a compromised computer can " +
                                "reuse it. Prefer Kerberos.");
        if (cfg.UseHttps && !cfg.VerifyCert)
            WarnOnce("cert", "WinRM HTTPS without certificate validation: a machine in the middle can read the session");
        if (PsAuthentication(transport) == "Basic" && !cfg.UseHttps)       // settings from elsewhere than Config.Validate
            throw new CollectError($"WinRM transport '{transport}' (Basic) needs HTTPS (use_https): the password would cross the network readable");
        var res = runner.Run(BuildRequest(host, cfg, transport, realm, bitlockerKey), TotalTimeout(cfg), MaxOutputBytes);
        JsonObject resp;
        try
        {
            resp = DecodeOutput(res.Stdout);
        }
        catch (CollectError exc)
        {
            var err = res.Stderr.Trim();
            throw new CollectError($"PowerShell exit {res.ExitCode}: {(err.Length > 300 ? err[..300] : err)}".TrimEnd(' ', ':')
                                   + (err.Length == 0 ? $" ({exc.Message})" : ""), exc);
        }
        if (resp["open_error"] is JsonValue oe && oe.GetValueKind() == JsonValueKind.String)
        {
            var msg = oe.GetValue<string>();
            var code = Number(resp["open_code"]) is { } cd && cd is >= int.MinValue and <= int.MaxValue ? (int)cd : 0;
            throw new WinRMOpenError(msg.Length > 500 ? msg[..500] : msg, ClassifyWinRMError(code, msg), code);
        }
        return resp;
    }

    private static bool CanFallBack(Exception exc) => exc switch
    {
        WinRMOpenError w => w.Kind == WinRMFailure.Auth,
        _ => Kerberos.IsAuthError(exc) && !Kerberos.IsNetworkError(exc),
    };

    /// <summary>Run every section on <paramref name="host"/> over WinRM. Throws <see cref="CollectError"/> only if
    /// <i>nothing</i> could be read; failed sections are listed in <c>section_errors</c>.
    /// <para>Kerberos is the primary transport. NTLMv2 (Negotiate) is tried only when <c>ntlm_fallback</c> is on, the
    /// transport is kerberos, explicit credentials are configured and Kerberos failed with an authentication error
    /// (never after a network error such as a timeout or a refused connection).</para>
    /// <paramref name="runner"/> defaults to Windows PowerShell (Windows only).</summary>
    public static JsonObject WinrmCollect(string host, WinRMSettings cfg, string realm = "", IPowerShellRunner? runner = null, string? bitlockerKey = null)
    {
        Remote.ValidateHost(host);
        runner ??= DefaultRunner();
        JsonObject resp;
        try
        {
            resp = RunSession(host, cfg, cfg.Transport, realm, runner, bitlockerKey);
            if (Log.Logger.IsEnabled(LogLevel.Information))
                Log.Logger.LogInformation("WinRM {Host}: authenticated with {Transport}", host, cfg.Transport);
        }
        catch (Exception exc) when (exc is CollectError or KerberosError)
        {
            if (!(cfg.Transport == "kerberos" && cfg.NtlmFallback && !string.IsNullOrEmpty(cfg.User)
                  && !string.IsNullOrEmpty(cfg.Password) && CanFallBack(exc)))
            {
                Log.Logger.LogWarning("WinRM {Host}: {Transport} failed{Note}: {Error}", host, cfg.Transport,
                    cfg.Transport == "kerberos" && !cfg.NtlmFallback ? "; NTLMv2 fallback is off" : "", exc.Message);
                throw exc as CollectError ?? new CollectError($"{exc.GetType().Name}: {exc.Message}", exc);
            }
            Log.Logger.LogWarning("WinRM {Host}: Kerberos failed ({Error}); falling back to NTLMv2", host, exc.Message);
            try
            {
                resp = RunSession(host, cfg, "ntlm", realm, runner, bitlockerKey);
            }
            catch (CollectError exc2)
            {
                throw new CollectError($"Kerberos: {exc.Message}; NTLMv2 fallback: {exc2.Message}", exc2);
            }
            Log.Logger.LogWarning("WinRM {Host}: authenticated with NTLMv2 (fallback)", host);
        }
        var result = new JsonObject();
        var errors = new JsonObject();
        var sections = resp["sections"] as JsonObject ?? [];
        foreach (var name in SectionNames)
        {
            try
            {
                if (sections[name] is not JsonObject sec) throw new CollectError("no result");
                var err = sec["error"] is JsonValue ev && ev.GetValueKind() == JsonValueKind.String ? ev.GetValue<string>() : "";
                if (err.Length > 0) throw new CollectError(err);
                var outText = sec["out"] is JsonValue ov && ov.GetValueKind() == JsonValueKind.String ? ov.GetValue<string>() : "";
                var part = DecodeOutput(Encoding.ASCII.GetBytes(outText));
                LogScriptErrors(host, name, part);
                foreach (var (k, v) in part.ToList())
                {
                    part.Remove(k);
                    result[k] = v;
                }
            }
            catch (CollectError exc)
            {
                var text = $"{exc.GetType().Name}: {exc.Message}";
                errors[name] = text.Length > 300 ? text[..300] : text;
                Log.Logger.LogWarning("WinRM {Host}: inventory section '{Section}' failed: {Error}", host, name, exc.Message);
            }
        }
        if (result.Count == 0)
            throw new CollectError(string.Join("; ", errors.Select(kv => $"{kv.Key}: {NodeText(kv.Value)}")));
        if (errors.Count > 0) result["section_errors"] = errors;
        return Normalize(result);
    }

    private static IPowerShellRunner DefaultRunner() =>
        OperatingSystem.IsWindows()
            ? PowerShellProcessRunner.WindowsPowerShell()
            : throw new CollectError("WinRM collection needs Windows (Windows PowerShell remoting)");
}
