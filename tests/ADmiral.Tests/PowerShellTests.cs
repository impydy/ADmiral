using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>test_powershell.py: runs the real inventory scripts with PowerShell 7 (pwsh). Linux pwsh has no CIM/WMI or
/// registry, so the Windows cmdlets are replaced with PowerShell functions (functions take precedence over cmdlets) that
/// return Windows-shaped objects. Skipped (with the reason) when pwsh is not installed.</summary>
public class PowerShellTests
{
    internal const string Mocks = """"
function Get-CimInstance {
  param([Parameter(Position = 0)] $ClassName, $Filter)
  switch ($ClassName) {
    'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Enterprise'; Version = '10.0.22631';
        BuildNumber = '22631'; ServicePackMajorVersion = 0; OSArchitecture = '64-bit';
        InstallDate = [datetime]'2024-03-05T08:00:00'; SerialNumber = '00330-80000-00000-AA123'; SystemDrive = 'C:';
        LastBootUpTime = [datetime]'2026-11-10T06:30:00' } }
    'Win32_ComputerSystem' { [pscustomobject]@{ UserName = 'CONTOSO\kovacs.anna'; Domain = 'contoso.local';
        Manufacturer = 'Dell Inc.'; Model = 'Latitude 7440'; SystemFamily = 'Latitude'; SystemSKUNumber = '0C0A';
        TotalPhysicalMemory = 17179869184 } }
    'Win32_ComputerSystemProduct' { [pscustomobject]@{ Version = 'A01' } }
    'Win32_BIOS' { [pscustomobject]@{ SerialNumber = 'ABC1234'; SMBIOSBIOSVersion = '1.17.1'; Manufacturer = 'Dell Inc.' } }
    'Win32_SystemEnclosure' { [pscustomobject]@{ SMBIOSAssetTag = 'IT-0042'; ChassisTypes = [uint16[]]@(10) } }
    'Win32_Processor' { [pscustomobject]@{ Name = 'Intel(R) Core(TM) i7-1365U   '; NumberOfCores = 10 } }
    'Win32_TimeZone' { [pscustomobject]@{ Caption = '(UTC+01:00) Belgrád, Budapest, Ljubljana, Pozsony, Prága' } }
    'Win32_NetworkAdapterConfiguration' {
      [pscustomobject]@{ Description = 'Hyper-V Virtual Ethernet'; MACAddress = '00:15:5D:00:00:01';
        IPAddress = @('172.20.0.1', 'fe80::1'); DefaultIPGateway = $null; DNSServerSearchOrder = $null; DHCPEnabled = $false }
      [pscustomobject]@{ Description = 'Intel(R) Ethernet I219-LM'; MACAddress = 'A4:BB:6D:11:22:33';
        IPAddress = @('fe80::abcd', '10.10.5.21'); DefaultIPGateway = @('10.10.5.1');
        DNSServerSearchOrder = @('10.10.0.11', '10.10.0.12'); DHCPEnabled = $true }
    }
    'Win32_LogicalDisk' {
      $c = [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; FileSystem = 'NTFS'; Size = 512GB; FreeSpace = 100GB }
      $d = [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Adatok'; FileSystem = 'NTFS'; Size = 1TB; FreeSpace = 900GB }
      if ($Filter -eq "DeviceID='C:'") { $c } elseif ($Filter -eq 'DriveType=3') { $c; $d } else { throw "unexpected filter $Filter" }
    }
    'Win32_QuickFixEngineering' {
      [pscustomobject]@{ HotFixID = 'KB5044285'; Description = 'Security Update'; InstalledOn = '10/15/2026'; InstalledBy = 'NT AUTHORITY\SYSTEM' }
      [pscustomobject]@{ HotFixID = 'KB5043080'; Description = 'Update'; InstalledOn = '01d9a5b2c3d4e5f6'; InstalledBy = '' }
    }
    'Win32_Service' {
      [pscustomobject]@{ Name = 'WinRM'; DisplayName = 'Windows Remote Management (WS-Management)'; State = 'Running'; StartMode = 'Auto'; StartName = 'NT AUTHORITY\NetworkService' }
      [pscustomobject]@{ Name = 'Spooler'; DisplayName = 'Nyomtatásisor-kezelő'; State = 'Stopped'; StartMode = 'Disabled'; StartName = 'LocalSystem' }
    }
    default { throw "unexpected class $ClassName" }
  }
}
function Get-ItemProperty {
  param([Parameter(Position = 0)] $Path)
  foreach ($p in @($Path)) {
    switch -Wildcard ($p) {
      '*Windows NT\CurrentVersion' { [pscustomobject]@{ UBR = 4460; DisplayVersion = '23H2'; ReleaseId = '2009' } }
      '*Authentication\LogonUI' { [pscustomobject]@{ LastLoggedOnDisplayName = 'Kovács Anna' } }
      '*Group Policy\History' { [pscustomobject]@{ DCName = '\\DC02.contoso.local' } }
      '*Internet Explorer' { [pscustomobject]@{ Version = '9.11.22621.0'; svcVersion = '11.1.22621.0' } }
      '*WOW6432Node*Uninstall*' {
        [pscustomobject]@{ DisplayName = 'ÁNYK – Általános Nyomtatványkitöltő'; DisplayVersion = '3.44.0'; Publisher = 'NAV'; InstallDate = '20250102'; PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ANYK' }
        [pscustomobject]@{ DisplayName = 'Google Chrome'; DisplayVersion = '131.0.6778.86'; Publisher = 'Google LLC'; InstallDate = '20261101'; PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Chrome' }
      }
      '*Uninstall*' {
        [pscustomobject]@{ DisplayName = 'Google Chrome'; DisplayVersion = '131.0.6778.86'; Publisher = 'Google LLC'; InstallDate = '20261101'; PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Chrome' }
        [pscustomobject]@{ DisplayName = '7-Zip 24.08 (x64)'; DisplayVersion = '24.08'; Publisher = 'Igor Pavlov'; InstallDate = $null; PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip' }
        [pscustomobject]@{ DisplayName = 'Hidden runtime'; SystemComponent = 1; PSPath = 'x' }
        [pscustomobject]@{ DisplayName = 'KB update child'; ParentKeyName = 'Office'; PSPath = 'x' }
        [pscustomobject]@{ DisplayName = $null; PSPath = 'x' }
      }
    }
  }
}
function Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $false } }
function Get-Service { param([Parameter(Position = 0)] $Name) if ($Name -eq 'mrxsmb10') { [pscustomobject]@{ StartType = 'Disabled' } } }
function Test-Path { param([Parameter(Position = 0)] $Path) $Path -like '*RebootRequired' }
"""";

    internal const string LocalgroupOk = """"
function Get-LocalGroupMember { param($SID)
  if ($SID -ne 'S-1-5-32-544') { throw 'wrong SID' }
  [pscustomobject]@{ Name = 'PC01\Administrator'; ObjectClass = 'User'; PrincipalSource = 'Local' }
  [pscustomobject]@{ Name = 'CONTOSO\Domain Admins'; ObjectClass = 'Group'; PrincipalSource = 'ActiveDirectory' } }
"""";

    internal const string LocalgroupFallback = """"
function Get-LocalGroupMember { throw 'Failed to compare two elements in the array.' }
function net { @('Alias name     Administrators', 'Comment        Administrators have complete access', '', 'Members', '',
  '-------------------------------------------------------------------------------',
  'Administrator', 'CONTOSO\Domain Admins', 'CONTOSO\helpdesk', 'The command completed successfully.', '') }
"""";

    private static JsonObject RunSection(string section, string prelude = Mocks)
    {
        var (code, _, err, raw) = Pwsh.Run(prelude + "\n" + Collector.Script(section));
        Assert.True(code == 0, err);
        return Collector.DecodeOutput(raw);
    }

    /// <summary>The PowerShell parser reports no error for <paramref name="script"/> (written to a file, as deployed).</summary>
    internal static void AssertParses(string script, CoreTemp tmp)
    {
        var p = tmp.File("s.ps1");
        File.WriteAllText(p, script, new UTF8Encoding(false));
        var cmd = "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile(" +
                  $"{Deploy.Q(p)},[ref]$t,[ref]$e); if($e){{$e|%{{$_.Message}};exit 1}}";
        var (code, stdout, stderr, _) = Pwsh.Run(cmd);
        Assert.True(code == 0, stdout + stderr);
    }

    private static string ParseErrors(string code) => Pwsh.Run($$"""
        $errs = $null; $tokens = $null
        $code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{Convert.ToBase64String(Encoding.UTF8.GetBytes(code))}}'))
        [void][System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errs)
        $errs | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }
        """).Stdout.Trim();

    /// <summary>Windows ships Windows PowerShell 5.1: no ?:, ??, ??=, ?., &amp;&amp;, || allowed.</summary>
    private static string Ps7Syntax(string code) => Pwsh.Run($$"""
        $code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{Convert.ToBase64String(Encoding.UTF8.GetBytes(code))}}'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null)
        $bad = $ast.FindAll({ param($n)
          $n -is [System.Management.Automation.Language.TernaryExpressionAst] -or
          $n -is [System.Management.Automation.Language.PipelineChainAst] -or
          ($n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'QuestionQuestion') -or
          ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Operator -eq 'QuestionQuestionEquals') -or
          ($n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.NullConditional)
        }, $true)
        $bad | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Extent.Text)" }
        """).Stdout.Trim();

    public static TheoryData<string> Sections() => [.. Collector.SectionNames];

    public static TheoryData<string> AllScripts()
    {
        var d = new TheoryData<string>();
        foreach (var s in Collector.SectionNames) d.Add(s);
        d.Add("combined");
        d.Add("driver");
        d.Add("loader");
        d.Add("deploy");
        d.Add("kill");
        return d;
    }

    private static string ScriptOf(string name) => name switch
    {
        "combined" => Collector.CombinedScript(),
        "driver" => Collector.Driver,
        "loader" => Collector.Loader,
        "deploy" => Deploy.InstallScript("msi", @"C:\Windows\Temp\admiral-0123456789ab-inst.msi", "/qn 'x' \u2019y\u2019", "r", "o", "t"),
        "kill" => Encoding.Unicode.GetString(Convert.FromBase64String(Pdq.KillCommand("0123456789ab").Split(' ')[^1])),
        _ => Collector.Script(name),
    };

    [PwshTheory]
    [MemberData(nameof(AllScripts))]
    public void ScriptsParseWithoutErrors(string name) => Assert.Equal("", ParseErrors(ScriptOf(name)));

    [PwshTheory]
    [MemberData(nameof(AllScripts))]
    public void ScriptsUseNoPowerShell7OnlySyntax(string name) => Assert.Equal("", Ps7Syntax(ScriptOf(name)));

    [PwshFact]
    public void DeployArgumentsStayOneLiteral()
    {
        // the parsed -ArgumentList value is exactly the text the administrator typed
        const string args = "/qn 'a' \u2019b\u2018 $(calc) `n ; & INSTALLDIR=\"C:\\P F\"";
        var lit = Deploy.Q(args);
        var (code, stdout, stderr, _) = Pwsh.Run($"$v = {lit}; [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($v)))");
        Assert.True(code == 0, stderr);
        Assert.Equal(args, Encoding.UTF8.GetString(Convert.FromBase64String(stdout.Trim())));
    }

    [PwshFact]
    public void GeneralSectionMapsEveryField()
    {
        var r = Collector.Normalize(RunSection("general"));
        var expected = new Dictionary<string, object?>
        {
            ["os_caption"] = "Microsoft Windows 11 Enterprise", ["os_version"] = "10.0.22631", ["os_build"] = "22631.4460",
            ["os_display_version"] = "23H2", ["os_service_pack"] = 0L, ["os_architecture"] = "64-bit",
            ["os_serial"] = "00330-80000-00000-AA123", ["system_drive"] = "C:",
            ["time_zone"] = "(UTC+01:00) Belgrád, Budapest, Ljubljana, Pozsony, Prága",
            ["smb1_server"] = false, ["smb1_client"] = false, ["ie_version"] = "11.1.22621.0", ["pending_reboot"] = true,
            ["logged_on_user"] = "CONTOSO\\kovacs.anna", ["user_display_name"] = "Kovács Anna", ["domain"] = "contoso.local",
            ["domain_controller"] = "DC02.contoso.local", ["ip_address"] = "10.10.5.21", ["mac_address"] = "A4:BB:6D:11:22:33",
            ["manufacturer"] = "Dell Inc.", ["model"] = "Latitude 7440", ["family"] = "Latitude", ["sku"] = "0C0A",
            ["product_version"] = "A01", ["serial"] = "ABC1234", ["bios_version"] = "1.17.1", ["bios_manufacturer"] = "Dell Inc.",
            ["bios_asset_tag"] = "IT-0042", ["cpu"] = "Intel(R) Core(TM) i7-1365U", ["cpu_count"] = 1L, ["cpu_cores"] = 10L,
            ["c_size_gb"] = 512.0, ["c_free_gb"] = 100.0, ["chassis"] = "Notebook", ["memory_gb"] = 16.0, ["os_short"] = "11",
        };
        foreach (var (k, v) in expected)
        {
            object? got = v switch
            {
                string => (string?)r[k],
                bool => (bool?)r[k],
                long l => r[k] is null ? null : (r[k]!.GetValue<double>() == l ? l : (object?)r[k]!.ToJsonString()),
                double => (double?)r[k],
                _ => null,
            };
            Assert.True(Equals(v, got), $"{k}: {r[k]?.ToJsonString()} != {v}");
        }
        Assert.StartsWith("2024-03-05", (string)r["os_installed"]!);
        Assert.StartsWith("2026-11-10", (string)r["last_boot"]!);
        Assert.StartsWith("7.", (string)r["powershell_version"]!);
    }

    [PwshFact]
    public void HardwareSection()
    {
        var r = Collector.Normalize(RunSection("hardware"));
        var disks = (JsonArray)r["disks"]!;
        Assert.Equal(["C:", "D:"], disks.Select(d => (string?)d!["drive"]));
        Assert.Equal("Adatok", (string?)disks[1]!["label"]);
        Assert.Equal("NTFS", (string?)disks[1]!["file_system"]);
        Assert.Equal(1024.0, (double)disks[1]!["size_gb"]!);
        Assert.Equal(900.0, (double)disks[1]!["free_gb"]!);
        var nics = (JsonArray)r["nics"]!;
        Assert.Equal(2, nics.Count);
        Assert.Equal("fe80::abcd, 10.10.5.21", (string?)nics[1]!["ip"]);
        Assert.True((bool)nics[1]!["dhcp"]!);
        Assert.Equal("10.10.0.11, 10.10.0.12", (string?)nics[1]!["dns"]);
        Assert.Equal("", (string?)nics[0]!["gateway"]);
        Assert.False((bool)nics[0]!["dhcp"]!);
        var hf = (JsonArray)r["hotfixes"]!;
        Assert.Equal("KB5044285", (string?)hf[0]!["id"]);
        Assert.Equal("2026-10-15", (string?)hf[0]!["installed_on"]);
        Assert.Equal("NT AUTHORITY\\SYSTEM", (string?)hf[0]!["installed_by"]);
        Assert.Null(hf[1]!["installed_on"]);                         // unparseable WMI date -> null, not a crash
    }

    [PwshFact]
    public void AppsSectionFiltersAndDedupes()
    {
        var r = Collector.Normalize(RunSection("apps"));
        var apps = (JsonArray)r["apps"]!;
        Assert.Equal(["7-Zip 24.08 (x64)", "Google Chrome", "ÁNYK – Általános Nyomtatványkitöltő"],
                     apps.Select(a => (string)a!["name"]!).Order(StringComparer.Ordinal));
        var anyk = apps.First(a => ((string)a!["name"]!).StartsWith("ÁNYK", StringComparison.Ordinal))!;
        Assert.Equal("x86", (string?)anyk["arch"]);
        Assert.Equal("20250102", (string?)anyk["installed"]);
        Assert.Equal("NAV", (string?)anyk["publisher"]);
    }

    [PwshFact]
    public void ServicesAndLocalAdmins()
    {
        var r = Collector.Normalize(RunSection("services", Mocks + "\n" + LocalgroupOk));
        var services = (JsonArray)r["services"]!;
        Assert.Equal(["Spooler", "WinRM"], services.Select(s => (string)s!["name"]!).Order(StringComparer.Ordinal));
        Assert.Equal("Nyomtatásisor-kezelő", (string?)services.First(s => (string?)s!["name"] == "Spooler")!["display_name"]);
        Assert.True(JsonNode.DeepEquals(new JsonArray(
            new JsonObject { ["name"] = "PC01\\Administrator", ["type"] = "User", ["source"] = "Local" },
            new JsonObject { ["name"] = "CONTOSO\\Domain Admins", ["type"] = "Group", ["source"] = "ActiveDirectory" }), r["local_admins"]));
    }

    [PwshFact]
    public void LocalAdminsFallbackToNetLocalgroup()
    {
        var r = Collector.Normalize(RunSection("services", Mocks + "\n" + LocalgroupFallback));
        Assert.Equal(["Administrator", "CONTOSO\\Domain Admins", "CONTOSO\\helpdesk"],
                     ((JsonArray)r["local_admins"]!).Select(a => (string?)a!["name"]));
    }

    [PwshFact]
    public void SingleItemListsStayLists()
    {
        const string oneDisk = """
            function Get-CimInstance { param([Parameter(Position = 0)] $ClassName, $Filter)
              if ($ClassName -eq 'Win32_LogicalDisk') { [pscustomobject]@{ DeviceID = 'C:'; VolumeName = ''; FileSystem = 'NTFS'; Size = 100GB; FreeSpace = 50GB } } }
            """;
        var raw = RunSection("hardware", Mocks + "\n" + oneDisk);
        Assert.Single((JsonArray)raw["disks"]!);
        Assert.Empty((JsonArray)raw["nics"]!);
        Assert.Empty((JsonArray)raw["hotfixes"]!);
    }

    [PwshTheory]
    [MemberData(nameof(Sections))]
    public void ScriptsSurviveMissingWindowsFeatures(string section)
    {
        var raw = RunSection(section, prelude: "");
        Assert.NotEmpty(raw);
        Collector.Normalize(raw);
    }

    /// <summary>Drive <see cref="Collector.WinrmCollect"/> with a runner that executes each section in pwsh (the remote
    /// side of the real driver, without remoting).</summary>
    private sealed class PwshSectionRunner : IPowerShellRunner
    {
        public List<string> Scripts { get; } = [];

        public PowerShellResult Run(string stdin, TimeSpan timeout, long maxOutputBytes)
        {
            var req = (JsonObject)JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(stdin)))!;
            var sections = new JsonObject();
            foreach (var n in (JsonArray)req["order"]!)
            {
                var name = (string)n!;
                var script = (string)req["sections"]![name]!;
                Scripts.Add(script);
                var (code, stdout, err, _) = Pwsh.Run(Mocks + "\n" + LocalgroupOk + "\n" + script);
                var last = stdout.Trim().Split('\n')[^1].Trim();
                sections[name] = new JsonObject { ["out"] = code == 0 ? last : "", ["error"] = code == 0 ? "" : err };
            }
            var resp = new JsonObject { ["open_error"] = null, ["open_code"] = 0, ["sections"] = sections };
            return new PowerShellResult(0, Encoding.ASCII.GetBytes(CollectorTests.Ok(resp)), "");
        }
    }

    [PwshFact]
    public void EndToEndThroughWinrmCollect()
    {
        var runner = new PwshSectionRunner();
        var inv = Collector.WinrmCollect("pc01.contoso.local", new WinRMSettings { User = "CORP\\svc", Password = "pw", Transport = "ntlm" }, runner: runner);
        Assert.Equal(Collector.SectionNames.Count, runner.Scripts.Count);
        Assert.Equal("Latitude 7440", (string?)inv["model"]);
        Assert.Equal(3, ((JsonArray)inv["apps"]!).Count);
        Assert.NotEmpty((JsonArray)inv["local_admins"]!);
        Assert.False(inv.ContainsKey("section_errors"));
        Assert.Equal(Collector.Script("general"), runner.Scripts[0]);
    }

    [PwshFact]
    public void LoaderReadsTheRequestFromStdin()
    {
        // the real loader, the real stdin path: a driver that just echoes a field back
        if (Pwsh.Exe is null) return;
        var runner = new PowerShellProcessRunner(Pwsh.Exe, Collector.LoaderArguments());
        var req = new JsonObject { ["driver"] = "param($r) [Console]::Out.WriteLine('got:' + $r.password)", ["password"] = "p'w\"$x" };
        var res = runner.Run(Convert.ToBase64String(Encoding.UTF8.GetBytes(req.ToJsonString())), TimeSpan.FromSeconds(60), 1 << 20);
        Assert.True(res.ExitCode == 0, res.Stderr);
        Assert.Contains("got:p'w\"$x", Encoding.UTF8.GetString(res.Stdout));
    }
}
