using System.Text.Json;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>test_ps_windows.py: runs the real inventory scripts against the local machine with Windows PowerShell
/// (Windows only), exactly as they are handed over (-EncodedCommand).</summary>
public class PsWindowsTests
{
    private static JsonObject Run(string section)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var (code, _, err, raw) = Pwsh.Run(Collector.Script(section), exe);
        Assert.True(code == 0, err);
        return Collector.DecodeOutput(raw);
    }

    [WindowsFact]
    public void GeneralSection()
    {
        var r = Collector.Normalize(Run("general"));
        foreach (var key in new[] { "os_caption", "os_version", "os_build", "last_boot", "time_zone", "powershell_version", "manufacturer",
                                    "model", "cpu", "memory_gb", "system_drive", "os_short", "c_size_gb" })
            Assert.False(r[key] is null || r[key]!.ToJsonString() == "\"\"", key);
        Assert.True(r["pending_reboot"] is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False);
    }

    [WindowsTheory]
    [InlineData("hardware", new[] { "disks", "nics", "hotfixes" })]
    [InlineData("apps", new[] { "apps" })]
    [InlineData("services", new[] { "services", "local_admins" })]
    public void ListSections(string section, string[] keys)
    {
        var r = Collector.Normalize(Run(section));
        foreach (var k in keys) Assert.IsType<JsonArray>(r[k]);
        if (section == "services")
            Assert.Contains((JsonArray)r["services"]!, s => (string?)s!["name"] == "WinRM");
        if (section == "hardware")
            Assert.False(string.IsNullOrEmpty((string?)((JsonArray)r["disks"]!)[0]!["drive"]));
    }
}
