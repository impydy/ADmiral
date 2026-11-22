using ADmiral.Core;

namespace ADmiral.Tests;

public class WinSecTests
{
    [Theory]
    [InlineData("S-1-5-21-1-2-3-1105", "CORP\\PC01$", "PC01", false, true)]
    [InlineData("S-1-5-21-1-2-3-1105", "CORP\\pc01$", "PC01.corp.local", false, true)]
    [InlineData("S-1-5-21-1-2-3-1106", "CORP\\PC02$", "PC01", false, false)]     // another computer: forgery
    [InlineData("S-1-5-21-1-2-3-1107", "CORP\\jdoe", "PC01", false, false)]      // a user: not for the logon files
    [InlineData("S-1-5-21-1-2-3-1107", "CORP\\jdoe", "PC01", true, true)]        // ...but fine for a logon-script inventory
    [InlineData("S-1-5-18", "NT AUTHORITY\\SYSTEM", "PC01", false, true)]
    [InlineData("S-1-5-32-544", "BUILTIN\\Administrators", "PC01", false, true)]
    [InlineData("", "", "PC01", false, true)]                                   // not Windows / unknown
    public void File_owner_must_match_the_computer(string sid, string name, string computer, bool users, bool ok) =>
        Assert.Equal(ok, WinSec.CheckOwner(sid, name, computer, users) is null);

    private sealed class FakeSecurity((string, string) owner) : IFileSecurity
    {
        public bool Supported => true;
        public IReadOnlyList<string> BroadWriters(string path) => [];
        public bool HardenDir(string path, IEnumerable<string>? extraSids = null) => true;
        public (string Sid, string Name) Owner(string path) => owner;
        public string CurrentUserSid() => "S-1-5-21-1-2-3-1000";
    }

    [Fact]
    public void Check_file_owner_uses_the_security_provider()
    {
        var fake = new FakeSecurity(("S-1-5-21-9-9-9-1200", "CORP\\OTHERPC$"));
        Assert.Equal("written by CORP\\OTHERPC$, not by PC01", WinSec.CheckFileOwner("x", "PC01", false, fake));
    }

    [Fact]
    public void Broad_writers_from_aces()
    {
        Assert.Equal(["Everyone (no DACL)"], WinSec.BroadWritersFromAces(null));
        Assert.Empty(WinSec.BroadWritersFromAces([]));
        List<AceInfo> aces =
        [
            new(0, 0, 0x1200A9, "S-1-5-32-545"),                    // Users: read & execute only
            new(0, 0x3, 0x1301BF, "S-1-5-11"),                      // Authenticated Users: modify
            new(0, 0x8 | 0x3, 0x1F01FF, "S-1-1-0"),                 // Everyone: inherit-only, does not apply here
            new(1, 0, 0x1F01FF, "S-1-5-4"),                         // a deny entry
            new(0, 0, 0x10000000, "S-1-5-21-1-2-3-513"),            // Domain Users: GENERIC_ALL
            new(0, 0, 0x1F01FF, "S-1-5-18"),                        // SYSTEM
            new(0, 0, 0x1F01FF, "S-1-5-11"),                        // a duplicate
        ];
        Assert.Equal(["Authenticated Users", "Domain Users"], WinSec.BroadWritersFromAces(aces));
    }

    [Fact]
    public void Harden_grants_never_include_broad_groups()
    {
        var g = WinSec.HardenGrants("S-1-5-21-1-2-3-1000", ["S-1-1-0", "S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001", ""]);
        Assert.Equal([WinSec.SystemSid, WinSec.AdminsSid, WinSec.OwnerRightsSid, "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001"], g.Select(x => x.Sid));
        Assert.Equal("RX", g[2].Rights);
        Assert.True(WinSec.IsBroad("S-1-5-32-545"));
        Assert.False(WinSec.IsBroad("S-1-5-21-1-2-3-512"));
    }

    [Fact]
    public void No_ops_off_windows()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Empty(WinSec.BroadWriters("/tmp"));
        Assert.True(WinSec.HardenDir("/tmp"));
        Assert.Equal(("", ""), WinSec.Owner("/tmp"));
        Assert.Equal("", WinSec.CurrentUserSid());
        Assert.Null(WinSec.CheckFileOwner("/tmp", "PC01", false));
    }

    [WindowsFact]
    public void Harden_dir_removes_broad_writers()
    {
        var dir = Directory.CreateTempSubdirectory("admiral-acl-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "x");
            Assert.True(WinSec.HardenDir(dir));
            Assert.Empty(WinSec.BroadWriters(dir));
            Assert.NotEqual("", WinSec.Owner(Path.Combine(dir, "a.txt")).Sid);
        }
        finally { Directory.Delete(dir, true); }
    }
}
