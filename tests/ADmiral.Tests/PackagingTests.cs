using System.Text.RegularExpressions;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>The security-relevant parts of packaging/installer.iss and packaging/build.ps1 (Inno Setup / Windows cannot
/// run here, so the scripts are checked as text; build.ps1 is also parsed by pwsh).</summary>
public sealed class PackagingTests : IDisposable
{
    private readonly CoreTemp _tmp = new();

    public void Dispose() => _tmp.Dispose();

    private static string Iss => File.ReadAllText(Path.Combine(RepoRoot.Path, "packaging", "installer.iss"));

    private static string Proc(string text, string name)
    {
        var m = Regex.Match(text, $@"procedure {name};.*?\nend;", RegexOptions.Singleline);
        Assert.True(m.Success, name);
        return m.Value;
    }

    private static int At(string body, string needle)
    {
        var i = body.IndexOf(needle, StringComparison.Ordinal);
        Assert.True(i >= 0, needle);
        return i;
    }

    [Fact]
    public void DataFolderGetsAFreshDaclNotAMergedOne()
    {
        var p = Proc(Iss, "SecureDataDir");
        // ownership first, then every explicit entry dropped (/reset), then exactly the intended entries
        Assert.True(At(p, "TakeOwn(Dir)") < At(p, "/reset /C /Q"));
        Assert.True(At(p, "/reset /C /Q") < At(p, "/inheritance:r /grant:r"));
        Assert.True(At(p, "/inheritance:r /grant:r") < At(p, @"\*"" /reset /T"));
        Assert.Contains("SaveStringsToUTF8File(DataUsersFile, Users, False)", p);   // the runtime check knows who was granted
        Assert.Contains("admiral-datausers.txt", Iss);
        Assert.Equal("admiral-datausers.txt", DesktopLogic.DataUsersFile);
        // the retry-service account and the earlier entries are granted again on an upgrade
        Assert.Contains(@"Services\{#ServiceName}', 'ObjectName'", Iss);
        Assert.Contains("LoadStringsFromFile(DataUsersFile, Lines)", Iss);
    }

    [Fact]
    public void UpgradeKeepsTheDataPointer()
    {
        var iss = Iss;
        var dataDir = Regex.Match(iss, @"function DataDir\(Param: String\): String;.*?\nend;", RegexOptions.Singleline).Value;
        Assert.True(At(dataDir, "{param:DATADIR|}") < At(dataDir, "ExistingDataDir") && At(dataDir, "ExistingDataDir") < At(dataDir, "DefaultDataDir"));
        var step = Proc(iss.Replace("procedure CurStepChanged(CurStep: TSetupStep);", "procedure CurStepChanged;"), "CurStepChanged");
        Assert.Contains("if (ExpandConstant('{param:DATADIR|}') <> '') or (ExistingDataDir = '') then", step);
        Assert.Single(Regex.Matches(iss, @"SaveStringsToUTF8File\(PointerFile"));
        // the in-program updater never passes /DATADIR=
        Assert.DoesNotContain(AppUpdate.InstallerArguments("S-1-5-21-1-2-3-1001"), a => a.StartsWith("/DATADIR", StringComparison.Ordinal));
    }

    [Fact]
    public void CustomProgramFolderIsProtected()
    {
        var iss = Iss;
        Assert.Contains("[Dirs]", iss);
        var p = Proc(iss, "SecureAppDir");
        Assert.Contains("{commonpf64}", p);
        Assert.True(At(p, "/reset /C /Q") < At(p, "/inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX"));
        Assert.Contains("if CurStep = ssInstall then\n    SecureAppDir;", iss.Replace("\r\n", "\n"));   // before the files are copied
    }

    [Fact]
    public void BuildVerifiesTheWebView2Signature()
    {
        var ps = File.ReadAllText(Path.Combine(RepoRoot.Path, "packaging", "build.ps1"));
        var check = At(ps, "Get-AuthenticodeSignature -FilePath $wv2");
        Assert.True(check < At(ps, "& $iscc"));
        Assert.Contains("$sig.Status -ne 'Valid'", ps);
        Assert.Contains("O=Microsoft Corporation", ps);
    }

    [Fact]
    public void DesktopHostsCheckFoldersBeforeUsingThem()
    {
        // ADmiral.Desktop targets net10.0-windows and is not loaded here: check the order in its source
        var svc = File.ReadAllText(Path.Combine(RepoRoot.Path, "src", "ADmiral.Desktop", "RetryServiceHost.cs"));
        Assert.True(At(svc, "DesktopLogic.ProgramDirProblem(env.ExeDir)") < At(svc, "Shell.SetupLogging("));
        Assert.True(At(svc, "DesktopLogic.SecureDataDir(home, dataUsers:") < At(svc, "Shell.SetupLogging("));
        var app = File.ReadAllText(Path.Combine(RepoRoot.Path, "src", "ADmiral.Desktop", "DesktopApp.cs"));
        Assert.True(At(app, "DesktopLogic.ProgramDirProblem(env.ExeDir)") < At(app, "DesktopLogic.DataDir(env)"));
        Assert.Contains("DesktopLogic.SecureDataDir(home, dataUsers: DataFolderUsers(env.ExeDir))", app);
        var install = File.ReadAllText(Path.Combine(RepoRoot.Path, "src", "ADmiral.Desktop", "WindowsRetryService.cs"));
        Assert.Contains("DesktopLogic.AddDataUser(exeDir, \"*\" + sid.Value)", install);
    }

    [Fact]
    public void InstallerShowsTheGplNoticeNotAnEula()
    {
        // ADmiral is GPL-3.0: an information page (no "I accept"), the full text installed next to the program
        Assert.DoesNotContain("LicenseFile", Iss);
        Assert.Contains("InfoBeforeFile=license-en.txt", Iss);
        Assert.Contains(@"InfoBeforeFile: ""license-hu.txt""", Iss);
        Assert.Contains(@"Source: ""..\LICENSE""; DestDir: ""{app}""; DestName: ""LICENSE.txt""", Iss);
        foreach (var name in new[] { "license-hu.txt", "license-en.txt" })
        {
            var text = File.ReadAllText(Path.Combine(RepoRoot.Path, "packaging", name));
            Assert.Contains("GNU General Public License", text);
            Assert.Contains("https://github.com/impydy/ADmiral", text);
        }
        Assert.Contains("GNU GENERAL PUBLIC LICENSE", File.ReadAllText(Path.Combine(RepoRoot.Path, "LICENSE")));
    }

    [PwshFact]
    public void BuildScriptParses() =>
        PowerShellTests.AssertParses(File.ReadAllText(Path.Combine(RepoRoot.Path, "packaging", "build.ps1")), _tmp);
}
