using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>The Send message tool (Devices) and the sync firewall rule.</summary>
public sealed class MessageFirewallTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    [Fact]
    public void FirewallScriptIsTheMinimalRule()
    {
        var s = Firewall.RuleScript(8766, "10.1.2.0/24", @"C:\Program Files\ADmiral\ADmiral.exe");
        Assert.Contains("-Direction Inbound -Action Allow -Protocol TCP -LocalPort 8766 -Profile Domain,Private", s);
        Assert.Contains("-RemoteAddress '10.1.2.0/24'", s);
        Assert.Contains(@"-Program 'C:\Program Files\ADmiral\ADmiral.exe'", s);
        Assert.Contains("Remove-NetFirewallRule", s);                   // run again: replaced, not duplicated
        Assert.DoesNotContain("Public", s);
        Assert.DoesNotContain("-Program", Firewall.RuleScript(8766, null, null));
        Assert.Contains(@"-Program 'C:\it''s\ADmiral.exe'", Firewall.RuleScript(1, null, @"C:\it's\ADmiral.exe"));
        Assert.ThrowsAny<ArgumentException>(() => Firewall.RuleScript(0, null, null));
        Assert.ThrowsAny<ArgumentException>(() => Firewall.RuleScript(70000, null, null));
        Assert.ThrowsAny<ArgumentException>(() => Firewall.RuleScript(8766, "10.0.0.0/24'; Remove-Item C:\\ -Recurse; '", null));
    }

    [PwshFact]
    public void FirewallScriptParses()
    {
        var code = Firewall.RuleScript(8766, "10.1.2.0/24", @"C:\it's\ADmiral.exe");
        var (exit, stdout, stderr, _) = Pwsh.Run(
            "$e=$null;[void][System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(code)) + "')),[ref]$null,[ref]$e); if($e){$e|%{$_.Message};exit 1}");
        Assert.True(exit == 0, stdout + stderr);
    }

    [Fact]
    public void FirewallApplyUsesTheSyncSettings()
    {
        App.Settings.Sync.Port = 9100;
        App.Settings.Sync.Network = "192.168.5.0/24";
        string? ran = null;
        App.FirewallRunner = s => { ran = s; return "ok"; };
        var r = App.FirewallApply();
        Assert.Equal(true, r["ok"]);
        Assert.Contains("-LocalPort 9100", ran);
        Assert.Contains("-RemoteAddress '192.168.5.0/24'", ran);
        Assert.Equal("ADmiral-Firewall.ps1", App.FirewallScript()["filename"]);
    }

    [Fact]
    public void MessageGoesToEveryChosenComputer()
    {
        App.FullScan();
        var comps = App.Computers();
        var shown = new List<(string Host, string Text, int Secs)>();
        App.MessageSender = (h, text, secs) =>
        {
            lock (shown) shown.Add((h, text, secs));
            return h.StartsWith("app-001", StringComparison.OrdinalIgnoreCase)
                ? new RemoteRunResult(0, "", "No user is logged on: the message was not shown", 0)
                : new RemoteRunResult(0, "", "Shown in 1 session(s)", 0);
        };
        var names = comps.Take(3).Select(c => (string)c["name"]!).ToList();
        var job = App.SendMessage(names, [], "Restart \"tonight\"\nsave work", 1);
        var done = _f.WaitJob(job.Id);
        Assert.Equal("done", done.Status);
        var res = (Row)done.Result!;
        Assert.Equal(3, res["total"]);
        Assert.Equal(3, shown.Count);
        Assert.All(shown, s => Assert.Equal("Restart 'tonight' save work", s.Text));
        Assert.All(shown, s => Assert.Equal(10, s.Secs));                // at least 10 s on screen
        Assert.Contains(App.Store.Activity(), a => (string?)a["action"] == "message");
        Assert.ThrowsAny<ArgumentException>(() => App.SendMessage([], [], "hi"));
        Assert.ThrowsAny<ArgumentException>(() => App.SendMessage(names, [], "   "));
    }
}
