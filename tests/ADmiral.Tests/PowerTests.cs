using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Tests;

/// <summary>Restart / shut down / wake on LAN: the message of the reboot / shutdown step, the power tool of Devices
/// (service and web route).</summary>
public sealed class PowerTests : IDisposable
{
    private readonly ServiceFixture _f = new();
    private AdmiralService App => _f.App;

    public void Dispose() => _f.Dispose();

    private static PackageEntry Entry() => new() { Id = "Acme.Kit" };

    // ------------------------------------------------------------------ the step's message
    [Fact]
    public void PowerMessageIsOptionalAndCleaned()
    {
        Assert.Null(Chain.ValidPowerMessage(null));
        Assert.Null(Chain.ValidPowerMessage("  \n "));
        Assert.Equal("Save 'your' work now", Chain.ValidPowerMessage("Save \"your\"\r\nwork\tnow"));
        Assert.Equal("f restart", Chain.ValidPowerMessage("/f restart"));               // never taken for an option
        Assert.Equal("t 0 x", Chain.ValidPowerMessage("-t 0 x\\\\"));                  // no trailing backslash
        Assert.Equal("a b", Chain.ValidPowerMessage("a\u0000\u2028b"));
        Assert.Equal(512, Chain.ValidPowerMessage(new string('x', 512))!.Length);
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidPowerMessage(new string('x', 513)));
        Assert.ThrowsAny<ArgumentException>(() => Chain.ValidPowerMessage("/-/ "));    // nothing left
    }

    [Fact]
    public void RebootAndShutdownStepsKeepTheCleanedMessage()
    {
        var steps = Chain.ValidateSteps(Entry(),
        [
            new PackageStep { Type = "reboot", Seconds = 30, Text = "Update: \"restart\"\nnow" },
            new PackageStep { Type = "shutdown", Text = "   " },
            new PackageStep { Type = "wol", Text = "ignored" },
        ]);
        Assert.Equal("Update: 'restart' now", steps[0].Text);
        Assert.Null(steps[1].Text);                                               // empty: the default "ADmiral"
        Assert.Null(steps[2].Text);                                               // only reboot / shutdown take one
        Assert.Contains("message: Update: 'restart' now", Chain.Describe(steps[0]));
        Assert.DoesNotContain("message", Chain.Describe(steps[1]));
        Assert.ThrowsAny<ArgumentException>(() =>
            Chain.ValidateSteps(Entry(), [new PackageStep { Type = "reboot", Text = new string('x', 600) }]));
    }

    [Fact]
    public void ThePowerScriptNeverCarriesTheText()
    {
        var plain = Chain.PowerScript(true, 30, "r", "o", "t");
        Assert.Contains("$m = 'ADmiral'", plain);
        Assert.Contains("shutdown.exe /r /f /t 30 /d p:4:1 /c $m", plain);
        var file = @"C:\run\admiral-0123456789ab-user.txt";
        var withText = Chain.PowerScript(false, 5, "r", "o", "t", file);
        Assert.Contains("shutdown.exe /s /f /t 15 /d p:4:1 /c $m", withText);    // at least MinPowerDelay
        Assert.Contains($"ReadAllText('{file}'", withText);
        // the message travels as a file: whatever it says, the script text is the same
        Assert.Equal(withText, Chain.PowerScript(false, 5, "r", "o", "t", file));
        Assert.DoesNotContain("ADmiral' 2>&1", withText);
    }

    [PwshTheory]
    [InlineData("x\" /f & calc ; '$(New-Item -ItemType File -Path MARKER)' \n /s -t 0 \\")]
    [InlineData("'; New-Item -ItemType File -Path MARKER; '")]
    [InlineData("`$(New-Item -ItemType File -Path MARKER)`\r\n/f")]
    [InlineData("\"\"\"")]
    public void TheMessageStaysOneArgumentOnTheComputer(string evil)
    {
        var dir = Path.Combine(Path.GetTempPath(), "admiral-pw-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(dir);
        try
        {
            var marker = Path.Combine(dir, "pwned");
            var textFile = Path.Combine(dir, "user.txt");
            // the raw text, not the server-cleaned one: the script itself must keep it a single literal argument
            File.WriteAllText(textFile, evil.Replace("MARKER", marker), new UTF8Encoding(false));
            var outFile = Path.Combine(dir, "out.json");
            var script = Chain.PowerScript(true, 30, Path.Combine(dir, "run.txt"), outFile, Path.Combine(dir, "tmp.json"), textFile);
            // a stand-in for shutdown.exe that reports what it was given
            var stub = "function shutdown.exe { 'N=' + $args.Count; foreach ($a in $args) { 'A<' + $a + '>' }; $global:LASTEXITCODE = 0 }\n";
            var (code, stdout, stderr, _) = Pwsh.Run(stub + script);
            Assert.True(code == 0, stdout + stderr);
            var res = JsonNode.Parse(File.ReadAllText(outFile))!;
            var output = (string)res["output"]!;
            Assert.Equal(0, (int)res["exit"]!);
            Assert.Contains("N=8", output);                                       // /r /f /t 30 /d p:4:1 /c <message>
            var msg = output.Split('\n').Select(l => l.Trim()).Last(l => l.StartsWith("A<", StringComparison.Ordinal));
            Assert.DoesNotContain("\"", msg);
            Assert.False(msg.EndsWith("\\>", StringComparison.Ordinal));
            Assert.False(msg.StartsWith("A</", StringComparison.Ordinal) || msg.StartsWith("A<-", StringComparison.Ordinal));
            Assert.False(File.Exists(marker), "the message text was executed");
        }
        finally
        {
            System.IO.Directory.Delete(dir, true);
        }
    }

    // ------------------------------------------------------------------ the power tool (Devices)
    private List<string> Names(int n) => App.Computers().Take(n).Select(c => (string)c["name"]!).ToList();

    [Fact]
    public void RestartGoesToEveryChosenComputerWithTheCleanedMessage()
    {
        App.LocalNames = ["ADMIN-PC"];
        var sent = new List<(string Host, string Action, int Secs, string? Text)>();
        App.PowerSender = (h, a, s, text) =>
        {
            lock (sent) sent.Add((h, a, s, text));
            return new RemoteRunResult(0, "", "", 0);
        };
        var names = Names(3);
        var done = _f.WaitJob(App.SendPower(names, [], "reboot", 1, "Update \"tonight\"\nsave work").Id);
        Assert.Equal("done", done.Status);
        var res = (Row)done.Result!;
        Assert.Equal(3, res["total"]);
        Assert.Equal(3, res["ok"]);
        Assert.Equal(3, sent.Count);
        Assert.All(sent, s => Assert.Equal(("reboot", Chain.MinPowerDelay, "Update 'tonight' save work"), (s.Action, s.Secs, s.Text)));
        Assert.Contains(App.Store.Activity(), a => (string?)a["action"] == "power");

        sent.Clear();
        _f.WaitJob(App.SendPower(names.Take(1).ToList(), [], "shutdown", 99999).Id);
        Assert.Equal(("shutdown", 3600, (string?)null), (sent[0].Action, sent[0].Secs, sent[0].Text));
    }

    [Fact]
    public void PowerRefusesBadInputAndThisComputer()
    {
        App.PowerSender = (_, _, _, _) => throw new InvalidOperationException("must not run");
        var names = Names(2);
        Assert.ThrowsAny<ArgumentException>(() => App.SendPower(names, [], "format"));
        Assert.ThrowsAny<ArgumentException>(() => App.SendPower([], [], "reboot"));
        Assert.ThrowsAny<ArgumentException>(() => App.SendPower(names, [], "reboot", 30, new string('x', 600)));
        // the computer ADmiral runs on: never restarted / shut down, also not by its DNS name
        App.LocalNames = [names[1].ToLowerInvariant()];
        var ex = Assert.ThrowsAny<ArgumentException>(() => App.SendPower(names, [], "shutdown"));
        Assert.Contains(names[1], ex.Message);
        var c = App.Computers().First(x => (string)x["name"]! == names[0]);
        App.LocalNames = [((string?)c["dns_hostname"] ?? names[0]).Split('.')[0]];
        Assert.ThrowsAny<ArgumentException>(() => App.SendPower(names, [], "reboot"));
    }

    [Fact]
    public void PowerNeverReachesThisComputerThroughAnAlias()
    {
        App.LocalNames = ["ADMIN-PC"];
        App.LocalAddresses = [System.Net.IPAddress.Parse("10.9.8.7")];
        var names = Names(3);
        var hosts = App.Computers().Where(c => names.Contains((string)c["name"]!))
            .ToDictionary(c => (string)c["name"]!, c => c["dns_hostname"] as string is { Length: > 0 } d ? d : (string)c["name"]!);
        // one name points at this computer's address, one at loopback (a stale record / CNAME), one elsewhere
        App.HostResolver = h => h == hosts[names[0]] ? [System.Net.IPAddress.Parse("10.9.8.7")]
            : h == hosts[names[1]] ? [System.Net.IPAddress.Parse("::ffff:127.0.0.1")] : [System.Net.IPAddress.Parse("10.1.1.1")];
        var sent = new List<string>();
        App.PowerSender = (h, _, _, _) => { lock (sent) sent.Add(h); return new RemoteRunResult(0, "", "", 0); };
        var res = (Row)_f.WaitJob(App.SendPower(names, [], "shutdown", 60).Id).Result!;
        Assert.Equal([hosts[names[2]]], sent);
        var results = (List<Row>)res["results"]!;
        Assert.Equal("failed", results.Single(r => (string)r["name"]! == names[0])["outcome"]);
        Assert.Equal("failed", results.Single(r => (string)r["name"]! == names[1])["outcome"]);
        // the fully qualified name counts as well
        var dns = App.Computers().First(c => (string)c["name"]! == names[2])["dns_hostname"] as string;
        if (dns is { Length: > 0 })
        {
            App.LocalNames = [dns];
            Assert.ThrowsAny<ArgumentException>(() => App.SendPower([names[2]], [], "reboot"));
        }
    }

    [Fact]
    public void PowerDoesNotDependOnTheScanSetting()
    {
        // "scanning disallowed" is about scanning only: restart / shutdown / wake on LAN still reach the computer
        App.LocalNames = [];
        var names = Names(2);
        var guids = App.Computers().Where(c => names.Contains((string)c["name"]!)).Select(c => (string)c["guid"]!).ToList();
        App.SetAllowScan(guids, false);
        var sent = new List<string>();
        App.PowerSender = (h, _, _, _) => { lock (sent) sent.Add(h); return new RemoteRunResult(0, "", "", 0); };
        var res = (Row)_f.WaitJob(App.SendPower(names, [], "reboot", 60).Id).Result!;
        Assert.Equal(2, res["total"]);
        Assert.Equal(2, sent.Count);
    }

    [PwshFact]
    public void ACutMessageNeverEndsInABackslash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "admiral-pw-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(dir);
        try
        {
            var textFile = Path.Combine(dir, "user.txt");
            // longer than the cap, with the cut landing right after a backslash (and spaces / backslashes before it)
            File.WriteAllText(textFile, new string('a', Chain.MaxPowerMessageChars - 4) + "\\ \\\\" + "tail", new UTF8Encoding(false));
            var outFile = Path.Combine(dir, "out.json");
            var script = Chain.PowerScript(true, 30, Path.Combine(dir, "run.txt"), outFile, Path.Combine(dir, "tmp.json"), textFile);
            var stub = "function shutdown.exe { foreach ($a in $args) { 'A<' + $a + '>' }; $global:LASTEXITCODE = 0 }\n";
            var (code, stdout, stderr, _) = Pwsh.Run(stub + script);
            Assert.True(code == 0, stdout + stderr);
            var output = (string)JsonNode.Parse(File.ReadAllText(outFile))!["output"]!;
            var msg = output.Split('\n').Select(l => l.Trim()).Last(l => l.StartsWith("A<", StringComparison.Ordinal));
            Assert.False(msg.EndsWith("\\>", StringComparison.Ordinal), msg);
            Assert.False(msg.EndsWith(" >", StringComparison.Ordinal), msg);
        }
        finally
        {
            System.IO.Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void WakeOnLanSendsTheMagicPacketOnlyToComputersThatAreOff()
    {
        App.LocalNames = [];
        var names = Names(4);
        var up = names[0];
        var hostOf = App.Computers().Where(c => names.Contains((string)c["name"]!))
            .ToDictionary(c => (string)c["name"]!, c => c["dns_hostname"] as string is { Length: > 0 } d ? d : (string)c["name"]!);
        App.ProbeOverride = (h, _, _) => h == hostOf[up] ? new ProbeResult("10.0.0.1", [445]) : ProbeResult.None;
        var packets = new List<(string Host, byte[] Packet)>();
        App.WolSender = (h, p, _) => { lock (packets) packets.Add((h, p)); };
        App.PowerSender = (_, _, _, _) => throw new InvalidOperationException("wake on LAN runs nothing remotely");
        var done = _f.WaitJob(App.SendPower(names, [], "wol", 600, "ignored").Id);
        Assert.Equal("done", done.Status);
        var res = (Row)done.Result!;
        var results = (List<Row>)res["results"]!;
        Assert.Equal("on", results.Single(r => (string)r["name"]! == up)["outcome"]);
        Assert.DoesNotContain(packets, p => p.Host == hostOf[up]);
        Assert.All(packets, p => Assert.Equal(102, p.Packet.Length));
        Assert.Equal(packets.Count, (int)res["ok"]!);
        Assert.Equal(4, (int)res["ok"]! + (int)res["on"]! + (int)res["failed"]!);
    }

    [Fact]
    public void PowerRouteValidatesAndStartsTheJob()
    {
        using var w = new WebFixture();
        var app = w.Fx.App;
        app.LocalNames = [];
        app.PowerSender = (_, _, _, _) => new RemoteRunResult(0, "", "", 0);
        var names = app.Computers().Take(2).Select(c => (string)c["name"]!).ToList();
        Assert.Equal(422, w.Post("/api/power", new { ids = names, action = "format" }).Code());
        Assert.Equal(422, w.Post("/api/power", new { ids = names }).Code());
        Assert.Equal(400, w.Post("/api/power", new { ids = Array.Empty<string>(), action = "reboot" }).Code());
        Assert.Equal(400, w.Post("/api/power", new { ids = names, action = "reboot", text = new string('x', 600) }).Code());
        using var r = w.Post("/api/power", new { ids = names, action = "reboot", seconds = 4294967311L, text = "bye" });
        Assert.Equal(202, r.Code());
        var job = w.WaitJob(WebFixture.Json(r));
        Assert.Equal("done", (string?)job["status"]);
        Assert.Equal(2, (int)job["result"]!["ok"]!);
    }
}
