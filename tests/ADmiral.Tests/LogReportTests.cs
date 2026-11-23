using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ADmiral.Core;
using Microsoft.Extensions.Logging;

namespace ADmiral.Tests;

[Collection("Diagnostics")]
public class LogReportTests
{
    private const string LogText = """
        2026-11-20 10:00:01 INFO admiral.web: bind as CONTOSO\jdoe to dc01.contoso.com:636 (DC=contoso,DC=com)
        2026-11-20 10:00:02 WARNING admiral.pdq: PC-042 failed: \\fs01\logins$ unreachable; principal host/pc-042.contoso.com@CONTOSO.COM
          File "C:\Users\kovacs.bela\AppData\Local\Programs\ADmiral\_internal\admiral\service.py", line 12, in run
        2026-11-20 10:00:03 INFO admiral.logins: anna.nagy@contoso.com logged on to PC-042$ (CN=Nagy Anna,OU=Budapest,OU=Staff,DC=contoso,DC=com)
        2026-11-20 10:00:04 ERROR impacket.smbconnection: SESSION_SETUP failed on LAPTOP-7 for svc-admiral password=Hunter22

        """;

    private static readonly string[] Names =
        ["contoso", "jdoe", "dc01", "pc-042", "fs01", "kovacs.bela", "anna.nagy", "Nagy Anna", "Budapest", "Staff", "laptop-7", "svc-admiral", "Hunter22"];

    [Fact]
    public void AnonymizerHidesHostsUsersDomainsAndKeepsCodeNames()
    {
        var a = new Anonymizer();
        a.Discover(LogText);
        a.AddHost("PC-042");
        a.AddHost("LAPTOP-7");
        a.AddUser("svc-admiral");
        var output = a.Apply(Diag.Redact(LogText));
        Assert.Empty(LogReport.NamesIn(output, Names));
        // module, logger and file names survive, so the log is still useful
        foreach (var keep in new[] { "admiral.web", "admiral.pdq", "impacket.smbconnection", "service.py", "AppData", "SESSION_SETUP" })
            Assert.Contains(keep, output);
        // same name -> same token everywhere (pc-042, PC-042$, pc-042.contoso.com)
        var tok = a.MakeToken("HOST", "pc-042");
        Assert.Equal(3, Regex.Count(output, Regex.Escape(tok)));
        Assert.Contains(tok + "$", output);
        foreach (var kind in new[] { "HOST-", "USER-", "DOMAIN-", "OU-", "NAME-" })
            Assert.Contains(kind, output);
    }

    [Fact]
    public void NonAsciiNamesAndIpAddressesAreHidden()
    {
        const string text = "bind as CORP\\Ádám failed; Örs logged on; éva.kiss@corp.hu changed a setting; "
                            + "peer 10.1.2.3:8765 and fe80::1ab:2 talk, 10.1.2.3 again; loopback 127.0.0.1; version 1.2.3.4.5\n";
        var a = new Anonymizer();
        a.Discover(text);
        a.AddUser("Örs");
        var output = a.Apply(text);
        foreach (var name in new[] { "Ádám", "Örs", "éva.kiss", "10.1.2.3", "fe80::1ab:2" })
            Assert.DoesNotContain(name, output, StringComparison.OrdinalIgnoreCase);
        var ip = a.MakeToken("IP", "10.1.2.3");
        Assert.Equal(2, Regex.Count(output, Regex.Escape(ip)));       // one pseudonym per address
        Assert.Contains(ip + ":8765", output);
        Assert.Contains("127.0.0.1", output);
        Assert.Contains("1.2.3.4.5", output);                          // a longer dotted number is not an address
        Assert.Contains("08:00:01", a.Apply("at 08:00:01 done"));       // times are not IPv6
        Assert.Contains("[IO.File]::WriteAllText", a.Apply("[IO.File]::WriteAllText"));
    }

    [Fact]
    public void TokensAreKeyedNotPlainHashes()
    {
        Anonymizer a = new(), b = new();
        Assert.NotEqual(a.MakeToken("HOST", "pc1"), b.MakeToken("HOST", "pc1"));
        var plain = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("pc1")))[..8];
        Assert.DoesNotContain(plain, a.MakeToken("HOST", "pc1"));
        var key = new byte[32];
        Assert.Equal(new Anonymizer(key).MakeToken("USER", "Anna"), new Anonymizer(key).MakeToken("USER", "anna"));
    }

    [Fact]
    public void BuiltInNamesAreNotHashed()
    {
        var a = new Anonymizer();
        a.AddUser("Administrator");
        a.AddUser("CORP\\SYSTEM");
        Assert.Equal("Run as Administrator by SYSTEM", a.Apply("Run as Administrator by SYSTEM"));
        a.AddHost("10.0.0.1");                                    // an IP address is not a name
        Assert.Empty(a.Hosts);
    }

    [Theory]
    [InlineData("admiral.log", "admiral.log")]
    [InlineData("admiral.log.1", "admiral.1.log")]
    [InlineData("admiral-debug.log.3", "admiral-debug.3.log")]
    [InlineData("admiral-errors.jsonl", "admiral-errors.jsonl.txt")]
    [InlineData("admiral-errors.jsonl.2", "admiral-errors.jsonl.2.txt")]
    public void OutNames(string name, string expected) => Assert.Equal(expected, LogReport.OutName(name));

    [Fact]
    public void BuildPacksAllLogsAnonymized()
    {
        using var f = new DiagFolder();
        Log.Logger.LogWarning("collect failed on PC-042 as CONTOSO\\jdoe via \\\\fs01\\logins$");
        File.WriteAllText(f.File("admiral.log.1"), LogText);
        // names known only from the settings / the database (no context in the log line) are hidden too
        var settings = new Settings { Mode = "demo" };
        settings.Ldap.User = "CONTOSO\\svc-admiral";
        using var store = new Store(":memory:");
        store.Execute("INSERT INTO computers (guid, name, dns_hostname) VALUES ('g-l7', 'LAPTOP-7', 'laptop-7.contoso.com')");
        store.Execute("INSERT INTO computers (guid, name, dns_hostname, dn) VALUES ('g-x', 'WS-ZETA', NULL, 'CN=WS-ZETA,OU=Desk,DC=contoso,DC=com')");
        Log.Logger.LogError("demo computer {Name} is unreachable", "WS-ZETA");
        var original = File.ReadAllBytes(f.File("admiral.log.1"));

        var r = LogReport.Build(settings, store, f.Path);
        Assert.Matches($"^{LogReport.IdPattern}$", r.Id);
        var outDir = Path.Combine(f.Path, LogReport.OutDir, r.Id);
        Assert.Equal(outDir, r.Folder);
        var files = Directory.GetFiles(outDir).ToDictionary(p => Path.GetFileName(p), p => File.ReadAllText(p));
        Assert.Equal(r.Files.Order(), files.Keys.Order());
        foreach (var n in new[] { "admiral.log", "admiral.1.log", "admiral-errors.jsonl.txt", "error-report.txt", "README.txt" })
            Assert.Contains(n, files.Keys);
        Assert.All(files.Keys, n => Assert.True(n.EndsWith(".log") || n.EndsWith(".txt")));    // file types GitHub accepts
        var text = string.Join("\n", files.Values);
        Assert.Empty(LogReport.NamesIn(text, [.. Names, "WS-ZETA"]));
        Assert.Contains(r.Id, files["README.txt"]);
        // the originals are untouched, and the next package does not swallow the previous one
        Assert.Equal(original, File.ReadAllBytes(f.File("admiral.log.1")));
        var r2 = LogReport.Build(settings, store, f.Path);
        Assert.NotEqual(r.Id, r2.Id);
        Assert.DoesNotContain(r2.Files, n => n.Contains("ADM-"));
        Assert.True(r.Counts["host"] >= 3);
        Assert.True(r.Counts["user"] >= 2);
        Assert.True(r.Counts["domain"] >= 1);
        Assert.StartsWith("https://github.com/impydy/ADmiral/issues/new", r.IssueUrl);
    }

    [Fact]
    public void JsonLinesAreAnonymizedPerString()
    {
        // the error ledger is JSON: "Task`1" is written as Task\u00601 and "Kovács" as Kov\u00E1cs. Neither may be taken
        // for (or hide) a DOMAIN\user
        var line = System.Text.Json.JsonSerializer.Serialize(new
        {
            message = "Logon of CORP\\kovács on pc-77.corp.local failed: \"x\"",
            traceback = "at System.Threading.Tasks.Task`1.InnerInvoke()\r\n   at Func`2.Invoke(Action`1 a)",
        });
        Assert.Contains("\\u0060", line);
        var anon = new Anonymizer();
        LogReport.MapJsonLines(line + "\nnot json CORP\\bela", s => { anon.Discover(s); return s; });
        Assert.DoesNotContain("task", anon.Domains);
        var outp = LogReport.MapJsonLines(line + "\nnot json CORP\\bela", anon.Apply);
        Assert.Contains("Task`1.InnerInvoke", outp);
        Assert.Contains("Func`2.Invoke(Action`1 a)", outp);
        Assert.Empty(LogReport.NamesIn(outp, ["kovács", "bela", "corp"]));
        Assert.NotNull(System.Text.Json.Nodes.JsonNode.Parse(outp.Split('\n')[0]));      // still one JSON object per line
    }

    [Fact]
    public void NewIdShape()
    {
        var ids = Enumerable.Range(0, 50).Select(_ => LogReport.NewId()).ToList();
        Assert.All(ids, id => Assert.Matches($"^{LogReport.IdPattern}$", id));
        Assert.True(ids.Distinct().Count() > 45);
    }
}
