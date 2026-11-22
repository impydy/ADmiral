#pragma warning disable CA5350, CA5351 // SHA-1 / MD5 only derive deterministic fake data, never security
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ADmiral.Core;

// Fake domain, probe, inventory, deployment and reference data for tests, evaluation and documentation screenshots
// (port of admiral/demo.py). Selected only with mode = "demo"; the shipped app starts in Active Directory mode.
// The data is deterministic (seeded), but not byte-identical to the Python version (other random generator).

/// <summary>A small seeded random generator with the helpers of Python's <c>random.Random</c> that the demo uses.</summary>
internal sealed class DemoRng(int seed)
{
    private readonly Random _r = new(seed);

    public double Next() => _r.NextDouble();

    /// <summary>Inclusive on both ends, like <c>randint</c>.</summary>
    public int Int(int a, int b) => _r.Next(a, b + 1);

    public double Uniform(double a, double b) => a + (b - a) * _r.NextDouble();

    public T Choice<T>(IReadOnlyList<T> items) => items[_r.Next(items.Count)];

    public T Weighted<T>(IReadOnlyList<T> items, IReadOnlyList<double> weights)
    {
        var x = _r.NextDouble() * weights.Sum();
        for (var i = 0; i < items.Count; i++)
        {
            x -= weights[i];
            if (x < 0) return items[i];
        }
        return items[^1];
    }

    public List<T> Sample<T>(IReadOnlyList<T> items, int k)
    {
        var pool = items.ToList();
        var outp = new List<T>(k);
        for (var i = 0; i < k && pool.Count > 0; i++)
        {
            var j = _r.Next(pool.Count);
            outp.Add(pool[j]);
            pool.RemoveAt(j);
        }
        return outp;
    }

    public string Letters(string alphabet, int k) => new([.. Enumerable.Range(0, k).Select(_ => alphabet[_r.Next(alphabet.Length)])]);
}

public static class Demo
{
    public const string Domain = "DC=contoso,DC=local";

    public static readonly IReadOnlyList<string> Groups =
    [
        "CN=Deploy-Office-Pilot,OU=Groups,DC=contoso,DC=local",
        "CN=Deploy-Win11-Upgrade,OU=Groups,DC=contoso,DC=local",
        "CN=GPO-Server-Hardening,OU=Groups,DC=contoso,DC=local",
    ];

    internal static readonly (string Ou, string Prefix, int Count, (string Os, string Ver, double W)[] Oses)[] Layout =
    [
        ("OU=Laptops,OU=Workstations", "LT", 70, [("Windows 11 Enterprise", "10.0 (22631)", 6), ("Windows 11 Enterprise", "10.0 (26100)", 3),
                                                  ("Windows 10 Enterprise", "10.0 (19045)", 2)]),
        ("OU=Desktops,OU=Workstations", "DT", 60, [("Windows 11 Enterprise", "10.0 (22631)", 4), ("Windows 10 Enterprise", "10.0 (19045)", 4),
                                                   ("Windows 10 Pro", "10.0 (19044)", 1)]),
        ("OU=Kiosks,OU=Workstations", "KSK", 14, [("Windows 10 Enterprise LTSC", "10.0 (17763)", 1)]),
        ("OU=App,OU=Servers", "APP", 18, [("Windows Server 2022 Standard", "10.0 (20348)", 3), ("Windows Server 2019 Standard", "10.0 (17763)", 2),
                                          ("Windows Server 2016 Standard", "10.0 (14393)", 1)]),
        ("OU=SQL,OU=Servers", "SQL", 8, [("Windows Server 2022 Datacenter", "10.0 (20348)", 2), ("Windows Server 2019 Datacenter", "10.0 (17763)", 1)]),
        ("OU=File,OU=Servers", "FS", 5, [("Windows Server 2025 Standard", "10.0 (26100)", 1), ("Windows Server 2016 Standard", "10.0 (14393)", 1)]),
        ("OU=Domain Controllers", "DC", 3, [("Windows Server 2022 Datacenter", "10.0 (20348)", 1)]),
        ("OU=Lab", "LAB", 12, [("Windows 11 Pro", "10.0 (22631)", 1), ("Windows Server 2025 Datacenter", "10.0 (26100)", 1)]),
    ];

    /// <summary>sam -> (department, title)</summary>
    public static readonly IReadOnlyDictionary<string, (string Department, string Title)> UserInfo = new Dictionary<string, (string, string)>
    {
        ["kovacs.anna"] = ("Pénzügy", "Könyvelő"), ["nagy.peter"] = ("Fejlesztés", "Szoftverfejlesztő"),
        ["szabo.eszter"] = ("HR", "HR üzletági partner"), ["toth.gabor"] = ("Fejlesztés", "Csapatvezető"),
        ["horvath.zsofia"] = ("Recepció", "Recepciós"), ["varga.balazs"] = ("Raktár", "Raktárvezető"),
        ["kiss.reka"] = ("Pénzügy", "Pénzügyi vezető"), ["molnar.adam"] = ("Üzemeltetés", "Rendszergazda"),
    };

    internal static readonly string[] Users =
        ["kovacs.anna", "nagy.peter", "szabo.eszter", "toth.gabor", "horvath.zsofia", "varga.balazs", "kiss.reka", "molnar.adam"];

    internal static readonly IReadOnlyDictionary<string, string> Display = new Dictionary<string, string>
    {
        ["kovacs.anna"] = "Kovács Anna", ["nagy.peter"] = "Nagy Péter", ["szabo.eszter"] = "Szabó Eszter", ["toth.gabor"] = "Tóth Gábor",
        ["horvath.zsofia"] = "Horváth Zsófia", ["varga.balazs"] = "Varga Balázs", ["kiss.reka"] = "Kiss Réka", ["molnar.adam"] = "Molnár Ádám",
    };

    private static readonly (string Make, string Model, string Family, int Chassis)[] Models =
    [
        ("Dell Inc.", "Latitude 7440", "Latitude", 10), ("Dell Inc.", "OptiPlex 7010", "OptiPlex", 3),
        ("LENOVO", "21AH00BUHV", "ThinkPad T14 Gen 4", 10), ("HP", "HP EliteBook 840 G10", "103C_5336AN HP EliteBook", 10),
        ("HP", "HP ProDesk 600 G6 SFF", "103C_53307F HP ProDesk", 4),
    ];

    private static readonly (string Make, string Model, string Family, int Chassis)[] ServerModels =
        [("VMware, Inc.", "VMware20,1", "", 1), ("Microsoft Corporation", "Virtual Machine", "Virtual Machine", 3)];

    private static readonly (string Name, string Version, string Publisher)[] Apps =
    [
        ("Google Chrome", "131.0.6778.86", "Google LLC"), ("Mozilla Firefox (x64 hu)", "133.0", "Mozilla"),
        ("Microsoft 365 Apps for enterprise - hu-hu", "16.0.18129.20158", "Microsoft Corporation"),
        ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov"), ("Adobe Acrobat Reader (64-bit)", "24.004.20220", "Adobe"),
        ("Notepad++ (64-bit x64)", "8.7.1", "Notepad++ Team"), ("VLC media player", "3.0.21", "VideoLAN"),
        ("Microsoft Teams Meeting Add-in", "1.24.25301", "Microsoft"), ("Zoom Workplace", "6.2.11", "Zoom"),
        ("Cisco Secure Client - AnyConnect VPN", "5.1.4.74", "Cisco Systems, Inc."),
        ("Microsoft Edge", "131.0.2903.70", "Microsoft Corporation"),
        ("Microsoft Visual C++ 2015-2022 Redistributable (x64)", "14.40.33810.0", "Microsoft Corporation"),
        ("ÁNYK – Általános Nyomtatványkitöltő", "3.44.0", "NAV"), ("Java 8 Update 431", "8.0.4310.10", "Oracle"),
    ];

    private static readonly (string Name, string Version, string Publisher)[] ServerApps =
    [
        ("Microsoft SQL Server 2022 (64-bit)", "16.0.4135.4", "Microsoft Corporation"),
        ("VMware Tools", "12.4.5.23787635", "VMware, Inc."), ("Veeam Agent for Microsoft Windows", "6.2.0.121", "Veeam"),
        ("Microsoft Edge", "131.0.2903.70", "Microsoft Corporation"), ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov"),
    ];

    private static readonly Dictionary<string, string[]> AppVersions = new()
    {
        ["Google Chrome"] = ["131.0.6778.86", "131.0.6778.86", "130.0.6723.117", "128.0.6613.138"],
        ["Mozilla Firefox (x64 hu)"] = ["133.0", "133.0", "132.0.2", "128.5.1"],
        ["7-Zip 24.08 (x64)"] = ["24.08", "24.08", "23.01", "22.01"],
    };

    /// <summary>Make the demo directory available to <see cref="DirectoryFactory"/> (idempotent).</summary>
    public static void Register() => DirectoryFactory.DemoFactory ??= () => new DemoDirectory();

    internal static BigInteger Sha1Int(string text) =>
        BigInteger.Parse("0" + Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(text.ToLowerInvariant()))), NumberStyles.HexNumber);

    internal static string Md5Guid(string text) =>
        Guid.ParseExact(Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(text))), "N").ToString();

    private static int Mod(BigInteger h, int m) => (int)(h % m);

    // ------------------------------------------------------------------ probe
    /// <summary>Deterministic fake reachability probe (~14 % offline; servers have RDP + WinRM).</summary>
    public static ProbeResult Probe(string host, IReadOnlyList<int> ports, double timeout = 1.0)
    {
        var h = Sha1Int(host);
        var ip = $"10.{Mod(h >> 8, 4) + 10}.{Mod(h >> 16, 254) + 1}.{Mod(h, 253) + 1}";
        if (Mod(h, 100) < 14) return new ProbeResult(ip, []);
        var wanted = ports.ToHashSet();
        var open = new List<int>();
        open.AddRange(new[] { 135, 445 }.Where(wanted.Contains));
        var lower = host.ToLowerInvariant();
        if (lower.Contains("srv", StringComparison.Ordinal) || lower.StartsWith("app", StringComparison.Ordinal)
            || lower.StartsWith("sql", StringComparison.Ordinal) || lower.StartsWith("fs", StringComparison.Ordinal)
            || lower.StartsWith("dc", StringComparison.Ordinal))
            open.AddRange(new[] { 3389, 5985 }.Where(wanted.Contains));
        else if (Mod(h, 100) < 85)
            open.AddRange(new[] { 5985 }.Where(wanted.Contains));
        if (Mod(h, 7) == 0) open.AddRange(new[] { 5986 }.Where(wanted.Contains));
        return new ProbeResult(ip, [.. open.Distinct().Order()]);
    }

    // ------------------------------------------------------------------ inventory
    private static (string Name, string Version, string Publisher) Vary((string Name, string Version, string Publisher) app, DemoRng rng)
    {
        if (!AppVersions.TryGetValue(app.Name, out var options)) return app;
        var v = rng.Choice(options);
        return (app.Name.StartsWith("7-Zip", StringComparison.Ordinal) ? $"7-Zip {v} (x64)" : app.Name, v, app.Publisher);
    }

    private static string Text(IReadOnlyDictionary<string, object?>? c, string key) =>
        c is not null && c.TryGetValue(key, out var v) && v is string s ? s : "";

    /// <summary>A fake (normalized) inventory of one computer; about one host in 23 fails like an unauthorized WinRM call.</summary>
    public static JsonObject Collect(string host, IReadOnlyDictionary<string, object?>? computer = null)
    {
        var big = Sha1Int(host);
        if (big % 23 == 0) throw new CollectError("WinRMTransportError: 401 Unauthorized (demo)");
        var rng = new DemoRng((int)(big & int.MaxValue));
        var osName = Text(computer, "os") is { Length: > 0 } o ? o : "Windows 11 Enterprise";
        var isServer = osName.Contains("Server", StringComparison.Ordinal);
        var name = Text(computer, "name");
        var (make, model, family, chassis) = rng.Choice(isServer ? ServerModels : Models);
        var now = DateTimeOffset.UtcNow;
        var ver = Text(computer, "os_version") is { Length: > 0 } v ? v : "10.0 (22631)";
        var buildNo = ver.Contains('(') ? ver.Split('(')[^1].TrimEnd(')') : "22631";
        string? release = buildNo switch
        {
            "22631" => "23H2", "26100" => "24H2", "19045" => "22H2", "19044" => "21H2", "20348" => "21H2", "17763" => "1809",
            "14393" => "1607", _ => null,
        };
        var size = (double)(isServer ? rng.Choice([80, 127, 200]) : rng.Choice([237, 476, 953]));
        var free = Math.Round(size * rng.Uniform(0.03, 0.7), 1);
        string? user = isServer || rng.Next() < 0.15 ? null : rng.Choice(Users);
        var mac = string.Join(":", Enumerable.Range(0, 6).Select(_ => rng.Int(0, 255).ToString("X2", CultureInfo.InvariantCulture)));
        var ip = Text(computer, "ip") is { Length: > 0 } i ? i : $"10.10.{rng.Int(1, 254)}.{rng.Int(1, 254)}";

        var hotfixes = new List<JsonObject>();
        var nHot = rng.Int(4, 12);
        for (var k = 0; k < nHot; k++)
            hotfixes.Add(new JsonObject
            {
                ["id"] = $"KB50{rng.Int(30000, 49999)}",
                ["description"] = rng.Choice(["Security Update", "Update", "Security Update"]),
                ["installed_on"] = now.AddDays(-rng.Int(3, 400)).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                ["installed_by"] = "NT AUTHORITY\\SYSTEM",
            });
        hotfixes = [.. hotfixes.OrderByDescending(x => (string)x["installed_on"]!, StringComparer.Ordinal)];

        List<(string Name, string Version, string Publisher)> appsSrc = isServer
            ? [.. ServerApps.Where(a => !a.Name.Contains("SQL Server", StringComparison.Ordinal)
                                         || name.StartsWith("SQL", StringComparison.OrdinalIgnoreCase))]
            : [.. rng.Sample(Apps, rng.Int(7, Apps.Length)).Select(a => Vary(a, rng))];
        var apps = new JsonArray();
        foreach (var (n, av, p) in appsSrc.OrderBy(a => a.Name, StringComparer.Ordinal).ThenBy(a => a.Version, StringComparer.Ordinal))
            apps.Add(new JsonObject
            {
                ["name"] = n, ["version"] = av, ["publisher"] = p,
                ["installed"] = now.AddDays(-rng.Int(5, 700)).ToString("yyyyMMdd", CultureInfo.InvariantCulture),
                ["arch"] = n.Contains("x86", StringComparison.Ordinal) || n.Contains("Java", StringComparison.Ordinal) ? "x86" : "x64",
            });

        var disks = new JsonArray { new JsonObject { ["drive"] = "C:", ["label"] = "", ["file_system"] = "NTFS", ["size_gb"] = size, ["free_gb"] = free } };
        if (isServer)
            disks.Add(new JsonObject
            {
                ["drive"] = "D:", ["label"] = "Data", ["file_system"] = "NTFS", ["size_gb"] = 500.0, ["free_gb"] = Math.Round(rng.Uniform(40, 400), 1),
            });

        var svcRows = new List<(string, string, string, string, string)>
        {
            ("BITS", "Background Intelligent Transfer Service", "Running", "Auto", "LocalSystem"),
            ("Dnscache", "DNS Client", "Running", "Auto", "NT AUTHORITY\\NetworkService"),
            ("LanmanServer", "Server", "Running", "Auto", "LocalSystem"),
            ("Spooler", "Print Spooler", isServer ? "Stopped" : "Running", isServer ? "Disabled" : "Auto", "LocalSystem"),
            ("WinRM", "Windows Remote Management (WS-Management)", "Running", "Auto", "NT AUTHORITY\\NetworkService"),
            ("wuauserv", "Windows Update", "Running", "Manual", "LocalSystem"),
            ("W32Time", "Windows Time", "Running", "Manual", "NT AUTHORITY\\LocalService"),
        };
        if (name.StartsWith("SQL", StringComparison.Ordinal))
            svcRows.Add(("MSSQLSERVER", "SQL Server (MSSQLSERVER)", "Running", "Auto", "NT Service\\MSSQLSERVER"));
        var services = new JsonArray();
        foreach (var (n, d, s, m, a) in svcRows)
            services.Add(new JsonObject { ["name"] = n, ["display_name"] = d, ["state"] = s, ["start_mode"] = m, ["account"] = a });

        var logons = new JsonArray();
        if (!isServer)
        {
            foreach (var u in rng.Sample(Users, rng.Int(1, 3)))
            {
                var times = rng.Int(2, 9);
                for (var k = 0; k < times; k++)
                    logons.Add(new JsonObject
                    {
                        ["time"] = Db.FormatUtc(now.AddHours(-rng.Int(1, 24 * 60))), ["user"] = u, ["domain"] = "CONTOSO",
                        ["type"] = rng.Choice([2, 2, 2, 7, 10, 11]),
                        ["ip"] = rng.Choice(["", "", $"10.10.{rng.Int(1, 254)}.{rng.Int(1, 254)}"]),
                    });
            }
            logons.Add(new JsonObject { ["time"] = Db.FormatUtc(now), ["user"] = "DWM-1", ["domain"] = "Window Manager", ["type"] = 2, ["ip"] = "" });
        }

        var admins = new JsonArray
        {
            new JsonObject { ["name"] = $"{(name.Length > 0 ? name : "PC")}\\Administrator", ["type"] = "User", ["source"] = "Local" },
            new JsonObject { ["name"] = "CONTOSO\\Domain Admins", ["type"] = "Group", ["source"] = "ActiveDirectory" },
        };
        if (user is not null && rng.Next() < 0.2)
            admins.Add(new JsonObject { ["name"] = $"CONTOSO\\{user}", ["type"] = "User", ["source"] = "ActiveDirectory" });

        var gateway = string.Join(".", ip.Split('.').Take(3).Append("1"));
        var raw = new JsonObject
        {
            ["logons"] = logons,
            ["os_caption"] = $"Microsoft {osName}", ["os_version"] = $"10.0.{buildNo}", ["os_build"] = $"{buildNo}.{rng.Int(1000, 4500)}",
            ["os_display_version"] = release, ["os_service_pack"] = 0, ["os_architecture"] = "64-bit",
            ["os_installed"] = Db.FormatUtc(now.AddDays(-rng.Int(60, 1500))),
            ["os_serial"] = $"00330-{rng.Int(10000, 99999)}-{rng.Int(10000, 99999)}-AA{rng.Int(100, 999)}",
            ["system_drive"] = "C:", ["last_boot"] = Db.FormatUtc(now.AddHours(-rng.Int(1, 24 * 40))),
            ["time_zone"] = "(UTC+01:00) Belgrád, Budapest, Ljubljana, Pozsony, Prága",
            ["powershell_version"] = "5.1." + buildNo + ".1", ["smb1_server"] = rng.Next() < 0.05, ["smb1_client"] = rng.Next() < 0.1,
            ["ie_version"] = !isServer || rng.Next() < .5 ? "11.0." + buildNo + ".0" : null,
            ["pending_reboot"] = rng.Next() < 0.2,
            ["logged_on_user"] = user is null ? null : $"CONTOSO\\{user}",
            ["user_display_name"] = user is null ? null : Display.GetValueOrDefault(user),
            ["domain"] = "contoso.local", ["domain_controller"] = $"DC0{rng.Int(1, 3)}.contoso.local",
            ["ip_address"] = ip, ["mac_address"] = mac,
            ["manufacturer"] = make, ["model"] = model, ["family"] = family.Length > 0 ? family : null,
            ["sku"] = isServer ? null : rng.Int(1000, 9999).ToString(CultureInfo.InvariantCulture), ["product_version"] = isServer ? null : "1.0",
            ["serial"] = rng.Letters("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", 8),
            ["bios_version"] = $"{rng.Int(1, 2)}.{rng.Int(1, 30)}.{rng.Int(0, 9)}",
            ["bios_manufacturer"] = isServer ? "Phoenix Technologies LTD" : make,
            ["bios_asset_tag"] = isServer ? null : $"IT-{rng.Int(1000, 9999)}",
            ["chassis_type"] = chassis,
            ["cpu"] = isServer ? "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz"
                : rng.Choice(["13th Gen Intel(R) Core(TM) i7-1365U", "13th Gen Intel(R) Core(TM) i5-13500", "AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics"]),
            ["cpu_count"] = isServer ? 2 : 1, ["cpu_cores"] = isServer ? 8 : rng.Choice([6, 10, 12]),
            ["memory_bytes"] = (long)(isServer ? rng.Choice([16, 32, 64]) : rng.Choice([8, 16, 16, 32])) * 1024L * 1024 * 1024,
            ["c_size_gb"] = size, ["c_free_gb"] = free,
            ["disks"] = disks,
            ["nics"] = new JsonArray
            {
                new JsonObject
                {
                    ["name"] = isServer ? "vmxnet3 Ethernet Adapter" : "Intel(R) Ethernet Connection (16) I219-LM",
                    ["mac"] = mac, ["ip"] = ip, ["gateway"] = gateway, ["dns"] = "10.10.0.11, 10.10.0.12", ["dhcp"] = !isServer,
                },
            },
            ["hotfixes"] = new JsonArray([.. hotfixes]), ["apps"] = apps, ["services"] = services, ["local_admins"] = admins,
        };
        return Collector.Normalize(raw);
    }

    // ------------------------------------------------------------------ reference data
    /// <summary>A fake "newest security release" so the monitoring can be shown without internet.</summary>
    public static UpdateReferenceData Reference()
    {
        var rel = DateTimeOffset.UtcNow.AddDays(-20).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var builds = new[] { "10.0.22631", "10.0.26100", "10.0.19045", "10.0.19044", "10.0.20348", "10.0.17763", "10.0.14393" }
            .ToDictionary(k => k, _ => new UpdateRef(2800, "demo", rel));
        return new UpdateReferenceData(builds, ["demo"]);
    }

    /// <summary>The demo CVEs that are on CISA's known-exploited list.</summary>
    public static readonly IReadOnlySet<string> Kev = new HashSet<string> { "CVE-2026-1234", "CVE-2025-0411" };

    /// <summary>Fake CVE data (version ranges) for the demo programs, so the vulnerability view works offline.</summary>
    public static Dictionary<(string Vendor, string Product), List<CveRecord>> Cves()
    {
        static CveRecord Rec(string cve, double score, string endExcl, string summary) =>
            new(cve, "2026-02-10", score, summary, [[null, null, null, endExcl, null]]);
        return new()
        {
            [("google", "chrome")] =
            [
                Rec("CVE-2026-1234", 9.6, "131.0.6778.85", "Use after free in a browser component allows remote code execution."),
                Rec("CVE-2026-0871", 8.8, "131.0.6778.69", "Type confusion in the V8 engine."),
                Rec("CVE-2025-8841", 6.5, "130.0.6723.117", "Insufficient validation of untrusted input."),
            ],
            [("mozilla", "firefox")] =
            [
                Rec("CVE-2025-9120", 7.5, "133.0", "Memory safety bugs fixed in Firefox 133."),
                Rec("CVE-2025-7002", 5.3, "132.0.2", "Information disclosure through a crafted page."),
            ],
            [("7-zip", "7-zip")] = [Rec("CVE-2025-0411", 7.0, "24.09", "Mark-of-the-Web bypass in archive extraction.")],
        };
    }

    // ------------------------------------------------------------------ deployment
    /// <summary>Stands in for the real copy + install (a few seconds per computer, about one in seven fails).
    /// <paramref name="delayScale"/> scales the pauses (0 = none; tests).</summary>
    public static DeployResult Deploy(string host, string localFile, string kind, string args, Action<string, int?> onStep, double delayScale = 1.0)
    {
        void Sleep(double s)
        {
            if (delayScale > 0) Thread.Sleep(TimeSpan.FromSeconds(s * delayScale));
        }
        onStep("connecting", null); Sleep(0.4);
        for (var pct = 0; pct <= 100; pct += 20)
        {
            onStep("copying", pct); Sleep(0.15);
        }
        onStep("starting", null); Sleep(0.3);
        onStep("installing", null); Sleep(1.0);
        onStep("cleanup", null); Sleep(0.3);
        var h = host.Sum(ch => ch) % 7;
        if (h == 0) return new DeployResult(1603, "failed", 1, "", "demo: fatal error during installation");
        return new DeployResult(h == 1 ? 3010 : 0, h == 1 ? "reboot" : "ok", 1, "", "");
    }
}

/// <summary>A deterministic fake domain so ADmiral can be evaluated without a DC. Read-only like the real one.</summary>
public sealed class DemoDirectory : IDirectory
{
    private readonly Lock _lock = new();
    private readonly List<Dictionary<string, object?>> _computers;
    private readonly Dictionary<string, List<string>> _groups;
    private readonly Dictionary<string, string> _groupNames;

    public DemoDirectory(int seed = 42)
    {
        _computers = Generate(seed);
        _groups = Demo.Groups.ToDictionary(g => g.ToLowerInvariant(), _ => new List<string>());
        _groupNames = Demo.Groups.ToDictionary(g => g.ToLowerInvariant(), g => g);
        // one group pre-populated with a few members + a user, like a real messy group
        _groups[Demo.Groups[0].ToLowerInvariant()] =
            [.. _computers.Take(4).Select(c => (string)c["dn"]!), "CN=Jane Admin,OU=Users,DC=contoso,DC=local"];
    }

    /// <summary>The generated computers (tests may remove one to simulate a computer deleted from AD).</summary>
    internal List<Dictionary<string, object?>> Computers => _computers;

    private static List<Dictionary<string, object?>> Generate(int seed)
    {
        var rng = new DemoRng(seed);
        var now = DateTimeOffset.UtcNow;
        var outp = new List<Dictionary<string, object?>>();
        string[] descriptions = ["", "", "", "Pénzügy", "Fejlesztés", "HR", "Recepció", "Raktár"];
        string?[] locations = ["Budapest, Váci út 1. – 3. emelet", "Budapest, Váci út 1. – 5. emelet", "Győr telephely", "Debrecen iroda", null];
        foreach (var (ou, prefix, count, oses) in Demo.Layout)
        {
            for (var i = 1; i <= count; i++)
            {
                var name = prefix == "DC" ? $"DC{i:00}" : $"{prefix}-{i:000}";
                var dn = $"CN={name},{ou},{Demo.Domain}";
                var (osName, osVer, _) = rng.Weighted(oses, [.. oses.Select(o => o.W)]);
                var roll = rng.Next();
                var days = roll < 0.08 ? rng.Int(60, 400) : roll < 0.15 ? rng.Int(15, 44) : rng.Int(0, 13);
                var last = now.AddDays(-days).AddMinutes(-rng.Int(0, 1440));
                var created = now.AddDays(-rng.Int(days + 30, days + 2000));
                var enabled = rng.Next() > 0.04;
                var description = rng.Choice(descriptions);
                var location = prefix is "DC" or "SQL" or "APP" or "FS" ? "Budapest DC – Rack B2" : rng.Choice(locations);
                var memberOf = new List<string>();
                if (prefix is "APP" or "SQL" or "FS") memberOf.Add($"CN=GPO-Server-Hardening,OU=Groups,{Demo.Domain}");
                if (prefix == "LT") memberOf.Add($"CN=BitLocker-Laptops,OU=Groups,{Demo.Domain}");
                memberOf.Sort(StringComparer.Ordinal);
                outp.Add(new Dictionary<string, object?>
                {
                    ["guid"] = Demo.Md5Guid(dn), ["name"] = name, ["dns_hostname"] = $"{name.ToLowerInvariant()}.contoso.local",
                    ["dn"] = dn, ["ou"] = DnUtil.OuPath(dn), ["os"] = osName, ["os_version"] = osVer, ["enabled"] = enabled,
                    ["last_logon"] = Db.FormatUtc(last), ["created"] = Db.FormatUtc(created), ["description"] = description,
                    ["location"] = location, ["member_of"] = memberOf,
                });
            }
        }
        return outp;
    }

    public string Test() => $"Demo domain contoso.local ({_computers.Count} computers)";

    public List<AdOu> ListOus(string? parent = null)
    {
        parent = string.IsNullOrEmpty(parent) ? Demo.Domain : parent;
        var kids = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var c in _computers)
        {
            var dn = DnUtil.ParentDn((string)c["dn"]!);
            while (dn.Length > 0 && DnUtil.IsUnder(dn, Demo.Domain) && DnUtil.NormDn(dn) != DnUtil.NormDn(Demo.Domain))
            {
                if (DnUtil.NormDn(DnUtil.ParentDn(dn)) == DnUtil.NormDn(parent))
                    kids[dn] = DnUtil.SplitDn(dn)[0].Value;
                dn = DnUtil.ParentDn(dn);
            }
        }
        return [.. kids.Select(kv => new AdOu(kv.Key, kv.Value)).OrderBy(o => o.Name.ToLowerInvariant(), StringComparer.Ordinal)];
    }

    public List<Dictionary<string, object?>> FetchComputers(string? baseDn = null)
    {
        // memberOf mirrors the demo groups' member lists, like a real DC would
        Dictionary<string, HashSet<string>> groups;
        lock (_lock)
            groups = _groups.ToDictionary(kv => _groupNames[kv.Key], kv => kv.Value.Select(m => m.ToLowerInvariant()).ToHashSet());
        var outp = new List<Dictionary<string, object?>>();
        foreach (var c in _computers)
        {
            var dn = (string)c["dn"]!;
            if (!string.IsNullOrEmpty(baseDn) && !DnUtil.IsUnder(dn, baseDn)) continue;
            var d = new Dictionary<string, object?>(c);
            var all = new HashSet<string>((List<string>)c["member_of"]!, StringComparer.Ordinal);
            foreach (var (g, ms) in groups)
                if (ms.Contains(dn.ToLowerInvariant())) all.Add(g);
            d["member_of"] = all.OrderBy(x => x.ToLowerInvariant(), StringComparer.Ordinal).ToList();
            outp.Add(d);
        }
        return outp;
    }

    public List<string> GroupMembers(string groupDn)
    {
        lock (_lock)
        {
            if (!_groups.TryGetValue((groupDn ?? "").ToLowerInvariant(), out var members))
                throw new KeyNotFoundException($"Group not found: {groupDn}  (demo groups: {string.Join(", ", Demo.Groups)})");
            return [.. members];
        }
    }

    public Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names)
    {
        var outp = new Dictionary<string, Dictionary<string, object?>>();
        foreach (var n in names)
        {
            var key = n.ToLowerInvariant();
            if (!Demo.Display.TryGetValue(key, out var display)) continue;
            var (dept, title) = Demo.UserInfo.GetValueOrDefault(key, ("", ""));
            var sp = display.IndexOf(' ');
            var first = sp < 0 ? display : display[..sp];
            var last = sp < 0 ? "" : display[(sp + 1)..];
            outp[key] = new Dictionary<string, object?>
            {
                ["guid"] = Demo.Md5Guid(key), ["sam"] = key, ["upn"] = $"{key}@contoso.local", ["display_name"] = display,
                ["given_name"] = last, ["surname"] = first, ["mail"] = $"{key}@contoso.local", ["department"] = dept, ["title"] = title,
                ["company"] = "Contoso Kft.", ["phone"] = "+36 1 555 01" + (10 + key.Length % 80).ToString(CultureInfo.InvariantCulture),
                ["mobile"] = null, ["office"] = "Budapest, Váci út 1.", ["manager"] = "Jane Admin", ["description"] = null, ["enabled"] = true,
                ["last_logon"] = Db.UtcNow(), ["created"] = "2019-03-01T08:00:00+00:00", ["password_set"] = "2026-01-10T09:00:00+00:00",
                ["dn"] = $"CN={display},OU=Users,{Demo.Domain}", ["ou"] = "contoso.local/Users",
                ["member_of"] = new List<string> { $"CN=Domain Users,CN=Users,{Demo.Domain}", $"CN=VPN-Users,OU=Groups,{Demo.Domain}" },
            };
        }
        return outp;
    }

    public List<Dictionary<string, object?>> FetchOuUsers(string? baseDn = null) =>
        [.. FetchUsers(Demo.Display.Keys).Values.Where(r => string.IsNullOrEmpty(baseDn) || DnUtil.IsUnder((string)r["dn"]!, baseDn))];

    // The demo domain has no real privileges; evaluation always "passes" the admin gate.
    public (bool Ok, string Detail) IsAdminAccount(string user) => (true, "demo domain (admin gate not enforced)");

    public Dictionary<string, (bool Ok, string Detail)> OuAdminScope(string user, IEnumerable<string> ouDns) =>
        ouDns.Where(o => !string.IsNullOrEmpty(o)).Distinct().ToDictionary(o => o, _ => (true, "demo domain (admin gate not enforced)"));
}
