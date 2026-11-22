using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// Anonymized copies of the log files, ready to attach to a GitHub issue (port of admiral/logreport.py).
//
// Build() reads the log files of the log folder (admiral.log, admiral-debug.log with its rotated copies,
// admiral-errors.jsonl) and the grouped error report, hides every computer name, user name and domain name in
// them, and writes the result as plain text files to <log folder>/anonymized/ADM-XXXX-XXXX/. The originals are not
// changed.
//
// Anonymization works in two passes over all the text:
//  1. discovery - names are collected from the database (computers, users seen in the logon history), the settings
//     (DC, base DN, accounts, shared folders), this Windows session (computer, user, domain) and from the log text
//     itself: DOMAIN\user, user@domain, \\server\share, C:\Users\<name>, DC=... and the CN= / OU= parts of DNs;
//  2. replacement - every occurrence of a discovered name becomes a stable token such as HOST-3f9a1c0b, USER-...,
//     DOMAIN-... (OU-... / NAME-... inside DNs). The token is an HMAC with a random key that is thrown away: the same
//     name gets the same token within one package, but nobody can compute the token of a guessed name.
// Passwords never reach the log files in the first place (Diag.Redact); it is applied once more.

/// <summary>The result of <see cref="LogReport.Build"/>.</summary>
public sealed record LogPackage(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("folder")] string Folder,
    [property: JsonPropertyName("files")] IReadOnlyList<string> Files,
    [property: JsonPropertyName("counts")] IReadOnlyDictionary<string, int> Counts,
    [property: JsonPropertyName("issue_url")] string IssueUrl);

/// <summary>Collects names, then replaces them in text with stable, keyed-hash tokens.</summary>
public sealed partial class Anonymizer
{
    // built-in or generic names: hashing them would only make the log harder to read
    private static readonly HashSet<string> Keep =
    [
        "administrator", "admin", "guest", "system", "local", "localhost", "krbtgt", "public", "default", "all users",
        "default user", "users", "computers", "domain", "builtin", "nt authority", "network service", "local service",
        "everyone", "authenticated users", "workgroup", "true", "false", "none", "null", "admiral",
    ];

    private static readonly HashSet<string> CodePackages =
    [
        "admiral", "uvicorn", "ldap3", "impacket", "spnego", "winrm", "urllib3", "requests", "asyncio", "fastapi",
        "starlette", "webview", "sqlite3", "concurrent", "logging", "json", "http", "socket", "ssl", "threading",
        "cryptography", "pydantic", "anyio", "h11", "sspilib", "clr", "system",
        // .NET namespaces that show up in stack traces and logger names
        "microsoft", "windows", "kestrel", "xunit", "tomlyn", "sqlitepclraw",
    ];

    private static readonly HashSet<string> FileExts =
    [
        "py", "pyc", "pyd", "dll", "exe", "ps1", "log", "txt", "json", "jsonl", "db", "js", "css", "html", "ini", "toml",
        "zip", "msi", "msu", "cab", "xml", "cfg", "config", "lnk", "bat", "cmd", "1", "2", "3", "cs", "pdb",
    ];

    [GeneratedRegex(@"\b(CN|OU|DC)=((?:\\.|[^,;+""\\\n\r\]\)}>])+)", RegexOptions.IgnoreCase)]
    internal static partial Regex DnPart();

    [GeneratedRegex(@"(?<![\w.+-])([\w.+-]{1,64})@([\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63})+)\b")]
    private static partial Regex Upn();

    [GeneratedRegex(@"(?<![\w.\\/:$-])([\p{L}\p{N}][\p{L}\p{N}.-]{0,63})\\{1,2}([\w.$-]{1,64})(?![\w\\/])")]
    private static partial Regex DomUser();

    [GeneratedRegex(@"(?<![\w\\])\\\\{1,2}([\p{L}\p{N}][\w.-]{0,253})\\")]
    private static partial Regex Unc();

    [GeneratedRegex(@"[\\/](?:Users|Documents and Settings)[\\/]{1,2}([^\\/""'\s:*?<>|]{1,64})", RegexOptions.IgnoreCase)]
    private static partial Regex Profile();

    [GeneratedRegex(@"[\p{L}\p{N}][\w$.-]*")]
    private static partial Regex Token();

    [GeneratedRegex(@"(?:DC=[^,;\s""]+,?\s*)+", RegexOptions.IgnoreCase)]
    private static partial Regex DcRun();

    [GeneratedRegex(@"^(?:[\d.]+|[0-9a-f:]+)\z")]
    private static partial Regex IpLike();

    [GeneratedRegex(@"\.(py|pyc|pyd|dll|exe|ps1|log|txt|json|jsonl|db|js|css|html|ini|toml|zip|msi|cs)\z", RegexOptions.IgnoreCase)]
    private static partial Regex FileName();

    [GeneratedRegex(@"\p{L}")]
    private static partial Regex Letter();

    // IPv4 (not part of a longer dotted number) and IPv6 with "::" or 8 groups; IPAddress.TryParse decides
    [GeneratedRegex(@"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)|(?<![\w:.])(?=[0-9A-Fa-f:]*\d)(?=[0-9A-Fa-f:]*::|(?:[0-9A-Fa-f]{1,4}:){7})[0-9A-Fa-f:]{3,39}(?![\w:])")]
    private static partial Regex IpAddr();

    private readonly byte[] _key;
    public HashSet<string> Hosts { get; } = [];
    public HashSet<string> Users { get; } = [];
    /// <summary>Lower case, DNS ("corp.example.com") or NetBIOS ("CORP").</summary>
    public HashSet<string> Domains { get; } = [];
    /// <summary>kind (HOST, USER, DOMAIN, OU, NAME) -> the (lower-case) names replaced.</summary>
    public Dictionary<string, HashSet<string>> Found { get; } = new()
    {
        ["HOST"] = [], ["USER"] = [], ["DOMAIN"] = [], ["OU"] = [], ["NAME"] = [], ["IP"] = [],
    };

    public Anonymizer(byte[]? key = null) => _key = key ?? RandomNumberGenerator.GetBytes(32);

    // -- names -------------------------------------------------------------------------------
    private static string Clean(object? name)
    {
        var s = (name?.ToString() ?? "").Trim().Trim('.').TrimEnd('$');
        return s.ToLowerInvariant();
    }

    private static bool Ok(string n) => n.Length >= 2 && !Keep.Contains(n) && !n.All(char.IsDigit);

    public void AddDomain(object? name)
    {
        var n = Clean(name);
        if (n.Length == 0 || n is "local" or "localhost" or "workgroup") return;
        Domains.Add(n);
        if (n.Contains('.'))                               // corp.example.com -> NetBIOS guess "corp"
        {
            var first = n.Split('.', 2)[0];
            if (first.Length >= 2) Domains.Add(first);
        }
    }

    public void AddHost(object? name)
    {
        var n = Clean(name);
        var scheme = n.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) n = n[(scheme + 3)..];
        n = n.Split('/', 2)[0].Split(':', 2)[0];
        if (n.Length == 0 || IpLike().IsMatch(n)) return;   // an IP address is not a name
        if (n.Contains('.'))
        {
            var parts = n.Split('.', 2);
            AddDomain(parts[1]);
            n = parts[0];
        }
        if (Ok(n)) Hosts.Add(n);
    }

    public void AddUser(object? name)
    {
        var n = Clean(name);
        var bs = n.LastIndexOf('\\');
        if (bs >= 0)
        {
            AddDomain(n[..bs]);
            n = n[(bs + 1)..];
        }
        var at = n.IndexOf('@');
        if (at >= 0)
        {
            AddDomain(n[(at + 1)..]);
            n = n[..at];
        }
        if (Ok(n)) Users.Add(n);
    }

    public void AddDn(object? dn)
    {
        var labels = DnPart().Matches(dn?.ToString() ?? "")
            .Where(m => m.Groups[1].Value.Equals("DC", StringComparison.OrdinalIgnoreCase)).Select(m => m.Groups[2].Value).ToList();
        if (labels.Count > 0) AddDomain(string.Join(".", labels));
    }

    /// <summary>Find names in free text by their context (DOMAIN\user, user@domain, UNC, DN...).</summary>
    public void Discover(string text)
    {
        foreach (Match m in Upn().Matches(text))
        {
            var user = m.Groups[1].Value;
            var dom = m.Groups[2].Value;
            if (user.Contains('/') || !Letter().IsMatch(dom.Split('.')[^1])) continue;
            AddDomain(dom);
            if (m.Index > 0 && text[m.Index - 1] == '/') AddHost(user);      // Kerberos SPN: host/pc1.corp.local@CORP.LOCAL
            else AddUser(user);
        }
        foreach (Match m in DomUser().Matches(text))
        {
            var user = m.Groups[2].Value;
            if (FileName().IsMatch(user)) continue;
            AddDomain(m.Groups[1].Value);
            AddUser(user);
        }
        foreach (Match m in Unc().Matches(text)) AddHost(m.Groups[1].Value);
        foreach (Match m in Profile().Matches(text)) AddUser(m.Groups[1].Value);
        foreach (Match m in DcRun().Matches(text)) AddDn(m.Value);
    }

    // -- replacement -------------------------------------------------------------------------
    public string MakeToken(string kind, string value)
    {
        var low = value.ToLowerInvariant();
        var digest = Convert.ToHexStringLower(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"{kind}:{low}")))[..8];
        if (!Found.TryGetValue(kind, out var set)) Found[kind] = set = [];
        set.Add(low);
        return $"{kind}-{digest}";
    }

    private string? Word(string word)
    {
        var n = word.ToLowerInvariant();
        var tail = n.EndsWith('$') ? "$" : "";
        n = n.TrimEnd('$');
        if (Hosts.Contains(n)) return MakeToken("HOST", n) + tail;
        if (Users.Contains(n)) return MakeToken("USER", n) + tail;
        if (Domains.Contains(n)) return MakeToken("DOMAIN", n) + tail;
        return null;
    }

    private string Dotted(Match m)
    {
        var tok = m.Value;
        var core = tok.TrimEnd('.');
        var trail = tok[core.Length..];
        if (!core.Contains('.')) return (Word(core) ?? core) + trail;
        var whole = Word(core);                           // dotted user names: kovacs.bela, anna.nagy
        if (whole is not null) return whole + trail;
        var parts = core.Split('.');
        var low = core.ToLowerInvariant();
        // module names (admiral.web, impacket.smb3) and file names (service.py) are never names
        if (CodePackages.Contains(parts[0].ToLowerInvariant()) || FileExts.Contains(parts[^1].ToLowerInvariant())) return tok;
        if (Domains.Contains(low)) return MakeToken("DOMAIN", low) + trail;
        for (var i = 1; i < parts.Length; i++)            // the longest known DNS domain suffix wins
        {
            var suffix = string.Join(".", parts[i..]).ToLowerInvariant();
            if (suffix.Contains('.') && Domains.Contains(suffix))
            {
                var host = string.Join(".", parts[..i]);
                var left = host.Contains('.') ? ReplacePieces(parts[..i]) : Word(host) ?? MakeToken("HOST", host);
                return $"{left}.{MakeToken("DOMAIN", suffix)}{trail}";
            }
        }
        return ReplacePieces(parts) + trail;
    }

    private string ReplacePieces(IEnumerable<string> parts) => string.Join(".", parts.Select(p => Word(p) ?? p));

    private string Dn(Match m)
    {
        var key = m.Groups[1].Value;
        var v = m.Groups[2].Value.Trim();
        return key.ToUpperInvariant() switch
        {
            "DC" => $"{key}={Word(v) ?? v}",
            "OU" => $"{key}={MakeToken("OU", v)}",
            _ => $"{key}={Word(v) ?? MakeToken("NAME", v)}",
        };
    }

    /// <summary>An IP address becomes a per-package pseudonym (IP-xxxxxxxx, the same address always the same token);
    /// loopback / unspecified addresses stay readable.</summary>
    private string Ip(Match m)
    {
        if (!System.Net.IPAddress.TryParse(m.Value, out var ip)) return m.Value;
        if (System.Net.IPAddress.IsLoopback(ip) || ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)) return m.Value;
        return MakeToken("IP", ip.ToString());
    }

    public string Apply(string text)
    {
        text = IpAddr().Replace(text, Ip);
        text = DnPart().Replace(text, Dn);
        return Token().Replace(text, Dotted);
    }
}

public static partial class LogReport
{
    public const string RepoIssues = "https://github.com/impydy/ADmiral/issues/new";
    /// <summary>The end of each log file at most.</summary>
    public const int MaxFileBytes = 6 * 1024 * 1024;
    /// <summary>&lt;log folder&gt;/anonymized/&lt;id&gt;/</summary>
    public const string OutDir = "anonymized";
    public const string IdPattern = "ADM-[0-9A-Z]{4}-[0-9A-Z]{4}";

    private const string IdAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public static string NewId()
    {
        var raw = RandomNumberGenerator.GetBytes(5);
        ulong n = 0;
        foreach (var b in raw) n = (n << 8) | b;
        var code = new string([.. Enumerable.Range(0, 8).Select(i => IdAlphabet[(int)((n >> (5 * i)) & 31)])]);
        return $"ADM-{code[..4]}-{code[4..]}";
    }

    private static void DbNames(Store? store, Anonymizer anon)
    {
        if (store is null) return;
        try
        {
            foreach (var r in store.Query("SELECT name, dns_hostname, dn FROM computers"))
            {
                anon.AddHost(r["name"]);
                anon.AddHost(r["dns_hostname"]);
                anon.AddDn(r["dn"]);
            }
        }
        catch (Exception ex)       // a log package must work even with a broken database
        {
            Log.Logger.LogDebug(ex, "log package: computer names unavailable");
        }
        try
        {
            foreach (var r in store.Query("SELECT key, data FROM users"))
            {
                anon.AddUser(r["key"]);
                JsonObject data;
                try
                {
                    data = JsonNode.Parse(r["data"] as string is { Length: > 0 } s ? s : "{}") as JsonObject ?? [];
                }
                catch (JsonException)
                {
                    data = [];
                }
                foreach (var f in new[] { "sAMAccountName", "userPrincipalName", "mail" })
                    if (data[f] is JsonValue v && v.GetValueKind() == JsonValueKind.String && v.GetValue<string>() is { Length: > 0 } u)
                        anon.AddUser(u);
                var dn = data["distinguishedName"] ?? data["dn"];
                if (dn is JsonValue dv && dv.GetValueKind() == JsonValueKind.String) anon.AddDn(dv.GetValue<string>());
            }
        }
        catch (Exception ex)
        {
            Log.Logger.LogDebug(ex, "log package: user names unavailable");
        }
    }

    [GeneratedRegex(@"[\s,;]+")]
    private static partial Regex PeerSep();

    private static void SettingsNames(Settings? s, Anonymizer anon)
    {
        if (s is null) return;
        anon.AddHost(s.Ldap.Server);
        anon.AddDn(s.Ldap.BaseDn);
        foreach (var user in new[] { s.Ldap.User, s.Winrm.User, s.Proxy.User })
            if (!string.IsNullOrEmpty(user)) anon.AddUser(user);
        foreach (var unc in new[] { s.Logins.Path, s.FileCollect.Inbox, s.Packages.Folder })
            anon.Discover(unc ?? "");
        foreach (var p in PeerSep().Split(s.Sync.Peer ?? ""))
            if (p.Length > 0) anon.AddHost(p);
        if (!string.IsNullOrEmpty(s.Proxy.Url)) anon.AddHost(s.Proxy.Url);
    }

    private static void SessionNames(Anonymizer anon)
    {
        var computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
        anon.AddHost(computer);
        anon.AddHost(Environment.MachineName);
        try
        {
            anon.AddHost(System.Net.Dns.GetHostName());
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrEmpty(domain)) anon.AddDomain(domain);
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or NetworkInformationException or PlatformNotSupportedException)
        {
        }
        foreach (var v in new[] { Environment.GetEnvironmentVariable("USERDNSDOMAIN"), Environment.GetEnvironmentVariable("USERDOMAIN") })
            if (!string.IsNullOrEmpty(v) && !v.Equals(computer ?? "", StringComparison.OrdinalIgnoreCase)
                && !v.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                anon.AddDomain(v);
        anon.AddUser(Environment.UserName);
        anon.AddUser(Environment.GetEnvironmentVariable("USERNAME"));
    }

    private static string TailText(string path, int limit = MaxFileBytes)
    {
        var (text, size) = Diag.Tail(path, limit);
        if (size > limit && text.Contains('\n'))
            text = "[... beginning cut ...]\n" + text[(text.IndexOf('\n') + 1)..];
        return text;
    }

    private static List<string> LogFilePaths(string folder)
    {
        var outList = new List<string>();
        foreach (var name in Diag.LogFiles)
            foreach (var p in new[] { Path.Combine(folder, name) }.Concat(Enumerable.Range(1, 5).Select(i => Path.Combine(folder, $"{name}.{i}"))))
                if (File.Exists(p)) outList.Add(p);
        return outList;
    }

    /// <summary>admiral-debug.log.1 -> admiral-debug.1.log, admiral-errors.jsonl -> admiral-errors.jsonl.txt.</summary>
    public static string OutName(string name)
    {
        var dot = name.LastIndexOf('.');
        string b = name, num = "";
        if (dot >= 0 && name[(dot + 1)..] is { Length: > 0 } last && last.All(char.IsDigit))
        {
            b = name[..dot];
            num = last;
        }
        if (b.EndsWith(".log", StringComparison.Ordinal))
            return num.Length > 0 ? $"{b[..^4]}.{num}.log" : b;
        return num.Length > 0 ? $"{b}.{num}.txt" : $"{b}.txt";
    }

    /// <summary>Write anonymized copies of the logs of <paramref name="folder"/> (default: the installed log folder).
    /// Names known from <paramref name="settings"/> and <paramref name="store"/> are hidden too.</summary>
    public static LogPackage Build(Settings? settings = null, Store? store = null, string? folder = null)
    {
        folder ??= Diag.InstalledFolder ?? ".";
        var reportId = NewId();
        var texts = new Dictionary<string, string>();
        foreach (var p in LogFilePaths(folder)) texts[OutName(Path.GetFileName(p))] = Diag.Redact(TailText(p));
        texts["error-report.txt"] = Diag.Redact(Diag.Report(folder));

        var anon = new Anonymizer();
        SettingsNames(settings, anon);
        DbNames(store, anon);
        SessionNames(anon);
        foreach (var t in texts.Values) anon.Discover(t);
        var outFiles = texts.ToDictionary(kv => kv.Key, kv => anon.Apply(kv.Value));
        var counts = anon.Found.Where(kv => kv.Value.Count > 0).ToDictionary(kv => kv.Key.ToLowerInvariant(), kv => kv.Value.Count);

        var info = new[]
        {
            $"ADmiral log package {reportId}", $"Created: {Db.UtcNow()}", $"Program: {Diag.DescribeEnvironment()}", "",
            "Computer, user and domain names are replaced by keyed hashes (HOST-, USER-, DOMAIN-, OU-, NAME-",
            "tokens). The same name has the same token in every file of this package; the key was discarded.",
            "Replaced: " + (counts.Count > 0 ? string.Join(", ", counts.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Value} {kv.Key}")) : "nothing"),
            "",
            "Files: " + string.Join(", ", outFiles.Keys.Order(StringComparer.Ordinal)),
        };
        outFiles["README.txt"] = anon.Apply(Diag.Redact(string.Join("\n", info) + "\n"));

        var target = Path.Combine(folder, OutDir, reportId);
        if (Directory.Exists(target)) throw new IOException($"{target} already exists");
        Directory.CreateDirectory(target);
        foreach (var (name, text) in outFiles)
            File.WriteAllText(Path.Combine(target, name), text, new UTF8Encoding(false));
        if (Log.Logger.IsEnabled(LogLevel.Information))
            Log.Logger.LogInformation("Anonymized log package {Id} written ({Count} files)", reportId, outFiles.Count);
        return new LogPackage(reportId, target, [.. outFiles.Keys.Order(StringComparer.Ordinal)], counts, RepoIssues);
    }

    /// <summary>The given names that still occur in <paramref name="text"/> (case-insensitive, whole words).</summary>
    public static List<string> NamesIn(string text, IEnumerable<string> names) =>
        [.. names.Where(n => Regex.IsMatch(text, $@"(?<![\w-]){Regex.Escape(n)}(?![\w-])", RegexOptions.IgnoreCase))];
}
