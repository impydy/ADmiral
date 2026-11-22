using System.Diagnostics;
using ADmiral.Core;

namespace ADmiral.Tests;

public sealed class PacTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("admiral-pac-").FullName;

    public void Dispose()
    {
        Pac.ClearCache();
        Directory.Delete(_dir, true);
    }

    private const string Wpad = """
        function FindProxyForURL(url, host) {
          if (dnsDomainIs(host, "intranet.corp")) { return "DIRECT"; }
          if (shExpMatch(url, "*.cdn.example/*") || isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
          if (isPlainHostName(host)) return "DIRECT";
          return "PROXY proxy.corp:3128; DIRECT";
        }
        """;

    private static string? NoDns(string host) => null;

    [Fact]
    public void Pac_file_decides_proxy_per_address()
    {
        var f = Path.Combine(_dir, "wpad.dat");
        File.WriteAllText(f, Wpad);
        var p = Pac.Get(f);
        Assert.Equal(["http://proxy.corp:3128", null], Pac.ProxiesFromResult(p.Find("https://api.msrc.microsoft.com/x", NoDns)));
        Assert.Equal("DIRECT", p.Find("https://app.intranet.corp/a", NoDns));
        Assert.Equal("DIRECT", p.Find("https://x.cdn.example/a", NoDns));
        Assert.Equal("DIRECT", p.Find("http://10.1.2.3/", NoDns));
        Assert.Equal("DIRECT", p.Find("http://server/", NoDns));
        Assert.Same(p, Pac.Get(f));                                       // cached while the file is unchanged
    }

    [Fact]
    public void Pac_errors_are_clear()
    {
        Assert.Throws<PacError>(() => Pac.Get(Path.Combine(_dir, "missing.dat")));
        Assert.Throws<PacError>(() => Pac.Parse("var x = 1;"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { while (true) {} }"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { return \"DIRECT\" "));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host { return 1; }"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { return 'x; }"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { /* never closed "));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { return `x`; }"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL("));
        var p = Pac.Parse("function FindProxyForURL(url, host) { return eval2('x'); }");
        Assert.Throws<PacError>(() => p.Find("http://a/", NoDns));
        p = Pac.Parse("function FindProxyForURL(url, host) { return nothere; }");
        Assert.Throws<PacError>(() => p.Find("http://a/", NoDns));
    }

    [Fact]
    public void Download_uses_the_fetcher_and_reports_errors()
    {
        var calls = new List<string>();
        var text = Pac.LoadPacText("auto", u => { calls.Add(u); return Wpad; });
        Assert.Equal(["http://wpad/wpad.dat"], calls);
        Assert.Equal(Wpad, text);
        Assert.Throws<PacError>(() => Pac.LoadPacText("https://x/proxy.pac", _ => throw new HttpRequestException("boom")));
        Assert.Throws<PacError>(() => Pac.LoadPacText("https://x/proxy.pac", _ => new string(' ', Pac.MaxSourceBytes + 1)));
        Assert.Equal("http://proxy.corp:3128", Pac.ProxyFor("https://pac.test/a.pac", "https://www.cisa.gov/x", _ => Wpad));
    }

    [Fact]
    public void Language_subset_works()
    {
        var p = Pac.Parse("""
            var ignored = 1;
            function helper(h) { var lower = h.toLowerCase(); return lower.substring(0, 3) == "app" ? "yes" : "no"; }
            function FindProxyForURL(url, host) {
              var parts = host.split(".");
              if (parts.length == 3 && parts[0] === "www" && !(url.indexOf("/skip") >= 0)) {
                return "PROXY " + parts[1] + ":" + (8000 + 80) + "; DIRECT";
              } else if (helper(host) == "yes") return 'HTTPS secure:443';
              x = 10 % 3 * 2 - -1;
              if (x != 3 || dnsDomainLevels(host) > 5 || host.charAt(0) == "z") return null;
              if (localHostOrDomainIs(host, "srv.corp") && myIpAddress() != "") return "PROXY local:1";
              if (weekdayRange("MON", "FRI") && timeRange(8, 18)) return "PROXY tz:" + host.replace("q", "Q").length;
              return "DIRECT";
            }
            """);
        Assert.Equal("PROXY example:8080; DIRECT", p.Find("http://www.example.com/a", NoDns));
        Assert.Equal("PROXY tz:15", p.Find("http://www.example.com/skip", NoDns));
        Assert.Equal("HTTPS secure:443", p.Find("http://APP.corp/", NoDns));
        Assert.Equal(["https://secure:443"], Pac.ProxiesFromResult("HTTPS secure:443; SOCKS s:1"));
        Assert.Equal("PROXY local:1", p.Find("http://srv/", NoDns));
        Assert.Equal("PROXY tz:5", p.Find("http://qq.ab/", NoDns));
        Assert.Equal("DIRECT", p.Find("http://zeta.b/", NoDns));                 // return null -> DIRECT
        Assert.Equal([null], Pac.ProxiesFromResult(""));
    }

    [Fact]
    public void Dns_functions_use_the_resolver()
    {
        var p = Pac.Parse("""
            function FindProxyForURL(url, host) {
              if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
              if (isResolvable(host)) return "PROXY " + dnsResolve(host) + ":80";
              return "PROXY fallback:80";
            }
            """);
        string? Fake(string h) => h switch { "lan.corp" => "192.168.4.5", "web.corp" => "172.16.0.1", _ => null };
        Assert.Equal("DIRECT", p.Find("http://lan.corp/", Fake));
        Assert.Equal("PROXY 172.16.0.1:80", p.Find("http://web.corp/", Fake));
        Assert.Equal("PROXY fallback:80", p.Find("http://none.corp/", Fake));
        Assert.Equal("DIRECT", p.Find("http://192.168.1.1/", Fake));
    }

    [Fact]
    public void Recursion_and_runaway_scripts_are_bounded()
    {
        var deep = Pac.Parse("function f(n) { return f(n + 1); } function FindProxyForURL(url, host) { return f(0); }");
        Assert.Contains("recurses", Assert.Throws<PacError>(() => deep.Find("http://a/", NoDns)).Message);

        // exponential fan-out within the depth limit: bounded by the step limit
        var fan = Pac.Parse("""
            function f(n) { if (n > 30) return 1; return f(n + 1) + f(n + 1); }
            function FindProxyForURL(url, host) { return "x" + f(0); }
            """);
        var sw = Stopwatch.StartNew();
        Assert.Throws<PacError>(() => fan.Find("http://a/", NoDns));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15));

        // a string doubling itself: bounded by the string limit
        var grow = Pac.Parse("function g(s, n) { if (n > 30) return s; return g(s + s, n + 1); } function FindProxyForURL(url, host) { return g('ab', 0); }");
        Assert.Contains("string", Assert.Throws<PacError>(() => grow.Find("http://a/", NoDns)).Message);

        // deeply nested source: refused at parse time
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { return " + new string('(', 5000) + "1" + new string(')', 5000) + "; }"));
        Assert.Throws<PacError>(() => Pac.Parse("function FindProxyForURL(url, host) { return " + new string('!', 5000) + "1; }"));

        // a very long operator chain: evaluated (or refused) without crashing the process
        var chain = Pac.Parse("function FindProxyForURL(url, host) { return 'x' " + string.Concat(Enumerable.Repeat("+ 'y' ", 50000)) + "; }");
        try { Assert.StartsWith("xyyy", chain.Find("http://a/", NoDns)); }
        catch (PacError) { }

        Assert.Throws<PacError>(() => Pac.Parse(new string(' ', Pac.MaxSourceBytes + 1)));
    }

    [Fact]
    public void Dns_lookups_per_evaluation_are_capped()
    {
        var body = string.Concat(Enumerable.Range(0, 40).Select(i => $"dnsResolve('h{i}.corp'); dnsResolve('h{i}.corp');\n"));
        var p = Pac.Parse("function FindProxyForURL(url, host) {\n" + body + "return 'DIRECT'; }");
        var lookups = 0;
        Assert.Equal("DIRECT", p.Find("http://a/", h => { lookups++; return null; }));
        Assert.Equal(Pac.MaxDnsLookups, lookups);                           // repeated names are cached, then capped
    }

    [Fact]
    public void ShExpMatch_is_a_plain_wildcard_match()
    {
        var p = Pac.Parse("function FindProxyForURL(url, host) { return shExpMatch(host, '[ab]*') ? 'A' : shExpMatch(host, 'x?z*') ? 'B' : 'C'; }");
        Assert.Equal("C", p.Find("http://a.com/", NoDns));                       // brackets are literal in PAC
        Assert.Equal("B", p.Find("http://xyz.com/", NoDns));
        Assert.Equal("A", Pac.Parse("function FindProxyForURL(url, host) { return shExpMatch(url, '*[ab]*') ? 'A' : 'C'; }")
            .Find("http://h/[ab]", NoDns));
    }

    [Fact]
    public void ShExpMatchFloodFinishesWithinTheTimeout()
    {
        // ~45 KB: a 32 KiB subject and a 24-character pattern, matched over a thousand times (no loops needed)
        var sb = new System.Text.StringBuilder("function FindProxyForURL(url, host) {\n  var s = \"aaaaaaaaaaaaaaaa\";\n");
        for (var i = 0; i < 11; i++) sb.Append("  s = s + s;\n");
        sb.Append("  if (false");
        while (sb.Length < 45 * 1024) sb.Append(" || shExpMatch(s, \"*a*a*a*a*a*a*a*a*a*a*a*b\")");
        sb.Append(") return \"PROXY evil:1\";\n  return \"DIRECT\";\n}\n");
        var pac = Pac.Parse(sb.ToString());
        var watch = Stopwatch.StartNew();
        var exc = Assert.Throws<PacError>(() => pac.Find("http://x/", NoDns));
        Assert.True(watch.Elapsed < Pac.EvalTimeout, $"took {watch.Elapsed}");
        Assert.Contains("too", exc.Message);
        // an oversized pair is refused at once
        var big = Pac.Parse("function FindProxyForURL(url, host) { var s = \"" + new string('a', 60_000) + "\"; "
                            + "return shExpMatch(s, \"" + string.Concat(Enumerable.Repeat("*a", 40)) + "\") ? \"DIRECT\" : \"DIRECT\"; }");
        Assert.Contains("too long", Assert.Throws<PacError>(() => big.Find("http://x/", NoDns)).Message);
        // normal use is unaffected
        Assert.Equal("DIRECT", Pac.Parse(Wpad).Find("https://x.cdn.example/a", NoDns));
    }
}
