using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>updates.py: MSRC reference, security state, proxy / PAC handling, the shared client and the downloads
/// (test_service.py, test_misc.py) - no real internet: fake HTTP handlers only.</summary>
public class UpdatesTests
{
    private static JsonObject Cvrf(params string[] fixedBuilds)
    {
        var rems = new JsonArray();
        foreach (var f in fixedBuilds) rems.Add(new JsonObject { ["FixedBuild"] = f, ["Type"] = "Vendor Fix" });
        rems.Add(new JsonObject { ["Type"] = "Workaround" });
        rems.Add(new JsonObject { ["FixedBuild"] = "not-a-build" });
        return new JsonObject
        {
            ["DocumentTracking"] = new JsonObject { ["InitialReleaseDate"] = "2026-11-10T08:00:00Z" },
            ["Vulnerability"] = new JsonArray(new JsonObject { ["Remediations"] = rems }),
        };
    }

    [Fact]
    public void UpdatesReferenceParsingAndState()
    {
        var oct = Cvrf("10.0.22631.4300", "10.0.14393.7000");
        oct["DocumentTracking"] = new JsonObject { ["InitialReleaseDate"] = "2026-10-13" };
        var docs = new Dictionary<string, JsonNode>
        {
            [$"{Updates.Msrc}/updates"] = new JsonObject
            {
                ["value"] = new JsonArray(
                    new JsonObject { ["ID"] = "2026-Oct", ["InitialReleaseDate"] = "2026-10-13T08:00:00Z", ["CvrfUrl"] = "u/oct" },
                    new JsonObject { ["ID"] = "2026-Nov", ["InitialReleaseDate"] = "2026-11-10T08:00:00Z", ["CvrfUrl"] = "u/nov" }),
            },
            ["u/nov"] = Cvrf("10.0.22631.4460", "10.0.19045.5000"),
            ["u/oct"] = oct,
        };
        var progress = new List<string>();
        var r = Updates.FetchReference(new ProxySettings(), 2, u => docs[u], (_, _, m) => progress.Add(m));
        var b = r.Builds;
        Assert.Equal(["2026-Nov", "2026-Oct"], r.Months);
        Assert.Equal(4460, b["10.0.22631"].Ubr);
        Assert.Equal("2026-Nov", b["10.0.22631"].Month);
        Assert.Equal("2026-11-10", b["10.0.22631"].Released);
        Assert.Equal(7000, b["10.0.14393"].Ubr);
        Assert.Equal("2026-Oct", b["10.0.14393"].Month);                 // only in the older month
        Assert.Equal("OK", progress[^1]);
        var now = new DateTimeOffset(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);
        string St(JsonObject? inv, int g = 0) => Updates.GetSecurityState(inv, b, g, now).State;
        JsonObject Inv(string v, string build) => new() { ["os_version"] = v, ["os_build"] = build };
        Assert.Equal("current", St(Inv("10.0.22631", "22631.4460")));
        Assert.Equal("missing", St(Inv("10.0.22631", "22631.4300")));
        Assert.Equal("pending", St(Inv("10.0.22631", "22631.4300"), 7));   // released 2 days ago
        Assert.Equal("missing", St(Inv("10.0.22631", "22631.4300"), 1));
        Assert.Equal("unknown", St(Inv("10.0.99999", "99999.1")));
        Assert.Equal("unknown", St(Inv("10.0.22631", "22631.")));
        Assert.Equal("unknown", St(null));
        var full = Updates.GetSecurityState(Inv("10.0.22631", "22631.4300"), b, 0, now);
        Assert.Equal("10.0.22631.4300", full.Installed);
        Assert.Equal("10.0.22631.4460", full.Latest);
    }

    [Fact]
    public void EmptyListingAndNoBuildsAreErrors()
    {
        Assert.Throws<InvalidDataException>(() => Updates.FetchReference(new ProxySettings(), 2, _ => new JsonObject { ["value"] = new JsonArray() }));
        Assert.Throws<InvalidDataException>(() => Updates.FetchReference(new ProxySettings(), 1, u => u.EndsWith("/updates")
            ? new JsonObject { ["value"] = new JsonArray(new JsonObject { ["ID"] = "2026-Nov" }) }
            : new JsonObject()));
    }

    [Fact]
    public void ProxyUrlEncodesCredentials()
    {
        Assert.Null(Updates.ProxyUrl(new ProxySettings()));
        Assert.Equal("http://proxy.corp:8080", Updates.ProxyUrl(new ProxySettings { Url = "proxy.corp:8080" }));
        var u = Updates.ProxyUrl(new ProxySettings { Url = "http://proxy.corp:8080", User = "CORP\\bob", Password = "p@ss:w/rd" });
        Assert.Equal("http://CORP%5Cbob:p%40ss%3Aw%2Frd@proxy.corp:8080", u);
    }

    [Fact]
    public void PacFileDecidesProxyPerAddress()
    {
        using var tmp = new CoreTemp();
        var f = tmp.File("wpad.dat");
        File.WriteAllText(f, """
            function FindProxyForURL(url, host) {
              if (dnsDomainIs(host, "intranet.corp")) { return "DIRECT"; }
              if (isPlainHostName(host)) return "DIRECT";
              return "PROXY proxy.corp:3128; DIRECT";
            }
            """);
        var s = new ProxySettings { Pac = f, User = "bob", Password = "pw" };
        Assert.Equal("http://bob:pw@proxy.corp:3128", Updates.ProxyUrl(s, "https://www.cisa.gov/x"));
        Assert.Null(Updates.ProxyUrl(s, "https://app.intranet.corp/"));
        Assert.Equal("http://p:1", Updates.ProxyUrl(new ProxySettings { Url = "p:1", Pac = f }));   // an explicit address wins
        Assert.True(Updates.PacTrusted(s));
        Assert.False(Updates.PacTrusted(new ProxySettings { Pac = "auto" }));
        Assert.False(Updates.PacTrusted(new ProxySettings { Pac = "http://wpad/wpad.dat" }));
        Assert.True(Updates.PacTrusted(new ProxySettings { Pac = "https://cfg.corp/proxy.pac" }));

        // the web proxy object: trusted PAC gets the account, an untrusted one never does
        var trusted = Updates.WebProxyFor(s)!;
        Assert.Equal(new Uri("http://proxy.corp:3128/"), trusted.GetProxy(new Uri("https://www.cisa.gov/x")));
        Assert.True(trusted.IsBypassed(new Uri("https://app.intranet.corp/")));
        Assert.IsType<NetworkCredential>(trusted.Credentials);
        var untrusted = Updates.WebProxyFor(new ProxySettings { Pac = "http://wpad.corp/wpad.dat", User = "bob", Password = "pw" })!;
        Assert.Null(untrusted.Credentials);
    }

    [Fact]
    public void WpadOrHttpPacProxyNeverGetsIntegratedAuthentication()
    {
        // no proxy account: integrated (Kerberos / NTLM) auth only for a proxy from a trusted PAC (local file / https)
        foreach (var pac in new[] { "auto", "AUTO", "http://wpad/wpad.dat", "HTTP://cfg.corp/proxy.pac" })
            Assert.Null(Updates.WebProxyFor(new ProxySettings { Pac = pac })!.Credentials);
        foreach (var pac in new[] { "https://cfg.corp/proxy.pac", @"C:\cfg\proxy.pac", "/etc/proxy.pac" })
            Assert.Same(CredentialCache.DefaultCredentials, Updates.WebProxyFor(new ProxySettings { Pac = pac })!.Credentials);
    }

    [Fact]
    public void ExplicitProxyGetsTheAccountAsCredentialNotInTheUrl()
    {
        var wp = Assert.IsType<WebProxy>(Updates.WebProxyFor(new ProxySettings { Url = "http://u:p@proxy.corp:3128", User = "bob", Password = "pw" }));
        Assert.Equal("http://proxy.corp:3128/", wp.Address!.AbsoluteUri);
        var cred = Assert.IsType<NetworkCredential>(wp.Credentials);
        Assert.Equal("bob", cred.UserName);
        Assert.Equal("pw", cred.Password);
        var fromUrl = Assert.IsType<WebProxy>(Updates.WebProxyFor(new ProxySettings { Url = "http://al%40x:s%3Acret@proxy.corp:3128" }));
        Assert.Equal("al@x", ((NetworkCredential)fromUrl.Credentials!).UserName);
        Assert.Equal("s:cret", ((NetworkCredential)fromUrl.Credentials!).Password);
        var integrated = Assert.IsType<WebProxy>(Updates.WebProxyFor(new ProxySettings { Url = "proxy.corp:3128" }));
        Assert.Same(CredentialCache.DefaultCredentials, integrated.Credentials);
        Assert.Null(Updates.WebProxyFor(new ProxySettings()));                 // the system proxy
    }

    [Fact]
    public void OneSharedClientPerProxySetting()
    {
        var a = Updates.Client(new ProxySettings { Url = "http://proxy.test:1" });
        Assert.Same(a, Updates.Client(new ProxySettings { Url = "http://proxy.test:1" }));
        Assert.NotSame(a, Updates.Client(new ProxySettings { Url = "http://proxy.test:1", User = "u", Password = "x" }));
        Assert.NotSame(a, Updates.Client(new ProxySettings { Url = "http://proxy.test:1" }, direct: true));
        Assert.Same(Updates.Client(null, direct: true), Updates.Client(new ProxySettings(), direct: true));
        using var h = Updates.CreateHandler(new ProxySettings(), direct: true);
        Assert.False(h.UseProxy);
        Assert.Null(h.SslOptions.RemoteCertificateValidationCallback);          // TLS validation is never switched off
    }

    [Fact]
    public void ExplainErrorMentionsProxyAuthentication()
    {
        Assert.Contains("407", Updates.ExplainError(new InvalidOperationException("Tunnel connection failed: 407 Proxy Authentication Required")));
        var text = Updates.ExplainError(new HttpRequestException("x", null, HttpStatusCode.ProxyAuthenticationRequired));
        Assert.Contains(I18n.T("err.proxy_407"), text);
        Assert.DoesNotContain(I18n.T("err.proxy_407"), Updates.ExplainError(new IOException("boom")));
    }

    [Fact]
    public void GetterParsesJsonAndSendsHeaders()
    {
        var fake = new FakeHttp(_ => FakeHttp.Json("﻿{\"a\": 1}"));
        var get = Updates.MakeGetter(new ProxySettings(), headers: new Dictionary<string, string> { ["apiKey"] = "k" }, client: fake.Client());
        Assert.Equal(1, (int)get("https://x.test/")!["a"]!);
        var seen = fake.Requests[0];
        Assert.Equal("k", seen.Headers["apiKey"]);
        Assert.Equal(Updates.UserAgent(), seen.Headers["User-Agent"]);
        Assert.StartsWith("ADmiral/", Updates.UserAgent());
        Assert.Contains("application/json", seen.Headers["Accept"]);
        var refused = new FakeHttp(_ => FakeHttp.Status(HttpStatusCode.ProxyAuthenticationRequired));
        var ex = Assert.Throws<HttpRequestException>(() => Updates.MakeGetter(new ProxySettings(), client: refused.Client())("https://x.test/"));
        Assert.Contains(I18n.T("err.proxy_407"), Updates.ExplainError(ex));
        Assert.Throws<ArgumentException>(() => get("file:///etc/passwd"));
    }

    [Fact]
    public void BrokenPacFileIsAnErrorNotDirect()
    {
        using var tmp = new CoreTemp();
        var fake = new FakeHttp(_ => FakeHttp.Json("{}"));
        var get = Updates.MakeGetter(new ProxySettings { Pac = tmp.File("missing.dat") }, client: fake.Client());
        Assert.Throws<PacError>(() => get("https://x.test/"));
        Assert.Empty(fake.Requests);
    }

    [Fact]
    public async Task ResponsesAreCappedAndTimedOut()
    {
        var big = new FakeHttp(_ => FakeHttp.Bytes(new byte[5000]));
        await Assert.ThrowsAsync<ResponseTooLargeException>(() => Updates.GetBytesAsync(big.Client(), "https://x.test/", 1000, TimeSpan.FromSeconds(5)));
        var chunked = new FakeHttp(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new ChunkedStream(300, 5000)) });
        await Assert.ThrowsAsync<ResponseTooLargeException>(() => Updates.GetBytesAsync(chunked.Client(), "https://x.test/", 1000, TimeSpan.FromSeconds(5)));
        var slow = new SlowHandler();
        using var client = new HttpClient(slow);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Updates.GetBytesAsync(client, "https://x.test/", 1000, TimeSpan.FromMilliseconds(100)));
    }

    private sealed class SlowHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            return FakeHttp.Json("{}");
        }
    }

    [Fact]
    public void DownloaderChecksTheHash()
    {
        using var tmp = new CoreTemp();
        var fake = new FakeHttp(_ => FakeHttp.Bytes("abc"u8.ToArray()));
        var dl = Updates.MakeDownloader(new ProxySettings(), client: fake.Client(), headers: new Dictionary<string, string> { ["X-ADmiral-Count"] = "self" });
        Assert.Equal("abc", File.ReadAllText(dl("https://example.test/f", tmp.File("f"), null)));
        Assert.True(File.Exists(dl("https://example.test/f", tmp.File("g"), Convert.ToHexStringLower(SHA256.HashData("abc"u8)))));
        Assert.Throws<InvalidDataException>(() => dl("https://example.test/f", tmp.File("h"), new string('0', 64)));
        Assert.False(File.Exists(tmp.File("h")));
        Assert.Equal("self", fake.Requests[0].Headers["X-ADmiral-Count"]);
        var capped = Updates.MakeDownloader(new ProxySettings(), client: fake.Client(), maxBytes: 2);
        Assert.Throws<ResponseTooLargeException>(() => capped("https://example.test/f", tmp.File("i"), null));
        Assert.False(File.Exists(tmp.File("i")));
    }

    [Fact]
    public void ParseReleaseKeepsTheNewestRevision()
    {
        var doc = Cvrf("10.0.22631.4460", "10.0.22631.4500", "10.0.22631.12");
        Assert.Equal(4500, Updates.ParseRelease(doc)["10.0.22631"]);
        Assert.Empty(Updates.ParseRelease(new JsonObject()));
        Assert.Empty(Updates.ParseRelease(null));
    }

    [Fact]
    public void SecurityStateSerialisesSnakeCase()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(SecurityState.Unknown);
        Assert.Equal("{\"state\":\"unknown\"}", json);
        Assert.Contains("\"installed\"", System.Text.Json.JsonSerializer.Serialize(new SecurityState("current", "a", "b", "m", "r")));
        _ = Encoding.UTF8;
    }
}
