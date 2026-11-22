using System.Net;
using System.Net.Sockets;
using System.Text;
using ADmiral.Core;
using ADmiral.Web;

namespace ADmiral.Tests;

/// <summary>Attacks on the local API: token, CSRF header, Host header (DNS rebinding), cross-origin requests, body size
/// and depth limits, path traversal, and the security headers on every answer.</summary>
public sealed class WebSecurityTests : IDisposable
{
    private readonly CoreTemp _tmp = new();
    private readonly WebFixture W;

    public WebSecurityTests()
    {
        // a UI folder with a secret next to it: nothing outside the folder may be served
        var www = Directory.CreateDirectory(_tmp.File("www")).FullName;
        File.WriteAllText(Path.Combine(www, "index.html"), "<html>ADmiral test</html>");
        File.WriteAllText(Path.Combine(www, "app.js"), "// js");
        File.WriteAllText(_tmp.File("secret.txt"), "TOP-SECRET");
        W = new WebFixture(configure: o =>
        {
            o.StaticRoot = www;
            o.MaxBodyBytes = 4096;
        });
    }

    public void Dispose()
    {
        W.Dispose();
        _tmp.Dispose();
    }

    private HttpResponseMessage Send(HttpMethod method, string path, Action<HttpRequestMessage>? setup = null, HttpContent? content = null)
    {
        var req = new HttpRequestMessage(method, path) { Content = content };
        setup?.Invoke(req);
        return W.Raw.Send(req);
    }

    private static void Auth(HttpRequestMessage r)
    {
        r.Headers.Add("X-ADmiral", "1");
        r.Headers.Add("X-ADmiral-Token", WebFixture.Token);
    }

    private static void AssertSecurityHeaders(HttpResponseMessage r)
    {
        foreach (var (k, v) in WebApp.SecurityHeaders)
            Assert.True(r.Headers.TryGetValues(k, out var got) && got.Single() == v, $"{k} missing on {(int)r.StatusCode}");
    }

    // ---------------------------------------------------------------- token
    [Fact]
    public void Missing_or_wrong_token_is_refused()
    {
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status").Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status", r => r.Headers.Add("X-ADmiral-Token", "wrong")).Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status", r => r.Headers.Add("X-ADmiral-Token", WebFixture.Token + "x")).Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status", r => r.Headers.Add("X-ADmiral-Token", "")).Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status?token=" + WebFixture.Token).Code());          // only the header counts
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status", r => r.Headers.TryAddWithoutValidation("X-ADmiral-Token", [WebFixture.Token, WebFixture.Token])).Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/api/status", r => r.Headers.Add("Cookie", "admiral-token=" + WebFixture.Token)).Code());
        Assert.Equal(200, Send(HttpMethod.Get, "/api/status", Auth).Code());
        Assert.Equal("Invalid session token", WebFixture.Detail(Send(HttpMethod.Get, "/api/summary")));
    }

    [Fact]
    public void Path_case_does_not_bypass_the_checks()
    {
        Assert.Equal(401, Send(HttpMethod.Get, "/API/status").Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/Api/Computers").Code());
        Assert.Equal(403, Send(HttpMethod.Post, "/API/tags", r => r.Headers.Add("X-ADmiral-Token", WebFixture.Token),
                               WebFixture.JsonContent(new { ids = new[] { "LT-001" }, add = new[] { "x" } })).Code());
        Assert.Equal(401, Send(HttpMethod.Get, "/nothing-here").Code());       // not public: no token, no answer
    }

    [Fact]
    public void Page_and_static_files_need_no_token()
    {
        using var index = Send(HttpMethod.Get, "/");
        Assert.Equal(200, index.Code());
        Assert.Contains("ADmiral test", WebFixture.Text(index));
        Assert.Equal(200, Send(HttpMethod.Get, "/static/app.js").Code());
        Assert.Equal(404, Send(HttpMethod.Get, "/static/missing.js").Code());
    }

    [Fact]
    public void Token_check_is_exact()
    {
        var state = new WebApp.State(W.App, new WebAppOptions(), System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("abc")));
        Assert.True(WebApp.TokenMatches(state, "abc"));
        Assert.False(WebApp.TokenMatches(state, "abd"));
        Assert.False(WebApp.TokenMatches(state, "ab"));
        Assert.False(WebApp.TokenMatches(state, ""));
        Assert.False(WebApp.TokenMatches(state, null));
    }

    // ---------------------------------------------------------------- CSRF / cross origin
    [Fact]
    public void Missing_csrf_header_is_refused_for_every_changing_method()
    {
        void NoCsrf(HttpRequestMessage r) => r.Headers.Add("X-ADmiral-Token", WebFixture.Token);
        var body = WebFixture.JsonContent(new { ids = new[] { "LT-001" }, add = new[] { "x" } });
        using var post = Send(HttpMethod.Post, "/api/tags", NoCsrf, body);
        Assert.Equal(403, post.Code());
        Assert.Equal("Missing x-admiral header", WebFixture.Detail(post));
        Assert.Equal(403, Send(HttpMethod.Put, "/api/settings", NoCsrf, WebFixture.JsonContent(new { theme = "dark" })).Code());
        Assert.Equal(403, Send(HttpMethod.Delete, "/api/fleets/1", NoCsrf).Code());
        Assert.Equal(403, Send(HttpMethod.Post, "/api/tags", r => { NoCsrf(r); r.Headers.Add("X-ADmiral", "true"); }, body).Code());
        Assert.Empty(W.App.Store.AllTags());                                   // nothing happened
    }

    [Fact]
    public void Cross_origin_requests_are_refused()
    {
        Assert.Equal(403, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Add("Origin", "http://evil.example"); }).Code());
        Assert.Equal(403, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Add("Origin", "null"); }).Code());
        Assert.Equal(403, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Add("Origin", $"http://localhost:{W.Base.Port + 1}"); }).Code());
        Assert.Equal(403, Send(HttpMethod.Post, "/api/tags", r => { Auth(r); r.Headers.Add("Sec-Fetch-Site", "cross-site"); },
                               WebFixture.JsonContent(new { ids = new[] { "LT-001" }, add = new[] { "x" } })).Code());
        Assert.Equal(403, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Add("Sec-Fetch-Site", "same-site"); }).Code());
        // the page's own requests
        Assert.Equal(200, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Add("Origin", $"http://{W.Base.Authority}"); r.Headers.Add("Sec-Fetch-Site", "same-origin"); }).Code());
    }

    [Fact]
    public void Cors_preflight_is_never_approved()
    {
        using var r = Send(HttpMethod.Options, "/api/tags", r =>
        {
            r.Headers.Add("Origin", "http://evil.example");
            r.Headers.Add("Access-Control-Request-Method", "POST");
            r.Headers.Add("Access-Control-Request-Headers", "x-admiral,x-admiral-token");
        });
        Assert.False(r.IsSuccessStatusCode && r.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(r.Headers.Contains("Access-Control-Allow-Origin"));
        AssertSecurityHeaders(r);
    }

    // ---------------------------------------------------------------- Host header
    [Fact]
    public void Wrong_host_header_is_refused()
    {
        using var evil = Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = "evil.example"; });
        Assert.Equal(400, evil.Code());
        AssertSecurityHeaders(evil);
        Assert.Equal(400, Send(HttpMethod.Get, "/", r => r.Headers.Host = $"evil.example:{W.Base.Port}").Code());
        Assert.Equal(400, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = $"localhost:{W.Base.Port + 1}"; }).Code());
        Assert.Equal(400, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = "127.0.0.1.nip.io"; }).Code());
        Assert.Equal(200, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = $"localhost:{W.Base.Port}"; }).Code());
        Assert.Equal(200, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = $"127.0.0.1:{W.Base.Port}"; }).Code());
        Assert.Equal(200, Send(HttpMethod.Get, "/api/status", r => { Auth(r); r.Headers.Host = $"[::1]:{W.Base.Port}"; }).Code());
    }

    [Fact]
    public void Listens_on_loopback_only_unless_allowed()
    {
        Assert.True(IPAddress.IsLoopback(IPAddress.Parse(W.Base.Host)));
        Assert.Throws<ArgumentException>(() => WebApp.Create(W.App, new WebAppOptions { Token = "t", Host = "0.0.0.0" }));
        Assert.Throws<ArgumentException>(() => WebApp.Create(W.App, new WebAppOptions { Token = "", Host = "127.0.0.1" }));
    }

    // ---------------------------------------------------------------- bodies
    [Fact]
    public void Oversized_bodies_are_refused()
    {
        var big = new string('a', 10_000);
        using var r = Send(HttpMethod.Put, "/api/settings", Auth, WebFixture.JsonContent(new { theme = big }));
        Assert.Equal(413, r.Code());
        AssertSecurityHeaders(r);
        // chunked (no Content-Length): counted while reading
        var chunked = new StreamContent(new MemoryStream(Encoding.ASCII.GetBytes("{\"ids\":[\"" + big + "\"]}")));
        chunked.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        using var r2 = Send(HttpMethod.Post, "/api/tags", r => { Auth(r); r.Headers.TransferEncodingChunked = true; }, chunked);
        Assert.Equal(413, r2.Code());
    }

    [Fact]
    public void Deep_or_malformed_json_is_refused()
    {
        var deep = new string('[', 200) + new string(']', 200);
        using var r = Send(HttpMethod.Post, "/api/fleets/preview", Auth, WebFixture.JsonContent("{\"conditions\":" + deep + "}"));
        Assert.Equal(422, r.Code());
        Assert.Equal(422, Send(HttpMethod.Post, "/api/fleets/preview", Auth, WebFixture.JsonContent("{not json")).Code());
        Assert.Equal(422, Send(HttpMethod.Post, "/api/tags", Auth, WebFixture.JsonContent("[1,2]")).Code());
        using var missing = Send(HttpMethod.Post, "/api/tags", Auth, WebFixture.JsonContent(new { add = new[] { "x" } }));
        Assert.Equal(422, missing.Code());
        Assert.Equal("ids", WebFixture.Json(missing)["detail"]![0]!["loc"]![1]!.ToString());
        Assert.Equal(422, Send(HttpMethod.Post, "/api/tags", Auth, WebFixture.JsonContent(new { ids = new object[] { 1 } })).Code());
    }

    // ---------------------------------------------------------------- traversal / downloads
    private string RawGet(string target)
    {
        using var tcp = new TcpClient();
        tcp.Connect(IPAddress.Loopback, W.Base.Port);
        using var s = tcp.GetStream();
        var req = $"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{W.Base.Port}\r\nX-ADmiral-Token: {WebFixture.Token}\r\nConnection: close\r\n\r\n";
        s.Write(Encoding.ASCII.GetBytes(req));
        using var sr = new StreamReader(s, Encoding.UTF8);
        return sr.ReadToEnd();
    }

    [Theory]
    [InlineData("/static/../secret.txt")]
    [InlineData("/static/%2e%2e/secret.txt")]
    [InlineData("/static/..%2fsecret.txt")]
    [InlineData("/static/..%5csecret.txt")]
    [InlineData("/static/....//secret.txt")]
    [InlineData("/static/%252e%252e/secret.txt")]
    [InlineData("/static//etc/passwd")]
    [InlineData("/static/" + "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd")]
    [InlineData("/api/logs/..%2f..%2fsecret.txt")]
    [InlineData("/api/logs/../../secret.txt")]
    public void Path_traversal_serves_nothing_outside(string target)
    {
        var answer = RawGet(target);
        Assert.DoesNotContain("TOP-SECRET", answer);
        Assert.DoesNotContain("root:", answer);
        Assert.StartsWith("HTTP/1.1 4", answer);
    }

    [Fact]
    public void Download_file_names_are_sanitised()
    {
        var h = WebApp.AttachmentHeader("..\\..\\evil\"name\r\n.txt");
        Assert.DoesNotContain("..", h.Replace("filename=", "", StringComparison.Ordinal).Split(';')[1]);
        Assert.DoesNotContain("\\", h);
        Assert.DoesNotContain("\r", h);
        Assert.DoesNotContain("\n", h);
        Assert.StartsWith("attachment; filename=\"", h);
        Assert.Contains("filename*=UTF-8''G%C3%A9pek.txt", WebApp.AttachmentHeader("Gépek.txt"));
        Assert.Equal("attachment; filename=\"a.csv\"", WebApp.AttachmentHeader("a.csv"));
        Assert.Equal("attachment; filename=\"passwd\"", WebApp.AttachmentHeader("../../etc/passwd"));

        var fid = (long)WebFixture.Json(W.Post("/api/fleets", new { name = "../..\\x\"y Gép", kind = "static", members = new[] { "LT-001" } }))["id"]!;
        using var r = W.Get($"/api/fleets/{fid}/export?format=csv");
        Assert.Equal(200, r.Code());
        var cd = r.Content.Headers.ContentDisposition!;
        Assert.Equal("attachment", cd.DispositionType);
        var name = cd.FileName!.Trim('"');
        Assert.DoesNotContain("/", name);
        Assert.DoesNotContain("\\", name);
        Assert.DoesNotContain("..", name);
        Assert.EndsWith(".csv", name);
    }

    // ---------------------------------------------------------------- headers and error bodies
    [Fact]
    public void Security_headers_on_every_answer()
    {
        var answers = new[]
        {
            Send(HttpMethod.Get, "/"), Send(HttpMethod.Get, "/static/app.js"), Send(HttpMethod.Get, "/static/missing.js"),
            Send(HttpMethod.Get, "/api/status"),                                                   // 401
            Send(HttpMethod.Post, "/api/tags", r => r.Headers.Add("X-ADmiral-Token", WebFixture.Token)),   // 403
            Send(HttpMethod.Get, "/api/status", Auth), Send(HttpMethod.Get, "/api/computers/nope", Auth),   // 200, 404
            Send(HttpMethod.Post, "/api/tags", Auth, WebFixture.JsonContent(new { ids = new[] { "NOPE" } })),  // 400
            Send(HttpMethod.Post, "/api/jobs/bogus", Auth),                                         // 422
            Send(HttpMethod.Get, "/api/nothing", Auth),                                             // 404
        };
        Assert.Equal(new[] { 200, 200, 404, 401, 403, 200, 404, 400, 422, 404 }, answers.Select(a => a.Code()));
        foreach (var a in answers) AssertSecurityHeaders(a);
        Assert.Equal("no-store", answers[5].Headers.CacheControl!.ToString());
        Assert.False(answers[5].Headers.Contains("Server"));
    }

    [Fact]
    public void Unexpected_errors_answer_500_without_a_stack_trace()
    {
        W.App.Store.Close();                                                   // every database call now fails
        using var r = W.Get("/api/summary");
        Assert.Equal(500, r.Code());
        AssertSecurityHeaders(r);
        var detail = WebFixture.Detail(r);
        Assert.DoesNotContain(" at ", detail);
        Assert.DoesNotContain(".cs:line", detail);
        Assert.Contains(":", detail);                                          // "Type: message", as web.py
    }
}
