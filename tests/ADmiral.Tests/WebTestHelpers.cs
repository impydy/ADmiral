using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ADmiral.Core;
using ADmiral.Web;
using Microsoft.AspNetCore.Builder;

namespace ADmiral.Tests;

/// <summary>The <c>client</c> pytest fixture: the demo service of <see cref="ServiceFixture"/> behind the real web app on
/// a loopback Kestrel port, and an HttpClient that sends the CSRF header and the session token.</summary>
internal sealed class WebFixture : IDisposable
{
    public const string Token = "test-token-0123456789";

    public ServiceFixture Fx { get; }
    public AdmiralService App => Fx.App;
    public WebApplication Web { get; }
    public Uri Base { get; }

    /// <summary>Sends X-ADmiral: 1 and the token.</summary>
    public HttpClient Client { get; }

    /// <summary>Sends nothing extra.</summary>
    public HttpClient Raw { get; }

    public WebFixture(bool editable = false, Action<WebAppOptions>? configure = null, ServiceFixture? fx = null)
    {
        Fx = fx ?? new ServiceFixture(editable);
        var options = new WebAppOptions { Token = Token, Port = 0, SyncBindAddress = IPAddress.Loopback };
        configure?.Invoke(options);
        Web = WebApp.Create(App, options);
        Web.StartAsync().GetAwaiter().GetResult();
        Base = WebApp.BoundAddress(Web);
        Client = new HttpClient { BaseAddress = Base, Timeout = TimeSpan.FromSeconds(60) };
        Client.DefaultRequestHeaders.Add("X-ADmiral", "1");
        Client.DefaultRequestHeaders.Add("X-ADmiral-Token", Token);
        Raw = new HttpClient { BaseAddress = Base, Timeout = TimeSpan.FromSeconds(60) };
    }

    public HttpResponseMessage Get(string path) => Client.GetAsync(path).GetAwaiter().GetResult();

    public HttpResponseMessage Delete(string path) => Client.DeleteAsync(path).GetAwaiter().GetResult();

    public HttpResponseMessage Post(string path, object? body = null) =>
        Client.PostAsync(path, body is null ? null : JsonContent(body)).GetAwaiter().GetResult();

    public HttpResponseMessage Put(string path, object body) => Client.PutAsync(path, JsonContent(body)).GetAwaiter().GetResult();

    public HttpResponseMessage PostBytes(string path, byte[] data)
    {
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return Client.PostAsync(path, content).GetAwaiter().GetResult();
    }

    public static StringContent JsonContent(object body) =>
        new(body is string s ? s : JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    public JsonNode GetJson(string path)
    {
        using var r = Get(path);
        Assert.True(r.IsSuccessStatusCode, $"GET {path}: {(int)r.StatusCode} {Text(r)}");
        return Json(r);
    }

    public static JsonNode Json(HttpResponseMessage r) => JsonNode.Parse(Text(r)) ?? JsonValue.Create("null")!;

    public static string Text(HttpResponseMessage r) => r.Content.ReadAsStringAsync().GetAwaiter().GetResult();

    public static string Detail(HttpResponseMessage r) => Json(r)["detail"]?.ToString() ?? "";

    /// <summary>Wait for a job of the API to finish.</summary>
    public JsonNode WaitJob(JsonNode job)
    {
        var id = (int)job["id"]!;
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(60))
        {
            var j = GetJson($"/api/jobs/{id}");
            if ((string?)j["status"] != "running") return j;
            Thread.Sleep(30);
        }
        throw new TimeoutException($"job {id} did not finish");
    }

    public void Dispose()
    {
        Client.Dispose();
        Raw.Dispose();
        Web.StopAsync().GetAwaiter().GetResult();
        Web.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Fx.Dispose();
    }
}

internal static class HttpExtensions
{
    public static int Code(this HttpResponseMessage r) => (int)r.StatusCode;
}
