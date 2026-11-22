using System.Net;

namespace ADmiral.Tests;

/// <summary>An HTTP handler that answers from a function and records every request (no network).</summary>
internal sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    public sealed record Seen(HttpMethod Method, Uri Uri, Dictionary<string, string> Headers, byte[] Body);

    public List<Seen> Requests { get; } = [];

    public HttpClient Client() => new(this, disposeHandler: false);

    private Seen Record(HttpRequestMessage request)
    {
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        var body = request.Content?.ReadAsByteArrayAsync().GetAwaiter().GetResult() ?? [];
        var seen = new Seen(request.Method, request.RequestUri!, headers, body);
        lock (Requests) Requests.Add(seen);
        return seen;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Record(request);
        var resp = respond(request);
        resp.RequestMessage ??= request;
        return Task.FromResult(resp);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken) =>
        SendAsync(request, cancellationToken).GetAwaiter().GetResult();

    public static HttpResponseMessage Bytes(byte[] body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new ByteArrayContent(body) };

    public static HttpResponseMessage Json(string json) => Bytes(System.Text.Encoding.UTF8.GetBytes(json));

    public static HttpResponseMessage Status(HttpStatusCode code) => new(code) { Content = new ByteArrayContent([]) };
}

/// <summary>A stream without a known length (like a chunked request body).</summary>
internal sealed class ChunkedStream(int chunk, int total) : Stream
{
    private int _left = total;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = Math.Min(Math.Min(count, chunk), _left);
        Array.Fill(buffer, (byte)'x', offset, n);
        _left -= n;
        return n;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
