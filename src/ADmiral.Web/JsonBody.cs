using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;

namespace ADmiral.Web;

/// <summary>A request body or query value that does not fit the expected shape: 422 with a FastAPI-style detail list
/// (<c>[{type, loc, msg}]</c>, which app.js turns into "field: message").</summary>
public sealed class RequestValidationException(string type, IReadOnlyList<object> loc, string message) : Exception(message)
{
    public string Type { get; } = type;
    public IReadOnlyList<object> Loc { get; } = loc;

    public object Detail => new[] { new Dictionary<string, object?> { ["type"] = Type, ["loc"] = Loc, ["msg"] = Message } };
}

/// <summary>An explicit HTTP error with a detail text (FastAPI's HTTPException).</summary>
public sealed class ApiErrorException(int status, string detail) : Exception(detail)
{
    public int Status { get; } = status;
}

/// <summary>The JSON body of one request, read with a depth limit and checked field by field (the counterpart of the
/// pydantic models of web.py: unknown fields are ignored, wrong types and missing required fields answer 422).</summary>
public sealed class JsonBody
{
    /// <summary>Deepest nesting accepted in a request body (rules, settings and printer forms need far less).</summary>
    public const int MaxDepth = 32;

    private static readonly JsonDocumentOptions DocOptions = new() { MaxDepth = MaxDepth, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow };

    public JsonObject Object { get; }

    private JsonBody(JsonObject obj) => Object = obj;

    /// <summary>The raw body as a JSON node; null when the body is empty. Malformed / too deep: 422.</summary>
    public static async Task<JsonNode?> ReadNodeAsync(HttpContext ctx)
    {
        using var ms = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(ms, ctx.RequestAborted).ConfigureAwait(false);   // capped by Kestrel's MaxRequestBodySize
        if (ms.Length == 0 || IsBlank(ms.GetBuffer().AsSpan(0, (int)ms.Length))) return null;
        try
        {
            return JsonNode.Parse(ms.GetBuffer().AsSpan(0, (int)ms.Length), documentOptions: DocOptions)
                   ?? JsonValue.Create((string?)null);
        }
        catch (JsonException)
        {
            throw new RequestValidationException("json_invalid", ["body", 0], "JSON decode error");
        }
    }

    private static bool IsBlank(ReadOnlySpan<byte> s)
    {
        foreach (var b in s)
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')) return false;
        return true;
    }

    /// <summary>A body that must be a JSON object (a pydantic model or <c>dict[str, Any]</c>).</summary>
    public static async Task<JsonBody> ReadAsync(HttpContext ctx)
    {
        var node = await ReadNodeAsync(ctx).ConfigureAwait(false);
        if (node is null) throw new RequestValidationException("missing", ["body"], "Field required");
        if (node is not JsonObject obj) throw new RequestValidationException("model_attributes_type", ["body"], "Input should be a valid dictionary or object");
        return new JsonBody(obj);
    }

    /// <summary>An optional body (<c>Model | None = None</c>): null when empty or JSON null.</summary>
    public static async Task<JsonBody?> ReadOptionalAsync(HttpContext ctx)
    {
        var node = await ReadNodeAsync(ctx).ConfigureAwait(false);
        if (node is null || (node is JsonValue v && v.GetValueKind() == JsonValueKind.Null)) return null;
        if (node is not JsonObject obj) throw new RequestValidationException("model_attributes_type", ["body"], "Input should be a valid dictionary or object");
        return new JsonBody(obj);
    }

    private JsonNode? Get(string name, out bool present)
    {
        present = Object.TryGetPropertyValue(name, out var node);
        return node;
    }

    private static bool IsNull(JsonNode? n) => n is null || (n is JsonValue v && v.GetValueKind() == JsonValueKind.Null);

    private static RequestValidationException Bad(string name, string type, string msg) => new(type, ["body", name], msg);

    private static string AsString(JsonNode? n, string name) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : throw Bad(name, "string_type", "Input should be a valid string");

    public string Str(string name)
    {
        var n = Get(name, out var present);
        if (!present) throw Bad(name, "missing", "Field required");
        return AsString(n, name);
    }

    public string Str(string name, string fallback)
    {
        var n = Get(name, out var present);
        return present ? AsString(n, name) : fallback;
    }

    /// <summary><c>str | None</c>: null when absent or JSON null.</summary>
    public string? OptStr(string name)
    {
        var n = Get(name, out _);
        return IsNull(n) ? null : AsString(n, name);
    }

    public bool Has(string name) => Object.ContainsKey(name);

    public string Literal(string name, IReadOnlyCollection<string> allowed, string? fallback = null)
    {
        var n = Get(name, out var present);
        if (!present && fallback is not null) return fallback;
        if (!present) throw Bad(name, "missing", "Field required");
        var s = n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;
        if (s is null || !allowed.Contains(s))
            throw Bad(name, "literal_error", "Input should be " + string.Join(" or ", allowed.Select(a => $"'{a}'")));
        return s;
    }

    private List<string> AsStrList(JsonNode? n, string name)
    {
        if (n is not JsonArray arr) throw Bad(name, "list_type", "Input should be a valid list");
        var outp = new List<string>(arr.Count);
        for (var i = 0; i < arr.Count; i++)
        {
            if (arr[i] is JsonValue v && v.GetValueKind() == JsonValueKind.String) outp.Add(v.GetValue<string>());
            else throw new RequestValidationException("string_type", ["body", name, i], "Input should be a valid string");
        }
        return outp;
    }

    /// <summary><c>list[str]</c> (required).</summary>
    public List<string> StrList(string name)
    {
        var n = Get(name, out var present);
        if (!present) throw Bad(name, "missing", "Field required");
        return AsStrList(n, name);
    }

    /// <summary><c>list[str] = []</c>.</summary>
    public List<string> StrListOr(string name)
    {
        var n = Get(name, out var present);
        return present ? AsStrList(n, name) : [];
    }

    /// <summary><c>list[str] | None</c>.</summary>
    public List<string>? OptStrList(string name)
    {
        var n = Get(name, out _);
        return IsNull(n) ? null : AsStrList(n, name);
    }

    private static long AsLong(JsonNode? n, string name, IReadOnlyList<object> loc)
    {
        if (n is JsonValue v)
        {
            switch (v.GetValueKind())
            {
                case JsonValueKind.Number:
                    if (v.TryGetValue<long>(out var l)) return l;
                    if (v.TryGetValue<double>(out var d) && Math.Abs(d % 1) == 0 && Math.Abs(d) < 9e15) return (long)d;
                    break;
                case JsonValueKind.String:
                    if (long.TryParse(v.GetValue<string>().Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var p)) return p;
                    break;
            }
        }
        throw new RequestValidationException("int_type", loc, "Input should be a valid integer");
    }

    /// <summary><c>int | None</c>.</summary>
    public long? OptLong(string name)
    {
        var n = Get(name, out _);
        return IsNull(n) ? null : AsLong(n, name, ["body", name]);
    }

    /// <summary><c>list[int] | None</c>.</summary>
    public List<long>? OptLongList(string name)
    {
        var n = Get(name, out _);
        if (IsNull(n)) return null;
        if (n is not JsonArray arr) throw Bad(name, "list_type", "Input should be a valid list");
        return [.. arr.Select((x, i) => AsLong(x, name, ["body", name, i]))];
    }

    public bool Bool(string name, bool? fallback = null)
    {
        var n = Get(name, out var present);
        if (!present)
            return fallback ?? throw Bad(name, "missing", "Field required");
        if (n is JsonValue v)
        {
            switch (v.GetValueKind())
            {
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                case JsonValueKind.Number when v.TryGetValue<long>(out var l) && l is 0 or 1: return l == 1;
                case JsonValueKind.String when ParseBool(v.GetValue<string>()) is { } b: return b;
            }
        }
        throw Bad(name, "bool_type", "Input should be a valid boolean");
    }

    /// <summary><c>dict[str, Any] | None</c>.</summary>
    public JsonObject? OptObject(string name)
    {
        var n = Get(name, out _);
        if (IsNull(n)) return null;
        return n as JsonObject ?? throw Bad(name, "dict_type", "Input should be a valid dictionary");
    }

    /// <summary><c>list[Any]</c> (required).</summary>
    public JsonArray Array(string name)
    {
        var n = Get(name, out var present);
        if (!present) throw Bad(name, "missing", "Field required");
        return n as JsonArray ?? throw Bad(name, "list_type", "Input should be a valid list");
    }

    /// <summary>The pydantic / FastAPI spelling of booleans in query strings and bodies.</summary>
    public static bool? ParseBool(string? s) => (s ?? "").Trim().ToLowerInvariant() switch
    {
        "1" or "true" or "t" or "yes" or "y" or "on" => true,
        "0" or "false" or "f" or "no" or "n" or "off" => false,
        _ => null,
    };
}
