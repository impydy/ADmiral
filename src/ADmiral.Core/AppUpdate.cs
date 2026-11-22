// Port of admiral/appupdate.py: ADmiral's own updates - a signed manifest and the installers on the official
// release server (Config.AppUpdateUrl; not a setting, so admiral.toml / the environment / the UI cannot move it).
//
//   latest.json                       the manifest, signed with Ed25519 (scripts/release_sign.py)
//   ADmiral-Setup-<version>.exe       the installer(s) it names
//
//   {"version": "0.2.4", "file": "ADmiral-Setup-0.2.4.exe", "sha256": "...", "notes": "...",
//    "previous": {"version": "0.2.3", "file": "ADmiral-Setup-0.2.3.exe", "sha256": "..."},     (optional: rollback)
//    "signed": "2026-11-22T10:00:00Z", "expires": "2027-02-20T10:00:00Z",                       (optional, see below)
//    "signature": "<base64 Ed25519 signature of the rest, canonical JSON>"}
//
// The manifest is trusted only when the signature verifies against the release key compiled into the program
// (the same key as the Python version, so the existing signing tool keeps working). Nothing from the download is
// used before that: the installer must match the signed SHA-256, it is written into a new folder private to the
// user, kept open (no writer / no delete) from verification to launch and hashed once more right before it starts.
//
// Stricter than Python: the manifest JSON must be canonical-representable (no floats, no duplicate keys, no lone
// surrogates) and small; an "update" must be newer than the running version and a "rollback" older; the previous
// entry must be older than the latest; the installer download has a size cap; reserved Windows device names are
// refused as file names; the private folder gets an explicit ACL on Windows.
//
// Replays: someone who can serve an old, genuinely signed manifest (a compromised mirror, a TLS interception) must not
// be able to offer an old, vulnerable version again - not even as a "rollback". So a manifest that carries "expires"
// is refused after that time; and the service remembers the newest manifest it has accepted (version and "signed"
// time) and refuses anything older, or one without "signed" once a signed one was seen (see AppUpdate.CheckReplay).
// A rollback also needs a manifest whose latest version is not older than the running one.

using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ADmiral.Core;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python UpdateError")]
public sealed class UpdateError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>A validated {version, file, sha256} entry of a verified manifest.</summary>
public sealed record UpdateEntry(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("sha256")] string Sha256);

/// <summary>The state shown to the user for a verified manifest.</summary>
public sealed record AppUpdateInfo(
    [property: JsonPropertyName("latest")] string Latest,
    [property: JsonPropertyName("notes")] string Notes,
    [property: JsonPropertyName("available")] bool Available,
    [property: JsonPropertyName("previous")] string? Previous);

/// <summary>Starts a verified installer. The default (Windows) shows the UAC prompt (ShellExecute "runas").</summary>
public interface IInstallerLauncher
{
    void Start(string path, IReadOnlyList<string> arguments);
}

[SupportedOSPlatform("windows")]
public sealed class ShellRunasLauncher : IInstallerLauncher
{
    public void Start(string path, IReadOnlyList<string> arguments)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true, Verb = "runas" };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        try
        {
            using var _ = System.Diagnostics.Process.Start(psi);
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            throw new UpdateError($"the installer could not be started ({exc.Message}; was the UAC prompt declined?)", exc);
        }
    }
}

/// <summary>A downloaded installer whose SHA-256 matched the signed one. The file stays open (others may read it but
/// neither write nor delete / rename it) until <see cref="Dispose"/>, so the file that is started is the file that was
/// verified.</summary>
public sealed class VerifiedInstaller : IDisposable
{
    private readonly FileStream _handle;

    public string Path { get; }
    public string Folder { get; }
    public UpdateEntry Entry { get; }
    public string Sha256 => Entry.Sha256;

    internal VerifiedInstaller(FileStream handle, string path, string folder, UpdateEntry entry)
    {
        _handle = handle;
        Path = path;
        Folder = folder;
        Entry = entry;
    }

    /// <summary>The SHA-256 of the bytes behind the held handle, now.</summary>
    public string HashNow()
    {
        lock (_handle)
        {
            _handle.Seek(0, SeekOrigin.Begin);
            return Convert.ToHexStringLower(SHA256.HashData(_handle));
        }
    }

    public void Dispose() => _handle.Dispose();
}

public static partial class AppUpdate
{
    /// <summary>The release public key (base64, raw 32-byte Ed25519) compiled into the program - the same as Python's.</summary>
    public const string BuiltinPublicKey = "JWDnQaIvOcVBuGY6CKDoaEYbdbVyjjHBLLx2775r3og=";
    public const string Manifest = "latest.json";
    public const int CheckHours = 24;
    public const string CountScript = "count.php";
    public const string CountHeader = "X-ADmiral-Count";
    public static readonly IReadOnlySet<string> CountedHosts = new HashSet<string>(StringComparer.Ordinal) { "tidecrestlabs.com", "www.tidecrestlabs.com" };

    public const int MaxManifestBytes = 256 * 1024;
    public const long MaxInstallerBytes = 512L * 1024 * 1024;
    public static readonly TimeSpan ManifestTimeout = TimeSpan.FromSeconds(45);
    public static readonly TimeSpan InstallerTimeout = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan CountTimeout = TimeSpan.FromSeconds(3);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}\.exe\z")]
    private static partial Regex NameRe();

    [GeneratedRegex(@"^[0-9a-fA-F]{64}\z")]
    private static partial Regex ShaRe();

    [GeneratedRegex(@"^S-1-[0-9-]+\z")]
    private static partial Regex SidRe();

    [GeneratedRegex(@"^-?(0|[1-9][0-9]*)\z")]
    private static partial Regex IntRe();

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    // ---------------------------------------------------------------------- canonical JSON + signature
    /// <summary>Parse manifest bytes strictly: an object, no duplicate keys, bounded depth and size.</summary>
    public static JsonObject ParseManifest(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length > MaxManifestBytes) throw new UpdateError("the manifest is too large");
        if (utf8.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) utf8 = utf8[3..];
        JsonNode? doc;
        try
        {
            doc = JsonNode.Parse(utf8, documentOptions: new JsonDocumentOptions { MaxDepth = 16, AllowDuplicateProperties = false });
        }
        catch (Exception exc) when (exc is JsonException or ArgumentException or InvalidOperationException)
        {
            throw new UpdateError($"the manifest is not valid JSON ({exc.GetType().Name})", exc);
        }
        return doc as JsonObject ?? throw new UpdateError("the manifest is not a JSON object");
    }

    /// <summary>The bytes that are signed: the manifest without its signature, as Python's
    /// <c>json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)</c> writes it, UTF-8.
    /// Anything that could serialise differently (floats, lone surrogates) is refused.</summary>
    public static byte[] Canonical(JsonObject manifest)
    {
        var sb = new StringBuilder();
        try { WriteObject(sb, manifest.Where(kv => kv.Key != "signature")); }
        catch (Exception exc) when (exc is InvalidOperationException or FormatException)   // e.g. an escaped lone surrogate
        {
            throw new UpdateError("the manifest holds an invalid value", exc);
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static readonly Comparison<string> CodePointOrder = (a, b) =>
    {
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            var ra = Rune.GetRuneAt(a, i);
            var rb = Rune.GetRuneAt(b, j);
            if (ra.Value != rb.Value) return ra.Value.CompareTo(rb.Value);
            i += ra.Utf16SequenceLength;
            j += rb.Utf16SequenceLength;
        }
        return (a.Length - i).CompareTo(b.Length - j);
    };

    private static void WriteObject(StringBuilder sb, IEnumerable<KeyValuePair<string, JsonNode?>> props)
    {
        var list = props.ToList();
        foreach (var kv in list) CheckText(kv.Key);
        list.Sort((x, y) => CodePointOrder(x.Key, y.Key));
        sb.Append('{');
        for (var i = 0; i < list.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteString(sb, list[i].Key);
            sb.Append(':');
            WriteValue(sb, list[i].Value);
        }
        sb.Append('}');
    }

    private static void WriteValue(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;
            case JsonObject o:
                WriteObject(sb, o);
                break;
            case JsonArray a:
                sb.Append('[');
                for (var i = 0; i < a.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    WriteValue(sb, a[i]);
                }
                sb.Append(']');
                break;
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.String:
                        var s = v.GetValue<string>();
                        CheckText(s);
                        WriteString(sb, s);
                        break;
                    case JsonValueKind.True: sb.Append("true"); break;
                    case JsonValueKind.False: sb.Append("false"); break;
                    case JsonValueKind.Null: sb.Append("null"); break;
                    case JsonValueKind.Number:
                        var raw = v.ToJsonString();
                        if (!IntRe().IsMatch(raw) || raw == "-0") throw new UpdateError("the manifest holds a number that is not a plain integer");
                        sb.Append(raw);
                        break;
                    default: throw new UpdateError("the manifest holds an unsupported value");
                }
                break;
        }
    }

    private static void CheckText(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
            else if (char.IsSurrogate(s[i])) throw new UpdateError("the manifest holds an invalid character");
        }
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    private static byte[] StrictBase64(string text, int expectedLength, string what)
    {
        var t = text.Trim();
        if (t.Length == 0 || t.Any(char.IsWhiteSpace)) throw new UpdateError($"the {what} is malformed");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(t); }
        catch (FormatException exc) { throw new UpdateError($"the {what} is malformed", exc); }
        if (bytes.Length != expectedLength) throw new UpdateError($"the {what} is malformed");
        return bytes;
    }

    /// <summary>Throw <see cref="UpdateError"/> unless the manifest carries a valid Ed25519 signature of
    /// <paramref name="publicKeyB64"/> (default: the built-in release key; another key is only passed by tests).</summary>
    public static void Verify(JsonObject manifest, string? publicKeyB64 = null)
    {
        var key = StrictBase64(string.IsNullOrWhiteSpace(publicKeyB64) ? BuiltinPublicKey : publicKeyB64, 32, "signing key");
        var sigText = manifest["signature"] is JsonValue sv && sv.TryGetValue<string>(out var st) ? st : "";
        var sig = StrictBase64(sigText, 64, "signature");
        var data = Canonical(manifest);
        bool ok;
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(key, 0));
            verifier.BlockUpdate(data, 0, data.Length);
            ok = verifier.VerifySignature(sig);
        }
        catch (Exception exc) when (exc is ArgumentException or InvalidOperationException or FormatException)
        {
            throw new UpdateError($"the signing key or signature is malformed ({exc.GetType().Name})", exc);
        }
        if (!ok) throw new UpdateError("the manifest's signature is not valid");
    }

    private static string Text(JsonNode? n)
    {
        try { return n is JsonValue v && v.TryGetValue<string>(out var s) ? s : ""; }
        catch (InvalidOperationException) { return ""; }
    }

    /// <summary>A validated {version, file, sha256} entry of the manifest.</summary>
    public static UpdateEntry Entry(JsonNode? doc, string what)
    {
        if (doc is not JsonObject o) throw new UpdateError($"{what}: missing");
        var version = Text(o["version"]);
        var file = Text(o["file"]);
        var sha = Text(o["sha256"]);
        if (version.Length == 0 || version.Length > 40 || Software.VersionKey(version).Length == 0) throw new UpdateError($"{what}: bad version");
        if (!NameRe().IsMatch(file) || file.Contains("..", StringComparison.Ordinal)
            || ReservedNames.Contains(file.Split('.')[0].TrimEnd(' ')) || file.EndsWith(" .exe", StringComparison.Ordinal))
            throw new UpdateError($"{what}: bad file name");
        if (!ShaRe().IsMatch(sha)) throw new UpdateError($"{what}: bad SHA-256");
        return new UpdateEntry(version, file, sha.ToLowerInvariant());
    }

    private static int Cmp(string a, string b) => Software.CompareVersions(a, b);

    /// <summary>"signed" / "expires" of a manifest: absent (null), or a UTC time; anything else is refused.</summary>
    public static DateTimeOffset? Time(JsonObject manifest, string key)
    {
        if (manifest[key] is not { } n || (n is JsonValue nv && nv.GetValueKind() == JsonValueKind.Null)) return null;
        var s = Text(n);
        if (s.Length is 0 or > 40 || !DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            throw new UpdateError($"manifest: bad '{key}' time");
        return t;
    }

    /// <summary>Refuse a manifest (latest <paramref name="version"/>, <paramref name="signed"/> time) that is older
    /// than the newest one accepted before (<paramref name="seenVersion"/> / <paramref name="seenSigned"/>, null = none
    /// yet): a replay. Returns what to remember now.</summary>
    public static (string Version, DateTimeOffset? Signed) CheckReplay(string version, DateTimeOffset? signed, string? seenVersion,
                                                                       DateTimeOffset? seenSigned)
    {
        if (!string.IsNullOrEmpty(seenVersion) && Software.VersionKey(seenVersion).Length > 0 && Cmp(version, seenVersion) < 0)
            throw new UpdateError($"the manifest offers {version}, older than {seenVersion} offered before: an old manifest is being replayed");
        if (seenSigned is { } ss)
        {
            if (signed is null) throw new UpdateError("the manifest has no signing time although an earlier one had: an old manifest is being replayed");
            if (signed < ss) throw new UpdateError($"the manifest was signed {signed:o}, before the one accepted earlier ({ss:o}): an old manifest is being replayed");
        }
        return (Cmp(version, seenVersion ?? "") >= 0 || string.IsNullOrEmpty(seenVersion) ? version : seenVersion!,
                signed is { } sg && (seenSigned is null || sg > seenSigned) ? sg : seenSigned);
    }

    /// <summary>The state shown to the user for a (verified) manifest.</summary>
    public static AppUpdateInfo Parse(JsonObject manifest, string current, DateTimeOffset? now = null)
    {
        var latest = Entry(manifest, "manifest");
        var t = now ?? DateTimeOffset.UtcNow;
        var signedAt = Time(manifest, "signed");
        if (signedAt is { } sa && sa > t.AddDays(1)) throw new UpdateError("manifest: signed in the future");
        if (Time(manifest, "expires") is { } exp && t > exp)
            throw new UpdateError($"the manifest expired on {exp:yyyy-MM-dd} (an old copy?): nothing is offered until the server has a fresh one");
        string? previous = null;
        if (manifest["previous"] is { } p && !(p is JsonValue pv && pv.GetValueKind() == JsonValueKind.Null))
        {
            var prev = Entry(p, "previous");
            if (Cmp(prev.Version, latest.Version) >= 0) throw new UpdateError("previous: not older than the latest version");
            previous = prev.Version;
        }
        var notes = Text(manifest["notes"]);
        if (notes.Length > 4000) notes = notes[..4000];
        return new AppUpdateInfo(latest.Version, notes, Cmp(latest.Version, current) > 0, previous);
    }

    /// <summary>The entry to install: the latest version (must be newer than <paramref name="current"/>: no downgrade
    /// disguised as an update, e.g. a replayed old manifest), or for a rollback the previous one (must be older than
    /// <paramref name="current"/> and than the latest).</summary>
    public static UpdateEntry Pick(JsonObject manifest, bool rollback, string current)
    {
        var info = Parse(manifest, current);          // validates both entries and their order
        if (!rollback)
        {
            if (!info.Available) throw new UpdateError(I18n.T("err.upd_none"));
            return Entry(manifest, "manifest");
        }
        if (info.Previous is null) throw new UpdateError(I18n.T("err.upd_no_prev"));
        // a manifest older than what runs here is stale: its "previous" could be any old version
        if (Cmp(info.Latest, current) < 0) throw new UpdateError("the manifest is older than the running version: no rollback from it");
        var prev = Entry(manifest["previous"], "previous");
        if (Cmp(prev.Version, current) >= 0) throw new UpdateError("previous: not older than the running version");
        return prev;
    }

    // ---------------------------------------------------------------------- location (fixed)
    /// <summary>The fixed release folder (https only; never taken from anywhere else).</summary>
    public static Uri BaseUri()
    {
        var u = new Uri(Config.AppUpdateUrl.TrimEnd('/') + "/", UriKind.Absolute);
        if (u.Scheme != Uri.UriSchemeHttps) throw new UpdateError("the update location must be an https address");
        return u;
    }

    private static HttpClient ClientFor(AppUpdateSettings cfg, ProxySettings proxy, HttpClient? client) =>
        client ?? Updates.Client(proxy, direct: !cfg.UseProxy);

    /// <summary>Download (not yet verified!) the manifest from the fixed location.</summary>
    public static JsonObject FetchManifest(AppUpdateSettings cfg, ProxySettings proxy, HttpClient? client = null)
    {
        var url = new Uri(BaseUri(), Manifest).AbsoluteUri;
        byte[] bytes;
        try
        {
            bytes = Updates.GetBytesAsync(ClientFor(cfg, proxy, client), url, MaxManifestBytes, ManifestTimeout,
                                          accept: "application/json").GetAwaiter().GetResult();
        }
        catch (ResponseTooLargeException exc) { throw new UpdateError("the manifest is too large", exc); }
        return ParseManifest(bytes);
    }

    /// <summary>(verified manifest, state). Throws <see cref="UpdateError"/> / network errors.</summary>
    public static (JsonObject Manifest, AppUpdateInfo Info) Check(AppUpdateSettings cfg, ProxySettings proxy, string current,
                                                                  string? publicKey = null, HttpClient? client = null)
    {
        var doc = FetchManifest(cfg, proxy, client);
        Verify(doc, publicKey);
        return (doc, Parse(doc, current));
    }

    /// <summary>Only the official release server keeps the anonymous download counter.</summary>
    public static bool Counted(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https")) return false;
        return CountedHosts.Contains(u.Host.ToLowerInvariant());
    }

    /// <summary>Best effort: tell the official server's counter that one installer download passed its SHA-256 check.
    /// No body, nothing identifying (User-Agent ADmiral/&lt;version&gt; and the count header); errors are swallowed.</summary>
    public static void ReportVerified(AppUpdateSettings cfg, ProxySettings proxy, HttpClient? client = null)
    {
        var baseUri = BaseUri();
        if (!Counted(baseUri.AbsoluteUri)) return;
        try
        {
            using var cts = new CancellationTokenSource(CountTimeout);
            using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, CountScript));
            req.Headers.TryAddWithoutValidation("User-Agent", Updates.UserAgent());
            req.Headers.TryAddWithoutValidation("Accept", "*/*");
            req.Headers.TryAddWithoutValidation(CountHeader, "verified");
            using var resp = ClientFor(cfg, proxy, client).SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
        }
        catch (Exception exc)       // the counter is never worth an error
        {
            if (Log.Logger.IsEnabled(LogLevel.Debug)) Log.Logger.LogDebug("Download counter not reached ({Error})", exc.GetType().Name);
        }
    }

    /// <summary>A new, empty folder only the current user (plus SYSTEM / Administrators) can write to.</summary>
    public static string PrivateFolder()
    {
        var dir = Directory.CreateTempSubdirectory("admiral-update-").FullName;   // mode 0700 on Unix
        if (OperatingSystem.IsWindows() && !WinSec.HardenDir(dir))
        {
            TryDeleteDir(dir);
            throw new UpdateError("could not create a private folder for the update");
        }
        return dir;
    }

    private static void TryDeleteDir(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Fetch the installer of <paramref name="entry"/> (from a verified manifest) into a new private folder
    /// (or <paramref name="folder"/>), check it against the signed SHA-256 and return it held open.</summary>
    public static VerifiedInstaller Download(AppUpdateSettings cfg, ProxySettings proxy, UpdateEntry entry,
                                             string? folder = null, HttpClient? client = null)
    {
        entry = Entry(new JsonObject { ["version"] = entry.Version, ["file"] = entry.File, ["sha256"] = entry.Sha256 }, "entry");
        var dir = folder ?? PrivateFolder();
        Directory.CreateDirectory(dir);
        var dest = System.IO.Path.Combine(dir, entry.File);
        var baseUri = BaseUri();
        var counted = Counted(baseUri.AbsoluteUri);
        var http = ClientFor(cfg, proxy, client);
        // CreateNew: never write through a file (or link) someone else put there (and never delete it either)
        var f = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        try
        {
            using (f)
            {
                using var cts = new CancellationTokenSource(InstallerTimeout);
                using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, Uri.EscapeDataString(entry.File)));
                req.Headers.TryAddWithoutValidation("User-Agent", Updates.UserAgent());
                req.Headers.TryAddWithoutValidation("Accept", "*/*");
                if (counted) req.Headers.TryAddWithoutValidation(CountHeader, "self");
                using var resp = http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();
                resp.EnsureSuccessStatusCode();
                Updates.CopyCappedAsync(resp, f, MaxInstallerBytes, null, cts.Token).GetAwaiter().GetResult();
                f.Flush(flushToDisk: true);
            }
            var verified = OpenVerified(dest, entry, dir);
            if (counted) ReportVerified(cfg, proxy, client);
            return verified;
        }
        catch (ResponseTooLargeException exc)
        {
            Updates.TryDelete(dest);
            throw new UpdateError($"{entry.File} is too large", exc);
        }
        catch
        {
            Updates.TryDelete(dest);
            throw;
        }
    }

    /// <summary>Open <paramref name="path"/> read-only (others may read, not write / delete / rename), hash it through
    /// that handle and return it held open when it matches <paramref name="entry"/>; otherwise delete it and throw.</summary>
    public static VerifiedInstaller OpenVerified(string path, UpdateEntry entry, string? folder = null)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var v = new VerifiedInstaller(fs, path, folder ?? System.IO.Path.GetDirectoryName(path) ?? "", entry);
        bool ok;
        try { ok = string.Equals(v.HashNow(), entry.Sha256, StringComparison.OrdinalIgnoreCase); }
        catch
        {
            v.Dispose();
            throw;
        }
        if (ok) return v;
        v.Dispose();
        Updates.TryDelete(path);
        throw new UpdateError($"SHA-256 mismatch for {entry.File}");
    }

    /// <summary>SHA-256 (lower-case hex) of a file.</summary>
    public static string Sha256Of(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(f));
    }

    /// <summary>Only the installed Windows program replaces itself (not a development build started by dotnet).</summary>
    public static bool CanInstall()
    {
        if (!OperatingSystem.IsWindows()) return false;
        var exe = Environment.ProcessPath ?? "";
        if (exe.Length == 0 || System.IO.Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return false;
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return pf.Length > 0 && exe.StartsWith(pf.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The installer's arguments: silent, it closes and restarts ADmiral itself; <paramref name="userSid"/> (the
    /// user running ADmiral) keeps write access to the data folder even when UAC is answered by another administrator.</summary>
    public static List<string> InstallerArguments(string userSid = "")
    {
        var args = new List<string> { "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS" };
        if (SidRe().IsMatch(userSid ?? "")) args.Add($"/DATAUSER=*{userSid}");
        return args;
    }

    /// <summary>Start the verified installer: hashed once more through the held handle right before it starts.</summary>
    public static void Launch(VerifiedInstaller installer, string userSid = "", IInstallerLauncher? launcher = null)
    {
        if (!string.Equals(installer.HashNow(), installer.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new UpdateError($"SHA-256 mismatch for {installer.Entry.File} (changed after the download)");
        if (launcher is null)
        {
            if (!OperatingSystem.IsWindows()) throw new UpdateError("the installer can only be started on Windows");
            launcher = new ShellRunasLauncher();
        }
        launcher.Start(installer.Path, InstallerArguments(userSid));
    }
}
