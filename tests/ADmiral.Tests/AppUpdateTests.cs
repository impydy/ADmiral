using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace ADmiral.Tests;

/// <summary>appupdate.py (test_appupdate.py): signed manifest, rollback / downgrade rules, installer hash, the
/// anonymous counter, launching only the verified file. A throwaway Ed25519 key signs the test releases.</summary>
public class AppUpdateTests
{
    private const string Current = "0.6.0";

    private sealed class Release
    {
        public Ed25519PrivateKeyParameters Priv { get; }
        public string Pub { get; }

        public Release()
        {
            var g = new Ed25519KeyPairGenerator();
            g.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = g.GenerateKeyPair();
            Priv = (Ed25519PrivateKeyParameters)kp.Private;
            Pub = Convert.ToBase64String(((Ed25519PublicKeyParameters)kp.Public).GetEncoded());
        }

        public JsonObject Sign(JsonObject doc)
        {
            var data = AppUpdate.Canonical(doc);
            var s = new Ed25519Signer();
            s.Init(true, Priv);
            s.BlockUpdate(data, 0, data.Length);
            doc["signature"] = Convert.ToBase64String(s.GenerateSignature());
            return doc;
        }
    }

    private static string Sha(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));

    private static byte[] Setup(string v) => Encoding.ASCII.GetBytes("MZ installer " + v);

    private static JsonObject Doc(string version, string? previous = null, string notes = "notes")
    {
        var d = new JsonObject
        {
            ["version"] = version, ["file"] = $"ADmiral-Setup-{version}.exe", ["sha256"] = Sha(Setup(version)), ["notes"] = notes,
        };
        if (previous is not null)
            d["previous"] = new JsonObject { ["version"] = previous, ["file"] = $"ADmiral-Setup-{previous}.exe", ["sha256"] = Sha(Setup(previous)) };
        return d;
    }

    /// <summary>The fixed release folder, served from memory.</summary>
    private sealed class Server
    {
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public bool PostFails { get; set; }
        public FakeHttp Http { get; }

        public Server()
        {
            Http = new FakeHttp(req =>
            {
                var path = req.RequestUri!.AbsolutePath;
                if (req.Method == HttpMethod.Post)
                    return PostFails ? throw new HttpRequestException("slow") : FakeHttp.Status(HttpStatusCode.OK);
                var name = Uri.UnescapeDataString(path[(path.LastIndexOf('/') + 1)..]);
                return Files.TryGetValue(name, out var b) && req.RequestUri.AbsoluteUri.StartsWith(Config.AppUpdateUrl, StringComparison.Ordinal)
                    ? FakeHttp.Bytes(b) : FakeHttp.Status(HttpStatusCode.NotFound);
            });
        }

        public void Publish(JsonObject manifest, params string[] versions)
        {
            Files[AppUpdate.Manifest] = Encoding.UTF8.GetBytes(manifest.ToJsonString());
            foreach (var v in versions) Files[$"ADmiral-Setup-{v}.exe"] = Setup(v);
        }
    }

    private static readonly AppUpdateSettings Cfg = new();
    private static readonly ProxySettings Proxy = new();

    [Fact]
    public void BuiltinKeyIsThePythonReleaseKey()
    {
        Assert.Equal("JWDnQaIvOcVBuGY6CKDoaEYbdbVyjjHBLLx2775r3og=", AppUpdate.BuiltinPublicKey);
        Assert.Equal(32, Convert.FromBase64String(AppUpdate.BuiltinPublicKey).Length);
        Assert.StartsWith("https://", Config.AppUpdateUrl);
        Assert.Equal(Config.AppUpdateUrl, new AppUpdateSettings().Url);
    }

    [Fact]
    public void CanonicalBytesMatchPythonJsonDumps()
    {
        // produced by Python: json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        const string doc = "eyJ2ZXJzaW9uIjogIjAuNy4wIiwgImZpbGUiOiAiQURtaXJhbC1TZXR1cC0wLjcuMC5leGUiLCAic2hhMjU2IjogImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCAibm90ZXMiOiAiXHUwMGRhamRvbnNcdTAwZTFnOiBcImlkXHUwMGU5emV0XCIgXFwgYmFja1xubGluZVx0dGFiIFx1MDAwMSBcdTAwN2YgXHUwMGU5XHUyMGFjXHVkODNkXHVkZTAwIDwvc2NyaXB0PiBcdTIwMjgiLCAicHJldmlvdXMiOiB7InZlcnNpb24iOiAiMC42LjAiLCAiZmlsZSI6ICJBRG1pcmFsLVNldHVwLTAuNi4wLmV4ZSIsICJzaGEyNTYiOiAiY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZCJ9LCAibiI6IDUsICJuZWciOiAtMTIsICJiIjogdHJ1ZSwgImYiOiBmYWxzZSwgInoiOiBudWxsLCAiXHUwMGM0IjogIngiLCAiYSI6IFsxLCAieCIsIHsieSI6IDIsICJCIjogMX1dLCAic2lnbmF0dXJlIjogInp6In0K";   // the input document (json.dumps, ensure_ascii=True), base64
        const string expected = "eyJhIjpbMSwieCIseyJCIjoxLCJ5IjoyfV0sImIiOnRydWUsImYiOmZhbHNlLCJmaWxlIjoiQURtaXJhbC1TZXR1cC0wLjcuMC5leGUiLCJuIjo1LCJuZWciOi0xMiwibm90ZXMiOiLDmmpkb25zw6FnOiBcImlkw6l6ZXRcIiBcXCBiYWNrXG5saW5lXHR0YWIgXHUwMDAxIH8gw6nigqzwn5iAIDwvc2NyaXB0PiDigKgiLCJwcmV2aW91cyI6eyJmaWxlIjoiQURtaXJhbC1TZXR1cC0wLjYuMC5leGUiLCJzaGEyNTYiOiJjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkIiwidmVyc2lvbiI6IjAuNi4wIn0sInNoYTI1NiI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJ2ZXJzaW9uIjoiMC43LjAiLCJ6IjpudWxsLCLDhCI6IngifQ==";
        var canon = AppUpdate.Canonical(AppUpdate.ParseManifest(Convert.FromBase64String(doc)));
        Assert.Equal(expected, Convert.ToBase64String(canon));
    }

    [Fact]
    public void SignedManifestRoundtripAndRollback()
    {
        var rel = new Release();
        var srv = new Server();
        srv.Publish(rel.Sign(Doc("0.7.0", previous: "0.5.0")), "0.7.0", "0.5.0");
        var (manifest, info) = AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client());
        Assert.True(info.Available);
        Assert.Equal("0.7.0", info.Latest);
        Assert.Equal("0.5.0", info.Previous);
        Assert.Equal("notes", info.Notes);
        Assert.Equal(Config.AppUpdateUrl + "latest.json", srv.Http.Requests[0].Uri.AbsoluteUri);

        using var tmp = new CoreTemp();
        var back = AppUpdate.Pick(manifest, rollback: true, Current);
        using (var inst = AppUpdate.Download(Cfg, Proxy, back, tmp.File("dl"), srv.Http.Client()))
            Assert.Equal(Setup("0.5.0"), File.ReadAllBytes(inst.Path));
        var up = AppUpdate.Pick(manifest, rollback: false, Current);
        using (var inst = AppUpdate.Download(Cfg, Proxy, up, tmp.File("dl2"), srv.Http.Client()))
        {
            Assert.Equal(Setup("0.7.0"), File.ReadAllBytes(inst.Path));
            Assert.Equal(up.Sha256, inst.HashNow());
        }
        var (_, same) = AppUpdate.Check(Cfg, Proxy, "0.7.0", rel.Pub, srv.Http.Client());
        Assert.False(same.Available);
    }

    [Fact]
    public void TamperingIsRejected()
    {
        var rel = new Release();
        var srv = new Server();
        var doc = rel.Sign(Doc("0.7.0"));
        doc["file"] = "evil.exe";
        srv.Publish(doc, "0.7.0");
        Assert.Throws<UpdateError>(() => AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client()));
        doc = rel.Sign(Doc("0.7.0"));
        doc["notes"] = "changed";                                       // any field, not only the important ones
        srv.Publish(doc, "0.7.0");
        Assert.Throws<UpdateError>(() => AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client()));
        doc = rel.Sign(Doc("0.7.0"));
        doc["extra"] = "added";
        srv.Publish(doc, "0.7.0");
        Assert.Throws<UpdateError>(() => AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client()));
    }

    [Fact]
    public void WrongKeyBuiltinKeyAndBadSignatures()
    {
        var rel = new Release();
        var other = new Release();
        var doc = rel.Sign(Doc("0.7.0"));
        Assert.Throws<UpdateError>(() => AppUpdate.Verify(doc, other.Pub));
        Assert.Throws<UpdateError>(() => AppUpdate.Verify(doc));          // the built-in release key did not sign this
        AppUpdate.Verify(doc, rel.Pub);
        foreach (var bad in new JsonNode?[] { null, "", "not base64!", Convert.ToBase64String(new byte[63]), Convert.ToBase64String(new byte[64]), 5 })
        {
            var d = (JsonObject)doc.DeepClone();
            d["signature"] = bad;
            Assert.Throws<UpdateError>(() => AppUpdate.Verify(d, rel.Pub));
        }
        var flipped = Convert.FromBase64String((string)doc["signature"]!);
        flipped[10] ^= 1;
        var f = (JsonObject)doc.DeepClone();
        f["signature"] = Convert.ToBase64String(flipped);
        Assert.Throws<UpdateError>(() => AppUpdate.Verify(f, rel.Pub));
        Assert.Throws<UpdateError>(() => AppUpdate.Verify(doc, Convert.ToBase64String(new byte[31])));
        Assert.Throws<UpdateError>(() => AppUpdate.Verify(doc, "AAAA"));
    }

    [Fact]
    public void ManifestMustBeStrictJson()
    {
        Assert.Throws<UpdateError>(() => AppUpdate.ParseManifest("""{"version": "1", "version": "2"}"""u8));
        Assert.Throws<UpdateError>(() => AppUpdate.ParseManifest("[1]"u8));
        Assert.Throws<UpdateError>(() => AppUpdate.ParseManifest("{"u8));
        Assert.Throws<UpdateError>(() => AppUpdate.ParseManifest(new byte[AppUpdate.MaxManifestBytes + 1]));
        Assert.Throws<UpdateError>(() => AppUpdate.Canonical(AppUpdate.ParseManifest("""{"n": 1.5}"""u8)));     // float: Python would print it differently
        Assert.Throws<UpdateError>(() => AppUpdate.Canonical(AppUpdate.ParseManifest("""{"n": 1e3}"""u8)));
        Assert.Throws<UpdateError>(() => AppUpdate.Canonical(AppUpdate.ParseManifest("""{"s": "\ud800"}"""u8))); // lone surrogate
        var srv = new Server();
        srv.Files[AppUpdate.Manifest] = new byte[AppUpdate.MaxManifestBytes + 10];
        Assert.Throws<UpdateError>(() => AppUpdate.Check(Cfg, Proxy, Current, new Release().Pub, srv.Http.Client()));
    }

    [Fact]
    public void DowngradeAndRollbackRules()
    {
        var rel = new Release();
        var old = rel.Sign(Doc("0.5.0", previous: "0.4.0"));                // a replayed, older (validly signed) manifest
        AppUpdate.Verify(old, rel.Pub);
        Assert.False(AppUpdate.Parse(old, Current).Available);
        Assert.Throws<UpdateError>(() => AppUpdate.Pick(old, rollback: false, Current));           // never an "update" to an older version
        Assert.Throws<UpdateError>(() => AppUpdate.Pick(rel.Sign(Doc(Current)), rollback: false, Current));   // nor to the same one
        var latest = rel.Sign(Doc("0.7.0", previous: "0.6.5"));
        Assert.Throws<UpdateError>(() => AppUpdate.Pick(latest, rollback: true, Current));          // "rollback" to a newer version
        Assert.Throws<UpdateError>(() => AppUpdate.Pick(rel.Sign(Doc("0.7.0")), rollback: true, Current));     // no previous
        var swapped = rel.Sign(Doc("0.7.0", previous: "0.8.0"));
        Assert.Throws<UpdateError>(() => AppUpdate.Parse(swapped, Current));                        // previous newer than latest
        Assert.Equal("0.5.0", AppUpdate.Pick(rel.Sign(Doc("0.7.0", previous: "0.5.0")), rollback: true, Current).Version);
        // a manifest older than the running version cannot offer a rollback (its "previous" could be anything old)
        var stale = Doc("0.5.0", previous: "0.4.0");
        Assert.Throws<UpdateError>(() => AppUpdate.Pick(rel.Sign(stale), rollback: true, "0.6.0"));
    }

    [Fact]
    public void ExpiredOrFutureSignedManifestIsRefused()
    {
        var rel = new Release();
        var now = new DateTimeOffset(2027, 1, 10, 0, 0, 0, TimeSpan.Zero);
        var d = Doc("0.7.0");
        d["signed"] = "2027-01-01T00:00:00Z";
        d["expires"] = "2027-04-01T00:00:00Z";
        var m = rel.Sign(d);
        AppUpdate.Verify(m, rel.Pub);                                    // "signed" / "expires" are covered by the signature
        Assert.True(AppUpdate.Parse(m, Current, now).Available);
        Assert.Contains("expired", Assert.Throws<UpdateError>(() => AppUpdate.Parse(m, Current, now.AddDays(90))).Message);
        Assert.Throws<UpdateError>(() => AppUpdate.Parse(m, Current, new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero)));   // signed "in the future"
        var bad = Doc("0.7.0");
        bad["expires"] = "soon";
        Assert.Throws<UpdateError>(() => AppUpdate.Parse(rel.Sign(bad), Current, now));
        Assert.True(AppUpdate.Parse(rel.Sign(Doc("0.7.0")), Current, now).Available);   // older manifests without the fields still work
    }

    [Fact]
    public void ReplayFloor()
    {
        var t = new DateTimeOffset(2027, 1, 10, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(("0.7.0", t), AppUpdate.CheckReplay("0.7.0", t, null, null));
        Assert.Throws<UpdateError>(() => AppUpdate.CheckReplay("0.6.0", t.AddDays(1), "0.7.0", t));   // older version
        Assert.Throws<UpdateError>(() => AppUpdate.CheckReplay("0.7.0", t.AddDays(-1), "0.7.0", t));  // signed earlier
        Assert.Throws<UpdateError>(() => AppUpdate.CheckReplay("0.7.0", null, "0.7.0", t));           // signing time dropped
        Assert.Equal(("0.8.0", t.AddDays(5)), AppUpdate.CheckReplay("0.8.0", t.AddDays(5), "0.7.0", t));
        Assert.Equal(("0.7.0", (DateTimeOffset?)null), AppUpdate.CheckReplay("0.7.0", null, "0.6.0", null));
    }

    [Fact]
    public void InstallerHashAndNames()
    {
        var rel = new Release();
        var srv = new Server();
        srv.Publish(rel.Sign(Doc("0.7.0")), "0.7.0");
        srv.Files["ADmiral-Setup-0.7.0.exe"] = "swapped"u8.ToArray();
        var (manifest, _) = AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client());
        using var tmp = new CoreTemp();
        var dir = tmp.File("dl");
        Assert.Throws<UpdateError>(() => AppUpdate.Download(Cfg, Proxy, AppUpdate.Pick(manifest, false, Current), dir, srv.Http.Client()));
        Assert.Empty(Directory.GetFiles(dir));                                  // nothing unverified is left behind
        Assert.DoesNotContain(srv.Http.Requests, r => r.Method == HttpMethod.Post);  // and nothing is counted
        foreach (var name in new[] { "..\\x.exe", "../x.exe", "x.dll", "CON.exe", "a/b.exe", ".x.exe", "x.exe\n", "" })
            Assert.Throws<UpdateError>(() => AppUpdate.Entry(new JsonObject { ["version"] = "1.0", ["file"] = name, ["sha256"] = new string('0', 64) }, "x"));
        Assert.Throws<UpdateError>(() => AppUpdate.Entry(new JsonObject { ["version"] = "x", ["file"] = "a.exe", ["sha256"] = new string('0', 64) }, "x"));
        Assert.Throws<UpdateError>(() => AppUpdate.Entry(new JsonObject { ["version"] = "1", ["file"] = "a.exe", ["sha256"] = "00" }, "x"));
    }

    [Fact]
    public void OversizeInstallerIsRefused()
    {
        var srv = new Server();
        var http = new FakeHttp(_ =>
        {
            var r = FakeHttp.Bytes([1, 2, 3]);
            r.Content.Headers.ContentLength = AppUpdate.MaxInstallerBytes + 1;
            return r;
        });
        using var tmp = new CoreTemp();
        var entry = new UpdateEntry("0.7.0", "ADmiral-Setup-0.7.0.exe", Sha(Setup("0.7.0")));
        Assert.Throws<UpdateError>(() => AppUpdate.Download(Cfg, Proxy, entry, tmp.File("dl"), http.Client()));
        _ = srv;
    }

    [Fact]
    public void ExistingFileInTheFolderIsNeverWrittenThrough()
    {
        using var tmp = new CoreTemp();
        var dir = tmp.File("dl");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ADmiral-Setup-0.7.0.exe"), "planted");
        var srv = new Server();
        srv.Publish(new JsonObject(), "0.7.0");
        var entry = new UpdateEntry("0.7.0", "ADmiral-Setup-0.7.0.exe", Sha(Setup("0.7.0")));
        Assert.Throws<IOException>(() => AppUpdate.Download(Cfg, Proxy, entry, dir, srv.Http.Client()));
        Assert.Equal("planted", File.ReadAllText(Path.Combine(dir, "ADmiral-Setup-0.7.0.exe")));
        Assert.Empty(srv.Http.Requests);
    }

    private sealed class RecordingLauncher : IInstallerLauncher
    {
        public List<(string Path, IReadOnlyList<string> Args, string Hash)> Started { get; } = [];

        public void Start(string path, IReadOnlyList<string> arguments) => Started.Add((path, arguments, AppUpdate.Sha256Of(path)));
    }

    [Fact]
    public void LaunchRechecksTheHashAndStartsTheVerifiedFile()
    {
        using var tmp = new CoreTemp();
        var f = tmp.File("ADmiral-Setup-9.exe");
        File.WriteAllBytes(f, "MZ ok"u8.ToArray());
        Assert.Throws<UpdateError>(() => AppUpdate.OpenVerified(f, new UpdateEntry("9", "ADmiral-Setup-9.exe", new string('0', 64))));
        Assert.False(File.Exists(f));                                           // a mismatching file is removed

        var rel = new Release();
        var srv = new Server();
        srv.Publish(rel.Sign(Doc("0.7.0")), "0.7.0");
        var (manifest, _) = AppUpdate.Check(Cfg, Proxy, Current, rel.Pub, srv.Http.Client());
        var entry = AppUpdate.Pick(manifest, false, Current);
        var launcher = new RecordingLauncher();
        using (var inst = AppUpdate.Download(Cfg, Proxy, entry, tmp.File("ok"), srv.Http.Client()))
        {
            AppUpdate.Launch(inst, "S-1-5-21-1-2-3-1001", launcher);
            var (path, args, hash) = Assert.Single(launcher.Started);
            Assert.Equal(inst.Path, path);
            Assert.Equal(entry.Sha256, hash);
            Assert.Equal(["/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS", "/DATAUSER=*S-1-5-21-1-2-3-1001"], args);
        }
        Assert.Equal(["/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"], AppUpdate.InstallerArguments("S-1-5\" /evil"));

        // swapped after the verification: either the held handle prevents it or the launch refuses
        using var inst2 = AppUpdate.Download(Cfg, Proxy, entry, tmp.File("swap"), srv.Http.Client());
        var swapped = false;
        try
        {
            using var w = new FileStream(inst2.Path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            w.Write("XX"u8);
            swapped = true;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        var l2 = new RecordingLauncher();
        if (swapped)
        {
            Assert.Throws<UpdateError>(() => AppUpdate.Launch(inst2, "", l2));
            Assert.Empty(l2.Started);
        }
        else
        {
            AppUpdate.Launch(inst2, "", l2);
            Assert.Equal(entry.Sha256, l2.Started[0].Hash);
        }
    }

    [Fact]
    public void OfficialServerMarksDownloadAndReportsOnce()
    {
        var rel = new Release();
        var srv = new Server();
        srv.Publish(rel.Sign(Doc("0.7.0")), "0.7.0");
        var entry = new UpdateEntry("0.7.0", "ADmiral-Setup-0.7.0.exe", Sha(Setup("0.7.0")));
        using var tmp = new CoreTemp();
        using (AppUpdate.Download(Cfg, Proxy, entry, tmp.File("dl"), srv.Http.Client())) { }
        var get = srv.Http.Requests.Single(r => r.Method == HttpMethod.Get);
        Assert.Equal("self", get.Headers[AppUpdate.CountHeader]);
        var post = srv.Http.Requests.Single(r => r.Method == HttpMethod.Post);
        Assert.Equal(Config.AppUpdateUrl + "count.php", post.Uri.AbsoluteUri);
        Assert.Equal("verified", post.Headers[AppUpdate.CountHeader]);
        Assert.Empty(post.Body);
        Assert.True(post.Headers.Keys.All(k => k is "Accept" or "X-ADmiral-Count" or "User-Agent"));   // nothing identifying
        using (AppUpdate.Download(Cfg, Proxy, entry, tmp.File("dl2"), srv.Http.Client())) { }          // e.g. a rollback
        Assert.Equal(2, srv.Http.Requests.Count(r => r.Method == HttpMethod.Post));                     // one ping per download
    }

    [Theory]
    [InlineData("https://updates.example.local/admiral/")]
    [InlineData("http://tidecrestlabs.com.evil.example/x/")]
    [InlineData("https://example.com/tidecrestlabs.com/")]
    [InlineData("\\\\server\\share")]
    public void CustomLocationsAreNotCounted(string url) => Assert.False(AppUpdate.Counted(url));

    [Fact]
    public void OfficialLocationIsCounted() => Assert.True(AppUpdate.Counted(Config.AppUpdateUrl));

    [Fact]
    public void PingErrorsAreSwallowed()
    {
        var srv = new Server { PostFails = true };
        srv.Publish(new JsonObject(), "0.7.0");
        var entry = new UpdateEntry("0.7.0", "ADmiral-Setup-0.7.0.exe", Sha(Setup("0.7.0")));
        using var tmp = new CoreTemp();
        using var inst = AppUpdate.Download(Cfg, Proxy, entry, tmp.File("dl"), srv.Http.Client());
        Assert.Equal(Setup("0.7.0"), File.ReadAllBytes(inst.Path));
    }

    [Fact]
    public void PrivateFolderIsNewAndEmpty()
    {
        var a = AppUpdate.PrivateFolder();
        var b = AppUpdate.PrivateFolder();
        try
        {
            Assert.NotEqual(a, b);
            Assert.Empty(Directory.EnumerateFileSystemEntries(a));
            if (!OperatingSystem.IsWindows())
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(a));
        }
        finally
        {
            Directory.Delete(a);
            Directory.Delete(b);
        }
        Assert.False(OperatingSystem.IsWindows() ? false : AppUpdate.CanInstall());
    }
}
