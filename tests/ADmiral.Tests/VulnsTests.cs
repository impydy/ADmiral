using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>vulns.py: version ranges, the curated catalog, NVD parsing / paging, KEV (test_software.py, test_misc.py).</summary>
public class VulnsTests
{
    private static string?[] M(string? si, string? se, string? ei, string? ee, string? exact) => [si, se, ei, ee, exact];

    [Fact]
    public void VersionRanges()
    {
        var m = M(null, null, null, "131.0.6778.85", null);
        Assert.True(Vulns.Affected("131.0.6778.69", [m]));
        Assert.False(Vulns.Affected("131.0.6778.85", [m]));
        Assert.True(Vulns.Affected("9.9", [M(null, null, "10.0", null, null)]));
        Assert.False(Vulns.Affected("10.0.1", [M(null, null, "10.0", null, null)]));
        Assert.True(Vulns.Affected("5.0", [M("4.0", null, null, "6.0", null)]));
        Assert.False(Vulns.Affected("3.9", [M("4.0", null, null, "6.0", null)]));
        Assert.False(Vulns.Affected("4.0", [M(null, "4.0", null, null, null)]));
        Assert.True(Vulns.Affected("24.08", [M(null, null, null, null, "24.08")]));
        Assert.False(Vulns.Affected("24.09", [M(null, null, null, null, "24.08")]));
        Assert.True(Vulns.Affected("1.2.3", [M(null, null, null, null, null)]));
        Assert.False(Vulns.Affected("", [m]));
        Assert.Equal("< 131.0.6778.85", Vulns.FixedIn([m]));
        Assert.Equal("<= 10.0", Vulns.FixedIn([M(null, null, "10.0", null, null), M(null, null, null, "9.0", null)]));
        Assert.Equal("", Vulns.FixedIn([M(null, null, null, null, "1")]));
        Assert.Equal(["critical", "high", "medium", "low", "unknown"], new double?[] { 9.8, 7.0, 5.0, 2.0, null }.Select(Vulns.Severity));
        var cm = Vulns.Compile(m);
        Assert.True(Vulns.InRangeC(Software.VersionKey("131.0.1"), cm));
        Assert.False(Vulns.InRangeC(Software.VersionKey("132"), cm));
    }

    [Fact]
    public void CatalogIsConservative()
    {
        Assert.Equal(("google", "chrome"), Vulns.CpeFor("Google Chrome"));
        Assert.Equal(("7-zip", "7-zip"), Vulns.CpeFor("7-Zip (x64)"));
        Assert.Equal(("notepad-plus-plus", @"notepad\+\+"), Vulns.CpeFor("Notepad++ (64-bit x64)"));
        Assert.Null(Vulns.CpeFor("Chrome Remote Desktop Host"));
        Assert.Null(Vulns.CpeFor("Pythonista Helper"));
        Assert.Null(Vulns.CpeFor(null));
    }

    private static JsonObject Item(string cve, double score, params JsonObject[] matches) => new()
    {
        ["cve"] = new JsonObject
        {
            ["id"] = cve, ["published"] = "2026-01-01T00:00:00.000",
            ["descriptions"] = new JsonArray(new JsonObject { ["lang"] = "en", ["value"] = "d" }),
            ["metrics"] = new JsonObject { ["cvssMetricV31"] = new JsonArray(new JsonObject { ["cvssData"] = new JsonObject { ["baseScore"] = score } }) },
            ["configurations"] = new JsonArray(new JsonObject
            {
                ["nodes"] = new JsonArray(new JsonObject { ["cpeMatch"] = new JsonArray([.. matches.Select(x => (JsonNode)x.DeepClone())]) }),
            }),
        },
    };

    [Fact]
    public void ParseCveAndPagedFetch()
    {
        var ok = new JsonObject { ["vulnerable"] = true, ["criteria"] = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", ["versionEndExcluding"] = "131.0" };
        var other = new JsonObject { ["vulnerable"] = true, ["criteria"] = "cpe:2.3:a:google:android:*:*:*:*:*:*:*:*" };
        var notVuln = new JsonObject { ["vulnerable"] = false, ["criteria"] = "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*" };
        var rec = Vulns.ParseCve(Item("CVE-1", 8.8, ok, other, notVuln), "google", "chrome")!;
        Assert.Equal("CVE-1", rec.Cve);
        Assert.Equal(8.8, rec.Score);
        Assert.Equal("2026-01-01", rec.Published);
        Assert.Equal([M(null, null, null, "131.0", null)], rec.Matches);
        Assert.Null(Vulns.ParseCve(Item("CVE-2", 5, other), "google", "chrome"));

        var pages = new Dictionary<int, JsonObject>
        {
            [0] = new() { ["totalResults"] = 3, ["vulnerabilities"] = new JsonArray(Item("CVE-1", 8.8, ok), Item("CVE-2", 5, other)) },
            [2] = new() { ["totalResults"] = 3, ["vulnerabilities"] = new JsonArray(Item("CVE-3", 9.1, ok)) },
        };
        var calls = new List<string>();
        var naps = new List<double>();
        JsonNode? Get(string url)
        {
            calls.Add(url);
            if (calls.Count == 1) throw new HttpRequestException("429");          // throttled once: retried
            return pages[int.Parse(url[(url.LastIndexOf("startIndex=", StringComparison.Ordinal) + 11)..])].DeepClone();
        }
        var got = Vulns.FetchProduct("google", "chrome", Get, pause: 0, sleep: naps.Add, pageSize: 2);
        Assert.Equal(["CVE-1", "CVE-3"], got.Select(r => r.Cve));
        Assert.Equal(3, calls.Count);
        Assert.NotEmpty(naps);
        Assert.Throws<HttpRequestException>(() => Vulns.FetchProduct("google", "chrome", _ => throw new HttpRequestException("503"),
                                                                     pause: 0, sleep: _ => { }));
    }

    [Fact]
    public void NvdUrlEscapesCpeSpecialCharacters()
    {
        var urls = new List<string>();
        Vulns.FetchProduct("notepad-plus-plus", @"notepad\+\+", u =>
        {
            urls.Add(u);
            return new JsonObject { ["totalResults"] = 0 };
        }, sleep: _ => { });
        Assert.Contains("notepad%5C%2B%5C%2B", urls[0]);
        Assert.DoesNotContain("+", urls[0].Split('?', 2)[1]);
        Assert.Contains("cpe:2.3:a:notepad-plus-plus:", urls[0]);
    }

    [Fact]
    public void KevParse()
    {
        var kev = Vulns.FetchKev(_ => JsonNode.Parse("""{"vulnerabilities": [{"cveID": "CVE-9"}, {"x": 1}]}"""));
        Assert.Equal(["CVE-9"], kev);
    }
}
