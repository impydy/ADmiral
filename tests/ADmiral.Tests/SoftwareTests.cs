using ADmiral.Core;

namespace ADmiral.Tests;

public class SoftwareTests
{
    [Fact]
    public void BaseNameRemovesVersions()
    {
        Assert.Equal("7-Zip (x64)", Software.BaseName("7-Zip 24.09 (x64)", "24.09"));
        Assert.Equal("7-Zip (x64)", Software.BaseName("7-Zip 23.01 (x64)", "23.01"));
        Assert.Equal("Google Chrome", Software.BaseName("Google Chrome", "131.0.6778.86"));
        Assert.Equal("Microsoft Visual C++ 2015-2022 Redistributable (x64)",
                     Software.BaseName("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", "14.40.33810.0"));
        Assert.Equal("Notepad++ (64-bit x64)", Software.BaseName("Notepad++ (64-bit x64)", "8.7.1"));
        Assert.Equal("Tool", Software.BaseName("Tool v1.2.3"));
        Assert.Equal("1.2", Software.BaseName("1.2"));              // nothing left: the original name
    }

    [Fact]
    public void AggregateCountsVersionsPerDevice()
    {
        var rows = new[]
        {
            ("a", "7-Zip 24.09 (x64)", "24.09", "Igor Pavlov"), ("b", "7-Zip 23.01 (x64)", "23.01", "Igor Pavlov"),
            ("c", "7-Zip 24.09 (x64)", "24.09", "Igor Pavlov"), ("a", "Chrome", "1.0", "G"), ("d", "", "1", "x"),
        };
        var agg = Software.Aggregate(rows);
        var z = agg["7-zip (x64)"];
        Assert.Equal(["a", "b", "c"], z.Devices.Order());
        Assert.Equal("Igor Pavlov", z.Publisher);
        Assert.Equal([("24.09", 2), ("23.01", 1)], Software.SortedVersions(z.Versions));
        Assert.Equal(2, Software.ListRow(z).VersionCount);
        Assert.Equal(2, agg.Count);
    }

    [Fact]
    public void MostCommonSpellingAndUnknownVersion()
    {
        var agg = Software.Aggregate([("a", "Foo Bar", "", ""), ("b", "foo bar", " ", "P"), ("c", "foo bar", "2.0", "P")]);
        var e = agg["foo bar"];
        Assert.Equal("foo bar", e.Name);
        Assert.Equal("P", e.Publisher);
        Assert.Contains("?", e.Versions.Keys);
    }

    [Fact]
    public void VersionKeyAndOrdering()
    {
        Assert.Equal([131L, 0, 6778, 86], Software.VersionKey("131.0.6778.86"));
        Assert.Empty(Software.VersionKey("beta"));
        Assert.Empty(Software.VersionKey(null));
        Assert.Equal(8, Software.VersionKey("1.2.3.4.5.6.7.8.9.10").Length);
        Assert.True(Software.CompareVersions("10.0", "9.9") > 0);
        Assert.True(Software.CompareVersions("1.2", "1.2.1") < 0);
        // same device count: the newer version first; a shorter key counts as "newer" like the Python sort key
        var versions = new Dictionary<string, HashSet<string>>
        {
            ["1.2"] = ["a"], ["1.10"] = ["b"], ["1.2.3"] = ["c"], ["0.9"] = ["d", "e"],
        };
        Assert.Equal(["0.9", "1.10", "1.2", "1.2.3"], Software.SortedVersions(versions).Select(v => v.Version));
    }

    [Fact]
    public void ListRowShowsTheTopFiveVersions()
    {
        var rows = Enumerable.Range(1, 7).Select(i => ($"g{i}", $"App {i}.0", $"{i}.0", "Acme"));
        var row = Software.ListRow(Software.Aggregate(rows)["app"]);
        Assert.Equal(7, row.Devices);
        Assert.Equal(7, row.VersionCount);
        Assert.Equal(5, row.Versions.Count);
        Assert.Equal("7.0", row.Versions[0].Version);
    }
}
