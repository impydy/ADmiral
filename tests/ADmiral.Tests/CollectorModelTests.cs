using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

public class CollectorModelTests
{
    [Theory]
    [InlineData("CORP", "anna", true)]
    [InlineData("CORP", "PC1$", false)]
    [InlineData("NT AUTHORITY", "x", false)]
    [InlineData("Window Manager", "DWM-3", false)]
    [InlineData("CORP", "UMFD-0", false)]
    [InlineData("CORP", "SYSTEM", false)]
    [InlineData("", "", false)]
    public void RealUser(string domain, string user, bool expected) => Assert.Equal(expected, CollectorModel.RealUser(domain, user));

    [Fact]
    public void CleanLogonsFiltersDeduplicatesAndSorts()
    {
        var rows = new JsonNode?[]
        {
            new JsonObject { ["time"] = "2026-01-01T08:00:00", ["user"] = "anna ", ["domain"] = "CORP", ["type"] = 2, ["ip"] = "-" },
            new JsonObject { ["time"] = "2026-01-02T08:00:00", ["user"] = "bela", ["domain"] = "CORP", ["type"] = "10", ["ip"] = "10.0.0.5" },
            new JsonObject { ["time"] = "2026-01-01T08:00:00", ["user"] = "ANNA", ["domain"] = "corp", ["type"] = 2 },     // duplicate
            new JsonObject { ["time"] = "2026-01-03T08:00:00", ["user"] = "svc", ["domain"] = "CORP", ["type"] = 5 },       // service logon
            new JsonObject { ["time"] = "", ["user"] = "x", ["domain"] = "CORP", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-01-03T08:00:00", ["user"] = "PC1$", ["domain"] = "CORP", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-01-03T08:00:00", ["user"] = "x", ["domain"] = "CORP", ["type"] = "nope" },
            JsonValue.Create(3), null,
        };
        var clean = CollectorModel.CleanLogons(rows);
        Assert.Equal(2, clean.Count);
        Assert.Equal("bela", (string?)clean[0]["user"]);
        Assert.Equal(10, (int)clean[0]["type"]!);
        Assert.Equal("anna", (string?)clean[1]["user"]);
        Assert.Equal("", (string?)clean[1]["ip"]);
    }

    [Theory]
    [InlineData(@"PC1\admin", "PC1", true)]
    [InlineData(@"pc1\admin", "PC1", true)]
    [InlineData(@".\admin", "PC1", true)]
    [InlineData(@"CORP\anna", "PC1", false)]
    [InlineData("anna", "PC1", false)]
    [InlineData(@"PC1\admin", null, false)]
    public void LocalAccountName(string account, string? computer, bool expected) =>
        Assert.Equal(expected, CollectorModel.IsLocalAccountName(account, computer));

    [Fact]
    public void CleanLogonsDropsLocalAccountsOfTheComputer()
    {
        var rows = new JsonNode?[]
        {
            new JsonObject { ["time"] = "2026-01-01T08:00:00", ["user"] = "anna", ["domain"] = "CORP", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-01-02T08:00:00", ["user"] = "admin", ["domain"] = "pc1", ["type"] = 2 },
            new JsonObject { ["time"] = "2026-01-03T08:00:00", ["user"] = "helyi", ["domain"] = ".", ["type"] = 2 },
        };
        Assert.Equal(["anna"], CollectorModel.CleanLogons(rows, "PC1").Select(l => (string?)l["user"]));
        Assert.Equal(3, CollectorModel.CleanLogons(rows).Count);      // without the computer's name nothing is known to be local
    }

    [Fact]
    public void CleanLogonsIsCapped()
    {
        var rows = Enumerable.Range(0, 400).Select(i => (JsonNode?)new JsonObject
        {
            ["time"] = $"2026-01-01T00:{i / 60:00}:{i % 60:00}", ["user"] = "u", ["domain"] = "d", ["type"] = 2,
        });
        var clean = CollectorModel.CleanLogons(rows);
        Assert.Equal(CollectorModel.MaxLogons, clean.Count);
        Assert.Equal("2026-01-01T00:06:39", (string?)clean[0]["time"]);
    }
}
