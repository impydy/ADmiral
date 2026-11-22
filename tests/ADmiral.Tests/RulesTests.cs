using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

public class RulesTests
{
    private static readonly Dictionary<string, object?> Pc = new()
    {
        ["name"] = "LT-001", ["ou"] = "corp.local/Workstations/Laptops", ["os"] = "Windows 11 Enterprise",
        ["tags"] = new List<string> { "Pilot" }, ["online"] = true, ["enabled"] = true, ["stale"] = false,
        ["last_logon_days"] = 3, ["open_ports"] = new List<int> { 445, 5985 },
        ["inventory"] = new Dictionary<string, object?> { ["c_free_gb"] = 10.5, ["model"] = "Latitude 7440" },
        ["member_of"] = new List<string> { "CN=Pilot Users,OU=Groups,DC=corp,DC=local" },
        ["uptime_s"] = 3 * 86400,
    };

    private static RuleSet R(string match, params (string Field, string Op, object? Value)[] conds) =>
        Rules.Validate(new Dictionary<string, object?>
        {
            ["match"] = match,
            ["conditions"] = conds.Select(c => (object?)new Dictionary<string, object?>
            {
                ["field"] = c.Field, ["op"] = c.Op, ["value"] = c.Value,
            }).ToList(),
        });

    public static TheoryData<string, string, object?, bool> Conditions => new()
    {
        { "ou", "contains", "workstations", true },
        { "name", "glob", "lt-*", true },
        { "name", "glob", "DT-*", false },
        { "name", "glob", "lt-00[0-9]", true },
        { "name", "glob", "lt-00[!1]", false },
        { "os", "regex", "Windows 1[01]", true },
        { "tag", "has", "pilot", true },
        { "tag", "not_has", "pilot", false },
        { "online", "is", "true", true },
        { "winrm", "is", true, true },
        { "last_logon_days", "lt", "7", true },
        { "c_free_gb", "lt", 15, true },
        { "model", "startswith", "Latitude", true },
        { "description", "empty", null, true },
        { "ad_group", "has", "pilot users", true },
        { "uptime_days", "gte", 3, true },
        { "stale", "is", "no", true },
    };

    [Theory]
    [MemberData(nameof(Conditions))]
    public void Conditions_match(string field, string op, object? value, bool expected) =>
        Assert.Equal(expected, Rules.Matches(Pc, R("all", (field, op, value))));

    [Fact]
    public void Any_vs_all()
    {
        Assert.True(Rules.Matches(Pc, R("any", ("name", "equals", "nope"), ("online", "is", true))));
        Assert.False(Rules.Matches(Pc, R("all", ("name", "equals", "nope"), ("online", "is", true))));
    }

    [Theory]
    [InlineData("""{"conditions": []}""")]
    [InlineData("""{"conditions": [{"field": "nope", "op": "equals", "value": "x"}]}""")]
    [InlineData("""{"conditions": [{"field": "name", "op": "lt", "value": "x"}]}""")]
    [InlineData("""{"conditions": [{"field": "name", "op": "equals", "value": ""}]}""")]
    [InlineData("""{"conditions": [{"field": "last_logon_days", "op": "lt", "value": "abc"}]}""")]
    [InlineData("""{"conditions": [{"field": "name", "op": "regex", "value": "("}]}""")]
    [InlineData("""{"match": "some", "conditions": [{"field": "name", "op": "equals", "value": "x"}]}""")]
    [InlineData("""[1, 2]""")]
    [InlineData("""{"conditions": [5]}""")]
    public void Validation_rejects(string json) =>
        Assert.Throws<RuleError>(() => Rules.Validate(JsonNode.Parse(json)));

    [Fact]
    public void Validated_rules_roundtrip_through_json()
    {
        var rs = Rules.Validate(JsonNode.Parse("""
            {"conditions": [{"field": "last_logon_days", "op": "lt", "value": "7"},
              {"field": "online", "op": "is", "value": "yes"}, {"field": "name", "op": "glob", "value": "LT-*"}]}
            """));
        Assert.Equal("all", rs.Match);
        Assert.Equal(7.0, rs.Conditions[0].Value);
        Assert.Equal(true, rs.Conditions[1].Value);
        var again = Rules.Parse(rs.ToJson());
        Assert.True(Rules.Matches(Pc, again));
    }

    [Fact]
    public void Regex_conditions_cannot_hang()
    {
        var evil = new Dictionary<string, object?> { ["name"] = new string('a', 30000) + "!" };
        var rs = R("all", ("name", "regex", "^(a+)+$"));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(Rules.Matches(evil, rs));                     // the match times out and counts as "no match"
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Glob_does_not_backtrack_exponentially()
    {
        var evil = new Dictionary<string, object?> { ["name"] = new string('a', 5000) };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(Rules.Matches(evil, R("all", ("name", "glob", string.Concat(Enumerable.Repeat("*a", 40)) + "b"))));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Schema_lists_fields_and_ops()
    {
        var s = Rules.Schema();
        Assert.Contains(s.Fields, f => f.Field == "app" && f.Type == "list");
        Assert.Equal(["equals", "not_equals", "contains"], s.Ops["string"].Take(3));
        Assert.Equal(["empty", "not_empty"], s.NoValueOps);
        var json = System.Text.Json.JsonSerializer.Serialize(s);
        Assert.Contains("\"no_value_ops\"", json);
    }
}
