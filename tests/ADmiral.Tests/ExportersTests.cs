using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using ADmiral.Core;

namespace ADmiral.Tests;

public class ExportersTests
{
    private static List<Dictionary<string, object?>> Computers() =>
    [
        new()
        {
            ["name"] = "PC1", ["dns_hostname"] = "pc1.corp.local", ["online"] = true, ["tags"] = new List<string> { "a", "b" },
            ["inventory"] = new JsonObject { ["model"] = "Latitude, 7440", ["memory_gb"] = 16.0 }, ["stale"] = false,
        },
        new() { ["name"] = "O'Brien-PC", ["dns_hostname"] = null, ["online"] = null, ["tags"] = new List<string>() },
    ];

    [Fact]
    public void TxtAndPs1()
    {
        Assert.Equal("pc1.corp.local\nO'Brien-PC\n", Exporters.Export(Computers(), "txt"));
        var ps = Exporters.Export(Computers(), "ps1");
        Assert.Contains("'O''Brien-PC'", ps);
        Assert.StartsWith("# 2 target(s) exported by ADmiral", ps);
        Assert.Equal("a’’b", Exporters.PsQuote("a’b"));
        Assert.Equal("ab", Exporters.PsQuote("a\nb"));
    }

    [Fact]
    public void CsvMergesInventoryAndQuotes()
    {
        var lines = Exporters.Export(Computers(), "csv").Split("\r\n");
        Assert.Equal(string.Join(",", Exporters.CsvColumns), lines[0]);
        Assert.StartsWith("PC1,pc1.corp.local,,True,", lines[1]);
        Assert.Contains("\"Latitude, 7440\"", lines[1]);
        Assert.Contains(",a;b,", lines[1]);
        Assert.Contains(",16,", lines[1].Replace(",16.0,", ",16,"));
    }

    [Theory]
    [InlineData("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\"")]
    [InlineData("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0")]
    [InlineData("@SUM(1)", "'@SUM(1)")]
    [InlineData("-2+3", "'-2+3")]
    [InlineData("\tx", "'\tx")]
    [InlineData("-12.5", "-12.5")]                                    // a plain number stays a number
    [InlineData("Latitude 7440", "Latitude 7440")]
    [InlineData("", "")]
    public void CsvCellsNeverStartAFormula(string value, string expected) => Assert.Equal(expected, Exporters.CsvField(value));

    [Fact]
    public void JsonAndAnsible()
    {
        using var doc = JsonDocument.Parse(Exporters.Export(Computers(), "json"));
        Assert.Equal(2, doc.RootElement.GetArrayLength());
        var ini = Exporters.Export(Computers(), "ansible", "2nd floor!");
        Assert.StartsWith("[fleet_2nd_floor]\npc1.corp.local\nO'Brien-PC\n\n[fleet_2nd_floor:vars]", ini);
        Assert.StartsWith("[targets]", Exporters.Export(Computers(), "ansible", "!!"));
        Assert.Throws<ArgumentException>(() => Exporters.Export(Computers(), "exe"));
    }

    [Fact]
    public void XlsxIsAValidZipWithEscapedCells()
    {
        var bytes = Exporters.XlsxBytes(["Name", "Count"], [["<b>&\u0001", 3], [null, 2.5], [true, ""]], "Sheet \"1\"");
        using var zip = new ZipArchive(new MemoryStream(bytes));
        Assert.Contains(zip.Entries, e => e.FullName == "xl/worksheets/sheet1.xml");
        using var reader = new StreamReader(zip.GetEntry("xl/worksheets/sheet1.xml")!.Open());
        var xml = reader.ReadToEnd();
        Assert.Contains("&lt;b&gt;&amp;", xml);
        Assert.False(xml.Contains('\u0001'));
        Assert.Contains("<v>3</v>", xml);
        Assert.Contains("<v>2.5</v>", xml);
        Assert.Contains("<c r=\"A1\" s=\"1\" t=\"inlineStr\">", xml);
        _ = System.Xml.Linq.XDocument.Parse(xml);
        using var wb = new StreamReader(zip.GetEntry("xl/workbook.xml")!.Open());
        _ = System.Xml.Linq.XDocument.Parse(wb.ReadToEnd());
    }
}
