using System.Collections;
using System.Globalization;
using System.IO.Compression;
using System.Security;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Text.Unicode;

namespace ADmiral.Core;

/// <summary>Turn a list of computers into deployment-tool friendly target lists (port of admiral/exporters.py).</summary>
public static partial class Exporters
{
    /// <summary>format -> (content type, description).</summary>
    public static readonly IReadOnlyDictionary<string, (string ContentType, string Description)> Formats =
        new Dictionary<string, (string, string)>
        {
            ["txt"] = ("text/plain", "One hostname per line (PDQ, psexec, Invoke-Command -ComputerName (gc file))"),
            ["csv"] = ("text/csv", "Full inventory as CSV (Excel, SCCM/MECM collection import)"),
            ["json"] = ("application/json", "Full records as JSON"),
            ["ansible"] = ("text/plain", "Ansible INI inventory with WinRM connection vars"),
            ["ps1"] = ("text/plain", "PowerShell array you can paste or dot-source"),
        };

    public static readonly IReadOnlyList<string> CsvColumns =
    [
        "name", "dns_hostname", "ip", "online", "os", "os_version", "ou", "enabled", "last_logon", "stale", "tags",
        "manufacturer", "model", "serial", "os_display_version", "memory_gb", "c_free_gb", "pending_reboot", "dn",
    ];

    private static readonly JsonSerializerOptions JsonOut = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    [GeneratedRegex("[^A-Za-z0-9_]")]
    private static partial Regex NonIdent();

    [GeneratedRegex(@"[\x00-\x08\x0b\x0c\x0e-\x1f]")]
    private static partial Regex XmlInvalid();

    private static string Host(IReadOnlyDictionary<string, object?> c) =>
        c.GetValueOrDefault("dns_hostname") is { } h && Text(h) is { Length: > 0 } s ? s : Text(c.GetValueOrDefault("name"));

    /// <summary>A value as text the way Python's str() shows it (None -> "", True -> "True").</summary>
    private static string Text(object? v) => v switch
    {
        null => "",
        string s => s,
        bool b => b ? "True" : "False",
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        float f => f.ToString("R", CultureInfo.InvariantCulture),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        JsonValue jv => jv.GetValueKind() switch
        {
            JsonValueKind.String => jv.GetValue<string>(),
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            JsonValueKind.Null => "",
            _ => jv.ToJsonString(),
        },
        JsonNode n => n.ToJsonString(),
        IEnumerable e => "[" + string.Join(", ", e.Cast<object?>().Select(Text)) + "]",
        _ => v.ToString() ?? "",
    };

    private static string CsvField(string s) =>
        s.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    /// <summary>Export <paramref name="computers"/> (rows of <see cref="Store.Computers"/>) in a format of
    /// <see cref="Formats"/>; an unknown format raises <see cref="ArgumentException"/>.</summary>
    public static string Export(IReadOnlyList<IReadOnlyDictionary<string, object?>> computers, string fmt, string groupName = "targets")
    {
        switch (fmt)
        {
            case "txt":
                return string.Concat(computers.Select(c => Host(c) + "\n"));
            case "csv":
            {
                var sb = new StringBuilder();
                sb.Append(string.Join(",", CsvColumns.Select(CsvField))).Append("\r\n");
                foreach (var c in computers)
                {
                    var row = new Dictionary<string, object?>(c);
                    if (c.GetValueOrDefault("inventory") is JsonObject inv)
                        foreach (var (k, v) in inv) row[k] = v;
                    row["tags"] = c.GetValueOrDefault("tags") is IEnumerable t and not string
                        ? string.Join(";", t.Cast<object?>().Select(Text)) : "";
                    sb.Append(string.Join(",", CsvColumns.Select(col => CsvField(Text(row.GetValueOrDefault(col)))))).Append("\r\n");
                }
                return sb.ToString();
            }
            case "json":
                return JsonSerializer.Serialize(computers, JsonOut);
            case "ansible":
            {
                var group = NonIdent().Replace(groupName, "_").Trim('_').ToLowerInvariant();
                if (group.Length == 0) group = "targets";
                if (char.IsDigit(group[0])) group = "fleet_" + group;
                var lines = new List<string> { $"[{group}]" };
                lines.AddRange(computers.Select(Host));
                lines.AddRange(["", $"[{group}:vars]", "ansible_connection=winrm", "ansible_winrm_transport=ntlm", "ansible_port=5985", ""]);
                return string.Join("\n", lines);
            }
            case "ps1":
            {
                var items = string.Join(",\n", computers.Select(c => $"    '{PsQuote(Host(c))}'"));
                return $"# {computers.Count} target(s) exported by ADmiral\n$Targets = @(\n{items}\n)\n";
            }
            default:
                throw new ArgumentException($"Unknown export format '{fmt}'. Choose from: {string.Join(", ", Formats.Keys)}");
        }
    }

    /// <summary>Content of a PowerShell single-quoted string: every quote character PowerShell accepts (' and the
    /// typographic ‘ ’ ‚ ‛) doubled, control characters removed.</summary>
    public static string PsQuote(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (char.IsControl(ch)) continue;
            sb.Append(ch);
            if (ch is '\'' or '‘' or '’' or '‚' or '‛') sb.Append(ch);
        }
        return sb.ToString();
    }

    /// <summary>A minimal .xlsx workbook (one sheet, bold frozen header row) without any extra library.</summary>
    public static byte[] XlsxBytes(IReadOnlyList<string> header, IEnumerable<IReadOnlyList<object?>> rows, string sheet = "ADmiral")
    {
        static string Clean(object? v) => XmlInvalid().Replace(Text(v), "");

        static string Col(int i)
        {
            var s = "";
            i += 1;
            while (i > 0)
            {
                var r = (i - 1) % 26;
                i = (i - 1) / 26;
                s = (char)('A' + r) + s;
            }
            return s;
        }

        static string Cell(int r, int c, object? v, int style = 0)
        {
            var reference = $"{Col(c)}{r}";
            if (v is JsonValue jv)
                v = jv.GetValueKind() switch
                {
                    JsonValueKind.String => jv.GetValue<string>(),
                    JsonValueKind.Number => jv.TryGetValue<long>(out var l) ? l : double.Parse(jv.ToJsonString(), CultureInfo.InvariantCulture),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    _ => null,
                };
            if (v is bool || v is null || v is "")
                return style != 0 ? $"<c r=\"{reference}\" s=\"{style}\"/>" : "";
            if (v is int or long or short or byte or uint or ulong or decimal
                || (v is double d && double.IsFinite(d)) || (v is float f && float.IsFinite(f)))
                return $"<c r=\"{reference}\" s=\"{style}\"><v>{Text(v)}</v></c>";
            return $"<c r=\"{reference}\" s=\"{style}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{SecurityElement.Escape(Clean(v))}</t></is></c>";
        }

        var lines = new List<string> { string.Concat(header.Select((h, c) => Cell(1, c, h, 1))) };
        lines.AddRange(rows.Select((r, i) => string.Concat(r.Select((v, c) => Cell(i + 2, c, v)))));
        var data = string.Concat(lines.Select((x, i) => $"<row r=\"{i + 1}\">{x}</row>"));
        var widths = string.Concat(header.Select((h, c) =>
            $"<col min=\"{c + 1}\" max=\"{c + 1}\" width=\"{Math.Min(60, Math.Max(10, Clean(h).Length + 4))}\" customWidth=\"1\"/>"));
        const string ns = "xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"";
        var sheetName = SecurityElement.Escape(new string(Clean(sheet).Take(31).ToArray()));
        var parts = new Dictionary<string, string>
        {
            ["[Content_Types].xml"] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/></Types>",
            ["_rels/.rels"] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>",
            ["xl/workbook.xml"] = $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><workbook {ns} xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"{sheetName}\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
            ["xl/_rels/workbook.xml.rels"] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>",
            ["xl/styles.xml"] = $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><styleSheet {ns}><fonts count=\"2\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts><fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills><borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"2\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/></cellXfs></styleSheet>",
            ["xl/worksheets/sheet1.xml"] = $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><worksheet {ns}><sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews><cols>{widths}</cols><sheetData>{data}</sheetData></worksheet>",
        };
        if (header.Count == 0)                 // an empty <cols/> is invalid in the schema
            parts["xl/worksheets/sheet1.xml"] = parts["xl/worksheets/sheet1.xml"].Replace("<cols></cols>", "", StringComparison.Ordinal);
        using var buf = new MemoryStream();
        using (var zip = new ZipArchive(buf, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, xml) in parts)
            {
                var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var s = entry.Open();
                var bytes = new UTF8Encoding(false).GetBytes(xml);
                s.Write(bytes, 0, bytes.Length);
            }
        }
        return buf.ToArray();
    }
}
