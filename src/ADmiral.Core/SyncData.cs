// Port of admiral/syncdata.py: the data ADmiral instances exchange (computers, collections, AD users, printers)
// and how it is merged.
//
// Merge rule: per record the newer timestamp wins (computers: the newest scan / collection / AD read; collections:
// "updated"; users: "synced_at"; printers: "updated" for the hand-edited fields, "polled" for the readings). Tags are
// only ever added. Nothing is deleted by a synchronisation, and the settings (passwords, AD account...) are never part
// of it. A timestamp more than <see cref="FutureSkew"/> (10 minutes of clock skew) in the future is not believed (it
// would win every later merge) - Python allowed a day and checked computers only; here it applies to every category.
// Every peer value is type-checked before it reaches SQL.
//
// Where ADmiral connects with the administrative account is this instance's own AD's business: a peer never changes the
// host / DN / name of a known computer, never switches scanning on or off, and a computer that only a peer knows is
// stored with allow_scan = 0 (listed in sync_unconfirmed) - it is not scanned, collected or retried until this
// instance's own AD synchronisation reads the same GUID; a trigger then re-enables scanning (host, DN and name are
// AD's by then: UpsertFromAd overwrites them). Once confirmed, everything AD says about a computer (OU, OS, enabled,
// groups, SID...) is this AD's word only.
//
// Collections and tags still merge (that is what sync is for), but they decide where a deployment goes: a collection a
// peer created or changed (fleets.peer_changed) and a tag a peer added (tags.peer_added) are marked until someone edits
// them here, and the deployment confirmation lists them (AdmiralService.DeploymentPreview).

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Core;

public sealed class SyncData
{
    public static readonly IReadOnlyList<string> Categories = Config.SyncCategories;

    /// <summary>Most records one <see cref="Apply"/> call accepts.</summary>
    public const int MaxRecords = 500;

    private static readonly string[] TsCols = ["collected_at", "scanned_at", "ad_synced_at", "last_scan_attempt", "added"];

    /// <summary>Columns of a known computer a peer never overwrites: they decide which host the administrative account
    /// is sent to, so only this instance's own AD synchronisation changes them.</summary>
    private static readonly string[] LocalCols = ["dns_hostname", "dn", "name"];
    /// <summary>Columns of a computer this instance's AD has confirmed that only that AD sync writes: what AD says about
    /// it (OU, OS, enabled, groups...) decides dynamic-collection membership and so where a deployment goes, so a peer's
    /// copy never overrides it. A computer only a peer knows (not confirmed yet) keeps the peer's values until then.</summary>
    private static readonly string[] AdOwnedCols = [.. Db.AdFields, "ad_synced_at"];

    /// <summary>Columns a peer never sets on any computer: whether this instance scans a computer is decided here, and
    /// the account SID the drop-folder owner check trusts comes only from this instance's own AD.</summary>
    private static readonly string[] NeverFromPeer = ["allow_scan", "sid"];

    /// <summary>How far in the future a peer's timestamp may be (clock skew).</summary>
    public static readonly TimeSpan FutureSkew = TimeSpan.FromMinutes(10);

    /// <summary>Computers created from a peer's record that this instance's AD has not confirmed yet (scanning off).
    /// The trigger fires on UpsertFromAd's UPDATE (it always sets dn; a peer's merge never does, see LocalCols).</summary>
    private static readonly string[] QuarantineSchema =
    [
        """
        CREATE TABLE IF NOT EXISTS sync_unconfirmed (
            guid  TEXT PRIMARY KEY REFERENCES computers(guid) ON DELETE CASCADE,
            added TEXT NOT NULL
        )
        """,
        """
        CREATE TRIGGER IF NOT EXISTS sync_confirmed_by_ad AFTER UPDATE OF dn ON computers
        WHEN EXISTS (SELECT 1 FROM sync_unconfirmed WHERE guid = NEW.guid)
        BEGIN
            UPDATE computers SET allow_scan = 1 WHERE guid = NEW.guid;
            DELETE FROM sync_unconfirmed WHERE guid = NEW.guid;
        END
        """,
    ];

    /// <summary>The collected inventory: taken from a peer only when its collection is newer (<c>collected_at</c>).</summary>
    private static readonly HashSet<string> InventoryCols = ["inventory", "collected_at"];
    /// <summary>The last collection attempt: newer collection or newer attempt (<c>last_scan_attempt</c>).</summary>
    private static readonly HashSet<string> AttemptCols = ["collect_error", "scan_status", "last_scan_attempt"];
    /// <summary>The reachability scan: newer <c>scanned_at</c>.</summary>
    private static readonly HashSet<string> ScanCols = ["ip", "online", "open_ports", "scanned_at"];

    private static JsonNode? Parse(string data)
    {
        try { return JsonNode.Parse(data); }
        catch (JsonException) { return null; }
    }

    private string LogonsOf(string guid) =>
        string.Join("\n", _store.Query("SELECT data FROM computer_items WHERE guid = ? AND kind = 'logons' ORDER BY pos", guid).Select(r => S(r["data"])));

    private static readonly string[] FleetCols = ["description", "kind", "rules", "ad_group_dn", "created", "updated"];

    private readonly Store _store;
    private readonly Func<Func<int>, int> _transaction;

    /// <param name="store">the database</param>
    /// <param name="transaction">runs one apply batch atomically. <see cref="Store"/> does not expose its transaction yet,
    /// so by default every statement commits on its own; the service should pass the store's transaction runner.</param>
    public SyncData(Store store, Func<Func<int>, int>? transaction = null)
    {
        _store = store;
        _transaction = transaction ?? (body => body());
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        foreach (var stmt in QuarantineSchema) _store.Execute(stmt);
    }

    /// <summary>GUIDs of computers a peer brought in that this instance's AD has not confirmed (not scanned).</summary>
    public HashSet<string> Unconfirmed() =>
        [.. _store.Query("SELECT guid FROM sync_unconfirmed").Select(r => S(r["guid"]))];

    /// <summary>Timestamps later than this (now + <see cref="FutureSkew"/>, ISO) are not believed.</summary>
    public static string Horizon(DateTimeOffset? now = null) =>
        Db.FormatUtc((now ?? DateTimeOffset.UtcNow).Add(FutureSkew));

    private static (string Ts, string Extra) Split(string value)
    {
        var i = (value ?? "").IndexOf('|', StringComparison.Ordinal);
        return i < 0 ? (value ?? "", "") : (value![..i], value[(i + 1)..]);
    }

    /// <summary>The collected_at part of a computer's manifest extra ("tags|collected_at"); null when there is none
    /// (other categories, or a peer before 0.6.2).</summary>
    private static string? Inventory(string extra)
    {
        var i = extra.IndexOf('|', StringComparison.Ordinal);
        return i < 0 ? null : extra[(i + 1)..];
    }

    /// <summary>(keys to pull from the peer, keys to push to it) for two manifests {key: "timestamp[|tag hash]"}.</summary>
    public static (List<string> Pull, List<string> Push) Plan(IReadOnlyDictionary<string, string> local, IReadOnlyDictionary<string, string> remote)
    {
        var pull = new List<string>();
        var push = new List<string>();
        foreach (var (key, rv) in remote)
        {
            if (!local.TryGetValue(key, out var lv))
            {
                pull.Add(key);
                continue;
            }
            if (lv == rv) continue;
            var (lt, lh) = Split(lv);
            var (rt, rh) = Split(rv);
            var c = string.CompareOrdinal(rt, lt);
            // computers: "ts|tags|collected_at". The side with the newer inventory sends it even when the other side's
            // record is newer as a whole (it saw the computer later but could not collect it)
            var li = Inventory(lh);
            var ri = Inventory(rh);
            var inv = li is not null && ri is not null ? string.CompareOrdinal(ri, li) : 0;
            if (c > 0 || inv > 0) pull.Add(key);
            if (c < 0 || inv < 0) push.Add(key);
            if (c == 0 && inv == 0 && lh != rh)       // same data, different tags: exchange both ways (union)
            {
                pull.Add(key);
                push.Add(key);
            }
        }
        push.AddRange(local.Keys.Where(k => !remote.ContainsKey(k)));
        return (pull, push);
    }

    private static string S(object? v) => v switch
    {
        null => "",
        string s => s,
        _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    private static string MaxTs(IReadOnlyDictionary<string, object?> row) =>
        TsCols.Select(c => row.TryGetValue(c, out var v) ? S(v) : "").Aggregate("", (a, b) => string.CompareOrdinal(a, b) >= 0 ? a : b);

    private static void CheckCategory(string cat)
    {
        if (!Categories.Contains(cat)) throw new ArgumentException($"unknown category '{cat}'");
    }

    // ------------------------------------------------------------------ manifests
    public Dictionary<string, string> Manifest(string cat)
    {
        CheckCategory(cat);
        var s = _store;
        var outp = new Dictionary<string, string>(StringComparer.Ordinal);
        switch (cat)
        {
            case "computers":
                var tags = new Dictionary<string, List<string>>(StringComparer.Ordinal);
                foreach (var r in s.Query("SELECT guid, tag FROM tags"))
                {
                    var g = S(r["guid"]);
                    if (!tags.TryGetValue(g, out var l)) tags[g] = l = [];
                    l.Add(S(r["tag"]));
                }
                foreach (var r in s.Query($"SELECT guid, {string.Join(", ", TsCols)} FROM computers"))
                {
                    var g = S(r["guid"]);
                    var list = tags.TryGetValue(g, out var l) ? l.Order(StringComparer.Ordinal) : Enumerable.Empty<string>();
                    var h = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", list))))[..16];
                    outp[g] = $"{MaxTs(r)}|{h}|{S(r["collected_at"])}";      // + when its inventory was collected
                }
                break;
            case "fleets":
                foreach (var r in s.Query("SELECT name, updated FROM fleets")) outp[S(r["name"])] = S(r["updated"]);
                break;
            case "users":
                foreach (var r in s.Query("SELECT key, synced_at FROM users")) outp[S(r["key"])] = S(r["synced_at"]);
                break;
            case "printers":                    // keys: "p:<ip>" the printer, "h:<ip>|<day>" one daily reading
                foreach (var r in s.Query("SELECT ip, updated, polled FROM printer")) outp[$"p:{S(r["ip"])}"] = $"{S(r["updated"])}|{S(r["polled"])}";
                foreach (var r in s.Query("SELECT ip, day, taken_at FROM printer_history")) outp[$"h:{S(r["ip"])}|{S(r["day"])}"] = S(r["taken_at"]);
                break;
        }
        return outp;
    }

    // ------------------------------------------------------------------ export
    private static JsonNode? ToNode(object? v) => v switch
    {
        null => null,
        string s => JsonValue.Create(s),
        long l => JsonValue.Create(l),
        int i => JsonValue.Create(i),
        double d => JsonValue.Create(d),
        bool b => JsonValue.Create(b),
        byte[] bytes => JsonValue.Create(Convert.ToBase64String(bytes)),
        _ => JsonValue.Create(S(v)),
    };

    private static JsonObject ToObject(Row row, params string[] drop)
    {
        var o = new JsonObject();
        foreach (var (k, v) in row)
            if (!drop.Contains(k)) o[k] = ToNode(v);
        return o;
    }

    public List<JsonObject> Export(string cat, IEnumerable<string> keys)
    {
        CheckCategory(cat);
        var s = _store;
        var outp = new List<JsonObject>();
        foreach (var key in keys)
        {
            switch (cat)
            {
                case "computers":
                {
                    var rows = s.Query("SELECT * FROM computers WHERE guid = ?", key);
                    if (rows.Count == 0) continue;
                    var items = new JsonArray();
                    foreach (var r in s.Query("SELECT kind, pos, data FROM computer_items WHERE guid = ? ORDER BY kind, pos", key))
                        items.Add(new JsonArray(ToNode(r["kind"]), ToNode(r["pos"]), ToNode(r["data"])));
                    var tagArr = new JsonArray();
                    foreach (var r in s.Query("SELECT tag FROM tags WHERE guid = ?", key)) tagArr.Add(ToNode(r["tag"]));
                    outp.Add(new JsonObject { ["row"] = ToObject(rows[0]), ["items"] = items, ["tags"] = tagArr });
                    break;
                }
                case "fleets":
                {
                    var rows = s.Query("SELECT * FROM fleets WHERE name = ?", key);
                    if (rows.Count == 0) continue;
                    var d = ToObject(rows[0], "id", "peer_changed");       // our own note, not the peer's business
                    var members = new JsonArray();
                    foreach (var r in s.Query("SELECT guid FROM fleet_members WHERE fleet_id = ?", rows[0]["id"])) members.Add(ToNode(r["guid"]));
                    d["members"] = members;
                    outp.Add(d);
                    break;
                }
                case "users":
                {
                    var rows = s.Query("SELECT key, data, synced_at FROM users WHERE key = ?", key);
                    if (rows.Count > 0) outp.Add(ToObject(rows[0]));
                    break;
                }
                case "printers":
                    if (key.StartsWith("p:", StringComparison.Ordinal))
                    {
                        var rows = s.Query("SELECT * FROM printer WHERE ip = ?", key[2..]);
                        if (rows.Count > 0) outp.Add(new JsonObject { ["printer"] = ToObject(rows[0], "id") });
                    }
                    else if (key.StartsWith("h:", StringComparison.Ordinal))
                    {
                        var rest = key[2..];
                        var bar = rest.LastIndexOf('|');
                        if (bar < 0) continue;
                        var rows = s.Query("SELECT * FROM printer_history WHERE ip = ? AND day = ?", rest[..bar], rest[(bar + 1)..]);
                        if (rows.Count > 0) outp.Add(new JsonObject { ["history"] = ToObject(rows[0]) });
                    }
                    break;
            }
        }
        return outp;
    }

    // ------------------------------------------------------------------ apply
    /// <summary>A scalar JSON value as SQLite gets it (true for ok); objects / arrays are refused.</summary>
    private static bool Scalar(JsonNode? n, out object? value)
    {
        value = null;
        switch (n)
        {
            case null:
                return true;
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.String: value = v.GetValue<string>(); return true;
                    case JsonValueKind.True: value = 1L; return true;
                    case JsonValueKind.False: value = 0L; return true;
                    case JsonValueKind.Null: return true;
                    case JsonValueKind.Number:
                        var raw = v.ToJsonString();
                        if (long.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l)) value = l;
                        else if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d)) value = d;
                        else return false;
                        return true;
                    default: return false;
                }
            default:
                return false;
        }
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    private static long? Long(JsonNode? n) => n is JsonValue v && v.GetValueKind() == JsonValueKind.Number
        && long.TryParse(v.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l) ? l : null;

    private static bool ValidJson(string text)
    {
        try
        {
            using var _ = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            return true;
        }
        catch (JsonException) { return false; }
    }

    /// <summary>Merge the peer's records into this database; returns how many records changed anything.</summary>
    public int Apply(string cat, IReadOnlyList<JsonNode?> records, DateTimeOffset? now = null)
    {
        CheckCategory(cat);
        if (records.Count > MaxRecords) throw new ArgumentException($"too many records ({records.Count}, at most {MaxRecords})");
        var horizon = Horizon(now);
        return _transaction(() => cat switch
        {
            "computers" => ApplyComputers(records, horizon),
            "fleets" => ApplyFleets(records, horizon),
            "users" => ApplyUsers(records, horizon),
            _ => ApplyPrinters(records, horizon),
        });
    }

    private bool Future(string ts, string horizon, string what, string name)
    {
        if (string.CompareOrdinal(ts, horizon) <= 0) return false;
        Log.Logger.LogWarning("Sync: ignored {What} {Name} with a future timestamp {Ts}", what, name, ts);
        return true;
    }

    private int ApplyComputers(IReadOnlyList<JsonNode?> records, string horizon)
    {
        var s = _store;
        var cols = s.Query("PRAGMA table_info(computers)").Select(r => S(r["name"])).ToHashSet(StringComparer.Ordinal);
        var unconfirmed = Unconfirmed();
        var n = 0;
        foreach (var rec in records)
        {
            if (rec?["row"] is not JsonObject rowIn) continue;
            var row = new Row(StringComparer.Ordinal);
            var bad = false;
            foreach (var (k, v) in rowIn)
            {
                if (!cols.Contains(k)) continue;
                if (!Scalar(v, out var value)) { bad = true; break; }
                row[k] = value;
            }
            if (bad || row.GetValueOrDefault("guid") is not string guid || guid.Length == 0
                || row.GetValueOrDefault("name") is not string { Length: > 0 } name) continue;
            var rts = MaxTs(row);
            if (Future(rts, horizon, "computer", name)) continue;
            var curRows = s.Query("SELECT * FROM computers WHERE guid = ?", guid);
            var cur = curRows.Count > 0 ? curRows[0] : null;
            if (cur is not null)                           // where ADmiral connects (with the admin account) is AD's business
            {
                foreach (var k in LocalCols) row.Remove(k);
                if (!unconfirmed.Contains(guid))
                    foreach (var k in AdOwnedCols) row.Remove(k);
            }
            foreach (var k in NeverFromPeer) row.Remove(k);
            // validate the items before anything is written
            var items = new List<(string Kind, long Pos, string Data)>();
            foreach (var it in rec["items"] as JsonArray ?? [])
            {
                if (it is not JsonArray { Count: 3 } a || Str(a[0]) is not { } kind || Long(a[1]) is not { } pos || Str(a[2]) is not { } data)
                {
                    bad = true;
                    break;
                }
                items.Add((kind, pos, data));
            }
            if (bad) continue;
            var changed = false;
            if (cur is null)
            {
                // only a peer knows it: its host name is the peer's word - no scan / collection / retry until our AD has it
                var names = row.Keys.ToList();             // column names: only ones PRAGMA table_info listed
                if (cols.Contains("allow_scan"))
                {
                    row["allow_scan"] = 0L;
                    names.Add("allow_scan");
                }
                s.Execute($"INSERT INTO computers ({string.Join(", ", names)}) VALUES ({string.Join(", ", names.Select(_ => "?"))})",
                          [.. names.Select(k => row[k])]);
                s.Execute("INSERT OR IGNORE INTO sync_unconfirmed (guid, added) VALUES (?, ?)", guid, Db.UtcNow());
                foreach (var (kind, pos, data) in items)
                    s.Execute("INSERT OR REPLACE INTO computer_items (guid, kind, pos, data) VALUES (?, ?, ?, ?)", guid, kind, pos, data);
                if (Log.Logger.IsEnabled(LogLevel.Information))
                    Log.Logger.LogInformation("Sync: new computer {Name} from a peer; not scanned until this instance's AD sync lists it", name);
                changed = true;
            }
            else
            {
                // every part of the record goes by its own time: a peer that saw the computer later (AD sync, a failed
                // attempt) but never collected it must not replace an older inventory with nothing
                bool Newer(string col) => row.ContainsKey(col) && string.CompareOrdinal(S(row[col]), cur.TryGetValue(col, out var v) ? S(v) : "") > 0;
                var takeInventory = Newer("collected_at");
                var takeAttempt = takeInventory || Newer("last_scan_attempt");
                var takeScan = Newer("scanned_at");
                var takeRest = string.CompareOrdinal(rts, MaxTs(cur)) > 0;
                var sets = row.Keys.Where(k => k != "guid" && (
                    InventoryCols.Contains(k) ? takeInventory
                    : AttemptCols.Contains(k) ? takeAttempt
                    : ScanCols.Contains(k) ? takeScan
                    : takeRest)).ToList();
                if (sets.Count > 0)
                {
                    s.Execute($"UPDATE computers SET {string.Join(", ", sets.Select(k => k + " = ?"))} WHERE guid = ?",
                              [.. sets.Select(k => row[k]), guid]);
                    changed = true;
                }
                if (takeInventory)
                {
                    s.Execute("DELETE FROM computer_items WHERE guid = ? AND kind <> 'logons'", guid);
                    foreach (var (kind, pos, data) in items.Where(i => i.Kind != "logons"))
                        s.Execute("INSERT OR REPLACE INTO computer_items (guid, kind, pos, data) VALUES (?, ?, ?, ?)", guid, kind, pos, data);
                }
                // the logon history is merged (never replaced): both sides may have seen other logons
                var logons = items.Where(i => i.Kind == "logons").Select(i => Parse(i.Data)).Where(n => n is not null).ToList();
                if (logons.Count > 0)
                {
                    var before = LogonsOf(guid);
                    s.AddLogons(guid, logons);
                    changed |= LogonsOf(guid) != before;
                }
            }
            foreach (var t in rec["tags"] as JsonArray ?? [])
                if (Str(t) is { Length: > 0 } tag)
                    changed |= s.Execute("INSERT OR IGNORE INTO tags (guid, tag, peer_added) VALUES (?, ?, ?)", guid, tag, Db.UtcNow()) > 0;
            if (changed) n++;
        }
        return n;
    }

    private int ApplyFleets(IReadOnlyList<JsonNode?> records, string horizon)
    {
        var s = _store;
        var n = 0;
        foreach (var rec in records)
        {
            if (rec is not JsonObject o || Str(o["name"]) is not { Length: > 0 } name || Str(o["kind"]) is not ("static" or "dynamic")) continue;
            if (Str(o["created"]) is null || Str(o["updated"]) is not { } updated || Future(updated, horizon, "collection", name)) continue;
            var vals = new object?[FleetCols.Length];
            var bad = false;
            for (var i = 0; i < FleetCols.Length; i++)
            {
                var v = o[FleetCols[i]];
                if (v is not null && Str(v) is null && !(v is JsonValue jv && jv.GetValueKind() == JsonValueKind.Null)) { bad = true; break; }
                vals[i] = Str(v);
            }
            if (bad) continue;
            vals[Array.IndexOf(FleetCols, "description")] ??= "";
            var cur = s.Query("SELECT id, updated FROM fleets WHERE name = ?", name);
            long fid;
            if (cur.Count == 0)
            {
                s.Execute($"INSERT INTO fleets (name, {string.Join(", ", FleetCols)}, peer_changed) VALUES (?, {string.Join(", ", FleetCols.Select(_ => "?"))}, ?)",
                          [name, .. vals, Db.UtcNow()]);
                fid = (long)s.Scalar("SELECT id FROM fleets WHERE name = ?", name)!;
            }
            else if (string.CompareOrdinal(updated, S(cur[0]["updated"])) > 0)
            {
                fid = (long)cur[0]["id"]!;
                s.Execute($"UPDATE fleets SET {string.Join(", ", FleetCols.Select(k => k + " = ?"))}, peer_changed = ? WHERE id = ?", [.. vals, Db.UtcNow(), fid]);
                s.Execute("DELETE FROM fleet_members WHERE fleet_id = ?", fid);
            }
            else continue;
            foreach (var m in o["members"] as JsonArray ?? [])
                if (Str(m) is { Length: > 0 } g)
                    s.Execute("INSERT OR IGNORE INTO fleet_members (fleet_id, guid) SELECT ?, guid FROM computers WHERE guid = ?", fid, g);
            n++;
        }
        return n;
    }

    private int ApplyUsers(IReadOnlyList<JsonNode?> records, string horizon)
    {
        var n = 0;
        foreach (var rec in records)
        {
            if (Str(rec?["key"]) is not { Length: > 0 } key || Str(rec?["data"]) is not { } data || !ValidJson(data)) continue;
            var synced = Str(rec?["synced_at"]) ?? "";
            if (Future(synced, horizon, "user", key)) continue;
            n += _store.Execute(
                "INSERT INTO users (key, data, synced_at) VALUES (?, ?, ?) "
                + "ON CONFLICT(key) DO UPDATE SET data = excluded.data, synced_at = excluded.synced_at "
                + "WHERE excluded.synced_at > users.synced_at", key, data, synced);
        }
        return n;
    }

    private int ApplyPrinters(IReadOnlyList<JsonNode?> records, string horizon)
    {
        var s = _store;
        string[] cfg = ["model", "location", "note", "community", "version", .. Printers.OidFields];
        string[] state = ["toner", "pages", "serial", "status", "polled", "error"];
        var n = 0;
        foreach (var rec in records)
        {
            if (rec?["history"] is JsonObject h)
            {
                if (Str(h["ip"]) is not { Length: > 0 } hip || Str(h["day"]) is not { Length: > 0 } day || Str(h["toner"]) is not { } toner
                    || !ValidJson(toner)) continue;
                var taken = Str(h["taken_at"]) ?? "";
                if (Future(taken, horizon, "printer reading", hip)) continue;
                n += s.Execute(
                    "INSERT INTO printer_history (ip, day, taken_at, pages, toner) VALUES (?,?,?,?,?) "
                    + "ON CONFLICT(ip, day) DO UPDATE SET taken_at=excluded.taken_at, pages=excluded.pages, toner=excluded.toner "
                    + "WHERE excluded.taken_at > printer_history.taken_at", hip, day, taken, Long(h["pages"]), toner);
                continue;
            }
            if (rec?["printer"] is not JsonObject p) continue;
            string ip;
            var vals = new Dictionary<string, object?>(StringComparer.Ordinal);
            try
            {
                ip = Printers.ValidHost(Str(p["ip"]));
                if (Str(p["version"]) is not ("1" or "2c")) continue;
                foreach (var f in Printers.OidFields) vals[f] = Printers.CleanOids(f, Str(p[f]) ?? "");
                var tonerText = Str(p["toner"]) ?? (p["toner"] is null ? "[]" : null);
                if (tonerText is null || !ValidJson(tonerText)) continue;
                vals["toner"] = tonerText;
            }
            catch (PrinterError) { continue; }
            foreach (var k in cfg.Concat(state))
            {
                if (vals.ContainsKey(k)) continue;
                vals[k] = k switch
                {
                    "pages" => Long(p[k]),
                    "polled" => Str(p[k]),
                    _ => Str(p[k]) ?? "",
                };
            }
            var updated = Str(p["updated"]) ?? "";
            var polled = vals["polled"] as string ?? "";
            if (Future(updated, horizon, "printer", ip) || Future(polled, horizon, "printer", ip)) continue;
            var curRows = s.Query("SELECT * FROM printer WHERE ip = ?", ip);
            if (curRows.Count == 0)
            {
                string[] names = ["ip", .. cfg, .. state, "updated"];
                s.Execute($"INSERT INTO printer ({string.Join(", ", names)}) VALUES ({string.Join(", ", names.Select(_ => "?"))})",
                          [ip, .. cfg.Concat(state).Select(k => vals[k]), updated]);
                n++;
                continue;
            }
            var cur = curRows[0];
            var changed = false;
            if (string.CompareOrdinal(updated, S(cur["updated"])) > 0)         // the hand-edited fields: the newer edit wins
            {
                s.Execute($"UPDATE printer SET {string.Join(", ", cfg.Select(k => k + " = ?"))}, updated = ? WHERE id = ?",
                          [.. cfg.Select(k => vals[k]), updated, cur["id"]]);
                changed = true;
            }
            if (string.CompareOrdinal(polled, S(cur["polled"])) > 0)           // the readings: the newer reading wins
            {
                s.Execute($"UPDATE printer SET {string.Join(", ", state.Select(k => k + " = ?"))} WHERE id = ?",
                          [.. state.Select(k => vals[k]), cur["id"]]);
                changed = true;
            }
            if (changed) n++;
        }
        return n;
    }
}
