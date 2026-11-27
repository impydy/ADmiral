using System.Collections;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Row = System.Collections.Generic.Dictionary<string, object?>;

namespace ADmiral.Core;

// SQLite-backed inventory store (port of admiral/db.py). Every value goes in through SQL parameters; the only
// identifiers ever put into SQL text come from the fixed column lists of this file.

public static class Db
{
    public const string Schema = """
        CREATE TABLE IF NOT EXISTS computers (
            guid          TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            dns_hostname  TEXT,
            dn            TEXT,
            ou            TEXT,
            os            TEXT,
            os_version    TEXT,
            enabled       INTEGER NOT NULL DEFAULT 1,
            last_logon    TEXT,
            created       TEXT,
            description   TEXT,
            ad_synced_at  TEXT,
            ip            TEXT,
            online        INTEGER,
            open_ports    TEXT,
            scanned_at    TEXT,
            inventory     TEXT,
            collected_at  TEXT,
            collect_error TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_computers_name ON computers(name);

        CREATE TABLE IF NOT EXISTS tags (
            guid TEXT NOT NULL REFERENCES computers(guid) ON DELETE CASCADE,
            tag  TEXT NOT NULL,
            PRIMARY KEY (guid, tag)
        );

        CREATE TABLE IF NOT EXISTS fleets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            kind        TEXT NOT NULL CHECK (kind IN ('static', 'dynamic')),
            rules       TEXT,
            ad_group_dn TEXT,
            created     TEXT NOT NULL,
            updated     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS fleet_members (
            fleet_id INTEGER NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
            guid     TEXT NOT NULL REFERENCES computers(guid) ON DELETE CASCADE,
            PRIMARY KEY (fleet_id, guid)
        );

        CREATE TABLE IF NOT EXISTS activity (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            ts     TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        """;

    /// <summary>Each migration brings the schema from version N-1 to N (PRAGMA user_version).</summary>
    public static readonly IReadOnlyList<string> Migrations =
    [
        // 1: computer page fields (PDQ-style "Computer" window) + list data
        """
        ALTER TABLE computers ADD COLUMN added TEXT;
        ALTER TABLE computers ADD COLUMN allow_scan INTEGER NOT NULL DEFAULT 1;
        ALTER TABLE computers ADD COLUMN location TEXT;
        ALTER TABLE computers ADD COLUMN member_of TEXT;
        ALTER TABLE computers ADD COLUMN scan_status TEXT;
        ALTER TABLE computers ADD COLUMN last_scan_attempt TEXT;
        UPDATE computers SET added = COALESCE(ad_synced_at, datetime('now'));
        UPDATE computers SET scan_status = CASE WHEN collect_error IS NOT NULL THEN 'failed'
                                                WHEN inventory IS NOT NULL THEN 'ok' END;
        CREATE TABLE IF NOT EXISTS computer_items (
            guid TEXT NOT NULL REFERENCES computers(guid) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            pos  INTEGER NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (guid, kind, pos)
        );
        CREATE INDEX IF NOT EXISTS ix_items_kind ON computer_items(kind);
        """,
        // 2: computers the user removed from the list (kept hidden so an AD sync does not bring them back)
        """
        ALTER TABLE computers ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0;
        """,
        // 3: Active Directory data of the users seen in the logon history (read from AD, cached here)
        """
        CREATE TABLE IF NOT EXISTS users (
            key       TEXT PRIMARY KEY,      -- lower(sAMAccountName)
            data      TEXT NOT NULL,         -- JSON: the AD attributes, or {"missing": true}
            synced_at TEXT NOT NULL
        );
        """,
        // 4: Microsoft's newest security-release build per Windows build (security-update monitoring)
        """
        CREATE TABLE IF NOT EXISTS update_ref (
            key      TEXT PRIMARY KEY,       -- '10.0.22631'
            ubr      INTEGER NOT NULL,       -- newest fixed revision
            month    TEXT,
            released TEXT
        );
        CREATE TABLE IF NOT EXISTS update_meta (k TEXT PRIMARY KEY, v TEXT);
        """,
        // 5: CVE data per product (NVD) and the CISA known-exploited list, for the software vulnerability view
        """
        CREATE TABLE IF NOT EXISTS cve_product (
            vendor    TEXT NOT NULL,
            product   TEXT NOT NULL,
            cve       TEXT NOT NULL,
            published TEXT,
            score     REAL,
            summary   TEXT,
            matches   TEXT NOT NULL,         -- JSON: version ranges of this product
            PRIMARY KEY (vendor, product, cve)
        );
        CREATE TABLE IF NOT EXISTS cve_fetch (
            vendor     TEXT NOT NULL,
            product    TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            total      INTEGER NOT NULL,
            PRIMARY KEY (vendor, product)
        );
        CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY);
        """,
        // 6: deployments (installer copied to computers and run there) with per-computer progress
        """
        CREATE TABLE IF NOT EXISTS deployment (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, finished TEXT,
            package_id TEXT NOT NULL, package_name TEXT, version TEXT, file TEXT NOT NULL, kind TEXT,
            args TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'running'
        );
        CREATE TABLE IF NOT EXISTS deployment_target (
            deployment_id INTEGER NOT NULL REFERENCES deployment(id) ON DELETE CASCADE,
            guid TEXT NOT NULL, name TEXT NOT NULL,
            step TEXT NOT NULL DEFAULT 'queued', percent INTEGER, outcome TEXT, exit_code INTEGER,
            error TEXT, log TEXT, started TEXT, finished TEXT,
            PRIMARY KEY (deployment_id, guid)
        );
        """,
        // 7: the full event log of a deployment (what happened, in order, per computer)
        """
        CREATE TABLE IF NOT EXISTS deployment_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id INTEGER NOT NULL REFERENCES deployment(id) ON DELETE CASCADE,
            ts TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS deployment_event_dep ON deployment_event(deployment_id, id);
        """,
        // 8: network printers read over SNMP
        """
        CREATE TABLE printer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE COLLATE NOCASE,
            model TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
            community TEXT NOT NULL DEFAULT 'public', version TEXT NOT NULL DEFAULT '2c',
            oid_model TEXT NOT NULL DEFAULT '', oid_toner TEXT NOT NULL DEFAULT '', oid_toner_max TEXT NOT NULL DEFAULT '',
            oid_pages TEXT NOT NULL DEFAULT '', oid_serial TEXT NOT NULL DEFAULT '', oid_status TEXT NOT NULL DEFAULT '',
            toner TEXT NOT NULL DEFAULT '[]', pages INTEGER, serial TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
            polled TEXT, error TEXT NOT NULL DEFAULT ''
        );
        """,
        // 9: printers know when they were last edited (sync) and keep one reading per day (toner / page count history)
        """
        ALTER TABLE printer ADD COLUMN updated TEXT NOT NULL DEFAULT '';
        CREATE TABLE printer_history (
            ip TEXT NOT NULL COLLATE NOCASE, day TEXT NOT NULL, taken_at TEXT NOT NULL,
            pages INTEGER, toner TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY (ip, day)
        );
        """,
        // 10: the computer account's SID from AD (the owner check of the drop folders compares SIDs, not names)
        """
        ALTER TABLE computers ADD COLUMN sid TEXT;
        """,
        // 11: what a sync peer changed and nobody here has edited since (shown before a deployment): when a peer last
        // changed a collection, when a peer added a tag
        """
        ALTER TABLE fleets ADD COLUMN peer_changed TEXT;
        ALTER TABLE tags ADD COLUMN peer_added TEXT;
        """,
        // 12: BitLocker recovery passwords, only as RSA-OAEP ciphertext made on the computer with ADmiral's public key
        // (the private key is in the DPAPI-protected secret store); never part of the inventory, never synced
        """
        CREATE TABLE bitlocker_key (
            guid TEXT NOT NULL REFERENCES computers(guid) ON DELETE CASCADE,
            drive TEXT NOT NULL, protector_id TEXT NOT NULL, cipher TEXT NOT NULL, collected_at TEXT NOT NULL,
            PRIMARY KEY (guid, drive, protector_id)
        );
        """,
        // 13: which ADmiral process runs a deployment (host, PID, process start time, a random id) and when it last said
        // it is alive: another instance starting up only closes a "running" deployment whose process is gone
        """
        ALTER TABLE deployment ADD COLUMN owner_id TEXT;
        ALTER TABLE deployment ADD COLUMN owner_host TEXT;
        ALTER TABLE deployment ADD COLUMN owner_pid INTEGER;
        ALTER TABLE deployment ADD COLUMN owner_started TEXT;
        ALTER TABLE deployment ADD COLUMN heartbeat TEXT;
        ALTER TABLE deployment ADD COLUMN closed_unverified INTEGER;
        """,
        // 14: the security-update reference is kept per build and family (client / server: "10.0.26100/server"),
        // with the KB and the MSRC product it came from. The old rows mixed Windows 11 and Server 2025 (one build
        // number, two update lines), so they are dropped and downloaded again at the next refresh.
        """
        ALTER TABLE update_ref ADD COLUMN kb TEXT;
        ALTER TABLE update_ref ADD COLUMN product TEXT;
        DELETE FROM update_ref;
        DELETE FROM update_meta WHERE k IN ('fetched_at', 'attempted_at', 'kbs', 'months');
        """,
    ];

    /// <summary>The computer fields that come from Active Directory (replaced by every AD sync).</summary>
    public static readonly IReadOnlyList<string> AdFields =
        ["name", "dns_hostname", "dn", "ou", "os", "os_version", "enabled", "last_logon", "created", "description", "location", "member_of", "sid"];

    /// <summary>The list sections of an inventory, stored as rows of computer_items.</summary>
    public static readonly IReadOnlyList<string> ListKinds = ["disks", "nics", "hotfixes", "apps", "services", "local_admins", "logons", "user_accounts", "local_groups", "monitors", "bitlocker"];

    /// <summary>Now, UTC, to the second, ISO-8601: "2026-11-21T10:00:00+00:00" (the format of every DB timestamp).</summary>
    public static string UtcNow() => FormatUtc(DateTimeOffset.UtcNow);

    public static string FormatUtc(DateTimeOffset t) =>
        t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'+00:00'", CultureInfo.InvariantCulture);

    /// <summary>Parse an ISO-8601 timestamp (a missing offset means UTC), like Python's datetime.fromisoformat.</summary>
    public static DateTimeOffset? ParseIso(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var s = value.Trim();
        if (s.EndsWith('Z') || s.EndsWith('z')) s = s[..^1] + "+00:00";
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                                       DateTimeStyles.AssumeUniversal | DateTimeStyles.AllowWhiteSpaces, out var t) ? t : null;
    }

    internal static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.Never };

    /// <summary>JSON text of any value (JsonNode, collection, primitive).</summary>
    public static string ToJson(object? value) => value switch
    {
        null => "null",
        JsonNode n => n.ToJsonString(),
        _ => JsonSerializer.Serialize(value, value.GetType(), Json),
    };

    /// <summary>Python truthiness of a JSON-ish value (null, false, 0, "", empty list / object are false).</summary>
    public static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        int i => i != 0,
        long l => l != 0,
        double d => d != 0,
        JsonObject o => o.Count > 0,
        JsonArray a => a.Count > 0,
        JsonValue jv => jv.GetValueKind() switch
        {
            JsonValueKind.False or JsonValueKind.Null or JsonValueKind.Undefined => false,
            JsonValueKind.String => jv.GetValue<string>().Length > 0,
            JsonValueKind.Number => jv.ToJsonString() is not ("0" or "0.0" or "-0" or "-0.0"),
            _ => true,
        },
        JsonElement e => e.ValueKind switch
        {
            JsonValueKind.False or JsonValueKind.Null or JsonValueKind.Undefined => false,
            JsonValueKind.String => e.GetString()!.Length > 0,
            JsonValueKind.Number => e.GetDouble() != 0,
            JsonValueKind.Array => e.GetArrayLength() > 0,
            JsonValueKind.Object => e.EnumerateObject().Any(),
            _ => true,
        },
        ICollection c => c.Count > 0,
        _ => true,
    };
}

/// <summary>CVE record of one product (NVD). <c>Matches</c>: version ranges
/// [start_including, start_excluding, end_including, end_excluding, exact] (null = open).</summary>
public sealed record CveRecord(
    [property: JsonPropertyName("cve")] string Cve,
    [property: JsonPropertyName("published")] string? Published,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("summary")] string? Summary,
    [property: JsonPropertyName("matches")] List<string?[]> Matches);

/// <summary>Newest fixed revision of one Windows build (and family) in Microsoft's security releases, with the KB and
/// the MSRC product it was read from (null when the data does not name them).</summary>
public sealed record UpdateRef(
    [property: JsonPropertyName("ubr")] long Ubr,
    [property: JsonPropertyName("month")] string? Month,
    [property: JsonPropertyName("released")] string? Released)
{
    [JsonPropertyName("kb"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Kb { get; init; }
    [JsonPropertyName("product"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Product { get; init; }
}

/// <summary>What the start-up check knows about the process that owns a running deployment.</summary>
public enum OwnerState { Alive, Gone, Unknown }

/// <summary>The ADmiral process that runs a deployment: computer, PID, the process's start time (a reused PID belongs to a
/// process started later) and a random id of this process.</summary>
public sealed record DeploymentOwner(string Id, string Host, long Pid, string Started)
{
    public static readonly DeploymentOwner Current = Make();

    private static DeploymentOwner Make()
    {
        string started;
        try
        {
            using var me = System.Diagnostics.Process.GetCurrentProcess();
            started = me.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        }
        catch (Exception exc) when (exc is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            started = "";
        }
        return new DeploymentOwner(Guid.NewGuid().ToString("N"), Environment.MachineName, Environment.ProcessId, started);
    }

    /// <summary>Is the process <paramref name="pid"/> started at <paramref name="started"/> on <paramref name="host"/> still
    /// running? Unknown when it cannot be told from here (another computer, no owner recorded, the start time is not
    /// readable for this account).</summary>
    public static OwnerState Probe(string? host, long? pid, string? started)
    {
        if (pid is not { } p || p <= 0 || p > int.MaxValue || string.IsNullOrEmpty(host)
            || !string.Equals(host, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            return OwnerState.Unknown;
        System.Diagnostics.Process proc;
        try { proc = System.Diagnostics.Process.GetProcessById((int)p); }
        catch (ArgumentException) { return OwnerState.Gone; }                   // no such process
        catch (InvalidOperationException) { return OwnerState.Gone; }
        using (proc)
        {
            try
            {
                if (proc.HasExited) return OwnerState.Gone;
                if (!DateTime.TryParse(started, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var want)) return OwnerState.Unknown;
                var diff = (proc.StartTime.ToUniversalTime() - want.ToUniversalTime()).Duration();
                return diff < TimeSpan.FromSeconds(2) ? OwnerState.Alive : OwnerState.Gone;    // otherwise: the PID was reused
            }
            catch (Exception exc) when (exc is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
            {
                return OwnerState.Unknown;                                           // e.g. another account's process
            }
        }
    }
}

/// <summary>The inventory database. Thread-safe: one connection, every access under one (re-entrant) lock.
/// Rows are returned as <c>Dictionary&lt;string, object?&gt;</c> keyed by column name (the JSON the UI gets);
/// integers come back as <c>long</c>, JSON columns as parsed <see cref="JsonNode"/>s.</summary>
public sealed class Store : IDisposable
{
    private readonly Lock _lock = new();
    private readonly SqliteConnection _conn;
    private SqliteTransaction? _tx;
    private int _version;
    private bool _closed;
    private static readonly ConcurrentDictionary<string, (string Sql, int Count)> SqlCache = new();

    public string Path { get; }

    /// <summary>Bumped whenever computers / logons / AD users change (a cache key for callers).</summary>
    public int Version => Volatile.Read(ref _version);

    public Store(string path = "admiral.db")
    {
        Path = path;
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString();
        _conn = new SqliteConnection(cs);
        _conn.Open();
        Exec("PRAGMA foreign_keys = ON");
        if (path != ":memory:") Exec("PRAGMA journal_mode = WAL");
        Exec(Db.Schema);
        Migrate();
    }

    private void Migrate()
    {
        lock (_lock)
        {
            var version = (int)(long)ScalarRaw("PRAGMA user_version")!;
            for (var n = version + 1; n <= Db.Migrations.Count; n++)
            {
                // run the migration and bump the version together (n is our own counter, not input)
                using var tx = _conn.BeginTransaction();
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = Db.Migrations[n - 1] + $"\nPRAGMA user_version = {n.ToString(CultureInfo.InvariantCulture)};";
                cmd.ExecuteNonQuery();
                tx.Commit();
            }
        }
    }

    public int SchemaVersion => (int)(long)Scalar("PRAGMA user_version")!;

    public void Close()
    {
        lock (_lock)
        {
            if (_closed) return;
            _closed = true;
            _conn.Close();
            _conn.Dispose();
        }
    }

    public void Dispose() => Close();

    // ------------------------------------------------------------------ low level
    /// <summary>"?" placeholders -> "$p0", "$p1", ... (outside quoted text).</summary>
    private static (string Sql, int Count) Positional(string sql) => SqlCache.GetOrAdd(sql, s =>
    {
        var sb = new StringBuilder(s.Length + 16);
        var n = 0;
        char quote = '\0';
        foreach (var c in s)
        {
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                sb.Append(c);
            }
            else if (c is '\'' or '"')
            {
                quote = c;
                sb.Append(c);
            }
            else if (c == '?')
            {
                sb.Append("$p").Append(n++.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                sb.Append(c);
            }
        }
        return (sb.ToString(), n);
    });

    /// <summary>A value as SQLite gets it: bool -> 0/1, JSON values unwrapped, other JSON / collections as JSON text.</summary>
    private static object ToDb(object? v) => v switch
    {
        null => DBNull.Value,
        bool b => b ? 1L : 0L,
        string or long or int or double or float or decimal or short or byte => v,
        DateTimeOffset t => Db.FormatUtc(t),
        Enum e => e.ToString(),
        JsonValue jv => jv.GetValueKind() switch
        {
            JsonValueKind.String => jv.GetValue<string>(),
            JsonValueKind.True => 1L,
            JsonValueKind.False => 0L,
            JsonValueKind.Null => DBNull.Value,
            JsonValueKind.Number => long.TryParse(jv.ToJsonString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var l)
                ? l : double.Parse(jv.ToJsonString(), CultureInfo.InvariantCulture),
            _ => jv.ToJsonString(),
        },
        JsonElement e => e.ValueKind switch
        {
            JsonValueKind.String => e.GetString()!,
            JsonValueKind.True => 1L,
            JsonValueKind.False => 0L,
            JsonValueKind.Null or JsonValueKind.Undefined => DBNull.Value,
            JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
            _ => e.GetRawText(),
        },
        _ => Db.ToJson(v),
    };

    private SqliteCommand Command(string sql, IReadOnlyList<object?> args)
    {
        var (text, count) = Positional(sql);
        if (count != args.Count)
            throw new ArgumentException($"SQL expects {count} parameter(s), got {args.Count}");
        var cmd = _conn.CreateCommand();
        cmd.Transaction = _tx;
        cmd.CommandText = text;
        for (var i = 0; i < count; i++)
            cmd.Parameters.AddWithValue("$p" + i.ToString(CultureInfo.InvariantCulture), ToDb(args[i]));
        return cmd;
    }

    private static Row ReadRow(SqliteDataReader r)
    {
        var row = new Row(r.FieldCount, StringComparer.Ordinal);
        for (var i = 0; i < r.FieldCount; i++)
            row[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
        return row;
    }

    /// <summary>Run a query with positional <c>?</c> parameters; rows keyed by column name.</summary>
    public List<Row> Query(string sql, params object?[] args)
    {
        lock (_lock)
        {
            using var cmd = Command(sql, args);
            using var r = cmd.ExecuteReader();
            var rows = new List<Row>();
            while (r.Read()) rows.Add(ReadRow(r));
            return rows;
        }
    }

    /// <summary>The first column of the first row (null if there is none).</summary>
    public object? Scalar(string sql, params object?[] args)
    {
        lock (_lock)
        {
            using var cmd = Command(sql, args);
            var v = cmd.ExecuteScalar();
            return v is DBNull ? null : v;
        }
    }

    private object? ScalarRaw(string sql) => Scalar(sql);

    /// <summary>Run a statement with positional <c>?</c> parameters; returns the number of changed rows.</summary>
    public int Execute(string sql, params object?[] args)
    {
        lock (_lock)
        {
            using var cmd = Command(sql, args);
            return cmd.ExecuteNonQuery();
        }
    }

    private void Exec(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.Transaction = _tx;
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private long LastId() => (long)Scalar("SELECT last_insert_rowid()")!;

    /// <summary>Run <paramref name="body"/> in one transaction (joins the running one if called inside another).</summary>
    private T InTx<T>(Func<T> body)
    {
        lock (_lock)
        {
            if (_tx is not null) return body();
            _tx = _conn.BeginTransaction();
            try
            {
                var result = body();
                _tx.Commit();
                return result;
            }
            catch
            {
                _tx.Rollback();
                throw;
            }
            finally
            {
                _tx.Dispose();
                _tx = null;
            }
        }
    }

    /// <summary>Run <paramref name="work"/> in one transaction (joins a running one); rolled back if it throws.</summary>
    public T InTransaction<T>(Func<T> work) => InTx(work);

    private void InTx(Action body) => InTx(() =>
    {
        body();
        return 0;
    });

    private void Bump() => Interlocked.Increment(ref _version);

    private static JsonNode? ParseJson(object? text) => text is string s && s.Length > 0 ? JsonNode.Parse(s) : null;

    private static JsonObject ParseObject(object? text) => ParseJson(text) switch
    {
        JsonObject o => o,
        null => [],
        var other => new JsonObject { ["value"] = other },
    };

    private static string Text(object? v) => v switch
    {
        null => "",
        string s => s,
        JsonValue jv when jv.GetValueKind() == JsonValueKind.String => jv.GetValue<string>(),
        JsonNode n => n.ToJsonString(),
        _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    // ------------------------------------------------------------------ computers
    /// <summary>Replace the AD-sourced fields of every read computer; drop computers no longer in AD.
    /// <paramref name="scope"/> (a DN) means only that OU and everything below it was read: computers elsewhere are
    /// left alone, and only the ones inside it that vanished are dropped. Scan / inventory data is preserved.
    /// Each record needs "guid" and may carry the <see cref="Db.AdFields"/>.</summary>
    public Dictionary<string, int> UpsertFromAd(IEnumerable<IReadOnlyDictionary<string, object?>> records, string? scope = null)
    {
        var now = Db.UtcNow();
        return InTx(() =>
        {
            Bump();
            var rows = Query("SELECT guid, dn FROM computers");
            var existing = rows.Select(r => (string)r["guid"]!).ToHashSet();
            var inScope = rows.Where(r => string.IsNullOrEmpty(scope) || DnUtil.IsUnder(r["dn"] as string ?? "", scope))
                              .Select(r => (string)r["guid"]!).ToHashSet();
            var seen = new HashSet<string>();
            int added = 0, updated = 0;
            var sets = string.Join(", ", Db.AdFields.Select(f => f + " = ?"));
            var cols = string.Join(", ", Db.AdFields);
            var marks = string.Join(", ", Db.AdFields.Select(_ => "?"));
            foreach (var rec in records)
            {
                var guid = Text(rec["guid"]);
                seen.Add(guid);
                var values = Db.AdFields.Select(f => rec.TryGetValue(f, out var v) ? v : null).ToList();
                values[IndexOf("enabled")] = !rec.TryGetValue("enabled", out var en) || Db.Truthy(en) ? 1L : 0L;
                values[IndexOf("member_of")] = Db.ToJson(rec.TryGetValue("member_of", out var mo) && Db.Truthy(mo) ? mo : Array.Empty<string>());
                if (existing.Contains(guid))
                {
                    Execute($"UPDATE computers SET {sets}, ad_synced_at = ? WHERE guid = ?", [.. values, now, guid]);
                    updated++;
                }
                else
                {
                    Execute($"INSERT INTO computers (guid, {cols}, ad_synced_at, added) VALUES (?, {marks}, ?, ?)",
                            [guid, .. values, now, now]);
                    existing.Add(guid);
                    added++;
                }
            }
            var removed = inScope.Except(seen).ToList();
            foreach (var g in removed) Execute("DELETE FROM computers WHERE guid = ?", g);
            return new Dictionary<string, int> { ["added"] = added, ["updated"] = updated, ["removed"] = removed.Count };
        });

        static int IndexOf(string f) => ((List<string>)[.. Db.AdFields]).IndexOf(f);
    }

    public void RecordScan(string guid, string? ip, IEnumerable<int> openPorts)
    {
        var ports = openPorts.Order().ToList();
        var online = ports.Count > 0 ? 1L : 0L;
        InTx(() => Execute(
            "UPDATE computers SET ip = COALESCE(?, ip), online = ?, open_ports = ?, scanned_at = ?, "
            + "scan_status = CASE WHEN ? = 0 THEN 'offline' WHEN scan_status = 'offline' THEN NULL ELSE scan_status END "
            + "WHERE guid = ?", ip, online, Db.ToJson(ports), Db.UtcNow(), online, guid));
    }

    /// <summary>How long logon events are kept (days; logins.retention_days). Older ones are dropped when a computer's
    /// history is written, and by <see cref="PruneLogons"/>.</summary>
    public int LogonRetentionDays { get; set; } = 60;

    /// <summary>The oldest logon time still kept (UTC ISO, compared as text like the stored times).</summary>
    private string LogonCutoff() => Db.FormatUtc(DateTimeOffset.UtcNow.AddDays(-Math.Max(1, LogonRetentionDays)));

    /// <summary>Union of the stored logon events and <paramref name="rows"/> (newest first, no duplicates, capped, none
    /// older than the retention). Runs inside the caller's transaction.</summary>
    private void MergeLogons(string guid, IEnumerable<JsonNode?> rows)
    {
        var old = Query("SELECT data FROM computer_items WHERE guid = ? AND kind = 'logons' ORDER BY pos", guid)
            .Select(r => ParseJson(r["data"]));
        // local accounts of the computer are not kept (also cleans what an older version stored)
        var name = Query("SELECT name FROM computers WHERE guid = ?", guid).Select(r => r["name"] as string).FirstOrDefault();
        var cutoff = LogonCutoff();
        var merged = CollectorModel.CleanLogons(rows.Concat(old), name).Where(e => KeepLogon(e, cutoff)).ToList();
        Execute("DELETE FROM computer_items WHERE guid = ? AND kind = 'logons'", guid);
        for (var i = 0; i < merged.Count; i++)
            Execute("INSERT INTO computer_items (guid, kind, pos, data) VALUES (?, 'logons', ?, ?)", guid, i, merged[i].ToJsonString());
    }

    private static bool KeepLogon(JsonObject e, string cutoff) =>
        Db.ParseIso(e["time"]?.GetValue<string>()) is not { } t || t >= Db.ParseIso(cutoff)!.Value;

    /// <summary>Drop the logon events older than the retention from every computer. Returns how many were dropped.</summary>
    public int PruneLogons() => InTx(() =>
    {
        var cutoff = LogonCutoff();
        var drop = Query("SELECT rowid AS id, data FROM computer_items WHERE kind = 'logons'")
            .Where(r => !KeepLogon(ParseObject(r["data"]), cutoff)).Select(r => (long)r["id"]!).ToList();
        foreach (var id in drop) Execute("DELETE FROM computer_items WHERE rowid = ?", id);
        if (drop.Count > 0) Bump();
        return drop.Count;
    });

    /// <summary>A logon event for the user logged on at collection time (<c>DOMAIN\user</c>), at most one per user and
    /// computer a day. Null when there is nothing to add.</summary>
    private JsonObject? CurrentUserLogon(string guid, string? loggedOn, DateTimeOffset now)
    {
        var raw = (loggedOn ?? "").Trim();
        var cut = raw.IndexOf('\\');
        if (cut <= 0 || cut == raw.Length - 1) return null;
        var (domain, user) = (raw[..cut], raw[(cut + 1)..]);
        var day = Db.FormatUtc(now)[..10];
        var already = Query("SELECT data FROM computer_items WHERE guid = ? AND kind = 'logons'", guid)
            .Select(r => ParseObject(r["data"]))
            .Any(e => string.Equals(e["user"]?.GetValue<string>(), user, StringComparison.OrdinalIgnoreCase)
                      && string.Equals(e["domain"]?.GetValue<string>(), domain, StringComparison.OrdinalIgnoreCase)
                      && (e["time"]?.GetValue<string>() ?? "").StartsWith(day, StringComparison.Ordinal));
        return already ? null : new JsonObject { ["time"] = Db.FormatUtc(now), ["user"] = user, ["domain"] = domain, ["type"] = 2, ["ip"] = "" };
    }

    /// <summary>Add logon events (from the login-tracking files) to a computer's history.</summary>
    public void AddLogons(string guid, IEnumerable<JsonNode?> events) => InTx(() =>
    {
        Bump();
        MergeLogons(guid, events.ToList());
    });

    /// <summary>Store a successful collection (scalars + list rows), or a failed attempt (<paramref name="inventory"/>
    /// null). A failure keeps the previously collected data; only the status / error change. A list section missing
    /// from the inventory (it failed) keeps its old rows; logons are merged, never replaced.</summary>
    public void RecordInventory(string guid, JsonObject? inventory, string? error = null)
    {
        var now = Db.UtcNow();
        InTx(() =>
        {
            Bump();
            if (inventory is null)
            {
                Execute("UPDATE computers SET collect_error = ?, last_scan_attempt = ?, scan_status = 'failed' WHERE guid = ?",
                        error, now, guid);
                return;
            }
            var scalars = new JsonObject();
            foreach (var (k, v) in inventory)
                if (!Db.ListKinds.Contains(k) && k != "bitlocker_keys") scalars[k] = v?.DeepClone();   // keys: see SetBitlockerKeys
            // a local account of the computer is not recorded as its logged-on user (older scripts still send it)
            var compName = Query("SELECT name FROM computers WHERE guid = ?", guid).Select(r => r["name"] as string).FirstOrDefault();
            if (scalars["logged_on_user"] is JsonValue lu && lu.GetValueKind() == JsonValueKind.String
                && CollectorModel.IsLocalAccountName(lu.GetValue<string>(), compName))
            {
                scalars["logged_on_user"] = null;
                scalars["user_display_name"] = null;
            }
            var sectionErrors = inventory["section_errors"];
            var partial = Db.Truthy(sectionErrors);
            var errText = partial && sectionErrors is JsonObject se
                ? string.Join("; ", se.Select(kv => $"{kv.Key}: {Text(kv.Value)}"))
                : partial ? Text(sectionErrors) : null;
            Execute("UPDATE computers SET inventory = ?, collected_at = ?, last_scan_attempt = ?, collect_error = ?, "
                    + "scan_status = ? WHERE guid = ?", scalars.ToJsonString(), now, now, errText, partial ? "partial" : "ok", guid);
            // the user logged on while the computer was scanned goes into the logon history too (once a day)
            var current = CurrentUserLogon(guid, scalars["logged_on_user"] is JsonValue cu && cu.GetValueKind() == JsonValueKind.String ? cu.GetValue<string>() : null,
                                           DateTimeOffset.UtcNow);
            if (current is not null && !inventory.ContainsKey("logons")) MergeLogons(guid, [current]);
            foreach (var kind in Db.ListKinds)
            {
                if (!inventory.TryGetPropertyValue(kind, out var section)) continue;   // section failed: keep the old rows
                var list = section is JsonArray a ? a.ToList() : section is JsonObject o ? [o] : [];
                if (list.Count > Collector.MaxItemsPerSection)
                {
                    ADmiral.Core.Log.Logger.LogWarning("Inventory of {Guid}: '{Kind}' has {Count} entries; only the first {Max} are kept",
                                          guid, kind, list.Count, Collector.MaxItemsPerSection);
                    list = list.GetRange(0, Collector.MaxItemsPerSection);
                }
                if (kind == "logons")
                {
                    if (current is not null) list = [.. list, current];
                    MergeLogons(guid, list);                  // event log + login-tracking files: merge, do not replace
                    continue;
                }
                Execute("DELETE FROM computer_items WHERE guid = ? AND kind = ?", guid, kind);
                for (var i = 0; i < list.Count; i++)
                    Execute("INSERT INTO computer_items (guid, kind, pos, data) VALUES (?, ?, ?, ?)",
                            guid, kind, i, list[i]?.ToJsonString() ?? "null");
            }
        });
    }

    /// <summary>Replace the stored BitLocker recovery keys of a computer (ciphertext only).</summary>
    public void SetBitlockerKeys(string guid, IEnumerable<(string Drive, string Id, string Cipher)> keys) => InTx(() =>
    {
        Execute("DELETE FROM bitlocker_key WHERE guid = ?", guid);
        var now = Db.UtcNow();
        foreach (var (d, id, c) in keys)
            Execute("INSERT OR REPLACE INTO bitlocker_key (guid, drive, protector_id, cipher, collected_at) VALUES (?,?,?,?,?)", guid, d, id, c, now);
    });

    /// <summary>[{drive, id, collected_at}] of the stored recovery keys - never the key itself.</summary>
    public List<Row> BitlockerKeyList(string guid) =>
        Query("SELECT drive, protector_id AS id, collected_at FROM bitlocker_key WHERE guid = ? ORDER BY drive, protector_id", guid);

    /// <summary>The ciphertext of one stored recovery key (null when there is none).</summary>
    public string? BitlockerCipher(string guid, string id) =>
        Query("SELECT cipher FROM bitlocker_key WHERE guid = ? AND protector_id = ?", guid, id).Select(r => r["cipher"] as string).FirstOrDefault();

    /// <summary>The list sections of one computer: kind -> rows (every <see cref="Db.ListKinds"/> key present).</summary>
    public Dictionary<string, List<JsonObject>> Items(string guid)
    {
        var outMap = Db.ListKinds.ToDictionary(k => k, _ => new List<JsonObject>());
        foreach (var r in Query("SELECT kind, data FROM computer_items WHERE guid = ? ORDER BY kind, pos", guid))
        {
            var kind = (string)r["kind"]!;
            if (!outMap.TryGetValue(kind, out var list)) outMap[kind] = list = [];
            list.Add(ParseObject(r["data"]));
        }
        return outMap;
    }

    public Dictionary<string, int> ItemCounts(string guid) =>
        Query("SELECT kind, COUNT(*) AS n FROM computer_items WHERE guid = ? GROUP BY kind", guid)
            .ToDictionary(r => (string)r["kind"]!, r => (int)(long)r["n"]!);

    /// <summary>Every stored logon event of the visible computers: (computer guid, event).</summary>
    public List<(string Guid, JsonObject Event)> LogonRows() =>
        [.. Query("SELECT i.guid, i.data FROM computer_items i JOIN computers c ON c.guid = i.guid "
                  + "WHERE i.kind = 'logons' AND c.hidden = 0")
            .Select(r => ((string)r["guid"]!, ParseObject(r["data"])))];

    /// <summary>The visible computers whose collected hotfix list names <paramref name="kb"/> ("KB5043080").</summary>
    public HashSet<string> ComputersWithHotfix(string kb) =>
        [.. Query("SELECT DISTINCT i.guid FROM computer_items i JOIN computers c ON c.guid = i.guid "
                  + "WHERE i.kind = 'hotfixes' AND c.hidden = 0 AND upper(json_extract(i.data, '$.id')) = upper(?)", kb)
            .Select(r => (string)r["guid"]!)];

    // ------------------------------------------------------------------ software + CVE data
    /// <summary>(computer guid, name, version, publisher) of every installed program on the visible computers.</summary>
    public List<(string Guid, string Name, string Version, string Publisher)> AppRows() =>
        [.. Query("SELECT i.guid, json_extract(i.data, '$.name') AS name, json_extract(i.data, '$.version') AS version, "
                  + "json_extract(i.data, '$.publisher') AS publisher FROM computer_items i "
                  + "JOIN computers c ON c.guid = i.guid WHERE i.kind = 'apps' AND c.hidden = 0")
            .Select(r => ((string)r["guid"]!, Text(r["name"]), Text(r["version"]), Text(r["publisher"])))];

    public void SaveCves(string vendor, string product, IReadOnlyCollection<CveRecord> records) => InTx(() =>
    {
        Execute("DELETE FROM cve_product WHERE vendor = ? AND product = ?", vendor, product);
        foreach (var r in records)
            Execute("INSERT OR REPLACE INTO cve_product (vendor, product, cve, published, score, summary, matches) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)", vendor, product, r.Cve, r.Published, r.Score, r.Summary, Db.ToJson(r.Matches));
        Execute("INSERT INTO cve_fetch (vendor, product, fetched_at, total) VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(vendor, product) DO UPDATE SET fetched_at = excluded.fetched_at, total = excluded.total",
                vendor, product, Db.UtcNow(), records.Count);
    });

    public Dictionary<(string Vendor, string Product), string> CveFetched() =>
        Query("SELECT * FROM cve_fetch").ToDictionary(r => ((string)r["vendor"]!, (string)r["product"]!), r => (string)r["fetched_at"]!);

    public List<CveRecord> CvesFor(string vendor, string product) =>
        [.. Query("SELECT * FROM cve_product WHERE vendor = ? AND product = ?", vendor, product)
            .Select(r => new CveRecord((string)r["cve"]!, r["published"] as string, r["score"] is null ? null : Convert.ToDouble(r["score"], CultureInfo.InvariantCulture),
                                       r["summary"] as string,
                                       JsonSerializer.Deserialize<List<string?[]>>((string)r["matches"]!) ?? []))];

    public void SaveKev(IEnumerable<string> ids) => InTx(() =>
    {
        Execute("DELETE FROM kev");
        foreach (var id in ids.Distinct().Order(StringComparer.Ordinal))
            Execute("INSERT OR IGNORE INTO kev (cve) VALUES (?)", id);
    });

    public HashSet<string> KevSet() => [.. Query("SELECT cve FROM kev").Select(r => (string)r["cve"]!)];

    public (Dictionary<string, UpdateRef> Builds, Dictionary<string, string> Meta) UpdateReference()
    {
        var builds = Query("SELECT * FROM update_ref").ToDictionary(
            r => (string)r["key"]!, r => new UpdateRef((long)r["ubr"]!, r["month"] as string, r["released"] as string)
            {
                Kb = r["kb"] as string, Product = r["product"] as string,
            });
        var meta = Query("SELECT k, v FROM update_meta").ToDictionary(r => (string)r["k"]!, r => r["v"] as string ?? "");
        return (builds, meta);
    }

    public void SaveUpdateReference(IReadOnlyDictionary<string, UpdateRef> builds, IReadOnlyDictionary<string, string> meta) => InTx(() =>
    {
        Execute("DELETE FROM update_ref");
        foreach (var (k, v) in builds)
            Execute("INSERT INTO update_ref (key, ubr, month, released, kb, product) VALUES (?, ?, ?, ?, ?, ?)",
                    k, v.Ubr, v.Month, v.Released, v.Kb, v.Product);
        SetUpdateMeta(meta);
    });

    public void SetUpdateMeta(IReadOnlyDictionary<string, string> meta) => InTx(() =>
    {
        foreach (var (k, v) in meta)
            Execute("INSERT INTO update_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, v);
    });

    /// <summary>The cached AD data of the users: key (lower sAMAccountName) -> attributes + "synced_at".</summary>
    public Dictionary<string, JsonObject> AdUsers()
    {
        var outMap = new Dictionary<string, JsonObject>();
        foreach (var r in Query("SELECT key, data, synced_at FROM users"))
        {
            var d = ParseObject(r["data"]);
            d["synced_at"] = r["synced_at"] as string;
            outMap[(string)r["key"]!] = d;
        }
        return outMap;
    }

    public void SaveAdUsers(IReadOnlyDictionary<string, JsonObject> records)
    {
        var now = Db.UtcNow();
        InTx(() =>
        {
            Bump();
            foreach (var (k, v) in records)
                Execute("INSERT INTO users (key, data, synced_at) VALUES (?, ?, ?) "
                        + "ON CONFLICT(key) DO UPDATE SET data = excluded.data, synced_at = excluded.synced_at", k, v.ToJsonString(), now);
        });
    }

    /// <summary>guid -> installed application names (for 'Application' rules).</summary>
    public Dictionary<string, List<string>> AppIndex()
    {
        var outMap = new Dictionary<string, List<string>>();
        foreach (var r in Query("SELECT guid, json_extract(data, '$.name') AS name FROM computer_items WHERE kind = 'apps'"))
        {
            var g = (string)r["guid"]!;
            if (!outMap.TryGetValue(g, out var list)) outMap[g] = list = [];
            list.Add(Text(r["name"]));
        }
        return outMap;
    }

    public void SetAllowScan(IEnumerable<string> guids, bool allow) => InTx(() =>
    {
        foreach (var g in guids) Execute("UPDATE computers SET allow_scan = ? WHERE guid = ?", allow ? 1L : 0L, g);
    });

    private Dictionary<string, List<string>> TagMap()
    {
        var tags = new Dictionary<string, List<string>>();
        foreach (var r in Query("SELECT guid, tag FROM tags ORDER BY tag"))
        {
            var g = (string)r["guid"]!;
            if (!tags.TryGetValue(g, out var list)) tags[g] = list = [];
            list.Add((string)r["tag"]!);
        }
        return tags;
    }

    private static Row RowToComputer(Row d, List<string> tags, int staleDays)
    {
        d["enabled"] = Convert.ToInt64(d["enabled"] ?? 1L, CultureInfo.InvariantCulture) != 0;
        d["allow_scan"] = Convert.ToInt64(d.GetValueOrDefault("allow_scan") ?? 1L, CultureInfo.InvariantCulture) != 0;
        d["member_of"] = d.GetValueOrDefault("member_of") is string mo && mo.Length > 0
            ? JsonSerializer.Deserialize<List<string>>(mo) ?? [] : new List<string>();
        d["online"] = d["online"] is null ? null : Convert.ToInt64(d["online"], CultureInfo.InvariantCulture) != 0;
        d["open_ports"] = d["open_ports"] is string op && op.Length > 0 ? JsonSerializer.Deserialize<List<int>>(op) ?? [] : new List<int>();
        var inv = d["inventory"] is string s && s.Length > 0 ? ParseObject(s) : null;
        d["inventory"] = inv;
        d["tags"] = tags;
        long? days = null;
        if (Db.ParseIso(d["last_logon"] as string) is { } last)
            days = (long)Math.Floor((DateTimeOffset.UtcNow - last).TotalDays);
        d["last_logon_days"] = days;
        d["stale"] = days is null || days > staleDays;
        d["uptime_s"] = null;
        if (d["online"] is true && inv?["last_boot"] is JsonValue lb && lb.GetValueKind() == JsonValueKind.String
            && Db.ParseIso(lb.GetValue<string>()) is { } boot)
            d["uptime_s"] = Math.Max(0L, (long)(DateTimeOffset.UtcNow - boot).TotalSeconds);
        return d;
    }

    /// <summary>The visible computers, by name, with tags, parsed JSON fields, staleness and uptime.</summary>
    public List<Row> Computers(int staleDays = 45)
    {
        var tags = TagMap();
        return [.. Query("SELECT * FROM computers WHERE hidden = 0 ORDER BY name COLLATE NOCASE")
            .Select(r => RowToComputer(r, tags.GetValueOrDefault((string)r["guid"]!) ?? [], staleDays))];
    }

    public void SetHidden(IEnumerable<string> guids, bool hidden) => InTx(() =>
    {
        Bump();
        foreach (var g in guids) Execute("UPDATE computers SET hidden = ? WHERE guid = ?", hidden ? 1L : 0L, g);
    });

    public int RestoreHidden() => InTx(() =>
    {
        Bump();
        return Execute("UPDATE computers SET hidden = 0 WHERE hidden = 1");
    });

    public int HiddenCount() => (int)(long)Scalar("SELECT COUNT(*) FROM computers WHERE hidden = 1")!;

    public Row? Computer(string guid, int staleDays = 45)
    {
        var rows = Query("SELECT * FROM computers WHERE guid = ? AND hidden = 0", guid);
        if (rows.Count == 0) return null;
        var tags = Query("SELECT tag FROM tags WHERE guid = ? ORDER BY tag", guid).Select(r => (string)r["tag"]!).ToList();
        return RowToComputer(rows[0], tags, staleDays);
    }

    /// <summary>Map computer names (case-insensitive) or GUIDs to GUIDs. Unknown entries raise
    /// <see cref="KeyNotFoundException"/> (message: err.unknown_computers).</summary>
    public List<string> ResolveNames(IEnumerable<string> namesOrGuids)
    {
        var lookup = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in Query("SELECT guid, name FROM computers WHERE hidden = 0"))
        {
            var g = (string)r["guid"]!;
            lookup[g.ToLowerInvariant()] = g;
            lookup[((string)r["name"]!).ToLowerInvariant()] = g;
        }
        var outList = new List<string>();
        var missing = new List<string>();
        foreach (var item in namesOrGuids)
        {
            if (lookup.TryGetValue(item.Trim().ToLowerInvariant(), out var g)) outList.Add(g);
            else missing.Add(item);
        }
        if (missing.Count > 0)
            throw new KeyNotFoundException(I18n.T("err.unknown_computers", ("names", string.Join(", ", missing))));
        return outList;
    }

    // ------------------------------------------------------------------ tags
    public void Tag(IReadOnlyCollection<string> guids, IEnumerable<string>? add = null, IEnumerable<string>? remove = null) => InTx(() =>
    {
        foreach (var t in add ?? [])
            foreach (var g in guids)        // tagged here: no longer only a peer's word
                Execute("INSERT INTO tags (guid, tag) VALUES (?, ?) ON CONFLICT(guid, tag) DO UPDATE SET peer_added = NULL", g, t);
        foreach (var t in remove ?? [])
            foreach (var g in guids) Execute("DELETE FROM tags WHERE guid = ? AND tag = ?", g, t);
    });

    /// <summary>[{tag, count}] by tag.</summary>
    public List<Row> AllTags() => Query("SELECT tag, COUNT(*) AS count FROM tags GROUP BY tag ORDER BY tag");

    // ------------------------------------------------------------------ fleets
    private static Row FleetRow(Row d)
    {
        d["rules"] = ParseJson(d["rules"]);
        return d;
    }

    public List<Row> Fleets() => [.. Query("SELECT * FROM fleets ORDER BY name COLLATE NOCASE").Select(FleetRow)];

    public Row? Fleet(long fleetId) => Query("SELECT * FROM fleets WHERE id = ?", fleetId).Select(FleetRow).FirstOrDefault();

    public Row? FleetByName(string name) => Query("SELECT * FROM fleets WHERE name = ? COLLATE NOCASE", name).Select(FleetRow).FirstOrDefault();

    public long CreateFleet(string name, string kind, string description = "", JsonNode? rules = null, string? adGroupDn = null)
    {
        var now = Db.UtcNow();
        return InTx(() =>
        {
            Execute("INSERT INTO fleets (name, description, kind, rules, ad_group_dn, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    name, description, kind, Db.Truthy(rules) ? rules!.ToJsonString() : null,
                    string.IsNullOrEmpty(adGroupDn) ? null : adGroupDn, now, now);
            return LastId();
        });
    }

    private static readonly string[] FleetEditable = ["name", "description", "rules", "ad_group_dn"];

    /// <summary>Change name / description / rules / ad_group_dn; any other key raises <see cref="ArgumentException"/>.</summary>
    public void UpdateFleet(long fleetId, IReadOnlyDictionary<string, object?> changes)
    {
        var sets = new List<string>();
        var args = new List<object?>();
        foreach (var (key, raw) in changes)
        {
            var col = FleetEditable.FirstOrDefault(c => c == key) ?? throw new ArgumentException($"Cannot update fleet field '{key}'");
            var value = raw;
            if (col == "rules") value = Db.Truthy(raw) ? Db.ToJson(raw) : null;
            if (col == "ad_group_dn") value = Db.Truthy(raw) ? raw : null;
            sets.Add(col + " = ?");
            args.Add(value);
        }
        if (sets.Count == 0) return;
        InTx(() => Execute($"UPDATE fleets SET {string.Join(", ", sets)}, updated = ?, peer_changed = NULL WHERE id = ?", [.. args, Db.UtcNow(), fleetId]));
    }

    public void DeleteFleet(long fleetId) => InTx(() => Execute("DELETE FROM fleets WHERE id = ?", fleetId));

    public HashSet<string> StaticMembers(long fleetId) =>
        [.. Query("SELECT guid FROM fleet_members WHERE fleet_id = ?", fleetId).Select(r => (string)r["guid"]!)];

    public void SetStaticMembers(long fleetId, IEnumerable<string>? add = null, IEnumerable<string>? remove = null) => InTx(() =>
    {
        foreach (var g in add ?? []) Execute("INSERT OR IGNORE INTO fleet_members (fleet_id, guid) VALUES (?, ?)", fleetId, g);
        foreach (var g in remove ?? []) Execute("DELETE FROM fleet_members WHERE fleet_id = ? AND guid = ?", fleetId, g);
        Execute("UPDATE fleets SET peer_changed = NULL WHERE id = ?", fleetId);      // edited here
    });

    // ------------------------------------------------------------------ deployments
    /// <summary>The process recorded as the owner of the deployments this store creates (tests replace it).</summary>
    internal DeploymentOwner Owner { get; set; } = DeploymentOwner.Current;

    public long CreateDeployment(string packageId, string? packageName, string? version, string file, string kind, string args,
                                 IEnumerable<(string Guid, string Name)> targets) => InTx(() =>
    {
        var now = Db.UtcNow();
        Execute("INSERT INTO deployment (created, package_id, package_name, version, file, kind, args, owner_id, owner_host, owner_pid, "
                + "owner_started, heartbeat) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                now, packageId, string.IsNullOrEmpty(packageName) ? packageId : packageName, version ?? "", file, kind, args,
                Owner.Id, Owner.Host, Owner.Pid, Owner.Started, now);
        var dep = LastId();
        foreach (var (g, n) in targets)
            Execute("INSERT INTO deployment_target (deployment_id, guid, name) VALUES (?,?,?)", dep, g, n);
        return dep;
    });

    private static readonly string[] TargetFields = ["step", "percent", "outcome", "exit_code", "error", "log", "started", "finished"];

    /// <summary>Update the progress fields of one target (unknown keys are ignored).</summary>
    public void UpdateTarget(long dep, string guid, IReadOnlyDictionary<string, object?> fields)
    {
        var cols = TargetFields.Where(fields.ContainsKey).ToList();
        if (cols.Count == 0) return;
        InTx(() => Execute($"UPDATE deployment_target SET {string.Join(", ", cols.Select(c => c + "=?"))} WHERE deployment_id=? AND guid=?",
                           [.. cols.Select(c => fields[c]), dep, guid]));
    }

    public void AddDeploymentEvent(long dep, string message, string name = "") => InTx(() =>
        Execute("INSERT INTO deployment_event (deployment_id, ts, name, message) VALUES (?,?,?,?)", dep, Db.UtcNow(), name, message));

    /// <summary>[{ts, name, message}] in order.</summary>
    public List<Row> DeploymentEvents(long dep) =>
        Query("SELECT ts, name, message FROM deployment_event WHERE deployment_id=? ORDER BY id", dep);

    /// <summary>The computers of <paramref name="dep"/> that have not started yet (queued / verifying): this step and percent.</summary>
    public void SetWaitingTargets(long dep, string step, int? percent) => InTx(() =>
        Execute("UPDATE deployment_target SET step=?, percent=? WHERE deployment_id=? AND step IN ('queued', 'verifying')", step, percent, dep));

    /// <summary>The running process says it still works on <paramref name="dep"/> (see <see cref="FailInterruptedDeployments"/>).</summary>
    /// The heartbeat is written even after another instance closed the deployment as interrupted: a heartbeat that keeps
    /// coming shows the owner is alive (see <see cref="RetryBlockedByOwner"/>).
    public void TouchDeployment(long dep) => InTx(() =>
        Execute("UPDATE deployment SET heartbeat=? WHERE id=?", Db.UtcNow(), dep));

    /// <summary>Close a deployment; its status from the outcomes: done / partial / failed / skipped.</summary>
    public string FinishDeployment(long dep) => InTx(() =>
    {
        if (Query("SELECT status FROM deployment WHERE id=?", dep) is [{ } was] && was["status"] as string is { } st && st != "running")
            Execute("INSERT INTO deployment_event (deployment_id, ts, name, message) VALUES (?,?,?,?)", dep, Db.UtcNow(), "",
                    $"NOTE: the deployment had already been closed ({st}); the status is computed again from the results that came in since");
        var outs = Query("SELECT outcome FROM deployment_target WHERE deployment_id=?", dep).Select(r => r["outcome"] as string).ToList();
        var real = outs.Where(o => o is not ("unreachable" or "current")).ToList();     // these two do not count either way
        var bad = real.Count(o => o is not ("ok" or "reboot"));
        var status = real.Count == 0 ? "skipped" : bad == 0 ? "done" : bad == real.Count ? "failed" : "partial";
        Execute("UPDATE deployment SET status=?, finished=? WHERE id=?", status, Db.UtcNow(), dep);
        return status;
    });

    /// <summary>A "running" deployment whose owner has not said it is alive for this long is taken as interrupted when the
    /// owner cannot be checked directly (another computer, a process this account may not inspect, an older version).</summary>
    public static readonly TimeSpan DeploymentStaleAfter = TimeSpan.FromMinutes(10);

    /// <summary>At start-up: close the deployments still marked running whose process is gone (it stopped during the run).
    /// A deployment another live ADmiral process (the program, while the retry service or the command line starts) is
    /// running is left alone. The owner is checked by PID and process start time on this computer (a reused PID is
    /// another process); when that is not possible, by its heartbeat (<see cref="DeploymentStaleAfter"/>).
    /// <paramref name="probe"/> replaces the process check (tests).</summary>
    public int FailInterruptedDeployments(DateTimeOffset? now = null, Func<string?, long?, string?, OwnerState>? probe = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        probe ??= DeploymentOwner.Probe;
        var closed = new List<(long Id, string Why)>();
        var ids = InTx(() =>
        {
            foreach (var r in Query("SELECT id, created, owner_host, owner_pid, owner_started, heartbeat FROM deployment WHERE status='running'"))
            {
                var dep = (long)r["id"]!;
                var state = probe(r["owner_host"] as string, r["owner_pid"] as long?, r["owner_started"] as string);
                var last = Db.ParseIso(r["heartbeat"] as string) ?? Db.ParseIso(r["created"] as string);
                var stale = last is null || at - last.Value > DeploymentStaleAfter;
                string? why = state switch
                {
                    OwnerState.Gone => $"the process that ran it ({r["owner_host"]}, PID {r["owner_pid"]}) is no longer running",
                    OwnerState.Unknown when stale => $"no sign of life from the process that ran it since {r["heartbeat"] ?? r["created"]}",
                    _ => null,
                };
                if (why is null) continue;
                // closed on a stale heartbeat alone (the owner could not be checked): a repeat waits until it is clear
                // the owner is really gone, or the same package could be sent while it is still installing
                if (state == OwnerState.Unknown) Execute("UPDATE deployment SET closed_unverified=1 WHERE id=?", dep);
                Execute("UPDATE deployment_target SET step='done', outcome='failed', finished=?, "
                        + "error='Interrupted: the program stopped during the deployment' WHERE deployment_id=? AND step!='done'",
                        Db.UtcNow(), dep);
                closed.Add((dep, why));
            }
            return closed;
        });
        foreach (var (dep, why) in ids)
        {
            AddDeploymentEvent(dep, $"Closed as interrupted at start-up: {why}");
            FinishDeployment(dep);
        }
        return ids.Count;
    }

    /// <summary>Why a repeat of <paramref name="dep"/> must wait (null = it may run): the deployment was closed as
    /// interrupted on a stale heartbeat alone, and its owner is not known to be gone - it is alive on this computer, or
    /// its heartbeat came again within <see cref="DeploymentStaleAfter"/>.</summary>
    public string? RetryBlockedByOwner(long dep, DateTimeOffset? now = null, Func<string?, long?, string?, OwnerState>? probe = null)
    {
        if (Query("SELECT closed_unverified, owner_host, owner_pid, owner_started, heartbeat, created FROM deployment WHERE id=?", dep)
            is not [{ } r] || r["closed_unverified"] is not (long and 1)) return null;
        var state = (probe ?? DeploymentOwner.Probe)(r["owner_host"] as string, r["owner_pid"] as long?, r["owner_started"] as string);
        if (state == OwnerState.Gone) return null;
        if (state == OwnerState.Alive) return $"{r["owner_host"]} (PID {r["owner_pid"]})";
        var last = Db.ParseIso(r["heartbeat"] as string) ?? Db.ParseIso(r["created"] as string);
        return last is { } l && (now ?? DateTimeOffset.UtcNow) - l <= DeploymentStaleAfter ? $"{r["owner_host"] ?? "?"} (PID {r["owner_pid"]})" : null;
    }

    /// <summary>Deployments (newest first) with per-state counts of their computers and the average run time.</summary>
    public List<Row> Deployments(int limit = 5000)
    {
        var rows = Query("SELECT * FROM deployment ORDER BY id DESC LIMIT ?", limit);
        var by = Query("SELECT deployment_id, step, outcome, started, finished FROM deployment_target")
            .GroupBy(r => (long)r["deployment_id"]!).ToDictionary(g => g.Key, g => g.ToList());
        foreach (var d in rows)
        {
            var c = by.GetValueOrDefault((long)d["id"]!) ?? [];
            d["total"] = c.Count;
            d["queued"] = c.Count(r => (r["step"] as string) == "queued");
            d["running"] = c.Count(r => r["step"] as string is not ("queued" or "done"));
            foreach (var o in new[] { "ok", "reboot", "failed", "unreachable", "current" })
                d[o] = c.Count(r => (r["outcome"] as string) == o);
            var secs = c.Select(r => (Db.ParseIso(r["started"] as string), Db.ParseIso(r["finished"] as string)))
                        .Where(p => p.Item1 is not null && p.Item2 is not null)
                        .Select(p => (p.Item2!.Value - p.Item1!.Value).TotalSeconds).ToList();
            d["avg_seconds"] = secs.Count > 0 ? (long)Math.Round(secs.Average(), MidpointRounding.ToEven) : null;
        }
        return rows;
    }

    /// <summary>One deployment with its "targets" (by name).</summary>
    public Row? Deployment(long dep)
    {
        var r = Query("SELECT * FROM deployment WHERE id=?", dep);
        if (r.Count == 0) return null;
        var d = r[0];
        d["targets"] = Query("SELECT * FROM deployment_target WHERE deployment_id=? ORDER BY name COLLATE NOCASE", dep);
        return d;
    }

    // ------------------------------------------------------------------ printers
    public static readonly IReadOnlyList<string> PrinterEditFields =
        ["ip", "model", "location", "note", "community", "version", "oid_model", "oid_toner", "oid_toner_max", "oid_pages", "oid_serial", "oid_status"];

    public static readonly IReadOnlyList<string> PrinterStateFields = ["toner", "pages", "serial", "status", "polled", "error", "model"];

    private static Row PrinterRow(Row d)
    {
        d["toner"] = ParseJson(d["toner"] as string is { Length: > 0 } t ? t : "[]");
        return d;
    }

    public List<Row> Printers() => [.. Query("SELECT * FROM printer ORDER BY id").Select(PrinterRow)];

    public Row? Printer(long pid) => Query("SELECT * FROM printer WHERE id=?", pid).Select(PrinterRow).FirstOrDefault();

    /// <summary>Add a printer from its editable fields (other keys are ignored); returns its id.</summary>
    public long AddPrinter(IReadOnlyDictionary<string, object?> fields)
    {
        var cols = PrinterEditFields.Where(fields.ContainsKey).ToList();
        return InTx(() =>
        {
            var names = string.Concat(cols.Select(c => c + ", "));
            var marks = string.Concat(cols.Select(_ => "?, "));
            Execute($"INSERT INTO printer ({names}updated) VALUES ({marks}?)", [.. cols.Select(c => fields[c]), Db.UtcNow()]);
            return LastId();
        });
    }

    /// <summary>Update edit fields and / or reading fields; a hand edit also stamps "updated" (sync merges by it).</summary>
    public void UpdatePrinter(long pid, IReadOnlyDictionary<string, object?> fields)
    {
        var cols = fields.Keys.Where(k => PrinterEditFields.Contains(k) || PrinterStateFields.Contains(k))
                         .Select(k => PrinterEditFields.Concat(PrinterStateFields).First(c => c == k)).Distinct().ToList();
        if (cols.Count == 0) return;
        var vals = cols.Select(c => c == "toner" ? Db.ToJson(fields[c]) : fields[c]).ToList();
        if (cols.Any(PrinterEditFields.Contains))
        {
            cols.Add("updated");
            vals.Add(Db.UtcNow());
        }
        InTx(() => Execute($"UPDATE printer SET {string.Join(", ", cols.Select(c => c + "=?"))} WHERE id=?", [.. vals, pid]));
    }

    public bool DeletePrinter(long pid) => InTx(() =>
    {
        if (Scalar("SELECT ip FROM printer WHERE id=?", pid) is string ip)
            Execute("DELETE FROM printer_history WHERE ip=?", ip);
        return Execute("DELETE FROM printer WHERE id=?", pid) > 0;
    });

    /// <summary>The reading of one day (a later reading the same day replaces it).</summary>
    public void SavePrinterSample(string ip, string day, long? pages, IEnumerable<int?> toner) => InTx(() =>
        Execute("INSERT INTO printer_history (ip, day, taken_at, pages, toner) VALUES (?,?,?,?,?) "
                + "ON CONFLICT(ip, day) DO UPDATE SET taken_at=excluded.taken_at, pages=excluded.pages, toner=excluded.toner",
                ip, day, Db.UtcNow(), pages, Db.ToJson(toner.ToList())));

    /// <summary>The newest <paramref name="limit"/> daily readings, oldest first: [{day, pages, toner}].</summary>
    public List<Row> PrinterHistory(string ip, int limit = 800)
    {
        var rows = Query("SELECT day, pages, toner FROM printer_history WHERE ip=? ORDER BY day DESC LIMIT ?", ip, limit);
        rows.Reverse();
        return [.. rows.Select(r => new Row { ["day"] = r["day"], ["pages"] = r["pages"], ["toner"] = ParseJson(r["toner"] as string is { Length: > 0 } t ? t : "[]") })];
    }

    /// <summary>{ip (lower case): the newest day with a reading}.</summary>
    public Dictionary<string, string> PrinterSampleDays() =>
        Query("SELECT ip, MAX(day) AS day FROM printer_history GROUP BY ip")
            .ToDictionary(r => ((string)r["ip"]!).ToLowerInvariant(), r => (string)r["day"]!);

    // ------------------------------------------------------------------ activity
    public void Log(string action, string detail = "") => InTx(() =>
        Execute("INSERT INTO activity (ts, action, detail) VALUES (?, ?, ?)", Db.UtcNow(), action, detail));

    /// <summary>[{id, ts, action, detail}], newest first.</summary>
    public List<Row> Activity(int limit = 200) => Query("SELECT * FROM activity ORDER BY id DESC LIMIT ?", limit);
}
