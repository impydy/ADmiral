using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

[SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python PackageError")]
public sealed class PackageError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>One stored file of a package (<c>path</c> is relative to the library folder, always with '/').</summary>
public sealed class PackageFile
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    /// <summary>The version the file belongs to; null in older registers (then it is the folder name).</summary>
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("added")] public string? Added { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "installer";
    [JsonPropertyName("vendor_checked")] public bool VendorChecked { get; set; }
    /// <summary>SHA-1 (hex) of the file: the Windows Update Catalog publishes this one (and the SHA-256) in base64.</summary>
    [JsonPropertyName("sha1"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Sha1 { get; set; }
    /// <summary>Where the checked hash came from: vendor | catalog (looked up in the Windows Update Catalog) | catalog-name
    /// (the SHA-1 the catalog puts into the file name).</summary>
    [JsonPropertyName("hash_source"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? HashSource { get; set; }
    /// <summary>catalog: the title of the catalog entry the file was found in.</summary>
    [JsonPropertyName("catalog_title"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? CatalogTitle { get; set; }

    public PackageFile Copy() => (PackageFile)MemberwiseClone();
}

/// <summary>One step of a package's chain (see <see cref="Chain"/>). Which fields count depends on <see cref="Type"/>.</summary>
public sealed class PackageStep
{
    /// <summary>install | copy | delete | scan | reboot | shutdown | wol | powershell | cmd | wait | message</summary>
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    /// <summary>install / copy: a file of this package (register path).</summary>
    [JsonPropertyName("file"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? File { get; set; }
    /// <summary>install: the installer's switches.</summary>
    [JsonPropertyName("args"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Args { get; set; }
    /// <summary>copy: the destination folder on the computer; delete: the file to delete.</summary>
    [JsonPropertyName("path"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Path { get; set; }
    /// <summary>powershell / cmd: the script run as SYSTEM.</summary>
    [JsonPropertyName("script"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Script { get; set; }
    /// <summary>message: the text shown to the users logged on to the computer.</summary>
    [JsonPropertyName("text"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Text { get; set; }
    /// <summary>reboot / shutdown: delay before it happens; wol: how long to wait for the computer to come up;
    /// wait: the pause; message: how long the message stays on the screen.</summary>
    [JsonPropertyName("seconds"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public int? Seconds { get; set; }
    /// <summary>reboot: wait until the computer is back before the next step.</summary>
    [JsonPropertyName("wait"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? Wait { get; set; }
    /// <summary>Go on with the next step when this one fails (the computer's result is still "failed").</summary>
    [JsonPropertyName("continue_on_error"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? ContinueOnError { get; set; }
}

public sealed class PackageEntry
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    /// <summary>null: a library package (files); "chain": an installation chain (steps only, it uses the library's files);
    /// "winupdate": a Windows update (.msu / .cab) for one Windows build.</summary>
    [JsonPropertyName("kind"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Kind { get; set; }
    /// <summary>winupdate: the Windows build it is for, e.g. 10.0.26100.</summary>
    [JsonPropertyName("os_build"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? OsBuild { get; set; }
    /// <summary>winupdate: the update's KB number, e.g. KB5043080.</summary>
    [JsonPropertyName("kb"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Kb { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("publisher")] public string Publisher { get; set; } = "";
    [JsonPropertyName("version")] public string Version { get; set; } = "";
    [JsonPropertyName("added")] public string? Added { get; set; }
    [JsonPropertyName("downloaded")] public string? Downloaded { get; set; }
    [JsonPropertyName("verified")] public string? Verified { get; set; }
    [JsonPropertyName("verify_ok")] public bool? VerifyOk { get; set; }
    [JsonPropertyName("source_hash_checked")] public bool? SourceHashChecked { get; set; }
    [JsonPropertyName("files")] public List<PackageFile> Files { get; set; } = [];
    /// <summary>The chain run on each computer when the package is deployed as a whole (empty: only single installers).</summary>
    [JsonPropertyName("steps")] public List<PackageStep> Steps { get; set; } = [];
}

public sealed class PackageManifest
{
    [JsonPropertyName("format")] public int Format { get; set; } = 1;
    [JsonPropertyName("updated")] public string? Updated { get; set; }
    [JsonPropertyName("packages")] public List<PackageEntry> Packages { get; set; } = [];
}

public sealed record PackageProblem([property: JsonPropertyName("path")] string Path, [property: JsonPropertyName("problem")] string Problem);

public sealed record PackageVerifyResult(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("problems")] IReadOnlyList<PackageProblem> Problems);

public sealed record PackageVersionRow(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("files")] int Files,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("added")] string Added);

/// <summary>A package as the UI lists it.</summary>
public sealed record PackageRow(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string? Kind,
    [property: JsonPropertyName("os_build")] string? OsBuild,
    [property: JsonPropertyName("kb")] string? Kb,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("publisher")] string Publisher,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("added")] string? Added,
    [property: JsonPropertyName("downloaded")] string? Downloaded,
    [property: JsonPropertyName("verified")] string? Verified,
    [property: JsonPropertyName("verify_ok")] bool? VerifyOk,
    [property: JsonPropertyName("source_hash_checked")] bool? SourceHashChecked,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("versions")] IReadOnlyList<PackageVersionRow> Versions,
    [property: JsonPropertyName("files")] IReadOnlyList<PackageFile> Files,
    [property: JsonPropertyName("steps")] IReadOnlyList<PackageStep> Steps);

/// <summary>Package library: application installers added by hand into a folder, with versions and a hash register.
/// <para>Files are stored under <c>&lt;folder&gt;/&lt;id&gt;/&lt;version&gt;/</c> and <c>&lt;folder&gt;/packages.json</c>
/// records every file with its version, size and SHA-256 (and whether the vendor's published SHA-256 was checked).
/// <see cref="Verify"/> re-hashes the files and reports anything missing or changed. Nothing is installed anywhere by
/// the library itself: it only holds files. The register is a plain JSON file that could have been edited, so every
/// path read from it is checked to stay inside the library folder (<see cref="File"/>).</para></summary>
public sealed partial class PackageLibrary(string folder)
{
    public const string Manifest = "packages.json";
    public const long MaxManifestBytes = 64L * 1024 * 1024;
    /// <summary>Upper bound for one uploaded file.</summary>
    public static long MaxUploadBytes { get; set; } = 16L * 1024 * 1024 * 1024;

    internal static readonly Lock Sync = new();                      // one library writer at a time (process-wide)

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public string Folder { get; } = System.IO.Path.GetFullPath(folder);
    public string ManifestPath => System.IO.Path.Combine(Folder, Manifest);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")]
    private static partial Regex IdRe();

    [GeneratedRegex(@"^[0-9a-f]{64}$")]
    internal static partial Regex ShaRe();

    [GeneratedRegex(@"[^\w.+-]")]
    private static partial Regex Unsafe();

    private static readonly StringComparison PathCmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static string ValidId(string? pkgId)
    {
        var pid = (pkgId ?? "").Trim();
        if (!IdRe().IsMatch(pid)) throw new PackageError($"Not a valid package ID: '{pkgId}'");
        return pid;
    }

    internal static string Now() => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'+00:00'", CultureInfo.InvariantCulture);

    public static string Sha256File(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024);
        return Convert.ToHexStringLower(SHA256.HashData(f));
    }

    /// <summary>SHA-256 and SHA-1 (lower-case hex) of a file, read once.</summary>
    public static (string Sha256, string Sha1) HashesFile(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024);
        using var h256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var h1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var buf = new byte[1024 * 1024];
        int n;
        while ((n = f.Read(buf)) > 0)
        {
            h256.AppendData(buf, 0, n);
            h1.AppendData(buf, 0, n);
        }
        return (Convert.ToHexStringLower(h256.GetHashAndReset()), Convert.ToHexStringLower(h1.GetHashAndReset()));
    }

    /// <summary>A published hash in any of the forms vendors and the Windows Update Catalog use: SHA-256 or SHA-1, as hex
    /// (64 / 40 characters) or base64 (44 / 28 characters). Returns (algorithm, lower-case hex) or null.</summary>
    public static (string Alg, string Hex)? ParseDigest(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 64 && ShaRe().IsMatch(v.ToLowerInvariant())) return ("sha256", v.ToLowerInvariant());
        if (v.Length == 40 && Sha1Re().IsMatch(v.ToLowerInvariant())) return ("sha1", v.ToLowerInvariant());
        if (v.Length is 44 or 28)
        {
            var bytes = new byte[32];
            if (Convert.TryFromBase64String(v, bytes, out var n) && n is 32 or 20)
                return (n == 32 ? "sha256" : "sha1", Convert.ToHexStringLower(bytes.AsSpan(0, n)));
        }
        return null;
    }

    [GeneratedRegex(@"^[0-9a-f]{40}$")]
    internal static partial Regex Sha1Re();

    /// <summary>A file/folder name made of safe characters; never "." or "..".</summary>
    internal static string Safe(string part)
    {
        var s = LooseValue.Cut(Unsafe().Replace(part, "_"), 80);
        return s is "" or "." or ".." ? "_" : s;
    }

    /// <summary>The version a stored file belongs to (older registers did not record it: it is the folder name).</summary>
    public static string FileVersion(PackageEntry entry, PackageFile rec)
    {
        if (rec.Version is not null) return rec.Version;
        var parts = rec.Path.Split('/');
        return parts.Length >= 3 && parts[1] != "manual" ? parts[1] : entry.Version ?? "";
    }

    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>A file of the library by its register path; never anything outside the library folder. Absolute paths,
    /// drive letters, '..' segments, alternate data streams, device names and links that lead outside are refused.</summary>
    public string File(string rel)
    {
        var r = rel ?? "";
        if (r.Length == 0 || r.Length > 1024 || r.Contains('\0') || r.Contains(':') || System.IO.Path.IsPathRooted(r)
            || r.StartsWith('/') || r.StartsWith('\\'))
            throw new PackageError($"'{rel}' is outside the package library");
        var segments = r.Split('/', '\\');
        foreach (var seg in segments)
        {
            var stem = seg.Split('.')[0];
            if (seg is "" or "." or ".." || seg.EndsWith(' ') || Reserved.Contains(stem))
                throw new PackageError($"'{rel}' is outside the package library");
        }
        var baseDir = RealPath(Folder);
        var full = System.IO.Path.GetFullPath(System.IO.Path.Combine([baseDir, .. segments]));
        if (!IsInside(baseDir, full)) throw new PackageError($"'{rel}' is outside the package library");
        // a link (symlink / junction) inside the library must not lead outside of it either
        var cur = baseDir;
        foreach (var seg in segments)
        {
            cur = System.IO.Path.Combine(cur, seg);
            FileSystemInfo info = Directory.Exists(cur) ? new DirectoryInfo(cur) : new FileInfo(cur);
            if (!info.Exists) break;
            if (info.LinkTarget is not null)
            {
                var target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
                if (target is null || !IsInside(baseDir, System.IO.Path.GetFullPath(target)))
                    throw new PackageError($"'{rel}' is outside the package library");
            }
        }
        return full;
    }

    private static string RealPath(string dir)
    {
        try
        {
            var di = new DirectoryInfo(dir);
            if (di.Exists && di.LinkTarget is not null && di.ResolveLinkTarget(true) is { } t) return System.IO.Path.GetFullPath(t.FullName);
        }
        catch (IOException) { }
        return System.IO.Path.TrimEndingDirectorySeparator(dir);
    }

    private static bool IsInside(string baseDir, string full)
    {
        var b = System.IO.Path.TrimEndingDirectorySeparator(baseDir) + System.IO.Path.DirectorySeparatorChar;
        return full.StartsWith(b, PathCmp) && full.Length > b.Length;
    }

    // ---------------------------------------------------------------- register
    public PackageManifest Load()
    {
        lock (Sync)
        {
            try
            {
                var fi = new FileInfo(ManifestPath);
                if (!fi.Exists) return new PackageManifest();
                if (fi.Length > MaxManifestBytes) throw new PackageError($"{ManifestPath} cannot be read: too large");
                var data = JsonSerializer.Deserialize<PackageManifest>(System.IO.File.ReadAllBytes(ManifestPath)) ?? new PackageManifest();
                data.Packages ??= [];
                foreach (var p in data.Packages) { p.Files ??= []; p.Steps ??= []; }
                data.Packages.RemoveAll(p => p is null || string.IsNullOrEmpty(p.Id));
                return data;
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or JsonException)
            {
                throw new PackageError($"{ManifestPath} cannot be read: {exc.Message}", exc);
            }
        }
    }

    public void Save(PackageManifest data)
    {
        lock (Sync)
        {
            Directory.CreateDirectory(Folder);
            data.Updated = Now();
            var tmp = System.IO.Path.ChangeExtension(ManifestPath, ".tmp");
            System.IO.File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(data, Json));
            System.IO.File.Move(tmp, ManifestPath, overwrite: true);
        }
    }

    private static PackageEntry? Find(PackageManifest data, string pkgId) =>
        data.Packages.FirstOrDefault(p => string.Equals(p.Id, pkgId, StringComparison.OrdinalIgnoreCase));

    public PackageEntry? Get(string pkgId) => Find(Load(), pkgId ?? "");

    // ---------------------------------------------------------------- changes
    public void Remove(string pkgId, bool deleteFiles = true)
    {
        string id;
        lock (Sync)
        {
            var data = Load();
            var entry = Find(data, pkgId ?? "") ?? throw new PackageError($"{pkgId} is not in the library.");
            id = entry.Id;
            data.Packages.Remove(entry);
            Save(data);
        }
        if (!deleteFiles) return;
        string dir;
        try { dir = File(Safe(id)); }
        catch (PackageError) { return; }                                     // never delete outside the library
        try
        {
            var di = new DirectoryInfo(dir);
            if (di.LinkTarget is not null) di.Delete();                      // a link: remove the link, not its target
            else if (di.Exists) di.Delete(recursive: true);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>A new package without files (its chain can then be put together and files added).</summary>
    public PackageEntry Create(string pkgId, string name, string version = "", string publisher = "", string? kind = null)
    {
        var id = ValidId(pkgId);
        if (kind is not (null or "chain")) throw new PackageError($"Not a package kind: '{kind}'");
        lock (Sync)
        {
            var data = Load();
            if (Find(data, id) is not null) throw new PackageError($"{id} is already in the library.");
            var entry = new PackageEntry
            {
                Id = id, Name = string.IsNullOrWhiteSpace(name) ? id : LooseValue.Cut(name.Trim(), 200),
                Version = LooseValue.Cut((version ?? "").Trim(), 64), Publisher = LooseValue.Cut((publisher ?? "").Trim(), 200), Added = Now(),
                Kind = kind,
            };
            data.Packages.Add(entry);
            Save(data);
            return entry;
        }
    }

    /// <summary>Replace the chain of a package (checked by <see cref="Chain.ValidateSteps"/>).</summary>
    public PackageEntry SetSteps(string pkgId, IReadOnlyList<PackageStep> steps)
    {
        lock (Sync)
        {
            var data = Load();
            var entry = Find(data, pkgId ?? "") ?? throw new PackageError($"{pkgId} is not in the library.");
            entry.Steps = Chain.ValidateSteps(entry, steps, data.Packages);
            Save(data);
            return entry;
        }
    }

    /// <summary>Remove one stored file (e.g. an old version) from the library and the disk.</summary>
    public PackageEntry RemoveFile(string pkgId, string path)
    {
        PackageEntry entry;
        PackageFile rec;
        lock (Sync)
        {
            var data = Load();
            entry = Find(data, pkgId ?? "") ?? throw new PackageError($"{pkgId}: no such file in the package.");
            rec = entry.Files.FirstOrDefault(f => f.Path == path) ?? throw new PackageError($"{pkgId}: no such file in the package.");
            entry.Files = entry.Files.Where(f => f.Path != path).ToList();
            PackageFile? newest = null;
            foreach (var f in entry.Files)
                if (newest is null || string.CompareOrdinal(f.Added ?? "", newest.Added ?? "") > 0) newest = f;
            entry.Version = newest is not null ? FileVersion(entry, newest) : "";
            entry.SourceHashChecked = entry.Files.Count > 0 && entry.Files.All(f => f.VendorChecked);
            Save(data);
        }
        var target = File(rec.Path);
        try
        {
            System.IO.File.Delete(target);
            var parent = System.IO.Path.GetDirectoryName(target);
            if (parent is not null && IsInside(RealPath(Folder), parent) && !Directory.EnumerateFileSystemEntries(parent).Any())
                Directory.Delete(parent);                                     // the version folder, once empty
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        return entry;
    }

    /// <summary>Store a file the user supplies: <c>using var u = lib.Upload(...); u.Write(chunk); ...; u.Commit();</c>.
    /// The file is hashed while it is written and registered by <see cref="PackageUpload.Commit"/>; disposing without
    /// a commit discards it.</summary>
    public PackageUpload Upload(string pkgId, string filename, string version = "", string title = "", string sha256 = "")
        => new(this, ValidId(pkgId), filename ?? "", LooseValue.Cut((version ?? "").Trim(), 60),
            LooseValue.Cut((title ?? "").Trim(), 120), (sha256 ?? "").Trim().ToLowerInvariant(), null);

    /// <summary>Store a Windows update (.msu / .cab) for <paramref name="osBuild"/>: the package is
    /// <c>WU-&lt;build&gt;-&lt;KB&gt;</c>, its name the KB number and its version the build the update brings
    /// (<see cref="WinUpdate"/>). <paramref name="digest"/> is the catalog's / vendor's hash in any form
    /// <see cref="ParseDigest"/> takes (optional).</summary>
    public PackageUpload UploadWinUpdate(string osBuild, string kb, string version, string filename, string digest = "")
    {
        var build = WinUpdate.ValidBuild(osBuild) ?? throw new PackageError($"Not a Windows build: '{osBuild}'");
        var k = WinUpdate.ValidKb(kb) ?? throw new PackageError($"Not a KB number: '{kb}'");
        var ver = WinUpdate.ValidVersion(version, build) ?? throw new PackageError($"Not a build version: '{version}'");
        if (!WinUpdate.IsUpdateFile(filename ?? "")) throw new PackageError("A Windows update must be an .msu or .cab file.");
        var d = (digest ?? "").Trim();
        (string Alg, string Hex)? parsed = d.Length == 0 ? null : ParseDigest(d) ?? throw new PackageError("The hash must be a SHA-256 or SHA-1, as hex or base64.");
        return new PackageUpload(this, WinUpdate.PackageId(build, k), filename ?? "", ver, k, parsed is { Alg: "sha256" } p ? p.Hex : "",
            new WinUpdateMeta(build, k, parsed is { Alg: "sha1" } p1 ? p1.Hex : ""));
    }

    /// <summary>Compare a published hash (the vendor's SHA-256, or the Windows Update Catalog's SHA-1 / SHA-256, hex or
    /// base64 - see <see cref="ParseDigest"/>) with a stored file (hashed again now). A match marks the file as checked; a
    /// mismatch throws and changes nothing.</summary>
    public PackageEntry CheckVendorHash(string pkgId, string path, string sha256, string source = "vendor", string? catalogTitle = null)
    {
        var (alg, want) = ParseDigest(sha256) ?? throw new PackageError("The hash must be a SHA-256 (or, for Windows updates, a SHA-1), as hex or base64.");
        lock (Sync)
        {
            var data = Load();
            var entry = Find(data, pkgId ?? "") ?? throw new PackageError($"{pkgId}: no such file in the package.");
            var rec = entry.Files.FirstOrDefault(f => f.Path == path) ?? throw new PackageError($"{pkgId}: no such file in the package.");
            // SHA-1 is accepted only where the publisher gives nothing better: the Windows Update Catalog's updates
            if (alg == "sha1" && entry.Kind != "winupdate") throw new PackageError("The hash must be a SHA-256 (SHA-1 is accepted for Windows updates only).");
            var f = File(rec.Path);
            if (!System.IO.File.Exists(f)) throw new PackageError($"{rec.Path} is missing from the library.");
            var (h256, h1) = HashesFile(f);
            var actual = alg == "sha256" ? h256 : h1;
            if (actual != want)
                throw new PackageError($"{(alg == "sha256" ? "SHA-256" : "SHA-1")} mismatch for {rec.Path}: the published value is {want}, the file's is {actual}.");
            if (h256 != rec.Sha256) throw new PackageError($"{rec.Path} changed since it was added (SHA-256 {h256}, registered {rec.Sha256}).");
            rec.Sha1 = h1;
            rec.VendorChecked = true;
            rec.HashSource = source is "vendor" or "catalog" ? source : "vendor";
            if (catalogTitle is { Length: > 0 }) rec.CatalogTitle = LooseValue.Cut(catalogTitle, 300);
            entry.SourceHashChecked = entry.Files.All(x => x.VendorChecked);
            Save(data);
            return entry;
        }
    }

    // ---------------------------------------------------------------- verification
    /// <summary>Re-hash the files of one package.</summary>
    public (bool Ok, List<PackageProblem> Problems) VerifyEntry(PackageEntry entry)
    {
        if (entry.Files.Count == 0) return (false, [new PackageProblem("", "not_downloaded")]);
        var problems = new List<PackageProblem>();
        foreach (var r in entry.Files)
        {
            var p = File(r.Path);
            var fi = new FileInfo(p);
            if (!fi.Exists) problems.Add(new PackageProblem(r.Path, "missing"));
            else if (fi.Length != r.Size || Sha256File(p) != r.Sha256) problems.Add(new PackageProblem(r.Path, "changed"));
        }
        return (problems.Count == 0, problems);
    }

    public List<PackageVerifyResult> Verify(string? pkgId = null)
    {
        var outp = new List<PackageVerifyResult>();
        lock (Sync)
        {
            var data = Load();
            foreach (var p in data.Packages)
            {
                if (!string.IsNullOrEmpty(pkgId) && !string.Equals(p.Id, pkgId, StringComparison.OrdinalIgnoreCase)) continue;
                var (ok, problems) = VerifyEntry(p);
                if (p.Files.Count > 0)
                {
                    p.Verified = Now();
                    p.VerifyOk = ok;
                }
                outp.Add(new PackageVerifyResult(p.Id, ok, problems));
            }
            Save(data);
        }
        return outp;
    }

    /// <summary>Packages for the UI. Hashes are not recomputed here (see <see cref="Verify"/>); <c>verify_ok</c> is the last result.</summary>
    public List<PackageRow> Rows()
    {
        var rows = new List<PackageRow>();
        foreach (var p in Load().Packages)
        {
            var files = p.Files.Select(f =>
            {
                var c = f.Copy();
                c.Version = FileVersion(p, f);
                return c;
            }).ToList();
            var versions = new List<(string Version, int Files, long Size, string Added)>();
            foreach (var f in files)
            {
                var i = versions.FindIndex(v => v.Version == f.Version);
                if (i < 0)
                {
                    versions.Add((f.Version!, 0, 0, ""));
                    i = versions.Count - 1;
                }
                var v = versions[i];
                var added = f.Added ?? p.Downloaded ?? "";
                versions[i] = (v.Version, v.Files + 1, v.Size + f.Size, string.CompareOrdinal(added, v.Added) > 0 ? added : v.Added);
            }
            rows.Add(new PackageRow(p.Id, p.Kind, p.OsBuild, p.Kb, string.IsNullOrEmpty(p.Name) ? p.Id : p.Name, p.Publisher ?? "", p.Version ?? "",
                p.Added, p.Downloaded, p.Verified, p.VerifyOk ?? (files.Count > 0 ? true : null), p.SourceHashChecked,
                files.Where(f => f.Kind != "manifest").Sum(f => f.Size),
                versions.OrderByDescending(v => v.Added, StringComparer.Ordinal).Select(v => new PackageVersionRow(v.Version, v.Files, v.Size, v.Added)).ToList(),
                files, p.Steps ?? []));
        }
        return rows;
    }
}

/// <summary>What a Windows update upload adds to its package (see <see cref="PackageLibrary.UploadWinUpdate"/>).</summary>
public sealed record WinUpdateMeta(string OsBuild, string Kb, string Sha1);

/// <summary>An upload in progress (see <see cref="PackageLibrary.Upload"/>).</summary>
public sealed partial class PackageUpload : IDisposable
{
    private readonly PackageLibrary _lib;
    private readonly string _pid, _version, _title, _expected;
    private readonly WinUpdateMeta? _wu;
    private readonly IncrementalHash _sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
    private readonly string _tmp;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private FileStream? _file;
    private bool _done;

    public string Name { get; }
    public long Size { get; private set; }

    [GeneratedRegex("[\\\\/:*?\"<>|\\x00-\\x1f]")]
    private static partial Regex BadChars();

    internal PackageUpload(PackageLibrary lib, string pid, string filename, string version, string title, string sha256, WinUpdateMeta? wu)
    {
        var baseName = filename.Replace('\\', '/');
        baseName = baseName[(baseName.LastIndexOf('/') + 1)..];
        var name = BadChars().Replace(baseName, "_").Trim(' ', '.');
        var stem = name.Split('.')[0];
        if (name.Length == 0 || name.Length > 200 || name.Equals(PackageLibrary.Manifest, StringComparison.OrdinalIgnoreCase)
            || stem.ToUpperInvariant() is "CON" or "PRN" or "AUX" or "NUL" || System.Text.RegularExpressions.Regex.IsMatch(stem, "^(?i:COM|LPT)[1-9]$"))
            throw new PackageError("Not a valid file name.");
        if (sha256.Length > 0 && !PackageLibrary.ShaRe().IsMatch(sha256)) throw new PackageError("The SHA-256 must be 64 hexadecimal characters.");
        (_lib, _pid, Name, _version, _title, _expected, _wu) = (lib, pid, name, version, title, sha256, wu);
        var dl = Path.Combine(lib.Folder, "_download");
        Directory.CreateDirectory(dl);
        _tmp = Path.Combine(dl, $"upload-{Guid.NewGuid():N}-{PackageLibrary.Safe(name)}");
        _file = new FileStream(_tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    }

    public void Write(ReadOnlySpan<byte> chunk)
    {
        ObjectDisposedException.ThrowIf(_file is null, this);
        if (Size + chunk.Length > PackageLibrary.MaxUploadBytes) throw new PackageError("The file is too large.");
        _file.Write(chunk);
        _hash.AppendData(chunk);
        _sha1.AppendData(chunk);
        Size += chunk.Length;
    }

    public void Write(byte[] chunk) => Write(chunk.AsSpan());

    /// <summary>Check the hash and register the file (the newest version added becomes the package's current one).</summary>
    public PackageEntry Commit()
    {
        ObjectDisposedException.ThrowIf(_file is null || _done, this);
        _file.Dispose();
        _file = null;
        _done = true;
        try
        {
            if (Size == 0) throw new PackageError("The file is empty.");
            var actual = Convert.ToHexStringLower(_hash.GetHashAndReset());
            var sha1 = Convert.ToHexStringLower(_sha1.GetHashAndReset());
            if (_expected.Length > 0 && actual != _expected)
                throw new PackageError($"SHA-256 mismatch for {Name}: the vendor's value is {_expected}, the file's is {actual}. The file was not added.");
            if (_wu is { Sha1.Length: > 0 } && sha1 != _wu.Sha1)
                throw new PackageError($"SHA-1 mismatch for {Name}: the published value is {_wu.Sha1}, the file's is {sha1}. The file was not added.");
            // the Windows Update Catalog names its files <name>_<SHA-1>.msu: a name like that must match the content
            var nameSha1 = WinUpdate.NameSha1(Name);
            if (nameSha1 is not null && nameSha1 != sha1)
                throw new PackageError($"{Name}: the file name carries the Windows Update Catalog SHA-1 {nameSha1}, but the file's is {sha1}. " +
                                       "The file is damaged or not the one published; it was not added.");
            // a SHA-1 in the file name only shows the file is intact: anyone can name a file after its own hash, so it does
            // not make the file checked (the catalog lookup / a published hash does)
            var source = _expected.Length > 0 || _wu is { Sha1.Length: > 0 } ? (_wu is null ? "vendor" : "catalog") : nameSha1 is not null ? "catalog-name" : null;
            var isChecked = source is "vendor" or "catalog";
            lock (PackageLibrary.Sync)
            {
                var data = _lib.Load();
                var entry = data.Packages.FirstOrDefault(p => string.Equals(p.Id, _pid, StringComparison.OrdinalIgnoreCase));
                if (entry is null)
                {
                    entry = new PackageEntry { Id = _pid, Name = _pid, Added = PackageLibrary.Now() };
                    data.Packages.Add(entry);
                }
                if (_title.Length > 0) entry.Name = _title;
                if (_wu is not null)
                {
                    if (entry.Kind != "winupdate" && (entry.Files.Count > 0 || entry.Steps.Count > 0))
                        throw new PackageError($"{entry.Id} is already in the library as another kind of package.");
                    entry.Kind = "winupdate";
                    entry.OsBuild = _wu.OsBuild;
                    entry.Kb = _wu.Kb;
                    entry.Publisher = "Microsoft";
                }
                else if (entry.Kind is "chain" or "winupdate")
                    throw new PackageError($"{entry.Id} is not a file package: add its files {(entry.Kind == "chain" ? "to the library" : "as a Windows update")}.");
                var version = _version.Length > 0 ? _version : entry.Version ?? "";
                entry.Version = version;
                var rel = $"{PackageLibrary.Safe(_pid)}/{PackageLibrary.Safe(version.Length > 0 ? version : "manual")}/{Name}";
                var dest = _lib.File(rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                System.IO.File.Move(_tmp, dest, overwrite: true);
                entry.Files = entry.Files.Where(f => f.Path != rel).ToList();
                entry.Files.Add(new PackageFile
                {
                    Path = rel, Version = version, Added = PackageLibrary.Now(), Size = Size, Sha256 = actual, Kind = "installer",
                    VendorChecked = isChecked, Sha1 = sha1, HashSource = source,
                });
                entry.SourceHashChecked = entry.Files.All(f => f.VendorChecked);
                entry.Downloaded = entry.Verified = PackageLibrary.Now();
                entry.VerifyOk = true;
                _lib.Save(data);
                return entry;
            }
        }
        finally
        {
            Cleanup();
        }
    }

    private void Cleanup()
    {
        try
        {
            if (System.IO.File.Exists(_tmp)) System.IO.File.Delete(_tmp);
            var dir = Path.GetDirectoryName(_tmp)!;
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any()) Directory.Delete(dir);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    public void Dispose()
    {
        _file?.Dispose();
        _file = null;
        _hash.Dispose();
        _sha1.Dispose();
        if (!_done)
        {
            _done = true;
            Cleanup();
        }
    }
}
