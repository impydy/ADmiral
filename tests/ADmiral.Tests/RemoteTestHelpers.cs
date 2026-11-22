using System.Diagnostics;
using System.Text;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>PowerShell 7 (pwsh) on PATH, for the tests that run the real inventory scripts.</summary>
internal static class Pwsh
{
    private static readonly Lazy<string?> PathLazy = new(() =>
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator))
        {
            foreach (var name in OperatingSystem.IsWindows() ? new[] { "pwsh.exe" } : ["pwsh"])
            {
                try
                {
                    var p = System.IO.Path.Combine(dir, name);
                    if (File.Exists(p)) return p;
                }
                catch (ArgumentException)
                {
                }
            }
        }
        return null;
    });

    public static string? Exe => PathLazy.Value;

    public const string SkipReason = "PowerShell 7 (pwsh) is not installed on this machine";

    /// <summary>Run <paramref name="script"/> with -EncodedCommand (exactly as ADmiral sends scripts).</summary>
    public static (int Code, string Stdout, string Stderr, byte[] Raw) Run(string script, string? exe = null)
    {
        var psi = new ProcessStartInfo(exe ?? Exe ?? throw new InvalidOperationException(SkipReason))
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var ms = new MemoryStream();
        var outTask = p.StandardOutput.BaseStream.CopyToAsync(ms);
        var err = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(2)))
        {
            p.Kill(true);
            throw new TimeoutException("pwsh did not finish");
        }
        outTask.Wait();
        var raw = ms.ToArray();
        return (p.ExitCode, Encoding.UTF8.GetString(raw), err.Result, raw);
    }
}

/// <summary>A fact that needs pwsh (skipped with a clear reason when it is not installed).</summary>
public sealed class PwshFactAttribute : FactAttribute
{
    public PwshFactAttribute()
    {
        if (Pwsh.Exe is null) Skip = Pwsh.SkipReason;
    }
}

/// <summary>A theory that needs pwsh (skipped with a clear reason when it is not installed).</summary>
public sealed class PwshTheoryAttribute : TheoryAttribute
{
    public PwshTheoryAttribute()
    {
        if (Pwsh.Exe is null) Skip = Pwsh.SkipReason;
    }
}

/// <summary>A theory that only runs on Windows.</summary>
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
    }
}

internal static class RepoRoot
{
    /// <summary>The repository root (the folder holding ADmiral.slnx), found upwards from the test binaries.</summary>
    public static string Path
    {
        get
        {
            for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
                if (File.Exists(System.IO.Path.Combine(d.FullName, "ADmiral.slnx"))) return d.FullName;
            throw new DirectoryNotFoundException("repository root not found");
        }
    }
}

/// <summary>Instant time for the polling loops: Sleep advances the clock.</summary>
internal class FakeClock : IClock
{
    public TimeSpan Elapsed { get; private set; }
    public List<TimeSpan> Sleeps { get; } = [];

    public void Sleep(TimeSpan duration)
    {
        Sleeps.Add(duration);
        Elapsed += duration;
    }
}

/// <summary>A target computer for the PDQ / deploy flows: its ADMIN$\Temp files, its SCM and the clock.</summary>
internal sealed class FakeTarget : FakeClock, IRemoteFiles, IServiceControl
{
    public Dictionary<string, byte[]> Files { get; } = [];
    /// <summary>Run folders that exist on the target.</summary>
    public HashSet<string> Dirs { get; } = [];
    public List<string> DirsCreated { get; } = [];
    /// <summary>Called with the bytes as they are read during PutLocal (e.g. to swap the local file mid-copy).</summary>
    public Action<int>? OnCopyChunk { get; set; }
    public string? FailAt { get; set; }
    public bool LeftoverService { get; set; }
    /// <summary>The script still runs and holds its .out file open.</summary>
    public bool Locked { get; set; }
    public List<string> Put { get; } = [];
    public List<string> Deleted { get; } = [];
    public List<string> Ran { get; } = [];
    public List<string> RanServices { get; } = [];
    public List<string> RemovedServices { get; } = [];
    public List<string> Killed { get; } = [];
    public List<string> ConnectedHosts { get; } = [];
    public int Connects { get; private set; }
    public int Closes { get; private set; }
    public Func<string, byte[]>? ReadOverride { get; set; }
    public Func<string, bool>? ExistsOverride { get; set; }
    /// <summary>What "running" the service does on the target.</summary>
    public Action<FakeTarget, string>? OnRun { get; set; }
    public int MaxFiles { get; private set; }

    public PdqBackend Backend => new(this, this, this);

    private void MaybeFail(string where)
    {
        if (FailAt == where) throw new InvalidOperationException($"boom at {where}");
    }

    /// <summary>The uploaded script as it was when the service ran (the files are gone afterwards).</summary>
    public string Script => _script ?? CurrentScript();

    private string? _script;

    private string CurrentScript() =>
        Encoding.UTF8.GetString(Files.First(kv => kv.Key.EndsWith(".ps1", StringComparison.Ordinal)).Value).TrimStart('\uFEFF');

    public string Base => Files.Keys.First(k => k.EndsWith(".ps1", StringComparison.Ordinal))[..^4];

    public IRemoteSession Connect(string host, SmbCreds creds, int timeoutSeconds)
    {
        MaybeFail("connect");
        Connects++;
        ConnectedHosts.Add(host);
        return new Session(this);
    }

    public void RunCommand(string host, SmbCreds creds, string command, string serviceName)
    {
        MaybeFail("run");
        Ran.Add(command);
        RanServices.Add(serviceName);
        if (Files.Keys.Any(k => k.EndsWith(".ps1", StringComparison.Ordinal))) _script = CurrentScript();
        OnRun?.Invoke(this, command);
    }

    public string RemoveService(string host, SmbCreds creds, string serviceName)
    {
        RemovedServices.Add(serviceName);
        MaybeFail("remove_service");
        return LeftoverService ? "removed" : "absent";
    }

    public void KillScript(string host, SmbCreds creds, string tag)
    {
        MaybeFail("kill");
        Killed.Add(tag);
        Locked = false;
    }

    private sealed class Session(FakeTarget t) : IRemoteSession
    {
        public void CreatePrivateDir(string shareDir)
        {
            Remote.ValidateShareDir(shareDir);
            t.MaybeFail("mkdir");
            if (!t.Dirs.Add(shareDir)) throw new IOException("exists");
            t.DirsCreated.Add(shareDir);
        }

        public void DeleteDir(string shareDir)
        {
            Remote.ValidateShareDir(shareDir);
            t.Deleted.Add(shareDir);
            if (t.Locked && t.Files.Keys.Any(k => k.StartsWith(shareDir + "\\", StringComparison.Ordinal)))
                throw new IOException("sharing violation");
            foreach (var k in t.Files.Keys.Where(k => k.StartsWith(shareDir + "\\", StringComparison.Ordinal)).ToList()) t.Files.Remove(k);
            t.Dirs.Remove(shareDir);
        }

        public bool DirExists(string shareDir) => t.Dirs.Contains(shareDir);

        private void RequireDir(string sharePath)
        {
            if (!t.Dirs.Contains(sharePath[..sharePath.LastIndexOf('\\')])) throw new DirectoryNotFoundException(sharePath);
        }

        public void PutFile(string sharePath, byte[] data)
        {
            Remote.ValidateSharePath(sharePath);
            RequireDir(sharePath);
            t.MaybeFail("put");
            t.Put.Add(sharePath);
            t.Files[sharePath] = data;
            t.MaxFiles = Math.Max(t.MaxFiles, t.Files.Count);
        }

        public void PutLocal(string sharePath, Stream source, Action<long, long>? progress = null)
        {
            Remote.ValidateSharePath(sharePath);
            RequireDir(sharePath);
            var total = source.CanSeek ? source.Length : 0;
            var ms = new MemoryStream();
            var buf = new byte[4];
            int n, chunk = 0;
            while ((n = source.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
                t.OnCopyChunk?.Invoke(chunk++);
            }
            var data = ms.ToArray();
            progress?.Invoke(data.Length / 2, total);
            progress?.Invoke(data.Length, total);
            t.Files[sharePath] = data;
            t.MaxFiles = Math.Max(t.MaxFiles, t.Files.Count);
        }

        public byte[] ReadFile(string sharePath, long maxBytes)
        {
            t.MaybeFail("read");
            if (t.ReadOverride is { } r) return r(sharePath);
            return t.Files.TryGetValue(sharePath, out var d) ? d : throw new FileNotFoundException(sharePath);
        }

        public void DeleteFile(string sharePath)
        {
            t.Deleted.Add(sharePath);
            if (t.Locked && sharePath.EndsWith(".out", StringComparison.Ordinal)) throw new IOException("sharing violation");
            t.Files.Remove(sharePath);
        }

        public bool FileExists(string sharePath) => t.ExistsOverride?.Invoke(sharePath) ?? t.Files.ContainsKey(sharePath);

        public void Dispose() => t.Closes++;
    }
}
