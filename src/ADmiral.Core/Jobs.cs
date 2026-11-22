using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// Tiny background job runner with progress reporting (port of admiral/jobs.py).

/// <summary>Progress callback handed to a job: <see cref="Report"/> (done, total, message) and <see cref="Track"/>
/// (which computer is being worked on right now). The counterpart of Python's <c>progress(done, total, msg)</c>
/// callable with its <c>track</c> attribute.</summary>
public class Progress(Action<int, int, string>? report = null, Action<string, string?>? track = null)
{
    /// <summary>A progress that discards everything.</summary>
    public static readonly Progress None = new();

    public virtual void Report(int done, int total, string message = "") => report?.Invoke(done, total, message);

    /// <summary>Mark <paramref name="key"/> as being worked on (<paramref name="phase"/>, e.g. "scan" / "collect")
    /// or finished (null).</summary>
    public virtual void Track(string key, string? phase) => track?.Invoke(key, phase);

    public void Invoke(int done, int total, string message = "") => Report(done, total, message);
}

/// <summary>Another job of the same kind is still running.</summary>
public sealed class JobBusy(string message) : InvalidOperationException(message);

/// <summary>A snapshot of a job, as the UI gets it (snake_case JSON).</summary>
public sealed record JobInfo
{
    [JsonPropertyName("id")] public int Id { get; init; }
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
    [JsonPropertyName("label")] public string Label { get; init; } = "";
    /// <summary>running | done | error</summary>
    [JsonPropertyName("status")] public string Status { get; init; } = "running";
    [JsonPropertyName("done")] public int Done { get; init; }
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("message")] public string Message { get; init; } = "";
    [JsonPropertyName("result")] public object? Result { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("started")] public string Started { get; init; } = "";
    [JsonPropertyName("finished")] public string? Finished { get; init; }
    /// <summary>key (guid) -> phase ("scan" | "collect") of the computers being queried right now.</summary>
    [JsonPropertyName("active")] public IReadOnlyDictionary<string, string> Active { get; init; } = new Dictionary<string, string>();
    [JsonPropertyName("trace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Trace { get; init; }
}

public static class Jobs
{
    /// <summary>Tell the job which computer is being queried right now (phase null = done with it).</summary>
    public static void Track(Progress? progress, string key, string? phase) => progress?.Track(key, phase);
}

public sealed class JobManager(int keep = 50)
{
    private readonly Lock _lock = new();
    private readonly SortedDictionary<int, JobInfo> _jobs = new();
    private int _ids;

    private sealed class JobProgress(JobManager owner, int id) : Progress
    {
        public override void Report(int done, int total, string message = "") =>
            owner.Update(id, j => j with { Done = done, Total = total, Message = message });

        public override void Track(string key, string? phase) => owner.Update(id, j =>
        {
            var active = new Dictionary<string, string>(j.Active);      // copy: readers get snapshots, never a live dict
            if (!string.IsNullOrEmpty(phase)) active[key] = phase;
            else active.Remove(key);
            return j with { Active = active };
        });
    }

    private void Update(int id, Func<JobInfo, JobInfo> change)
    {
        lock (_lock)
            if (_jobs.TryGetValue(id, out var j)) _jobs[id] = change(j);
    }

    /// <summary>Start a job (in a background thread, or inline with <paramref name="background"/> false).
    /// Throws <see cref="JobBusy"/> if a job of the same kind is running.</summary>
    public JobInfo Start(string kind, string label, Func<Progress, object?> fn, bool background = true)
    {
        int jobId;
        lock (_lock)
        {
            if (_jobs.Values.Any(j => j.Kind == kind && j.Status == "running"))
                throw new JobBusy(I18n.T("err.job_busy", ("kind", kind)));
            jobId = ++_ids;
            _jobs[jobId] = new JobInfo
            {
                Id = jobId, Kind = kind, Label = label, Status = "running", Message = "Starting…", Started = Db.UtcNow(),
            };
            foreach (var old in (keep > 0 ? _jobs.Keys.SkipLast(keep) : []).ToList())
                if (_jobs[old].Status != "running") _jobs.Remove(old);
        }

        var progress = new JobProgress(this, jobId);

        void Run()
        {
            // the final state is set in one step, so a reader never sees "done" with computers still active
            try
            {
                var result = fn(progress);
                Update(jobId, j => j with
                {
                    Status = "done", Result = result, Message = "Finished", Finished = Db.UtcNow(), Active = new Dictionary<string, string>(),
                });
            }
            catch (Exception ex)       // report every failure to the UI
            {
                if (ex is ArgumentException)             // an expected, explained failure (no internet, bad input...)
                    Log.Logger.LogWarning("Job {Id} ({Kind}) failed: {Error}", jobId, kind, ex.Message);
                else
                    Log.Logger.LogError(ex, "Job {Id} ({Kind}) failed", jobId, kind);
                var trace = ex.ToString();
                Update(jobId, j => j with
                {
                    Status = "error", Error = $"{ex.GetType().Name}: {ex.Message}", Message = "Failed",
                    Trace = Diag.Redact(trace.Length > 4000 ? trace[..4000] : trace),
                    Finished = Db.UtcNow(), Active = new Dictionary<string, string>(),
                });
            }
        }

        if (background)
            new Thread(Run) { Name = $"admiral-{kind}-{jobId}", IsBackground = true }.Start();
        else
            Run();
        return Get(jobId)!;
    }

    public JobInfo? Get(int jobId)
    {
        lock (_lock) return _jobs.GetValueOrDefault(jobId);
    }

    /// <summary>All kept jobs, newest first.</summary>
    public List<JobInfo> List()
    {
        lock (_lock) return [.. _jobs.Values.Reverse()];
    }
}
