using ADmiral.Core;

namespace ADmiral.Tests;

public class JobsTests
{
    private static JobInfo WaitDone(JobManager jm, int id)
    {
        for (var i = 0; i < 250; i++)
        {
            var j = jm.Get(id)!;
            if (j.Status != "running") return j;
            Thread.Sleep(20);
        }
        return jm.Get(id)!;
    }

    [Fact]
    public void JobsBusyErrorAndPruning()
    {
        var jm = new JobManager(keep: 3);
        using var gate = new ManualResetEventSlim();
        var j = jm.Start("scan", "s", _ => gate.Wait(2000));
        Assert.Throws<JobBusy>(() => jm.Start("scan", "again", _ => null));
        gate.Set();
        Assert.Equal("done", WaitDone(jm, j.Id).Status);
        var zero = 0;
        var bad = jm.Start("collect", "c", _ => 1 / zero, background: false);
        Assert.Equal("error", bad.Status);
        Assert.Contains("DivideByZeroException", bad.Error);
        Assert.NotNull(bad.Finished);
        for (var i = 0; i < 5; i++)
            jm.Start($"k{i}", "x", p =>
            {
                p.Report(1, 1, "m");
                return null;
            }, background: false);
        Assert.True(jm.List().Count <= 4);
        Assert.Null(jm.Get(99999));
    }

    [Fact]
    public void ProgressAndTrackingAreVisible()
    {
        var jm = new JobManager();
        using var inside = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var j = jm.Start("collect", "c", p =>
        {
            p.Report(1, 3, "one");
            Jobs.Track(p, "g1", "collect");
            Jobs.Track(p, "g2", "scan");
            Jobs.Track(p, "g2", null);
            inside.Set();
            release.Wait(2000);
            return 42;
        });
        Assert.True(inside.Wait(2000));
        var mid = jm.Get(j.Id)!;
        Assert.Equal((1, 3, "one"), (mid.Done, mid.Total, mid.Message));
        Assert.Equal(new Dictionary<string, string> { ["g1"] = "collect" }, mid.Active);
        release.Set();
        var done = WaitDone(jm, j.Id);
        Assert.Equal("done", done.Status);
        Assert.Equal(42, done.Result);
        Assert.Empty(done.Active);
        Assert.Equal("Finished", done.Message);
        Assert.Equal(j.Id, jm.List()[0].Id);
        Jobs.Track(null, "x", "y");                       // no progress: a no-op
    }

    [Fact]
    public void ExpectedFailureMessage()
    {
        var jm = new JobManager();
        var j = jm.Start("updates", "u", _ => throw new ArgumentException("no internet"), background: false);
        Assert.Equal("ArgumentException: no internet", j.Error);
        Assert.Equal("Failed", j.Message);
    }
}
