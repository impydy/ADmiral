using System.Diagnostics;
using ADmiral.Web;

namespace ADmiral.Tests;

/// <summary>A fact that runs only where node is installed.</summary>
public sealed class NodeFactAttribute : FactAttribute
{
    public NodeFactAttribute()
    {
        if (PlaywrightFactAttribute.NodePath() is null) Skip = "node not available";
        else if (WebXssTests.Script() is null || WebXssTests.WwwRoot() is null) Skip = "e2e/escape_test.js or wwwroot not found";
    }
}

/// <summary>HTML injection in the UI: values from AD / sync peers must never become markup.</summary>
public sealed class WebXssTests
{
    private static string? Up(params string[] parts)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var p = Path.Combine([dir.FullName, .. parts]);
            if (File.Exists(p) || System.IO.Directory.Exists(p)) return p;
        }
        return null;
    }

    internal static string? Script() => Up("e2e", "escape_test.js");

    /// <summary>The source wwwroot (the build copies it unchanged).</summary>
    internal static string? WwwRoot() => Up("src", "ADmiral.Web", "wwwroot") ?? Up("wwwroot");

    [NodeFact]
    public void Ui_escaping_helpers_t_bars_and_the_trusted_types_policy()
    {
        var psi = new ProcessStartInfo(PlaywrightFactAttribute.NodePath()!) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(Script()!);
        psi.ArgumentList.Add(WwwRoot()!);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        Assert.True(p.WaitForExit(60_000), "escape_test.js timed out");
        Assert.True(p.ExitCode == 0, stdout.Result + stderr.Result);
        Assert.Contains("escape tests ok", stdout.Result);
    }

    [Fact]
    public void Welcome_bars_escape_the_whole_data_node_attribute()
    {
        // static guard (runs without node too): the prefix must not be interpolated on its own
        var app = File.ReadAllText(Path.Combine(WwwRoot()!, "app.js"));
        Assert.DoesNotContain("data-node=\"${prefix}", app);
        Assert.Contains("data-node=\"${esc(prefix + label)}\"", app);
    }

    [Fact]
    public void Csp_requires_trusted_types_and_forbids_frames()
    {
        var csp = WebApp.SecurityHeaders["Content-Security-Policy"];
        Assert.Contains("require-trusted-types-for 'script'", csp);
        Assert.Contains("trusted-types default", csp);
        Assert.Contains("frame-src 'none'", csp);
        Assert.Contains("script-src 'self';", csp);                 // still no inline script
        Assert.DoesNotContain("unsafe-eval", csp);
        var index = File.ReadAllText(Path.Combine(WwwRoot()!, "index.html"));
        Assert.True(index.IndexOf("/static/tt.js", StringComparison.Ordinal) < index.IndexOf("/static/icons.js", StringComparison.Ordinal));
    }
}
