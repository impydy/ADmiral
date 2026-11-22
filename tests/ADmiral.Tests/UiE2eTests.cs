using System.Diagnostics;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>A fact that runs only where node + the playwright package are installed (opt-in, as test_ui_e2e.py).</summary>
public sealed class PlaywrightFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> Missing = new(Check);

    public PlaywrightFactAttribute()
    {
        if (Missing.Value is { } why) Skip = why;
    }

    internal static string? NodePath()
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            foreach (var name in OperatingSystem.IsWindows() ? new[] { "node.exe" } : ["node"])
            {
                var p = Path.Combine(dir, name);
                if (File.Exists(p)) return p;
            }
        }
        return null;
    }

    /// <summary>NODE_PATH with the global npm modules (where `npm i -g playwright` puts it).</summary>
    internal static string NodeModules()
    {
        try
        {
            var psi = new ProcessStartInfo(OperatingSystem.IsWindows() ? "npm.cmd" : "npm") { RedirectStandardOutput = true, RedirectStandardError = true };
            psi.ArgumentList.Add("root");
            psi.ArgumentList.Add("-g");
            using var p = Process.Start(psi)!;
            var root = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(20_000);
            // also a per-user install: npm install -g --prefix ~/.local playwright
            var user = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "lib", "node_modules");
            return string.Join(Path.PathSeparator, new[] { root, Directory.Exists(user) ? user : null, Environment.GetEnvironmentVariable("NODE_PATH") }
                .Where(s => !string.IsNullOrEmpty(s)));
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return Environment.GetEnvironmentVariable("NODE_PATH") ?? "";
        }
    }

    private static string? Check()
    {
        if (UiE2eTests.Script() is null) return "e2e/ui_smoke.js not found";
        var node = NodePath();
        if (node is null) return "node not available";
        var psi = new ProcessStartInfo(node) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add("require('playwright')");
        psi.Environment["NODE_PATH"] = NodeModules();
        using var p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return p.ExitCode == 0 ? null : "node + playwright not available";
    }
}

/// <summary>tests/test_ui_e2e.py: tests/e2e/ui_smoke.js drives the real page in Chromium against a live server.</summary>
public sealed class UiE2eTests
{
    internal static string? Script()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var p = Path.Combine(dir.FullName, "e2e", "ui_smoke.js");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    [PlaywrightFact]
    public void Ui_end_to_end()
    {
        // disposed with the web fixture
        var fx = new ServiceFixture(editable: true, settings: new Settings { Mode = "demo", DbPath = ":memory:", Language = "hu" });
        fx.App.FullScan();
        using var w = new WebFixture(fx: fx);
        var psi = new ProcessStartInfo(PlaywrightFactAttribute.NodePath()!) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(Script()!);
        psi.ArgumentList.Add($"http://127.0.0.1:{w.Base.Port}/?token={WebFixture.Token}");
        psi.Environment["NODE_PATH"] = PlaywrightFactAttribute.NodeModules();
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        Assert.True(p.WaitForExit(240_000), "ui_smoke.js timed out");
        Assert.True(p.ExitCode == 0, stdout.Result + stderr.Result);
    }
}
