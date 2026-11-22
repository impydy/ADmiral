#pragma warning disable CA1873 // log arguments are cheap here
using System.Globalization;
using System.Security.Cryptography;
using ADmiral.Core;
using ADmiral.Web;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;

namespace ADmiral.Desktop;

/// <summary><c>ADmiral.exe --self-test</c>: headless check of a packaged build (server, token, bundled UI, native
/// libraries). Prints one line per check and exits 0 when all passed.</summary>
internal static class SelfTest
{
    public static int Run(DesktopArgs args)
    {
        Shell.AttachParentConsole();
        Shell.SetupLogging(args.Home ?? DesktopLogic.DataDir(DesktopEnv.Current()));     // log where users / CI expect it
        var tmp = Directory.CreateTempSubdirectory("admiral-selftest-").FullName;
        var checks = new List<(string Name, bool Ok)>();
        try
        {
            using var service = DesktopLogic.BuildService(tmp);         // offline check; a release ships no demo data
            var token = DesktopLogic.NewToken();
            var web = WebApp.Create(service, DesktopApp.WebOptions(token));
            web.StartAsync().GetAwaiter().GetResult();
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                checks.AddRange(DesktopChecks.HttpChecksAsync(http, WebApp.BoundAddress(web), token).GetAwaiter().GetResult());
            }
            finally
            {
                web.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                web.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            checks.Add(("sqlite", Try(() => service.Computers() is not null)));
            checks.Add(("dpapi", Try(() =>
            {
                var data = RandomNumberGenerator.GetBytes(16);
                var p = new DpapiProtector();
                return p.Unprotect(p.Protect(data)).AsSpan().SequenceEqual(data);
            })));
            checks.Add(("webview2 runtime", Try(() => !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()))));
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogError(exc, "self-test failed");
            checks.Add(("start", false));
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }   // SQLite / WAL files may linger
        }
        foreach (var (name, ok) in checks)
        {
            var line = string.Format(CultureInfo.InvariantCulture, "{0,-18} {1}", name, ok ? "ok" : "FAIL");
            Log.Logger.LogInformation("self-test {Line}", line);
            Console.WriteLine(line);
        }
        Diag.Uninstall();
        return checks.Count > 0 && checks.All(c => c.Ok) ? 0 : 1;
    }

    private static bool Try(Func<bool> check)
    {
        try
        {
            return check();
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogError("self-test check failed: {Type}: {Message}", exc.GetType().Name, exc.Message);
            return false;
        }
    }
}
