#pragma warning disable CA1873 // log arguments are cheap here
using ADmiral.Core;
using ADmiral.Web;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ADmiral.Desktop;

/// <summary>The desktop window's start-up and shutdown (port of admiral/desktop.py main()). No browser is opened: the
/// API runs on a random loopback port that only this window can use, because every request must carry a per-launch
/// random token.</summary>
internal static class DesktopApp
{
    /// <summary>The web layer's options for the desktop window: loopback only, random port, the given token, the UI
    /// files next to the exe (when present), framework log messages into the ADmiral log.</summary>
    public static WebAppOptions WebOptions(string token)
    {
        var root = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        return new WebAppOptions
        {
            Token = token, Host = "127.0.0.1", Port = 0, AllowRemote = false,
            StaticRoot = File.Exists(Path.Combine(root, "index.html")) ? root : null,
            ExtraLogger = Diag.Provider,
        };
    }

#if DEBUG
    private const bool IsDebugBuild = true;
#else
    private const bool IsDebugBuild = false;
#endif

    public static int Run(DesktopArgs args)
    {
        var env = DesktopEnv.Current();
        // a program folder every user can change means anyone could swap ADmiral's files: never run from it
        if (DesktopLogic.ProgramDirProblem(env.ExeDir) is { } exeProblem)
        {
            Shell.MessageBox(DesktopLogic.AppName, exeProblem);
            return 1;
        }
        var home = Path.GetFullPath(args.Home ?? DesktopLogic.DataDir(env));
        try
        {
            Shell.SetupLogging(home);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            Shell.MessageBox(DesktopLogic.AppName, $"ADmiral could not use its data folder {home}:\n\n{exc.Message}");
            return 1;
        }
        Log.Logger.LogInformation("ADmiral {Version} starting, data dir {Home}", Diag.Version, home);
        var problem = DesktopLogic.SecureDataDir(home, dataUsers: DataFolderUsers(env.ExeDir));
        if (problem is not null)
        {
            Log.Logger.LogError("Not starting: {Problem}", problem);
            Shell.MessageBox(DesktopLogic.AppName, problem);
            return 1;
        }
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => Crash(e.Exception, home, fatal: false);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception exc) Crash(exc, home, fatal: true);
        };

        AdmiralService? service = null;
        Microsoft.AspNetCore.Builder.WebApplication? web = null;
        try
        {
            service = DesktopLogic.BuildService(home);
            var svc = service;
            // offline files left by computers that cannot reach this machine (never blocks the window)
            new Thread(() =>
            {
                try { svc.ImportOffline(); }
                catch (Exception exc) when (exc is not OutOfMemoryException) { Log.Logger.LogError(exc, "Offline folder import failed"); }
            }) { IsBackground = true, Name = "admiral-offline" }.Start();
            service.StartBackground();
            var token = DesktopLogic.NewToken();
            web = WebApp.Create(service, WebOptions(token));
            web.StartAsync().GetAwaiter().GetResult();
            var origin = WebApp.BoundAddress(web);
            Log.Logger.LogInformation("Internal API on {Origin}", origin.GetLeftPart(UriPartial.Authority));

            using var form = new MainForm(service, origin, token, home, DesktopLogic.WebViewDir(home, env),
                                          debug: IsDebugBuild || args.Debug || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADMIRAL_DEBUG")),
                                          uiTest: args.UiTest);
            // the update installer closes ADmiral too; leave the window cleanly first
            service.ExitAfterUpdate = form.ExitForUpdate;
            Application.Run(form);
            return form.ExitCode;
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)   // surface every start-up failure to the user
        {
            Log.Logger.LogError(exc, "Fatal: {Message}", exc.Message);
            Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.StartupFailureText(exc, home));
            return 1;
        }
        finally
        {
            // window closed: stop the API and wait for in-flight requests before closing the database
            if (web is not null)
            {
                try
                {
                    web.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                    web.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
                catch (Exception exc) when (exc is not OutOfMemoryException)
                {
                    Log.Logger.LogWarning("Stopping the internal API failed: {Error}", exc.Message);
                }
            }
            service?.Dispose();
            Log.Logger.LogInformation("ADmiral closed");
            Diag.Uninstall();
        }
    }

    /// <summary>Who besides SYSTEM, Administrators and this user may change the data folder: the accounts the installer
    /// recorded next to the exe and the account the retry service runs as (read from the Service Control Manager, which
    /// only administrators can change - never from the data folder itself).</summary>
    internal static List<string> DataFolderUsers(string? exeDir)
    {
        var users = DesktopLogic.DataUsers(exeDir);
        try
        {
            var account = new WindowsRetryService().Status().Account;
            if (account.Length > 0 && !account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
                && !users.Contains(account, StringComparer.OrdinalIgnoreCase))
                users.Add(account.StartsWith(@".\", StringComparison.Ordinal) ? Environment.MachineName + account[1..] : account);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogDebug("Retry service not readable: {Error}", exc.Message);
        }
        return users;
    }

    private static int _crashShown;

    /// <summary>The crash dialog: logged first (Diag also records it in the error ledger), shown once.</summary>
    private static void Crash(Exception exc, string home, bool fatal)
    {
        Log.Logger.LogCritical(exc, "Unhandled exception: {Message}", exc.Message);
        if (Interlocked.Exchange(ref _crashShown, 1) != 0) return;          // one dialog at a time
        var text = (fatal ? "ADmiral stopped because of an unexpected error" : "ADmiral hit an unexpected error")
                   + $":\n\n{exc.GetType().Name}: {exc.Message}\n\nDetails: {Path.Combine(home, Diag.LogDir, Diag.LogFile)}";
        try
        {
            Shell.MessageBox(DesktopLogic.AppName, text);
        }
        finally
        {
            if (!fatal) Interlocked.Exchange(ref _crashShown, 0);
        }
    }
}
