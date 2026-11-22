#pragma warning disable CA1873 // log arguments are cheap here
using ADmiral.Core;
using ADmiral.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ADmiral.Desktop;

/// <summary>The "ADmiral retry" Windows service process (<c>ADmiral.exe --retry-service --home &lt;dir&gt;</c>; port of the
/// host half of admiral/winservice.py). Microsoft.Extensions.Hosting.WindowsServices speaks the Service Control Manager
/// protocol; started from a console it simply runs the loop in the foreground (like Python's fallback).</summary>
internal static class RetryServiceHost
{
    public static int Run(DesktopArgs args)
    {
        var env = DesktopEnv.Current();
        var home = Path.GetFullPath(args.Home ?? DesktopLogic.DataDir(env));
        // check (and restrict) the data folder BEFORE anything is created in it: the service log folder and files must
        // never be created inside a folder someone else controls
        var problem = DesktopLogic.ProgramDirProblem(env.ExeDir)
                      ?? DesktopLogic.SecureDataDir(home, dataUsers: DesktopApp.DataFolderUsers(env.ExeDir));
        if (problem is not null)
        {
            // no file log yet (it would be created inside that folder): the Windows event log, and the SCM records the exit
            try
            {
                System.Diagnostics.EventLog.WriteEntry(DesktopLogic.AppName, $"ADmiral retry service not starting: {problem}",
                                                       System.Diagnostics.EventLogEntryType.Error, 1001);
            }
            catch (Exception exc) when (exc is not OutOfMemoryException) { _ = exc; }
            return 1;
        }
        Shell.SetupLogging(Path.Combine(home, "service"));
        Log.Logger.LogInformation("ADmiral {Version} retry service starting, data dir {Home}", Diag.Version, home);
        // an empty builder: no appsettings.json / environment / command-line configuration is read, so nothing next to
        // the exe or in the environment can reconfigure the service
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            ApplicationName = DesktopLogic.AppName,
            ContentRootPath = AppContext.BaseDirectory,
            DisableDefaults = true,
        });
        builder.Services.AddWindowsService(o => o.ServiceName = DesktopLogic.ServiceName);
        builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(25));
        builder.Logging.ClearProviders();
        if (Diag.Provider is { } provider) builder.Logging.AddProvider(provider);
        builder.Services.AddSingleton(new RetryWorkerOptions(home));
        builder.Services.AddHostedService<RetryWorker>();
        try
        {
            using var host = builder.Build();
            host.Run();
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogCritical(exc, "Retry service failed");
            return 1;
        }
        finally
        {
            Log.Logger.LogInformation("Retry service stopped");
        }
        return Environment.ExitCode;
    }
}

internal sealed record RetryWorkerOptions(string Home);

/// <summary>Runs <see cref="Retry.RunLoop"/> on its own thread until the service is stopped, and hosts the sync
/// listener for the instance the sync loop hands over.</summary>
internal sealed class RetryWorker(RetryWorkerOptions options, IHostApplicationLifetime lifetime) : BackgroundService
{
    private readonly Lock _webLock = new();
    private WebApplication? _web;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                Retry.RunLoop(options.Home, stoppingToken, onSyncInstance: SyncInstance);
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                Log.Logger.LogCritical(exc, "Retry loop crashed");
            }
            finally
            {
                SyncInstance(null);
                done.TrySetResult();
                if (!stoppingToken.IsCancellationRequested)
                {
                    // the loop must only end when told to: let the SCM see a failure (and restart the service)
                    Environment.ExitCode = 1;
                    lifetime.StopApplication();
                }
            }
        }) { IsBackground = true, Name = "admiral-retry" };
        thread.Start();
        return done.Task;
    }

    /// <summary>The sync loop's hosting instance changed (null = sync off). The web layer serves the sync endpoints for
    /// it: its UI API is bound to loopback with a random token nobody receives, so only the sync listener (which the
    /// web layer starts when <see cref="AdmiralService.SyncListenerWanted"/>) is usable from outside.</summary>
    private void SyncInstance(AdmiralService? instance)
    {
        lock (_webLock)
        {
            if (_web is not null)
            {
                try
                {
                    _web.StopAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
                    _web.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
                catch (Exception exc) when (exc is not OutOfMemoryException)
                {
                    Log.Logger.LogWarning("Sync: stopping the listener failed: {Error}", exc.Message);
                }
                _web = null;
            }
            if (instance is null) return;
            try
            {
                var web = WebApp.Create(instance, new WebAppOptions
                {
                    Token = DesktopLogic.NewToken(), Host = "127.0.0.1", Port = 0, AllowRemote = false, ExtraLogger = Diag.Provider,
                });
                web.StartAsync().GetAwaiter().GetResult();
                _web = web;
            }
            catch (Exception exc) when (exc is not OutOfMemoryException)
            {
                Log.Logger.LogError(exc, "Sync: the listener could not start");
            }
        }
    }
}
