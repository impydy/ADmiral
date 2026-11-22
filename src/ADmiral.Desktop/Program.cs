using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using ADmiral.Core;

namespace ADmiral.Desktop;

// ADmiral.exe (port of admiral/desktop.py main()):
//   ADmiral.exe                                   the desktop window
//   ADmiral.exe --self-test                       headless check of a packaged build (CI)
//   ADmiral.exe --ui-test                         opens the real window, checks the page, closes it (CI)
//   ADmiral.exe --retry-service [--home <dir>]    the "ADmiral retry" Windows service (started by the SCM)
// The window needs administrator rights: a start without them restarts ADmiral elevated (one UAC prompt).
internal static class Program
{
    [STAThread]
    private static int Main(string[] argv)
    {
        DesktopArgs args;
        try
        {
            args = DesktopLogic.ParseArgs(argv);
        }
        catch (ArgumentException exc)
        {
            Shell.MessageBox(DesktopLogic.AppName, exc.Message);
            return 2;
        }
        // Inside the service itself the default stays "no service manager": its instances must not see "the service
        // owns the sync" (that is them) and stand back from hosting it.
        if (args.RetryService) return RetryServiceHost.Run(args);
        // the settings page (and the sync ownership check) talk to the real Service Control Manager
        Retry.DefaultControl = new WindowsRetryService();
        if (args.SelfTest) return SelfTest.Run(args);
        switch (DesktopLogic.ElevationNeeded(args, IsElevated()))
        {
            case DesktopLogic.Elevation.Restart:
                return RestartElevated(argv);
            case DesktopLogic.Elevation.Refuse:
                Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.NeedAdminText());
                return 1;
        }
        return DesktopApp.Run(args);
    }

    /// <summary>True when the process token holds the Administrators group enabled (elevated under UAC).</summary>
    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Start this exe again with "runas" (the UAC prompt) and the same arguments; this process then ends.</summary>
    private static int RestartElevated(string[] argv)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.NeedAdminText());
            return 1;
        }
        var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
        foreach (var a in DesktopLogic.ElevatedArgs(argv)) psi.ArgumentList.Add(a);
        try
        {
            using var _ = Process.Start(psi);
            return 0;
        }
        catch (Win32Exception exc) when (exc.NativeErrorCode == 1223)        // ERROR_CANCELLED: "No" on the UAC prompt
        {
            Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.NeedAdminText());
            return 1;
        }
        catch (Win32Exception exc)
        {
            Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.NeedAdminText() + "\n\n" + exc.Message);
            return 1;
        }
    }
}
