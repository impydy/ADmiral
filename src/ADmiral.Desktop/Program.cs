using ADmiral.Core;

namespace ADmiral.Desktop;

// ADmiral.exe (port of admiral/desktop.py main()):
//   ADmiral.exe                                   the desktop window
//   ADmiral.exe --self-test                       headless check of a packaged build (CI)
//   ADmiral.exe --ui-test                         opens the real window, checks the page, closes it (CI)
//   ADmiral.exe --retry-service [--home <dir>]    the "ADmiral retry" Windows service (started by the SCM)
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
        return DesktopApp.Run(args);
    }
}
