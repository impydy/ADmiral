#pragma warning disable CA1873 // log arguments are cheap here
using System.Diagnostics;
using ADmiral.Core;
using Microsoft.Extensions.Logging;

namespace ADmiral.Desktop;

/// <summary>Small Windows shell helpers shared by the window, the self-test and the service host.</summary>
internal static class Shell
{
    /// <summary>An error box that works before (or without) a WinForms message loop.</summary>
    public static void MessageBox(string title, string text)
    {
        if (Environment.UserInteractive)
            _ = NativeMethods.MessageBoxW(IntPtr.Zero, text, title, NativeMethods.MB_ICONERROR | NativeMethods.MB_TOPMOST);
    }

    /// <summary>Logging into <c>&lt;folder&gt;\logs</c> (admiral.log, admiral-debug.log, the error ledger).</summary>
    public static string SetupLogging(string folder)
    {
        Directory.CreateDirectory(folder);
        return Diag.Install(Diag.LogDirFor(folder));
    }

    /// <summary>Open a folder in Explorer (explorer.exe from the Windows folder, the path as one argument).</summary>
    public static void OpenFolder(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full)) return;
        var psi = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
        {
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(full);
        using var _ = Process.Start(psi);
    }

    /// <summary>Open one of ADmiral's own https links in the default browser. The link is validated again here:
    /// ShellExecute only ever sees an allow-listed https URL, never a file, a program or another scheme.</summary>
    public static void OpenUrl(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!DesktopLogic.IsAllowedExternalUrl(url.AbsoluteUri, out var safe) || safe!.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("this link is not allowed");
        Log.Logger.LogInformation("Opening {Url} in the default browser", safe.AbsoluteUri);
        using var _ = Process.Start(new ProcessStartInfo(safe.AbsoluteUri) { UseShellExecute = true });
    }

    /// <summary>Console output for <c>--self-test</c> started from a console (ADmiral.exe is a windowed program).</summary>
    public static void AttachParentConsole()
    {
        if (NativeMethods.AttachConsole(NativeMethods.ATTACH_PARENT_PROCESS))
        {
            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(stdout);
        }
    }
}
