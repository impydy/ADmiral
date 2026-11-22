#pragma warning disable CA1873 // log arguments are cheap here
using System.Drawing;
using ADmiral.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ADmiral.Desktop;

/// <summary>The ADmiral window: the local UI in Edge WebView2.
/// <list type="bullet">
/// <item>The profile (history, storage) is per Windows user: %LOCALAPPDATA%\ADmiral\webview.</item>
/// <item>Navigation is restricted to the local API origin; ADmiral's own links (OPEN_URL_HOSTS, the GitHub repository)
/// open in the default browser, everything else is refused. No new windows.</item>
/// <item>The page reaches the host only through <c>window.pywebview.api.*</c> (postMessage, checked origin).</item>
/// <item>Developer tools and the default context menu only with --debug / ADMIRAL_DEBUG.</item>
/// </list></summary>
internal sealed class MainForm : Form, IDesktopShell
{
    private readonly AdmiralService _service;
    private readonly Uri _origin;
    private readonly string _token;
    private readonly string _webviewDir;
    private readonly bool _debug;
    private readonly bool _uiTest;
    private readonly WebView2 _web;
    private readonly DesktopBridge _bridge;
    private readonly string _home;
    private bool _forceClose;
    private bool _uiTestStarted;
    private System.Threading.Timer? _watchdog;
    private string _theme;

    /// <summary>The process exit code once the window closed (ui-test result, start-up failure).</summary>
    public int ExitCode { get; private set; }

    public MainForm(AdmiralService service, Uri origin, string token, string home, string webviewDir, bool debug, bool uiTest)
    {
        _service = service;
        _origin = new Uri(origin.GetLeftPart(UriPartial.Authority));
        _token = token;
        _home = home;
        _webviewDir = webviewDir;
        _debug = debug;
        _uiTest = uiTest;
        _bridge = new DesktopBridge(this, home, service.RemoteAssist);

        Text = DesktopLogic.AppName;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath); }
        catch (Exception exc) when (exc is ArgumentException or IOException) { }
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = LogicalToDeviceUnits(new Size(1360, 880));
        MinimumSize = LogicalToDeviceUnits(new Size(960, 620));
        _theme = service.Settings.Theme;
        var bg = Color.FromArgb(unchecked((int)0xFF000000) | DesktopLogic.WindowBackColor(DesktopLogic.TitleBarDark(_theme, WindowsDark())));
        BackColor = bg;
        _web = new WebView2 { Dock = DockStyle.Fill, DefaultBackgroundColor = bg };
        Controls.Add(_web);
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;     // Windows light/dark switched
        Load += async (_, _) => await InitAsync().ConfigureAwait(true);
        FormClosing += OnFormClosing;
        if (uiTest)
        {
            // a frozen window must fail the test instead of hanging CI
            _watchdog = new System.Threading.Timer(_ =>
            {
                Log.Logger.LogError("ui-test: no result within 120 s (window frozen?)");
                Diag.Uninstall();
                Environment.Exit(3);
            }, null, TimeSpan.FromSeconds(120), Timeout.InfiniteTimeSpan);
        }
    }

    private async Task InitAsync()
    {
        try
        {
            Directory.CreateDirectory(_webviewDir);
            var options = new CoreWebView2EnvironmentOptions { AllowSingleSignOnUsingOSPrimaryAccount = false };
            var env = await CoreWebView2Environment.CreateAsync(null, _webviewDir, options).ConfigureAwait(true);
            await _web.EnsureCoreWebView2Async(env).ConfigureAwait(true);
            var core = _web.CoreWebView2;
            var s = core.Settings;
            s.AreDevToolsEnabled = _debug;
            s.AreDefaultContextMenusEnabled = _debug;
            s.AreHostObjectsAllowed = false;            // the bridge is postMessage only
            s.IsWebMessageEnabled = true;
            s.IsStatusBarEnabled = false;
            s.IsGeneralAutofillEnabled = false;
            s.IsPasswordAutosaveEnabled = false;
            s.IsSwipeNavigationEnabled = false;
            s.AreDefaultScriptDialogsEnabled = true;
            await core.AddScriptToExecuteOnDocumentCreatedAsync(DesktopLogic.BridgeScript(_origin)).ConfigureAwait(true);
            core.NavigationStarting += (_, e) => OnNavigationStarting(e, isMainFrame: true);
            core.FrameNavigationStarting += (_, e) => OnNavigationStarting(e, isMainFrame: false);
            core.NewWindowRequested += OnNewWindowRequested;
            core.WebMessageReceived += OnWebMessage;
            core.DownloadStarting += OnDownloadStarting;
            core.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;     // camera, location ...
            core.NavigationCompleted += OnNavigationCompleted;
            core.ProcessFailed += (_, e) => Log.Logger.LogError("WebView2 process failed: {Kind} ({Reason})", e.ProcessFailedKind, e.Reason);
            core.Navigate(new Uri(_origin, "/?token=" + Uri.EscapeDataString(_token)).AbsoluteUri);
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            Log.Logger.LogError(exc, "Fatal: the window could not start: {Message}", exc.Message);
            Shell.MessageBox(DesktopLogic.AppName, DesktopLogic.StartupFailureText(exc, _home));
            ExitCode = 1;
            _forceClose = true;
            Close();
        }
    }

    // ------------------------------------------------------------------ title bar follows the theme
    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyTitleBar();
    }

    /// <summary>Called by the page (bridge "set_theme") whenever its theme changes, including the live preview.</summary>
    public void SetTheme(string theme)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => SetTheme(theme));
            return;
        }
        _theme = theme;
        ApplyTitleBar();
    }

    private void OnUserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category != UserPreferenceCategory.General || IsDisposed || !IsHandleCreated) return;
        try { BeginInvoke(ApplyTitleBar); }
        catch (InvalidOperationException) { }                 // the window is closing
    }

    /// <summary>Windows' "app mode" (Settings → Personalisation → Colours): true = dark.</summary>
    private static bool WindowsDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception exc) when (exc is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    /// <summary>Dark or light title bar (Windows 10 20H1+ / 11); on Windows 11 also exactly the page's toolbar colours.</summary>
    private void ApplyTitleBar()
    {
        if (IsDisposed || !IsHandleCreated) return;
        var dark = DesktopLogic.TitleBarDark(_theme, WindowsDark());
        var on = dark ? 1 : 0;
        if (NativeMethods.DwmSetWindowAttribute(Handle, NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int)) != 0)
            _ = NativeMethods.DwmSetWindowAttribute(Handle, NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref on, sizeof(int));
        if (Environment.OSVersion.Version.Build >= 22000)
        {
            var (caption, text) = DesktopLogic.TitleBarColors(dark);
            var c = ColorRef(caption);
            var t = ColorRef(text);
            _ = NativeMethods.DwmSetWindowAttribute(Handle, NativeMethods.DWMWA_CAPTION_COLOR, ref c, sizeof(int));
            _ = NativeMethods.DwmSetWindowAttribute(Handle, NativeMethods.DWMWA_TEXT_COLOR, ref t, sizeof(int));
        }
        var bg = Color.FromArgb(unchecked((int)0xFF000000) | DesktopLogic.WindowBackColor(dark));
        BackColor = bg;
        _web.DefaultBackgroundColor = bg;
    }

    /// <summary>0xRRGGBB -> COLORREF (0x00BBGGRR).</summary>
    private static int ColorRef(int rgb) => ((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF);

    // ------------------------------------------------------------------ navigation restrictions
    private void OnNavigationStarting(CoreWebView2NavigationStartingEventArgs e, bool isMainFrame)
    {
        // main frame and every frame (incl. meta refresh, script and form navigations): only the exact local origin
        var action = DesktopLogic.DecideNavigation(e.Uri, _origin, e.IsUserInitiated, isMainFrame);
        if (action == DesktopLogic.NavigationAction.Allow) return;
        e.Cancel = true;
        if (action == DesktopLogic.NavigationAction.OpenExternal && DesktopLogic.IsAllowedExternalUrl(e.Uri, out var external))
            TryOpenExternal(external!);
        else Log.Logger.LogWarning("Navigation refused: {Url}", Trim(e.Uri));
    }

    private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        e.Handled = true;                            // never a second WebView2 window
        // like a navigation: only a click on an allow-listed ADmiral link opens the browser, never a script / refresh
        if (e.IsUserInitiated && DesktopLogic.IsAllowedExternalUrl(e.Uri, out var external)) TryOpenExternal(external!);
        else Log.Logger.LogWarning("New window refused: {Url}", Trim(e.Uri));
    }

    private static string Trim(string? url) => url is null ? "" : url.Length > 200 ? url[..200] + "..." : url;

    private static void TryOpenExternal(Uri url)
    {
        try
        {
            Shell.OpenUrl(url);
        }
        catch (Exception exc) when (exc is ArgumentException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Log.Logger.LogWarning("Could not open {Url}: {Error}", url.AbsoluteUri, exc.Message);
        }
    }

    // ------------------------------------------------------------------ the bridge
    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (!DesktopLogic.IsLocalOrigin(e.Source, _origin) || e.Source == "about:blank")
        {
            Log.Logger.LogWarning("Bridge message from {Source} ignored", Trim(e.Source));
            return;
        }
        var json = e.WebMessageAsJson;
        // run outside the WebView2 event (a modal save dialog must not nest inside it)
        BeginInvoke(() =>
        {
            var reply = _bridge.Handle(json);
            if (!IsDisposed && _web.CoreWebView2 is { } core) core.PostWebMessageAsJson(reply);
        });
    }

    public string? PickSaveFile(string suggestedName)
    {
        var ext = Path.GetExtension(suggestedName);
        using var dlg = new SaveFileDialog
        {
            FileName = suggestedName,
            OverwritePrompt = true,
            AddExtension = ext.Length > 0,
            DefaultExt = ext.TrimStart('.'),
            Filter = ext.Length > 0 ? $"*{ext}|*{ext}|*.*|*.*" : "*.*|*.*",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        return dlg.ShowDialog(this) == DialogResult.OK ? dlg.FileName : null;
    }

    public void OpenFolder(string path) => Shell.OpenFolder(path);

    public void OpenUrl(Uri url) => Shell.OpenUrl(url);

    public void Quit() => BeginInvoke(Close);

    // ------------------------------------------------------------------ downloads
    private void OnDownloadStarting(object? sender, CoreWebView2DownloadStartingEventArgs e)
    {
        var uri = e.DownloadOperation.Uri;
        if (!DesktopLogic.IsLocalDownload(uri, _origin))
        {
            Log.Logger.LogWarning("Download refused: {Url}", Trim(uri));
            e.Cancel = true;
            return;
        }
        var deferral = e.GetDeferral();
        var suggested = DesktopLogic.SafeFileName(Path.GetFileName(e.ResultFilePath));
        BeginInvoke(() =>
        {
            try
            {
                var path = PickSaveFile(suggested);
                if (path is null)
                {
                    e.Cancel = true;
                }
                else
                {
                    e.ResultFilePath = path;
                    e.Handled = true;                // no download bubble: the user chose where it goes
                }
            }
            finally
            {
                deferral.Complete();
            }
        });
    }

    // ------------------------------------------------------------------ closing / update / ui-test
    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_forceClose || _uiTest) return;
        try
        {
            var n = _service.UnfinishedDeployments();
            if (n == 0) return;
            var answer = MessageBox.Show(this, I18n.T("dep.close_confirm", ("n", n)), DesktopLogic.AppName, MessageBoxButtons.YesNo,
                                         MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) e.Cancel = true;
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)   // never trap the user in a window that cannot be closed
        {
            Log.Logger.LogError(exc, "close confirmation failed");
        }
    }

    /// <summary>The update installer was started: close the window 2.5 s later (it closes ADmiral too; do not leave it to
    /// chance), and end the process if that does not happen within 15 s.</summary>
    public void ExitForUpdate()
    {
        new Thread(() =>
        {
            Thread.Sleep(2500);
            try
            {
                BeginInvoke(() =>
                {
                    _forceClose = true;
                    Close();
                });
            }
            catch (InvalidOperationException) { }            // already closed
            Thread.Sleep(15000);
            Environment.Exit(0);
        }) { IsBackground = true, Name = "admiral-update-exit" }.Start();
    }

    private async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (!e.IsSuccess) Log.Logger.LogWarning("Page load failed: {Status}", e.WebErrorStatus);
        if (!_uiTest || _uiTestStarted) return;
        _uiTestStarted = true;
        var ok = false;
        string last = "";
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                last = await _web.CoreWebView2.ExecuteScriptAsync(DesktopChecks.UiProbe).ConfigureAwait(true);
                var (ready, good) = DesktopChecks.UiProbeResult(last);
                if (ready)
                {
                    ok = good;
                    break;
                }
                await Task.Delay(500).ConfigureAwait(true);
            }
        }
        catch (Exception exc) when (exc is not OutOfMemoryException)
        {
            last = $"{exc.GetType().Name}: {exc.Message}";
        }
        Log.Logger.LogInformation("ui-test result: ok={Ok} {Data}", ok, last);
        ExitCode = ok ? 0 : 1;
        _forceClose = true;
        Close();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _watchdog?.Dispose();            // the window is closed: the watchdog must not fire later
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;   // a static event: never leave it holding the form
            _watchdog = null;
            _web.Dispose();
        }
        base.Dispose(disposing);
    }
}
