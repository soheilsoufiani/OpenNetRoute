using System.Linq;
using System.Windows;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Services;
using ProxyApp.Network;
using ProxyApp.Processes;
using ProxyApp.WinDivert;

namespace ProxyApp;

/// <summary>
/// Application composition root. Constructs the settings store (persistence),
/// the process enumerator, the proxy engine host, and the proxy tester — the
/// only place the UI is wired to concrete services — and passes them into the
/// main window through interfaces.
/// </summary>
public partial class App : Application
{
    private IProxyEngine? _engine;
    private IApplicationSettingsStore? _settingsStore;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // The session log starts at the earliest possible moment so the Debug
        // window shows EVERYTHING from process launch onward — settings load,
        // service construction, and every runtime event afterwards.
        var log = new LogPanel(Dispatcher);
        log.Log("INFO", "Application starting…");

        _settingsStore = new JsonApplicationSettingsStore();
        var settings = _settingsStore.Load();
        log.Log("INFO", $"Settings loaded from {_settingsStore.Location}.");

        _engine = new ProxyEngine();
        log.Log("INFO", "Engine host constructed.");

        // Phase 11: with the tray enabled and "start minimized to the tray"
        // persisted, the app launches as a tray icon only — Show() is skipped
        // so the window stays hidden until the tray icon opens it. The
        // application keeps running (icon + dispatcher) with no visible window.
        var startHiddenToTray = settings.Preferences.EnableTrayIcon &&
                                settings.Preferences.StartMinimizedToTray;
        var mainWindow = new MainWindow(
            _engine,
            new ProcessEnumerator(),
            _settingsStore,
            new Socks5ProxyTester(),
            settings,
            log,
            startHiddenToTray);
        if (!startHiddenToTray)
            mainWindow.Show();

        // Windows shutdown/sign-out must never be held up by close-to-tray.
        SessionEnding += (_, _) => mainWindow.NotifySessionEnding();

        // Diagnostic hook: `ProxyApp.exe --open-debug` opens the session log
        // window immediately (dev convenience + automated smoke tests).
        if (e.Args.Contains("--open-debug"))
            mainWindow.OpenDebugLogWindow();
        if (e.Args.Contains("--open-processes"))
            mainWindow.OpenRunningProcesses();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _engine?.Dispose();
        base.OnExit(e);
    }
}
