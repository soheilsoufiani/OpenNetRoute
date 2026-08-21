using System.Windows;
using ProxyApp.Core.Services;
using ProxyApp.Processes;
using ProxyApp.WinDivert;

namespace ProxyApp;

/// <summary>
/// Application composition root. Constructs the process enumerator and the
/// proxy engine host (the only place the UI is wired to WinDivert-backed
/// services) and passes them into the main window through interfaces.
/// </summary>
public partial class App : Application
{
    private IProxyEngine? _engine;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _engine = new ProxyEngine();
        var mainWindow = new MainWindow(
            _engine,
            new ProcessEnumerator());
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _engine?.Dispose();
        base.OnExit(e);
    }
}
