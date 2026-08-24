using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Controls;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Core.Services;
using ProxyApp.Core.Validation;

namespace ProxyApp;

/// <summary>One process row in the Applications list.</summary>
public sealed class ProcessRow : INotifyPropertyChanged
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ProcessPath { get; init; }

    private bool _routeViaProxy;

    /// <summary>True when this process is routed through the SOCKS5 proxy.</summary>
    public bool RouteViaProxy
    {
        get => _routeViaProxy;
        set
        {
            if (_routeViaProxy == value) return;
            _routeViaProxy = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(RouteViaProxy)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>A manually added .exe rule (static, survives Refresh).</summary>
public sealed class ManualRuleRow : INotifyPropertyChanged
{
    public string ExecutableName { get; init; } = "";
    public string ExecutablePath { get; init; } = "";

    private bool _enabled = true;

    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value) return;
            _enabled = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Enabled)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>A folder bundle rule (static, survives Refresh).</summary>
public sealed class BundleRow : INotifyPropertyChanged
{
    public string FolderPath { get; init; } = "";
    public string DisplayName { get; init; } = "";

    /// <summary>Executables found under the folder at add time (display only).</summary>
    public ObservableCollection<string> Exes { get; } = new();

    private bool _enabled = true;

    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value) return;
            _enabled = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Enabled)));
        }
    }

    /// <summary>Index into the Proxy/Direct ComboBox (0 = Proxy, 1 = Direct).</summary>
    private int _modeIndex;

    public int ModeIndex
    {
        get => _modeIndex;
        set
        {
            if (_modeIndex == value) return;
            _modeIndex = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ModeIndex)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// Main window. Communicates with the engine ONLY through
/// <see cref="IProxyEngine"/> and with processes only through
/// <see cref="IProcessEnumerator"/> — it contains no packet, SOCKS5, or
/// WinDivert code (architecture rules 1–3).
/// </summary>
public partial class MainWindow : Window
{
    private readonly IProxyEngine _engine;
    private readonly IProcessEnumerator _processEnumerator;
    private readonly ObservableCollection<ProcessRow> _processes = new();
    private readonly ObservableCollection<ManualRuleRow> _manualRules = new();
    private readonly ObservableCollection<BundleRow> _bundles = new();
    private readonly LogPanel _logPanel;

    public MainWindow(IProxyEngine engine, IProcessEnumerator processEnumerator)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _processEnumerator = processEnumerator ?? throw new ArgumentNullException(nameof(processEnumerator));

        InitializeComponent();

        ProcessList.ItemsSource = _processes;
        ManualRuleList.ItemsSource = _manualRules;
        BundleList.ItemsSource = _bundles;

        // Debug/Log panel: the engine's trace sink feeds a bounded ring buffer
        // (fire-and-forget, never blocks the capture path); a dispatcher timer
        // drains it to the UI in batches.
        _logPanel = new LogPanel(Dispatcher);
        DebugLogList.ItemsSource = _logPanel.Lines;
        _engine.SetTrace(_logPanel.Append);
        _logPanel.Log("INFO", "App started — log panel ready. Trace sink wired to the engine.");

        RefreshProcesses();
    }

    private void RefreshProcesses()
    {
        // Preserve the user's selections (by PID) across a refresh.
        var selections = _processes
            .Where(p => p.RouteViaProxy)
            .Select(p => p.ProcessId)
            .ToHashSet();

        _processes.Clear();
        foreach (var process in _processEnumerator.GetRunningProcesses())
        {
            _processes.Add(new ProcessRow
            {
                ProcessId = process.ProcessId,
                ProcessName = process.Name,
                ProcessPath = process.ExecutablePath ?? "(unknown path)"
            });
        }

        foreach (var row in _processes)
        {
            if (selections.Contains(row.ProcessId))
                row.RouteViaProxy = true;
        }

        // Manual rules and bundles are static — they survive Refresh untouched.
        ApplySearchFilter();
    }

    // ── Feature 1: search box ──

    private void OnSearchTextChanged(object sender, TextChangedEventArgs e)
    {
        ApplySearchFilter();
    }

    private void OnRefreshClicked(object sender, RoutedEventArgs e)
    {
        RefreshProcesses();
    }

    /// <summary>
    /// Filters the process list (name + path), manual rules (exe name + path),
    /// and bundle groups (folder name + path) by the search text.
    /// </summary>
    private void ApplySearchFilter()
    {
        var text = SearchBox.Text.Trim();

        var view = CollectionViewSource.GetDefaultView(_processes);
        view.Filter = p =>
        {
            if (text.Length == 0) return true;
            var row = (ProcessRow)p;
            return row.ProcessName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                   (row.ProcessPath?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false);
        };

        var manualView = CollectionViewSource.GetDefaultView(_manualRules);
        manualView.Filter = m =>
        {
            if (text.Length == 0) return true;
            var row = (ManualRuleRow)m;
            return row.ExecutableName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                   row.ExecutablePath.Contains(text, StringComparison.OrdinalIgnoreCase);
        };

        var bundleView = CollectionViewSource.GetDefaultView(_bundles);
        bundleView.Filter = b =>
        {
            if (text.Length == 0) return true;
            var row = (BundleRow)b;
            return row.DisplayName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                   row.FolderPath.Contains(text, StringComparison.OrdinalIgnoreCase);
        };
    }

    // ── Feature 2: add a manual .exe rule ──

    private void OnAddExeClicked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select an executable to route through the proxy",
            Filter = "Executable files (*.exe)|*.exe",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) != true)
            return;

        var path = dialog.FileName;
        // Prevent duplicates (case-insensitive, ordinal path comparison).
        if (_manualRules.Any(r => string.Equals(r.ExecutablePath, path, StringComparison.OrdinalIgnoreCase)))
        {
            SetStatus($"'{path}' is already a manual rule.", isError: true);
            return;
        }

        _manualRules.Add(new ManualRuleRow
        {
            ExecutableName = Path.GetFileName(path),
            ExecutablePath = path
        });
        ApplySearchFilter();
    }

    private void OnRemoveManualRuleClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: ManualRuleRow row })
            _manualRules.Remove(row);
    }

    // ── Feature 3: add a folder bundle ──

    private void OnAddFolderClicked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select a folder of applications to route",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
            return;

        var path = dialog.FolderName;
        if (string.IsNullOrWhiteSpace(path))
            return;

        if (_bundles.Any(b => string.Equals(b.FolderPath, path, StringComparison.OrdinalIgnoreCase)))
        {
            SetStatus($"'{path}' is already a bundle rule.", isError: true);
            return;
        }

        var bundle = new BundleRow
        {
            FolderPath = path,
            DisplayName = Path.GetFileName(path.TrimEnd('\\', '/'))
        };

        // Scan recursively at add time (display only — matching is by prefix at
        // SYN time, so newly added exes in the folder are covered).
        try
        {
            foreach (var exe in Directory.EnumerateFiles(path, "*.exe", SearchOption.AllDirectories)
                         .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                bundle.Exes.Add(exe);
            }
        }
        catch (Exception ex)
        {
            SetStatus($"Could not scan '{path}': {ex.Message}", isError: true);
        }

        _bundles.Add(bundle);
        ApplySearchFilter();
    }

    private void OnRemoveBundleClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: BundleRow row })
            _bundles.Remove(row);
    }

    // ── Start / Stop ──

    private async void OnStartClicked(object sender, RoutedEventArgs e)
    {
        StartButton.IsEnabled = false;
        _logPanel.Log("INFO", "Start clicked");
        try
        {
            SetStatus("Starting...");

            var settings = BuildSettingsFromUi();

            var validation = ConfigurationValidator.Validate(settings);
            if (!validation.IsValid)
            {
                var msg = "Cannot start: " + string.Join("; ", validation.Errors);
                SetStatus(msg, isError: true);
                _logPanel.Log("ERR", msg);
                return;
            }

            // Elevation check (informs the user up front; WinDivertOpen will
            // still surface its own actionable error if not elevated).
            var elevated = IsRunningElevated();
            _logPanel.Log(elevated ? "INFO" : "WARN",
                elevated
                    ? "Elevation check: process is running as Administrator."
                    : "Elevation check: process is NOT elevated — packet interception (WinDivert) will fail. Run the app as Administrator.");
            _logPanel.Log("INFO", $"Starting engine: proxy={settings.Proxy.Host}:{settings.Proxy.Port}, rules={settings.Rules.Count}");

            _engine.Start(settings);
            SetStatus("Status: Running");
            StopButton.IsEnabled = true;
            _logPanel.Log("INFO", "Engine started — capturing SYN traffic. Trace lines follow.");
        }
        catch (Exception ex)
        {
            // The engine surfaces actionable errors (e.g. WinDivert requires
            // Administrator privileges); show them verbatim — never a silent
            // failure.
            var msg = "Cannot start: " + ex.Message;
            SetStatus(msg, isError: true);
            _logPanel.Log("ERR", msg);
        }
        finally
        {
            StartButton.IsEnabled = true;
        }
    }

    private async void OnStopClicked(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        _logPanel.Log("INFO", "Stop clicked");
        try
        {
            await _engine.StopAsync();
            SetStatus("Status: Stopped");
            _logPanel.Log("INFO", "Engine stopped.");
        }
        catch (Exception ex)
        {
            var msg = "Error while stopping: " + ex.Message;
            SetStatus(msg, isError: true);
            _logPanel.Log("ERR", msg);
        }
        finally
        {
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = _engine.IsRunning;
        }
    }

    private static bool IsRunningElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Builds an <see cref="ApplicationSettings"/> from the UI: the SOCKS5 proxy
    /// fields and the rules — selected processes (ordered by name), manual exe
    /// rules, and folder bundles — matching the RuleEngine first-match-wins
    /// semantics (rules are evaluated in list order).
    /// </summary>
    private ApplicationSettings BuildSettingsFromUi()
    {
        var rules = new List<ApplicationRule>();

        // Selected running processes → name rules.
        rules.AddRange(_processes
            .Where(p => p.RouteViaProxy)
            .OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(p => new ApplicationRule
            {
                ExecutableName = p.ProcessName,
                Enabled = true,
                Mode = ProxyMode.Proxy
            }));

        // Manual exe rules → name + path rules.
        rules.AddRange(_manualRules
            .Select(m => new ApplicationRule
            {
                ExecutableName = m.ExecutableName,
                ExecutablePath = m.ExecutablePath,
                Enabled = m.Enabled,
                Mode = ProxyMode.Proxy
            }));

        // Folder bundles → folder rules.
        rules.AddRange(_bundles
            .Select(b => new ApplicationRule
            {
                FolderPath = b.FolderPath,
                Enabled = b.Enabled,
                Mode = b.ModeIndex == 0 ? ProxyMode.Proxy : ProxyMode.Direct
            }));

        var proxy = new ProxyConfiguration
        {
            Host = ProxyHostBox.Text.Trim(),
            Port = int.TryParse(ProxyPortBox.Text.Trim(), out var port) ? port : 0,
            Username = string.IsNullOrEmpty(ProxyUsernameBox.Text) ? null : ProxyUsernameBox.Text,
            Password = string.IsNullOrEmpty(ProxyPasswordBox.Password) ? null : ProxyPasswordBox.Password,
            AuthenticationType = string.IsNullOrEmpty(ProxyUsernameBox.Text)
                ? ProxyAuthenticationType.None
                : ProxyAuthenticationType.UsernamePassword,
            Enabled = true
        };

        return new ApplicationSettings
        {
            Proxy = proxy,
            Rules = rules
        };
    }

    private void SetStatus(string message, bool isError = false)
    {
        StatusText.Text = message;
        StatusText.Foreground = isError
            ? System.Windows.Media.Brushes.Firebrick
            : System.Windows.Media.Brushes.Gray;
    }

    // ── Debug / Log panel ──

    private void OnCopyLogClicked(object sender, RoutedEventArgs e)
    {
        _logPanel.CopyToClipboard();
        _logPanel.Log("INFO", $"Copied {_logPanel.Lines.Count} log lines to clipboard.");
    }

    private void OnClearLogClicked(object sender, RoutedEventArgs e)
    {
        _logPanel.Clear();
    }

    protected override void OnClosed(EventArgs e)
    {
        _logPanel.Shutdown();
        base.OnClosed(e);
    }
}
