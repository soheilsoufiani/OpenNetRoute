using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
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

    public MainWindow(IProxyEngine engine, IProcessEnumerator processEnumerator)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _processEnumerator = processEnumerator ?? throw new ArgumentNullException(nameof(processEnumerator));

        InitializeComponent();
        ProcessList.ItemsSource = _processes;
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
    }

    private void OnRefreshClicked(object sender, RoutedEventArgs e)
    {
        RefreshProcesses();
    }

    private async void OnStartClicked(object sender, RoutedEventArgs e)
    {
        StartButton.IsEnabled = false;
        try
        {
            SetStatus("Starting...");

            var settings = BuildSettingsFromUi();

            var validation = ConfigurationValidator.Validate(settings);
            if (!validation.IsValid)
            {
                SetStatus("Cannot start: " + string.Join("; ", validation.Errors), isError: true);
                return;
            }

            _engine.Start(settings);
            SetStatus("Status: Running");
            StopButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            // The engine surfaces actionable errors (e.g. WinDivert requires
            // Administrator privileges); show them verbatim — never a silent
            // failure.
            SetStatus("Cannot start: " + ex.Message, isError: true);
        }
        finally
        {
            StartButton.IsEnabled = true;
        }
    }

    private async void OnStopClicked(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        try
        {
            await _engine.StopAsync();
            SetStatus("Status: Stopped");
        }
        catch (Exception ex)
        {
            SetStatus("Error while stopping: " + ex.Message, isError: true);
        }
        finally
        {
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = _engine.IsRunning;
        }
    }

    /// <summary>
    /// Builds an <see cref="ApplicationSettings"/> from the UI: the SOCKS5 proxy
    /// fields and one rule per selected application (ordered by process name,
    /// matching the RuleEngine first-match-wins semantics).
    /// </summary>
    private ApplicationSettings BuildSettingsFromUi()
    {
        var rules = _processes
            .Where(p => p.RouteViaProxy)
            .OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(p => new ApplicationRule
            {
                ExecutableName = p.ProcessName,
                Enabled = true,
                Mode = ProxyMode.Proxy
            })
            .ToList();

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
}
