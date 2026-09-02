using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Processes;
using ProxyApp.Core.Services;
using ProxyApp.Core.Validation;

namespace ProxyApp;

/// <summary>One process row in the running-processes picker.</summary>
public sealed class ProcessRow : INotifyPropertyChanged
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ProcessPath { get; init; }

    private bool _routeViaProxy;

    /// <summary>
    /// Pending picker selection. Checking a box does NOT create a routing
    /// rule — a rule is created only when the user clicks "Add to Manual
    /// Rules"; closing the picker without Add discards the selection.
    /// </summary>
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
/// A manually added .exe rule (static, survives Refresh). Rows with an empty
/// <see cref="ExecutablePath"/> are migrated name-only rules — they match by
/// name alone and display a dash in the PATH column.
/// </summary>
public sealed class ManualRuleRow : INotifyPropertyChanged
{
    public string ExecutableName { get; init; } = "";
    public string ExecutablePath { get; init; } = "";

    /// <summary>PATH cell text: the path, or a dash for name-only rules.</summary>
    public string PathDisplay =>
        string.IsNullOrEmpty(ExecutablePath) ? "—" : ExecutablePath;

    /// <summary>Hover text shown next to the cursor over the PATH cell.</summary>
    public string PathToolTip =>
        string.IsNullOrEmpty(ExecutablePath)
            ? "(name-only rule — matches any location)"
            : ExecutablePath + "  (click to copy)";

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
/// <see cref="IProxyEngine"/>, with processes only through
/// <see cref="IProcessEnumerator"/>, and with persistence only through
/// <see cref="IApplicationSettingsStore"/> â€” it contains no packet, SOCKS5, or
/// WinDivert code (architecture rules 1â€“3).
///
/// Persistence contract: EVERY user-visible mutation (proxy field edit,
/// profile add/edit/delete/select, rule change, theme/accent/test preference)
/// updates the in-memory <see cref="_settings"/> immediately and schedules a
/// debounced save (~0.5 s). A final save runs on window close â€” state is never
/// lost across restarts.
/// </summary>
public partial class MainWindow : Window
{
    private readonly IProxyEngine _engine;
    private readonly IProcessEnumerator _processEnumerator;
    private readonly IApplicationSettingsStore _settingsStore;
    private readonly IProxyTester _proxyTester;
    private readonly ApplicationSettings _settings;

    /// <summary>
    /// View model for one proxy-profile card (v2rayNG-style list): the
    /// configuration plus observable selection and ping-test state. Edits
    /// mutate <see cref="Config"/> in place; call <see cref="RefreshFromConfig"/>
    /// afterwards so the card bindings re-read the changed values.
    /// </summary>
    public sealed class ProfileItem : INotifyPropertyChanged
    {
        public ProfileItem(ProxyConfiguration config) => Config = config;

        public ProxyConfiguration Config { get; }

        private bool _isSelected;

        /// <summary>Whether this card is the profile START routes through.</summary>
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                Raise(nameof(IsSelected));
            }
        }

        private int? _pingMs;

        /// <summary>Latency of the last real ping in ms; null = not tested or failed.</summary>
        public int? PingMs
        {
            get => _pingMs;
            set
            {
                if (_pingMs == value) return;
                _pingMs = value;
                Raise(nameof(PingMs));
                Raise(nameof(PingDisplay));
                Raise(nameof(PingTone));
            }
        }

        private bool _pingFailed;

        /// <summary>True when the last ping test failed (timeout, rejection, …).</summary>
        public bool PingFailed
        {
            get => _pingFailed;
            set
            {
                if (_pingFailed == value) return;
                _pingFailed = value;
                Raise(nameof(PingFailed));
                Raise(nameof(PingDisplay));
                Raise(nameof(PingTone));
            }
        }

        private string _pingDetails = "";

        /// <summary>Human-readable outcome of the last ping (credential-free).</summary>
        public string PingDetails
        {
            get => _pingDetails;
            set
            {
                value ??= "";
                if (string.Equals(_pingDetails, value, StringComparison.Ordinal)) return;
                _pingDetails = value;
                Raise(nameof(PingDetails));
            }
        }

        /// <summary>Right-hand ping label: "—", "123 ms", or "Failed".</summary>
        public string PingDisplay =>
            _pingFailed ? "Failed" :
            _pingMs is int ms ? $"{ms} ms" :
            "—";

        /// <summary>Semantic tone for coloring the ping label: None/Good/Slow/Bad.</summary>
        public string PingTone =>
            _pingFailed ? "Bad" :
            _pingMs is int ms ? (ms <= 500 ? "Good" : "Slow") :
            "None";

        /// <summary>Second card line: host and port.</summary>
        public string EndpointDisplay => $"{Config.Host} : {Config.Port}";

        /// <summary>Third card line: protocol and authentication mode (never credentials).</summary>
        public string DetailsDisplay =>
            $"SOCKS5 · {(Config.AuthenticationType == ProxyAuthenticationType.UsernamePassword
                ? "Username/Password auth"
                : "No authentication")}";

        /// <summary>Re-raises config-derived bindings after an in-place edit.</summary>
        public void RefreshFromConfig()
        {
            Raise(nameof(Config));
            Raise(nameof(EndpointDisplay));
            Raise(nameof(DetailsDisplay));
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void Raise(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private readonly ObservableCollection<ProcessRow> _processes = new();
    private readonly ObservableCollection<ManualRuleRow> _manualRules = new();
    private readonly ObservableCollection<BundleRow> _bundles = new();
    private readonly ObservableCollection<ProfileItem> _profiles = new();
    private readonly LogPanel _logPanel;

    /// <summary>
    /// False until the constructor finishes <see cref="InitializeComponent"/>
    /// plus state restore. XAML-wired change handlers must be inert before
    /// that: events can fire DURING the XAML load, when sibling named
    /// controls and profile state do not exist yet (NullReferenceException
    /// at startup).
    /// </summary>
    private bool _uiReady;

    /// <summary>Debounced persistence: restarted on every mutation, fires Save.</summary>
    private readonly DispatcherTimer _saveTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };

    /// <summary>
    /// The notification-area (tray) icon; null when the user disabled it
    /// (<see cref="UiPreferences.EnableTrayIcon"/>). UI thread only.
    /// </summary>
    private TrayIconController? _tray;

    /// <summary>
    /// Guards programmatic preference-control updates during startup restore:
    /// their change events must not re-write the values they are echoing.
    /// </summary>
    private bool _suppressPreferenceEvents;

    /// <summary>True once Windows signals session end (shutdown/sign-out).</summary>
    private bool _sessionEnding;

    public MainWindow(
        IProxyEngine engine,
        IProcessEnumerator processEnumerator,
        IApplicationSettingsStore settingsStore,
        IProxyTester proxyTester,
        ApplicationSettings? settings = null,
        LogPanel? logPanel = null,
        bool startHiddenToTray = false)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _processEnumerator = processEnumerator ?? throw new ArgumentNullException(nameof(processEnumerator));
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        _proxyTester = proxyTester ?? throw new ArgumentNullException(nameof(proxyTester));
        _settings = settings ?? new ApplicationSettings();
        _logPanel = logPanel ?? new LogPanel(Dispatcher);

        InitializeComponent();

        // All named controls now exist; XAML-wired handlers stay inert until
        // this flag is true, and user input is only honored afterwards.
        _uiReady = true;

        RestoreWindowPlacement();

        ManualRuleList.ItemsSource = _manualRules;
        BundleList.ItemsSource = _bundles;

        // Debounced save timer: coalesces bursts of changes (typing, bulk
        // checkbox toggles) into one file write.
        _saveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _saveTimer.Tick += (_, _) => PersistNow();

        LoadPreferencesToUi();
        RestoreProfilesToUi();

        // The session-wide log arrives from App.OnStartup, so every event
        // since process launch is already captured. Wire BOTH engine sinks to
        // it exactly once for the app lifetime â€” they are never stolen or
        // re-routed when the Debug window opens/closes (fixes the previous
        // design where opening Debug detached the main-window log).
        _engine.SetTrace(_logPanel.Append);
        _engine.SetFlowClosed(_logPanel.Append);
        _logPanel.Log("INFO", "Engine trace + flow-summary sinks wired.");

        RefreshProcesses();

        // Phase 11: tray icon (notification area). Created AFTER state restore
        // so its first state sync already knows the selected profile.
        _tray = _settings.Preferences.EnableTrayIcon
            ? new TrayIconController()
            : null;
        if (_tray is not null)
        {
            _tray.OpenRequested += OnTrayOpenRequested;
            _tray.StartRequested += OnTrayStartRequested;
            _tray.StopRequested += OnTrayStopRequested;
            _tray.ExitRequested += OnTrayExitRequested;
            SyncTrayState();
            _logPanel.Log("INFO", "Tray icon shown (notification area).");
        }
        else
        {
            _logPanel.Log("INFO", "Tray icon disabled in settings.");
        }

        // "Start minimized to the tray" is consumed here for THIS launch; it
        // is not auto-cleared, so a tray-only restart repeats the behavior
        // until the user turns the option off (the setting is the contract).
        if (startHiddenToTray)
        {
            _logPanel.Log("INFO", "Starting minimized to tray (window hidden).");
            if (_tray is { } tray)
                tray.ShowBalloon("Open NetRoute is running in the tray",
                    "Use the tray icon to open the window or exit.");
        }
    }

    private void RefreshProcesses()
    {
        // Preserve the user's PENDING picker selection (by PID) across a
        // refresh. Checks are only a staging area for the picker's "Add to
        // Manual Rules" button — they never become rules on their own, and
        // closing the picker discards them.
        var pending = _processes
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
            if (pending.Contains(row.ProcessId))
                row.RouteViaProxy = true;
        }

        // Manual rules and bundles are static â€” they survive Refresh untouched.
    }

    // â”€â”€ Feature 1: search box â”€â”€

    // â”€â”€ Running-processes picker â”€â”€

    private RunningProcessesWindow? _processesWindow;

    /// <summary>
    /// Opens (or activates) the running-processes picker. The picker binds the
    /// SAME <see cref="ProcessRow"/> instances this window owns, but checkbox
    /// state is only a PENDING selection: rules are created exclusively by
    /// <see cref="AddProcessesToManualRules"/> (the picker's Add button), and
    /// closing the picker without Add never adds rules.
    /// Also exposed for the <c>--open-processes</c> CLI diagnostic hook.
    /// </summary>
    public void OpenRunningProcesses()
    {
        if (_processesWindow != null && _processesWindow.IsVisible)
        {
            _processesWindow.Activate();
            return;
        }

        _processesWindow = new RunningProcessesWindow(
            _processes, _settings.Preferences, RefreshProcesses, AddProcessesToManualRules)
        {
            Owner = this
        };
        _processesWindow.Closed += (_, _) => _processesWindow = null;
        _processesWindow.Show();

        _logPanel.Log("INFO", "Running-processes picker opened.");
    }

    private void OnOpenProcessesClicked(object sender, RoutedEventArgs e) =>
        OpenRunningProcesses();

    /// <summary>
    /// Adds the given running processes as manual executable rules (deduped by
    /// path). Called from the processes picker's "Add to Manual Rules" button —
    /// the ONLY way a picker selection becomes a rule. Returns the rows that
    /// actually became rules so the picker can clear exactly their checks.
    /// </summary>
    public IReadOnlyList<ProcessRow> AddProcessesToManualRules(IEnumerable<ProcessRow> rows)
    {
        var added = new List<ProcessRow>();
        foreach (var row in rows)
        {
            var path = row.ProcessPath;
            if (string.IsNullOrWhiteSpace(path) || path == "(unknown path)")
                continue;
            if (_manualRules.Any(r => string.Equals(r.ExecutablePath, path, StringComparison.OrdinalIgnoreCase)))
                continue;

            var manualRow = new ManualRuleRow
            {
                ExecutableName = System.IO.Path.GetFileName(path),
                ExecutablePath = path,
                Enabled = true
            };
            manualRow.PropertyChanged += (_, _) => ScheduleSave();
            _manualRules.Add(manualRow);
            added.Add(row);
        }

        if (added.Count > 0)
        {
            ScheduleSave();
            UpdateEmptyStateHints();
            SetStatus($"Added {added.Count} manual rule(s).");
            _logPanel.Log("INFO", $"Added {added.Count} running process(es) as manual executable rules.");
        }
        return added;
    }

    // â”€â”€ Feature 2: add a manual .exe rule â”€â”€

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
            SetStatus($"'{path}' is already a manual rule.", StatusSeverity.Warning);
            return;
        }

        var manualRow = new ManualRuleRow
        {
            ExecutableName = Path.GetFileName(path),
            ExecutablePath = path
        };
        manualRow.PropertyChanged += (_, _) => ScheduleSave();
        _manualRules.Add(manualRow);
        ScheduleSave();
        UpdateEmptyStateHints();
    }

    private void OnRemoveManualRuleClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: ManualRuleRow row })
        {
            _manualRules.Remove(row);
            ScheduleSave();
            UpdateEmptyStateHints();
        }
    }

    // ―― Manual rules list: empty-state hint + stretched/clickable PATH cells ――

    /// <summary>
    /// Updates empty-state visibility: the hint over the manual-rules list
    /// while it has no rows, and the folder-bundles header while there are no
    /// bundles (with the chips list empty the section collapses entirely).
    /// </summary>
    private void UpdateEmptyStateHints()
    {
        EmptyRulesHint.Visibility = _manualRules.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;

        BundleHeaderPanel.Visibility = _bundles.Count == 0
            ? Visibility.Collapsed
            : Visibility.Visible;

        EmptyProxyHint.Visibility = _profiles.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    /// <summary>
    /// Keeps the PATH column stretched to the remaining list width so long
    /// paths trim with an ellipsis instead of forcing a horizontal scrollbar
    /// (which would push the ✕ remove button out of view).
    /// </summary>
    private void OnManualRuleListSizeChanged(object sender, SizeChangedEventArgs e) =>
        GridViewHelper.StretchPathColumn(ManualRuleList, ManualRulePathColumn, 64 + 180 + 44);

    /// <summary>
    /// Clicking a PATH cell copies the full path to the clipboard and pops the
    /// "Copied to clipboard" toast at the bottom of the window.
    /// </summary>
    private void OnCopyPathTextClicked(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (sender is TextBlock { DataContext: ManualRuleRow row } &&
            !string.IsNullOrWhiteSpace(row.ExecutablePath))
        {
            if (CopyToast.CopyText(this, row.ExecutablePath, bottomMargin: 64))
                _logPanel.Log("DEBUG", $"Path copied to clipboard: {row.ExecutablePath}");
        }
        else
        {
            CopyToast.Show(this, "Nothing to copy — name-only rule", bottomMargin: 64);
        }
    }

    // â”€â”€ Feature 3: add a folder bundle â”€â”€

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
            SetStatus($"'{path}' is already a bundle rule.", StatusSeverity.Warning);
            return;
        }

        var bundle = new BundleRow
        {
            FolderPath = path,
            DisplayName = Path.GetFileName(path.TrimEnd('\\', '/'))
        };
        bundle.PropertyChanged += (_, _) => ScheduleSave();

        // Scan recursively at add time (display only â€” matching is by prefix at
        // SYN time, so newly added exes in the folder are covered).
        var scanFailed = false;
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
            scanFailed = true;
            SetStatus($"Could not scan '{path}': {ex.Message}", StatusSeverity.Error);
        }

        _bundles.Add(bundle);
        ScheduleSave();
        UpdateEmptyStateHints();

        // A folder with no executables is still a valid prefix rule (exes added
        // later are covered), but the user should know that nothing matched
        // right now. When the scan itself failed the error is already reported,
        // so the empty warning would be misleading and is skipped.
        if (!scanFailed && bundle.Exes.Count == 0)
        {
            var name = string.IsNullOrEmpty(bundle.DisplayName) ? path : bundle.DisplayName;
            SetStatus($"No .exe files found in '{name}'.", StatusSeverity.Warning);
            CopyToast.Show(this, $"No .exe files found in '{name}'", bottomMargin: 64, warning: true);
            _logPanel.Log("WARN", $"Folder bundle has no executables: {path}");
        }
    }

    private void OnRemoveBundleClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: BundleRow row })
            RemoveFolderBundle(row);
    }

    /// <summary>Shared removal path for the chip ✕ and the info popup.</summary>
    private void RemoveFolderBundle(BundleRow row)
    {
        _bundles.Remove(row);
        ScheduleSave();
        UpdateEmptyStateHints();
        SetStatus($"Bundle '{row.DisplayName}' removed.");
        _logPanel.Log("INFO", $"Folder bundle removed: {row.FolderPath}");
    }

    // ―― Bundle chips: click-to-open info popup, hover toolbar actions ――

    private readonly List<BundleInfoWindow> _bundleInfoWindows = new();

    /// <summary>
    /// Opens (or activates) the styled info popup for a bundle. The popup binds
    /// the SAME <see cref="BundleRow"/> instance as the chip, so Enabled /
    /// Proxy-Direct edits flow through the usual persistence path.
    /// </summary>
    private void OpenBundleInfo(BundleRow bundle)
    {
        var existing = _bundleInfoWindows.FirstOrDefault(w =>
            ReferenceEquals(w.DataContext, bundle));
        if (existing != null)
        {
            existing.Activate();
            return;
        }

        var popup = new BundleInfoWindow(bundle, _settings.Preferences, RemoveFolderBundle)
        {
            Owner = this
        };
        popup.Closed += (_, _) => _bundleInfoWindows.Remove(popup);
        _bundleInfoWindows.Add(popup);
        popup.Show();

        _logPanel.Log("INFO", $"Bundle info opened: {bundle.DisplayName}");
    }

    /// <summary>
    /// Chip click = enable/disable the bundle (persisted via
    /// PropertyChanged → ScheduleSave). Shift+click opens the details popup.
    /// </summary>
    private void OnBundleChipClicked(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        e.Handled = true;
        if ((e.OriginalSource as FrameworkElement)?.DataContext is not BundleRow bundle)
            return;

        if (System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Shift)
        {
            OpenBundleInfo(bundle);
            return;
        }

        bundle.Enabled = !bundle.Enabled;
        SetStatus($"Bundle '{bundle.DisplayName}' {(bundle.Enabled ? "enabled" : "disabled")}.");
        _logPanel.Log("INFO", $"Folder bundle {(bundle.Enabled ? "enabled" : "disabled")}: {bundle.FolderPath}");
    }

    // â”€â”€ Persistence: profiles, preferences, immediate save â”€â”€

    /// <summary>Schedules a debounced save (coalesces rapid mutations).</summary>
    private void ScheduleSave()
    {
        _saveTimer.Stop();
        _saveTimer.Start();
    }

    /// <summary>Writes the complete settings document to disk now.</summary>
    private void PersistNow()
    {
        _saveTimer.Stop();

        // Commit any uncommitted UI state into the model first.
        CaptureWindowPlacement(_settings.Preferences);
        PersistStateIntoSettings();

        try
        {
            _settingsStore.Save(_settings);
        }
        catch (Exception ex)
        {
            // Persistence failure must never take the app down mid-session,
            // but it must never be silent either.
            SetStatus($"Could not save settings: {ex.Message}", StatusSeverity.Error);
            _logPanel.Log("ERR", $"[Settings] Save failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Copies the current rules/proxy-selection/prefs into the settings
    /// document. <see cref="ApplicationSettings.Proxy"/> is kept in sync with
    /// the selected profile so the active proxy survives a restart.
    /// </summary>
    private void PersistStateIntoSettings()
    {
        _settings.Rules = CollectRulesFromUi();
        _settings.Proxies = _profiles.Select(p => p.Config).ToList();
        _settings.SelectedProxyName = SelectedProfile?.Name;

        _settings.Proxy = SelectedProfile is { } profile
            ? new ProxyConfiguration
            {
                Protocol = profile.Protocol,
                Name = profile.Name,
                Host = profile.Host,
                Port = profile.Port,
                Username = profile.Username,
                Password = profile.Password,
                AuthenticationType = profile.AuthenticationType,
                Enabled = true
            }
            : null;
    }

    /// <summary>The profile card currently selected (null when none).</summary>
    private ProfileItem? _selectedProfileItem;

    private ProxyConfiguration? SelectedProfile => _selectedProfileItem?.Config;

    private static string MaskedUri(ProxyConfiguration p)
    {
        var auth = string.IsNullOrEmpty(p.Username) ? "" : $"{p.Username}:***@";
        return $"socks5://{auth}{p.Host}:{p.Port}";
    }

    private void LoadPreferencesToUi()
    {
        ThemeCombo.SelectedIndex = _settings.Preferences.Theme switch
        {
            AppTheme.Light => 1,
            AppTheme.Dark => 2,
            _ => 0
        };
        TestOnSaveCheck.IsChecked = _settings.Preferences.TestProxyOnSave;

        // Tray group — checkboxes echo the persisted prefs; the auto-start
        // checkbox reflects the REGISTRY (its single source of truth).
        // Programmatic updates are guarded so the change handlers stay inert.
        _suppressPreferenceEvents = true;
        try
        {
            TrayEnabledCheck.IsChecked = _settings.Preferences.EnableTrayIcon;
            StartMinimizedCheck.IsChecked = _settings.Preferences.StartMinimizedToTray;
            StartMinimizedCheck.IsEnabled = _settings.Preferences.EnableTrayIcon;
            MinimizeToTrayCheck.IsChecked = _settings.Preferences.MinimizeToTrayInsteadOfTaskbar;
            MinimizeToTrayCheck.IsEnabled = _settings.Preferences.EnableTrayIcon;
            CloseBehaviorCombo.SelectedIndex = _settings.Preferences.CloseButton switch
            {
                CloseButtonBehavior.Exit => 1,
                _ => 0
            };
            AutoStartCheck.IsChecked = AutoStartManager.IsEnabled();
            AutoStartCheck.IsEnabled = AutoStartManager.IsSupported;
            if (!AutoStartManager.IsSupported)
                AutoStartCheck.Content += "  (unavailable: executable path unknown)";

            // Font choice — index 0 is the system font, then UiFontCatalog
            // order. Each item previews in its own family; the closed combo
            // shows the selected family's name in that family.
            AppFontCombo.Items.Clear();
            AppFontCombo.Items.Add(new ComboBoxItem { Content = "System (Segoe UI)" });
            foreach (var key in UiFontCatalog.BundledKeys)
                AppFontCombo.Items.Add(new ComboBoxItem
                {
                    Content = key,
                    Tag = key,
                    FontFamily = FontCatalog.ResolveFamily(key)
                });

            var fontKey = UiFontCatalog.Normalize(_settings.Preferences.AppFontKey);
            AppFontCombo.SelectedIndex = UiFontCatalog.IndexOf(fontKey) + 1; // -1 → 0 = system
        }
        finally
        {
            _suppressPreferenceEvents = false;
        }

        ThemeApplier.Apply(this, _settings.Preferences);
    }

    private void RestoreProfilesToUi()
    {
        // Migration: a document with no saved profiles but a standalone
        // active proxy (saved by older versions that had inline Host/Port
        // fields) becomes the first selectable profile, so it is editable,
        // deletable, and restored on the next launch.
        if (_settings.Proxies.Count == 0 && _settings.Proxy is { Host.Length: > 0 })
        {
            var active = _settings.Proxy;
            _settings.Proxies.Add(new ProxyConfiguration
            {
                Protocol = active.Protocol,
                Name = !string.IsNullOrWhiteSpace(active.Name)
                    ? active.Name
                    : $"{active.Host}:{active.Port}",
                Host = active.Host,
                Port = active.Port,
                Username = active.Username,
                Password = active.Password,
                AuthenticationType = active.AuthenticationType,
                Enabled = true
            });
            _settings.SelectedProxyName = _settings.Proxies[0].Name;
        }

        _profiles.Clear();
        foreach (var proxy in _settings.Proxies)
            _profiles.Add(new ProfileItem(proxy));
        ProfileCardList.ItemsSource = _profiles;

        // Restore the selected profile by saved name; fall back to the last
        // card (direct assignment — no save scheduling during startup restore).
        var selected = _profiles.FirstOrDefault(p =>
                string.Equals(p.Config.Name, _settings.SelectedProxyName,
                    StringComparison.OrdinalIgnoreCase))
            ?? _profiles.LastOrDefault();
        foreach (var p in _profiles)
            p.IsSelected = ReferenceEquals(p, selected);
        _selectedProfileItem = selected;

        RestoreRulesFromSettings();
    }

    private void RestoreRulesFromSettings()
    {
        _manualRules.Clear();
        _bundles.Clear();

        foreach (var rule in _settings.Rules)
        {
            if (!string.IsNullOrEmpty(rule.FolderPath))
            {
                var bundle = new BundleRow
                {
                    FolderPath = rule.FolderPath,
                    DisplayName = Path.GetFileName(rule.FolderPath.TrimEnd('\\', '/')),
                    Enabled = rule.Enabled,
                    ModeIndex = rule.Mode == ProxyMode.Proxy ? 0 : 1
                };
                bundle.PropertyChanged += (_, _) => ScheduleSave();
                _bundles.Add(bundle);

                // Re-scan the folder's executables in the background (display
                // only â€” matching at SYN time is by folder prefix).
                RescanBundleExes(bundle);
            }
            else if (!string.IsNullOrEmpty(rule.ExecutablePath))
            {
                var manual = new ManualRuleRow
                {
                    ExecutableName = rule.ExecutableName ?? "",
                    ExecutablePath = rule.ExecutablePath,
                    Enabled = rule.Enabled
                };
                manual.PropertyChanged += (_, _) => ScheduleSave();
                _manualRules.Add(manual);
            }
            else if (!string.IsNullOrEmpty(rule.ExecutableName))
            {
                // Legacy name-only rule from older sessions (when ticking the
                // process checklist created rules): surface it as a manual rule
                // with no path so it stays visible, toggleable and removable.
                // RuleEngine matches these by name alone (an empty path never
                // path-matches), so routing behavior is preserved.
                var manual = new ManualRuleRow
                {
                    ExecutableName = rule.ExecutableName,
                    ExecutablePath = "",
                    Enabled = rule.Enabled
                };
                manual.PropertyChanged += (_, _) => ScheduleSave();
                _manualRules.Add(manual);
            }
        }

        UpdateEmptyStateHints();
    }

    private async void RescanBundleExes(BundleRow bundle)
    {
        try
        {
            await Task.Run(() =>
            {
                foreach (var exe in Directory.EnumerateFiles(
                             bundle.FolderPath, "*.exe", SearchOption.AllDirectories)
                             .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    Dispatcher.Invoke(() => bundle.Exes.Add(exe));
                }
            });
        }
        catch (Exception)
        {
            // Display-only scan; the folder may be on an unavailable volume.
            // Matching still works by folder prefix.
        }
    }

    // ―― Profile cards: selection, per-card actions, list-wide actions ――

    /// <summary>Makes <paramref name="item"/> the profile START routes through.</summary>
    private void SelectProfile(ProfileItem? item)
    {
        foreach (var p in _profiles)
            p.IsSelected = ReferenceEquals(p, item);
        _selectedProfileItem = item;
        _settings.SelectedProxyName = item?.Config.Name;
        SyncTrayState(); // the tray's Start gate and status follow the selection
        if (_uiReady)
            ScheduleSave();
    }

    /// <summary>
    /// Clicking a card body selects that profile (v2rayNG-style). Clicks that
    /// originate on the card's action buttons bubble up here as well — ignore
    /// those so, e.g., Delete never first re-selects the card being deleted.
    /// </summary>
    private void OnProxyCardClicked(object sender, MouseButtonEventArgs e)
    {
        if (IsInsideButton(e.OriginalSource as DependencyObject))
            return;

        if (sender is Border { Tag: ProfileItem item })
            SelectProfile(item);
    }

    /// <summary>True when the visual-tree ancestor chain contains a ButtonBase.</summary>
    private static bool IsInsideButton(DependencyObject? source)
    {
        while (source is not null)
        {
            if (source is System.Windows.Controls.Primitives.ButtonBase)
                return true;
            source = System.Windows.Media.VisualTreeHelper.GetParent(source);
        }
        return false;
    }

    private void OnNewProxyClicked(object sender, RoutedEventArgs e)
    {
        var editor = new ProxyEditorWindow(_proxyTester, null);
        ThemeApplier.Apply(editor, _settings.Preferences);
        editor.Owner = this;
        if (editor.ShowDialog() != true)
            return;

        var profile = editor.Profile;
        profile.Name = UniqueProfileName(profile.Name ?? $"{profile.Host}:{profile.Port}");
        var item = new ProfileItem(profile);
        _profiles.Add(item);
        _settings.Proxies = _profiles.Select(p => p.Config).ToList();
        SelectProfile(item);
        UpdateEmptyStateHints();

        AutoTestIfConfigured(item);
        SetStatus($"Added proxy '{profile.Name}' ({MaskedUri(profile)}).");
        PersistNow();
    }

    /// <summary>Edits the profile whose card's Edit button was clicked.</summary>
    private void OnEditProxyClicked(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ProfileItem item })
            return;

        var profile = item.Config;
        var editor = new ProxyEditorWindow(_proxyTester, profile);
        ThemeApplier.Apply(editor, _settings.Preferences);
        editor.Owner = this;
        if (editor.ShowDialog() != true)
            return;

        var edited = editor.Profile;
        profile.Name = edited.Name;
        profile.Host = edited.Host;
        profile.Port = edited.Port;
        profile.Username = edited.Username;
        profile.Password = edited.Password;
        profile.AuthenticationType = edited.AuthenticationType;
        profile.Enabled = edited.Enabled;

        item.RefreshFromConfig();
        AutoTestIfConfigured(item);
        SetStatus($"Updated proxy '{profile.Name}' ({MaskedUri(profile)}).");
        PersistNow();
    }

    /// <summary>Deletes the profile whose card's Delete button was clicked.</summary>
    private void OnDeleteProxyClicked(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ProfileItem item })
            return;

        var wasSelected = ReferenceEquals(item, _selectedProfileItem);
        _profiles.Remove(item);
        _settings.Proxies = _profiles.Select(p => p.Config).ToList();
        if (wasSelected)
            SelectProfile(_profiles.LastOrDefault());

        UpdateEmptyStateHints();
        SetStatus($"Deleted proxy '{item.Config.Name}'.");
        PersistNow();
    }

    /// <summary>
    /// Deletes every saved profile after an explicit confirmation — a bulk,
    /// hard-to-reverse action must never run on a single mis-click.
    /// </summary>
    private void OnDeleteAllProxiesClicked(object sender, RoutedEventArgs e)
    {
        if (_profiles.Count == 0)
        {
            SetStatus("No proxy profiles to delete.");
            return;
        }

        var confirm = MessageBox.Show(
            this,
            $"Delete all {_profiles.Count} saved proxy profile(s)? This cannot be undone.",
            "Delete all proxy profiles",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
            return;

        var count = _profiles.Count;
        _profiles.Clear();
        _selectedProfileItem = null;
        _settings.SelectedProxyName = null;
        SyncTrayState();

        UpdateEmptyStateHints();
        SetStatus($"Deleted {count} proxy profile(s).");
        _logPanel.Log("INFO", $"[Proxies] Deleted all {count} profile(s).");
        PersistNow();
    }

    /// <summary>
    /// Copies the profile as a socks5:// URL (Paste Config consumes the same
    /// format). Userinfo is percent-encoded so credentials with reserved
    /// characters round-trip through <see cref="Socks5UriParser"/>; the full
    /// URI only ever goes to the clipboard — status and log stay masked.
    /// </summary>
    private void OnShareProxyClicked(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ProfileItem item })
            return;

        var profile = item.Config;
        var auth = string.IsNullOrEmpty(profile.Username)
            ? ""
            : $"{Uri.EscapeDataString(profile.Username)}:{Uri.EscapeDataString(profile.Password ?? "")}@";
        var uri = $"socks5://{auth}{profile.Host}:{profile.Port}";

        if (CopyToast.CopyText(this, uri, bottomMargin: 64))
            _logPanel.Log("DEBUG", $"[Share] Copied {MaskedUri(profile)} to the clipboard.");
    }

    /// <summary>
    /// Window-level Ctrl+V: pastes a proxy config exactly like the Paste
    /// Config button. When focus is inside a text input (editor dialog fields,
    /// search boxes) the shortcut keeps its normal clipboard-paste behavior
    /// and the config paste is skipped.
    /// </summary>
    private void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (!_uiReady || e.Key != Key.V || Keyboard.Modifiers != ModifierKeys.Control)
            return;

        if (Keyboard.FocusedElement is TextBox or RichTextBox or PasswordBox)
            return; // let the focused text control paste into itself

        OnPasteConfigClicked(sender, e);
        e.Handled = true;
    }

    /// <summary>Parses socks5:// URLs from the clipboard and saves the first as a profile.</summary>
    private void OnPasteConfigClicked(object sender, RoutedEventArgs e)
    {
        var text = Clipboard.GetText().Trim();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Socks5UriParser.TryParse(line, out var parsed))
                continue;

            parsed.Name = UniqueProfileName(parsed.Name ?? $"{parsed.Host}:{parsed.Port}");
            var item = new ProfileItem(parsed);
            _profiles.Add(item);
            _settings.Proxies = _profiles.Select(p => p.Config).ToList();
            SelectProfile(item);
            UpdateEmptyStateHints();

            AutoTestIfConfigured(item);
            SetStatus($"Pasted proxy '{parsed.Name}' ({MaskedUri(parsed)}).");
            CopyToast.Show(this, $"Pasted proxy '{parsed.Name}'", bottomMargin: 64);
            PersistNow();
            return;
        }

        SetStatus("Clipboard does not contain a valid proxy URL. Expected: socks5://host:port or socks5://user:pass@host:port (user/pass optional).", StatusSeverity.Warning);
        CopyToast.Show(this, "No valid proxy URL in the clipboard", bottomMargin: 64, warning: true);
    }

    private string UniqueProfileName(string desired)
    {
        var taken = _profiles.Select(p => p.Config.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (taken.Add(desired))
            return desired;
        for (var i = 2; ; i++)
            if (taken.Add($"{desired} ({i})"))
                return $"{desired} ({i})";
    }

    private bool _pingTestRunning;

    /// <summary>
    /// Real ping for every profile: a full SOCKS5 handshake + CONNECT through
    /// each proxy (5 s timeout each), run concurrently. Results land on the
    /// cards as they complete; the run is guarded against re-entry.
    /// </summary>
    private async void OnTestPingClicked(object sender, RoutedEventArgs e)
    {
        if (_pingTestRunning)
            return;
        if (_profiles.Count == 0)
        {
            SetStatus("No profiles to ping — create one with New… or Paste Config.", StatusSeverity.Warning);
            return;
        }

        _pingTestRunning = true;
        PingAllButton.IsEnabled = false;
        _logPanel.Log("INFO", $"[Ping] Testing {_profiles.Count} profile(s): SOCKS5 handshake + CONNECT via each proxy…");
        SetStatus($"Pinging {_profiles.Count} profile(s)…");

        try
        {
            await Task.WhenAll(_profiles.Select(RunPingTestAsync));
            var ok = _profiles.Count(p => !p.PingFailed && p.PingMs is not null);
            SetStatus($"Ping finished: {ok}/{_profiles.Count} reachable.");
            _logPanel.Log("INFO", $"[Ping] Finished: {ok}/{_profiles.Count} reachable.");
        }
        finally
        {
            _pingTestRunning = false;
            PingAllButton.IsEnabled = true;
        }
    }

    /// <summary>Runs one real ping and stores the outcome on the card.</summary>
    private async Task RunPingTestAsync(ProfileItem item)
    {
        try
        {
            var result = await _proxyTester.TestAsync(item.Config, TimeSpan.FromSeconds(5));
            item.PingMs = result.Success ? Math.Max(1, result.LatencyMs) : null;
            item.PingFailed = !result.Success;
            item.PingDetails = result.Message;
            _logPanel.Log(result.Success ? "INFO" : "WARN",
                $"[Ping {item.Config.Name}] {(result.Success ? $"{result.LatencyMs} ms" : "FAILED")} — {result.Message}");
        }
        catch (Exception ex)
        {
            item.PingMs = null;
            item.PingFailed = true;
            item.PingDetails = ex.Message;
            _logPanel.Log("ERR", $"[Ping {item.Config.Name}] {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Reorders the cards by last ping: tested fastest → slowest, then
    /// untested, then failed (stable for equal keys). Move() keeps the card
    /// instances, so ping state and selection survive the reorder.
    /// </summary>
    private void OnSortByPingClicked(object sender, RoutedEventArgs e)
    {
        if (_profiles.Count < 2)
            return;

        var ordered = _profiles
            .OrderBy(p => p.PingFailed ? int.MaxValue : p.PingMs ?? int.MaxValue - 1)
            .ToList();

        for (var i = 0; i < ordered.Count; i++)
        {
            var index = _profiles.IndexOf(ordered[i]);
            if (index != i)
                _profiles.Move(index, i);
        }

        _settings.Proxies = _profiles.Select(p => p.Config).ToList();
        ScheduleSave();

        var fastest = ordered.FirstOrDefault(p => !p.PingFailed && p.PingMs is not null);
        SetStatus(fastest?.PingMs is int ms
            ? $"Sorted by ping — fastest: '{fastest.Config.Name}' ({ms} ms)."
            : "Sorted. No successful ping yet — run Test Ping first.");
    }

    private async void AutoTestIfConfigured(ProfileItem item)
    {
        if (!_settings.Preferences.TestProxyOnSave)
            return;

        var result = await _proxyTester.TestAsync(item.Config, TimeSpan.FromSeconds(5));
        item.PingMs = result.Success ? Math.Max(1, result.LatencyMs) : null;
        item.PingFailed = !result.Success;
        item.PingDetails = result.Message;
        _logPanel.Log(result.Success ? "INFO" : "WARN",
            $"[Test {item.Config.Name}] {(result.Success ? "OK" : "FAILED")} — {result.Message}");
        SetStatus($"Proxy test: {result.Message}", result.Success ? StatusSeverity.Info : StatusSeverity.Error);
    }

    // â”€â”€ Settings group handlers â”€â”€

    private void OnThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        _settings.Preferences.Theme = ThemeCombo.SelectedIndex switch
        {
            1 => AppTheme.Light,
            2 => AppTheme.Dark,
            _ => AppTheme.System
        };
        ThemeApplier.Apply(this, _settings.Preferences);
        ScheduleSave();
    }

    private void OnAppFontChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_uiReady || _suppressPreferenceEvents)
            return;

        // Index 0 is "System (Segoe UI)"; the rest map 1:1 to UiFontCatalog order.
        var key = AppFontCombo.SelectedIndex > 0
            ? UiFontCatalog.BundledKeys[AppFontCombo.SelectedIndex - 1]
            : UiFontCatalog.SystemKey;
        _settings.Preferences.AppFontKey = key;

        ThemeApplier.Apply(this, _settings.Preferences);

        // Secondary windows may be open right now — re-apply so they follow
        // immediately instead of on their next (re)creation.
        if (_debugLogWindow is { IsVisible: true } debugWindow)
            ThemeApplier.Apply(debugWindow, _settings.Preferences);
        if (_processesWindow is { IsVisible: true } processesWindow)
            ThemeApplier.Apply(processesWindow, _settings.Preferences);

        ScheduleSave();
        _logPanel.Log("INFO",
            $"[Appearance] UI font: {(key.Length == 0 ? "System (Segoe UI)" : key)}.");
    }

    private void OnTestPrefChanged(object sender, RoutedEventArgs e)
    {
        _settings.Preferences.TestProxyOnSave = TestOnSaveCheck.IsChecked == true;
        ScheduleSave();
    }

    // ―― Tray & startup settings (Phase 11) ――

    private void OnTrayPrefChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady || _suppressPreferenceEvents)
            return;

        _settings.Preferences.EnableTrayIcon = TrayEnabledCheck.IsChecked == true;
        _settings.Preferences.StartMinimizedToTray = StartMinimizedCheck.IsChecked == true;
        _settings.Preferences.MinimizeToTrayInsteadOfTaskbar = MinimizeToTrayCheck.IsChecked == true;

        // The dependent options are meaningless without the icon: disable them
        // so the UI keeps telling the truth about what is in effect.
        StartMinimizedCheck.IsEnabled = _settings.Preferences.EnableTrayIcon;
        MinimizeToTrayCheck.IsEnabled = _settings.Preferences.EnableTrayIcon;

        SetTrayEnabled(_settings.Preferences.EnableTrayIcon);
        ScheduleSave();
        _logPanel.Log("INFO",
            $"[Tray] Icon {(_settings.Preferences.EnableTrayIcon ? "enabled" : "disabled")}; " +
            $"start-minimized={_settings.Preferences.StartMinimizedToTray}; " +
            $"minimize-to-tray={_settings.Preferences.MinimizeToTrayInsteadOfTaskbar}.");
    }

    private void OnCloseBehaviorChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_uiReady || _suppressPreferenceEvents)
            return;

        _settings.Preferences.CloseButton = CloseBehaviorCombo.SelectedIndex == 1
            ? CloseButtonBehavior.Exit
            : CloseButtonBehavior.MinimizeToTray;
        ScheduleSave();
        _logPanel.Log("INFO", $"[Tray] Close button behavior: {_settings.Preferences.CloseButton}.");
    }

    private void OnAutoStartChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady || _suppressPreferenceEvents)
            return;

        var wantEnabled = AutoStartCheck.IsChecked == true;
        if (AutoStartManager.SetEnabled(wantEnabled))
        {
            SetStatus(wantEnabled
                ? "Open NetRoute will start when Windows signs in (current user)."
                : "Auto-start with Windows disabled.");
            _logPanel.Log("INFO", $"[Tray] Auto-start {(wantEnabled ? "registered" : "removed")} (HKCU Run).");
            // Intentionally NOT persisted: the registry is the single source
            // of truth; the checkbox just mirrors it.
        }
        else
        {
            // The registry write failed — revert the visual, surface the
            // failure (never silent), and re-read the actual state.
            AutoStartCheck.IsChecked = AutoStartManager.IsEnabled();
            SetStatus("Could not update the Windows auto-start registration (registry access denied?).",
                StatusSeverity.Error);
            _logPanel.Log("ERR", "[Tray] Auto-start registry update failed.");
        }
    }

    /// <summary>Creates or destroys the tray icon to match the preference.</summary>
    private void SetTrayEnabled(bool enabled)
    {
        if (enabled && _tray is null)
        {
            _tray = new TrayIconController();
            _tray.OpenRequested += OnTrayOpenRequested;
            _tray.StartRequested += OnTrayStartRequested;
            _tray.StopRequested += OnTrayStopRequested;
            _tray.ExitRequested += OnTrayExitRequested;
            SyncTrayState();
            _logPanel.Log("INFO", "[Tray] Icon created.");
        }
        else if (!enabled && _tray is { } tray)
        {
            tray.OpenRequested -= OnTrayOpenRequested;
            tray.StartRequested -= OnTrayStartRequested;
            tray.StopRequested -= OnTrayStopRequested;
            tray.ExitRequested -= OnTrayExitRequested;
            tray.Dispose();
            _tray = null;
            _logPanel.Log("INFO", "[Tray] Icon removed.");
        }
    }

    /// <summary>Pushes engine state + the selected profile into the tray icon.</summary>
    private void SyncTrayState()
    {
        if (_tray is null)
            return;

        var profile = SelectedProfile;
        _tray.SetEngineState(_engine.IsRunning, profile?.Name);
    }

    // â”€â”€ Start / Stop â”€â”€

    private void OnEngineToggleChecked(object sender, RoutedEventArgs e)
    {
        // Stop-failure snap-back re-enters Checked while already running —
        // that is a visual-only correction, not a start request.
        if (_engine.IsRunning)
            return;

        _logPanel.Log("INFO", "Start clicked");
        StartEngineCore();
    }

    private async void OnEngineToggleUnchecked(object sender, RoutedEventArgs e)
    {
        // Reverting a FAILED start also raises Unchecked while the engine was
        // never running — treat that as a visual-only change, not a stop.
        if (!_engine.IsRunning)
        {
            SetStatus("Status: Stopped");
            return;
        }

        _logPanel.Log("INFO", "Stop clicked");
        var stopped = await StopEngineCoreAsync();
        if (!stopped && _engine.IsRunning)
        {
            // Stop failed — snap the toggle back to the running (STOP) state.
            EngineToggleButton.IsChecked = true;
        }
    }

    // ―― Tray command handlers (Phase 11) ――
    // The tray icon raises INTENTS; this window executes them through the
    // SAME Start/Stop cores as the window toggle, so validation, elevation
    // notices, status text and snap-back logic exist exactly once.

    private void OnTrayOpenRequested(object? sender, EventArgs e) => ShowFromTray();

    private void OnTrayStartRequested(object? sender, EventArgs e)
    {
        if (_engine.IsRunning)
        {
            SyncTrayState();
            return;
        }

        _logPanel.Log("INFO", "Start requested from the tray icon");
        StartEngineCore();
        SyncTrayState();

        // A hidden window cannot show the status bar: announce the outcome.
        if (_engine.IsRunning)
            _tray?.ShowBalloon("Routing started",
                "Selected applications are routed through the proxy.");
        else if (_tray is not null)
            _tray.ShowBalloon("Could not start routing", StatusText.Text);
    }

    private async void OnTrayStopRequested(object? sender, EventArgs e)
    {
        if (!_engine.IsRunning)
        {
            SyncTrayState();
            return;
        }

        _logPanel.Log("INFO", "Stop requested from the tray icon");
        await StopEngineCoreAsync();
        SyncTrayState();

        if (!_engine.IsRunning)
            _tray?.ShowBalloon("Routing stopped",
                "All traffic is back on the normal network path.");
    }

    private async void OnTrayExitRequested(object? sender, EventArgs e)
    {
        _logPanel.Log("INFO", "Exit requested from the tray icon");
        if (_engine.IsRunning)
            await StopEngineCoreAsync();

        // Explicit exit: bypass close-to-tray, tear down, then shut the app
        // down explicitly (covers a never-shown main window too).
        _realExit = true;
        Close();
        Application.Current.Shutdown();
    }

    /// <summary>Shows and activates the window (tray click / Open menu item).</summary>
    private void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>
    /// Shared start path (START toggle and Restart Services): selected-profile
    /// guard → validation → elevation notice → <see cref="IProxyEngine.Start"/>.
    /// Snap-back (IsChecked = false) happens BEFORE the error status is written
    /// so the Unchecked handler's visual-only "Status: Stopped" never masks it.
    /// </summary>
    private void StartEngineCore()
    {
        EngineToggleButton.IsEnabled = false;
        try
        {
            // Profiles are the only proxy source now; without one there is
            // nothing to connect through, so stop before validation with a
            // message that points at the two ways to add one.
            if (SelectedProfile is null)
            {
                const string msg = "Cannot start: no proxy selected. Create one with New… or Paste Config in the Proxies tab, then select it.";
                EngineToggleButton.IsChecked = false; // snap back to START
                SetStatus(msg, StatusSeverity.Error);
                _logPanel.Log("ERR", msg);
                return;
            }

            SetStatus("Starting...");

            var settings = BuildSettingsFromUi();

            var validation = ConfigurationValidator.Validate(settings);
            if (!validation.IsValid)
            {
                var msg = "Cannot start: " + string.Join("; ", validation.Errors);
                EngineToggleButton.IsChecked = false; // snap back to START
                SetStatus(msg, StatusSeverity.Error);
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
            _logPanel.Log("INFO", $"Starting engine: proxy={settings.Proxy?.Host}:{settings.Proxy?.Port}, rules={settings.Rules.Count}");

            _engine.Start(settings);
            SetStatus("Status: Running");
            _logPanel.Log("INFO", "Engine started — capturing SYN traffic. Trace lines follow.");
        }
        catch (Exception ex)
        {
            // The engine surfaces actionable errors (e.g. WinDivert requires
            // Administrator privileges); show them verbatim — never a silent
            // failure.
            var msg = "Cannot start: " + ex.Message;
            EngineToggleButton.IsChecked = false; // snap back to START
            SetStatus(msg, StatusSeverity.Error);
            _logPanel.Log("ERR", msg);
        }
        finally
        {
            EngineToggleButton.IsEnabled = true;
            SyncTrayState(); // badge/status/Start-gate follow the engine on every path
        }
    }

    /// <summary>Shared stop path (STOP toggle and Restart Services).</summary>
    /// <returns>True when the engine is no longer running.</returns>
    private async Task<bool> StopEngineCoreAsync()
    {
        EngineToggleButton.IsEnabled = false;
        try
        {
            await _engine.StopAsync();
            SetStatus("Status: Stopped");
            _logPanel.Log("INFO", "Engine stopped.");
            return !_engine.IsRunning;
        }
        catch (Exception ex)
        {
            var msg = "Error while stopping: " + ex.Message;
            SetStatus(msg, StatusSeverity.Error);
            _logPanel.Log("ERR", msg);
            return !_engine.IsRunning;
        }
        finally
        {
            EngineToggleButton.IsEnabled = true;
            SyncTrayState(); // badge/status/Start-gate follow the engine on every path
        }
    }

    /// <summary>
    /// Restart services: stop the engine if it is running, then start it again
    /// with the currently selected profile. The toggle is realigned with the
    /// engine's actual state; its handlers treat those realignments as
    /// visual-only (their early-return guards make that safe).
    /// </summary>
    private async void OnRestartServicesClicked(object sender, RoutedEventArgs e)
    {
        if (!_engine.IsRunning)
        {
            SetStatus("Engine is not running — nothing to restart. Press START instead.");
            _logPanel.Log("INFO", "Restart ignored: engine is not running.");
            return;
        }

        _logPanel.Log("INFO", "Restart clicked — stopping engine");
        var stopped = await StopEngineCoreAsync();
        if (!stopped)
        {
            EngineToggleButton.IsChecked = _engine.IsRunning; // restore the STOP visual
            return;
        }

        EngineToggleButton.IsChecked = false; // align with the stopped state (visual-only event)
        _logPanel.Log("INFO", "Restart: starting engine again");
        StartEngineCore();
        EngineToggleButton.IsChecked = _engine.IsRunning; // align with the final state (visual-only event)
    }

    private static bool IsRunningElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Builds an <see cref="ApplicationSettings"/> from the UI: the selected
    /// proxy profile (the only proxy source — START is rejected with guidance
    /// when nothing is selected), the ordered rule list matching RuleEngine
    /// first-match-wins semantics, and the persisted proxies/preferences/
    /// log-level. The returned document is exactly what gets validated by
    /// Start and persisted.
    /// </summary>
    private ApplicationSettings BuildSettingsFromUi()
    {
        var proxy = SelectedProfile is { } profile
            ? new ProxyConfiguration
            {
                Protocol = profile.Protocol,
                Name = profile.Name,
                Host = profile.Host,
                Port = profile.Port,
                Username = profile.Username,
                Password = profile.Password,
                AuthenticationType = profile.AuthenticationType,
                Enabled = true
            }
            : null;

        return new ApplicationSettings
        {
            Proxy = proxy,
            Rules = CollectRulesFromUi(),
            Proxies = _profiles.Select(p => p.Config).ToList(),
            SelectedProxyName = SelectedProfile?.Name,
            LogLevel = _settings.LogLevel,
            Preferences = _settings.Preferences
        };
    }

    /// <summary>
    /// Collects the ordered rule list from the two rule sources: manual exe
    /// rules (name+path) and folder bundles. Running-process checks are NOT
    /// rules — they are the picker's pending selection and become rules only
    /// through "Add to Manual Rules" (closing the picker adds nothing).
    /// Order matches the RuleEngine list-order evaluation contract.
    /// </summary>
    private List<ApplicationRule> CollectRulesFromUi()
    {
        var rules = new List<ApplicationRule>();

        // Manual exe rules — name + path rules (path empty for migrated
        // name-only rules; the engine then matches by name alone).
        rules.AddRange(_manualRules
            .Select(m => new ApplicationRule
            {
                ExecutableName = m.ExecutableName,
                ExecutablePath = string.IsNullOrEmpty(m.ExecutablePath) ? null : m.ExecutablePath,
                Enabled = m.Enabled,
                Mode = ProxyMode.Proxy
            }));

        // Folder bundles â†’ folder rules.
        rules.AddRange(_bundles
            .Select(b => new ApplicationRule
            {
                FolderPath = b.FolderPath,
                Enabled = b.Enabled,
                Mode = b.ModeIndex == 0 ? ProxyMode.Proxy : ProxyMode.Direct
            }));

        return rules;
    }

    // â”€â”€ Window placement persistence â”€â”€

    /// <summary>Smallest window worth restoring; anything smaller smells like junk data.</summary>
    private const double MinRestorableWidth = 200;
    private const double MinRestorableHeight = 150;

    /// <summary>
    /// Writes the current main-window geometry into preferences. While
    /// maximized or minimized the NORMAL-state bounds
    /// (<see cref="Window.RestoreBounds"/>) are captured so a restored session
    /// returns to the size the user chose, not to the transient frame.
    /// </summary>
    private void CaptureWindowPlacement(UiPreferences preferences)
    {
        var rect = WindowState == WindowState.Normal
            ? new Rect(Left, Top, ActualWidth, ActualHeight)
            : new Rect(RestoreBounds.X, RestoreBounds.Y,
                       RestoreBounds.Width, RestoreBounds.Height);

        if (!double.IsFinite(rect.Width) || !double.IsFinite(rect.Height) ||
            rect.Width < MinRestorableWidth || rect.Height < MinRestorableHeight)
            return; // never shown yet, or degenerate â€” keep whatever was stored

        if (double.IsFinite(rect.X) && double.IsFinite(rect.Y))
        {
            preferences.WindowLeft = rect.X;
            preferences.WindowTop = rect.Y;
        }

        preferences.WindowWidth = rect.Width;
        preferences.WindowHeight = rect.Height;
        preferences.WindowMaximized = WindowState == WindowState.Maximized;
    }

    /// <summary>
    /// Applies persisted window geometry, ignoring absent/implausible values.
    /// A rect that no longer intersects any attached display (monitor
    /// unplugged since last run) falls back to defaults rather than opening an
    /// invisible window.
    /// </summary>
    private void RestoreWindowPlacement()
    {
        var p = _settings.Preferences;
        if (p.WindowLeft is not { } left || p.WindowTop is not { } top ||
            p.WindowWidth is not { } width || p.WindowHeight is not { } height)
            return; // legacy document or first run â€” defaults

        if (!double.IsFinite(left) || !double.IsFinite(top) ||
            width < MinRestorableWidth || height < MinRestorableHeight ||
            !IntersectsVirtualScreen(left, top, width, height))
            return;

        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = left;
        Top = top;
        Width = width;
        Height = height;
        if (p.WindowMaximized)
            WindowState = WindowState.Maximized;
    }

    /// <summary>True when the rect overlaps the virtual desktop by at least a visible sliver.</summary>
    private static bool IntersectsVirtualScreen(double x, double y, double w, double h)
    {
        const double minVisiblePixels = 40;
        var vsLeft = SystemParameters.VirtualScreenLeft;
        var vsTop = SystemParameters.VirtualScreenTop;

        return x + w > vsLeft + minVisiblePixels &&
               y + h > vsTop + minVisiblePixels &&
               x < vsLeft + SystemParameters.VirtualScreenWidth - minVisiblePixels &&
               y < vsTop + SystemParameters.VirtualScreenHeight - minVisiblePixels;
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        // The HWND now exists â€” apply the dark native title bar per palette.
        ThemeApplier.ApplyDarkTitleBar(this, ThemeApplier.IsDark(_settings.Preferences.Theme));
    }

    protected override void OnLocationChanged(EventArgs e)
    {
        base.OnLocationChanged(e);
        if (_uiReady)
            ScheduleSave();
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo sizeInfo)
    {
        base.OnRenderSizeChanged(sizeInfo);
        if (_uiReady)
            ScheduleSave();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (!_uiReady)
            return;

        // Phase 11: minimize-to-tray — hide instead of docking to the taskbar.
        // The engine and the message loop keep running; the tray icon (or the
        // taskbar while the window is merely hidden) restores it. Skipped when
        // the icon is disabled — otherwise the window would be unreachable.
        if (WindowState == WindowState.Minimized &&
            _tray is not null &&
            _settings.Preferences.MinimizeToTrayInsteadOfTaskbar &&
            !_sessionEnding)
        {
            Hide();
            _logPanel.Log("INFO", "Minimized to tray (window hidden, engine unaffected).");
        }

        ScheduleSave();
    }

    /// <summary>Severity of a message shown in the bottom status bar.</summary>
    private enum StatusSeverity
    {
        /// <summary>Neutral / informational (secondary text color).</summary>
        Info,

        /// <summary>
        /// Advisory caution: nothing failed, but the action was a no-op or
        /// found nothing. Yellow.
        /// </summary>
        Warning,

        /// <summary>Hard failure: an operation threw or was rejected. Red.</summary>
        Error
    }

    private void SetStatus(string message, StatusSeverity severity = StatusSeverity.Info)
    {
        StatusText.Text = message;
        // Themed tokens stay readable in light AND dark palettes. Warnings use
        // amber yellow, distinct from the hard-error red; Goldenrod keeps
        // contrast on both the light and dark card backgrounds.
        StatusText.Foreground = severity switch
        {
            StatusSeverity.Error => System.Windows.Media.Brushes.Firebrick,
            StatusSeverity.Warning => System.Windows.Media.Brushes.Goldenrod,
            _ => TryFindResource("TextSecondaryBrush") as System.Windows.Media.Brush
                 ?? System.Windows.Media.Brushes.Gray
        };
    }

    // â”€â”€ Debug log window â”€â”€

    private DebugLogWindow? _debugLogWindow;

    /// <summary>
    /// Opens the session Debug window (separate, non-modal). The window is a
    /// live view over the shared <see cref="LogPanel"/> â€” the engine sinks stay
    /// attached to the panel for the whole app lifetime, so opening/closing
    /// this window never drops or re-routes logging. Single instance: opening
    /// it again just activates the existing window.
    /// </summary>
    /// <summary>Opens (or activates) the session Debug log window. Also exposed
    /// for the <c>--open-debug</c> CLI diagnostic hook and smoke tests.</summary>
    public void OpenDebugLogWindow()
    {
        if (_debugLogWindow != null && _debugLogWindow.IsVisible)
        {
            _debugLogWindow.Activate();
            return;
        }

        _debugLogWindow = new DebugLogWindow(_logPanel, _settings.Preferences)
        {
            Owner = this
        };
        _debugLogWindow.Closed += (_, _) => _debugLogWindow = null;
        _debugLogWindow.Show();

        _logPanel.Log("INFO", "Debug window opened.");
    }

    private void OnDebugClicked(object sender, RoutedEventArgs e) =>
        OpenDebugLogWindow();

    /// <summary>
    /// True for an explicit exit (tray Exit / real close) — bypasses
    /// close-to-tray so the window actually closes.
    /// </summary>
    private bool _realExit;

    /// <summary>
    /// Phase 11: close-to-tray. With the icon enabled and the close button at
    /// its default, the X button HIDES the window and the engine keeps routing
    /// in the background; exit lives in the tray menu. Without the icon (or
    /// with CloseButton=Exit, or on session end) the close proceeds — the
    /// window can never end up hidden with no way to bring it back.
    /// </summary>
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_realExit &&
            !_sessionEnding &&
            _tray is not null &&
            _settings.Preferences.CloseButton == CloseButtonBehavior.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            _tray.ShowBalloon("Open NetRoute keeps routing",
                "Minimized to the tray. Use the tray icon to open the window or exit.");
            _logPanel.Log("INFO", "Close button: hidden to tray (engine keeps running).");
            return;
        }

        base.OnClosing(e);
    }

    /// <summary>
    /// Called by App when Windows is shutting down or signing out: the pending
    /// close must PROCEED (never hide) so the session end is not blocked.
    /// </summary>
    public void NotifySessionEnding() => _sessionEnding = true;

    protected override void OnClosed(EventArgs e)
    {
        // Final persistence flush — state is never lost on close.
        try
        {
            PersistNow();
        }
        catch
        {
            // Never block shutdown on a failed save; mutations were already
            // persisted incrementally.
        }

        _tray?.Dispose();
        _tray = null;
        _logPanel.Shutdown();
        base.OnClosed(e);
    }
}
