using System.Collections.Specialized;
using System.Windows;
using ProxyApp.Core.Configuration;

namespace ProxyApp;

/// <summary>
/// The Debug / Session-Log window: a read-only LIVE view over the
/// application-wide <see cref="LogPanel"/> (created in <c>App.OnStartup</c>,
/// so it holds the complete history for this session — settings load, service
/// construction, engine trace, per-connection flow summaries).
///
/// The window owns no buffer and no timer of its own: it binds the shared
/// observable collection and adds Copy / Clear actions on the store. Theme
/// tokens are applied at open time (live re-theme while the window is open is
/// a v1 limitation, consistent with the proxy editor window).
/// </summary>
public partial class DebugLogWindow : Window
{
    private readonly LogPanel _panel;
    private readonly bool _darkTitleBar;

    public DebugLogWindow(LogPanel panel, UiPreferences? preferences = null)
    {
        var prefs = preferences ?? new UiPreferences();
        _darkTitleBar = ThemeApplier.IsDark(prefs.Theme);
        _panel = panel ?? throw new ArgumentNullException(nameof(panel));
        InitializeComponent();
        ThemeApplier.Apply(this, prefs);

        LogList.ItemsSource = _panel.Lines;
        _panel.Lines.CollectionChanged += OnLinesChanged;
        UpdateCount();
        ScrollToEnd();
    }

    private void OnLinesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        UpdateCount();

        // Auto-follow new lines unless the operator selected one (e.g. to copy
        // a specific entry) — a selection pins the scroll position.
        if (e.Action == NotifyCollectionChangedAction.Add && LogList.SelectedItem is null)
            ScrollToEnd();
    }

    private void ScrollToEnd()
    {
        if (_panel.Lines.Count == 0)
            return;
        LogList.ScrollIntoView(_panel.Lines[^1]);
    }

    private void UpdateCount() =>
        CountText.Text = $"{_panel.Lines.Count:N0} of max {LogPanel.MaxLines:N0} lines";

    private void OnCopyClicked(object sender, RoutedEventArgs e) =>
        _panel.CopyToClipboard();

    private void OnClearClicked(object sender, RoutedEventArgs e)
    {
        _panel.Clear();
        _panel.Log("INFO", "Log cleared.");
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ThemeApplier.ApplyDarkTitleBar(this, _darkTitleBar);
    }

    protected override void OnClosed(EventArgs e)
    {
        // Unhook from the longer-lived panel so the closed window cannot be
        // kept alive by its CollectionChanged subscription.
        _panel.Lines.CollectionChanged -= OnLinesChanged;
        base.OnClosed(e);
    }
}