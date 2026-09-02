using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using ProxyApp.Core.Configuration;

namespace ProxyApp;

/// <summary>
/// The Debug / Session-Log window: a read-only LIVE view over the
/// application-wide <see cref="LogPanel"/> (created in <c>App.OnStartup</c>,
/// so it holds the complete history for this session — settings load, service
/// construction, engine trace, per-connection flow summaries).
///
/// The window owns no buffer and no timer of its own: it mirrors the shared
/// log into a single read-only, fully selectable text view (severity-tinted)
/// and adds Copy / Clear actions on the store. Theme
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

        LogView.Document.Blocks.Clear();
        foreach (var line in _panel.Lines)
            LogView.Document.Blocks.Add(FormatLine(line));
        _panel.TextLogChanged += OnTextLogChanged;
        UpdateCount();
        LogView.ScrollToEnd();
    }

    private void OnTextLogChanged(object? sender, PlainLogChangedEventArgs e)
    {
        if (e.Reset)
        {
            LogView.Document.Blocks.Clear();
        }
        else
        {
            // Ring-buffer overflow trims from the FRONT; the view mirrors it.
            for (var i = 0; i < e.RemovedFromFront && LogView.Document.Blocks.Count > 0; i++)
                LogView.Document.Blocks.Remove(LogView.Document.Blocks.FirstBlock);

            foreach (var line in e.Added)
                LogView.Document.Blocks.Add(FormatLine(line));
        }

        UpdateCount();

        // Auto-follow the tail unless the operator pinned a position (active
        // selection, or caret parked away from the end to read/copy history).
        if (LogView.Selection.IsEmpty &&
            LogView.CaretPosition.CompareTo(LogView.Document.ContentEnd) >= 0)
        {
            LogView.ScrollToEnd();
        }
    }

    /// <summary>
    /// Builds one monospace paragraph per log line, severity-tinted like the
    /// previous list view (red ERR/ERROR, amber WARN, primary text otherwise).
    /// </summary>
    private Paragraph FormatLine(LogLine line)
    {
        var run = new Run($"{line.Timestamp}  {line.Level,-5}  {line.Message}")
        {
            Foreground = line.Level switch
            {
                "ERR" or "ERROR" => TryFindResource("DangerBrush") as Brush ?? Brushes.Firebrick,
                "WARN" => TryFindResource("WarningBrush") as Brush ?? Brushes.DarkOrange,
                _ => TryFindResource("TextPrimaryBrush") as Brush ?? Brushes.Black
            }
        };
        return new Paragraph(run) { Margin = new Thickness(0) };
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
        // kept alive by its TextLogChanged subscription.
        _panel.TextLogChanged -= OnTextLogChanged;
        base.OnClosed(e);
    }
}