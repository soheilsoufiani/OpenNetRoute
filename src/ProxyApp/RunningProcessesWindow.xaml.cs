using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using ProxyApp.Core.Configuration;

namespace ProxyApp;

/// <summary>
/// The running-processes picker window: a live, filterable view over the
/// SHARED <see cref="ProcessRow"/> collection owned by <see cref="MainWindow"/>.
///
/// Checkboxes are a PENDING SELECTION only — they do not create routing rules
/// and are not persisted. A rule is created exclusively by the "Add to Manual
/// Rules" button (<paramref name="addManual"/>); closing the window without
/// Add discards the selection entirely. <paramref name="refresh"/> re-enumerates
/// processes on the owning side (executed on the UI thread).
/// </summary>
public partial class RunningProcessesWindow : Window
{
    private readonly ObservableCollection<ProcessRow> _processes;
    private readonly Action _refresh;
    private readonly Func<IEnumerable<ProcessRow>, IReadOnlyList<ProcessRow>> _addManual;
    private readonly ICollectionView _view;
    private readonly bool _darkTitleBar;

    public RunningProcessesWindow(ObservableCollection<ProcessRow> processes,
                                  UiPreferences preferences,
                                  Action refresh,
                                  Func<IEnumerable<ProcessRow>, IReadOnlyList<ProcessRow>> addManual)
    {
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _refresh = refresh ?? throw new ArgumentNullException(nameof(refresh));
        _addManual = addManual ?? throw new ArgumentNullException(nameof(addManual));
        _darkTitleBar = ThemeApplier.IsDark((preferences ?? new UiPreferences()).Theme);

        InitializeComponent();
        ThemeApplier.Apply(this, preferences ?? new UiPreferences());

        var view = CollectionViewSource.GetDefaultView(_processes);
        view.Filter = MatchesSearch;
        _view = view;
        ProcessList.ItemsSource = _view;

        UpdateCount();
    }

    private bool MatchesSearch(object item)
    {
        var text = SearchBox.Text.Trim();
        if (text.Length == 0)
            return true;

        var row = (ProcessRow)item;
        return row.ProcessName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
               (row.ProcessPath?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void OnSearchTextChanged(object sender, TextChangedEventArgs e)
    {
        _view.Refresh();
        UpdateCount();
    }

    private void OnRefreshClicked(object sender, RoutedEventArgs e)
    {
        // Owner re-enumerates processes on the UI thread; the shared
        // collection updates and this window's view follows automatically.
        _refresh();
        _view.Refresh();
        UpdateCount();
    }

    private void OnAddToManualClicked(object sender, RoutedEventArgs e)
    {
        var checkedRows = _processes.Where(p => p.RouteViaProxy).ToList();
        if (checkedRows.Count == 0)
        {
            CountText.Text = "Nothing to add — tick the PICK box next to a process first.";
            return;
        }

        var addedRows = _addManual(checkedRows);

        // The pending selection is consumed: rules now exist for exactly these
        // rows, so clear their checks. Rows that could not become rules (already
        // present, or unknown path) stay checked so the user sees what failed.
        foreach (var row in addedRows)
            row.RouteViaProxy = false;

        CountText.Text = addedRows.Count > 0
            ? $"Added {addedRows.Count} manual rule(s)."
            : "Nothing added — the checked processes are already rules (or have no known path).";
    }

    private void UpdateCount() =>
        CountText.Text = $"{_view.Cast<object>().Count():N0} running processes";

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);

        // Discard the pending selection: checks stage the Add button only and
        // must never silently become rules (picking alone persists nothing).
        foreach (var row in _processes)
            row.RouteViaProxy = false;
    }

    /// <summary>
    /// Keeps the PATH column stretched to the remaining list width so long
    /// paths trim with an ellipsis instead of forcing a horizontal scrollbar.
    /// </summary>
    private void OnProcessListSizeChanged(object sender, SizeChangedEventArgs e) =>
        GridViewHelper.StretchPathColumn(ProcessList, ProcessPathColumn, 64 + 180 + 70);

    /// <summary>
    /// Clicking a PATH cell copies the full path to the clipboard and pops the
    /// "Copied to clipboard" toast at the bottom of the window.
    /// </summary>
    private void OnCopyPathTextClicked(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (sender is TextBlock { DataContext: ProcessRow row } &&
            !string.IsNullOrWhiteSpace(row.ProcessPath) &&
            row.ProcessPath != "(unknown path)")
        {
            CopyToast.CopyText(this, row.ProcessPath);
        }
        else
        {
            CopyToast.Show(this, "Nothing to copy");
        }
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ThemeApplier.ApplyDarkTitleBar(this, _darkTitleBar);
    }
}
