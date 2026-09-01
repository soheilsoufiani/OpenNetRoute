using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ProxyApp.Core.Configuration;

namespace ProxyApp;

/// <summary>One row of the bundle info popup's executable table.</summary>
public sealed record ExeInfo(int Index, string Name, string FullPath);

/// <summary>
/// Info popup for a single folder bundle, themed exactly like the main app
/// (same resource dictionary + ThemeApplier tokens + native chrome). Binds the
/// SAME <see cref="BundleRow"/> instance rendered as a chip in
/// <see cref="MainWindow"/>, so Enabled / Proxy-Direct edits made here flow
/// through the usual persistence path. "Remove" detaches the bundle from the
/// main window via the <paramref name="removed"/> callback, then closes.
/// </summary>
public partial class BundleInfoWindow : Window
{
    private readonly BundleRow _bundle;
    private readonly Action<BundleRow> _removed;
    private readonly bool _darkTitleBar;

    public BundleInfoWindow(BundleRow bundle, UiPreferences preferences, Action<BundleRow> removed)
    {
        _bundle = bundle ?? throw new ArgumentNullException(nameof(bundle));
        _removed = removed ?? throw new ArgumentNullException(nameof(removed));
        _darkTitleBar = ThemeApplier.IsDark((preferences ?? new UiPreferences()).Theme);

        InitializeComponent();
        ThemeApplier.Apply(this, preferences ?? new UiPreferences());

        DataContext = _bundle;
        Title = $"Folder bundle — {_bundle.DisplayName}";

        ExeList.ItemsSource = _bundle.Exes
            .Select((path, i) => new ExeInfo(i + 1, Path.GetFileName(path), path))
            .ToList();
        CountText.Text =
            $"{_bundle.Exes.Count:N0} executable(s) matched by folder prefix";

        if (_bundle.Exes.Count == 0)
        {
            ExeList.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Visible;
        }
    }

    private void OnCloseClicked(object sender, RoutedEventArgs e) => Close();

    /// <summary>
    /// Keeps the FULL PATH column stretched to the remaining list width so long
    /// paths trim with an ellipsis instead of forcing a horizontal scrollbar.
    /// </summary>
    private void OnExeListSizeChanged(object sender, SizeChangedEventArgs e) =>
        GridViewHelper.StretchPathColumn(ExeList, ExePathColumn, 44 + 220);

    /// <summary>Clicking an executable path row copies it (with a "Copied to clipboard" toast).</summary>
    private void OnCopyPathTextClicked(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (sender is TextBlock { DataContext: ExeInfo exe } &&
            !string.IsNullOrWhiteSpace(exe.FullPath))
        {
            CopyToast.CopyText(this, exe.FullPath);
        }
    }

    /// <summary>Clicking the bundle's folder path copies it (with a "Copied to clipboard" toast).</summary>
    private void OnCopyFolderPathClicked(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (!string.IsNullOrWhiteSpace(_bundle.FolderPath))
            CopyToast.CopyText(this, _bundle.FolderPath);
    }

    private void OnRemoveBundleClicked(object sender, RoutedEventArgs e)
    {
        // Main window removes the bundle from its collection and persists.
        _removed(_bundle);
        Close();
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ThemeApplier.ApplyDarkTitleBar(this, _darkTitleBar);
    }
}
