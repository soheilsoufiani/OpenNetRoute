using System.Windows;
using System.Windows.Controls;

namespace ProxyApp;

/// <summary>
/// Keeps the LAST column of a <see cref="GridView"/> (typically a long PATH
/// column) sized to fill the <see cref="ListView"/> viewport's remaining width,
/// so long paths trim with an ellipsis instead of forcing a horizontal
/// scrollbar — which would push trailing controls (e.g. a row's remove ✕
/// button) out of view. Pair with
/// <c>ScrollViewer.HorizontalScrollBarVisibility="Disabled"</c> on the list.
/// </summary>
public static class GridViewHelper
{
    /// <summary>
    /// Resizes <paramref name="column"/> to
    /// <c>list width − <paramref name="fixedColumnsWidth"/> − reserved</c>,
    /// clamped to a readable minimum. <paramref name="reserved"/> covers the
    /// vertical scrollbar (14 px with the app's scrollbar style) plus a small
    /// layout slack. Call from the list's <c>SizeChanged</c> handler.
    /// </summary>
    public static void StretchPathColumn(
        FrameworkElement list,
        GridViewColumn column,
        double fixedColumnsWidth,
        double reserved = 18,
        double minimumWidth = 140)
    {
        var available = list.ActualWidth - fixedColumnsWidth - reserved;
        if (!double.IsFinite(available) || available <= 0)
            return; // not laid out yet — SizeChanged fires again with a real size

        column.Width = Math.Max(minimumWidth, Math.Floor(available));
    }
}
