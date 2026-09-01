using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;

namespace ProxyApp;

/// <summary>
/// Transient bottom-center notification ("Copied to clipboard") matching the
/// app theme. Implemented as an overlay child of the host window's root Grid:
/// it fades in, holds briefly, fades out, and never intercepts mouse input
/// (<c>IsHitTestVisible = false</c>). One toast instance is reused per window.
/// </summary>
public static class CopyToast
{
    private const string OverlayName = "CopyToastOverlay";

    private static readonly TimeSpan HoldDuration = TimeSpan.FromMilliseconds(1400);
    private static readonly TimeSpan FadeInDuration = TimeSpan.FromMilliseconds(120);
    private static readonly TimeSpan FadeOutDuration = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Copies <paramref name="text"/> to the clipboard and shows the toast.
    /// The clipboard can be briefly locked by other processes; that failure is
    /// surfaced as a "Copy failed" toast rather than silently swallowed.
    /// </summary>
    /// <returns>True when the text was placed on the clipboard.</returns>
    public static bool CopyText(Window window, string text, double bottomMargin = 18)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception)
        {
            Show(window, "Copy failed — clipboard is busy", bottomMargin);
            return false;
        }

        Show(window, "Copied to clipboard", bottomMargin);
        return true;
    }

    /// <summary>
    /// Shows the toast at the bottom-center of <paramref name="window"/>.
    /// <paramref name="bottomMargin"/> lifts the toast above window chrome —
    /// the main window's persistent action bar needs more clearance than the
    /// popup windows. <paramref name="warning"/> prefixes the message with the
    /// warning-glyph emoji so caution toasts read differently from success
    /// toasts at a glance.
    /// </summary>
    public static void Show(Window window, string message = "Copied to clipboard", double bottomMargin = 18, bool warning = false)
    {
        if (window?.Content is not Grid root)
            return;

        var toast = root.Children
            .OfType<Border>()
            .FirstOrDefault(b => b.Name == OverlayName);
        if (toast is null)
        {
            toast = BuildToast(window, bottomMargin);
            // Span every row so the toast hugs the bottom of the whole window.
            Grid.SetRowSpan(toast, Math.Max(1, root.RowDefinitions.Count));
            root.Children.Add(toast);
        }
        else
        {
            toast.Margin = new Thickness(0, 0, 0, bottomMargin);
        }

        // Cancel any in-flight hold/fade from a previous show; the new show
        // fully owns the toast from here on.
        if (toast.Tag is CancellationTokenSource previous)
            previous.Cancel();

        UpdateMessage(toast, warning ? "⚠️ " + message : message);

        toast.Opacity = 1;
        toast.Visibility = Visibility.Visible;
        toast.BeginAnimation(
            UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, FadeInDuration) { FillBehavior = FillBehavior.Stop });

        var cts = new CancellationTokenSource();
        toast.Tag = cts;
        _ = HoldThenFadeAsync(toast, cts.Token);
    }

    /// <summary>Holds the toast visible, then fades it out and collapses it.</summary>
    private static async Task HoldThenFadeAsync(Border toast, CancellationToken ct)
    {
        try
        {
            await Task.Delay(HoldDuration, ct).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return; // a newer Show owns the toast now
        }

        var fadeOut = new DoubleAnimation(1, 0, FadeOutDuration);
        fadeOut.Completed += (_, _) =>
        {
            if (!ct.IsCancellationRequested)
                toast.Visibility = Visibility.Collapsed;
        };
        toast.BeginAnimation(UIElement.OpacityProperty, fadeOut);
    }

    private static Border BuildToast(Window window, double bottomMargin)
    {
        var text = new TextBlock
        {
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brush(window, "TextPrimaryBrush", SystemColors.ControlTextBrush)
        };

        return new Border
        {
            Name = OverlayName,
            Child = text,
            Background = Brush(window, "CardBrush", Brushes.White),
            BorderBrush = Brush(window, "BorderSubtleBrush", Brushes.Gray),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(16, 8, 16, 8),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Bottom,
            Margin = new Thickness(0, 0, 0, bottomMargin),
            IsHitTestVisible = false,
            Visibility = Visibility.Collapsed,
            Effect = new DropShadowEffect
            {
                BlurRadius = 16,
                ShadowDepth = 2,
                Direction = 270,
                Opacity = 0.3,
                Color = Colors.Black
            }
        };
    }

    private static void UpdateMessage(Border toast, string message)
    {
        if (toast.Child is not TextBlock text)
            return;

        text.Text = message;
    }

    private static Brush Brush(Window window, string key, Brush fallback) =>
        window.TryFindResource(key) as Brush ?? fallback;
}
