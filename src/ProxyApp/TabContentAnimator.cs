using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace ProxyApp;

/// <summary>
/// One animated detail for the tabbed workspaces: when the user switches to
/// another tab, the newly selected panel FADES IN and SETTLES from a small
/// downward offset (opacity 0 → 1, translateY 14 → 0, cubic ease-out, ~1/4 s).
/// A tab switch then reads as a pick-up-and-place instead of a hard swap, and
/// the direction-less settle keeps it calm regardless of whether the user
/// moved left or right across the tab strip.
///
/// Used as an attached property on the TabControl itself:
/// <code>
///     &lt;TabControl x:Name="MainTabs" local:TabContentAnimator.Enabled="True" .../&gt;
/// </code>
///
/// WHY CODE, NOT A CONTROLTEMPLATE TRIGGER: the selected content host
/// (<c>ContentSource="SelectedContent"</c> in the FlatTabs template) lives in a
/// different visual subtree than the TabItems, and "which item is newly
/// selected" is not a template-visible property on it — the pill-side tints
/// animate per TabItem, but the panel itself has no triggerable state. The
/// SelectionChanged event is the one reliable hook, so the behavior lives here.
///
/// Depth of the slide is small ON PURPOSE: the panel can be taller than the
/// visual viewport, and a large movement would imply spatial navigation that
/// does not exist (all tabs occupy the same space); a settle, not a slide-in.
/// </summary>
public static class TabContentAnimator
{
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached(
        "Enabled", typeof(bool), typeof(TabContentAnimator),
        new PropertyMetadata(false, OnEnabledChanged));

    public static bool GetEnabled(DependencyObject obj) => (bool)obj.GetValue(EnabledProperty);

    public static void SetEnabled(DependencyObject obj, bool value) =>
        obj.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TabControl tabs)
            throw new ArgumentException("TabContentAnimator.Enabled attaches to a TabControl.", nameof(d));

        var enable = (bool)e.NewValue;
        if (enable == (bool)e.OldValue)
            return;

        if (enable)
            tabs.SelectionChanged += OnSelectionChanged;
        else
            tabs.SelectionChanged -= OnSelectionChanged;
    }

    private static void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Nested selectors bubble SelectionChanged up to the TabControl (a
        // ComboBox or ListView inside a tab content). Ignore anything that is
        // not the attached control's own selection change — only a tab switch
        // should animate the panel.
        if (!ReferenceEquals(e.OriginalSource, sender))
            return;

        if (sender is not TabControl tabs || tabs.SelectedItem is not TabItem { Content: FrameworkElement root })
            return;

        AnimateSwitch(root);
    }

    /// <summary>Runs the fade + settle on the panel's element.</summary>
    private static void AnimateSwitch(FrameworkElement root)
    {
        // Start pose, set explicitly so every run begins from the same frame
        // even when the previous run's held animation is still attached.
        root.Opacity = 0;

        // Own the transform: reuse an existing TranslateTransform, otherwise
        // install one. (No content root in this app carries a render
        // transform, so installing never destroys meaningful state.)
        if (root.RenderTransform is not TranslateTransform transform)
        {
            transform = new TranslateTransform();
            root.RenderTransform = transform;
        }

        transform.Y = SettleDistance;

        // BeginAnimation (not a Storyboard) per animation: each holds its final
        // value while it runs, and a rapid B→C→A selection simply restarts the
        // run on whatever element won — last click always wins.
        var fade = new DoubleAnimation(0, 1, FadeDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        var settle = new DoubleAnimation(SettleDistance, 0, SettleDuration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        root.BeginAnimation(UIElement.OpacityProperty, fade);
        transform.BeginAnimation(TranslateTransform.YProperty, settle);
    }

    private static readonly Duration FadeDuration = new(TimeSpan.FromMilliseconds(220));

    private static readonly Duration SettleDuration = new(TimeSpan.FromMilliseconds(260));

    private const double SettleDistance = 14;
}
