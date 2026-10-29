using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace ProxyApp;

/// <summary>
/// The sliding segmented tab strip, ported from a CSS/JS demo the user
/// provided: a dark track hosts equal-width tabs, and a lighter "handle"
/// glides under the newly selected tab on every switch
/// (demo: <c>::after</c> with <c>width: 100% / count</c>,
/// <c>margin-left: active * width</c>, <c>transition: margin-left 300ms</c>,
/// scaled to <c>0.94 × 0.8</c>). The translation is animated instead of the
/// margin because a TranslateTransform is a pure render change — no layout
/// pass, no reflow of the tab content while the handle moves.
///
/// Attached to the <see cref="TabControl"/> that uses the FlatTabs template:
/// <code>
///     &lt;TabControl x:Name="MainTabs" Style="{StaticResource FlatTabs}"
///                  local:TabContentAnimator.Enabled="True"
///                  local:TabSlider.Enabled="True" ... /&gt;
/// </code>
///
/// Contract with the template (Themes/Modern.xaml, FlatTabs): named parts
/// <c>PART_SlideTrack</c>, <c>PART_SlideHandle</c>, <c>PART_SlideHost</c>.
/// TryGetParts leaves the handle untouched when any part is missing, so a
/// TabControl with a different template simply does nothing — no crash, no
/// stray visuals.
///
/// Geometry ownership: the handle's Width and vertical bands (10% top/bottom
/// — the demo's 0.8 vertical scale) and the host's equal Columns are set
/// here; the slot base is the UniformGrid's own width. Horizontal offset is
/// a render TranslateTransform, animated on selection CHANGE (300 ms,
/// ease-out — the closest WPF match to the CSS <c>ease</c> curve of
/// <c>transition: margin-left 300ms</c>) and SNAPPED on geometry changes
/// (load, resize), where animating would betray the user's intent.
///
/// Item-set note: the slot count is re-derived on every sync, so dynamic
/// add/remove of tabs is handled whenever another sync event fires (selection
/// change, resize, load). This app's tab set is fixed, so no separate
/// collection-changed subscription is wired — if tabs ever become dynamic,
/// that is the one place to extend, not the geometry math.
/// </summary>
public static class TabSlider
{
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached(
        "Enabled", typeof(bool), typeof(TabSlider),
        new PropertyMetadata(false, OnEnabledChanged));

    // Per-control runtime state. Registered under an internal key rather than
    // the public Enabled value so Get/SetEnabled stays a clean boolean and
    // dispose/hook bookkeeping has a home.
    private static readonly DependencyProperty StateProperty = DependencyProperty.RegisterAttached(
        "State", typeof(SliderState), typeof(TabSlider),
        new PropertyMetadata(null));

    public static bool GetEnabled(DependencyObject obj) => (bool)obj.GetValue(EnabledProperty);

    public static void SetEnabled(DependencyObject obj, bool value) =>
        obj.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TabControl tabs)
            throw new ArgumentException("TabSlider.Enabled attaches to a TabControl.", nameof(d));

        if (d.GetValue(StateProperty) is SliderState previous)
            previous.Dispose();
        d.SetValue(StateProperty, null);

        if (e.NewValue is not true)
            return;

        var state = new SliderState(tabs);
        d.SetValue(StateProperty, state);
        state.Begin();
    }

    /// <summary>Demo-ported proportions; constants live in one place.</summary>
    private const double HandleWidthFraction = 0.94; // demo: scale(0.94)
    private const double HandleHeightFraction = 0.8; // demo: scale(0.8)
    private const int SlideDurationMs = 300;         // demo: transition 300ms

    private sealed class SliderState
    {
        private readonly TabControl _tabs;
        private readonly List<Action> _unhooks = new();

        private Border? _track;
        private Border? _handle;
        private UniformGrid? _host;
        private bool _partsHooked;

        public SliderState(TabControl tabs) => _tabs = tabs;

        /// <summary>Wires the events; syncs immediately if already visualized.</summary>
        public void Begin()
        {
            // Nested selectors bubble SelectionChanged up to the TabControl;
            // only the strip's own selection should move the handle.
            SelectionChangedEventHandler selection = (s, args) =>
            {
                if (!ReferenceEquals(args.OriginalSource, s))
                    return;
                Sync(animate: true);
            };
            _tabs.SelectionChanged += selection;
            _unhooks.Add(() => _tabs.SelectionChanged -= selection);

            RoutedEventHandler loaded = (s, _) => Sync(animate: false);
            _tabs.Loaded += loaded;
            _unhooks.Add(() => _tabs.Loaded -= loaded);

            if (_tabs.IsLoaded)
                Sync(animate: false);
        }

        public void Dispose()
        {
            foreach (var unhook in _unhooks)
                unhook();
            _unhooks.Clear();
        }

        /// <summary>
        /// Recomputes count/slot/size and places (or animates) the handle.
        /// Quiet no-op until the template parts exist and are measured.
        /// </summary>
        private void Sync(bool animate)
        {
            HookPartsOnce();
            if (!_partsHooked)
                return;

            // Equal slots: the host fills the track's padded area, so its
            // ActualWidth per slot IS the demo's `100% / count`.
            int count = Math.Max(1, _host!.Children.Count > 0 ? _host.Children.Count : _tabs.Items.Count);
            if (_host.Columns != count)
                _host.Columns = count; // one row of `count` equal columns

            double slot = _host.ActualWidth / count;
            if (slot <= 1)
                return; // not measured yet (first layout pass hasn't run)

            int index = Math.Max(0, _tabs.SelectedIndex);
            // 0.03 = (1 - 0.94) / 2: center the 94%-wide pill in its slot.
            double targetX = slot * (index + (1 - HandleWidthFraction) / 2);

            if (Math.Abs(_handle!.Width - slot * HandleWidthFraction) > 0.25)
                _handle.Width = slot * HandleWidthFraction;

            // The 0.8 vertical scale as symmetric 10% bands.
            double band = _host.ActualHeight * (1 - HandleHeightFraction) / 2;
            var bands = new Thickness(0, band, 0, band);
            if (Math.Abs(bands.Top - _handle.Margin.Top) > 0.25)
                _handle.Margin = bands;

            if (_handle.RenderTransform is not TranslateTransform translate)
            {
                translate = new TranslateTransform();
                _handle.RenderTransform = translate;
            }

            if (animate)
            {
                // From whatever value the LAST timeline reached (a quick
                // double-click mid-flight hands over at the current point).
                var slide = new DoubleAnimation(targetX, TimeSpan.FromMilliseconds(SlideDurationMs))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
                };
                translate.BeginAnimation(TranslateTransform.XProperty, slide);
            }
            else
            {
                // Snap: kill any timeline first, then write the value — a
                // pending animation would otherwise override the assignment.
                translate.BeginAnimation(TranslateTransform.XProperty, null);
                translate.X = targetX;
            }
        }

        /// <summary>
        /// Resolves the template parts on first opportunity and hooks the
        /// geometry events (template parts are instantiated once per control,
        /// so a single hook per pair is enough).
        /// </summary>
        private void HookPartsOnce()
        {
            if (_partsHooked)
                return;

            if (_tabs.Template is null)
                return;

            _track = _tabs.Template.FindName("PART_SlideTrack", _tabs) as Border;
            _handle = _tabs.Template.FindName("PART_SlideHandle", _tabs) as Border;
            _host = _tabs.Template.FindName("PART_SlideHost", _tabs) as UniformGrid;
            if (_track is null || _handle is null || _host is null)
                return;

            _partsHooked = true;

            // Size recalibration snaps (animated slides on a resize read as
            // the bar chasing its own content).
            SizeChangedEventHandler onSize = (s, _) => Sync(animate: false);
            _track.SizeChanged += onSize;
            _unhooks.Add(() => _track!.SizeChanged -= onSize);
            _host.SizeChanged += onSize;
            _unhooks.Add(() => _host!.SizeChanged -= onSize);
        }
    }
}
