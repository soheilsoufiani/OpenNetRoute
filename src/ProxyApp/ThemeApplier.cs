using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using ProxyApp.Core.Configuration;
using Microsoft.Win32;

namespace ProxyApp;

/// <summary>
/// Applies persisted <see cref="UiPreferences"/> to a window: swaps the
/// themed resource tokens defined in Themes/Modern.xaml
/// (<c>BgWindowBrush</c>, <c>CardBrush</c>, <c>TextPrimaryBrush</c>, …) AND
/// applies the selected UI font (<see cref="FontCatalog"/>) at window scope.
///
/// Scope note (v1): token-based recoloring of surfaces/text/accents — not a
/// full control-template reskin; standard controls inherit readable colors
/// through the implicit style setters keyed off these tokens.
/// </summary>
public static class ThemeApplier
{
    /// <summary>Reads the Windows "Apps use light theme" personalization value.</summary>
    public static bool SystemPrefersLight()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is not 0;
        }
        catch
        {
            return true; // default light on any registry failure
        }
    }

    public static bool IsDark(AppTheme theme) => theme switch
    {
        AppTheme.Dark => true,
        AppTheme.Light => false,
        _ => !SystemPrefersLight()
    };

    /// <summary>Parses "#RGB"/"#RRGGBB" safely, falling back to the given default.</summary>
    public static Color ParseAccent(string? hex, Color fallback)
    {
        if (string.IsNullOrWhiteSpace(hex))
            return fallback;
        try
        {
            return (Color)ColorConverter.ConvertFromString(hex.Trim());
        }
        catch (FormatException)
        {
            return fallback;
        }
    }

    private static SolidColorBrush Solid(byte a, byte r, byte g, byte b) =>
        new(Color.FromArgb(a, r, g, b));

    /// <summary>
    /// Swaps every themed token on the window for the resolved palette and
    /// applies accent to <see cref="Window.Resources"/>["AccentBrush"].
    /// DynamicResource consumers update live.
    /// </summary>
    public static void Apply(Window window, UiPreferences preferences)
    {
        var dark = IsDark(preferences.Theme);

        // Accent is FIXED to the brand blue (#0078D7) — the user-facing accent
        // picker was removed. Persisted AccentColorHex values are ignored.
        var accent = Color.FromRgb(0x00, 0x78, 0xD7);

        var res = window.Resources;
        res["BgWindowBrush"] = dark ? Solid(255, 0x20, 0x20, 0x20)
                                    : Solid(255, 0xFA, 0xFA, 0xFA);
        res["CardBrush"] = dark ? Solid(255, 0x2B, 0x2B, 0x2B)
                                : Solid(255, 0xFF, 0xFF, 0xFF);
        res["BorderSubtleBrush"] = dark ? Solid(255, 0x3D, 0x3D, 0x3D)
                                        : Solid(255, 0xE1, 0xE1, 0xE1);
        res["TextPrimaryBrush"] = dark ? Solid(255, 0xF2, 0xF2, 0xF2)
                                       : Solid(255, 0x1B, 0x1B, 0x1B);
        res["TextSecondaryBrush"] = dark ? Solid(255, 0xA0, 0xA0, 0xA0)
                                         : Solid(255, 0x66, 0x66, 0x66);
        // Neutral hover tint flips direction per palette.
        res["HoverTintBrush"] = dark ? Solid(0x22, 0xFF, 0xFF, 0xFF)
                                     : Solid(0x14, 0x00, 0x00, 0x00);
        // Accent-derived translucent tint used for selected tabs/rows.
        res["TabSelectedBrush"] = Solid(0x26, accent.R, accent.G, accent.B);
        res["TabHoverBrush"] = dark ? Solid(0x33, 0xFF, 0xFF, 0xFF)
                                    : Solid(0x14, 0x00, 0x00, 0x00);
        res["AccentBrush"] = new SolidColorBrush(accent);

        // Input & state tokens (fields, combo popups, start/stop state button).
        // Field background matches the card surface (#2B2B2B) in dark mode.
        res["InputBackgroundBrush"] = dark ? Solid(255, 0x2B, 0x2B, 0x2B)
                                           : Solid(255, 0xFF, 0xFF, 0xFF);
        res["InputBorderBrush"] = dark ? Solid(255, 0x3D, 0x3D, 0x3D)
                                       : Solid(255, 0xD5, 0xD5, 0xE0);
        res["InputTextBrush"] = dark ? Solid(255, 0xE0, 0xE0, 0xE0)
                                     : Solid(255, 0x1B, 0x1B, 0x1B);
        res["InputFocusBrush"] = new SolidColorBrush(accent);
        res["PopupBackgroundBrush"] = dark ? Solid(255, 0x2B, 0x2B, 0x2B)
                                           : Solid(255, 0xFF, 0xFF, 0xFF);
        // Scrollbars (Windows 11 style: thin rounded floating thumb).
        res["ScrollThumbBrush"] = dark ? Solid(255, 0x55, 0x55, 0x5A)
                                       : Solid(255, 0xC2, 0xC2, 0xC6);
        res["ScrollThumbHoverBrush"] = dark ? Solid(255, 0x78, 0x78, 0x80)
                                            : Solid(255, 0x99, 0x99, 0xA1);
        res["SuccessBrush"] = Solid(255, 0x2E, 0x9E, 0x44);
        res["DangerBrush"] = Solid(255, 0xD1, 0x34, 0x38);
        // Amber for "reachable but slow" proxy ping results (same in both palettes).
        res["WarningBrush"] = Solid(255, 0xD9, 0x77, 0x06);

        // Tooltips render in popups outside the window tree, so their palette
        // must be swapped at APPLICATION scope (window-level resources are not
        // visible to them — verified empirically). App.xaml hosts the implicit
        // ToolTip style bound to these keys via DynamicResource.
        var app = Application.Current;
        if (app != null)
        {
            app.Resources["ToolTipBackgroundBrush"] = dark ? Solid(255, 0x2B, 0x2B, 0x2B)
                                                           : Solid(255, 0xFF, 0xFF, 0xFF);
            app.Resources["ToolTipForegroundBrush"] = dark ? Solid(255, 0xF2, 0xF2, 0xF2)
                                                           : Solid(255, 0x1B, 0x1B, 0x1B);
            app.Resources["ToolTipBorderBrush"] = dark ? Solid(255, 0x3D, 0x3D, 0x3D)
                                                       : Solid(255, 0xD5, 0xD5, 0xE0);
        }

        window.Background = (SolidColorBrush)res["BgWindowBrush"];
        window.Foreground = (SolidColorBrush)res["TextPrimaryBrush"];

        // UI font: the persisted choice resolves to an embedded family (with
        // a Segoe UI fallback chain) applied at WINDOW scope — everything in
        // the window's tree inherits it. ThemeApplier is the single
        // application point for both palette and font, so every window that
        // themes itself also picks up the font automatically.
        window.FontFamily = FontCatalog.ResolveFamily(preferences.AppFontKey);

        // Native chrome follows the palette too — but only once the HWND
        // exists (ctor-time calls are too early; OnSourceInitialized re-applies).
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd != IntPtr.Zero)
            ApplyDarkTitleBar(window, dark);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    /// <summary>
    /// Switches the native title bar (window chrome) to dark or light.
    /// Cosmetic only — never throws; falls back to the older Win10 attribute
    /// id when the current one is unsupported.
    /// </summary>
    public static void ApplyDarkTitleBar(Window window, bool dark)
    {
        try
        {
            var hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd == IntPtr.Zero)
                return;
            var enabled = dark ? 1 : 0;
            // 20 = DWMWA_USE_IMMERSIVE_DARK_MODE; 19 = pre-20H1 Win10 builds.
            if (DwmSetWindowAttribute(hwnd, 20, ref enabled, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, 19, ref enabled, sizeof(int));
        }
        catch
        {
            // Ignore — a light title bar on a dark app is cosmetic, not fatal.
        }
    }
}

