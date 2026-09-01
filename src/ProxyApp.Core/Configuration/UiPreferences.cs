namespace ProxyApp.Core.Configuration;

/// <summary>
/// The application visual theme. <see cref="System"/> follows the Windows
/// personalization setting at startup.
/// </summary>
public enum AppTheme
{
    System = 0,
    Light = 1,
    Dark = 2
}

/// <summary>
/// User interface preferences persisted across launches: theme, accent color,
/// and the proxy connection-test preference.
/// </summary>
public sealed class UiPreferences
{
    /// <summary>Light/Dark/System window theme.</summary>
    public AppTheme Theme { get; set; } = AppTheme.System;

    /// <summary>
    /// The accent color as a hex string ("#RRGGBB"). Applied to primary
    /// action buttons and highlights.
    /// </summary>
    public string AccentColorHex { get; set; } = "#0078D7";

    /// <summary>
    /// When true, a SOCKS5 connectivity test runs automatically after a proxy
    /// profile is added or edited (and on demand from the editor's Test button).
    /// </summary>
    public bool TestProxyOnSave { get; set; } = true;

    // ── Window placement ──
    // Nullable: absent keys (legacy documents, first run) mean "use defaults".
    // Values are captured from the main window's NORMAL-state rectangle
    // (RestoreBounds while maximized/minimized), so restoring never loses the
    // size the user chose even across maximized sessions.

    /// <summary>Restored main-window left edge (device-independent units).</summary>
    public double? WindowLeft { get; set; }

    /// <summary>Restored main-window top edge (device-independent units).</summary>
    public double? WindowTop { get; set; }

    /// <summary>Restored main-window width (normal state).</summary>
    public double? WindowWidth { get; set; }

    /// <summary>Restored main-window height (normal state).</summary>
    public double? WindowHeight { get; set; }

    /// <summary>The window was maximized when the app was last closed.</summary>
    public bool WindowMaximized { get; set; }
}
