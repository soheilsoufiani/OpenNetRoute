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
/// What the main window's close (X) button does while the tray icon is
/// enabled (<see cref="UiPreferences.EnableTrayIcon"/>).
/// </summary>
public enum CloseButtonBehavior
{
    /// <summary>
    /// Close hides the window to the notification area; the engine keeps
    /// routing in the background. The tray icon's Exit menu item exits.
    /// </summary>
    MinimizeToTray = 0,

    /// <summary>Close exits the application (stops the engine).</summary>
    Exit = 1
}

/// <summary>
/// User interface preferences persisted across launches: theme, accent color,
/// the proxy connection-test preference, window placement, and the tray
/// (notification-area) behavior.
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

    /// <summary>
    /// The application-wide UI font: a <see cref="UiFontCatalog.BundledKeys"/>
    /// entry or <see cref="UiFontCatalog.SystemKey"/> for the Windows system
    /// font. Defaults to <see cref="UiFontCatalog.DefaultKey"/> (Geist); values
    /// from older documents or removed families resolve back to the system
    /// font at apply time (<see cref="UiFontCatalog.Normalize"/>) — never a
    /// failure.
    /// </summary>
    public string AppFontKey { get; set; } = UiFontCatalog.DefaultKey;

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

    // ── Tray (notification area) ──

    /// <summary>
    /// Shows the notification-area icon with its control menu
    /// (Open / Start-Stop routing / Exit) and engine status.
    /// </summary>
    public bool EnableTrayIcon { get; set; } = true;

    /// <summary>
    /// The next launch starts minimized to the tray (main window hidden until
    /// the tray icon is used). Requires <see cref="EnableTrayIcon"/>.
    /// </summary>
    public bool StartMinimizedToTray { get; set; }

    /// <summary>
    /// The minimize button hides the window to the tray instead of leaving it
    /// on the taskbar. Requires <see cref="EnableTrayIcon"/>.
    /// </summary>
    public bool MinimizeToTrayInsteadOfTaskbar { get; set; } = true;

    /// <summary>What the close (X) button does while the tray icon is shown.</summary>
    public CloseButtonBehavior CloseButton { get; set; } = CloseButtonBehavior.MinimizeToTray;
}
