using System.Drawing;
using System.Windows.Forms;

namespace ProxyApp;

/// <summary>
/// The notification-area (tray) icon: left-click opens the main window, the
/// context menu offers Open, Start/Stop routing, live status, and Exit, and
/// the icon shows a green badge while the engine is routing.
///
/// This file is the ONLY place Windows Forms is used (NotifyIcon has no WPF
/// equivalent — see ProxyApp.csproj). It contains no networking logic: menu
/// commands are raised as events and executed by the main window's shared
/// Start/Stop cores. All members must be called on the UI thread; the icon's
/// messages are pumped by the WPF dispatcher's message loop.
/// </summary>
public sealed class TrayIconController : IDisposable
{
    /// <summary>Raised when the user asks to open the main window.</summary>
    public event EventHandler? OpenRequested;

    /// <summary>Raised when the user asks to start routing.</summary>
    public event EventHandler? StartRequested;

    /// <summary>Raised when the user asks to stop routing.</summary>
    public event EventHandler? StopRequested;

    /// <summary>Raised when the user asks to exit the application.</summary>
    public event EventHandler? ExitRequested;

    /// <summary>Hard cap of the native tooltip text (NotifyIcon throws beyond it).</summary>
    private const int MaxTooltipLength = 63;

    private readonly NotifyIcon _notifyIcon;
    private readonly ContextMenuStrip _menu;

    /// <summary>
    /// Hidden message-only window used as the foreground target for the
    /// context menu (see <see cref="ShowContextMenu"/>).
    /// </summary>
    private readonly NativeWindow _messageWindow;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _startStopItem;

    private readonly Icon _baseIcon;
    private readonly bool _ownsBaseIcon;

    private Icon? _composedIcon; // running-badge icon currently displayed
    private IntPtr _composedHandle; // HICON backing it (destroyed explicitly)
    private bool _running;
    private bool _disposed;

    public TrayIconController()
    {
        // Message-only target for foreground activation (tray menu fix below).
        _messageWindow = new NativeWindow();
        _messageWindow.CreateHandle(new CreateParams { Caption = "OpenNetRoute.TrayHost" });

        _statusItem = new ToolStripMenuItem("Status: Stopped") { Enabled = false };
        _startStopItem = new ToolStripMenuItem("Start routing") { Enabled = false };
        _startStopItem.Click += (_, _) =>
        {
            if (_running)
                StopRequested?.Invoke(this, EventArgs.Empty);
            else
                StartRequested?.Invoke(this, EventArgs.Empty);
        };

        var openItem = new ToolStripMenuItem("Open", null,
            (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty));
        var exitItem = new ToolStripMenuItem("Exit", null,
            (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty));

        _menu = new ContextMenuStrip { ShowImageMargin = false, ShowCheckMargin = false };
        _menu.Items.AddRange(
        [
            _statusItem,
            new ToolStripSeparator(),
            openItem,
            _startStopItem,
            new ToolStripSeparator(),
            exitItem
        ]);

        (_baseIcon, _ownsBaseIcon) = LoadApplicationIcon();

        // Right-click is handled manually (ShowContextMenu) instead of
        // NotifyIcon.ContextMenuStrip: a tray menu must be shown while our
        // process is foreground, or the first focus change — e.g. the taskbar
        // overflow panel ("⌃") closing — dismisses it before any item can be
        // clicked.
        _notifyIcon = new NotifyIcon
        {
            Text = "Open NetRoute — Stopped",
            Visible = true,
            Icon = _baseIcon
        };
        _notifyIcon.MouseClick += OnMouseClick;
        _notifyIcon.DoubleClick += (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Reflects engine state: tooltip, status line, running badge, and which
    /// of Start/Stop routing the menu offers. <paramref name="profileName"/>
    /// (the selected profile, null when none) is shown while routing and gates
    /// the Start item — without a profile there is nothing to route through.
    /// </summary>
    public void SetEngineState(bool running, string? profileName)
    {
        _running = running;

        var status = running
            ? string.IsNullOrEmpty(profileName) ? "Routing" : $"Routing via {profileName}"
            : "Stopped";

        _statusItem.Text = $"Status: {status}";
        _startStopItem.Text = running ? "Stop routing" : "Start routing";
        _startStopItem.Enabled = running || !string.IsNullOrEmpty(profileName);

        var tooltip = $"Open NetRoute — {status}";
        _notifyIcon.Text = tooltip.Length <= MaxTooltipLength
            ? tooltip
            : tooltip[..MaxTooltipLength];

        UpdateEngineVisuals();
    }

    /// <summary>Shows a transient balloon (status announcements for a hidden window).</summary>
    public void ShowBalloon(string title, string message)
    {
        if (_disposed)
            return;
        _notifyIcon.BalloonTipTitle = title;
        _notifyIcon.BalloonTipText = message;
        _notifyIcon.ShowBalloonTip(4000);
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        _notifyIcon.Visible = false; // remove the icon from the area immediately
        _notifyIcon.Icon = null;
        _notifyIcon.Dispose();
        _menu.Dispose();

        try
        {
            _messageWindow.DestroyHandle();
        }
        catch
        {
            // Teardown-only: the handle may already be gone; nothing to clean.
        }

        ClearComposedIcon();
        if (_ownsBaseIcon)
            _baseIcon.Dispose();
    }

    private void OnMouseClick(object? sender, MouseEventArgs e)
    {
        switch (e.Button)
        {
            case MouseButtons.Left:
                OpenRequested?.Invoke(this, EventArgs.Empty);
                break;
            case MouseButtons.Right:
                ShowContextMenu();
                break;
        }
    }

    /// <summary>
    /// Shows the context menu at the cursor. Before tracking, this process is
    /// made foreground: a menu opened by a background process is dismissed by
    /// the first focus change (taskbar overflow panel closing, another window
    /// activating) because it never owns the foreground menu chain (Microsoft
    /// KB135788). With the main window hidden this process has no foreground
    /// window, so right-clicking the tray icon would otherwise produce a menu
    /// that dies instantly and never closes on outside clicks.
    /// </summary>
    private void ShowContextMenu()
    {
        if (_disposed || _messageWindow.Handle == IntPtr.Zero)
            return;

        SetForegroundWindow(_messageWindow.Handle);
        _menu.Show(Cursor.Position);
    }

    // ── Icon composition ──

    private void UpdateEngineVisuals()
    {
        if (_running && ComposeRunningBadge(_baseIcon) is { } badge)
        {
            // Swap first so the NotifyIcon never references a disposed icon.
            _notifyIcon.Icon = badge.Icon;
            ClearComposedIcon();
            _composedIcon = badge.Icon;
            _composedHandle = badge.Handle;
            return;
        }

        _notifyIcon.Icon = _baseIcon;
        ClearComposedIcon();
    }

    private void ClearComposedIcon()
    {
        if (_composedIcon is null)
            return;

        if (_composedHandle != IntPtr.Zero)
            DestroyIcon(_composedHandle);
        _composedHandle = IntPtr.Zero;
        _composedIcon.Dispose();
        _composedIcon = null;
    }

    /// <summary>
    /// Draws the application icon with a green bottom-right badge (routing
    /// active). The caller owns the returned icon AND its HICON (Dispose +
    /// <see cref="DestroyIcon"/>). Cosmetic only: on failure the plain
    /// application icon is used.
    /// </summary>
    private static (Icon Icon, IntPtr Handle)? ComposeRunningBadge(Icon baseIcon)
    {
        try
        {
            using var bitmap = new Bitmap(32, 32);
            using (var graphics = Graphics.FromImage(bitmap))
            {
                graphics.DrawIcon(baseIcon, new Rectangle(0, 0, 32, 32));
                using var fill = new SolidBrush(Color.FromArgb(0, 200, 83));
                graphics.FillEllipse(fill, 21, 21, 9, 9);
                using var ring = new Pen(Color.White, 1.6f);
                graphics.DrawEllipse(ring, 21, 21, 9, 9);
            }

            var handle = bitmap.GetHicon();
            return (Icon.FromHandle(handle), handle);
        }
        catch
        {
            return null; // badge is cosmetic — the plain icon is fine
        }
    }

    /// <summary>
    /// The application icon extracted from the running executable, or the
    /// shared system application icon as a fallback (never disposed).
    /// </summary>
    private static (Icon Icon, bool Owned) LoadApplicationIcon()
    {
        try
        {
            var path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path))
            {
                var icon = Icon.ExtractAssociatedIcon(path);
                if (icon is not null)
                    return (icon, true);
            }
        }
        catch
        {
            // Fall through to the shared system icon — the tray still works.
        }

        return (SystemIcons.Application, false);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);
}