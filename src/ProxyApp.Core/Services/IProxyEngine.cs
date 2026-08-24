using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Services;

/// <summary>
/// UI-facing contract for the proxy routing engine. The WPF shell drives the
/// ferry exclusively through this interface — it never sees WinDivert, SOCKS5,
/// or packet types (architecture rule: UI communicates with services through
/// interfaces). The implementation lives in ProxyApp.WinDivert.
/// </summary>
public interface IProxyEngine : IDisposable
{
    /// <summary>True while the engine is capturing and routing traffic.</summary>
    bool IsRunning { get; }

    /// <summary>
    /// Starts routing with the given configuration. Validates the settings first;
    /// throws <see cref="ArgumentException"/> when validation fails and
    /// <see cref="InvalidOperationException"/> when already running or when
    /// WinDivert cannot be opened (e.g. the process is not elevated).
    /// </summary>
    void Start(ApplicationSettings settings);

    /// <summary>Stops routing and releases all engine resources. Safe to call when not running.</summary>
    Task StopAsync();

    /// <summary>
    /// Sets the diagnostic trace sink. The sink receives engine events (SYN
    /// captured, SOCKS5 CONNECT timings, relay byte counts, WinDivert errors)
    /// as plain-text lines with a "[TcpFerry]" prefix. The sink may be invoked
    /// from background threads; it MUST be cheap and non-blocking (e.g. append
    /// to a bounded ring buffer) — never do UI work or I/O inline.
    /// </summary>
    void SetTrace(Action<string>? trace);
}
