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

    /// <summary>
    /// Sets the per-connection summary sink ([FLOW]/[CLOSE] lines: flow key,
    /// process, close reason, bytes each way). Same threading and non-blocking
    /// contract as <see cref="SetTrace"/>.
    /// </summary>
    void SetFlowClosed(Action<string>? flowClosed);

    /// <summary>
    /// The last DNS-relay probe result (Phase 8): "Active" when the proxy
    /// accepted the UDP ASSOCIATE, otherwise a failure message (typically
    /// "the proxy does not support UDP"). Null = never probed (DNS relay
    /// disabled, or the engine has not started yet).
    /// </summary>
    string? LastDnsRelayStatus { get; }

    /// <summary>
    /// Raised whenever the DNS-relay status changes: the eager probe at START
    /// (success or failure) and background retries. May fire from background
    /// threads — the UI must marshal. <c>ok</c> = the relay is usable.
    /// </summary>
    event Action<bool, string>? DnsRelayStatusChanged;
}
