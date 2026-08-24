using ProxyApp.Core.Configuration;
using ProxyApp.Core.Services;
using ProxyApp.Core.Validation;
using ProxyApp.Network;
using ProxyApp.Processes;

namespace ProxyApp.WinDivert;

/// <summary>
/// The production host for the TCP ferry. This is the single public seam the
/// WPF shell drives (via <see cref="IProxyEngine"/>); it wires the real
/// SOCKS5 client, the real <see cref="ProcessTable"/> attribution, and the
/// configured rules into a <see cref="TcpFerry"/>.
///
/// The UI never touches WinDivert, SOCKS5, or packet types directly — all of
/// that stays behind this host (architecture rules 1–3, 6).
/// </summary>
public sealed class ProxyEngine : IProxyEngine, IDisposable
{
    private readonly object _traceLock = new();
    private Action<string>? _trace;
    private TcpFerry? _ferry;

    /// <summary>
    /// Creates the engine host. The ferry itself is only constructed when
    /// <see cref="Start"/> is called.
    /// </summary>
    /// <param name="trace">Optional diagnostic trace sink (e.g. the UI log).</param>
    public ProxyEngine(Action<string>? trace = null)
    {
        _trace = trace;
    }

    /// <summary>
    /// Sets the diagnostic trace sink. The sink receives ferry events
    /// (SYN captured, CONNECT timings, relay byte counts, WinDivert errors).
    /// It may be called from background threads and must not block the
    /// capture path. The new sink applies to the next Start; if the engine is
    /// currently running the sink takes effect on the next restart.
    /// </summary>
    public void SetTrace(Action<string>? trace)
    {
        lock (_traceLock)
        {
            _trace = trace;
        }
    }

    /// <inheritdoc />
    public bool IsRunning => _ferry?.IsRunning ?? false;

    /// <inheritdoc />
    public void Start(ApplicationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(settings.Proxy);

        var validation = ConfigurationValidator.Validate(settings);
        if (!validation.IsValid)
        {
            throw new ArgumentException(
                "Invalid configuration: " + string.Join("; ", validation.Errors),
                nameof(settings));
        }

        if (IsRunning)
        {
            throw new InvalidOperationException("The engine is already running.");
        }

        var ferry = new TcpFerry(
            new Socks5Client(settings.Proxy),
            new ProcessTable(),
            settings.Rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            // DefaultHoldMs is 0: the crafted SYN-ACK is injected immediately on
            // SYN capture and the SOCKS5 CONNECT runs in parallel, so the hold
            // mechanism is gone. The parameter is retained for source
            // compatibility but has no effect.
            holdTimeoutMs: TcpFerry.DefaultHoldMs,
            trace: _trace);

        // Throws InvalidOperationException with the WinDivert error and an
        // actionable message (e.g. "requires Administrator privileges") when
        // the capture handle cannot be opened. Never a silent failure.
        ferry.Start();
        _ferry = ferry;
    }

    /// <inheritdoc />
    public async Task StopAsync()
    {
        if (_ferry == null)
            return;

        var ferry = _ferry;
        _ferry = null;
        await ferry.StopAsync();
        ferry.Dispose();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        try
        {
            StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            // Dispose must not throw during shutdown.
        }
        GC.SuppressFinalize(this);
    }
}
