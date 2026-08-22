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
    private readonly Action<string>? _trace;
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
            // The 600ms default adds that delay to EVERY new connection before
            // the SYN-ACK is injected — a browser opening many concurrent
            // connections pays it per connection, dominating perceived latency.
            // Pin the browser-friendly 100ms value (validated by the elevated
            // E2E tests) explicitly so the app path never regresses to 600ms.
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
