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
    private Action<string>? _flowClosed;
    private TcpFerry? _ferry;
    private UdpDnsFerry? _udpDnsFerry;

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

    /// <summary>
    /// Sets the per-connection close-summary sink ([FLOW]/[CLOSE] lines). Same
    /// threading and non-blocking contract as <see cref="SetTrace"/>.
    /// </summary>
    public void SetFlowClosed(Action<string>? flowClosed)
    {
        lock (_traceLock)
        {
            _flowClosed = flowClosed;
        }
    }

    /// <summary>The last DNS-relay probe result ("Active" or a failure message); null = never probed.</summary>
    public string? LastDnsRelayStatus { get; private set; }

    /// <summary>
    /// Raised whenever the DNS-relay status changes (eager probe at START,
    /// background retries). May fire from background threads.
    /// </summary>
    public event Action<bool, string>? DnsRelayStatusChanged;

    /// <inheritdoc />
    public bool IsRunning => _ferry?.IsRunning ?? _udpDnsFerry?.IsRunning ?? false;

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

        var optimization = settings.Optimization ?? new OptimizationSettings();
        var ferry = new TcpFerry(
            new Socks5Client(settings.Proxy),
            // CachedProcessTable: a browser opens 30+ concurrent connections in
            // a burst; the uncached ProcessTable walks the ENTIRE OS connection
            // table per SYN (~3ms each), serializing the SYN handlers. The
            // cached resolver reuses one snapshot per 50ms window.
            new CachedProcessTable(),
            settings.Rules,
            // Saved profiles: rules may pin one by name, routing their traffic
            // through that profile's SOCKS5 client instead of the active one.
            proxies: settings.Proxies,
            captureFilter: "outbound and ip and tcp and not loopback",
            // DefaultHoldMs is 0: the crafted SYN-ACK is injected immediately on
            // SYN capture and the SOCKS5 CONNECT runs in parallel, so the hold
            // mechanism is gone. The parameter is retained for source
            // compatibility but has no effect.
            holdTimeoutMs: TcpFerry.DefaultHoldMs,
            trace: _trace,
            flowClosed: _flowClosed,
            // Destination rules (IP/Domain tab): evaluated first, matching the
            // SYN's original destination. The resolver caches per session and
            // is dropped on Stop.
            destinationRules: settings.IpDomainRules,
            destinationResolver: new DnsDestinationResolver(),
            // Game Mode: DSCP EF on injected packets + advertised MSS 1360.
            gameMode: optimization.GameMode,
            // Per-configuration usage accounting: active-proxy flows bucket
            // under the active profile's name (Data Usage tab).
            activeProxyName: settings.SelectedProxyName);

        // Throws InvalidOperationException with the WinDivert error and an
        // actionable message (e.g. "requires Administrator privileges") when
        // the capture handle cannot be opened. Never a silent failure.
        ferry.Start();
        _ferry = ferry;

        // ── Automatic MTU: probe the path in the background and lower the
        //    ferry's advertised-MSS cap to what survives (never raises it;
        //    Game Mode's 1360 clamp already applies inside the ferry). ──
        if (optimization.AutoMtu)
        {
            var probeHost = settings.Proxy.Host;
            _ = Task.Run(async () =>
            {
                try
                {
                    var mss = await MssTuner.TuneAsync(probeHost).ConfigureAwait(false);
                    ferry.ApplyMssCap(mss);
                    _trace?.Invoke($"[MTU] Auto-tuned advertised MSS={mss} (probe host={probeHost}).");
                }
                catch (Exception ex)
                {
                    _trace?.Invoke($"[MTU] Auto-tune failed (using the default MSS): {ex.Message}");
                }
            });
        }
        else
        {
            _trace?.Invoke("[MTU] Auto-tune disabled; using the default MSS cap.");
        }

        // Throws InvalidOperationException with the WinDivert error and an
        // actionable message (e.g. "requires Administrator privileges") when
        // the capture handle cannot be opened. Never a silent failure.
        ferry.Start();
        _ferry = ferry;

        // ── Phase 8: DNS ferry (opt-in) ──
        // When enabled, DNS queries of proxy-selected processes are relayed
        // through the active proxy's UDP ASSOCIATE leg (see docs/DNS-DESIGN.md
        // — the mechanics are the proven E8-a/E8-b spike results). Started
        // only after the TCP ferry is up; a failure here must not kill a
        // running TCP session — trace and continue without DNS interception.
        _udpDnsFerry = null;
        if (settings.Dns?.Enabled == true)
        {
            try
            {
                var dnsFerry = new UdpDnsFerry(
                    settings.Dns,
                    () => new Socks5UdpAssociateClient(settings.Proxy, trace: _trace),
                    _trace,
                    // Eager ASSOCIATE probe result → the UI status surface.
                    (ok, message) =>
                    {
                        LastDnsRelayStatus = ok ? "Active" : message;
                        _trace?.Invoke($"[UdpDns] {message}");
                        DnsRelayStatusChanged?.Invoke(ok, message);
                    },
                    gameMode: optimization.GameMode);
                dnsFerry.Start();
                _udpDnsFerry = dnsFerry;
            }
            catch (Exception ex)
            {
                _trace?.Invoke($"[UdpDns] DNS interception could not start — running without it. {ex.Message}");
            }
        }
    }

    /// <inheritdoc />
    public UsageSnapshot GetUsageSnapshot()
    {
        var ferry = _ferry;
        return ferry is not null && ferry.IsRunning
            ? ferry.GetUsageSnapshot()
            : UsageSnapshot.Empty;
    }

    /// <inheritdoc />
    public async Task StopAsync()
    {
        if (_ferry == null && _udpDnsFerry == null)
            return;

        var ferry = _ferry;
        var dnsFerry = _udpDnsFerry;
        _ferry = null;
        _udpDnsFerry = null;

        if (ferry is not null)
        {
            await ferry.StopAsync();
            ferry.Dispose();
        }
        if (dnsFerry is not null)
        {
            await dnsFerry.StopAsync();
            dnsFerry.Dispose();
        }
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
