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
    /// <summary>
    /// Destination ports the TCP ferry always routes through the active proxy
    /// while the DNS relay is enabled: 53 (plaintext DNS over TCP, the
    /// fallback transport for truncated answers).
    /// </summary>
    private static readonly IReadOnlySet<ushort> DnsRelayTcpPorts = new HashSet<ushort> { 53 };

    /// <summary>
    /// IPv6 twin of the TCP ferry's capture filter, used ONLY for the
    /// DNS-over-TCP leg when the DNS relay is on. A WinDivert filter expression
    /// cannot mix <c>ip</c> and <c>ipv6</c>, so this needs its own handle
    /// (see <c>TcpFerry</c>'s <c>captureFilterV6</c>). Without it, a DNS query
    /// that falls back to TCP over IPv6 transport bypassed the relay entirely
    /// and went straight out — a plaintext DNS leak that no port-53 IPv4 filter
    /// could see.
    /// </summary>
    private const string DnsTcpCaptureFilterV6 =
        "outbound and ipv6 and tcp and tcp.DstPort == 53 and not loopback";

    private readonly object _traceLock = new();
    private Action<string>? _trace;
    private Action<string>? _flowClosed;
    private TcpFerry? _ferry;
    private UdpDnsFerry? _udpDnsFerry;
    private DnsSniInspector? _sniInspector;
    private StunBlocker? _stunBlocker;

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
    /// The most recent encrypted-DNS (DoH) detection message, or null when none
    /// has been seen this session. Reset on every START so a stale detection
    /// from a previous session is never reported as current.
    /// </summary>
    public string? LastEncryptedDnsDetection { get; private set; }

    /// <summary>
    /// Raised whenever the DNS-relay status changes (eager probe at START,
    /// background retries). May fire from background threads.
    /// </summary>
    public event Action<bool, string>? DnsRelayStatusChanged;

    /// <summary>
    /// Raised when the SNI inspector sees a connection to a known encrypted-DNS
    /// resolver (DoH). The message names the process, the destination and the
    /// resolver hostname. May fire from a background thread. This is a
    /// DIAGNOSTIC, not a block — the connection still goes out.
    /// </summary>
    public event Action<string>? DnsEncryptedDnsDetected;

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

        // A detection belongs to the session that saw it.
        LastEncryptedDnsDetection = null;

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
            activeProxyName: settings.SelectedProxyName,
            // DNS-over-TCP leg: when the relay is on, plaintext DNS on port 53
            // is ferried through the active proxy SYSTEM-WIDE, independent of
            // the app rules (see TcpFerry._forcedProxyPorts). Windows falls
            // back to TCP/53 for truncated answers, so without this the UDP
            // leg alone would leave those queries on the direct path.
            forcedProxyPorts: settings.Dns?.Enabled == true ? DnsRelayTcpPorts : null,
            // DNS over TCP+IPv6 leg: the same relay, over IPv6 transport.
            // Opens a second capture handle; a v4-only system simply has no
            // handle (traced, never silent) and behaves exactly as before.
            captureFilterV6: settings.Dns?.Enabled == true ? DnsTcpCaptureFilterV6 : null);

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

        // ── DNS ferry (opt-in) ──
        // Started only after the TCP ferry is up; a failure here must not kill
        // a running TCP session — trace and continue without DNS interception.
        //
        // WHY THE CONDITION IS NOT JUST `Dns.Enabled` (a real reported bug):
        // this gate used to require the DNS relay to be on, which made the
        // "relay STUN" checkbox silently inert whenever the DNS relay was off.
        // STUN relaying is a SEPARATE feature — it needs the UDP ferry and the
        // proxy's UDP ASSOCIATE leg, but it has nothing to do with relaying
        // DNS, and coupling them meant a user who only wanted WebRTC
        // protection got no STUN interception and no indication why. The log
        // showed zero captured datagrams while the setting read "on".
        //
        // Either leg is enough to justify the handle: the ferry's filter is
        // built per-leg, so opening it for STUN alone captures no DNS.
        var dns = settings.Dns;

        // NOTE: BlockWebRtc is deliberately absent. Blocking used to be a leg of
        // this ferry, which coupled a port-matched drop to DNS interception and
        // left the real leak in place. It now has its own content-matched
        // handle (below), so it must not be able to start this one.
        var needsDnsFerry = dns?.Enabled == true || dns?.RelayStun == true;

        _udpDnsFerry = null;
        if (needsDnsFerry)
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

            // ── Pass 1 diagnostic: the encrypted-DNS observer. A SNIFF-mode
            //    handle copies outbound TLS ClientHellos and lets the real
            //    packets continue untouched, so it cannot affect routing. Its
            //    only job is to NAME the encrypted resolver that a leak test
            //    merely reports as an unexplained IP list. Started after the
            //    relay; never fatal (a failure costs visibility, not routing). ──
            try
            {
                var inspector = new DnsSniInspector(
                    settings.Dns,
                    _trace,
                    // A detected resolver is the single most useful line in the
                    // log, so it also goes through the DNS status event to reach
                    // the UI's prominent warning surface.
                    message =>
                    {
                        LastEncryptedDnsDetection = message;
                        DnsEncryptedDnsDetected?.Invoke(message);
                    });
                if (inspector.ShouldRun)
                {
                    inspector.Start();
                    _sniInspector = inspector;
                }
                else
                {
                    inspector.Dispose();
                }
            }
            catch (Exception ex)
            {
                _trace?.Invoke($"[Sni] Encrypted-DNS inspection could not start — routing is unaffected. {ex.Message}");
            }
        }

        // ── WebRTC blocking: its own handle, matched by CONTENT. ──
        // Deliberately NOT a leg of the DNS ferry above. The ferry matched
        // STUN by DESTINATION PORT, and that is a guess: a WebRTC server may
        // listen on any port (the port travels in the STUN server URI), so the
        // leak test's STUN server — which uses a non-standard port — never
        // matched the filter. The setting read "on", nothing was dropped, and
        // the page reported a server-reflexive candidate with the real address.
        // <see cref="StunBlocker"/> matches the RFC 5389 magic cookie instead,
        // so the port is irrelevant.
        //
        // It is a separate handle because the cost profile differs: it must
        // copy broad UDP traffic to inspect it, which is not an acceptable side
        // effect of enabling DNS relaying.
        _stunBlocker = null;
        if (dns?.BlockWebRtc == true)
        {
            try
            {
                var blocker = new StunBlocker(_trace);
                blocker.Start();
                if (blocker.IsRunning)
                    _stunBlocker = blocker;
                else
                    blocker.Dispose(); // could not start; already traced
            }
            catch (Exception ex)
            {
                _trace?.Invoke($"[WebRTC] STUN blocking could not start — " +
                               "WebRTC is NOT protected; routing is unaffected. " + ex.Message);
            }
        }
    }

    /// <inheritdoc />
    public DnsDiagnostics GetDnsDiagnostics()
    {
        var dns = _udpDnsFerry;
        var sni = _sniInspector;
        var blocker = _stunBlocker;
        return new DnsDiagnostics(
            // The relay is only "enabled" when DNS interception is on. A WebRTC-only
            // session (blocking, or STUN relaying with DNS off) runs the same
            // ferry, so IsRunning alone would claim a DNS relay that is not there.
            RelayEnabled: dns is not null && dns.IsRunning && dns.IsDnsRelayEnabled,
            RelayStatus: dns?.RelayStatus ?? "Not started",
            // Every counter defaults to 0 when the relay is off, so the UI can
            // render one shape unconditionally instead of null-checking each.
            QueriesCaptured: dns?.QueriesCaptured ?? 0,
            QueriesRelayed: dns?.QueriesRelayed ?? 0,
            RepliesInjected: dns?.RepliesInjected ?? 0,
            RelayFailures: dns?.RelayFailures ?? 0,
            QueriesDroppedUnparsable: dns?.QueriesDroppedUnparsable ?? 0,
            Ipv6CaptureActive: dns?.IsIpv6CaptureActive ?? false,
            SniInspectionActive: sni is not null && sni.IsRunning,
            // WebRTC state comes from the BLOCKER, not the ferry: "enabled" must
            // mean "a handle is open and matching", otherwise the UI would
            // claim protection the user does not have — exactly how this bug
            // hid. WebRtcBlockingIpv6Active exists because a missing IPv6 handle
            // means STUN escapes via IPv6, which browsers prefer.
            WebRtcBlockingEnabled: blocker is not null && blocker.IsRunning,
            WebRtcBlocked: blocker?.Dropped ?? 0,
            WebRtcBlockingIpv6Active: blocker?.IsIpv6Active ?? false,
            StunRelayEnabled: dns?.IsStunRelayEnabled ?? false,
            StunCaptured: dns?.StunCaptured ?? 0,
            StunRelayed: dns?.StunRelayed ?? 0,
            StunInjected: dns?.StunInjected ?? 0,
            StunFailures: dns?.StunFailures ?? 0,
            TlsConnectionsObserved: sni?.ConnectionsObserved ?? 0,
            EncryptedDnsDetected: sni?.EncryptedDnsHits ?? 0,
            EncryptedDnsHostnamesParsed: sni?.HostnamesParsed ?? 0,
            SniBlindSpots: sni?.NoSniConnections ?? 0);
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
        if (_ferry == null && _udpDnsFerry == null && _sniInspector == null && _stunBlocker == null)
            return;

        var ferry = _ferry;
        var dnsFerry = _udpDnsFerry;
        var sniInspector = _sniInspector;
        var stunBlocker = _stunBlocker;
        _ferry = null;
        _udpDnsFerry = null;
        _sniInspector = null;
        _stunBlocker = null;

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
        if (sniInspector is not null)
        {
            await sniInspector.StopAsync();
            sniInspector.Dispose();
        }
        if (stunBlocker is not null)
        {
            // Closed FIRST consideration is moot, but ordering matters for a
            // different reason: until this handle is closed, every outbound UDP
            // datagram is parked in its queue rather than on the wire.
            await stunBlocker.StopAsync();
            stunBlocker.Dispose();
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
