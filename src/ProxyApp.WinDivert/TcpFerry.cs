using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Core.Rules;
using ProxyApp.Network;

namespace ProxyApp.WinDivert;

/// <summary>
/// The TCP redirection engine (ferry). It captures outbound SYNs from selected
/// processes, injects a crafted SYN-ACK so the client's handshake completes
/// with ~zero added delay, and establishes the SOCKS5 upstream IN PARALLEL —
/// the client's first payload is buffered (bounded) until the upstream is
/// ready, then relayed. Bidirectional data relay uses the E5b/E7-validated
/// packet semantics (S1 ISN, window 0x7210, PSH|ACK data, separate FIN|ACK,
/// inbound injection, Impostor unset).
///
/// The ferry runs on a background task and is controlled by Start/Stop methods.
/// </summary>
internal sealed class TcpFerry : IDisposable
{
    /// <summary>Default server ISN (S1) to present to the client in crafted SYN-ACKs.</summary>
    internal const uint DefaultServerIsn = 0x12345678;

    /// <summary>
    /// Per-packet diagnostic traces (packet hex dumps, per-read lines).
    /// Off by default: at bulk-transfer rates they emit thousands of string
    /// allocations per second through the UI log sink. Opt in for one Start
    /// session with PROXYAPP_TRACE_PACKETS=1.
    /// </summary>
    private static readonly bool VerbosePackets =
        Environment.GetEnvironmentVariable("PROXYAPP_TRACE_PACKETS") == "1";

    /// <summary>
    /// Upper bound for the MSS the ferry advertises in its SYN-ACKs — 1460
    /// (Ethernet MTU 1500 − IP 20 − TCP 20) unless auto-MTU tuning or Game
    /// Mode lowered it (see <see cref="ApplyMssCap"/> and
    /// <see cref="MssTuner.GameModeMss"/>).
    /// </summary>
    internal const ushort MaxAdvertisedMss = 1460;

    /// <summary>
    /// The CURRENT advertised-MSS cap (volatile: the auto-MTU probe may lower
    /// it while flows are being created). Lower bound 536 per RFC 793.
    /// </summary>
    private volatile ushort _advertisedMssCap = MaxAdvertisedMss;

    /// <summary>Game Mode: DSCP EF marking on injected packets.</summary>
    private readonly bool _gameMode;

    /// <summary>
    /// Lowers the advertised-MSS cap (auto-MTU probe result / Game Mode).
    /// Never raises it above <see cref="MaxAdvertisedMss"/>; applies to flows
    /// created afterwards.
    /// </summary>
    internal void ApplyMssCap(ushort mss) =>
        _advertisedMssCap = Math.Clamp(mss, (ushort)536, MaxAdvertisedMss);

    /// <summary>
    /// Game Mode packet tuning (TunnelX port): DSCP EF (Expedited Forwarding)
    /// marking on IPv4 packets we inject toward the client — the ECN bits are
    /// preserved. Must run BEFORE the checksum helper (the IPv4 header
    /// checksum covers the TOS byte).
    /// </summary>
    private void ApplyGameModeDscp(byte[] packet)
    {
        if (!_gameMode || packet.Length < 2)
            return;
        packet[1] = (byte)((packet[1] & 0x03) | 0xB8); // DSCP 46 (EF) << 2
    }

    /// <summary>
    /// How long the downstream pump may see a zero client window before it
    /// proceeds anyway (legacy behavior) instead of waiting forever — a safety
    /// valve against an ACK-tracking desync turning into a permanent stall.
    /// </summary>
    private static readonly TimeSpan WindowStallBypassAfter = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Retained for backward compatibility with the serial-establishment design
    /// (the SYN-ACK was held until the SOCKS5 CONNECT finished, adding that
    /// delay to EVERY new connection). Parallel establishment (SYN-ACK injected
    /// immediately, CONNECT in flight) removes the hold entirely — the constant
    /// is pinned to 0 so a stale caller cannot reintroduce a delay.
    /// </summary>
    internal const int DefaultHoldMs = 0;

    /// <summary>Default idle timeout for proxied flows.</summary>
    internal static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(2);

    private readonly string _captureFilter;
    private readonly TimeSpan _idleTimeout;
    private readonly IConnectionProcessResolver _processResolver;
    private readonly IReadOnlyList<ApplicationRule> _rules;
    private readonly IReadOnlyList<IpDomainRule> _destinationRules;
    private readonly IDestinationResolver? _destinationResolver;
    private readonly ISocks5Client _socks5Client;

    // ── Per-rule proxy selection ──
    // Saved profiles by name (OrdinalIgnoreCase); a rule may pin one of them.
    // Clients are built lazily on first use — one Socks5Client per pinned
    // profile, the active-proxy client (_socks5Client) for everything else.
    private readonly IReadOnlyDictionary<string, ProxyConfiguration> _proxiesByName;
    private readonly ConcurrentDictionary<string, ISocks5Client> _clientsByName =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Action<string>? _trace;
    private readonly Action<string>? _flowClosed; // per-connection summary sink
    private IntPtr _captureHandle = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _captureLoop;
    private readonly FlowTable _flowTable = new();
    private volatile bool _isRunning;

    // ── Health counters (Interlocked; read by the periodic stats ticker) ──
    private long _synsCaptured;
    private long _synAcksInjected;
    private long _rstsInjected;
    private long _windivertErrors;
    private long _connectFailures;

    // ── Throughput/quality counters for the periodic [PERF] report ──
    private long _bytesRelayedUpstream;     // client → SOCKS5 upstream bytes
    private long _bytesRelayedToClient;     // upstream → client injected bytes
    private long _duplicateSegmentsDropped; // retransmits/probes/gaps dropped by the sequencer
    private long _windowStallBypasses;      // downstream window closed > bypass threshold
    private long _flowsExpiredIdle;         // zombie flows removed by the ticker sweep

    /// <summary>Total pure SYNs attributed to a proxied rule.</summary>
    internal long SynsCaptured => Interlocked.Read(ref _synsCaptured);

    /// <summary>Total crafted SYN-ACKs injected.</summary>
    internal long SynAcksInjected => Interlocked.Read(ref _synAcksInjected);

    /// <summary>Total RSTs injected (CONNECT failure / upstream error).</summary>
    internal long RstsInjected => Interlocked.Read(ref _rstsInjected);

    /// <summary>Total WinDivertSend/Recv failures observed.</summary>
    internal long WinDivertErrors => Interlocked.Read(ref _windivertErrors);

    /// <summary>Total SOCKS5 CONNECT failures.</summary>
    internal long ConnectFailures => Interlocked.Read(ref _connectFailures);

    /// <summary>Period between [PERF] report bursts (also drives expiry sweep).</summary>
    internal static readonly TimeSpan HealthInterval = TimeSpan.FromSeconds(10);

    /// <summary>Hard cap for one [PERF] report burst — keeps the log small.</summary>
    internal const int MaxPerfReportBytes = 5 * 1024;

    /// <summary>Emits a diagnostic trace line (defaults to a no-op).</summary>
    private void Trace(string message) => _trace?.Invoke($"[TcpFerry] {message}");

    /// <summary>
    /// Creates a ferry with the given capture filter.
    /// </summary>
    /// <param name="socks5Client">The SOCKS5 client for default (active-proxy) routing.</param>
    /// <param name="processResolver">Optional process resolver (defaults to a pass-through that never attributes).</param>
    /// <param name="rules">Optional application rules (defaults to empty).</param>
    /// <param name="proxies">
    /// Optional saved proxy profiles a rule may pin by name. When a rule's
    /// <see cref="ApplicationRule.ProxyName"/> matches one of these (case-insensitive,
    /// enabled) profiles, its traffic is ferried through THAT profile instead of
    /// the default client. Names that are unknown or disabled fall back to the
    /// default client with a trace (never silent, never dropped).
    /// </param>
    /// <param name="captureFilter">
    /// WinDivert filter string for the network-layer capture handle.
    /// Default: "outbound and ip and tcp and not loopback".
    /// </param>
    /// <param name="destinationRules">
    /// Optional destination-based rules (IP/domain, IPv4 only) evaluated
    /// BEFORE <paramref name="rules"/>: the first enabled rule matching the
    /// SYN's original destination (address, optional port, or a domain the
    /// address resolves to) wins.
    /// </param>
    /// <param name="destinationResolver">
    /// Domain resolver used by <paramref name="destinationRules"/> to match
    /// domain rules (cached by the implementation). Null = domain rules never
    /// match (IP-literal rules still apply).
    /// </param>
    /// <param name="gameMode">
    /// Game Mode packet tuning: advertised MSS clamped to 1360 (TunnelX's
    /// value) and DSCP EF (Expedited Forwarding) marking on packets injected
    /// toward the client.
    /// </param>
    /// <param name="idleTimeout">
    /// Idle timeout for proxied flows (default: 2 minutes).
    /// </param>
    /// <param name="trace">Optional diagnostic trace sink.</param>
    /// <param name="flowClosed">Optional per-connection close summary sink.</param>
    public TcpFerry(
        ISocks5Client socks5Client,
        IConnectionProcessResolver? processResolver = null,
        IReadOnlyList<ApplicationRule>? rules = null,
        IEnumerable<ProxyConfiguration>? proxies = null,
        string? captureFilter = null,
        int holdTimeoutMs = DefaultHoldMs,
        TimeSpan? idleTimeout = null,
        Action<string>? trace = null,
        Action<string>? flowClosed = null,
        IReadOnlyList<IpDomainRule>? destinationRules = null,
        IDestinationResolver? destinationResolver = null,
        bool gameMode = false)
    {
        _socks5Client = socks5Client ?? throw new ArgumentNullException(nameof(socks5Client));
        _processResolver = processResolver ?? new DefaultPassThroughResolver();
        _rules = rules ?? Array.Empty<ApplicationRule>();
        _destinationRules = destinationRules ?? Array.Empty<IpDomainRule>();
        _destinationResolver = destinationResolver;
        _gameMode = gameMode;
        if (gameMode)
            _advertisedMssCap = MssTuner.GameModeMss;
        _proxiesByName = (proxies ?? Array.Empty<ProxyConfiguration>())
            .Where(p => p is not null && !string.IsNullOrWhiteSpace(p.Name))
            .GroupBy(p => p.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        _captureFilter = captureFilter ?? "outbound and ip and tcp and not loopback";
        _idleTimeout = idleTimeout ?? DefaultIdleTimeout;
        _trace = trace;
        _flowClosed = flowClosed;

        // The SYN-ACK is injected IMMEDIATELY on SYN capture; the SOCKS5 CONNECT
        // runs in parallel. The old serial hold (600ms → 100ms) added the full
        // proxy round-trip to EVERY connection's handshake, which a browser
        // opening many concurrent connections paid per connection — the
        // handshake now completes in ~0 added delay regardless of CONNECT time.
        _ = holdTimeoutMs; // retained (dead) parameter for source compatibility
    }

    /// <summary>True when the capture loop is running.</summary>
    public bool IsRunning => _isRunning;

    /// <summary>The flow table, for diagnostic access.</summary>
    public FlowTable Flows => _flowTable;

    /// <summary>
    /// Starts the capture loop. Opens a WinDivert handle with the configured
    /// filter and begins processing packets on a background task.
    /// </summary>
    public void Start()
    {
        if (_isRunning)
            return;

        // Ensure WinDivert.dll can be located (native dependency).
        WinDivertLibrary.EnsureRegistered();

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        _captureHandle = WinDivertNative.WinDivertOpen(
            _captureFilter, WinDivertLayer.Network, 0, 0);

        if (_captureHandle == IntPtr.Zero || _captureHandle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"WinDivertOpen failed: error {err} ({DescribeError(err)})");
        }

        // Tune queue params for the capture loop.
        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueLength, 16384);
        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueTime, 2000);
        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueSize, 33554432);

        _isRunning = true;
        _captureLoop = Task.Run(() => CaptureLoopAsync(ct), ct);
        StartHealthTicker(ct);
    }

    /// <summary>
    /// Periodic health ticker: every <see cref="HealthInterval"/> it emits a
    /// compact [PERF] report (interval throughput, totals, quality counters)
    /// capped at <see cref="MaxPerfReportBytes"/>, then expires zombie flows.
    ///
    /// Design goals: IMPORTANT information only, at a readable cadence — no
    /// per-packet noise (that lives behind PROXYAPP_TRACE_PACKETS) and no
    /// unbounded log growth. Runs off the packet hot path entirely.
    /// </summary>
    private void StartHealthTicker(CancellationToken ct)
    {
        _ = Task.Run(async () =>
        {
            var prevUp = 0L;
            var prevDown = 0L;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(HealthInterval, ct);

                    // ── [PERF] report ──
                    var up = Interlocked.Read(ref _bytesRelayedUpstream);
                    var down = Interlocked.Read(ref _bytesRelayedToClient);
                    var seconds = HealthInterval.TotalSeconds;
                    var downMbps = (down - prevDown) * 8 / seconds / 1_000_000.0;
                    var upMbps = (up - prevUp) * 8 / seconds / 1_000_000.0;
                    prevUp = up;
                    prevDown = down;

                    // Size guard: stop appending once the burst exceeds the cap.
                    var budget = MaxPerfReportBytes;
                    void Emit(string line)
                    {
                        if (budget <= 0) return;
                        budget -= line.Length + 1;
                        Trace(line);
                    }

                    Emit($"[PERF] interval={HealthInterval.TotalSeconds:F0}s " +
                         $"down={downMbps:F1} Mbps up={upMbps:F1} Mbps");
                    Emit($"[PERF] totals down={FormatBytes(down)} up={FormatBytes(up)} | " +
                         $"flows={_flowTable.Count} syns={SynsCaptured} synacks={SynAcksInjected} rsts={RstsInjected}");
                    Emit($"[PERF] quality dup-dropped={Interlocked.Read(ref _duplicateSegmentsDropped)} " +
                         $"stall-bypasses={Interlocked.Read(ref _windowStallBypasses)} " +
                         $"expired-flows={Interlocked.Read(ref _flowsExpiredIdle)} " +
                         $"connect-fails={ConnectFailures} wd-errors={WinDivertErrors}");

                    // ── Expire idle / abandoned flows (bounded leaks). This
                    //    catches: half-open handshakes where the client never
                    //    ACKed the SYN-ACK, flows whose client RST was somehow
                    //    missed, and stuck closes. Active flows keep touching
                    //    LastActivityUtc, so only true zombies expire.
                    foreach (var expired in _flowTable.RemoveExpired(_idleTimeout))
                    {
                        try
                        {
                            Interlocked.Increment(ref _flowsExpiredIdle);
                            Trace($"Expiring idle/stuck flow {expired.Key} " +
                                  $"(status={expired.Status}, last activity {expired.LastActivityUtc:HH:mm:ss})");
                            expired.Status = FlowStatus.Closed;
                            DisposeFlowResources(expired);
                        }
                        catch
                        {
                            // The sweep must never die — a failed dispose of one
                            // zombie flow must not stop the others.
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
        }, ct);
    }

    /// <summary>Formats a byte count for the [PERF] report (KB/MB/GB).</summary>
    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1_073_741_824 => $"{bytes / 1_073_741_824.0:F2} GB",
        >= 1_048_576 => $"{bytes / 1_048_576.0:F1} MB",
        >= 1024 => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes} B"
    };

    /// <summary>
    /// Stops the capture loop, closes the handle, and drains all pending flows.
    /// </summary>
    public async Task StopAsync()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();

        // Close the handle to unblock any pending WinDivertRecv.
        if (_captureHandle != IntPtr.Zero)
        {
            WinDivertNative.WinDivertClose(_captureHandle);
            _captureHandle = IntPtr.Zero;
        }

        if (_captureLoop != null)
        {
            try { await _captureLoop; }
            catch (OperationCanceledException) { }
        }

        // Clean up all flows.
        var orphaned = _flowTable.RemoveAll();
        foreach (var flow in orphaned)
        {
            try { flow.UpstreamStream?.Dispose(); } catch { }
            try { flow.TryClaimPendingUpstream()?.Dispose(); } catch { }
            try { flow.LoopCts?.Cancel(); } catch { }
            try { flow.LoopCts?.Dispose(); } catch { }
        }

        _cts?.Dispose();
        _cts = null;
    }

    /// <summary>
    /// The main capture loop. Reads packets from the WinDivert handle, classifies
    /// them, and dispatches to the appropriate handler WITHOUT blocking on
    /// per-flow I/O:
    ///
    ///   - Packets for an existing flow are ENQUEUED to the flow's processing
    ///     channel and the loop returns immediately — the flow's consumer task
    ///     handles them serially (same-flow ordering preserved), while other
    ///     flows proceed independently. This is essential: a browser opens many
    ///     concurrent connections, and awaiting each flow's upstream write
    ///     inline would serialize all flows through the loop and stall it while
    ///     any flow's network I/O is in flight.
    ///   - New SYNs are dispatched to a background task (the SOCKS5 CONNECT can
    ///     take seconds); duplicate SYNs see the flow already in the table and
    ///     pass through.
    /// </summary>
    private async Task CaptureLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65535];
        var addr = new WinDivertAddress();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(
                        _captureHandle, buffer, (uint)buffer.Length,
                        ref readLen, ref addr))
                {
                    if (ct.IsCancellationRequested || !_isRunning)
                        break;
                    continue;
                }

                if (readLen < 20 || !TcpPacketParser.TryParse(buffer, readLen, out var tuple))
                    continue;

                // Check if this packet belongs to an existing flow.
                var key = FlowTable.KeyFrom(tuple.SrcIp, tuple.SrcPort, tuple.DstIp, tuple.DstPort);
                var existingFlow = _flowTable.Get(key);

                if (existingFlow != null)
                {
                    // Existing flow: enqueue the work (the buffer is copied by
                    // the closure — the loop reuses the same array). The flow's
                    // consumer serializes same-flow packets.
                    var workBuffer = buffer.ToArray();
                    existingFlow.EnqueueProcessing(() =>
                        HandleExistingFlowAsync(existingFlow, workBuffer, readLen, tuple, ct));
                    continue;
                }

                // New connection: only handle pure SYNs.
                if (!tuple.IsPureSyn)
                {
                    // Not a SYN we want to intercept — pass through.
                    WinDivertNative.WinDivertSend(
                        _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
                    continue;
                }

                // ── New SYN: attribute, inject crafted SYN-ACK immediately,
                //    and establish the SOCKS5 upstream in parallel.
                //    Dispatched to a background task so the loop is not blocked
                //    by the SOCKS5 CONNECT (which can take seconds). The flow is
                //    added to the table before the CONNECT, so a retransmitted
                //    SYN sees it and passes through. The continuation observes
                //    exceptions so a handler failure cannot surface as an
                //    unobserved task exception. ──
                var synBuffer = buffer.ToArray();
                _ = Task.Run(() => HandleNewSynAsync(synBuffer, readLen, tuple, addr, ct), ct)
                    .ContinueWith(t =>
                    {
                        if (t.IsFaulted && _isRunning)
                            Debug.WriteLine($"[TcpFerry] SYN handler error: {t.Exception?.GetBaseException().Message}");
                    }, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (_isRunning)
                Debug.WriteLine($"[TcpFerry] Capture loop error: {ex.Message}");
        }
    }

    /// <summary>
    /// Handles a new pure SYN: attribute the owning process, apply rules, and
    /// either ferry (Proxy) or reinject unchanged (Direct / no match).
    ///
    /// For proxied flows the crafted SYN-ACK is injected IMMEDIATELY (before the
    /// upstream is established), so the client's TCP handshake completes with
    /// ~zero added delay; the SOCKS5 CONNECT runs in parallel and the client's
    /// first payload is buffered until it completes (see
    /// <see cref="HandleExistingFlowAsync"/>). On CONNECT failure the client is
    /// reset — the failure path is retained, it just happens after the
    /// handshake instead of before it.
    /// </summary>
    private async Task HandleNewSynAsync(
        byte[] buffer, uint readLen, TcpTuple tuple, WinDivertAddress addr,
        CancellationToken ct)
    {
        var flowKey = FlowTable.KeyFrom(tuple.SrcIp, tuple.SrcPort, tuple.DstIp, tuple.DstPort);

        // ── R1: attribute the owning process at SYN time (validated in E7) ──
        var processInfo = _processResolver.ResolveOwner(
            tuple.SrcIp, tuple.SrcPort, tuple.DstIp, tuple.DstPort);

var processName = processInfo?.ExecutableName;
// Pass the REAL executable path: hardcoding null here silently disabled
// every path-based and FolderPath-bundle rule while the UI kept
// offering them (RuleEngine matches by name OR path).
// Destination rules (IP/Domain tab) are evaluated first — per-destination
// intent overrides an app-wide process pin. A domain rule may await a
// (cached, timeout-bounded) DNS lookup here on its first connection.
var decision = await RuleEngine.DecideAsync(
    _destinationRules, _rules, processName, processInfo?.ExecutablePath,
    tuple.DstIp, tuple.DstPort, _destinationResolver, ct);

        Trace($"SYN src={tuple.SrcIp}:{tuple.SrcPort} dst={tuple.DstIp}:{tuple.DstPort} " +
              $"pid={processInfo?.ProcessId} name={processName ?? "?"} mode={decision.Mode} " +
              $"proxy={(string.IsNullOrWhiteSpace(decision.ProxyName) ? "default" : decision.ProxyName)}");

        if (decision.Mode != ProxyMode.Proxy)
        {
            // Direct, or no matching rule — reinject unchanged.
            Trace($"SYN -> Direct (pass-through)");
            WinDivertNative.WinDivertSend(
                _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
            return;
        }

        // The rule may pin a specific saved proxy profile; everything else
        // (no pin, unknown name, disabled profile) routes through the default
        // (active) proxy — ResolveClient traces any fallback.
        var ruleClient = ResolveClient(decision.ProxyName);

        // Create flow state and add it to the table ATOMICALLY. With the SYN
        // handler dispatched to a background task, two retransmitted SYNs could
        // both pass the Contains check below before either adds the flow — so
        // the TryAdd return value is authoritative: only the winner proceeds to
        // establish an upstream; the loser passes the duplicate SYN through.
        // ── Mirror the client's SYN TCP options (MSS, window scale). Without
        //    these the client fell back to MSS 536 and a 64 KiB unscaled
        //    window, pinning throughput at ~29200 bytes/RTT (the Speedtest
        //    finding). Per RFC 7323 the WS option may only be sent when the
        //    client's SYN carried one; our shift is our own choice. ──
        var synOptions = TcpPacketParser.ParseSynOptions(buffer, readLen, tuple);
        var advertisedMss = synOptions.HasMss
            ? Math.Clamp(synOptions.Mss, (ushort)536, _advertisedMssCap)
            : _advertisedMssCap;

        var flow = new FlowState(
            flowKey, tuple.Seq, DefaultServerIsn, addr)
        {
            ProcessName = processName,
            ProcessId = processInfo?.ProcessId ?? 0,
            Status = FlowStatus.Connecting,
            ClientWindowShift = synOptions.WindowScale,
            AdvertisedMss = advertisedMss,
            ServerWindowShift = synOptions.HasWindowScale
                ? TcpPacketBuilder.FerryWindowScaleShift
                : (byte)0
        };
        if (tuple.Window != 0)
            flow.ClientAdvertisedWindow = tuple.Window;

        if (!_flowTable.TryAdd(flowKey, flow))
        {
            // A concurrent handler already created this flow (duplicate SYN).
            Trace("SYN -> duplicate (flow already being created); pass-through");
            WinDivertNative.WinDivertSend(
                _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
            return;
        }

        Interlocked.Increment(ref _synsCaptured);

        // ── Start the per-flow consumer NOW (not at pump start). The capture
        //    loop enqueues client packets while the flow is still Connecting;
        //    the consumer drains them serially, which the buffering path in
        //    HandleExistingFlowAsync depends on (bounded pending buffer). It
        //    also applies the completed CONNECT in order. ──
        flow.LoopCts = CancellationTokenSource.CreateLinkedTokenSource(_cts?.Token ?? CancellationToken.None);
        StartFlowProcessing(flow, flow.LoopCts.Token);

        // ── Inject the crafted SYN-ACK IMMEDIATELY (E5b/E7 validated semantics).
        //    The client's handshake completes NOW; the upstream is established
        //    in parallel below. The SYN itself is NOT re-injected — the ferry
        //    consumes it, exactly as before. ──
        var stopwatch = Stopwatch.StartNew();
        Trace($"Injecting crafted SYN-ACK seq={DefaultServerIsn} ack={tuple.Seq + 1u}");
        var synAck = TcpPacketBuilder.BuildSynAck(
            tuple.DstIp, tuple.SrcIp, tuple.DstPort, tuple.SrcPort,
            DefaultServerIsn, tuple.Seq, advertisedMss, synOptions.HasWindowScale);

        var synAddr = addr;
        synAddr.LayerEventFlags &= ~(1uL << 17); // Outbound → 0 (inbound), Impostor stays 0
        ApplyGameModeDscp(synAck);
        WinDivertNative.WinDivertHelperCalcChecksums(synAck, (uint)synAck.Length, ref synAddr, 0);

        if (!WinDivertNative.WinDivertSend(
                _captureHandle, synAck, (uint)synAck.Length, IntPtr.Zero, ref synAddr))
        {
            // Injection failed; remove the flow.
            InjectRstToClient(tuple, flow);
            CleanupFlow(flowKey, flow, "synack-inject-failed");
            return;
        }
        Interlocked.Increment(ref _synAcksInjected);
        Trace($"SYN-ACK injected in {stopwatch.ElapsedMilliseconds}ms");

        flow.Touch();
        _flowClosed?.Invoke(
            $"[FLOW] {flowKey} created process={processName ?? "?"} pid={processInfo?.ProcessId ?? 0} " +
            $"dst={tuple.DstIp}:{tuple.DstPort}");

        // ── Establish the SOCKS5 upstream IN PARALLEL. The handshake has
        //    already completed, so the CONNECT time is hidden from the client.
        //    The result is applied via the flow's processing channel (serialized
        //    with packet processing): on success the upstream stream is set, any
        //    buffered client payload is flushed first, and the read pump starts;
        //    on failure the client is reset and the flow removed. ──
        //
        //    The per-flow consumer started above drains the channel serially
        //    even while Connecting — so client payload arriving during the
        //    CONNECT is buffered (bounded) and the completed CONNECT is applied
        //    in order.
        var destination = new Socks5Destination(tuple.DstIp.ToString(), tuple.DstPort);
        Trace($"Establishing SOCKS5 upstream to {tuple.DstIp}:{tuple.DstPort} via proxy (parallel)...");
        var connectStopwatch = Stopwatch.StartNew();
        var upstream = await EstablishUpstreamAsync(destination, ct, ruleClient);
        connectStopwatch.Stop();
        // TotalMilliseconds (F1) — NOT ElapsedMilliseconds, which truncates
        // sub-1ms durations to 0 and hides real CONNECT latency (a 0ms line for
        // a remote proxy is how a half-parsed reply would look; full-precision
        // timing distinguishes 'legitimately fast local proxy' from 'bug').
        Trace($"SOCKS5 CONNECT {destination.Host}:{destination.Port} " +
              $"{(upstream == null ? "FAILED" : "OK")} in {connectStopwatch.Elapsed.TotalMilliseconds:F1}ms " +
              (upstream == null ? string.Empty
               : $"(bnd={upstream.BndAddress}:{upstream.BndPort})"));

        if (upstream == null)
        {
            // CONNECT failed AFTER the SYN-ACK was injected — reset the client
            // so it sees connection-refused rather than a hang, and clean up.
            // The RST+cleanup is enqueued (serialized with packet processing);
            // if the flow was already cleaned up (channel completed), the
            // enqueue fails and the cleanup already happened.
            Interlocked.Increment(ref _connectFailures);
            Trace($"SOCKS5 upstream failed — injecting RST to client.");
            flow.EnqueueProcessing(() =>
            {
                InjectRstToClient(tuple, flow);
                CleanupFlow(flowKey, flow, "connect-failed");
                return Task.CompletedTask;
            });
            return;
        }

        // CONNECT succeeded. Store the connection so the per-flow consumer can
        // claim it; the consumer's establish-action flushes any buffered client
        // payload first, then starts the normal relay. If the flow was already
        // cleaned up (client FIN, stop, timeout), CleanupFlow disposes the
        // stored connection — it is never orphaned.
        if (!flow.TryStorePendingUpstream(upstream))
        {
            // Should not happen (one CONNECT per flow) — dispose defensively.
            upstream.Dispose();
            return;
        }

        // Enqueue the apply action. If the enqueue fails the channel was
        // completed — which only happens in CleanupFlow, and cleanup claims
        // and disposes the pending upstream — so there is nothing more to do.
        if (!flow.EnqueueProcessing(() => ApplyUpstreamEstablishedAsync(flow, tuple, ct)))
        {
            // The flow was cleaned up while the CONNECT was finishing (client
            // RST/FIN, ferry stop, idle-expiry). Depending on interleaving,
            // cleanup may not have been able to claim/dispose the connection
            // (TryClaim returns null until TryStore runs) — so dispose HERE to
            // guarantee no socket is orphaned.
            Trace($"Flow {flow.Key} cleaned up during CONNECT — disposing completed upstream.");
            upstream.Dispose();
        }
    }

    /// <summary>
    /// Applies a completed SOCKS5 CONNECT to the flow: flushes any buffered
    /// client payload, sets the upstream stream, marks the flow Established,
    /// and starts the read pump. Runs on the flow's processing channel so it
    /// is serialized with packet processing.
    /// </summary>
    private async Task ApplyUpstreamEstablishedAsync(
        FlowState flow, TcpTuple tuple, CancellationToken ct)
    {
        var upstream = flow.TryClaimPendingUpstream();
        if (upstream == null)
        {
            // Nothing to claim (cleanup already disposed it) — nothing to do.
            return;
        }

        // The flow may have been cleaned up while the CONNECT was in flight
        // (client FIN, ferry stop, idle expiry). The stream is then disposed —
        // never written through a dead flow.
        if (!_flowTable.Contains(flow.Key))
        {
            Trace($"Flow {flow.Key} cleaned up during CONNECT — disposing upstream.");
            upstream.Dispose();
            return;
        }

        // Flush buffered client payload (arrived before CONNECT completed)
        // before any newly-captured bytes, preserving ordering.
        //
        // The flushed bytes were ALREADY counted toward ClientBytesSent when
        // they were buffered (HandleExistingFlowAsync's buffering path), so
        // this write MUST NOT increment ClientBytesSent again — doing so would
        // double-count and produce the exact symptom the user saw: the same
        // TLS records written upstream twice, a handshake that can never
        // complete, and a browser that gives up. BytesFlushedFromBuffer tracks
        // the flush separately for the exactly-once assertion in the relay.
        var buffered = flow.DrainPendingBuffer();
        if (buffered != null && buffered.Length > 0)
        {
            try
            {
                Trace($"Flushing {buffered.Length} buffered client bytes to upstream for {flow.Key} " +
                      $"(ClientBytesSent already includes them)");
                await upstream.Stream.WriteAsync(buffered, ct);
                flow.BytesFlushedFromBuffer += buffered.Length;
                Interlocked.Add(ref _bytesRelayedUpstream, buffered.Length);
                flow.Touch();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Trace($"Buffered flush failed for {flow.Key}: {ex.Message}");
                InjectRstToClient(tuple, flow);
                CleanupFlow(flow.Key, flow, "flush-failed");
                upstream.Dispose();
                return;
            }
        }

        flow.UpstreamStream = upstream.Stream;
        flow.Status = FlowStatus.Established;
        flow.UpstreamReady = true;
        flow.Touch();

        Trace($"SOCKS5 upstream established for {flow.Key} — flow is ready.");
        StartUpstreamReadPump(flow, tuple);
    }

    /// <summary>
    /// Starts the upstream→client read pump for an established flow. Reads bytes
    /// from the upstream stream and injects crafted inbound packets (Step 3C).
    /// Runs in the background; each flow has its own loop. The per-flow
    /// processing consumer was already started at SYN-capture time (it must
    /// drain packets while the flow is still Connecting), so it is NOT started
    /// here again.
    /// </summary>
    private void StartUpstreamReadPump(FlowState flow, TcpTuple clientSynTuple)
    {
        var ct = flow.LoopCts?.Token ?? CancellationToken.None;
        var task = Task.Run(() => UpstreamReadPumpAsync(flow, clientSynTuple, ct), ct);

        // Safety net for abnormal exits: if the pump ends and the client's FIN
        // never arrives (upstream error, client vanished, or the pump was
        // cancelled before it started), the graceful-close path never runs and
        // the flow would leak. Clean up only when the flow is still Closing and
        // still in the table. During a NORMAL close the client-FIN handler
        // removes the flow first, so this becomes a no-op.
        _ = task.ContinueWith(_ =>
        {
            if (_isRunning &&
                flow.Status == FlowStatus.Closing &&
                _flowTable.Contains(flow.Key))
            {
                Trace($"Pump exited without client FIN — cleaning up {flow.Key}");
                CleanupFlow(flow.Key, flow, "pump-exit-no-fin");
            }
        }, TaskScheduler.Default);
    }

    /// <summary>
    /// Per-flow packet-processing consumer: drains the flow's processing channel
    /// serially, preserving same-flow packet ordering while different flows
    /// proceed independently (the capture loop enqueues and returns immediately).
    /// </summary>
    private static void StartFlowProcessing(FlowState flow, CancellationToken ct)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await foreach (var work in flow.ProcessingReader.ReadAllAsync(ct))
                {
                    await work();
                }
            }
            catch (OperationCanceledException) { }
        }, ct);
    }

    /// <summary>
    /// Reads application bytes from the upstream stream and injects crafted
    /// inbound TCP packets to the client (E6-validated semantics):
    ///   seq = ServerIsn + 1 + ClientBytesRecv
    ///   ack = ClientIsn + 1 + ClientBytesSent
    /// with Outbound=0, captured IfIdx/SubIfIdx, and helper checksums. On
    /// upstream EOF the server's close is delivered as a separate FIN|ACK after
    /// the client has ACKed the final data (never piggybacked on the data).
    /// </summary>
    internal async Task UpstreamReadPumpAsync(
        FlowState flow, TcpTuple clientSynTuple, CancellationToken ct)
    {
        var buffer = new byte[16384];
        var upstreamEof = false;
        var upstreamError = false;
        Trace($"Upstream pump starting for {flow.Key} " +
              $"(ServerIsn={flow.ServerIsn}, ClientIsn={flow.ClientIsn}, " +
              $"ClientBytesSent={flow.ClientBytesSent}, ClientBytesRecv={flow.ClientBytesRecv})");
        try
        {
            while (!ct.IsCancellationRequested && flow.UpstreamStream != null)
            {
                if (VerbosePackets) Trace("Waiting on upstream ReadAsync...");
                var n = await flow.UpstreamStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                if (VerbosePackets) Trace($"Upstream ReadAsync returned {n} bytes");
                if (n <= 0)
                {
                    Trace("Upstream ReadAsync returned EOF");
                    upstreamEof = true;
                    break;
                }

                // Deliver the upstream payload with PSH|ACK (0x18). The server's
                // close is NOT piggybacked on the data (that would set FIN on
                // every segment); it is delivered as a separate FIN|ACK once the
                // client has ACKed the data (see InjectFinAfterAckAsync).
                //
                // Downstream flow control: inject at most what the client's
                // advertised receive window permits. Data injected beyond the
                // window is silently DISCARDED by the client's TCP stack and —
                // since the ferry never retransmits — lost forever, so this is
                // a correctness requirement, not an optimization.
                Trace($"Relay upstream→client {n} bytes (seq={flow.NextServerSeq}, ack={flow.NextClientAck})");
                var sent = 0;
                var stalledMs = 0;
                var bypassWarned = false;
                while (sent < n && !ct.IsCancellationRequested && flow.UpstreamStream != null)
                {
                    var allowed = flow.AllowedUnackedBytesToClient;
                    if (allowed <= 0)
                    {
                        // Window exhausted: wait for the client's ACKs to open
                        // it again. Safety valve — if nothing opens for 5s,
                        // proceed legacy-style rather than hang forever.
                        await Task.Delay(2, ct);
                        stalledMs += 2;
                        if (stalledMs < WindowStallBypassAfter.TotalMilliseconds)
                            continue;
                        if (!bypassWarned)
                        {
                            Trace($"Client window still closed after {WindowStallBypassAfter.TotalSeconds:F0}s " +
                                  $"for {flow.Key} — proceeding beyond window (possible ACK desync)");
                            Interlocked.Increment(ref _windowStallBypasses);
                            bypassWarned = true;
                        }
                        allowed = int.MaxValue;
                    }

                    var take = (int)Math.Min(n - sent, Math.Min(allowed, ushort.MaxValue));
                    var packet = TcpPacketBuilder.BuildDataPacket(
                        clientSynTuple.DstIp, clientSynTuple.SrcIp,
                        clientSynTuple.DstPort, clientSynTuple.SrcPort,
                        flow.NextServerSeq,
                        flow.NextClientAck,
                        buffer.AsSpan(sent, take),
                        flow.ServerAdvertisedWindowField);

                    var addr = flow.SynAddress;
                    addr.LayerEventFlags &= ~(1uL << 17); // Outbound → 0 (inbound), Impostor NOT set
                    ApplyGameModeDscp(packet);
                    WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);

                    if (VerbosePackets)
                    {
                        Trace($"WinDivertSend inbound packet ({packet.Length} bytes, seq={flow.NextServerSeq}, ack={flow.NextClientAck}, flags=0x{packet[20 + 13]:X2})");

                        // ── Diagnostic: dump the complete response packet ──
                        Trace($"RESPONSE_PACKET: IP={clientSynTuple.DstIp}->{clientSynTuple.SrcIp} " +
                              $"len={packet.Length} proto=6 ttl={packet[8]}");
                        Trace($"RESPONSE_PACKET: TCP ports={clientSynTuple.DstPort}->{clientSynTuple.SrcPort} " +
                              $"seq={flow.NextServerSeq} ack={flow.NextClientAck} " +
                              $"flags=0x{packet[20 + 13]:X2} window={(packet[20 + 14] << 8) | packet[20 + 15]} " +
                              $"payload={take}");
                        Trace($"RESPONSE_PACKET: addr Outbound={addr.Outbound} Impostor={addr.Impostor} " +
                              $"IpChecksum={addr.IpChecksumValid} TcpChecksum={addr.TcpChecksumValid} " +
                              $"IfIdx={addr.IfIdx} SubIfIdx={addr.SubIfIdx} " +
                              $"IPv6={addr.IPv6} Loopback={addr.Loopback} Layer=0x{addr.Layer:X2} Event=0x{addr.Event:X2}");
                        var hexLen = Math.Min(packet.Length, 64);
                        var hex = BitConverter.ToString(packet, 0, hexLen).Replace("-", " ");
                        Trace($"RESPONSE_PACKET hex({hexLen}): {hex}");
                    }

                    if (!WinDivertNative.WinDivertSend(
                            _captureHandle, packet, (uint)packet.Length, IntPtr.Zero, ref addr))
                    {
                        Interlocked.Increment(ref _windivertErrors);
                        Trace($"WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
                        // An abnormal pump exit must REACH the client: marking
                        // this as an upstream error makes the finally block
                        // inject a RST instead of leaving the connection to die
                        // silently in the pump-exit safety net.
                        upstreamError = true;
                        return;
                    }

                    flow.ClientBytesRecv += take;
                    Interlocked.Add(ref _bytesRelayedToClient, take);
                    flow.Touch();
                    sent += take;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (flow.Status == FlowStatus.Closed)
            {
                // Expected teardown race: CleanupFlow disposed the upstream
                // stream under our pending read ("The I/O operation has been
                // aborted..."). The client was already notified by whoever
                // cleaned up — keep this OUT of the user-visible error log so
                // real errors are not drowned in shutdown noise.
                Debug.WriteLine($"[TcpFerry] Pump read aborted during teardown of {flow.Key}: {ex.Message}");
            }
            else
            {
                Trace($"Upstream read pump error for {flow.Key}: {ex.Message}");
                upstreamError = true;
            }
        }
        finally
        {
            if (flow.Status == FlowStatus.Established || flow.Status == FlowStatus.Closing)
            {
                flow.Status = FlowStatus.Closing;

                if (upstreamError)
                {
                    // The upstream leg failed mid-relay (e.g. the backend was
                    // killed). The client can never ACK the truncated data, so a
                    // graceful FIN-wait is futile and would hang the client.
                    // Fail the connection with a RST and remove the flow now —
                    // no silent hang, no leaked flow.
                    Trace($"Upstream error — injecting RST to client for {flow.Key}");
                    InjectRstToClient(clientSynTuple, flow);
                    CleanupFlow(flow.Key, flow, "upstream-error");
                }
                else if (upstreamEof)
                {
                    if (ShouldResetOnUpstreamEof(flow.ClientBytesRecv, flow.ClientBytesSent))
                    {
                        // The upstream closed WITHOUT sending a single byte back,
                        // even though the client sent data (e.g. the TLS
                        // ClientHello). The connection failed before any server
                        // data existed — a graceful FIN|ACK would look to the
                        // browser like "server completed TLS and closed", and the
                        // browser would wait (never FIN-ing back) while the flow
                        // sat in Closing and the site hung. RST is the correct
                        // failure signal: the browser sees the connection was
                        // refused and retries immediately (visible in the user's
                        // log as repeated SYNs to the same IP).
                        Trace($"Upstream EOF with 0 bytes received after {flow.ClientBytesSent} sent — " +
                              $"injecting RST to client for {flow.Key} (connection failed, not closed)");
                        InjectRstToClient(clientSynTuple, flow);
                        CleanupFlow(flow.Key, flow, "upstream-eof-zero-bytes");
                    }
                    else
                    {
                        // The upstream leg closed cleanly AFTER delivering data
                        // (recv > 0) or with nothing sent by the client (an idle
                        // server-initiated close). Deliver the server's close to
                        // the client as a SEPARATE FIN|ACK — never piggybacked on
                        // data (that set FIN on every segment and could break the
                        // close on clients that treat data+FIN specially).
                        //
                        // The FIN is only sent once the client has ACKed every
                        // byte we injected; its seq is the next server send-seq
                        // (which consumes the FIN's own sequence number). The
                        // client's FIN, received later, is ACKed by the capture
                        // loop (see HandleExistingFlowAsync). This is a standard
                        // graceful close: client → FIN (observed) → we ACK it →
                        // client exits.
                        //
                        // NOTE: the flow is NOT removed here — the client's FIN
                        // must still reach HandleExistingFlowAsync so it can be
                        // ACKed (the last step of the graceful close). Final
                        // cleanup happens in the client-FIN path; the ContinueWith
                        // in StartUpstreamReadPump is the safety net for abnormal
                        // exits.
                        await InjectFinAfterAckAsync(flow, clientSynTuple, ct);
                    }
                }
                // Neither EOF nor error (e.g. WinDivertSend failed): the flow is
                // left Closing for the ContinueWith safety net to clean up.
            }
        }
    }

    /// <summary>
    /// Injects a separate FIN|ACK to the client once the client has ACKed all
    /// injected data. Polls <see cref="FlowState.ClientAckedUpTo"/> (the client's
    /// ACK sequence from captured packets) against the bytes we have injected.
    /// </summary>
    private async Task InjectFinAfterAckAsync(FlowState flow, TcpTuple tuple, CancellationToken ct)
    {
        var finSeq = (uint)(flow.ServerIsn + 1 + flow.ClientBytesRecv); // FIN consumes this seq
        var deadline = DateTime.UtcNow.AddSeconds(5);

        while (!ct.IsCancellationRequested && flow.Status == FlowStatus.Closing)
        {
            if (SequenceAtLeast(flow.ClientAckedUpTo, finSeq))
                break;
            if (DateTime.UtcNow >= deadline)
            {
                // The client never accepted all injected data within the wait
                // window (slow reader, paused download, stalled window).
                // Returning WITHOUT any terminal packet made the browser hang
                // until its own timeout — the connection died silently when
                // the pump-exit safety net cleaned up. A RST tells it plainly
                // that this connection is over so it can fail fast and retry.
                Trace($"FIN wait timed out (acked={flow.ClientAckedUpTo}, need={finSeq}) — resetting client");
                InjectRstToClient(tuple, flow);
                return;
            }
            await Task.Delay(20, ct);
        }

        if (flow.Status != FlowStatus.Closing || ct.IsCancellationRequested)
            return;

        var fin = TcpPacketBuilder.BuildFin(
            tuple.DstIp, tuple.SrcIp, tuple.DstPort, tuple.SrcPort,
            finSeq, flow.NextClientAck, flow.ServerAdvertisedWindowField);

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound
        ApplyGameModeDscp(fin);
        WinDivertNative.WinDivertHelperCalcChecksums(fin, (uint)fin.Length, ref addr, 0);
        Trace($"Injecting FIN|ACK to client (seq={finSeq}, ack={flow.NextClientAck})");
        if (!WinDivertNative.WinDivertSend(
                _captureHandle, fin, (uint)fin.Length, IntPtr.Zero, ref addr))
        {
            // Observed during development: close-packet injection can fail with
            // error 6 after the client has sent its own FIN. The failure is
            // logged, not swallowed — the client will time out and give up if
            // the FIN never arrives.
            Interlocked.Increment(ref _windivertErrors);
            Trace($"FIN WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
        }
    }


    /// <summary>
    /// Resolves the SOCKS5 client for a rule-pinned proxy name: the pinned
    /// profile's client when the name matches an enabled saved proxy, otherwise
    /// the default (active) client. Unknown/disabled names fall back WITH a
    /// trace — a mis-pinned rule never silently changes routing behavior.
    /// Internal for unit testing without a live WinDivert handle.
    /// </summary>
    internal ISocks5Client ResolveClient(string? proxyName)
    {
        if (string.IsNullOrWhiteSpace(proxyName))
            return _socks5Client;

        if (!_proxiesByName.TryGetValue(proxyName, out var profile))
        {
            Trace($"Rule proxy '{proxyName}' does not match any saved proxy — using the active proxy.");
            return _socks5Client;
        }

        if (!profile.Enabled)
        {
            Trace($"Rule proxy '{proxyName}' is disabled — using the active proxy.");
            return _socks5Client;
        }

        return _clientsByName.GetOrAdd(proxyName, _ => new Socks5Client(profile));
    }

    /// <summary>
    /// Establishes the SOCKS5 upstream connection for the held SYN. Returns the
    /// connection on success, or null when the connection failed or timed out.
    /// Exposed as internal for unit testing without a live WinDivert handle.
    /// </summary>
    /// <param name="destination">The remote destination to reach via the proxy.</param>
    /// <param name="ct">Cancellation for the whole operation.</param>
    /// <param name="client">
    /// The client to dial through; null uses the default (active-proxy) client.
    /// </param>
    internal async Task<Socks5Connection?> EstablishUpstreamAsync(
        Socks5Destination destination, CancellationToken ct, ISocks5Client? client = null)
    {
        var dial = client ?? _socks5Client;
        try
        {
            var conn = await dial.ConnectAsync(destination, ct);
            Trace($"SOCKS5 CONNECT {destination.Host}:{destination.Port} OK " +
                  $"(bnd={conn.BndAddress}:{conn.BndPort})");
            return conn;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Caller cancelled; propagate as a null result for cleanup.
            Trace("SOCKS5 CONNECT cancelled");
            return null;
        }
        catch (Exception ex)
        {
            Trace($"SOCKS5 CONNECT failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Injects a crafted RST to the client, so the client sees a reset rather
    /// than hanging. Uses the E5b injection pattern (inbound, Impostor NOT set,
    /// helper checksums).
    ///
    /// Seq/ack framing: the RST is sent with the server's next send seq and the
    /// client's next expected ack (<see cref="FlowState.NextServerSeq"/> /
    /// <see cref="FlowState.NextClientAck"/>). This is the correct framing for
    /// the ESTABLISHED state — the parallel-establishment design injects the
    /// SYN-ACK first, so a CONNECT-failure RST arrives AFTER the handshake
    /// completed and must be in the client's receive window. (In SYN-SENT the
    /// client accepts any RST seq, so this framing is also fine for the
    /// SYN-ACK-injection-failure path.)
    /// </summary>
    private void InjectRstToClient(TcpTuple tuple, FlowState flow)
    {
        var rst = TcpPacketBuilder.BuildRst(
            tuple.DstIp, tuple.SrcIp, tuple.DstPort, tuple.SrcPort,
            flow.NextServerSeq, flow.NextClientAck);

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound
        ApplyGameModeDscp(rst);
        WinDivertNative.WinDivertHelperCalcChecksums(rst, (uint)rst.Length, ref addr, 0);
        if (WinDivertNative.WinDivertSend(_captureHandle, rst, (uint)rst.Length, IntPtr.Zero, ref addr))
            Interlocked.Increment(ref _rstsInjected);
        else
            Interlocked.Increment(ref _windivertErrors);
    }

    /// <summary>
    /// Removes a flow and disposes its upstream stream (including any CONNECT
    /// that completed but was not yet claimed).
    ///
    /// <see cref="FlowState.Status"/> is set to <see cref="FlowStatus.Closed"/>
    /// FIRST, before the upstream stream is disposed: the upstream read pump's
    /// pending ReadAsync then throws on the disposed stream, and its error
    /// path sees Status == Closed and suppresses the spurious RST. Without
    /// this ordering, a CLEAN close (client FIN → CleanupFlow) racing the
    /// pump's stream-dispose could inject a RST to a client connection that
    /// closed normally — on a browser this kills connections that still had
    /// requests in flight.
    /// </summary>
    private void CleanupFlow(FlowKey key, FlowState flow, string reason = "cleanup")
    {
        if (_flowTable.TryRemove(key, out _))
        {
            // Per-connection diagnostic summary.
            _flowClosed?.Invoke(
                $"[CLOSE] {key} reason={reason} " +
                $"sent={flow.ClientBytesSent} recv={flow.ClientBytesRecv} " +
                $"process={flow.ProcessName ?? "?"} pid={flow.ProcessId}");

            // Mark closed BEFORE disposing so concurrent readers (the upstream
            // pump's finally, HandleExistingFlowAsync) never act on a
            // half-torn-down flow.
            flow.Status = FlowStatus.Closed;
            DisposeFlowResources(flow);
        }
    }

    /// <summary>
    /// Disposes everything a flow owns: the upstream stream, an unclaimed
    /// CONNECT result, the per-flow cancellation source, and the processing
    /// channel. Caller must have removed the flow from the table (or never
    /// added it) and set <see cref="FlowStatus.Closed"/> first.
    /// </summary>
    private static void DisposeFlowResources(FlowState flow)
    {
        try { flow.UpstreamStream?.Dispose(); } catch { }
        try { flow.TryClaimPendingUpstream()?.Dispose(); } catch { }
        try { flow.LoopCts?.Cancel(); } catch { }
        try { flow.LoopCts?.Dispose(); } catch { }
        flow.CompleteProcessing(); // lets the per-flow consumer exit
    }

    /// <summary>
    /// Handles a packet belonging to an established proxied flow (Step 3B):
    /// extracts the client's TCP payload and writes it to the upstream SOCKS5
    /// stream. The original client packet is NOT re-injected — it is consumed by
    /// the ferry. Pure ACKs (no payload) are dropped, but their ACK sequence is
    /// recorded so a pending server FIN can be sent once the client has accepted
    /// all injected data; a client FIN is ACKed so its stack completes the close.
    ///
    /// Parallel-establishment behavior: while the SOCKS5 CONNECT is still in
    /// flight (<see cref="FlowState.UpstreamReady"/> == false) client payload is
    /// buffered in the flow's bounded pending buffer instead of being dropped,
    /// so the client's first request is relayed the moment the upstream is
    /// ready (never re-transmitted).
    /// </summary>
    internal async Task HandleExistingFlowAsync(
        FlowState flow, byte[] buffer, uint readLen, TcpTuple tuple, CancellationToken ct)
    {
        if (flow.Status == FlowStatus.Closed)
        {
            // Already cleaned up — nothing to do.
            return;
        }

        // ── Client RST: the client aborted the connection (page navigation,
        //    tab close, app cancel, socket kill). Tear the flow and upstream
        //    socket down IMMEDIATELY. Previously the RST was swallowed here:
        //    the ferry kept pumping data into a dead tuple (the client's stack
        //    answered with more ignored RSTs) and the flow leaked until STOP.
        //    Nothing is injected back — the client has already reset its side.
        //    Cost on the hot path: one bool check per packet. ──
        if (tuple.IsRst)
        {
            Trace($"Client sent RST — tearing down {flow.Key}");
            CleanupFlow(flow.Key, flow, "client-rst");
            return;
        }

        // Every captured client segment refreshes the advertised receive window
        // the downstream pump must respect (pure ACKs are its main updates).
        if (tuple.Window != 0)
            flow.ClientAdvertisedWindow = tuple.Window;

        // ── Parallel-establishment path: buffer client payload until the
        //    SOCKS5 CONNECT completes. The flow may be Connecting (CONNECT in
        //    flight) or Established (CONNECT done). While Connecting, all
        //    payload is buffered; pure ACK seq is still recorded so the
        //    deferred FIN works; FIN is handled normally (the close proceeds
        //    even if the CONNECT hasn't completed yet). ──
        var payloadLen = TcpPacketParser.GetPayloadLength(buffer, readLen, tuple);
        if (payloadLen <= 0)
        {
            // No payload. If the client sent a FIN, the client is closing:
            // ACK its FIN so its stack completes the close (curl exits only
            // after its FIN is ACKed). A pure ACK/keepalive/window update is
            // dropped — but it still advances our view of what the client has
            // accepted, so record its ACK seq.
            if (tuple.IsFin)
            {
                flow.ClientAckedUpTo = Math.Max(flow.ClientAckedUpTo, tuple.Ack);
                flow.Touch();
                InjectAckToClient(flow, tuple);
                Trace("Client sent FIN — ACKed; flow is closing");
                // The client has closed its side; the connection is done. Remove
                // the flow from the table so it cannot leak (previously every
                // completed connection left a Closing-state flow behind,
                // accumulating indefinitely — caught by the
                // SustainedTraffic_NoPacketLoop elevated test).
                CleanupFlow(flow.Key, flow, "client-fin");
                return;
            }

            // Pure ACK (no payload) — record the client's ACK so a pending
            // server FIN can be sent once the client has accepted all data.
            if (tuple.IsAck)
                flow.ClientAckedUpTo = Math.Max(flow.ClientAckedUpTo, tuple.Ack);

            return;
        }

        // ── Client has payload. If the upstream is not ready yet, buffer it
        //    (bounded, non-blocking). The per-flow consumer guarantees same-flow
        //    ordering, so the CONNECT establish-action will drain the buffer
        //    before capturing any new payload. ──
        if (!flow.UpstreamReady)
        {
            // Dedup applies here too: retransmitted/probe segments that arrive
            // while the CONNECT is in flight must not enter the pending buffer.
            var plan = RelaySequencer.Plan(flow.NextClientAck, tuple.Seq, payloadLen);
            var newLen = payloadLen - plan.SkipBytes;
            if (plan.IsGap || newLen <= 0)
            {
                Interlocked.Increment(ref _duplicateSegmentsDropped);
                Trace($"Buffering path: duplicate/gap segment dropped " +
                      $"({payloadLen} bytes at seq={tuple.Seq}, expected={flow.NextClientAck})");
                flow.Touch();
                InjectAckToClient(flow, tuple);
                return;
            }

            var tcpOffset = (buffer[0] & 0x0F) * 4;
            var payload = buffer.AsSpan(
                tcpOffset + tuple.TcpHeaderLen + plan.SkipBytes, newLen);

            if (flow.TryAppendPendingBuffer(payload))
            {
                // Count the bytes toward ClientBytesSent so the ACK framing is
                // correct — the client's ACK sequence is ClientIsn + 1 + ClientBytesSent.
                // The flushed bytes also count; the client's view of what was sent
                // is monotonic even though the upstream write is deferred.
                flow.ClientBytesSent += newLen;
                flow.Touch();
                Trace($"Buffered {newLen} client bytes (pending={flow.PendingBufferLength})");
                InjectAckToClient(flow, tuple);
            }
            else
            {
                // Buffer overflow — drop the payload; the client will retransmit.
                // The upstream CONNECT will drain the buffer when it completes,
                // and the client's retransmit will then be accepted.
                Trace($"Pending buffer overflow — dropping {payloadLen} bytes (client will retransmit)");
                InjectAckToClient(flow, tuple);
            }
            return;
        }

        // ── Upstream is ready and Established — normal relay path. ──
        if (flow.Status != FlowStatus.Established || flow.UpstreamStream == null)
        {
            // Should not be reachable, but guard against the race where
            // UpstreamReady is set but the flow was cleaned up.
            return;
        }

        var tcpOffset2 = (buffer[0] & 0x0F) * 4;

        // ── Exactly-once sequencing: only bytes at/after NextClientAck are
        //    relayed. Retransmissions, keepalive and persist probes (which
        //    carry already-ACKed data at seq−1) would otherwise be written as
        //    fresh bytes and corrupt the upstream stream (the Speedtest upload
        //    failure). Partial overlaps are sliced to their new tail. ──
        var relayPlan = RelaySequencer.Plan(flow.NextClientAck, tuple.Seq, payloadLen);
        var relayNewLen = payloadLen - relayPlan.SkipBytes;
        if (relayNewLen <= 0)
        {
            Interlocked.Increment(ref _duplicateSegmentsDropped);
            Trace($"Relay: duplicate segment dropped ({payloadLen} bytes at seq={tuple.Seq}, " +
                  $"expected={flow.NextClientAck})");
            flow.Touch();
            InjectAckToClient(flow, tuple);
            return;
        }
        if (relayPlan.IsGap)
        {
            // Should not occur (same-flow packets are serialized; nothing skips
            // data) — drop and re-ACK so the client retransmits the missing
            // range instead of building a hole into the upstream stream.
            Interlocked.Increment(ref _duplicateSegmentsDropped);
            Trace($"Relay: out-of-order segment dropped ({payloadLen} bytes at seq={tuple.Seq}, " +
                  $"expected={flow.NextClientAck}) — awaiting retransmission");
            flow.Touch();
            InjectAckToClient(flow, tuple);
            return;
        }

        var payload2 = buffer.AsMemory(tcpOffset2 + tuple.TcpHeaderLen + relayPlan.SkipBytes, relayNewLen);

        try
        {
            // Exactly-once invariant: every client payload byte is written to
            // the upstream exactly once. ClientBytesSent counts all bytes the
            // client sent (buffered at SYN time + relayed after Established);
            // BytesFlushedFromBuffer counts the subset that was written from
            // the pending buffer. The remaining bytes are written by this
            // relay path. If the same bytes were written twice (e.g. if the
            // flush re-incremented ClientBytesSent), the relay path would
            // write fewer bytes than expected and the client's ACK framing
            // would be corrupt — the exactly-once integration test
            // (TcpFerryDataRelayTests.Relay_ExactlyOnce_ByteLevel) asserts
            // this cannot happen.
            Trace($"Relay client→upstream {relayNewLen} bytes (total sent={flow.ClientBytesSent + relayNewLen})");
            await flow.UpstreamStream.WriteAsync(payload2, ct);
            flow.ClientBytesSent += relayNewLen;
            Interlocked.Add(ref _bytesRelayedUpstream, relayNewLen);
            flow.Touch();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (flow.Status == FlowStatus.Closed)
                return; // lost the cleanup race — never inject into a dead tuple

            // Upstream write failed — the flow is broken; fail the client and clean up.
            Debug.WriteLine($"[TcpFerry] Upstream write failed for {flow.Key}: {ex.Message}");
            InjectRstToClient(tuple, flow);
            CleanupFlow(flow.Key, flow, "upstream-write-failed");
            return;
        }

        // Promptly ACK the client's data so its TCP stack does not retransmit.
        // Without this, the client retransmits its request until the response
        // arrives, inflating ClientBytesSent and delaying/breaking delivery.
        InjectAckToClient(flow, tuple);
    }

    /// <summary>
    /// Injects a pure ACK to the client acknowledging the data received so far.
    /// seq = ServerIsn + 1 + ClientBytesRecv (the server's next send seq — a pure
    /// ACK does not consume sequence space), ack = ClientIsn + 1 + ClientBytesSent.
    /// </summary>
    private void InjectAckToClient(FlowState flow, TcpTuple tuple)
    {
        var ack = TcpPacketBuilder.BuildAck(
            tuple.DstIp, tuple.SrcIp,
            tuple.DstPort, tuple.SrcPort,
            (uint)(flow.ServerIsn + 1 + flow.ClientBytesRecv),
            (uint)(flow.ClientIsn + 1 + flow.ClientBytesSent),
            flow.ServerAdvertisedWindowField);

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound, Impostor NOT set
        ApplyGameModeDscp(ack);
        WinDivertNative.WinDivertHelperCalcChecksums(ack, (uint)ack.Length, ref addr, 0);
        if (!WinDivertNative.WinDivertSend(
                _captureHandle, ack, (uint)ack.Length, IntPtr.Zero, ref addr))
        {
            Interlocked.Increment(ref _windivertErrors);
            Trace($"ACK WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
        }
    }

    /// <summary>
    /// Decides whether an upstream EOF should be delivered to the client as a
    /// RST instead of a graceful FIN|ACK.
    ///
    /// Returns true when the upstream closed WITHOUT sending a single byte
    /// back (recv == 0) even though the client had sent data (sent > 0) — e.g.
    /// the TLS ClientHello went out but the server never responded. In that
    /// case a FIN|ACK misleads the browser into thinking the server completed
    /// a TLS handshake and closed gracefully; the browser waits for a reply
    /// that never comes, the flow sits Closing until the safety-net timeout,
    /// and the site hangs. RST is the correct failure signal: the browser
    /// retries immediately.
    ///
    /// Exposed as internal for unit testing (no WinDivert handle required).
    /// </summary>
    internal static bool ShouldResetOnUpstreamEof(long clientBytesRecv, long clientBytesSent)
        => clientBytesRecv == 0 && clientBytesSent > 0;

    /// <summary>
    /// Wraparound-safe sequence-space comparison (RFC 1982 semantics for a
    /// single window): returns true when <paramref name="a"/> is at or after
    /// <paramref name="b"/>. A plain <c>&gt;=</c> on raw uints breaks when the
    /// 32-bit sequence space wraps on very long-lived bulk transfers.
    /// </summary>
    internal static bool SequenceAtLeast(uint a, uint b)
        => a == b || ((a - b) & 0x80000000u) == 0;

    /// <summary>Maps a WinDivert error code to a human-readable message.</summary>
    private static string DescribeError(int error) => error switch
    {
        2 => "ERROR_FILE_NOT_FOUND — WinDivert64.sys driver not found",
        5 => "ERROR_ACCESS_DENIED — requires Administrator privileges",
        87 => "ERROR_INVALID_PARAMETER — invalid filter syntax",
        1060 => "ERROR_SERVICE_DOES_NOT_EXIST — WinDivert service not installed",
        1275 => "ERROR_INVALID_USER_BUFFER — driver signature enforcement",
        _ => $"unknown error {error}"
    };

    /// <summary>Disposes the ferry, stopping it if running.</summary>
    public void Dispose()
    {
        try
        {
            if (_isRunning)
                StopAsync().GetAwaiter().GetResult();
        }
        catch { }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Default process resolver used when none is supplied: never attributes a
    /// connection, so every SYN is treated as "no match" → Direct (pass through).
    /// This keeps the ferry safe by default until an attribution source is wired.
    /// </summary>
    private sealed class DefaultPassThroughResolver : IConnectionProcessResolver
    {
        public ConnectionProcessInfo? ResolveOwner(
            System.Net.IPAddress localIp, ushort localPort,
            System.Net.IPAddress remoteIp, ushort remotePort)
            => null;
    }
}