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
    private readonly ISocks5Client _socks5Client;
    private readonly Action<string>? _trace;
    private IntPtr _captureHandle = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _captureLoop;
    private readonly FlowTable _flowTable = new();
    private volatile bool _isRunning;

    /// <summary>Emits a diagnostic trace line (defaults to a no-op).</summary>
    private void Trace(string message) => _trace?.Invoke($"[TcpFerry] {message}");

    /// <summary>
    /// Creates a ferry with the given capture filter.
    /// </summary>
    /// <param name="socks5Client">The SOCKS5 client used for upstream connections.</param>
    /// <param name="processResolver">Optional process resolver (defaults to a pass-through that never attributes).</param>
    /// <param name="rules">Optional application rules (defaults to empty).</param>
    /// <param name="captureFilter">
    /// WinDivert filter string for the network-layer capture handle.
    /// Default: "outbound and ip and tcp and not loopback".
    /// </param>
    /// <param name="idleTimeout">
    /// Idle timeout for proxied flows (default: 2 minutes).
    /// </param>
    /// <param name="trace">Optional diagnostic trace sink.</param>
    public TcpFerry(
        ISocks5Client socks5Client,
        IConnectionProcessResolver? processResolver = null,
        IReadOnlyList<ApplicationRule>? rules = null,
        string? captureFilter = null,
        int holdTimeoutMs = DefaultHoldMs,
        TimeSpan? idleTimeout = null,
        Action<string>? trace = null)
    {
        _socks5Client = socks5Client ?? throw new ArgumentNullException(nameof(socks5Client));
        _processResolver = processResolver ?? new DefaultPassThroughResolver();
        _rules = rules ?? Array.Empty<ApplicationRule>();
        _captureFilter = captureFilter ?? "outbound and ip and tcp and not loopback";
        _idleTimeout = idleTimeout ?? DefaultIdleTimeout;
        _trace = trace;

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
    }

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
        var mode = RuleEngine.Evaluate(_rules, processName, /* processPath */ null);

        Trace($"SYN src={tuple.SrcIp}:{tuple.SrcPort} dst={tuple.DstIp}:{tuple.DstPort} " +
              $"pid={processInfo?.ProcessId} name={processName ?? "?"} mode={mode}");

        if (mode != ProxyMode.Proxy)
        {
            // Direct, or no matching rule — reinject unchanged.
            Trace($"SYN -> Direct (pass-through)");
            WinDivertNative.WinDivertSend(
                _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
            return;
        }

        // Create flow state and add it to the table ATOMICALLY. With the SYN
        // handler dispatched to a background task, two retransmitted SYNs could
        // both pass the Contains check below before either adds the flow — so
        // the TryAdd return value is authoritative: only the winner proceeds to
        // establish an upstream; the loser passes the duplicate SYN through.
        var flow = new FlowState(
            flowKey, tuple.Seq, DefaultServerIsn, addr)
        {
            ProcessName = processName,
            ProcessId = processInfo?.ProcessId ?? 0,
            Status = FlowStatus.Connecting
        };

        if (!_flowTable.TryAdd(flowKey, flow))
        {
            // A concurrent handler already created this flow (duplicate SYN).
            Trace("SYN -> duplicate (flow already being created); pass-through");
            WinDivertNative.WinDivertSend(
                _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
            return;
        }

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
            DefaultServerIsn, tuple.Seq);

        var synAddr = addr;
        synAddr.LayerEventFlags &= ~(1uL << 17); // Outbound → 0 (inbound), Impostor stays 0
        WinDivertNative.WinDivertHelperCalcChecksums(synAck, (uint)synAck.Length, ref synAddr, 0);

        if (!WinDivertNative.WinDivertSend(
                _captureHandle, synAck, (uint)synAck.Length, IntPtr.Zero, ref synAddr))
        {
            // Injection failed; remove the flow.
            InjectRstToClient(tuple, flow);
            CleanupFlow(flowKey, flow);
            return;
        }
        Trace($"SYN-ACK injected in {stopwatch.ElapsedMilliseconds}ms");

        flow.Touch();

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
        var upstream = await EstablishUpstreamAsync(destination, ct);
        connectStopwatch.Stop();
        Trace($"SOCKS5 CONNECT {destination.Host}:{destination.Port} " +
              $"{(upstream == null ? "FAILED" : "OK")} in {connectStopwatch.ElapsedMilliseconds}ms");

        if (upstream == null)
        {
            // CONNECT failed AFTER the SYN-ACK was injected — reset the client
            // so it sees connection-refused rather than a hang, and clean up.
            // The RST+cleanup is enqueued (serialized with packet processing);
            // if the flow was already cleaned up (channel completed), the
            // enqueue fails and the cleanup already happened.
            Trace($"SOCKS5 upstream failed — injecting RST to client.");
            flow.EnqueueProcessing(() =>
            {
                InjectRstToClient(tuple, flow);
                CleanupFlow(flowKey, flow);
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
            Trace($"Flow {flow.Key} cleaned up during CONNECT — upstream already disposed by cleanup.");
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
        var buffered = flow.DrainPendingBuffer();
        if (buffered != null && buffered.Length > 0)
        {
            try
            {
                Trace($"Flushing {buffered.Length} buffered client bytes to upstream for {flow.Key}");
                await upstream.Stream.WriteAsync(buffered, ct);
                flow.Touch();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Trace($"Buffered flush failed for {flow.Key}: {ex.Message}");
                InjectRstToClient(tuple, flow);
                CleanupFlow(flow.Key, flow);
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
                CleanupFlow(flow.Key, flow);
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
                Trace($"Waiting on upstream ReadAsync...");
                var n = await flow.UpstreamStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                Trace($"Upstream ReadAsync returned {n} bytes");
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
                Trace($"Relay upstream→client {n} bytes (seq={flow.NextServerSeq}, ack={flow.NextClientAck})");

                var packet = TcpPacketBuilder.BuildDataPacket(
                    clientSynTuple.DstIp, clientSynTuple.SrcIp,
                    clientSynTuple.DstPort, clientSynTuple.SrcPort,
                    flow.NextServerSeq,
                    flow.NextClientAck,
                    buffer.AsSpan(0, n));

                var addr = flow.SynAddress;
                addr.LayerEventFlags &= ~(1uL << 17); // Outbound → 0 (inbound), Impostor NOT set
                WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);

                Trace($"WinDivertSend inbound packet ({packet.Length} bytes, seq={flow.NextServerSeq}, ack={flow.NextClientAck}, flags=0x{packet[20 + 13]:X2})");

                // ── Diagnostic: dump the complete response packet ──
                Trace($"RESPONSE_PACKET: IP={clientSynTuple.DstIp}->{clientSynTuple.SrcIp} " +
                      $"len={packet.Length} proto=6 ttl={packet[8]}");
                Trace($"RESPONSE_PACKET: TCP ports={clientSynTuple.DstPort}->{clientSynTuple.SrcPort} " +
                      $"seq={flow.NextServerSeq} ack={flow.NextClientAck} " +
                      $"flags=0x{packet[20 + 13]:X2} window={(packet[20 + 14] << 8) | packet[20 + 15]} " +
                      $"payload={n}");
                Trace($"RESPONSE_PACKET: addr Outbound={addr.Outbound} Impostor={addr.Impostor} " +
                      $"IpChecksum={addr.IpChecksumValid} TcpChecksum={addr.TcpChecksumValid} " +
                      $"IfIdx={addr.IfIdx} SubIfIdx={addr.SubIfIdx} " +
                      $"IPv6={addr.IPv6} Loopback={addr.Loopback} Layer=0x{addr.Layer:X2} Event=0x{addr.Event:X2}");
                var hexLen = Math.Min(packet.Length, 64);
                var hex = BitConverter.ToString(packet, 0, hexLen).Replace("-", " ");
                Trace($"RESPONSE_PACKET hex({hexLen}): {hex}");
                if (!WinDivertNative.WinDivertSend(
                        _captureHandle, packet, (uint)packet.Length, IntPtr.Zero, ref addr))
                {
                    Trace($"WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
                    break;
                }

                flow.ClientBytesRecv += n;
                flow.Touch();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Trace($"Upstream read pump error for {flow.Key}: {ex.Message}");
            upstreamError = true;
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
                    CleanupFlow(flow.Key, flow);
                }
                else if (upstreamEof)
                {
                    // The upstream leg closed cleanly. Deliver the server's close
                    // to the client as a SEPARATE FIN|ACK — never piggybacked on
                    // data (that set FIN on every segment and could break the
                    // close on clients that treat data+FIN specially).
                    //
                    // The FIN is only sent once the client has ACKed every byte
                    // we injected; its seq is the next server send-seq (which
                    // consumes the FIN's own sequence number). The client's FIN,
                    // received later, is ACKed by the capture loop (see
                    // HandleExistingFlowAsync). This is a standard graceful
                    // close: client → FIN (observed) → we ACK it → client exits.
                    //
                    // NOTE: the flow is NOT removed here — the client's FIN must
                    // still reach HandleExistingFlowAsync so it can be ACKed (the
                    // last step of the graceful close). Final cleanup happens in
                    // the client-FIN path; the ContinueWith in
                    // StartUpstreamReadPump is the safety net for abnormal exits.
                    await InjectFinAfterAckAsync(flow, clientSynTuple, ct);
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
            if (flow.ClientAckedUpTo >= finSeq)
                break;
            if (DateTime.UtcNow >= deadline)
            {
                Trace($"FIN wait timed out (acked={flow.ClientAckedUpTo}, need={finSeq})");
                return;
            }
            await Task.Delay(20, ct);
        }

        if (flow.Status != FlowStatus.Closing || ct.IsCancellationRequested)
            return;

        var fin = TcpPacketBuilder.BuildFin(
            tuple.DstIp, tuple.SrcIp, tuple.DstPort, tuple.SrcPort,
            finSeq, flow.NextClientAck);

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound
        WinDivertNative.WinDivertHelperCalcChecksums(fin, (uint)fin.Length, ref addr, 0);
        Trace($"Injecting FIN|ACK to client (seq={finSeq}, ack={flow.NextClientAck})");
        if (!WinDivertNative.WinDivertSend(
                _captureHandle, fin, (uint)fin.Length, IntPtr.Zero, ref addr))
        {
            // Observed during development: close-packet injection can fail with
            // error 6 after the client has sent its own FIN. The failure is
            // logged, not swallowed — the client will time out and give up if
            // the FIN never arrives.
            Trace($"FIN WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
        }
    }


    /// <summary>
    /// Establishes the SOCKS5 upstream connection for the held SYN. Returns the
    /// connection on success, or null when the connection failed or timed out.
    /// Exposed as internal for unit testing without a live WinDivert handle.
    /// </summary>
    internal async Task<Socks5Connection?> EstablishUpstreamAsync(
        Socks5Destination destination, CancellationToken ct)
    {
        try
        {
            var conn = await _socks5Client.ConnectAsync(destination, ct);
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
        WinDivertNative.WinDivertHelperCalcChecksums(rst, (uint)rst.Length, ref addr, 0);
        WinDivertNative.WinDivertSend(_captureHandle, rst, (uint)rst.Length, IntPtr.Zero, ref addr);
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
    private void CleanupFlow(FlowKey key, FlowState flow)
    {
        if (_flowTable.TryRemove(key, out _))
        {
            // Mark closed BEFORE disposing so concurrent readers (the upstream
            // pump's finally, HandleExistingFlowAsync) never act on a
            // half-torn-down flow.
            flow.Status = FlowStatus.Closed;
            try { flow.UpstreamStream?.Dispose(); } catch { }
            try { flow.TryClaimPendingUpstream()?.Dispose(); } catch { }
            try { flow.LoopCts?.Cancel(); } catch { }
            try { flow.LoopCts?.Dispose(); } catch { }
            flow.CompleteProcessing(); // lets the per-flow consumer exit
        }
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
                CleanupFlow(flow.Key, flow);
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
            var tcpOffset = (buffer[0] & 0x0F) * 4;
            var payload = buffer.AsSpan(tcpOffset + tuple.TcpHeaderLen, payloadLen);

            if (flow.TryAppendPendingBuffer(payload))
            {
                // Count the bytes toward ClientBytesSent so the ACK framing is
                // correct — the client's ACK sequence is ClientIsn + 1 + ClientBytesSent.
                // The flushed bytes also count; the client's view of what was sent
                // is monotonic even though the upstream write is deferred.
                flow.ClientBytesSent += payloadLen;
                flow.Touch();
                Trace($"Buffered {payloadLen} client bytes (pending={flow.PendingBufferLength})");
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
        var payload2 = buffer.AsMemory(tcpOffset2 + tuple.TcpHeaderLen, payloadLen);

        try
        {
            Trace($"Relay client→upstream {payloadLen} bytes (total sent={flow.ClientBytesSent + payloadLen})");
            await flow.UpstreamStream.WriteAsync(payload2, ct);
            flow.ClientBytesSent += payloadLen;
            flow.Touch();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Upstream write failed — the flow is broken; fail the client and clean up.
            Debug.WriteLine($"[TcpFerry] Upstream write failed for {flow.Key}: {ex.Message}");
            InjectRstToClient(tuple, flow);
            CleanupFlow(flow.Key, flow);
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
            (uint)(flow.ClientIsn + 1 + flow.ClientBytesSent));

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound, Impostor NOT set
        WinDivertNative.WinDivertHelperCalcChecksums(ack, (uint)ack.Length, ref addr, 0);
        if (!WinDivertNative.WinDivertSend(
                _captureHandle, ack, (uint)ack.Length, IntPtr.Zero, ref addr))
        {
            Trace($"ACK WinDivertSend FAILED err={Marshal.GetLastWin32Error()}");
        }
    }

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