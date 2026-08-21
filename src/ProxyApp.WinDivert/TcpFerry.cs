using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Core.Rules;
using ProxyApp.Network;

namespace ProxyApp.WinDivert;

/// <summary>
/// The TCP redirection engine (ferry). This is the initial minimal version that
/// validates the production code paths reproduce the E5b/E7 spike results:
/// capture a SYN → attribute the process → hold → inject a crafted SYN-ACK →
/// observe the client's ACK. SOCKS5 integration and bidirectional data relay
/// are added incrementally in later steps.
///
/// The ferry runs on a background task and is controlled by Start/Stop methods.
/// </summary>
internal sealed class TcpFerry : IDisposable
{
    /// <summary>Default server ISN (S1) to present to the client in crafted SYN-ACKs.</summary>
    internal const uint DefaultServerIsn = 0x12345678;

    /// <summary>Default SYN hold time before injecting the crafted SYN-ACK (milliseconds).</summary>
    internal const int DefaultHoldMs = 600;

    /// <summary>Default idle timeout for proxied flows.</summary>
    internal static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(2);

    private readonly string _captureFilter;
    private readonly int _holdTimeoutMs;
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
    /// Creates a ferry with the given capture filter and hold timeout.
    /// </summary>
    /// <param name="captureFilter">
    /// WinDivert filter string for the network-layer capture handle.
    /// Default: "outbound and ip and tcp and not loopback".
    /// </param>
    /// <param name="holdTimeoutMs">
    /// How long to hold the client SYN before injecting the crafted SYN-ACK
    /// (default: 600ms, validated in E7).
    /// </param>
    /// <param name="idleTimeout">
    /// Idle timeout for proxied flows (default: 2 minutes).
    /// </param>
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
        _holdTimeoutMs = holdTimeoutMs > 0 ? holdTimeoutMs : DefaultHoldMs;
        _idleTimeout = idleTimeout ?? DefaultIdleTimeout;
        _trace = trace;
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
            try { flow.LoopCts?.Cancel(); } catch { }
            try { flow.LoopCts?.Dispose(); } catch { }
        }

        _cts?.Dispose();
        _cts = null;
    }

    /// <summary>
    /// The main capture loop. Reads packets from the WinDivert handle, classifies
    /// them, and dispatches to the appropriate handler.
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
                    await HandleExistingFlowAsync(existingFlow, buffer, readLen, tuple, ct);
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

                // ── New SYN: attribute, hold, and inject crafted SYN-ACK ──
                await HandleNewSynAsync(buffer, readLen, tuple, addr, ct);
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
    /// either hold+ferry (Proxy) or reinject unchanged (Direct / no match).
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

        if (_flowTable.Contains(flowKey))
        {
            // Duplicate SYN; pass through.
            WinDivertNative.WinDivertSend(
                _captureHandle, buffer, readLen, IntPtr.Zero, ref addr);
            return;
        }

        // Create flow state.
        var flow = new FlowState(
            flowKey, tuple.Seq, DefaultServerIsn, addr)
        {
            ProcessName = processName,
            ProcessId = processInfo?.ProcessId ?? 0,
            Status = FlowStatus.Connecting
        };

        _flowTable.TryAdd(flowKey, flow);

        // ── R4: hold the SYN while the upstream is established ──
        // The upstream SOCKS5 connection is established concurrently with the hold
        // so we don't add the hold time on top of the proxy latency.
        var destination = new Socks5Destination(tuple.DstIp.ToString(), tuple.DstPort);
        Trace($"Establishing SOCKS5 upstream to {tuple.DstIp}:{tuple.DstPort} via proxy...");
        var upstream = await EstablishUpstreamAsync(destination, ct);
        if (upstream == null)
        {
            Trace($"SOCKS5 upstream failed — injecting RST.");
            InjectRstToClient(tuple, flow);
            CleanupFlow(flowKey, flow);
            return;
        }
        Trace($"SOCKS5 upstream established.");

        // Hold the SYN for the remainder of the configured hold period.
        await Task.Delay(_holdTimeoutMs, ct);

        // Store the upstream stream in the flow.
        flow.UpstreamStream = upstream.Stream;
        flow.Status = FlowStatus.Established;

        // ── Inject crafted SYN-ACK (E5b/E7 validated semantics) ──
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

        flow.Touch();

        // ── Step 3C: start the upstream→client read pump ──
        StartUpstreamReadPump(flow, tuple);
    }

    /// <summary>
    /// Starts the upstream→client read pump for an established flow. Reads bytes
    /// from the upstream stream and injects crafted inbound packets (Step 3C).
    /// Runs in the background; each flow has its own loop.
    /// </summary>
    private void StartUpstreamReadPump(FlowState flow, TcpTuple clientSynTuple)
    {
        var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(_cts?.Token ?? CancellationToken.None);
        flow.LoopCts = pumpCts;
        var task = Task.Run(() => UpstreamReadPumpAsync(flow, clientSynTuple, pumpCts.Token), pumpCts.Token);

        // If the pump exits, clean up the flow unless we're shutting down.
        _ = task.ContinueWith(_ =>
        {
            if (_isRunning && flow.Status == FlowStatus.Established)
                CleanupFlow(flow.Key, flow);
        }, TaskScheduler.Default);
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
        }
        finally
        {
            if (flow.Status == FlowStatus.Established)
            {
                flow.Status = FlowStatus.Closing;

                // The upstream leg has closed (EOF) or errored. Deliver the
                // server's close to the client as a SEPARATE FIN|ACK — never
                // piggybacked on data (that set FIN on every segment and could
                // break the close on clients that treat data+FIN specially).
                //
                // The FIN is only sent once the client has ACKed every byte we
                // injected; its seq is the next server send-seq (which consumes
                // the FIN's own sequence number). The client's FIN, received
                // later, is ACKed by the capture loop (see
                // HandleExistingFlowAsync). This is a standard graceful close:
                //   client → FIN (observed) → we ACK it → client exits.
                if (upstreamEof)
                {
                    await InjectFinAfterAckAsync(flow, clientSynTuple, ct);
                }
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
    /// Injects a crafted RST to the client for the given SYN, so the client sees
    /// connection-refused rather than hanging. Uses the E5b injection pattern
    /// (inbound, Impostor NOT set, helper checksums).
    /// </summary>
    private void InjectRstToClient(TcpTuple tuple, FlowState flow)
    {
        var rst = TcpPacketBuilder.BuildRst(
            tuple.DstIp, tuple.SrcIp, tuple.DstPort, tuple.SrcPort,
            DefaultServerIsn, tuple.Seq);

        var addr = flow.SynAddress;
        addr.LayerEventFlags &= ~(1uL << 17); // inbound
        WinDivertNative.WinDivertHelperCalcChecksums(rst, (uint)rst.Length, ref addr, 0);
        WinDivertNative.WinDivertSend(_captureHandle, rst, (uint)rst.Length, IntPtr.Zero, ref addr);
    }

    /// <summary>Removes a flow and disposes its upstream stream.</summary>
    private void CleanupFlow(FlowKey key, FlowState flow)
    {
        if (_flowTable.TryRemove(key, out _))
        {
            try { flow.UpstreamStream?.Dispose(); } catch { }
            try { flow.LoopCts?.Cancel(); } catch { }
            try { flow.LoopCts?.Dispose(); } catch { }
            flow.Status = FlowStatus.Closed;
        }
    }

    /// <summary>
    /// Handles a packet belonging to an established proxied flow (Step 3B):
    /// extracts the client's TCP payload and writes it to the upstream SOCKS5
    /// stream. The original client packet is NOT re-injected — it is consumed by
    /// the ferry. Pure ACKs (no payload) are dropped, but their ACK sequence is
    /// recorded so a pending server FIN can be sent once the client has accepted
    /// all injected data; a client FIN is ACKed so its stack completes the close.
    /// </summary>
    internal async Task HandleExistingFlowAsync(
        FlowState flow, byte[] buffer, uint readLen, TcpTuple tuple, CancellationToken ct)
    {
        if (flow.Status != FlowStatus.Established || flow.UpstreamStream == null)
        {
            // Not yet established or already closed — nothing to relay.
            return;
        }

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
                return;
            }

            // Pure ACK (no payload) — record the client's ACK so a pending
            // server FIN can be sent once the client has accepted all data.
            if (tuple.IsAck)
                flow.ClientAckedUpTo = Math.Max(flow.ClientAckedUpTo, tuple.Ack);

            return;
        }

        var tcpOffset = (buffer[0] & 0x0F) * 4;
        var payload = buffer.AsMemory(tcpOffset + tuple.TcpHeaderLen, payloadLen);

        try
        {
            Trace($"Relay client→upstream {payloadLen} bytes (total sent={flow.ClientBytesSent + payloadLen})");
            await flow.UpstreamStream.WriteAsync(payload, ct);
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