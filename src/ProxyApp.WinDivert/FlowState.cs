using System.Net;
using System.Threading.Channels;
using ProxyApp.Network;

namespace ProxyApp.WinDivert;

/// <summary>
/// The state of a proxied TCP connection. Created when a new SYN is captured and
/// the owning process is selected for proxy routing. Updated through the
/// connection lifecycle.
///
/// IMPORTANT: the upstream leg is a byte stream (via SOCKS5). The upstream
/// kernel's ISN is never observed or translated — the ferry uses only the
/// presented server ISN (S1) and the client ISN, with byte counters for the
/// seq/ack framing in crafted server→client packets. This design is validated
/// in the spike experiment E6.
/// </summary>
internal sealed class FlowState
{
    /// <summary>Maximum pending-buffer size (64 KB).</summary>
    internal const int MaxPendingBufferSize = 64 * 1024;

    /// <summary>The connection's 4-tuple.</summary>
    public FlowKey Key { get; }

    /// <summary>The client's ISN from the captured SYN.</summary>
    public uint ClientIsn { get; }

    /// <summary>
    /// The server ISN (S1) presented to the client. This is the ISN in the
    /// crafted SYN-ACK. The upstream kernel's ISN is never observed.
    /// </summary>
    public uint ServerIsn { get; }

    /// <summary>The WinDivert address from the captured SYN, preserved for injection.</summary>
    public WinDivertAddress SynAddress { get; set; }

    /// <summary>
    /// The process name that owns this connection, resolved at SYN-capture time
    /// (e.g. "curl.exe"). Used for rule matching and logging.
    /// </summary>
    public string? ProcessName { get; set; }

    /// <summary>The owning PID, resolved at SYN-capture time.</summary>
    public int ProcessId { get; set; }

    // ── Parallel-establishment state ──

    /// <summary>
    /// True once the SOCKS5 CONNECT has completed (success or failure). The
    /// per-flow consumer checks this flag to decide whether to buffer client
    /// payload or relay normally. Written by the CONNECT completion task; read
    /// by the per-flow consumer (<see cref="HandleExistingFlowAsync"/>).
    /// </summary>
    private bool _upstreamReady;

    /// <inheritdoc cref="_upstreamReady"/>
    public bool UpstreamReady
    {
        get => Volatile.Read(ref _upstreamReady);
        set => Volatile.Write(ref _upstreamReady, value);
    }

    /// <summary>
    /// The completed SOCKS5 CONNECT, held here while it waits to be claimed by
    /// the per-flow consumer (which applies it: flush buffer → set stream →
    /// start pump). Claimed via <see cref="TryClaimPendingUpstream"/> so the
    /// connection is never orphaned (if the flow is cleaned up while the
    /// CONNECT is in flight, <see cref="CleanupFlow"/> disposes this instead).
    /// Written by the CONNECT completion task; read/claimed by the per-flow
    /// consumer and by cleanup.
    /// </summary>
    private Socks5Connection? _pendingUpstream;

    /// <summary>
    /// Claims the completed upstream connection, clearing the field. Returns
    /// null when there is nothing to claim. Thread-safe (single atomic
    /// exchange).
    /// </summary>
    public Socks5Connection? TryClaimPendingUpstream()
        => Interlocked.Exchange(ref _pendingUpstream, null);

    /// <summary>
    /// Stores the completed upstream connection for the consumer to claim.
    /// Returns true if the connection was stored; false if a connection was
    /// already pending (should never happen — one CONNECT per flow).
    /// </summary>
    public bool TryStorePendingUpstream(Socks5Connection conn)
        => Interlocked.CompareExchange(ref _pendingUpstream, conn, null) == null;

    /// <summary>
    /// Bounded pending buffer for client payload bytes that arrive before the
    /// SOCKS5 CONNECT completes. Protected by <see cref="_pendingLock"/> so the
    /// per-flow consumer (writer) and CONNECT completion (reader) do not race.
    /// </summary>
    private readonly object _pendingLock = new();
    private byte[]? _pendingBuffer;
    private int _pendingBufferLen;

    /// <summary>
    /// Appends client payload bytes to the pending buffer (up to
    /// <see cref="MaxPendingBufferSize"/>). Returns true on success, false on
    /// overflow. The caller must still increment <see cref="ClientBytesSent"/>
    /// so the ACK framing stays correct.
    ///
    /// Thread-safe: the per-flow consumer calls this from the serialized channel,
    /// and the CONNECT completion may call <see cref="DrainPendingBuffer"/> from
    /// a background task concurrently.
    /// </summary>
    public bool TryAppendPendingBuffer(ReadOnlySpan<byte> data)
    {
        lock (_pendingLock)
        {
            if (_pendingBufferLen + data.Length > MaxPendingBufferSize)
                return false;
            if (_pendingBuffer == null || _pendingBuffer.Length < _pendingBufferLen + data.Length)
                Array.Resize(ref _pendingBuffer, Math.Max(_pendingBufferLen + data.Length, 1024));
            data.CopyTo(_pendingBuffer.AsSpan(_pendingBufferLen));
            _pendingBufferLen += data.Length;
            return true;
        }
    }

    /// <summary>
    /// Extracts all buffered payload bytes and clears the buffer. Returns null
    /// when the buffer is empty. Called once by the CONNECT-establish action
    /// (enqueued on the per-flow channel) before the upstream is set.
    ///
    /// Thread-safe (acquires <see cref="_pendingLock"/>).
    /// </summary>
    public byte[]? DrainPendingBuffer()
    {
        lock (_pendingLock)
        {
            if (_pendingBufferLen == 0)
                return null;
            var result = _pendingBuffer.AsSpan(0, _pendingBufferLen).ToArray();
            _pendingBufferLen = 0;
            return result;
        }
    }

    /// <summary>
    /// Number of payload bytes written to the upstream from the pending buffer
    /// (the buffered-while-Connecting bytes that the CONNECT-establish action
    /// flushes). These bytes are ALREADY included in <see cref="ClientBytesSent"/>
    /// (they were counted when buffered), so the flush must NOT increment
    /// ClientBytesSent again — this counter tracks the flush separately so the
    /// exactly-once invariant can be asserted: every client payload byte is
    /// written upstream exactly once, whether via the buffered flush or the
    /// normal relay path.
    /// </summary>
    private long _bytesFlushedFromBuffer;

    /// <inheritdoc cref="_bytesFlushedFromBuffer"/>
    public long BytesFlushedFromBuffer
    {
        get => Interlocked.Read(ref _bytesFlushedFromBuffer);
        set => Interlocked.Exchange(ref _bytesFlushedFromBuffer, value);
    }

    /// <summary>
    /// Current pending-buffer length in bytes (for diagnostics). Thread-safe.
    /// </summary>
    public int PendingBufferLength
    {
        get { lock (_pendingLock) { return _pendingBufferLen; } }
    }

    // ── Data-translation state ──

    /// <summary>
    /// The window-scale shift the ferry OFFERED in its SYN-ACK (0 when the
    /// client's SYN carried no window-scale option — per RFC 7323 the option
    /// must not be sent unilaterally, and then both sides use shift 0).
    /// Interprets the window field of every packet the ferry injects.
    /// </summary>
    public byte ServerWindowShift { get; set; }

    /// <summary>
    /// The window-scale shift the CLIENT offered in its SYN (0 when absent).
    /// Interprets the window field of captured client packets, i.e. how much
    /// server→client data may be in flight before the pump must wait.
    /// </summary>
    public byte ClientWindowShift { get; set; }

    /// <summary>
    /// The raw (unscaled) receive window most recently advertised by a captured
    /// client segment. Initialized from the SYN; updated on every client packet.
    /// Read by the upstream read pump for downstream flow control.
    /// </summary>
    private ushort _clientAdvertisedWindow = 0xFFFF;

    /// <inheritdoc cref="_clientAdvertisedWindow"/>
    public ushort ClientAdvertisedWindow
    {
        get => Volatile.Read(ref _clientAdvertisedWindow);
        set => Volatile.Write(ref _clientAdvertisedWindow, value);
    }

    /// <summary>
    /// The MSS the ferry advertised in its SYN-ACK (diagnostics; 0 when the
    /// client's SYN carried no MSS option and none was advertised).
    /// </summary>
    public ushort AdvertisedMss { get; set; }

    /// <summary>
    /// Receive space the ferry advertises to the CLIENT for upload traffic
    /// (the effective window is this value &lt;&lt; <see cref="ServerWindowShift"/>).
    /// The legacy constant 29200 capped upload throughput at ~29200 bytes per
    /// RTT; 1 MiB removes that ceiling while remaining modest in memory.
    /// </summary>
    internal const long FerryReceiveWindowBytes = 1024 * 1024;

    /// <summary>
    /// The window FIELD value the ferry puts in injected server→client packets:
    /// <see cref="FerryReceiveWindowBytes"/> scaled down by the negotiated
    /// <see cref="ServerWindowShift"/>, clamped to 16 bits. A pure permission
    /// slip — the relay never buffers this much (writes go straight into the
    /// upstream socket), it only bounds how far the client may run ahead.
    /// </summary>
    public ushort ServerAdvertisedWindowField => (ushort)Math.Min(
        ushort.MaxValue,
        FerryReceiveWindowBytes >> ServerWindowShift);

    /// <summary>
    /// The client's current receive window in BYTES (raw field &lt;&lt;
    /// <see cref="ClientWindowShift"/>) — how much server→client data may be
    /// outstanding before the pump must wait for the client's ACKs.
    /// </summary>
    public long ClientReceiveWindowBytes => (long)ClientAdvertisedWindow << ClientWindowShift;

    /// <summary>
    /// How many more server→client bytes the ferry may inject right now without
    /// overrunning the client's advertised receive window:
    /// window − (injected but not yet ACKed by the client).
    ///
    /// WHY: the pump previously ignored the client's window entirely and could
    /// inject data beyond it — the client stack silently DISCARDS unacceptable
    /// segments, and since the ferry never retransmits those bytes were lost
    /// forever (a permanent stream hole under heavy download). With scaling
    /// enabled windows grow large enough that respecting them is mandatory.
    /// </summary>
    public long AllowedUnackedBytesToClient
    {
        get
        {
            // accepted = highest client ACK − SYN-consumed server seq (wrap-safe).
            var accepted = (long)(uint)(ClientAckedUpTo - (uint)(ServerIsn + 1));
            if (accepted < 0)
                accepted = 0;
            var inFlight = ClientBytesRecv - accepted;
            if (inFlight < 0)
                inFlight = 0;
            var allowed = ClientReceiveWindowBytes - inFlight;
            return allowed > 0 ? allowed : 0;
        }
    }

    /// <summary>
    /// The upstream socket's stream, set once the SOCKS5 CONNECT completes.
    /// Null until the upstream leg is established.
    /// </summary>
    public Stream? UpstreamStream { get; set; }

    /// <summary>
    /// Number of payload bytes from the client that have been written to the
    /// upstream socket. Used to compute the ack value in injected server→client
    /// packets. Written by the per-flow consumer; read by the upstream pump.
    /// Volatile so the pump never reads a stale cached value.
    /// </summary>
    private long _clientBytesSent;

    /// <inheritdoc cref="_clientBytesSent"/>
    public long ClientBytesSent
    {
        get => Interlocked.Read(ref _clientBytesSent);
        set => Interlocked.Exchange(ref _clientBytesSent, value);
    }

    /// <summary>
    /// Number of payload bytes from the upstream that have been injected to the
    /// client. Used to compute the seq value in injected server→client packets
    /// (seq = ServerIsn + 1 + ClientBytesRecv). Written by the upstream pump;
    /// read by the per-flow consumer.
    /// </summary>
    private long _clientBytesRecv;

    /// <inheritdoc cref="_clientBytesRecv"/>
    public long ClientBytesRecv
    {
        get => Interlocked.Read(ref _clientBytesRecv);
        set => Interlocked.Exchange(ref _clientBytesRecv, value);
    }

    /// <summary>
    /// The highest ACK sequence the client has sent (from captured client ACK
    /// packets). The ferry compares this against the server seq it has injected
    /// to decide when the client has accepted all response bytes, so the
    /// separate server FIN is only injected after the client ACKed the data.
    /// Written by the per-flow consumer; read by the upstream pump.
    /// </summary>
    private uint _clientAckedUpTo;

    /// <inheritdoc cref="_clientAckedUpTo"/>
    public uint ClientAckedUpTo
    {
        get => Volatile.Read(ref _clientAckedUpTo);
        set => Volatile.Write(ref _clientAckedUpTo, value);
    }

    // ── Lifecycle ──

    /// <summary>UTC timestamp of the last activity (data, SYN, ACK, FIN, RST).</summary>
    public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Current flow phase.</summary>
    public FlowStatus Status { get; set; } = FlowStatus.Resolving;

    /// <summary>CancellationTokenSource for the upstream leg; cancelled on cleanup.</summary>
    public CancellationTokenSource? LoopCts { get; set; }

    // ── Per-flow packet-processing serialization ──
    //
    // The capture loop must not block on per-flow I/O: a browser opens many
    // concurrent connections, and awaiting each flow's upstream write inline
    // would serialize all flows through the loop (and stall it entirely while
    // any flow's network I/O is in flight). Instead, the loop enqueues work
    // here and returns immediately; a single per-flow consumer task drains
    // this channel serially, preserving same-flow packet ordering while
    // different flows proceed independently.

    private readonly Channel<Func<Task>> _processing = Channel.CreateUnbounded<Func<Task>>();

    /// <summary>
    /// Enqueues a packet-processing step for this flow (non-blocking). Returns
    /// false when the channel has been completed (flow cleaned up) and the work
    /// was NOT enqueued — the caller must then dispose any resources it holds
    /// (e.g. a completed SOCKS5 connection) instead of leaking them.
    /// </summary>
    public bool EnqueueProcessing(Func<Task> work) => _processing.Writer.TryWrite(work);

    /// <summary>The reader the per-flow consumer drains.</summary>
    public ChannelReader<Func<Task>> ProcessingReader => _processing.Reader;

    /// <summary>Completes the channel so the per-flow consumer exits.</summary>
    public void CompleteProcessing() => _processing.Writer.TryComplete();

    /// <param name="key">The connection's 4-tuple.</param>
    /// <param name="clientIsn">The client ISN from the captured SYN.</param>
    /// <param name="serverIsn">The server ISN (S1) to present to the client.</param>
    /// <param name="synAddress">The WinDivert address from the captured SYN.</param>
    public FlowState(
        FlowKey key,
        uint clientIsn,
        uint serverIsn,
        WinDivertAddress synAddress)
    {
        Key = key;
        ClientIsn = clientIsn;
        ServerIsn = serverIsn;
        SynAddress = synAddress;
    }

    /// <summary>Marks the flow as active (updates the last-activity timestamp).</summary>
    public void Touch() => LastActivityUtc = DateTime.UtcNow;

    /// <summary>
    /// The seq value for the next upstream→client packet (E6-validated):
    /// ServerIsn + 1 + ClientBytesRecv. The SYN-ACK consumed ServerIsn, so the
    /// first data byte is ServerIsn + 1.
    /// </summary>
    public uint NextServerSeq => (uint)(ServerIsn + 1 + ClientBytesRecv);

    /// <summary>
    /// The ack value for the next upstream→client packet (E6-validated):
    /// ClientIsn + 1 + ClientBytesSent.
    /// </summary>
    public uint NextClientAck => (uint)(ClientIsn + 1 + ClientBytesSent);
}

/// <summary>Flow lifecycle phase.</summary>
internal enum FlowStatus
{
    /// <summary>Process attribution is in progress.</summary>
    Resolving,

    /// <summary>Upstream (SOCKS5) connection is being established.</summary>
    Connecting,

    /// <summary>Handshake complete; data relay is active.</summary>
    Established,

    /// <summary>Flow is being torn down.</summary>
    Closing,

    /// <summary>Flow is closed and has been removed from the flow table.</summary>
    Closed
}