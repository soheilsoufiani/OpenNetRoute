using System.Net;
using System.Threading.Channels;

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

    // ── Data-translation state ──

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

    /// <summary>Enqueues a packet-processing step for this flow (non-blocking).</summary>
    public void EnqueueProcessing(Func<Task> work) => _processing.Writer.TryWrite(work);

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