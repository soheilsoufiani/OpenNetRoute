using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Network;

/// <summary>
/// The result of one relayed DNS exchange.
/// </summary>
/// <param name="DnsPayload">The DNS reply payload (no IP/UDP headers) — the exact
/// bytes the relayed DNS server produced.</param>
/// <param name="Server">The DNS server the reply came from (as reported by the relay).</param>
public sealed record UdpRelayResult(byte[] DnsPayload, IPEndPoint Server);

/// <summary>
/// A SOCKS5 UDP ASSOCIATE client leg (RFC 1928 §7) for relaying DNS queries
/// through the proxy.
///
/// Lifecycle: <see cref="StartAsync"/> opens the TCP control connection,
/// performs the usual version/method negotiation (shared with
/// <see cref="Socks5Client"/>), issues a UDP ASSOCIATE request (CMD 3), and
/// binds a local UDP socket for relaying. Every <see cref="RelayAsync"/> wraps
/// one DNS payload in the RFC 1928 datagram header
/// (RSV(2)=0, FRAG(1)=0, ATYP, DST.ADDR, DST.PORT) and sends it to the
/// proxy-reported relay endpoint; the reply datagram (header + DNS payload) is
/// unwrapped and returned.
///
/// Concurrency: multiple queries may be in flight; replies are correlated by
/// the DNS transaction ID (the first two payload bytes — the same correlation
/// the DNS client itself uses). FRAG≠0 datagrams are never sent (fragmentation
/// is not needed for DNS and many proxies reject it).
///
/// The UDP association lives as long as the TCP control connection (RFC 1928
/// §7) — <see cref="Dispose"/> closes both.
/// </summary>
public sealed class Socks5UdpAssociateClient : ISocks5UdpRelay, IDisposable
{
    /// <summary>Default overall timeout for establishing the association.</summary>
    public static readonly TimeSpan DefaultAssociateTimeout = TimeSpan.FromSeconds(10);

    private const byte Version5 = 0x05;
    private const byte CommandUdpAssociate = 0x03;
    private const byte AtypIpv4 = 0x01;
    private const byte AtypDomain = 0x03;
    private const byte AtypIpv6 = 0x04;

    private readonly ProxyConfiguration _proxy;
    private readonly TimeSpan _associateTimeout;

    private Socket? _controlSocket;
    private NetworkStream? _controlStream;
    private Socket? _udpSocket;
    private IPEndPoint? _relayEndPoint;

    // In-flight queries keyed by their transaction key (hex of the leading
    // correlation bytes — see <see cref="RelayAsync"/>'s correlationBytes).
    private readonly ConcurrentDictionary<string, TaskCompletionSource<UdpRelayResult>> _pending = new();
    private CancellationTokenSource? _receiveLoopCts;
    private Task? _receiveLoop;
    private bool _disposed;

    /// <summary>Trace sink for diagnostics (may be null).</summary>
    private readonly Action<string>? _trace;

    /// <summary>
    /// Creates the client for the given proxy configuration. Call
    /// <see cref="StartAsync"/> before relaying.
    /// </summary>
    public Socks5UdpAssociateClient(
        ProxyConfiguration proxy,
        TimeSpan? associateTimeout = null,
        Action<string>? trace = null)
    {
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _associateTimeout = associateTimeout ?? DefaultAssociateTimeout;
        _trace = trace;
    }

    /// <summary>True once the association (control + relay endpoint) is established.</summary>
    public bool IsAssociated => _relayEndPoint is not null;

    private void Trace(string message) => _trace?.Invoke($"[Socks5Udp] {message}");

    /// <summary>
    /// Establishes the TCP control connection, negotiates, issues the UDP
    /// ASSOCIATE request and binds the relay UDP socket.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_relayEndPoint is not null)
            return;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_associateTimeout);
        var ct = timeoutCts.Token;

        var control = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        NetworkStream? stream = null;
        try
        {
            await control.ConnectAsync(_proxy.Host, _proxy.Port, ct).ConfigureAwait(false);
            stream = new NetworkStream(control, ownsSocket: true);

            await Socks5Client.NegotiateAsync(stream, _proxy, cancellationToken, ct).ConfigureAwait(false);

            // UDP ASSOCIATE request: FRAG-less CMD 3 with DST.ADDR 0.0.0.0:0 —
            // the client does not yet know the target; each datagram carries
            // its own destination.
            var request = new byte[] { Version5, CommandUdpAssociate, 0x00, AtypIpv4, 0, 0, 0, 0, 0, 0 };
            await Socks5Client.WriteExactAsync(stream, request, ct).ConfigureAwait(false);

            var header = new byte[4];
            await Socks5Client.ReadExactAsync(stream, header, cancellationToken, ct).ConfigureAwait(false);
            if (header[0] != Version5)
                throw new Socks5Exception($"Unexpected SOCKS5 version 0x{header[0]:X2} in UDP ASSOCIATE reply.");
            if (header[1] != (byte)Socks5ReplyCode.Succeeded)
                throw new Socks5Exception((Socks5ReplyCode)header[1]);

            var (bndAddress, bndPort) =
                await Socks5Client.ReadBoundEndpointAsync(stream, header[3], cancellationToken, ct).ConfigureAwait(false);

            // The relay endpoint. Proxies report BND.ADDR for THEIR side; when
            // they report 0.0.0.0 (a wildcard), the relay is reachable at the
            // proxy's own address.
            var relayIp = IPAddress.Parse(bndAddress);
            if (relayIp.Equals(IPAddress.Any) || relayIp.Equals(IPAddress.IPv6Any))
                relayIp = (await Dns.GetHostAddressesAsync(_proxy.Host, ct).ConfigureAwait(false))
                    .First(a => a.AddressFamily == AddressFamily.InterNetwork);
            _relayEndPoint = new IPEndPoint(relayIp, bndPort);

            // Local UDP socket the client relays through.
            var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Any, 0));

            _controlSocket = control;
            _controlStream = stream;
            _udpSocket = udp;

            _receiveLoopCts = new CancellationTokenSource();
            _receiveLoop = Task.Run(() => ReceiveLoopAsync(_receiveLoopCts.Token));

            Trace($"associated — relay endpoint {_relayEndPoint} (control to {_proxy.Host}:{_proxy.Port})");
        }
        catch
        {
            // Any failure releases everything — the association never half-exists.
            try { stream?.Dispose(); } catch { }
            try { control.Dispose(); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Relays one UDP payload to <paramref name="dnsServer"/>:<paramref name="dnsPort"/>
    /// through the proxy's UDP relay and returns the reply payload.
    /// Throws TimeoutException when no reply arrives within <paramref name="timeout"/>,
    /// and OperationCanceledException when <paramref name="cancellationToken"/> fires.
    /// </summary>
    /// <param name="correlationBytes">
    /// How many leading payload bytes identify the transaction: 2 for DNS
    /// (transaction ID) or 12 for STUN (full transaction ID — the reply's
    /// message type differs from the request's, so the first two bytes don't
    /// correlate).
    /// </param>
    public async Task<UdpRelayResult> RelayAsync(
        byte[] dnsPayload,
        IPAddress dnsServer,
        int dnsPort,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default,
        int correlationBytes = 2)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (correlationBytes is not (2 or 12))
            throw new ArgumentOutOfRangeException(nameof(correlationBytes));
        var relay = _relayEndPoint
            ?? throw new InvalidOperationException("The UDP association is not established — call StartAsync first.");
        var udp = _udpSocket
            ?? throw new InvalidOperationException("The relay UDP socket is not available.");

        if (dnsPayload.Length < Math.Max(12, correlationBytes))
            throw new ArgumentException("A DNS payload must be at least 12 bytes (the header).", nameof(dnsPayload));

        // Transaction key: DNS correlates on the FIRST 2 bytes (the echoed
        // ID); STUN's message TYPE changes between request (0x0001) and
        // response (0x0101), so its identity is the magic+transaction-ID at
        // offset 4 (12 bytes).
        var id = correlationBytes == 12 ? KeyFrom(dnsPayload, 4, 12) : KeyFrom(dnsPayload, 0, 2);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout ?? TimeSpan.FromSeconds(2));
        var ct = timeoutCts.Token;

        var tcs = new TaskCompletionSource<UdpRelayResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var registration = ct.Register(() => _pending.TryRemove(id, out _));
        _pending[id] = tcs;
        try
        {
            // RFC 1928 §7 datagram header: RSV(2), FRAG(1)=0, ATYP, DST.ADDR,
            // DST.PORT, then the payload — the port sits BETWEEN the address
            // and the payload (not at the end; the E8-datagram off-by-one).
            var addrBytes = dnsServer.GetAddressBytes();
            var atyp = dnsServer.AddressFamily == AddressFamily.InterNetworkV6 ? AtypIpv6 : AtypIpv4;
            var datagram = new byte[4 + addrBytes.Length + 2 + dnsPayload.Length];
            datagram[2] = 0; // FRAG=0
            datagram[3] = atyp;
            addrBytes.CopyTo(datagram, 4);
            var portPos = 4 + addrBytes.Length;
            datagram[portPos] = (byte)(dnsPort >> 8);
            datagram[portPos + 1] = (byte)dnsPort;
            dnsPayload.CopyTo(datagram, portPos + 2);

            await udp.SendToAsync(datagram, SocketFlags.None, relay, ct).ConfigureAwait(false);

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(Timeout.Infinite, ct)).ConfigureAwait(false);
            if (completed != tcs.Task)
            {
                throw cancellationToken.IsCancellationRequested
                    ? new OperationCanceledException(cancellationToken)
                    : new TimeoutException("Timed out waiting for the DNS reply through the proxy relay.");
            }

            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            registration.Dispose();
            _pending.TryRemove(id, out _);
        }
    }

    /// <summary>
    /// Receives relayed reply datagrams, unwraps the RFC 1928 header, and
    /// completes the pending query by DNS transaction ID.
    /// </summary>
    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var udp = _udpSocket!;
        var buffer = new byte[65535];
        var remoteAny = new IPEndPoint(IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var received = await udp.ReceiveFromAsync(buffer, SocketFlags.None, remoteAny)
                    .ConfigureAwait(false);

                // Parse the RFC 1928 datagram header: RSV(2), FRAG(1), ATYP(1), ADDR, PORT(2).
                if (received.ReceivedBytes < 4 + 1 + 2) continue;
                var frag = buffer[2];
                if (frag != 0) continue; // fragmented relays are not supported
                var atyp = buffer[3];

                int addrLen, headerLen;
                IPEndPoint server;
                switch (atyp)
                {
                    case AtypIpv4:
                        server = new IPEndPoint(new IPAddress(buffer.AsSpan(4, 4)),
                            (buffer[8] << 8) | buffer[9]);
                        addrLen = 4;
                        headerLen = 4 + 4 + 2;
                        break;
                    case AtypIpv6:
                        server = new IPEndPoint(new IPAddress(buffer.AsSpan(4, 16)),
                            (buffer[20] << 8) | buffer[21]);
                        addrLen = 16;
                        headerLen = 4 + 16 + 2;
                        break;
                    case AtypDomain:
                        var len = buffer[4];
                        headerLen = 4 + 1 + len + 2;
                        server = new IPEndPoint(IPAddress.Any, (buffer[5 + len] << 8) | buffer[6 + len]);
                        break;
                    default:
                        continue; // unknown ATYP — drop, never crash the loop
                }

                if (received.ReceivedBytes <= headerLen) continue;
                var payload = buffer.AsSpan(headerLen, received.ReceivedBytes - headerLen).ToArray();
                if (payload.Length < 12) continue;

                // The pending entry's key shape was chosen at request time —
                // DNS: first 2 bytes; STUN: magic+txid at offset 4 (12 bytes;
                // the message type differs between request and response).
                if (_pending.TryRemove(KeyFrom(payload, 0, 2), out var tcs) ||
                    _pending.TryRemove(KeyFrom(payload, 4, 12), out tcs))
                    tcs.TrySetResult(new UdpRelayResult(payload, server));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                // Transient UDP-level error (e.g. ICMP port unreachable on a
                // previous send). Keep serving — the pending query times out.
            }
            catch (ObjectDisposedException)
            {
                break;
            }
        }
        await Task.CompletedTask;
    }

    /// <summary>
    /// Builds the transaction key: hex of <paramref name="count"/> payload
    /// bytes starting at <paramref name="offset"/> (the bytes a reply echoes).
    /// </summary>
    private static string KeyFrom(ReadOnlySpan<byte> payload, int offset, int count)
    {
        Span<char> chars = stackalloc char[count * 2];
        for (var i = 0; i < count; i++)
        {
            payload[offset + i].TryFormat(chars[(i * 2)..], out _, "X2");
        }
        return new string(chars);
    }

    /// <summary>Stops the association and releases the control and UDP sockets.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _receiveLoopCts?.Cancel(); } catch { }
        try { _controlStream?.Dispose(); } catch { }
        try { _controlSocket?.Dispose(); } catch { }
        try { _udpSocket?.Dispose(); } catch { }
        try { _receiveLoopCts?.Dispose(); } catch { }
    }
}
