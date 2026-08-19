using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Network;

/// <summary>
/// A SOCKS5 client implementing RFC 1928 (SOCKS protocol version 5) and
/// RFC 1929 (username/password authentication).
///
/// The client connects to the configured SOCKS5 proxy over TCP, negotiates the
/// version and authentication method, then issues a CONNECT request for the
/// requested destination. On success it hands back the live stream to the
/// destination. The client is a thin, deterministic protocol layer: it performs
/// byte-exact reads and writes and never swallows errors. It holds no state or
/// resources between calls — each <see cref="ConnectAsync"/> is self-contained
/// and the returned connection owns its socket.
/// </summary>
public sealed class Socks5Client : ISocks5Client
{
    private const byte Version5 = 0x05;
    private const byte CommandConnect = 0x01;
    private const byte MethodNoAuthentication = 0x00;
    private const byte MethodUsernamePassword = 0x02;
    private const byte MethodNoAcceptable = 0xFF;
    private const byte AuthVersion = 0x01;
    private const byte AtypIpv4 = 0x01;
    private const byte AtypDomain = 0x03;
    private const byte AtypIpv6 = 0x04;

    /// <summary>Default overall timeout (TCP connect + negotiation) when none is specified.</summary>
    public static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly ProxyConfiguration _proxy;
    private readonly TimeSpan _connectTimeout;

    /// <summary>
    /// Creates a client for the given proxy configuration.
    /// </summary>
    /// <param name="proxy">
    /// The SOCKS5 proxy to connect to. The host must be non-empty and the port in
    /// range (see <see cref="ProxyApp.Core.Validation.ConfigurationValidator"/>).
    /// </param>
    /// <param name="connectTimeout">
    /// Maximum time allowed for the TCP connect to the proxy and for the SOCKS5
    /// negotiation as a whole. A server that stalls mid-negotiation therefore
    /// fails within this bound.
    /// </param>
    public Socks5Client(ProxyConfiguration proxy, TimeSpan? connectTimeout = null)
    {
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
    }

    /// <inheritdoc />
    public async ValueTask<Socks5Connection> ConnectAsync(
        Socks5Destination destination,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_proxy.Host))
            throw new InvalidOperationException("The SOCKS5 proxy host is not configured.");
        if (_proxy.Port is < 1 or > 65535)
            throw new InvalidOperationException($"The SOCKS5 proxy port {_proxy.Port} is out of range.");

        if (destination.Host is null)
            throw new ArgumentException("Destination host must not be null.", nameof(destination));

        // Bound the whole operation (TCP connect + negotiation) by the connect
        // timeout, while still honoring caller cancellation. Keeping the caller's
        // token separately lets us distinguish "we timed out" from "the caller
        // cancelled" so the caller gets a useful error instead of a bare cancel.
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_connectTimeout);
        var ct = timeoutCts.Token;

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        NetworkStream? stream = null;
        try
        {
            await socket.ConnectAsync(_proxy.Host, _proxy.Port, ct).ConfigureAwait(false);

            // One stream for the lifetime of the connection. It owns the socket and
            // is transferred to the Socks5Connection on success.
            stream = new NetworkStream(socket, ownsSocket: true);

            await NegotiateAsync(stream, cancellationToken, ct).ConfigureAwait(false);

            var (bndAddress, bndPort) = await SendConnectAsync(stream, destination, cancellationToken, ct).ConfigureAwait(false);

            return new Socks5Connection(stream, bndAddress, bndPort);
        }
        catch
        {
            // Any failure releases the socket. On success ownership moved to the
            // Socks5Connection, which the caller disposes.
            try { stream?.Dispose(); } catch { }
            try { socket.Dispose(); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Performs the SOCKS5 method negotiation (RFC 1928 §3): sends the greeting,
    /// reads the server's method selection, and completes the RFC 1929
    /// username/password sub-negotiation when that method is selected.
    /// </summary>
    private async Task NegotiateAsync(
        NetworkStream stream,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        // Greeting: VER(0x05), NMETHODS(1), METHODS[NMETHODS]
        var methods = _proxy.AuthenticationType switch
        {
            ProxyAuthenticationType.None => new[] { MethodNoAuthentication },
            ProxyAuthenticationType.UsernamePassword => new[] { MethodNoAuthentication, MethodUsernamePassword },
            _ => throw new InvalidOperationException(
                $"Unsupported authentication type '{_proxy.AuthenticationType}'.")
        };

        var greeting = new byte[2 + methods.Length];
        greeting[0] = Version5;
        greeting[1] = (byte)methods.Length;
        methods.CopyTo(greeting, 2);

        await WriteExactAsync(stream, greeting, ct).ConfigureAwait(false);

        // Reply: VER(1), METHOD(1)
        var reply = new byte[2];
        await ReadExactAsync(stream, reply, callerToken, ct).ConfigureAwait(false);
        if (reply[0] != Version5)
            throw new Socks5Exception($"Unexpected SOCKS5 version 0x{reply[0]:X2} in greeting reply.");

        switch (reply[1])
        {
            case MethodNoAuthentication:
                break;

            case MethodUsernamePassword:
                await AuthenticateAsync(stream, callerToken, ct).ConfigureAwait(false);
                break;

            case MethodNoAcceptable:
                throw new Socks5Exception("The SOCKS5 server rejected all offered authentication methods.");

            default:
                throw new Socks5Exception($"The SOCKS5 server selected an unsupported method 0x{reply[1]:X2}.");
        }
    }

    /// <summary>
    /// RFC 1929 username/password sub-negotiation:
    ///   VER(0x01), ULEN(1), UNAME, PLEN(1), PASSWD
    /// The server replies VER(0x01), STATUS(1) where 0x00 = success.
    /// </summary>
    private async Task AuthenticateAsync(
        NetworkStream stream,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        var username = _proxy.Username ?? string.Empty;
        var password = _proxy.Password ?? string.Empty;

        // RFC 1929: ULEN/PLEN are single octets (max 255). Truncate defensively
        // so an overlong configured value cannot corrupt the wire format.
        if (username.Length > 255)
            username = username[..255];
        if (password.Length > 255)
            password = password[..255];

        var ubytes = Encoding.UTF8.GetBytes(username);
        var pbytes = Encoding.UTF8.GetBytes(password);

        var request = new byte[1 + 1 + ubytes.Length + 1 + pbytes.Length];
        request[0] = AuthVersion;
        request[1] = (byte)ubytes.Length;
        ubytes.CopyTo(request, 2);
        request[2 + ubytes.Length] = (byte)pbytes.Length;
        pbytes.CopyTo(request, 3 + ubytes.Length);

        await WriteExactAsync(stream, request, ct).ConfigureAwait(false);

        var reply = new byte[2];
        await ReadExactAsync(stream, reply, callerToken, ct).ConfigureAwait(false);
        if (reply[0] != AuthVersion)
            throw new Socks5Exception($"Unexpected authentication version 0x{reply[0]:X2} in RFC 1929 reply.");

        if (reply[1] != 0x00)
            throw new Socks5Exception("The SOCKS5 server rejected the username/password credentials.");
    }

    /// <summary>
    /// Sends an RFC 1928 CONNECT request and parses the success reply, returning
    /// the proxy-reported bound address and port.
    /// </summary>
    private async Task<(string BndAddress, int BndPort)> SendConnectAsync(
        NetworkStream stream,
        Socks5Destination destination,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        var request = BuildConnectRequest(destination);
        await WriteExactAsync(stream, request, ct).ConfigureAwait(false);

        // Reply: VER(1), REP(1), RSV(1), ATYP(1), BND.ADDR, BND.PORT(2)
        var header = new byte[4];
        await ReadExactAsync(stream, header, callerToken, ct).ConfigureAwait(false);

        if (header[0] != Version5)
            throw new Socks5Exception($"Unexpected SOCKS5 version 0x{header[0]:X2} in CONNECT reply.");

        if (header[1] != (byte)Socks5ReplyCode.Succeeded)
            throw new Socks5Exception((Socks5ReplyCode)header[1]);

        var (bndAddress, bndPort) = await ReadBoundEndpointAsync(stream, header[3], callerToken, ct).ConfigureAwait(false);
        return (bndAddress, bndPort);
    }

    /// <summary>
    /// Builds the CONNECT request bytes for the given destination.
    ///
    /// Hosts that parse as an IP literal are encoded as ATYP IPv4/IPv6 (no DNS
    /// resolution performed by the client). Everything else is encoded as a
    /// domain name (ATYP 0x03), leaving resolution to the proxy.
    /// </summary>
    internal static byte[] BuildConnectRequest(Socks5Destination destination)
    {
        if (destination.Host is null)
            throw new ArgumentException("Destination host must not be null.", nameof(destination));

        if (destination.Port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(destination), destination.Port, "Port must be 1-65535.");

        if (IPAddress.TryParse(destination.Host, out var ip))
        {
            var addrBytes = ip.GetAddressBytes();
            var atyp = ip.AddressFamily == AddressFamily.InterNetworkV6 ? AtypIpv6 : AtypIpv4;
            return BuildRequestWithAddress(atyp, addrBytes, destination.Port);
        }

        var domainBytes = Encoding.ASCII.GetBytes(destination.Host);
        if (domainBytes.Length == 0 || domainBytes.Length > 255)
            throw new ArgumentException(
                $"Destination host '{destination.Host}' cannot be encoded as a SOCKS5 domain.",
                nameof(destination));

        var request = new byte[4 + 1 + domainBytes.Length + 2];
        request[0] = Version5;
        request[1] = CommandConnect;
        request[2] = 0x00;
        request[3] = AtypDomain;
        request[4] = (byte)domainBytes.Length;
        domainBytes.CopyTo(request, 5);
        request[^2] = (byte)(destination.Port >> 8);
        request[^1] = (byte)destination.Port;
        return request;
    }

    private static byte[] BuildRequestWithAddress(byte atyp, byte[] address, int port)
    {
        var request = new byte[4 + address.Length + 2];
        request[0] = Version5;
        request[1] = CommandConnect;
        request[2] = 0x00;
        request[3] = atyp;
        address.CopyTo(request, 4);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)port;
        return request;
    }

    /// <summary>
    /// Reads the BND.ADDR + BND.PORT portion of a reply given its ATYP byte.
    /// The bound address is informational (RFC 1928 clients generally ignore it).
    /// </summary>
    private async Task<(string Address, int Port)> ReadBoundEndpointAsync(
        NetworkStream stream,
        byte atyp,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        switch (atyp)
        {
            case AtypIpv4:
            {
                var buf = new byte[4];
                await ReadExactAsync(stream, buf, callerToken, ct).ConfigureAwait(false);
                var port = await ReadPortAsync(stream, callerToken, ct).ConfigureAwait(false);
                return (new IPAddress(buf).ToString(), port);
            }

            case AtypIpv6:
            {
                var buf = new byte[16];
                await ReadExactAsync(stream, buf, callerToken, ct).ConfigureAwait(false);
                var port = await ReadPortAsync(stream, callerToken, ct).ConfigureAwait(false);
                return (new IPAddress(buf).ToString(), port);
            }

            case AtypDomain:
            {
                var lenBuf = new byte[1];
                await ReadExactAsync(stream, lenBuf, callerToken, ct).ConfigureAwait(false);
                var buf = new byte[lenBuf[0]];
                await ReadExactAsync(stream, buf, callerToken, ct).ConfigureAwait(false);
                var port = await ReadPortAsync(stream, callerToken, ct).ConfigureAwait(false);
                return (Encoding.ASCII.GetString(buf), port);
            }

            default:
                throw new Socks5Exception($"Unsupported address type 0x{atyp:X2} in SOCKS5 reply.");
        }
    }

    private static async Task<int> ReadPortAsync(
        NetworkStream stream,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        var buf = new byte[2];
        await ReadExactAsync(stream, buf, callerToken, ct).ConfigureAwait(false);
        return (buf[0] << 8) | buf[1];
    }

    /// <summary>
    /// Reads exactly <paramref name="buffer"/>.Length bytes from the stream,
    /// honoring cancellation. If the operation times out because the connect
    /// deadline expired (not because the caller cancelled), a
    /// <see cref="TimeoutException"/> is thrown so the caller sees a useful error
    /// rather than a bare cancellation.
    /// </summary>
    private static async Task ReadExactAsync(
        NetworkStream stream,
        byte[] buffer,
        CancellationToken callerToken,
        CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            int n;
            try
            {
                n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!callerToken.IsCancellationRequested)
            {
                // The caller did not cancel, so this cancellation is the connect
                // deadline firing — report it as a timeout rather than a bare cancel.
                throw new TimeoutException("Timed out waiting for a response from the SOCKS5 server.");
            }

            if (n <= 0)
                throw new Socks5Exception("The SOCKS5 server closed the connection during negotiation.");

            read += n;
        }
    }

    private static async Task WriteExactAsync(
        NetworkStream stream,
        byte[] buffer,
        CancellationToken ct)
    {
        await stream.WriteAsync(buffer, ct).ConfigureAwait(false);
    }
}