using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyApp.Network.Tests.TestInfrastructure;

/// <summary>
/// A minimal, scriptable SOCKS5 test server used to exercise the client over real
/// TCP sockets. It is intentionally a genuine protocol peer — it parses and
/// answers real wire bytes — so tests exercise the actual negotiation path rather
/// than a fake that hides protocol bugs.
///
/// The server drives each accepted client connection through a user-supplied
/// <see cref="ConnectionHandler"/> that receives the parsed request and returns
/// the reply to send. The server accepts multiple sequential client connections.
/// </summary>
public sealed class Socks5TestServer : IDisposable
{
    /// <summary>RFC 1928 address type: IPv4.</summary>
    public const byte AtypIpv4 = 0x01;

    /// <summary>RFC 1928 address type: domain name.</summary>
    public const byte AtypDomain = 0x03;

    /// <summary>RFC 1928 address type: IPv6.</summary>
    public const byte AtypIpv6 = 0x04;

    /// <summary>Signature for handling one SOCKS5 client connection.</summary>
    /// <param name="request">The parsed CONNECT request.</param>
    /// <param name="stream">The live TCP stream to the client.</param>
    /// <param name="cancellationToken">Cancellation for the handler's I/O.</param>
    public delegate Task ConnectionHandler(
        ParsedConnectRequest request,
        NetworkStream stream,
        CancellationToken cancellationToken);

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly List<Task> _connections = new();
    private readonly byte _expectedVersion;
    private readonly byte _methodToSelect;
    private readonly Func<string, string, bool>? _credentialValidator;

    /// <summary>
    /// Creates the server on an ephemeral loopback port.
    /// </summary>
    /// <param name="handler">Handles each parsed CONNECT request.</param>
    /// <param name="expectedVersion">Expected SOCKS version (5).</param>
    /// <param name="methodToSelect">The authentication method the server selects
    /// (0x00 = no auth, 0x02 = username/password).</param>
    /// <param name="credentialValidator">Optional validator for the username and
    /// password when <paramref name="methodToSelect"/> is 0x02.</param>
    public Socks5TestServer(
        ConnectionHandler handler,
        byte expectedVersion = 0x05,
        byte methodToSelect = 0x00,
        Func<string, string, bool>? credentialValidator = null)
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _expectedVersion = expectedVersion;
        _methodToSelect = methodToSelect;
        _credentialValidator = credentialValidator;

        _acceptLoop = Task.Run(() => AcceptLoopAsync(handler));
    }

    /// <summary>The loopback port the server is listening on.</summary>
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>
    /// The parsed SOCKS5 CONNECT request, read by the test server from the client.
    /// </summary>
    public sealed record ParsedConnectRequest(
        byte Version,
        byte Command,
        byte Atyp,
        string Host,
        int Port,
        byte[] RawAddress);

    /// <summary>Reads exactly <paramref name="count"/> bytes, throwing on early EOF.</summary>
    public static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
            if (n <= 0)
                throw new EndOfStreamException("Test server read past end of stream.");
            read += n;
        }
    }

    private async Task AcceptLoopAsync(ConnectionHandler handler)
    {
        var ct = _cts.Token;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                _connections.Add(Task.Run(() => HandleClientAsync(client, handler, ct), ct));
            }
        }
        catch (Exception)
        {
            // Listener teardown.
        }
    }

    private async Task HandleClientAsync(
        TcpClient client,
        ConnectionHandler handler,
        CancellationToken ct)
    {
        try
        {
            using (client)
            using (var stream = client.GetStream())
            {
                var request = await ReadRequestAsync(stream, ct);
                await handler(request, stream, ct);
            }
        }
        catch (Exception)
        {
            // A malformed request or a test that cancels mid-flight is expected in
            // protocol tests; swallow here and let the test assert what it needs.
        }
    }

    /// <summary>
    /// Reads a full client exchange: greeting, method selection, optional RFC 1929
    /// auth, then the CONNECT request. Returns the parsed CONNECT request.
    /// </summary>
    private async Task<ParsedConnectRequest> ReadRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        // Greeting: VER(1), NMETHODS(1), METHODS[NMETHODS]
        var greeting = new byte[2];
        await ReadExactAsync(stream, greeting, ct);
        if (greeting[0] != _expectedVersion)
            throw new InvalidDataException($"Expected SOCKS version {_expectedVersion}, got {greeting[0]:X2}.");

        var methods = new byte[greeting[1]];
        await ReadExactAsync(stream, methods, ct);

        if (!methods.Contains(_methodToSelect))
        {
            await stream.WriteAsync(new[] { _expectedVersion, (byte)0xFF }, ct);
            throw new InvalidOperationException(
                $"Client did not offer the method the test wants to select (0x{_methodToSelect:X2}).");
        }

        await stream.WriteAsync(new[] { _expectedVersion, _methodToSelect }, ct);

        if (_methodToSelect == 0x02)
        {
            await ReadAndReplyAuthAsync(stream, ct);
        }

        // CONNECT request header: VER(1), CMD(1), RSV(1), ATYP(1)
        var request = new byte[4];
        await ReadExactAsync(stream, request, ct);
        if (request[0] != _expectedVersion)
            throw new InvalidDataException($"Expected SOCKS version {_expectedVersion}, got {request[0]:X2}.");
        // The server serves CONNECT (0x01) and, for the UDP ASSOCIATE client
        // tests, UDP ASSOCIATE (0x03).
        if (request[1] is not (0x01 or 0x03))
            throw new InvalidDataException($"Expected CONNECT or UDP ASSOCIATE command, got 0x{request[1]:X2}.");

        var atyp = request[3];
        string host;
        byte[] rawAddress;
        switch (atyp)
        {
            case 0x01: // IPv4
                {
                    var addr = new byte[4];
                    await ReadExactAsync(stream, addr, ct);
                    rawAddress = addr;
                    host = new IPAddress(addr).ToString();
                    break;
                }
            case 0x03: // domain
                {
                    var lenBuf = new byte[1];
                    await ReadExactAsync(stream, lenBuf, ct);
                    var name = new byte[lenBuf[0]];
                    await ReadExactAsync(stream, name, ct);
                    rawAddress = name;
                    host = Encoding.ASCII.GetString(name);
                    break;
                }
            case 0x04: // IPv6
                {
                    var addr = new byte[16];
                    await ReadExactAsync(stream, addr, ct);
                    rawAddress = addr;
                    host = new IPAddress(addr).ToString();
                    break;
                }
            default:
                throw new InvalidDataException($"Unsupported ATYP 0x{atyp:X2}.");
        }

        var portBuf = new byte[2];
        await ReadExactAsync(stream, portBuf, ct);
        var port = (portBuf[0] << 8) | portBuf[1];

        return new ParsedConnectRequest(request[0], request[1], atyp, host, port, rawAddress);
    }

    private async Task ReadAndReplyAuthAsync(NetworkStream stream, CancellationToken ct)
    {
        // RFC 1929: VER(1), ULEN(1), UNAME, PLEN(1), PASSWD
        var authHdr = new byte[2];
        await ReadExactAsync(stream, authHdr, ct);
        if (authHdr[0] != 0x01)
            throw new InvalidDataException($"Expected auth version 1, got {authHdr[0]:X2}.");

        var uname = new byte[authHdr[1]];
        await ReadExactAsync(stream, uname, ct);
        var passHdr = new byte[1];
        await ReadExactAsync(stream, passHdr, ct);
        var pass = new byte[passHdr[0]];
        await ReadExactAsync(stream, pass, ct);

        var username = Encoding.UTF8.GetString(uname);
        var password = Encoding.UTF8.GetString(pass);

        var accepted = _credentialValidator?.Invoke(username, password) ?? true;
        // 0x00 = success, any other value = failure.
        await stream.WriteAsync(new byte[] { 0x01, accepted ? (byte)0x00 : (byte)0x01 }, ct);
        if (!accepted)
            throw new InvalidOperationException("Credentials rejected by test server configuration.");
    }

    /// <summary>
    /// Writes a SOCKS5 reply (success or failure) to the client. For domain
    /// ATYP the bound address is written length-prefixed as RFC 1928 requires.
    /// </summary>
    public static async Task WriteReplyAsync(
        NetworkStream stream,
        byte replyCode,
        byte atyp = 0x01,
        byte[]? boundAddress = null,
        int boundPort = 0,
        CancellationToken ct = default)
    {
        var header = new byte[4];
        header[0] = 0x05;
        header[1] = replyCode;
        header[2] = 0x00;
        header[3] = atyp;
        await stream.WriteAsync(header, ct);

        if (atyp == AtypDomain)
        {
            var addr = boundAddress ?? Array.Empty<byte>();
            if (addr.Length > 255)
                throw new ArgumentException("Domain bound address exceeds 255 bytes.", nameof(boundAddress));
            await stream.WriteAsync(new[] { (byte)addr.Length }, ct);
            await stream.WriteAsync(addr, ct);
        }
        else
        {
            var addr = boundAddress ?? new byte[] { 0, 0, 0, 0 };
            await stream.WriteAsync(addr, ct);
        }

        await stream.WriteAsync(new[] { (byte)(boundPort >> 8), (byte)boundPort }, ct);
    }

    /// <summary>Disposes the listener and cancels all pending connections.</summary>
    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _acceptLoop.GetAwaiter().GetResult(); } catch { }
        try { Task.WaitAll(_connections.ToArray(), TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}