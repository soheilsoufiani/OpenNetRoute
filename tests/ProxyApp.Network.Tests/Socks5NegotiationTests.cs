using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Network.Tests.TestInfrastructure;

namespace ProxyApp.Network.Tests;

/// <summary>
/// End-to-end negotiation tests against a real SOCKS5 test server speaking the
/// wire protocol. These exercise actual TCP I/O and the full RFC 1928/RFC 1929
/// state machine.
/// </summary>
public class Socks5NegotiationTests
{
    private static ProxyConfiguration Proxy(
        string host = "127.0.0.1",
        int port = 1080,
        ProxyAuthenticationType auth = ProxyAuthenticationType.None,
        string? username = null,
        string? password = null)
    {
        return new ProxyConfiguration
        {
            Host = host,
            Port = port,
            AuthenticationType = auth,
            Username = username,
            Password = password,
            Enabled = true
        };
    }

    [Fact]
    public async Task ConnectToIpv4Destination_Succeeds_AndStreamIsUsable()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            // The proxy "reaches" the destination by connecting to the echo server
            // and relaying, exactly like a real SOCKS5 server would.
            Assert.Equal(Socks5TestServer.AtypIpv4, request.Atyp);
            Assert.Equal("127.0.0.1", request.Host);
            Assert.Equal(echo.Port, request.Port);

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
            using (var upstreamStream = upstream.GetStream())
            {
                await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01,
                    new byte[] { 0, 0, 0, 0 }, 0, ct);
                await RelayAsync(stream, upstreamStream, ct);
            }
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));
        using var connection = await client.ConnectAsync(
            new Socks5Destination("127.0.0.1", echo.Port));

        // Verify real data flows through the proxied connection (echo).
        var payload = "hello-through-socks5"u8.ToArray();
        await connection.Stream.WriteAsync(payload);
        var reply = new byte[payload.Length];
        await ReadExactlyAsync(connection.Stream, reply, payload.Length);

        Assert.Equal(payload, reply);
    }

    [Fact]
    public async Task Connect_WaitsForFullReply_WithDelayedNonZeroBndPort()
    {
        // Regression for the "CONNECT OK in 0ms" symptom: the client must read
        // the FULL RFC 1928 reply (4-byte header + BND.ADDR + 2-byte BND.PORT)
        // before reporting success — it must NOT treat the first 4 bytes as
        // success and start relaying into a half-negotiated socket.
        //
        // The server delays the reply in two halves and returns a non-zero
        // BND.PORT. If the client returned early, BndPort would be garbage/0
        // (or the relayed data would corrupt the negotiation). It must wait
        // for the complete reply.
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
            using var upstreamStream = upstream.GetStream();

            // Reply in TWO halves with a delay between them — the reply does
            // not arrive in a single read, so a client that returns after the
            // header would observe a missing/zero BND.PORT.
            var header = new byte[] { 0x05, 0x00, 0x00, 0x01 };
            await stream.WriteAsync(header, ct);
            await Task.Delay(120, ct);
            // BND.ADDR 0.0.0.0 + BND.PORT 40000 (0x9C40) — non-zero, so the
            // test can assert the client actually consumed these bytes.
            await stream.WriteAsync(new byte[] { 0, 0, 0, 0, 0x9C, 0x40 }, ct);

            await RelayAsync(stream, upstreamStream, ct);
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));
        using var connection = await client.ConnectAsync(
            new Socks5Destination("127.0.0.1", echo.Port));

        // The full reply was parsed: BND.PORT must be 40000, not 0/garbage.
        Assert.Equal(40000, connection.BndPort);
        Assert.Equal("0.0.0.0", connection.BndAddress);

        // And the stream is usable (echo round-trips) — proving the relay
        // started only AFTER the full reply was consumed.
        var payload = "full-reply-echo"u8.ToArray();
        await connection.Stream.WriteAsync(payload);
        var reply = new byte[payload.Length];
        await ReadExactlyAsync(connection.Stream, reply, payload.Length);
        Assert.Equal(payload, reply);
    }

    [Fact]
    public async Task ConnectToDomainDestination_SendsDomainAtyp()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            // The client sent a domain; the server resolves "localhost" itself.
            Assert.Equal(Socks5TestServer.AtypDomain, request.Atyp);
            Assert.Equal("localhost", request.Host);
            Assert.Equal(echo.Port, request.Port);

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
            using (var upstreamStream = upstream.GetStream())
            {
                await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x03,
                    Encoding.ASCII.GetBytes("localhost"), 0, ct);
                await RelayAsync(stream, upstreamStream, ct);
            }
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));
        using var connection = await client.ConnectAsync(
            new Socks5Destination("localhost", echo.Port));

        var payload = "domain-test"u8.ToArray();
        await connection.Stream.WriteAsync(payload);
        var reply = new byte[payload.Length];
        await ReadExactlyAsync(connection.Stream, reply, payload.Length);

        Assert.Equal(payload, reply);
    }

    [Fact]
    public async Task ConnectToIpv6Destination_Succeeds()
    {
        if (!Socket.OSSupportsIPv6)
            return; // Environment without IPv6 support; skip quietly.

        using var echo = new Ipv6EchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            Assert.Equal(Socks5TestServer.AtypIpv6, request.Atyp);
            Assert.Equal("::1", request.Host);

            using var upstream = new TcpClient(AddressFamily.InterNetworkV6);
            await upstream.ConnectAsync(IPAddress.IPv6Loopback, echo.Port, ct);
            using (var upstreamStream = upstream.GetStream())
            {
                await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x04,
                    IPAddress.IPv6Loopback.GetAddressBytes(), 0, ct);
                await RelayAsync(stream, upstreamStream, ct);
            }
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));
        using var connection = await client.ConnectAsync(
            new Socks5Destination("::1", echo.Port));

        var payload = "ipv6-test"u8.ToArray();
        await connection.Stream.WriteAsync(payload);
        var reply = new byte[payload.Length];
        await ReadExactlyAsync(connection.Stream, reply, payload.Length);

        Assert.Equal(payload, reply);
    }

    [Fact]
    public async Task ServerReply_GeneralFailure_ThrowsWithCode()
    {
        using var server = new Socks5TestServer(async (_, stream, ct) =>
        {
            await Socks5TestServer.WriteReplyAsync(stream, 0x01, 0x01, ct: ct); // 0x01 general failure
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.True(ex.IsReplyError);
        Assert.Equal(Socks5ReplyCode.GeneralFailure, ex.ReplyCode);
    }

    [Fact]
    public async Task ServerReply_HostUnreachable_ThrowsWithCode()
    {
        using var server = new Socks5TestServer(async (_, stream, ct) =>
        {
            await Socks5TestServer.WriteReplyAsync(stream, 0x04, 0x01, ct: ct); // 0x04 host unreachable
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.Equal(Socks5ReplyCode.HostUnreachable, ex.ReplyCode);
    }

    [Fact]
    public async Task ServerReply_ConnectionRefused_ThrowsWithCode()
    {
        using var server = new Socks5TestServer(async (_, stream, ct) =>
        {
            await Socks5TestServer.WriteReplyAsync(stream, 0x05, 0x01, ct: ct); // 0x05 connection refused
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.Equal(Socks5ReplyCode.ConnectionRefused, ex.ReplyCode);
    }

    [Fact]
    public async Task ServerClosesConnection_DuringNegotiation_ThrowsProtocolError()
    {
        using var server = new Socks5TestServer(async (_, stream, ct) =>
        {
            // Server closes the TCP connection without replying.
            await Task.CompletedTask;
        });

        var client = new Socks5Client(Proxy(host: "127.0.0.1", port: server.Port));

        // The server handler returns immediately, which closes the stream; the
        // client reads 0 bytes and must surface a protocol error, not a hang.
        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.False(ex.IsReplyError);
    }

    private static async Task RelayAsync(NetworkStream client, NetworkStream upstream, CancellationToken ct)
    {
        var pump1 = PumpAsync(client, upstream, ct);
        var pump2 = PumpAsync(upstream, client, ct);
        await Task.WhenAll(pump1, pump2);
    }

    private static async Task PumpAsync(Stream src, Stream dst, CancellationToken ct)
    {
        var buffer = new byte[4096];
        while (!ct.IsCancellationRequested)
        {
            var n = await src.ReadAsync(buffer, ct);
            if (n <= 0)
                break;
            await dst.WriteAsync(buffer.AsMemory(0, n), ct);
        }
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int count)
    {
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, count - read));
            if (n <= 0)
                throw new EndOfStreamException();
            read += n;
        }
    }
}