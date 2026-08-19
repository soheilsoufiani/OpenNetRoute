using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Network.Tests.TestInfrastructure;

namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for how the client handles malformed or unexpected server responses
/// (protocol violations). These must surface as <see cref="Socks5Exception"/>
/// with useful messages — never hang, never silently succeed.
/// </summary>
public class Socks5MalformedResponseTests
{
    private static ProxyConfiguration Proxy(int port) => new()
    {
        Host = "127.0.0.1",
        Port = port,
        AuthenticationType = ProxyAuthenticationType.None,
        Enabled = true
    };

    /// <summary>
    /// Runs a server that sends <paramref name="greetingReply"/> bytes after the
    /// greeting and returns the exception the client throws.
    /// </summary>
    private static async Task<Socks5Exception> AssertProtocolFailureAsync(
        byte[] greetingReply)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            using var stream = client.GetStream();
            var greeting = new byte[2];
            await Socks5TestServer.ReadExactAsync(stream, greeting, cts.Token);
            var methods = new byte[greeting[1]];
            await Socks5TestServer.ReadExactAsync(stream, methods, cts.Token);
            await stream.WriteAsync(greetingReply, cts.Token);
            // Keep the connection open briefly so the client can observe the reply.
            await Task.Delay(TimeSpan.FromSeconds(2), cts.Token);
        });

        var client = new Socks5Client(Proxy(((IPEndPoint)listener.LocalEndpoint).Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        cts.Cancel();
        try { await serverTask; } catch { }
        return ex;
    }

    [Fact]
    public async Task WrongVersion_InGreetingReply_Throws()
    {
        // Server replies with version 0x04 instead of 0x05.
        var ex = await AssertProtocolFailureAsync(new byte[] { 0x04, 0x00 });

        Assert.False(ex.IsReplyError);
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnsupportedMethodSelected_Throws()
    {
        // Server selects a method (0x01 = GSSAPI) the client did not offer.
        var ex = await AssertProtocolFailureAsync(new byte[] { 0x05, 0x01 });

        Assert.Contains("unsupported method", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WrongVersion_InConnectReply_Throws()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            // Reply with wrong version 0x04, success code.
            await stream.WriteAsync(new byte[] { 0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct);
        });

        var client = new Socks5Client(Proxy(server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port)).AsTask());

        Assert.False(ex.IsReplyError);
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnsupportedAtyp_InConnectReply_Throws()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            // ATYP 0x09 (unsupported), success code.
            await stream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x09 }, ct);
        });

        var client = new Socks5Client(Proxy(server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port)).AsTask());

        Assert.Contains("address type", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TruncatedConnectReply_Throws()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            // Reply header says success but sends only 3 of 4 header bytes, then EOF.
            await stream.WriteAsync(new byte[] { 0x05, 0x00, 0x00 }, ct);
            // Stream disposed when handler returns → client sees EOF mid-reply.
        });

        var client = new Socks5Client(Proxy(server.Port));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port)).AsTask());

        Assert.False(ex.IsReplyError);
        Assert.Contains("closed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SuccessReply_WithDomainBoundAddress_Parses()
    {
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
            using (var upstreamStream = upstream.GetStream())
            {
                // Success reply with a domain-typed BND.ADDR.
                var header = new byte[] { 0x05, 0x00, 0x00, 0x03, 0x05 };
                var bnd = Encoding.ASCII.GetBytes("proxy");
                var port = new byte[] { 0x04, 0x38 };
                await stream.WriteAsync(header.Concat(bnd).Concat(port).ToArray(), ct);
                await RelayAsync(stream, upstreamStream, ct);
            }
        });

        var client = new Socks5Client(Proxy(server.Port));
        using var connection = await client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port));

        Assert.Equal("proxy", connection.BndAddress);
        Assert.Equal(1080, connection.BndPort);
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
}