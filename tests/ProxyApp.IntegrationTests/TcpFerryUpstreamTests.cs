using System.Net;
using System.Net.Sockets;
using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.Network.Tests.TestInfrastructure;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the ferry's SOCKS5 upstream connection (Step 3A): establishing the
/// upstream leg, handling failure, timeout, and cancellation. These exercise the
/// <see cref="TcpFerry.EstablishUpstreamAsync"/> helper against a real local
/// SOCKS5 test server — no WinDivert handle or elevation required.
/// </summary>
public class TcpFerryUpstreamTests
{
    private static ProxyConfiguration Proxy(int port) => new()
    {
        Host = "127.0.0.1",
        Port = port,
        AuthenticationType = ProxyAuthenticationType.None,
        Enabled = true
    };

    /// <summary>A local HTTP endpoint that the "destination" resolves to via the proxy.</summary>
    private static async Task<(LoopbackEchoServer Echo, Socks5TestServer Proxy)> StartUpstreamChainAsync()
    {
        var echo = new LoopbackEchoServer();
        var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            // The proxy connects to the echo server as the destination.
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            // Keep the connection open so the client (ferry) sees an established stream.
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        });
        return (echo, proxy);
    }

    [Fact]
    public async Task EstablishUpstream_Succeeds_WhenProxyAccepts()
    {
        var (echo, proxy) = await StartUpstreamChainAsync();
        using (echo)
        using (proxy)
        {
            var ferry = new TcpFerry(new Socks5Client(Proxy(proxy.Port)));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            var connection = await ferry.EstablishUpstreamAsync(
                new Socks5Destination("127.0.0.1", echo.Port), cts.Token);

            Assert.NotNull(connection);
            Assert.NotNull(connection!.Stream);
            connection.Dispose();
        }
    }

    [Fact]
    public async Task EstablishUpstream_ReturnsNull_WhenProxyRejects()
    {
        // A proxy that replies with "connection refused" (0x05).
        using var proxy = new Socks5TestServer(async (_, stream, ct) =>
        {
            await Socks5TestServer.WriteReplyAsync(stream, 0x05, 0x01, ct: ct);
        });

        var ferry = new TcpFerry(new Socks5Client(Proxy(proxy.Port)));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var connection = await ferry.EstablishUpstreamAsync(
            new Socks5Destination("127.0.0.1", 80), cts.Token);

        Assert.Null(connection);
    }

    [Fact]
    public async Task EstablishUpstream_ReturnsNull_WhenProxyUnreachable()
    {
        // Point the SOCKS5 client at a closed port.
        using var deadListener = new TcpListener(IPAddress.Loopback, 0);
        deadListener.Start();
        var deadPort = ((IPEndPoint)deadListener.LocalEndpoint).Port;
        deadListener.Stop();

        var ferry = new TcpFerry(new Socks5Client(Proxy(deadPort)));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var connection = await ferry.EstablishUpstreamAsync(
            new Socks5Destination("127.0.0.1", 80), cts.Token);

        Assert.Null(connection);
    }

    [Fact]
    public async Task EstablishUpstream_ReturnsNull_OnCancellation()
    {
        using var proxy = new Socks5TestServer(async (_, stream, ct) =>
        {
            // Never reply; the ferry's cancellation should abort the connect.
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        });

        var ferry = new TcpFerry(new Socks5Client(Proxy(proxy.Port)));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        var connection = await ferry.EstablishUpstreamAsync(
            new Socks5Destination("127.0.0.1", 80), cts.Token);

        Assert.Null(connection);
    }

    [Fact]
    public void Constructor_NullSocks5Client_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TcpFerry(null!));
    }

    // ── Upstream-EOF close policy (the recv=0 hang) ──

    [Fact]
    public void ShouldResetOnUpstreamEof_ZeroBytesReceived_ClientSentData_Resets()
    {
        // The user's real-browser failure: the client sent its TLS ClientHello
        // (197/303 bytes) but the upstream returned NOTHING and EOF'd. A
        // graceful FIN|ACK would make the browser wait forever; it must be RST.
        Assert.True(TcpFerry.ShouldResetOnUpstreamEof(clientBytesRecv: 0, clientBytesSent: 197));
        Assert.True(TcpFerry.ShouldResetOnUpstreamEof(clientBytesRecv: 0, clientBytesSent: 303));
    }

    [Fact]
    public void ShouldResetOnUpstreamEof_DataReceived_DoesNotReset()
    {
        // The upstream delivered data before closing (e.g. Google/Microsoft
        // flows with recv=4533). This is a clean server-initiated close →
        // graceful FIN|ACK is correct.
        Assert.False(TcpFerry.ShouldResetOnUpstreamEof(clientBytesRecv: 4533, clientBytesSent: 2094));
        Assert.False(TcpFerry.ShouldResetOnUpstreamEof(clientBytesRecv: 1, clientBytesSent: 100));
    }

    [Fact]
    public void ShouldResetOnUpstreamEof_NothingSentByClient_DoesNotReset()
    {
        // The client sent nothing and the upstream closed — an idle
        // server-initiated close (e.g. server timed out an idle connection).
        // FIN|ACK is correct here.
        Assert.False(TcpFerry.ShouldResetOnUpstreamEof(clientBytesRecv: 0, clientBytesSent: 0));
    }
}
