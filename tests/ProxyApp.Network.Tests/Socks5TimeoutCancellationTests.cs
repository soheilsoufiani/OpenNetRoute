using System.Net;
using System.Net.Sockets;
using ProxyApp.Core.Configuration;
using ProxyApp.Network.Tests.TestInfrastructure;

namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for timeout and cancellation behavior of the SOCKS5 client.
/// </summary>
public class Socks5TimeoutCancellationTests
{
    private static ProxyConfiguration Proxy(int port) => new()
    {
        Host = "127.0.0.1",
        Port = port,
        AuthenticationType = ProxyAuthenticationType.None,
        Enabled = true
    };

    [Fact]
    public async Task ConnectTimeout_WhenServerStalls_ThrowsTimeout()
    {
        // A server that accepts the TCP connection and then never responds.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var serverCts = new CancellationTokenSource();
        var serverTask = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(serverCts.Token);
                using var stream = client.GetStream();
                // Read (and discard) the greeting so the client is blocked waiting
                // for a method reply that never comes.
                var greeting = new byte[2];
                await Socks5TestServer.ReadExactAsync(stream, greeting, serverCts.Token);
                var methods = new byte[greeting[1]];
                await Socks5TestServer.ReadExactAsync(stream, methods, serverCts.Token);
                await Task.Delay(Timeout.InfiniteTimeSpan, serverCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Test finished; server torn down.
            }
        });

        var client = new Socks5Client(Proxy(((IPEndPoint)listener.LocalEndpoint).Port),
            connectTimeout: TimeSpan.FromMilliseconds(250));

        // The client must surface a TimeoutException, not hang.
        await Assert.ThrowsAsync<TimeoutException>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        serverCts.Cancel();
        try { await serverTask; } catch { }
    }

    [Fact]
    public async Task CallerCancellation_CancelsConnect()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var serverCts = new CancellationTokenSource();
        var serverTask = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(serverCts.Token);
                using var stream = client.GetStream();
                var greeting = new byte[2];
                await Socks5TestServer.ReadExactAsync(stream, greeting, serverCts.Token);
                var methods = new byte[greeting[1]];
                await Socks5TestServer.ReadExactAsync(stream, methods, serverCts.Token);
                await Task.Delay(Timeout.InfiniteTimeSpan, serverCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Test finished.
            }
        });

        var client = new Socks5Client(Proxy(((IPEndPoint)listener.LocalEndpoint).Port),
            connectTimeout: TimeSpan.FromSeconds(30));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        // Caller cancellation must surface as OperationCanceledException (not
        // TimeoutException) so the caller can distinguish "I cancelled" from
        // "we timed out".
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80), cts.Token).AsTask());

        serverCts.Cancel();
        try { await serverTask; } catch { }
    }

    [Fact]
    public async Task ConnectionRefused_ByProxy_ThrowsSocketError()
    {
        // Point the client at a port with no listener → TCP connect fails.
        using var deadListener = new TcpListener(IPAddress.Loopback, 0);
        deadListener.Start();
        var deadPort = ((IPEndPoint)deadListener.LocalEndpoint).Port;
        deadListener.Stop(); // Port released; nothing listening now.

        var client = new Socks5Client(Proxy(deadPort));

        // The client must surface the connection failure, not swallow it.
        await Assert.ThrowsAsync<SocketException>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());
    }

    [Fact]
    public async Task NoProxyHostConfigured_ThrowsInvalidOperation()
    {
        var client = new Socks5Client(new ProxyConfiguration
        {
            Host = "",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());
    }

    [Fact]
    public async Task ProxyPortOutOfRange_ThrowsInvalidOperation()
    {
        var client = new Socks5Client(new ProxyConfiguration
        {
            Host = "127.0.0.1",
            Port = 0,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());
    }
}