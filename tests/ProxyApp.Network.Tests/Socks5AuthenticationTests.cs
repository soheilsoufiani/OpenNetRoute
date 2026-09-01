using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Network.Tests.TestInfrastructure;

namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for RFC 1929 username/password authentication, exercised against a real
/// SOCKS5 test server that selects the 0x02 method.
/// </summary>
public class Socks5AuthenticationTests
{
    private static ProxyConfiguration Proxy(
        int port,
        string? username,
        string? password) => new()
        {
            Host = "127.0.0.1",
            Port = port,
            AuthenticationType = ProxyAuthenticationType.UsernamePassword,
            Username = username,
            Password = password,
            Enabled = true
        };

    [Fact]
    public async Task ValidCredentials_Authenticate_AndConnect()
    {
        string? seenUsername = null;
        string? seenPassword = null;

        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(
            async (request, stream, ct) =>
            {
                using var upstream = new TcpClient();
                await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
                using (var upstreamStream = upstream.GetStream())
                {
                    await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01,
                        new byte[] { 0, 0, 0, 0 }, 0, ct);
                    await RelayAsync(stream, upstreamStream, ct);
                }
            },
            methodToSelect: 0x02,
            credentialValidator: (user, pass) =>
            {
                seenUsername = user;
                seenPassword = pass;
                return user == "alice" && pass == "secret";
            });

        var client = new Socks5Client(Proxy(server.Port, "alice", "secret"));
        using var connection = await client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port));

        // Verify the server actually received the credentials.
        Assert.Equal("alice", seenUsername);
        Assert.Equal("secret", seenPassword);

        var payload = "auth-ok"u8.ToArray();
        await connection.Stream.WriteAsync(payload);
        var reply = new byte[payload.Length];
        await ReadExactlyAsync(connection.Stream, reply, payload.Length);
        Assert.Equal(payload, reply);
    }

    [Fact]
    public async Task EmptyPassword_Authenticates()
    {
        // RFC 1929 permits an empty password (PLEN = 0).
        using var echo = new LoopbackEchoServer();
        using var server = new Socks5TestServer(
            async (request, stream, ct) =>
            {
                using var upstream = new TcpClient();
                await upstream.ConnectAsync(IPAddress.Loopback, echo.Port, ct);
                using (var upstreamStream = upstream.GetStream())
                {
                    await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01,
                        new byte[] { 0, 0, 0, 0 }, 0, ct);
                    await RelayAsync(stream, upstreamStream, ct);
                }
            },
            methodToSelect: 0x02,
            credentialValidator: (user, pass) => user == "bob" && pass == "");

        var client = new Socks5Client(Proxy(server.Port, "bob", ""));
        using var connection = await client.ConnectAsync(new Socks5Destination("127.0.0.1", echo.Port));
        Assert.NotNull(connection.Stream);
    }

    [Fact]
    public async Task InvalidCredentials_ThrowProtocolError()
    {
        using var server = new Socks5TestServer(
            async (_, stream, ct) =>
            {
                // Server rejects at the RFC 1929 layer before the CONNECT request;
                // the client should never reach this handler.
                throw new InvalidOperationException("Client should have failed at auth.");
            },
            methodToSelect: 0x02,
            credentialValidator: (_, _) => false);

        var client = new Socks5Client(Proxy(server.Port, "alice", "wrong"));

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.Contains("credentials", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ServerRejectsAllMethods_Throws()
    {
        // A server that replies 0xFF (no acceptable method).
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
            await stream.WriteAsync(new byte[] { 0x05, 0xFF }, cts.Token); // no acceptable method
        });

        var client = new Socks5Client(new ProxyConfiguration
        {
            Host = "127.0.0.1",
            Port = ((IPEndPoint)listener.LocalEndpoint).Port,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        var ex = await Assert.ThrowsAsync<Socks5Exception>(
            () => client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask());

        Assert.Contains("rejected all offered authentication methods", ex.Message);
        await serverTask;
    }

    [Fact]
    public async Task NoAuthentication_DoesNotOfferUsernamePassword_WhenConfiguredForNone()
    {
        // With AuthenticationType.None, the client must offer only method 0x00.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        byte[]? receivedMethods = null;
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            using var stream = client.GetStream();
            var greeting = new byte[2];
            await Socks5TestServer.ReadExactAsync(stream, greeting, cts.Token);
            receivedMethods = new byte[greeting[1]];
            await Socks5TestServer.ReadExactAsync(stream, receivedMethods, cts.Token);
            await stream.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            // Read the CONNECT request the client sends next, handling its ATYP.
            var request = new byte[4];
            await Socks5TestServer.ReadExactAsync(stream, request, cts.Token);
            switch (request[3])
            {
                case 0x01:
                    await Socks5TestServer.ReadExactAsync(stream, new byte[4], cts.Token); // IPv4
                    break;
                case 0x03:
                    {
                        var len = new byte[1];
                        await Socks5TestServer.ReadExactAsync(stream, len, cts.Token);
                        await Socks5TestServer.ReadExactAsync(stream, new byte[len[0]], cts.Token); // domain
                        break;
                    }
                case 0x04:
                    await Socks5TestServer.ReadExactAsync(stream, new byte[16], cts.Token); // IPv6
                    break;
                default:
                    throw new InvalidOperationException($"Unexpected ATYP 0x{request[3]:X2}.");
            }
            await Socks5TestServer.ReadExactAsync(stream, new byte[2], cts.Token); // port

            // Send a success reply, then hold the connection open briefly so the
            // client can finish parsing the reply before the stream is closed.
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, ct: cts.Token);
            await Task.Delay(TimeSpan.FromMilliseconds(300), cts.Token);
        });

        var client = new Socks5Client(new ProxyConfiguration
        {
            Host = "127.0.0.1",
            Port = ((IPEndPoint)listener.LocalEndpoint).Port,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        await client.ConnectAsync(new Socks5Destination("127.0.0.1", 80)).AsTask();
        await serverTask;

        Assert.NotNull(receivedMethods);
        Assert.Equal(new byte[] { 0x00 }, receivedMethods);
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