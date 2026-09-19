using System.Net;
using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.Network.Tests.TestInfrastructure;

namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for <see cref="Socks5UdpAssociateClient"/> (RFC 1928 §7) against a
/// real loopback SOCKS5 + UDP relay peer: association, datagram framing,
/// DNS-relay round trip, concurrency, timeout, and cancellation.
/// </summary>
public class Socks5UdpAssociateTests
{
    private static ProxyConfiguration ProxyConfig(int port) => new()
    {
        Name = "test",
        Host = "127.0.0.1",
        Port = port,
        Protocol = ProxyProtocol.Socks5,
        AuthenticationType = ProxyAuthenticationType.None,
        Enabled = true
    };

    /// <summary>A plausible DNS query for "example.com" A record, id 0x1234.</summary>
    private static byte[] DnsQuery(byte idHi = 0x12, byte idLo = 0x34)
    {
        // header(12) | qname example.com | qtype A | qclass IN
        byte[] q = [0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
                    0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
                    0x00, 0x01, 0x00, 0x01];
        var payload = new byte[12 + q.Length];
        payload[0] = idHi; payload[1] = idLo;
        payload[2] = 0x01; payload[3] = 0x00; // RD
        payload[5] = 0x01;                    // QDCOUNT=1
        q.CopyTo(payload, 12);
        return payload;
    }

    private static async Task<Socks5UdpAssociateClient> StartClientAsync(int controlPort)
    {
        var client = new Socks5UdpAssociateClient(ProxyConfig(controlPort));
        await client.StartAsync();
        return client;
    }

    [Fact]
    public async Task Associate_ThenRelay_DnsQuery_ReturnsDnsReply()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        Assert.True(client.IsAssociated);

        var result = await client.RelayAsync(DnsQuery(), IPAddress.Parse("192.168.100.1"), 53);

        Assert.Equal(0x12, result.DnsPayload[0]);
        Assert.Equal(0x34, result.DnsPayload[1]);
        // QR bit set (response) — the peer's DNS-style reply.
        Assert.True((result.DnsPayload[2] & 0x80) != 0);
        Assert.Equal(1, server.DatagramsReceived);
    }

    [Fact]
    public async Task Relay_IsCorrelatedByDnsTransactionId()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        var q1 = client.RelayAsync(DnsQuery(0x11, 0x11), IPAddress.Parse("192.168.100.1"), 53);
        var q2 = client.RelayAsync(DnsQuery(0x22, 0x22), IPAddress.Parse("192.168.100.1"), 53);
        var r1 = await q1;
        var r2 = await q2;

        Assert.Equal(0x11, r1.DnsPayload[0]);
        Assert.Equal(0x22, r2.DnsPayload[0]);
    }

    [Fact]
    public async Task Relay_WithoutAssociate_Throws()
    {
        var client = new Socks5UdpAssociateClient(ProxyConfig(1)); // nothing started
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.RelayAsync(DnsQuery(), IPAddress.Parse("192.168.100.1"), 53));
    }

    /// <summary>A syntactically valid DNS payload with NO question (QDCOUNT=0) — the echo relay drops it.</summary>
    private static byte[] DnsPayloadNoQuestion(byte idHi, byte idLo)
    {
        var payload = new byte[12];
        payload[0] = idHi;
        payload[1] = idLo;
        return payload;
    }

    [Fact]
    public async Task Relay_TimesOut_WhenNoReplyArrives()
    {
        // A control server that completes the ASSOCIATE, but a payload the UDP
        // relay drops (QDCOUNT=0, never answered) — the client must hit its
        // timeout, not hang.
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.RelayAsync(
                DnsPayloadNoQuestion(0x7F, 0x7F),
                IPAddress.Parse("192.168.100.1"), 53,
                timeout: TimeSpan.FromMilliseconds(300)));
    }

    [Fact]
    public async Task Relay_Honors_Cancellation()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        using var cts = new CancellationTokenSource();
        var task = client.RelayAsync(
            DnsQuery(0x55, 0x55), IPAddress.Parse("192.168.100.1"), 53,
            timeout: null, cancellationToken: cts.Token);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    [Fact]
    public async Task RelayAsync_ShortPayload_Throws()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayAsync(new byte[8], IPAddress.Parse("192.168.100.1"), 53));
    }

    [Fact]
    public async Task Relay_SupportsStunCorrelation_12ByteTransactionId()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        // STUN Binding Request: type 0x0001, length 0, magic cookie, txid.
        var request = new byte[20];
        request[1] = 0x01;               // Binding Request
        request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42; // magic
        for (var i = 8; i < 20; i++) request[i] = (byte)(i * 7); // txid bytes

        var result = await client.RelayAsync(
            request, IPAddress.Parse("192.168.100.1"), 3478,
            correlationBytes: 12);

        // Binding Success Response echoes the transaction ID verbatim.
        Assert.Equal(0x01, result.DnsPayload[0]);
        Assert.Equal(0x01, result.DnsPayload[1]);
        for (var i = 8; i < 20; i++)
            Assert.Equal((byte)(i * 7), result.DnsPayload[i]);
    }

    [Fact]
    public async Task StartAsync_IsIdempotent()
    {
        using var server = new Socks5UdpAssociateTestServer();
        using var client = await StartClientAsync(server.ControlPort);

        await client.StartAsync(); // second call is a no-op, not a second association

        Assert.True(client.IsAssociated);
    }
}
