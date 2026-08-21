using System.Net;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Network;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the ferry's client→upstream data relay (Step 3B). These verify
/// that payload bytes are extracted from captured client packets and written to
/// the upstream stream, while pure ACKs are dropped.
/// </summary>
public class TcpFerryDataRelayTests
{
    private static readonly IPAddress ClientIp = IPAddress.Parse("192.168.100.10");
    private static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
    private const ushort ClientPort = 12345;
    private const ushort ServerPort = 80;

    /// <summary>Builds a TcpFerry with a no-op socks5 client and pass-through resolver.</summary>
    private static TcpFerry MakeFerry() =>
        new(new Socks5Client(new ProxyConfiguration
        {
            Host = "127.0.0.1", Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None, Enabled = true
        }));

    /// <summary>Creates a flow in Established state with a MemoryStream as the upstream.</summary>
    private static (FlowState Flow, MemoryStream Upstream) MakeEstablishedFlow(byte[]? synPacket = null)
    {
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Established
        };
        var upstream = new MemoryStream();
        flow.UpstreamStream = upstream;
        return (flow, upstream);
    }

    [Fact]
    public async Task Relay_ClientPayload_WritesToUpstream()
    {
        var ferry = MakeFerry();
        var (flow, upstream) = MakeEstablishedFlow();

        // Build a client data packet with a known payload.
        var payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray();
        var packet = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, payload);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(ClientIp, tuple.SrcIp);
        Assert.Equal(ServerIp, tuple.DstIp);

        await ferry.HandleExistingFlowAsync(flow, packet, (uint)packet.Length, tuple, CancellationToken.None);

        // The payload should have been written to the upstream stream.
        Assert.Equal(payload.Length, flow.ClientBytesSent);
        Assert.Equal(payload, upstream.ToArray());
    }

    [Fact]
    public async Task Relay_PureAck_DoesNotWriteToUpstream()
    {
        var ferry = MakeFerry();
        var (flow, upstream) = MakeEstablishedFlow();

        // Build a pure ACK (no payload, flags=0x10).
        var ackPacket = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, ReadOnlySpan<byte>.Empty);
        // Override flags to ACK (0x10) instead of PSH|ACK (0x18).
        // BuildDataPacket creates PSH|ACK; we need a pure ACK. Let's build manually.
        ackPacket[20 + 13] = 0x10; // ACK only

        Assert.True(TcpPacketParser.TryParse(ackPacket, (uint)ackPacket.Length, out var tuple));
        Assert.Equal(0, TcpPacketParser.GetPayloadLength(ackPacket, (uint)ackPacket.Length, tuple));

        await ferry.HandleExistingFlowAsync(flow, ackPacket, (uint)ackPacket.Length, tuple, CancellationToken.None);

        // No data should have been written.
        Assert.Equal(0, flow.ClientBytesSent);
        Assert.Equal(0, upstream.Length);
    }

    [Fact]
    public async Task Relay_NotEstablished_DoesNothing()
    {
        var ferry = MakeFerry();
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Connecting // not yet established
        };
        var upstream = new MemoryStream();
        flow.UpstreamStream = upstream;

        var payload = "data"u8.ToArray();
        var packet = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, payload);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        await ferry.HandleExistingFlowAsync(flow, packet, (uint)packet.Length, tuple, CancellationToken.None);

        Assert.Equal(0, flow.ClientBytesSent);
        Assert.Equal(0, upstream.Length);
    }

    /// <summary>Builds a client FIN packet (flags=0x11) with the given ack.</summary>
    private static byte[] BuildClientFin(uint ack)
    {
        var packet = TcpPacketBuilder.BuildFin(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, ack);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.True(tuple.IsFin);
        return packet;
    }

    [Fact]
    public async Task Relay_ClientFin_IsNotRelayedToUpstream()
    {
        // Regression: the client's FIN (closing the connection after the last
        // response) must NOT be forwarded to the upstream as payload — the ferry
        // consumes it and only ACKs it so the client's stack completes the close.
        var ferry = MakeFerry();
        var (flow, upstream) = MakeEstablishedFlow();

        var fin = BuildClientFin(ack: 2000);
        Assert.True(TcpPacketParser.TryParse(fin, (uint)fin.Length, out var tuple));
        await ferry.HandleExistingFlowAsync(flow, fin, (uint)fin.Length, tuple, CancellationToken.None);

        Assert.Equal(0, flow.ClientBytesSent);
        Assert.Equal(0, upstream.Length);
    }

    [Fact]
    public async Task Relay_PureAck_RecordsClientAckedUpTo()
    {
        // Regression: pure ACKs carry the client's ACK sequence, which the ferry
        // must record so the deferred server FIN is only sent once the client has
        // accepted all injected data.
        var ferry = MakeFerry();
        var (flow, upstream) = MakeEstablishedFlow();

        var ackPacket = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 305419957, ReadOnlySpan<byte>.Empty);
        ackPacket[20 + 13] = 0x10; // ACK only
        Assert.True(TcpPacketParser.TryParse(ackPacket, (uint)ackPacket.Length, out var tuple));

        await ferry.HandleExistingFlowAsync(flow, ackPacket, (uint)ackPacket.Length, tuple, CancellationToken.None);

        Assert.Equal(0, flow.ClientBytesSent);
        Assert.Equal(305419957u, flow.ClientAckedUpTo);
    }

    [Fact]
    public async Task Relay_ClientBytesSent_TracksExactMultiple()
    {
        var ferry = MakeFerry();
        var (flow, upstream) = MakeEstablishedFlow();

        // Send two data packets.
        var payload1 = "hello"u8.ToArray();
        var packet1 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, payload1);
        Assert.True(TcpPacketParser.TryParse(packet1, (uint)packet1.Length, out var tuple1));
        await ferry.HandleExistingFlowAsync(flow, packet1, (uint)packet1.Length, tuple1, CancellationToken.None);

        var payload2 = "world"u8.ToArray();
        var packet2 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1006, 2000, payload2);
        Assert.True(TcpPacketParser.TryParse(packet2, (uint)packet2.Length, out var tuple2));
        await ferry.HandleExistingFlowAsync(flow, packet2, (uint)packet2.Length, tuple2, CancellationToken.None);

        Assert.Equal(10, flow.ClientBytesSent);
        Assert.Equal(payload1.Concat(payload2).ToArray(), upstream.ToArray());
    }
}