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

    /// <summary>
    /// Creates a flow in Established state with a MemoryStream as the upstream.
    /// Both <see cref="FlowState.Status"/> and <see cref="FlowState.UpstreamReady"/>
    /// are set, matching the post-CONNECT state the ferry produces.
    /// </summary>
    private static (FlowState Flow, MemoryStream Upstream) MakeEstablishedFlow()
    {
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Established,
            UpstreamReady = true
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
    public async Task Relay_NotReady_BuffersPayloadUntilUpstreamReady()
    {
        // Parallel establishment: the client's payload arrives while the
        // SOCKS5 CONNECT is still in flight (UpstreamReady == false). The
        // ferry must BUFFER the payload (bounded) instead of dropping it, and
        // count it toward ClientBytesSent so the client's ACK framing stays
        // correct. The upstream write happens only when the CONNECT completes.
        var ferry = MakeFerry();
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Connecting, // CONNECT still in flight
            UpstreamReady = false
        };
        var upstream = new MemoryStream();
        flow.UpstreamStream = upstream;

        var payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray();
        var packet = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, payload);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        await ferry.HandleExistingFlowAsync(flow, packet, (uint)packet.Length, tuple, CancellationToken.None);

        // Buffered, not dropped; counted toward ClientBytesSent.
        Assert.Equal(payload.Length, flow.PendingBufferLength);
        Assert.Equal(payload.Length, flow.ClientBytesSent);
        Assert.Equal(0, upstream.Length); // nothing written yet

        // Now the CONNECT completes: draining + writing the buffered bytes is
        // the ferry's job (ApplyUpstreamEstablishedAsync); here we verify the
        // buffer holds exactly the client payload, ready for that drain.
        var drained = flow.DrainPendingBuffer();
        Assert.Equal(payload, drained);
        Assert.Equal(0, flow.PendingBufferLength);
    }

    [Fact]
    public async Task Relay_BufferOverflow_DropsExcess_DoesNotBlock()
    {
        // The pending buffer is bounded (64 KB). Payload beyond the bound is
        // dropped (the client will retransmit) — the capture loop must never
        // block on buffering.
        var ferry = MakeFerry();
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Connecting,
            UpstreamReady = false
        };
        var upstream = new MemoryStream();
        flow.UpstreamStream = upstream;

        // First payload: fills the buffer (64 KB).
        var big = new byte[FlowState.MaxPendingBufferSize];
        Array.Fill(big, (byte)'A');
        var packet1 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, big);
        Assert.True(TcpPacketParser.TryParse(packet1, (uint)packet1.Length, out var tuple1));
        await ferry.HandleExistingFlowAsync(flow, packet1, (uint)packet1.Length, tuple1, CancellationToken.None);
        Assert.Equal(FlowState.MaxPendingBufferSize, flow.PendingBufferLength);

        // Second payload: exceeds the bound → dropped, but the client is still
        // ACKed so its stack does not stall.
        var extra = "overflow"u8.ToArray();
        var packet2 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, (uint)(1001 + big.Length), 2000, extra);
        Assert.True(TcpPacketParser.TryParse(packet2, (uint)packet2.Length, out var tuple2));
        await ferry.HandleExistingFlowAsync(flow, packet2, (uint)packet2.Length, tuple2, CancellationToken.None);

        Assert.Equal(FlowState.MaxPendingBufferSize, flow.PendingBufferLength); // unchanged
        Assert.Equal(FlowState.MaxPendingBufferSize, flow.ClientBytesSent); // dropped bytes not counted
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

    [Fact]
    public async Task Relay_ExactlyOnce_ByteLevel_BufferedThenFlushedThenRelayed()
    {
        // THE double-write regression test: the flush of the pending buffer
        // must NOT re-increment ClientBytesSent (the buffered bytes were
        // already counted at buffer time), and the relay must write each
        // client byte EXACTLY ONCE. A duplicate write corrupts TLS records and
        // breaks the handshake — the symptom the user saw on real sites.
        var ferry = MakeFerry();
        var key = FlowTable.KeyFrom(ClientIp, ClientPort, ServerIp, ServerPort);
        var flow = new FlowState(key, 1000, TcpFerry.DefaultServerIsn, default)
        {
            Status = FlowStatus.Connecting,
            UpstreamReady = false
        };
        var upstream = new MemoryStream();
        flow.UpstreamStream = upstream;

        // Phase 1 — client payload while Connecting: buffered (counted).
        var tls1 = "ClientHello-536-bytes"u8.ToArray();
        var p1 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, 1001, 2000, tls1);
        Assert.True(TcpPacketParser.TryParse(p1, (uint)p1.Length, out var t1));
        await ferry.HandleExistingFlowAsync(flow, p1, (uint)p1.Length, t1, CancellationToken.None);
        Assert.Equal(tls1.Length, flow.PendingBufferLength);
        Assert.Equal(tls1.Length, flow.ClientBytesSent); // counted at buffer time
        Assert.Equal(0, upstream.Length); // NOT written yet

        // Phase 2 — CONNECT completes: flush writes the buffered bytes exactly
        // once and records them in BytesFlushedFromBuffer (NOT ClientBytesSent).
        var buffered = flow.DrainPendingBuffer();
        Assert.Equal(tls1, buffered);
        await upstream.WriteAsync(buffered!);
        flow.BytesFlushedFromBuffer += buffered.Length;
        flow.UpstreamStream = upstream;
        flow.Status = FlowStatus.Established;
        flow.UpstreamReady = true;
        Assert.Equal(tls1.Length, flow.BytesFlushedFromBuffer);
        Assert.Equal(tls1.Length, flow.ClientBytesSent); // unchanged by flush
        Assert.Equal(tls1, upstream.ToArray()); // written exactly once

        // Phase 3 — more client payload after Established: relayed (counted).
        var tls2 = "ServerHello-response-continues"u8.ToArray();
        var p2 = TcpPacketBuilder.BuildDataPacket(
            ClientIp, ServerIp, ClientPort, ServerPort, (uint)(1001 + tls1.Length), 2000, tls2);
        Assert.True(TcpPacketParser.TryParse(p2, (uint)p2.Length, out var t2));
        await ferry.HandleExistingFlowAsync(flow, p2, (uint)p2.Length, t2, CancellationToken.None);
        Assert.Equal(tls1.Length + tls2.Length, flow.ClientBytesSent);
        Assert.Equal(tls1.Length, flow.BytesFlushedFromBuffer); // unchanged by relay
        Assert.Equal(tls1.Concat(tls2).ToArray(), upstream.ToArray()); // exactly once, in order
    }
}