using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the crafted-packet builder. These verify the packet bytes produced
/// by the E5b/E6-validated semantics: SYN-ACK with server ISN S1 and ack=C+1;
/// data starting at S1+1; RST; correct header layout and checksums.
/// </summary>
public class TcpPacketBuilderTests
{
    private static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
    private static readonly IPAddress ClientIp = IPAddress.Parse("192.168.100.10");
    private const ushort ServerPort = 80;
    private const ushort ClientPort = 12345;
    private const uint ServerIsn = 0x12345678;
    private const uint ClientIsn = 0xABCDEF01;

    [Fact]
    public void BuildSynAck_HasCorrectHeaderAndSeqAck()
    {
        var packet = TcpPacketBuilder.BuildSynAck(ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn, ClientIsn);

        Assert.Equal(40, packet.Length);
        // IPv4 header.
        Assert.Equal(0x45, packet[0]);          // v4, IHL 5
        Assert.Equal(40, (packet[2] << 8) | packet[3]); // total length
        Assert.Equal(64, packet[8]);            // TTL
        Assert.Equal(6, packet[9]);             // TCP
        Assert.Equal(ServerIp.GetAddressBytes(), packet[12..16]);
        Assert.Equal(ClientIp.GetAddressBytes(), packet[16..20]);

        // TCP header.
        int tcp = 20;
        Assert.Equal(ServerPort, (ushort)((packet[tcp] << 8) | packet[tcp + 1]));
        Assert.Equal(ClientPort, (ushort)((packet[tcp + 2] << 8) | packet[tcp + 3]));
        Assert.Equal(ServerIsn, BigEndianUint(packet, tcp + 4));   // seq = S1
        Assert.Equal(ClientIsn + 1, BigEndianUint(packet, tcp + 8)); // ack = C+1
        Assert.Equal(0x12, packet[tcp + 13]);   // SYN|ACK
    }

    [Fact]
    public void BuildDataPacket_StartsAtSeqPlusOne_AndCarriesPayload()
    {
        byte[] payload = { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"
        // First data byte is at seq = S1 + 1 (SYN-ACK consumed S1).
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1, payload);

        Assert.Equal(40 + payload.Length, packet.Length);
        int tcp = 20;
        Assert.Equal(ServerIsn + 1, BigEndianUint(packet, tcp + 4)); // seq = S1+1
        Assert.Equal(ClientIsn + 1, BigEndianUint(packet, tcp + 8)); // ack = C+1
        Assert.Equal(0x18, packet[tcp + 13]);  // PSH|ACK
        // Payload at the end.
        Assert.Equal(payload, packet[40..]);
    }

    [Fact]
    public void BuildRst_HasRstFlag()
    {
        var packet = TcpPacketBuilder.BuildRst(ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn, ClientIsn);

        Assert.Equal(40, packet.Length);
        Assert.Equal(0x04, packet[20 + 13]); // RST
        Assert.Equal(ServerIsn, BigEndianUint(packet, 20 + 4));
        Assert.Equal(ClientIsn, BigEndianUint(packet, 20 + 8));
    }

    [Fact]
    public void BuildAck_HasAckFlag_AndCorrectSeqAck()
    {
        var packet = TcpPacketBuilder.BuildAck(ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1 + 71);

        Assert.Equal(40, packet.Length);
        Assert.Equal(0x10, packet[20 + 13]); // ACK only
        Assert.Equal(ServerIp.GetAddressBytes(), packet[12..16]);
        Assert.Equal(ClientIp.GetAddressBytes(), packet[16..20]);
        Assert.Equal(ServerIsn + 1, BigEndianUint(packet, 20 + 4));      // seq = S1+1 (no data)
        Assert.Equal(ClientIsn + 1 + 71, BigEndianUint(packet, 20 + 8)); // ack = C+1+sent
        Assert.Equal(0x7210, (ushort)((packet[20 + 14] << 8) | packet[20 + 15])); // window
    }

    [Fact]
    public void BuildFin_HasFinAckFlags_AndHeader()
    {
        var packet = TcpPacketBuilder.BuildFin(ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1);

        Assert.Equal(40, packet.Length);
        Assert.Equal(0x11, packet[20 + 13]); // FIN|ACK
        Assert.Equal(ServerIp.GetAddressBytes(), packet[12..16]);
        Assert.Equal(ClientIp.GetAddressBytes(), packet[16..20]);
        Assert.Equal(ServerIsn + 1, BigEndianUint(packet, 20 + 4));
        Assert.Equal(ClientIsn + 1, BigEndianUint(packet, 20 + 8));
    }

    [Fact]
    public void BuildDataPacket_EmptyPayload_IsHeaderOnly()
    {
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1, ReadOnlySpan<byte>.Empty);

        Assert.Equal(40, packet.Length);
        Assert.Equal(0x18, packet[20 + 13]);
    }

    [Fact]
    public void BuildDataPacket_AdvertisesNonZeroWindow()
    {
        // Regression: the data packet must advertise a non-zero window (E6 used
        // 0x7210). A window of 0 tells the client the server cannot accept more
        // data, which can stall the client's processing of the response.
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1, "OK"u8.ToArray());

        var window = (ushort)((packet[20 + 14] << 8) | packet[20 + 15]);
        Assert.Equal(0x7210, window);
    }

    [Fact]
    public void BuildDataPacket_WithFinFlag_SetsFinPshAck()
    {
        // Regression: the final data packet must carry the server's close
        // (FIN|PSH|ACK = 0x19) so the client completes the connection close
        // without needing a separate close-packet injection (which WinDivert
        // rejects with error 6 after the client has sent its own FIN).
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1,
            "OK"u8.ToArray(), setFin: true);

        Assert.Equal(0x19, packet[20 + 13]); // FIN|PSH|ACK
    }

    [Fact]
    public void BuildDataPacket_WithoutFinFlag_IsPshAck()
    {
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, ServerPort, ClientPort, ServerIsn + 1, ClientIsn + 1,
            "OK"u8.ToArray(), setFin: false);

        Assert.Equal(0x18, packet[20 + 13]); // PSH|ACK
    }

    private static uint BigEndianUint(byte[] p, int offset)
        => ((uint)p[offset] << 24) | ((uint)p[offset + 1] << 16) |
           ((uint)p[offset + 2] << 8) | p[offset + 3];
}
