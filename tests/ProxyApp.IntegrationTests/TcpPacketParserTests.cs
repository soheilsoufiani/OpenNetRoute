using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the IPv4/TCP packet parser.
/// </summary>
public class TcpPacketParserTests
{
    [Fact]
    public void TryParse_ParsesARealSyn()
    {
        // Build a SYN packet the way the builder does, then parse it back.
        var serverIp = IPAddress.Parse("8.8.8.8");
        var clientIp = IPAddress.Parse("192.168.100.10");
        var packet = TcpPacketBuilder.BuildSynAck(serverIp, clientIp, 80, 12345, 0x12345678, 0xABCDEF01);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        // The built packet is server→client: src = server, dst = client.
        Assert.Equal(serverIp, tuple.SrcIp);
        Assert.Equal(clientIp, tuple.DstIp);
        Assert.Equal(80, tuple.SrcPort);
        Assert.Equal(12345, tuple.DstPort);
        Assert.True(tuple.IsSyn);
        Assert.True(tuple.IsAck);   // SYN|ACK
        Assert.Equal(0x12345678u, tuple.Seq);
        Assert.Equal(0xABCDEF01u + 1, tuple.Ack);
        Assert.Equal(20, tuple.TcpHeaderLen);
        Assert.False(tuple.IsPureSyn); // SYN|ACK is not a pure SYN
    }

    [Fact]
    public void TryParse_RejectsNonIpv4()
    {
        var packet = new byte[40];
        packet[0] = 0x60; // IPv6 version nibble
        Assert.False(TcpPacketParser.TryParse(packet, (uint)packet.Length, out _));
    }

    [Fact]
    public void TryParse_RejectsNonTcp()
    {
        var packet = new byte[40];
        packet[0] = 0x45;
        packet[9] = 17; // UDP
        Assert.False(TcpPacketParser.TryParse(packet, (uint)packet.Length, out _));
    }

    [Fact]
    public void TryParse_RejectsTooShort()
    {
        var packet = new byte[10];
        Assert.False(TcpPacketParser.TryParse(packet, (uint)packet.Length, out _));
    }

    [Fact]
    public void GetPayloadLength_MeasuresDataPacket()
    {
        byte[] payload = { 1, 2, 3, 4, 5 };
        var packet = TcpPacketBuilder.BuildDataPacket(
            IPAddress.Parse("8.8.8.8"), IPAddress.Parse("192.168.100.10"),
            80, 12345, 0x12345679, 0xABCDEF02, payload);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(5, TcpPacketParser.GetPayloadLength(packet, (uint)packet.Length, tuple));
    }

    [Fact]
    public void GetPayloadLength_SynAckIsZero()
    {
        var packet = TcpPacketBuilder.BuildSynAck(
            IPAddress.Parse("8.8.8.8"), IPAddress.Parse("192.168.100.10"), 80, 12345, 0x12345678, 0xABCDEF01);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(0, TcpPacketParser.GetPayloadLength(packet, (uint)packet.Length, tuple));
    }
}
