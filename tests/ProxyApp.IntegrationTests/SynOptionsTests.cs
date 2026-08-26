using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for SYN option parsing (MSS, window scale) and the ferry's mirrored
/// SYN-ACK options — the throughput fix for the MSS-536 / unscaled-window
/// fallback observed in live Speedtest traffic.
/// </summary>
public class SynOptionsTests
{
    private static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
    private static readonly IPAddress ClientIp = IPAddress.Parse("192.168.100.10");

    /// <summary>Builds a client-side pure SYN with raw TCP options bytes appended.</summary>
    private static byte[] BuildClientSyn(byte[]? options)
    {
        var optLen = options?.Length ?? 0;
        var packet = new byte[40 + optLen];
        // IPv4 header
        packet[0] = 0x45;
        packet[2] = (byte)((40 + optLen) >> 8);
        packet[3] = (byte)(40 + optLen);
        packet[8] = 64;
        packet[9] = 6;
        ClientIp.GetAddressBytes().AsSpan().CopyTo(packet.AsSpan(12));
        ServerIp.GetAddressBytes().AsSpan().CopyTo(packet.AsSpan(16));
        // TCP header at offset 20: ports 12345 → 443, seq, ack, offset, flags=0x02 (SYN)
        packet[20] = 0x30; packet[21] = 0x39; // 12345
        packet[22] = 0x01; packet[23] = 0xBB; // 443
        packet[26] = 0xDE; packet[27] = 0xAD; packet[28] = 0xBE; packet[29] = 0xEF; // ISN
        packet[32] = (byte)(((20 + optLen) / 4) << 4); // TCP data offset (header only)
        packet[33] = 0x02;
        packet[34] = 0xFF; packet[35] = 0xFF; // window 65535
        options?.AsSpan().CopyTo(packet.AsSpan(40));
        return packet;
    }

    [Fact]
    public void ParseSynOptions_ExtractsMssAndWindowScale()
    {
        // MSS 1460 + WS 8 + NOPs to a 4-byte boundary.
        byte[] opts = { 2, 4, 0x05, 0xB4, 3, 3, 8, 1 };
        var packet = BuildClientSyn(opts);

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.True(tuple.IsPureSyn);
        var parsed = TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple);
        Assert.Equal((ushort)1460, parsed.Mss);
        Assert.Equal(8, parsed.WindowScale);
    }

    [Fact]
    public void ParseSynOptions_Absent_ReturnsDefaults()
    {
        var packet = BuildClientSyn(null);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.False(TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple).HasMss);
        Assert.False(TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple).HasWindowScale);
    }

    [Fact]
    public void ParseSynOptions_MalformedLength_DoesNotOverrun()
    {
        // MSS option claiming length 200 (> remaining space).
        byte[] opts = { 2, 200, 0x05 };
        var packet = BuildClientSyn(opts);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        var parsed = TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple);
        Assert.Equal(0, parsed.Mss); // rejected, no crash/overrun
    }

    [Fact]
    public void ParseSynOptions_WindowScaleClampsTo14()
    {
        byte[] opts = { 3, 3, 15, 1 }; // WS beyond the RFC maximum
        var packet = BuildClientSyn(opts);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(14, TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple).WindowScale);
    }

    [Fact]
    public void BuildSynAck_WithBothOptions_HasCorrectLayout()
    {
        var packet = TcpPacketBuilder.BuildSynAck(
            ServerIp, ClientIp, 443, 5211, 0x12345678, 0xABCDEF01,
            mss: 1460, withWindowScale: true);

        Assert.Equal(48, packet.Length); // 20 IP + 28 TCP (20 + 8 option bytes)
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(28, tuple.TcpHeaderLen);

        // Option bytes: MSS(2,4,1460) WS(3,3,shift) NOP.
        var o = 40;
        Assert.Equal(2, packet[o]); Assert.Equal(4, packet[o + 1]);
        Assert.Equal((1460 >> 8) & 0xFF, packet[o + 2]);
        Assert.Equal(1460 & 0xFF, packet[o + 3]);
        Assert.Equal(3, packet[o + 4]); Assert.Equal(3, packet[o + 5]);
        Assert.Equal(TcpPacketBuilder.FerryWindowScaleShift, packet[o + 6]);
    }

    [Fact]
    public void BuildSynAck_WithMssOnly_PadsToFourByteBoundary()
    {
        var packet = TcpPacketBuilder.BuildSynAck(
            ServerIp, ClientIp, 443, 5211, 0x12345678, 0xABCDEF01, mss: 1400);

        Assert.Equal(48, packet.Length);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(28, tuple.TcpHeaderLen);
        Assert.Equal((ushort)1400, TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple).Mss);
        Assert.False(TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple).HasWindowScale);
    }

    [Fact]
    public void BuildSynAck_Default_RemainsOptionFree()
    {
        var packet = TcpPacketBuilder.BuildSynAck(
            ServerIp, ClientIp, 443, 5211, 0x12345678, 0xABCDEF01);

        Assert.Equal(40, packet.Length);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(20, tuple.TcpHeaderLen);
    }

    [Fact]
    public void Builders_AcceptAdvertisedWindow()
    {
        const ushort window = 0xFFFF;
        var data = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, 443, 5211, 100, 200,
            new byte[] { 1, 2, 3 }, window);
        Assert.Equal(window, (ushort)((data[20 + 14] << 8) | data[20 + 15]));

        var ackPkt = TcpPacketBuilder.BuildAck(
            ServerIp, ClientIp, 443, 5211, 100, 200, window);
        Assert.Equal(window, (ushort)((ackPkt[20 + 14] << 8) | ackPkt[20 + 15]));
    }
}
