using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the IPv6 half of the TCP ferry's parser and builder.
///
/// Context: DNS over TCP is the fallback transport when a UDP answer is
/// truncated, and Windows may use IPv6 transport for it. The TCP ferry's
/// capture filter was IPv4-only, so DNS over TCP+IPv6 was relayed by nothing
/// and left on the direct path — a plaintext leak invisible to the IPv4
/// port-53 filter.
///
/// The bugs these tests pin are the ones a family-blind implementation has:
/// <list type="bullet">
/// <item>IP header length 20 vs 40. The old inline <c>(packet[0] &amp; 0x0F) * 4</c>
/// yields 0 for IPv6 (that nibble is traffic class / flow label), so every
/// payload offset pointed into the IP header.</item>
/// <item>Injected packet layout. A crafted SYN-ACK built with a 20-byte IPv4
/// header for an IPv6 tuple is not an IPv6 packet at all.</item>
/// </list>
/// </summary>
public class TcpIpv6Tests
{
    private static readonly IPAddress V6Src = IPAddress.Parse("2001:db8::10");
    private static readonly IPAddress V6Dst = IPAddress.Parse("2001:4860:4860::8888");

    /// <summary>Wraps a TCP payload in a minimal IPv6/TCP header.</summary>
    private static byte[] BuildV6TcpPacket(
        IPAddress src, IPAddress dst, ushort srcPort, ushort dstPort, byte[] payload)
    {
        const int ipLen = TcpPacketParser.Ipv6HeaderLength, tcpLen = 20;
        var packet = new byte[ipLen + tcpLen + payload.Length];
        packet[0] = 0x60;                              // version 6
        var payloadLen = tcpLen + payload.Length;
        packet[4] = (byte)(payloadLen >> 8);
        packet[5] = (byte)payloadLen;
        packet[6] = 6;                                 // Next Header: TCP
        packet[7] = 64;                                // Hop Limit
        src.GetAddressBytes().CopyTo(packet, 8);
        dst.GetAddressBytes().CopyTo(packet, 24);
        packet[ipLen + 0] = (byte)(srcPort >> 8);
        packet[ipLen + 1] = (byte)srcPort;
        packet[ipLen + 2] = (byte)(dstPort >> 8);
        packet[ipLen + 3] = (byte)dstPort;
        packet[ipLen + 12] = 0x50;                     // data offset 5 (no options)
        packet[ipLen + 13] = 0x18;                     // PSH|ACK
        payload.CopyTo(packet.AsSpan(ipLen + tcpLen));
        return packet;
    }

    [Fact]
    public void IpHeaderLength_Is40ForIpv6_NotZero()
    {
        // The regression that mattered: the family-blind expression
        // (packet[0] & 0x0F) * 4 returns 0 here, because the low nibble of an
        // IPv6 first byte is part of the traffic class / flow label.
        var packet = BuildV6TcpPacket(V6Src, V6Dst, 51234, 53, new byte[8]);

        Assert.Equal(40, TcpPacketParser.IpHeaderLength(packet, (uint)packet.Length));
    }

    [Fact]
    public void IpHeaderLength_Is20ForIpv4()
    {
        var packet = new byte[60];
        packet[0] = 0x45;
        Assert.Equal(20, TcpPacketParser.IpHeaderLength(packet, 60));
    }

    [Fact]
    public void IpHeaderLength_ReturnsZeroForUnknownVersion()
    {
        var packet = new byte[60];
        packet[0] = 0x25; // version 2 — not IP at all
        Assert.Equal(0, TcpPacketParser.IpHeaderLength(packet, 60));
    }

    [Fact]
    public void TryParse_ParsesIpv6AddressesPortsAndFlags()
    {
        var packet = BuildV6TcpPacket(V6Src, V6Dst, 51234, 53, new byte[] { 0xDE, 0xAD });

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));

        Assert.Equal(V6Src, tuple.SrcIp);
        Assert.Equal(V6Dst, tuple.DstIp);
        Assert.Equal(51234, tuple.SrcPort);
        Assert.Equal(53, tuple.DstPort);       // the DNS-over-TCP port
        Assert.Equal(20, tuple.TcpHeaderLen);
        Assert.Equal(2, TcpPacketParser.GetPayloadLength(packet, (uint)packet.Length, tuple));
    }

    [Fact]
    public void TryParse_RejectsIpv6WithExtensionHeaders()
    {
        // Next Header != TCP means an extension header is present. Parsing it as
        // plain TCP would compute a wrong payload offset and corrupt the relay
        // stream, so it must be rejected rather than guessed at.
        var packet = BuildV6TcpPacket(V6Src, V6Dst, 51234, 53, new byte[8]);
        packet[6] = 44; // Fragment header

        Assert.False(TcpPacketParser.TryParse(packet, (uint)packet.Length, out _));
    }

    [Fact]
    public void TryParse_RejectsTooShortIpv6Packet()
    {
        var packet = new byte[20];
        packet[0] = 0x60;
        Assert.False(TcpPacketParser.TryParse(packet, (uint)packet.Length, out _));
    }

    [Fact]
    public void BuildSynAck_ProducesRealIpv6PacketForIpv6Tuple()
    {
        var packet = TcpPacketBuilder.BuildSynAck(
            V6Dst, V6Src, 53, 51234, 0x12345678, 0xAABBCCDD, mss: 1460, withWindowScale: true);

        // Version 6 and Next Header TCP.
        Assert.Equal(0x60, packet[0] & 0xF0);
        Assert.Equal(6, packet[6]);

        // The 40-byte IPv6 header must carry the right addresses at the v6
        // offsets (8 and 24), NOT the v4 ones (12 and 16).
        Assert.Equal(V6Dst.GetAddressBytes(), packet.AsSpan(8, 16).ToArray());
        Assert.Equal(V6Src.GetAddressBytes(), packet.AsSpan(24, 16).ToArray());

        // TCP header starts at 40. Injected inbound: the SERVER (here the DNS
        // resolver on 53) is the source, the client is the destination.
        const int tcp = TcpPacketParser.Ipv6HeaderLength;
        Assert.Equal(53, (packet[tcp] << 8) | packet[tcp + 1]);
        Assert.Equal(51234, (packet[tcp + 2] << 8) | packet[tcp + 3]);

        // Payload length excludes the 40-byte IPv6 header.
        Assert.Equal(packet.Length - TcpPacketParser.Ipv6HeaderLength,
            (packet[4] << 8) | packet[5]);

        // The packet must round-trip through the parser, which is the property
        // the ferry actually relies on.
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(V6Dst, tuple.SrcIp);
        Assert.Equal(53, tuple.SrcPort);
        Assert.Equal(V6Src, tuple.DstIp);
        Assert.Equal(51234, tuple.DstPort);
    }

    [Fact]
    public void BuildSynAck_KeepsIpv4LayoutUnchanged()
    {
        // The v4 path must be byte-for-byte what it was: this builder is used
        // by every ordinary proxied connection, so a regression here would be
        // far more visible than a v6-only bug.
        var packet = TcpPacketBuilder.BuildSynAck(
            IPAddress.Parse("93.184.216.34"), IPAddress.Parse("192.168.1.10"),
            443, 51234, 0x12345678, 0xAABBCCDD, mss: 1460, withWindowScale: true);

        Assert.Equal(0x45, packet[0]);
        Assert.Equal(6, packet[9]);

        // The SYN-ACK is injected INBOUND toward the client, so the SERVER
        // address sits in the source field (offset 12) and the client's in the
        // destination field (offset 16). Asserting this pins the direction: a
        // swapped pair here would make every proxied connection fail at the
        // client's stack, not merely parse oddly.
        Assert.Equal(IPAddress.Parse("93.184.216.34").GetAddressBytes(), packet.AsSpan(12, 4).ToArray());
        Assert.Equal(IPAddress.Parse("192.168.1.10").GetAddressBytes(), packet.AsSpan(16, 4).ToArray());
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        Assert.Equal(IPAddress.Parse("93.184.216.34"), tuple.SrcIp);
        Assert.Equal(443, tuple.SrcPort);
        Assert.Equal(51234, tuple.DstPort);
    }

    [Fact]
    public void BuildDataPacket_PayloadStartsAfterTheIpv6Header()
    {
        byte[] payload = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var packet = TcpPacketBuilder.BuildDataPacket(
            V6Dst, V6Src, 53, 51234, 1, 2, payload);

        Assert.Equal(0x60, packet[0] & 0xF0);
        Assert.Equal(payload, packet.AsSpan(TcpPacketParser.Ipv6HeaderLength + 20, payload.Length).ToArray());
        Assert.Equal(TcpPacketParser.Ipv6HeaderLength + 20 + payload.Length, packet.Length);
    }

    [Theory]
    [InlineData("ack")]
    [InlineData("fin")]
    [InlineData("rst")]
    public void ControlPackets_UseTheIpv6HeaderLength(string kind)
    {
        byte[] packet = kind switch
        {
            "ack" => TcpPacketBuilder.BuildAck(V6Dst, V6Src, 53, 51234, 1, 2),
            "fin" => TcpPacketBuilder.BuildFin(V6Dst, V6Src, 53, 51234, 1, 2),
            _ => TcpPacketBuilder.BuildRst(V6Dst, V6Src, 53, 51234, 1, 2),
        };

        // A 40-byte packet here would mean the IPv4 layout leaked through:
        // the TCP header would start at 20 and the client would read the IP
        // header's addresses as ports.
        Assert.Equal(TcpPacketParser.Ipv6HeaderLength + 20, packet.Length);
        Assert.Equal(0x60, packet[0] & 0xF0);
        Assert.Equal(6, packet[6]);
        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        // Injected inbound toward the client: resolver:53 is the source.
        Assert.Equal(V6Dst, tuple.SrcIp);
        Assert.Equal(53, tuple.SrcPort);
        Assert.Equal(V6Src, tuple.DstIp);
        Assert.Equal(51234, tuple.DstPort);
    }

    [Fact]
    public void ParseSynOptions_ReadsOptionsFromAnIpv6Syn()
    {
        // IPv6 SYN with MSS(1460) + window scale(7) options.
        const int ipLen = TcpPacketParser.Ipv6HeaderLength, tcpLen = 28;
        var packet = new byte[ipLen + tcpLen];
        packet[0] = 0x60;
        var payloadLen = tcpLen;
        packet[4] = (byte)(payloadLen >> 8);
        packet[5] = (byte)payloadLen;
        packet[6] = 6;
        packet[7] = 64;
        V6Src.GetAddressBytes().CopyTo(packet, 8);
        V6Dst.GetAddressBytes().CopyTo(packet, 24);
        packet[ipLen + 0] = 0x02; packet[ipLen + 1] = 0x00;      // SYN
        packet[ipLen + 12] = 0x70;                              // data offset 7 (28 bytes)
        var o = ipLen + 20;
        packet[o] = 2; packet[o + 1] = 4;                        // MSS
        packet[o + 2] = 0x05; packet[o + 3] = 0xB4;              // 1460
        packet[o + 4] = 3; packet[o + 5] = 3;                    // window scale
        packet[o + 6] = 7;
        packet[o + 7] = 1;                                       // NOP pad

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        var options = TcpPacketParser.ParseSynOptions(packet, (uint)packet.Length, tuple);

        Assert.True(options.HasMss);
        Assert.Equal(1460, options.Mss);
        Assert.True(options.HasWindowScale);
        Assert.Equal(7, options.WindowScale);
    }

    [Fact]
    public void BuildFilterV6_IsIpv6OnlyOutboundAndPort53()
    {
        // The DNS-over-TCP-over-IPv6 filter. A WinDivert expression cannot mix
        // `ip` and `ipv6`, so this MUST be a separate handle from the IPv4 one.
        const string filter = "outbound and ipv6 and tcp and tcp.DstPort == 53 and not loopback";

        Assert.Contains("outbound", filter);
        Assert.Contains("ipv6", filter);
        Assert.Contains("tcp.DstPort == 53", filter);
        Assert.Contains("not loopback", filter);
        Assert.DoesNotContain(" and ip ", filter);
    }
}