using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// IPv4/IPv6 + UDP packet header parsing and construction for the DNS ferry —
/// the typed port of the PROVEN E8-a/E8-b spike helpers (ParseUdp,
/// BuildUdpPacket), extended with IPv6 transport (no extension headers: a v6
/// packet whose Next Header is not UDP at offset 6 fails to parse and the
/// ferry drops it fail-closed).
/// </summary>
internal static class UdpPacketParser
{
    /// <summary>
    /// Parses the IPv4 and UDP headers of a captured packet.
    /// Returns false for anything that is not IPv4/UDP (dropped by the filter
    /// anyway) or too short to carry a UDP header.
    /// </summary>
    public static bool TryParse(
        byte[] packet, uint len,
        out IPAddress srcIp, out IPAddress dstIp,
        out ushort srcPort, out ushort dstPort,
        out int ipHeaderLength)
    {
        srcIp = dstIp = new IPAddress(0);
        srcPort = dstPort = 0;
        ipHeaderLength = 0;

        if (len < 28) return false;              // IPv4(20) + UDP(8) minimum
        if ((packet[0] >> 4) != 4) return false; // IPv4 only
        if (packet[9] != 17) return false;       // UDP protocol
        ipHeaderLength = (packet[0] & 0x0F) * 4;
        if (len < ipHeaderLength + 8) return false;

        srcIp = new IPAddress(packet.AsSpan(12, 4));
        dstIp = new IPAddress(packet.AsSpan(16, 4));
        var udp = ipHeaderLength;
        srcPort = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        dstPort = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        return true;
    }

    /// <summary>
    /// Builds an IPv4/UDP packet carrying <paramref name="payload"/> (E8-b
    /// BuildUdpPacket). Checksums are left to
    /// <c>WinDivertHelperCalcChecksums</c> — the caller computes them with the
    /// injection address before sending.
    /// </summary>
    public static byte[] BuildUdpPacket(
        IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var packet = new byte[20 + 8 + payload.Length];
        // IPv4 header.
        packet[0] = 0x45;                    // version 4, IHL 5
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;     // total length
        packet[6] = 0x40;                    // DF
        packet[8] = 64;                      // TTL
        packet[9] = 17;                      // UDP
        srcIp.GetAddressBytes().CopyTo(packet, 12);
        dstIp.GetAddressBytes().CopyTo(packet, 16);

        // UDP header (checksum filled by the WinDivert helper).
        var udp = 20;
        packet[udp + 0] = (byte)(srcPort >> 8);
        packet[udp + 1] = (byte)srcPort;
        packet[udp + 2] = (byte)(dstPort >> 8);
        packet[udp + 3] = (byte)dstPort;
        var udpLen = 8 + payload.Length;
        packet[udp + 4] = (byte)(udpLen >> 8);
        packet[udp + 5] = (byte)udpLen;
        payload.CopyTo(packet, udp + 8);
        return packet;
    }

    /// <summary>Fixed IPv6 header length (no extension headers supported).</summary>
    internal const int Ipv6HeaderLength = 40;

    /// <summary>
    /// Parses the IPv6 and UDP headers of a captured packet.
    /// Returns false for anything that is not IPv6/UDP (including v6 packets
    /// with extension headers — Next Header must be UDP at offset 6) or too
    /// short to carry a UDP header. The caller drops unparsable packets
    /// fail-closed (never reinjects them).
    /// </summary>
    public static bool TryParseUdp6(
        byte[] packet, uint len,
        out IPAddress srcIp, out IPAddress dstIp,
        out ushort srcPort, out ushort dstPort)
    {
        srcIp = dstIp = new IPAddress(0);
        srcPort = dstPort = 0;

        if (len < Ipv6HeaderLength + 8) return false; // IPv6(40) + UDP(8) minimum
        if ((packet[0] >> 4) != 6) return false;      // IPv6 only
        if (packet[6] != 17) return false;            // Next Header must be UDP (no extension headers)

        srcIp = new IPAddress(packet.AsSpan(8, 16));
        dstIp = new IPAddress(packet.AsSpan(24, 16));
        const int udp = Ipv6HeaderLength;
        srcPort = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        dstPort = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        return true;
    }

    /// <summary>
    /// Builds an IPv6/UDP packet carrying <paramref name="payload"/>.
    /// The UDP checksum is left to <c>WinDivertHelperCalcChecksums</c> (it is
    /// mandatory in IPv6 — the helper computes it over the pseudo-header).
    /// </summary>
    public static byte[] BuildUdp6Packet(
        IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var packet = new byte[Ipv6HeaderLength + 8 + payload.Length];
        // IPv6 header.
        packet[0] = 0x60;                       // version 6, traffic class 0, flow label 0
        var payloadLen = 8 + payload.Length;
        packet[4] = (byte)(payloadLen >> 8);
        packet[5] = (byte)payloadLen;            // payload length
        packet[6] = 17;                          // Next Header: UDP
        packet[7] = 64;                          // Hop Limit
        srcIp.GetAddressBytes().CopyTo(packet, 8);
        dstIp.GetAddressBytes().CopyTo(packet, 24);

        // UDP header (checksum filled by the WinDivert helper).
        const int udp = Ipv6HeaderLength;
        packet[udp + 0] = (byte)(srcPort >> 8);
        packet[udp + 1] = (byte)srcPort;
        packet[udp + 2] = (byte)(dstPort >> 8);
        packet[udp + 3] = (byte)dstPort;
        packet[udp + 4] = (byte)(payloadLen >> 8);
        packet[udp + 5] = (byte)payloadLen;
        payload.CopyTo(packet, udp + 8);
        return packet;
    }
}
