using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// IPv4+UDP packet header parsing and construction for the DNS ferry — the
/// typed port of the PROVEN E8-a/E8-b spike helpers (ParseUdp, BuildUdpPacket).
/// Only IPv4 is handled: the ferry's filter and this parser agree, and IPv6
/// transport DNS is a documented Phase 9 gap.
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
}
