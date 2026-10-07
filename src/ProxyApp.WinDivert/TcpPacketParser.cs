using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// The 5-tuple and header details of a captured IPv4/TCP packet. Used to key
/// flows and to extract payload bytes.
/// </summary>
internal readonly record struct TcpTuple(
    IPAddress SrcIp,
    IPAddress DstIp,
    ushort SrcPort,
    ushort DstPort,
    byte TcpFlags,
    uint Seq,
    uint Ack,
    byte TcpHeaderLen,
    ushort Window)
{
    /// <summary>True when the SYN flag is set (bit 0x02).</summary>
    public bool IsSyn => (TcpFlags & 0x02) != 0;

    /// <summary>True when the ACK flag is set (bit 0x10).</summary>
    public bool IsAck => (TcpFlags & 0x10) != 0;

    /// <summary>True when the FIN flag is set (bit 0x01).</summary>
    public bool IsFin => (TcpFlags & 0x01) != 0;

    /// <summary>True when the RST flag is set (bit 0x04).</summary>
    public bool IsRst => (TcpFlags & 0x04) != 0;

    /// <summary>True for a pure SYN (SYN set, ACK clear).</summary>
    public bool IsPureSyn => IsSyn && !IsAck;
}

/// <summary>
/// Minimal IPv4/IPv6 + TCP header parser. Read-only; it does not modify packets.
/// Handles only unfragmented IPv4/TCP and IPv6/TCP WITHOUT extension headers
/// (a v6 packet whose Next Header is not TCP at offset 6 fails to parse).
///
/// IPv6 support exists for the DNS-over-TCP leg: Windows falls back to TCP when
/// a UDP answer is truncated, and it may do so over IPv6 transport. Without it,
/// DNS over TCP+IPv6 was relayed by nothing and left on the direct path.
/// </summary>
internal static class TcpPacketParser
{
    /// <summary>Fixed IPv6 header length (extension headers are not supported).</summary>
    internal const int Ipv6HeaderLength = 40;

    /// <summary>
    /// The IP header length of a captured packet: the fixed 40 bytes for IPv6,
    /// the IHL-derived length for IPv4. Returns 0 for a packet too short to hold
    /// a version nibble or for an unknown IP version.
    ///
    /// Centralized so every offset computation in the ferry is family-correct:
    /// the old inline <c>(packet[0] &amp; 0x0F) * 4</c> yields 0 for IPv6 (the
    /// low nibble is part of the traffic class / flow label), which silently
    /// pointed the payload offset at the IP header.
    /// </summary>
    public static int IpHeaderLength(byte[] packet, uint length)
    {
        if (length < 1 || packet.Length < 1)
            return 0;
        return (packet[0] >> 4) switch
        {
            4 => (packet[0] & 0x0F) * 4,
            6 => Ipv6HeaderLength,
            _ => 0
        };
    }

    /// <summary>
    /// Parses a raw IPv4/TCP or IPv6/TCP packet into a <see cref="TcpTuple"/>.
    /// Returns false for a non-IP, non-TCP, or malformed packet, and for an
    /// IPv6 packet carrying extension headers (not supported — the caller
    /// treats it as unparsable rather than misreading the payload).
    /// </summary>
    public static bool TryParse(byte[] packet, uint length, out TcpTuple tuple)
    {
        tuple = default;
        if (length < 20 || packet.Length < 20)
            return false;

        var ipHeaderLength = IpHeaderLength(packet, length);
        if (ipHeaderLength < 20 || length < ipHeaderLength + 20)
            return false;

        IPAddress srcIp, dstIp;
        if (ipHeaderLength == Ipv6HeaderLength)
        {
            // IPv6: version must be 6 and Next Header (offset 6) must be TCP.
            // Extension headers (43/44/60/…) are rejected rather than skipped —
            // a wrong payload offset would corrupt the relay stream.
            if ((packet[0] >> 4) != 6 || packet[6] != 6)
                return false;
            srcIp = new IPAddress(packet.AsSpan(8, 16));
            dstIp = new IPAddress(packet.AsSpan(24, 16));
        }
        else
        {
            if ((packet[0] >> 4) != 4)
                return false; // Not IPv4.
            if (packet[9] != 6)
                return false; // Not TCP.
            srcIp = new IPAddress(packet.AsSpan(12, 4));
            dstIp = new IPAddress(packet.AsSpan(16, 4));
        }

        var tcp = ipHeaderLength;
        var srcPort = (ushort)((packet[tcp] << 8) | packet[tcp + 1]);
        var dstPort = (ushort)((packet[tcp + 2] << 8) | packet[tcp + 3]);
        var seq = ((uint)packet[tcp + 4] << 24) | ((uint)packet[tcp + 5] << 16) |
                  ((uint)packet[tcp + 6] << 8) | packet[tcp + 7];
        var ack = ((uint)packet[tcp + 8] << 24) | ((uint)packet[tcp + 9] << 16) |
                  ((uint)packet[tcp + 10] << 8) | packet[tcp + 11];
        var dataOffset = (byte)((packet[tcp + 12] >> 4) * 4);
        var flags = packet[tcp + 13];

        tuple = new TcpTuple(srcIp, dstIp, srcPort, dstPort, flags, seq, ack, dataOffset,
            (ushort)((packet[tcp + 14] << 8) | packet[tcp + 15]));
        return true;
    }

    /// <summary>
    /// Parses a captured SYN's TCP options for the values the ferry must mirror
    /// in the crafted SYN-ACK: the maximum segment size (MSS, kind 2) and the
    /// window-scale shift (WS, kind 3). Returns defaults when absent.
    /// </summary>
    public static SynOptions ParseSynOptions(byte[] packet, uint length, in TcpTuple tuple)
    {
        var ihl = IpHeaderLength(packet, length);
        var optsStart = ihl + 20;
        var optsEnd = ihl + tuple.TcpHeaderLen;
        if (length < optsStart || optsEnd > packet.Length)
            return default;

        ushort mss = 0;
        byte ws = 0;
        var i = optsStart;
        while (i < optsEnd)
        {
            var kind = packet[i];
            if (kind == 0) break;          // End of option list.
            if (kind == 1) { i++; continue; } // No-op.

            // kind+len options; a malformed length cannot terminate the walk.
            if (i + 1 >= optsEnd) break;
            var optLen = packet[i + 1];
            if (optLen < 2 || i + optLen > optsEnd) break;

            if (kind == 2 && optLen == 4)
                mss = (ushort)((packet[i + 2] << 8) | packet[i + 3]);
            else if (kind == 3 && optLen == 3)
                ws = Math.Min(packet[i + 2], (byte)14);

            i += optLen;
        }

        return new SynOptions(mss, ws);
    }

    /// <summary>
    /// Computes the payload length of a parsed packet: total length minus the IP
    /// header minus the TCP header. Returns 0 for headers-only segments.
    /// </summary>
    public static int GetPayloadLength(byte[] packet, uint length, in TcpTuple tuple)
    {
        if (length < 20)
            return 0;
        var ihl = IpHeaderLength(packet, length);
        var payload = (int)length - ihl - tuple.TcpHeaderLen;
        return payload < 0 ? 0 : payload;
    }
}

/// <summary>
/// The SYN options the ferry mirrors in the crafted SYN-ACK.
/// </summary>
/// <param name="Mss">The client's maximum segment size offer (0 when absent).</param>
/// <param name="WindowScale">The client's window-scale shift offer (0 when absent).</param>
internal readonly record struct SynOptions(ushort Mss, byte WindowScale)
{
    /// <summary>True when the SYN carried an MSS option.</summary>
    public bool HasMss => Mss > 0;

    /// <summary>True when the SYN carried a window-scale option.</summary>
    public bool HasWindowScale => WindowScale > 0;
}
