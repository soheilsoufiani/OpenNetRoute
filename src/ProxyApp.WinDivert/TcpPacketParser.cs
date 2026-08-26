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
/// Minimal IPv4/TCP header parser. Read-only; it does not modify packets.
/// Handles only unfragmented IPv4/TCP.
/// </summary>
internal static class TcpPacketParser
{
    /// <summary>
    /// Parses a raw IPv4/TCP packet into a <see cref="TcpTuple"/>. Returns false
    /// for non-IPv4, non-TCP, or malformed packets.
    /// </summary>
    public static bool TryParse(byte[] packet, uint length, out TcpTuple tuple)
    {
        tuple = default;
        if (length < 20 || packet.Length < 20)
            return false;

        if ((packet[0] >> 4) != 4)
            return false; // Not IPv4.

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl + 20)
            return false;

        if (packet[9] != 6)
            return false; // Not TCP.

        var srcIp = new IPAddress(packet.AsSpan(12, 4));
        var dstIp = new IPAddress(packet.AsSpan(16, 4));

        var tcp = (int)ihl;
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
        var ihl = (packet[0] & 0x0F) * 4;
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
        var ihl = (packet[0] & 0x0F) * 4;
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
