using System.Net;

namespace WinDivertSpike;

/// <summary>
/// Minimal IPv4/TCP header parser for spike packet inspection. Read-only — the
/// spike inspects, it does not yet construct/modify production packets.
/// </summary>
internal readonly record struct TcpTuple(
    IPAddress SrcIp,
    IPAddress DstIp,
    ushort SrcPort,
    ushort DstPort,
    byte TcpFlags,
    uint Seq,
    uint Ack,
    byte TcpHeaderLen)
{
    public override string ToString() =>
        $"{SrcIp}:{SrcPort} -> {DstIp}:{DstPort} flags=0x{TcpFlags:X2} seq={Seq} ack={Ack}";
}

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

        tuple = new TcpTuple(srcIp, dstIp, srcPort, dstPort, flags, seq, ack, dataOffset);
        return true;
    }
}