using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// Builds crafted IPv4/TCP packets for injection back to a client, using the
/// packet semantics validated in the spike experiments E5b (crafted SYN-ACK
/// acceptance) and E6 (bidirectional data with ISN translation):
///
///   - The crafted SYN-ACK uses a server ISN S1 and ack = clientISN + 1.
///   - The first DATA byte after the SYN-ACK is at seq = S1 + 1 (the SYN-ACK
///     consumed seq S1).
///   - Injection is inbound (Outbound bit cleared), with the interface indices
///     from the captured SYN and checksums computed via
///     WinDivertHelperCalcChecksums. The Impostor bit is left at its captured
///     value (E5b: a crafted SYN-ACK with Impostor=0 is accepted by a real
///     Windows client; E5: Impostor=1 also works — the bit is WinDivert loop
///     mitigation, not a stack-acceptance gate).
///
/// These methods build the packet bytes only; injection is performed by
/// <see cref="TcpFerry"/> via WinDivertSend.
/// </summary>
internal static class TcpPacketBuilder
{
    /// <summary>The window-scale shift the ferry offers in its SYN-ACK.</summary>
    internal const byte FerryWindowScaleShift = 8;

    /// <summary>
    /// Builds a SYN-ACK packet (no payload) for the client's held SYN.
    ///
    /// TCP options matter for throughput: without an MSS option Windows falls
    /// back to MSS 536, and without a window-scale option BOTH sides disable
    /// scaling (RFC 7323) and cap the receive window at 64 KiB. Together those
    /// two omissions pinned ferry throughput at ~29200 bytes per RTT.
    /// Options are padded to a 4-byte boundary:
    ///   MSS only: MSS(4)+NOP×4     → options 8 bytes, data offset 7
    ///   WS only:  WS(3)+NOP        → options 4 bytes, data offset 6
    ///   Both:     MSS(4)+WS(3)+NOP → options 8 bytes, data offset 7
    /// </summary>
    /// <param name="serverIp">The real destination IP the client attempted to reach.</param>
    /// <param name="clientIp">The client's local IP.</param>
    /// <param name="serverPort">The real destination port.</param>
    /// <param name="clientPort">The client's ephemeral source port.</param>
    /// <param name="serverIsn">The server ISN (S1) to present to the client.</param>
    /// <param name="clientIsn">The client ISN from the captured SYN.</param>
    /// <param name="mss">MSS value to advertise (0 omits the option).</param>
    /// <param name="withWindowScale">Include the window-scale option (shift <see cref="FerryWindowScaleShift"/>). Per RFC 7323 it must only be sent when the client's SYN carried one.</param>
    public static byte[] BuildSynAck(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint serverIsn,
        uint clientIsn,
        ushort mss = 0,
        bool withWindowScale = false)
    {
        var useMss = mss > 0;
        var optLen = 0;
        if (useMss) optLen += 4;
        if (withWindowScale) optLen += 4;
        if (useMss && !withWindowScale) optLen += 4; // pad the lone MSS block to 8 bytes

        var tcpLen = 20 + optLen;
        var packet = new byte[20 + tcpLen];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);

        // Advertise a reasonable window (0x7210 = 29200, matching E6). A window
        // of 0 would cause the client to send 1-byte window probes instead of
        // the full HTTP request, starving the relay. When scaling is negotiated
        // this field is interpreted by the client as 0x7210 << 8.
        WriteTcpHeader(packet, 20, serverPort, clientPort, serverIsn, clientIsn + 1, 0x12, 0x7210);
        packet[20 + 12] = (byte)((tcpLen / 4) << 4); // data offset now covers options

        var o = 20 + 20;
        if (useMss)
        {
            packet[o] = 2; packet[o + 1] = 4;
            packet[o + 2] = (byte)(mss >> 8); packet[o + 3] = (byte)mss;
            o += 4;
            if (!withWindowScale)
            {
                packet[o] = 1; packet[o + 1] = 1; packet[o + 2] = 1; // NOP padding
                o += 3;
            }
        }
        if (withWindowScale)
        {
            packet[o] = 3; packet[o + 1] = 3; packet[o + 2] = FerryWindowScaleShift;
            o += 3;
            packet[o] = 1; // NOP pad so the options end on a 4-byte boundary
        }
        return packet;
    }

    /// <summary>
    /// Builds an inbound DATA packet carrying upstream payload bytes to the
    /// client. seq starts at <paramref name="seq"/> (the caller passes
    /// S1 + 1 + bytesAlreadySent). The packet is PSH|ACK (0x18) — the server's
    /// close is NEVER piggybacked on data; the ferry delivers it as a separate
    /// FIN|ACK (see <see cref="TcpFerry"/> upstream pump) once the client has
    /// ACKed the data. When <paramref name="setFin"/> is true, the packet is
    /// FIN|PSH|ACK (0x19) — retained for callers that must deliver the close
    /// with the data, but the ferry does not use it.
    /// </summary>
    public static byte[] BuildDataPacket(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint seq,
        uint ack,
        ReadOnlySpan<byte> payload,
        ushort window = 0x7210,
        bool setFin = false)
    {
        int ipLen = 20, tcpLen = 20;
        var packet = new byte[ipLen + tcpLen + payload.Length];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        var flags = setFin ? (byte)0x19 : (byte)0x18; // FIN|PSH|ACK vs PSH|ACK
        WriteTcpHeader(packet, ipLen, serverPort, clientPort, seq, ack, flags, window);
        payload.CopyTo(packet.AsSpan(ipLen + tcpLen));
        return packet;
    }

    /// <summary>
    /// Builds a pure ACK packet (no payload) to the client. The ferry injects
    /// this after relaying client payload to the upstream so the client's TCP
    /// stack receives a prompt ACK for its data and does not retransmit. Without
    /// it, the client retransmits its request until the response arrives, which
    /// inflates the relay counters and delays/breaks the response delivery.
    /// </summary>
    public static byte[] BuildAck(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint seq,
        uint ack,
        ushort window = 0x7210)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        WriteTcpHeader(packet, 20, serverPort, clientPort, seq, ack, 0x10, window);
        return packet;
    }

    /// <summary>
    /// Builds a TCP FIN|ACK packet to the client, used to propagate the upstream
    /// close so curl sees the server close the connection after the response.
    /// </summary>
    public static byte[] BuildFin(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint seq,
        uint ack,
        ushort window = 0x7210)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        // FIN|ACK (0x11).
        WriteTcpHeader(packet, 20, serverPort, clientPort, seq, ack, 0x11, window);
        return packet;
    }

    /// <summary>
    /// Builds a TCP RST packet to the client (used to fail a held SYN when the
    /// SOCKS5 upstream cannot be established).
    /// </summary>
    public static byte[] BuildRst(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint seq,
        uint ack)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        WriteTcpHeader(packet, 20, serverPort, clientPort, seq, ack, 0x04, 0);
        return packet;
    }

    /// <summary>Writes a minimal IPv4 header (no options), checksum computed later.</summary>
    private static void WriteIpHeader(byte[] packet, int totalLen, IPAddress src, IPAddress dst)
    {
        packet[0] = 0x45; // IPv4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        packet[2] = (byte)(totalLen >> 8);
        packet[3] = (byte)totalLen;
        packet[4] = 0x00;
        packet[5] = 0x00;
        packet[6] = 0x40; // DF
        packet[7] = 0x00;
        packet[8] = 64; // TTL
        packet[9] = 6;  // TCP
        var s = src.GetAddressBytes();
        var d = dst.GetAddressBytes();
        System.Buffer.BlockCopy(s, 0, packet, 12, 4);
        System.Buffer.BlockCopy(d, 0, packet, 16, 4);
    }

    /// <summary>Writes a minimal TCP header (no options).</summary>
    private static void WriteTcpHeader(
        byte[] packet,
        int tcp,
        ushort srcPort,
        ushort dstPort,
        uint seq,
        uint ack,
        byte flags,
        ushort window)
    {
        packet[tcp + 0] = (byte)(srcPort >> 8);
        packet[tcp + 1] = (byte)srcPort;
        packet[tcp + 2] = (byte)(dstPort >> 8);
        packet[tcp + 3] = (byte)dstPort;
        packet[tcp + 4] = (byte)(seq >> 24);
        packet[tcp + 5] = (byte)(seq >> 16);
        packet[tcp + 6] = (byte)(seq >> 8);
        packet[tcp + 7] = (byte)seq;
        packet[tcp + 8] = (byte)(ack >> 24);
        packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8);
        packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50; // data offset 5 (no options)
        packet[tcp + 13] = flags;
        packet[tcp + 14] = (byte)(window >> 8);
        packet[tcp + 15] = (byte)window;
        // Checksum bytes 16-17 are filled by WinDivertHelperCalcChecksums.
    }
}
