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
    /// <summary>Builds a SYN-ACK packet (no payload) for the client's held SYN.</summary>
    /// <param name="serverIp">The real destination IP the client attempted to reach.</param>
    /// <param name="clientIp">The client's local IP.</param>
    /// <param name="serverPort">The real destination port.</param>
    /// <param name="clientPort">The client's ephemeral source port.</param>
    /// <param name="serverIsn">The server ISN (S1) to present to the client.</param>
    /// <param name="clientIsn">The client ISN from the captured SYN.</param>
    public static byte[] BuildSynAck(
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint serverIsn,
        uint clientIsn)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        var tcp = 20;
        // Advertise a reasonable window (0x7210 = 29200, matching E6).
        // A window of 0 would cause the client to send 1-byte window probes
        // instead of the full HTTP request, starving the relay.
        WriteTcpHeader(packet, tcp, serverPort, clientPort, serverIsn, clientIsn + 1, 0x12, 0x7210);
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
        bool setFin = false)
    {
        int ipLen = 20, tcpLen = 20;
        var packet = new byte[ipLen + tcpLen + payload.Length];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        // Advertise a reasonable window (0x7210 = 29200, matching E6). A window
        // of 0 would tell the client the server cannot accept more data, which
        // may cause the client to stall or reject the response.
        var flags = setFin ? (byte)0x19 : (byte)0x18; // FIN|PSH|ACK vs PSH|ACK
        WriteTcpHeader(packet, ipLen, serverPort, clientPort, seq, ack, flags, 0x7210);
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
        uint ack)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        WriteTcpHeader(packet, 20, serverPort, clientPort, seq, ack, 0x10, 0x7210);
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
        uint ack)
    {
        var packet = new byte[40];
        WriteIpHeader(packet, packet.Length, serverIp, clientIp);
        // FIN|ACK (0x11).
        WriteTcpHeader(packet, 20, serverPort, clientPort, seq, ack, 0x11, 0x7210);
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
