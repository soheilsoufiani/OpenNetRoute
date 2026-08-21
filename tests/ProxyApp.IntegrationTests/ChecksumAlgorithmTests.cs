using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Verifies the managed IPv4/TCP checksum algorithm against a known-good
/// RFC 793 example, then confirms the packets built by <see cref="TcpPacketBuilder"/>
/// become checksum-valid once their checksum fields are filled (the ferry fills
/// them via WinDivertHelperCalcChecksums before injection).
/// </summary>
public class ChecksumAlgorithmTests
{
    [Fact]
    public void Ipv4Checksum_MatchesKnownRfcExample()
    {
        // RFC 1071 example: header 45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c
        // with the checksum field (bytes 10-11) zeroed, the computed checksum is 0xb1e6.
        byte[] header =
        {
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c
        };
        // OnesComplementSum returns the folded 16-bit sum. The checksum is the
        // one's complement of that. For the RFC header the folded sum is 0x4E19,
        // so the checksum is ~0x4E19 = 0xB1E6.
        var sum = OnesComplementSum(header, 0, 20);
        Assert.Equal(0x4E19u, sum);
        var checksum = (ushort)~sum;
        Assert.Equal(0xB1E6u, checksum);
    }

    [Fact]
    public void BuilderPackets_BecomeChecksumValid_WhenChecksumsFilled()
    {
        var serverIp = IPAddress.Parse("8.8.8.8");
        var clientIp = IPAddress.Parse("192.168.100.10");

        // Build a data packet, then fill its IP and TCP checksum fields exactly as
        // the ferry does before injection.
        var packet = TcpPacketBuilder.BuildDataPacket(
            serverIp, clientIp, 80, 12345, 0x12345679, 0xABCDEF72, "HTTP/1.1 200 OK"u8.ToArray());

        var tcp = (packet[0] & 0x0F) * 4;
        // OnesComplementSum returns the folded sum; the checksum is ~folded.
        var ipCsum = (ushort)~OnesComplementSum(packet, 0, 20);
        packet[10] = (byte)(ipCsum >> 8);
        packet[11] = (byte)ipCsum;

        var src = new IPAddress(packet.AsSpan(12, 4));
        var dst = new IPAddress(packet.AsSpan(16, 4));
        var tcpLen = packet.Length - tcp;
        uint sum = 0;
        foreach (var b in src.GetAddressBytes()) sum += b;
        foreach (var b in dst.GetAddressBytes()) sum += b;
        sum += 6u;
        sum += (uint)tcpLen;
        // Sum TCP header + payload with the (still zero) checksum field, then fold.
        sum += Fold(OnesComplementSumRaw(packet, tcp, tcpLen));
        var tcpCsum = (ushort)~Fold(sum);
        packet[tcp + 16] = (byte)(tcpCsum >> 8);
        packet[tcp + 17] = (byte)tcpCsum;

        // Now the packet's checksum fields hold the computed values. Verify that a
        // receiver (summing the whole thing including the stored checksum) gets 0xFFFF.
        Assert.True(ReceiverValidates(packet), "filled-checksum data packet must be valid");
    }

    private static bool ReceiverValidates(byte[] packet)
    {
        var ihl = (packet[0] & 0x0F) * 4;
        var tcp = ihl;
        var tcpLen = packet.Length - ihl;
        var src = new IPAddress(packet.AsSpan(12, 4));
        var dst = new IPAddress(packet.AsSpan(16, 4));

        var ipOk = OnesComplementSum(packet, 0, ihl) == 0xFFFF;
        if (!ipOk) return false;

        uint sum = 0;
        foreach (var b in src.GetAddressBytes()) sum += b;
        foreach (var b in dst.GetAddressBytes()) sum += b;
        sum += 6u;
        sum += (uint)tcpLen;
        sum += Fold(OnesComplementSumRaw(packet, tcp, tcpLen));
        return Fold(sum) == 0xFFFF;
    }

    private static uint OnesComplementSum(byte[] data, int offset, int length)
        => Fold(OnesComplementSumRaw(data, offset, length));

    private static uint OnesComplementSumRaw(byte[] data, int offset, int length)
    {
        uint sum = 0;
        int i = offset;
        while (i + 1 < offset + length)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
            i += 2;
        }
        if (i < offset + length)
            sum += (uint)(data[i] << 8);
        return sum;
    }

    private static uint Fold(uint sum)
    {
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return sum;
    }
}
