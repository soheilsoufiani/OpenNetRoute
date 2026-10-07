using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the IPv6/UDP half of the DNS ferry's parser/builder.
///
/// The v6 leg exists so DNS over IPv6 transport is intercepted like v4 — it
/// used to bypass the relay entirely, which was a genuine plaintext leak.
/// These tests pin the round trip and the fail-closed parse contract.
/// </summary>
public class UdpPacketParserV6Tests
{
    [Fact]
    public void TryParseUdp6_ParsesAddressesAndPorts()
    {
        var src = IPAddress.Parse("fe80::1");
        var dst = IPAddress.Parse("2001:4860:4860::8888");
        byte[] payload = { 0xAB, 0xCD, 0x01, 0x00 };
        var packet = UdpPacketParser.BuildUdp6Packet(dst, src, 53, 51234, payload);

        Assert.True(UdpPacketParser.TryParseUdp6(
            packet, (uint)packet.Length, out var pSrc, out var pDst, out var pSrcPort, out var pDstPort));

        Assert.Equal(dst, pSrc);
        Assert.Equal(src, pDst);
        Assert.Equal(53, pSrcPort);
        Assert.Equal(51234, pDstPort);
    }

    [Fact]
    public void BuildUdp6Packet_HasFixedHeaderAndPayloadLength()
    {
        byte[] payload = new byte[17];
        var packet = UdpPacketParser.BuildUdp6Packet(
            IPAddress.Parse("::1"), IPAddress.Parse("::2"), 53, 53, payload);

        // version 6, Next Header UDP (17), Hop Limit, payload length = UDP(8)+17.
        Assert.Equal(0x60, packet[0] & 0xF0);
        Assert.Equal(17, packet[6]);
        Assert.Equal(64, packet[7]);
        Assert.Equal(25, (packet[4] << 8) | packet[5]);
        Assert.Equal(UdpPacketParser.Ipv6HeaderLength + 8 + payload.Length, packet.Length);
    }

    [Fact]
    public void TryParseUdp6_RejectsIpv4()
    {
        var packet = new byte[60];
        packet[0] = 0x45; // IPv4 version nibble
        Assert.False(UdpPacketParser.TryParseUdp6(packet, (uint)packet.Length, out _, out _, out _, out _));
    }

    [Fact]
    public void TryParseUdp6_RejectsExtensionHeaders()
    {
        // A v6 packet with a fragment/hop-by-hop extension header has
        // Next Header != 17 at offset 6 — unsupported, so it must fail and be
        // dropped fail-closed rather than mis-parsed.
        var packet = new byte[64];
        packet[0] = 0x60;
        packet[6] = 44; // Fragment header
        Assert.False(UdpPacketParser.TryParseUdp6(packet, (uint)packet.Length, out _, out _, out _, out _));
    }

    [Fact]
    public void TryParseUdp6_RejectsTooShort()
    {
        var packet = new byte[20];
        packet[0] = 0x60;
        Assert.False(UdpPacketParser.TryParseUdp6(packet, (uint)packet.Length, out _, out _, out _, out _));
    }

    [Fact]
    public void BuildFilterV6_CapturesOutboundV6Dns()
    {
        // With only the DNS leg on, the v6 filter must be DNS-only and
        // outbound-only: outbound means injected replies can never re-enter the
        // capture (no loop).
        var filter = UdpDnsFerry.BuildFilterV6(dnsEnabled: true, stunPortsEnabled: false);

        Assert.Equal("outbound and ipv6 and udp and udp.DstPort == 53 and not loopback", filter);
        Assert.DoesNotContain(" and ip ", filter);
    }

    [Fact]
    public void BuildFilterV6_IncludesStunPortsWhenStunHandlingIsEnabled()
    {
        // THE REGRESSION THIS PINS: the v6 handle used to be DNS-only with a
        // comment claiming "STUN is IPv4-standard". Browsers resolve AAAA
        // records and prefer IPv6 for the same STUN server, so on a dual-stack
        // machine every STUN request left the v4 handle and went out the IPv6
        // NIC directly — reporting the real address. The STUN setting appeared
        // to do nothing, which is exactly the reported symptom.
        var filter = UdpDnsFerry.BuildFilterV6(dnsEnabled: true, stunPortsEnabled: true);

        Assert.Contains("ipv6", filter);
        Assert.Contains("udp.DstPort == 53", filter);
        // Both the standard ports and Google's browser-default range.
        foreach (var port in new[] { 3478, 5349, 19302, 19309 })
            Assert.Contains(port.ToString(), filter);
        Assert.Contains("not loopback", filter);
        Assert.DoesNotContain(" and ip ", filter);
    }

    [Fact]
    public void BuildFilterV6_SeparatesTheTwoLegs_Independently()
    {
        // WebRTC blocking alone must not start intercepting IPv6 DNS.
        var stunOnly = UdpDnsFerry.BuildFilterV6(dnsEnabled: false, stunPortsEnabled: true);
        Assert.DoesNotContain("udp.DstPort == 53", stunOnly);
        Assert.Contains("19302", stunOnly);
    }

    [Fact]
    public void BothFamilies_CarryTheSameStunPorts()
    {
        // A port present on only ONE side is a silent, family-dependent leak:
        // the result then depends on which address family the client happened
        // to pick, which is why this was invisible on the IPv4-only tests.
        var v4 = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: true);
        var v6 = UdpDnsFerry.BuildFilterV6(dnsEnabled: true, stunPortsEnabled: true);

        foreach (var port in UdpDnsFerry.StunPorts)
        {
            Assert.Contains(port.ToString(), v4);
            Assert.Contains(port.ToString(), v6);
        }
    }

    [Fact]
    public void BuildFilterV4_RemainsIpv4Only()
    {
        var filter = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: false);

        Assert.Contains("outbound", filter);
        Assert.Contains("ip and udp", filter);
        Assert.Contains("udp.DstPort == 53", filter);
        Assert.DoesNotContain("ipv6", filter);
    }
}
