using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for <see cref="StunMessage"/> — the CONTENT test that replaced
/// port-based WebRTC blocking.
///
/// <para>
/// The bug: blocking matched STUN by destination port (3478, 19302–19309, …).
/// That is a guess, and it was wrong — a WebRTC server may listen on any port,
/// because the port travels in the STUN server URI, and browserleaks.com's
/// WebRTC test uses a non-standard one. The filter looked correct, the setting
/// read "on", and the page still reported a server-reflexive candidate carrying
/// the real address. Matching on the RFC 5389 magic cookie removes the port from
/// the decision entirely.
/// </para>
///
/// <para>
/// These tests exist mainly to protect OTHER traffic: a false positive here
/// silently discards a datagram the user needed, so the negative cases matter as
/// much as the positive one.
/// </para>
/// </summary>
public class StunMessageTests
{
    /// <summary>
    /// Builds a minimal but spec-shaped STUN header: type(2) length(2)
    /// cookie(4) transaction-id(12) = 20 bytes, the RFC 5389 §6 minimum.
    /// </summary>
    private static byte[] BuildStun(ushort messageType)
    {
        var packet = new byte[20];
        packet[0] = (byte)(messageType >> 8);
        packet[1] = (byte)messageType;
        // packet[2..4] = message length; 0 is valid for a header-only message.
        packet[4] = 0x21; // magic cookie 0x2112A442, RFC 5389 §6
        packet[5] = 0x12;
        packet[6] = 0xA4;
        packet[7] = 0x42;
        // packet[8..20] = transaction ID, left as zeros; irrelevant to detection.
        return packet;
    }

    [Theory]
    // Binding Request — the message that discovers the public address.
    [InlineData(0x0001)]
    // Binding Success Response — inbound, but matched symmetrically so the test
    // documents that the check is type-driven, not direction-driven.
    [InlineData(0x0101)]
    // Binding Error Response.
    [InlineData(0x0111)]
    // Binding Indication (ICE consent freshness).
    [InlineData(0x0002)]
    public void AddressDiscoveryMessages_AreDetected(ushort messageType)
    {
        Assert.True(StunMessage.IsStun(BuildStun(messageType)));
    }

    [Fact]
    public void ARealShapedBindingRequest_Detected()
    {
        // The actual shape sent by a browser, including a USERNAME/MAPPED-ADDRESS
        // attribute body, to prove detection does not depend on the message being
        // exactly 20 bytes.
        var packet = new byte[20 + 12];
        var header = BuildStun(0x0001);
        Array.Copy(header, packet, 20);
        packet[21] = 0x08; // attribute type MAPPED-ADDRESS
        packet[22] = 0x00;
        packet[23] = 0x04; // attribute length

        Assert.True(StunMessage.IsStun(packet));
    }

    [Fact]
    public void TurnDataAndChannelData_AreNotDetected()
    {
        // Deliberate: these are the MEDIA path, not address discovery. Dropping
        // them would break a call that is already working without improving
        // privacy — and a relay candidate, once obtained, is what reveals the
        // address, not the media that follows.
        Assert.False(StunMessage.IsStun(BuildStun(0x0013))); // TURN Data
        Assert.False(StunMessage.IsStun(BuildStun(0x0014))); // TURN Allocate is
                                                              // 0x0003; 0x0014 is
                                                              // Send/Data Indication

        // TURN ChannelData has no magic cookie at all: the first two bits of the
        // channel number are 01, which the type-bit check also rejects.
        var channelData = new byte[4];
        channelData[0] = 0x40;
        channelData[1] = 0x01;
        Assert.False(StunMessage.IsStun(channelData));
    }

    [Fact]
    public void NonStunUdp_IsNotDetected()
    {
        // The negative cases that protect everything else. Each of these is real
        // traffic that must pass through untouched.

        // Plain QUIC initial (browsers use QUIC heavily — a false positive here
        // would break all HTTPS on QUIC-capable sites).
        var quic = new byte[1200];
        quic[0] = 0xC0; // QUIC long header: the top bits are 1, not 0
        Assert.False(StunMessage.IsStun(quic));

        // A payload long enough to pass the size check, with high type bits set.
        var dnsish = new byte[64];
        dnsish[0] = 0x80;
        Assert.False(StunMessage.IsStun(dnsish));
    }

    [Fact]
    public void ShortPayloads_AreNeverTreatedAsStun()
    {
        // The length guard matters more than it looks: a 17-byte DNS query is
        // smaller than a STUN header. Without the guard, dropping short datagrams
        // would take DNS with it.
        for (var len = 0; len < 20; len++)
        {
            var payload = new byte[len];
            if (len > 7)
            {
                payload[0] = 0x00;
                payload[1] = 0x01;
                payload[4] = 0x21;
                payload[5] = 0x12;
                payload[6] = 0xA4;
                payload[7] = 0x42;
            }
            Assert.False(StunMessage.IsStun(payload));
        }
    }

    [Fact]
    public void CorrectCookie_WithWrongTypeBits_IsRejected()
    {
        // A random payload can contain the cookie at offset 4. The RFC requires
        // the two most significant bits of the message type to be zero, and this
        // check is what keeps a 1-in-65,536 collision from discarding a datagram.
        var packet = BuildStun(0x0001);
        packet[0] |= 0x80; // set the top bit, violating RFC 5389 §6

        Assert.False(StunMessage.IsStun(packet));
    }

    [Fact]
    public void CorrectType_WithWrongCookie_IsRejected()
    {
        // The cookie is the discriminator; a matching message type alone is not
        // enough. This is the case a port-based filter could not even express.
        var packet = BuildStun(0x0001);
        packet[7] = 0x99;

        Assert.False(StunMessage.IsStun(packet));
    }

    [Fact]
    public void TheCookieIsReadAtTheSpecifiedOffset()
    {
        // Guards against an off-by-N in the offset, which would look correct in
        // review and match nothing on the wire — the same class of defect as the
        // IPv4/IPv6 header-length bug already fixed in this codebase.
        var packet = BuildStun(0x0001);
        var shifted = new byte[20];
        Array.Copy(packet, 3, shifted, 0, 17); // cookie now sits at offset 7

        Assert.False(StunMessage.IsStun(shifted));
    }
}
