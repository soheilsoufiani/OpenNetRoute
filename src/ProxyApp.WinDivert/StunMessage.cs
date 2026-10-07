namespace ProxyApp.WinDivert;

/// <summary>
/// Identifies STUN/TURN messages by CONTENT rather than by port.
///
/// <para>
/// WHY THIS EXISTS: STUN handling was originally port-based (3478, 19302, …).
/// That is a guess, and it was wrong — WebRTC servers may listen on any port,
/// because the port travels in the STUN server URI, and the browserleaks.com
/// WebRTC test uses a non-standard one. A port-matched filter let that traffic
/// through, the STUN server answered, and the page reported a
/// server-reflexive candidate carrying the user's real address. The filter
/// looked correct and simply did not match.
/// </para>
///
/// <para>
/// The reliable discriminator is the STUN magic cookie. RFC 5389 §6 puts the
/// fixed value <c>0x2112A442</c> in bytes 4–7 of every STUN message header
/// (after the 2-byte type and 2-byte length), and RFC 8489 keeps it. The
/// first two bits of the message type are also required to be zero, which
/// removes almost all false positives on random UDP payloads.
/// </para>
///
/// <para>
/// This is detection only — it never inspects or modifies content beyond
/// reading four fixed bytes of the header, and it is used to DROP a datagram
/// that would otherwise reveal the user's address. It is not TLS
/// interception and does not decrypt anything.
/// </para>
/// </summary>
internal static class StunMessage
{
    /// <summary>
    /// The RFC 5389 §6 magic cookie, present in every STUN message header at
    /// offset 4. Kept as named constants because the byte comparison below is
    /// the entire detection mechanism and should read as the spec value.
    /// </summary>
    private const byte Cookie0 = 0x21;
    private const byte Cookie1 = 0x12;
    private const byte Cookie2 = 0xA4;
    private const byte Cookie3 = 0x42;

    /// <summary>
    /// The STUN/TURN message types worth acting on. Binding Request (0x0001)
    /// is what discovers the public address; the others are ICE consent,
    /// keep-alives and TURN Allocate that carry the same disclosure.
    ///
    /// 0x0003 and 0x0004 (TURN Data / ChannelData) are deliberately NOT listed:
    /// they are the media path, not address discovery, and dropping them would
    /// break a working call without improving privacy.
    /// </summary>
    private static bool IsAddressDiscoveryType(ushort messageType) => messageType switch
    {
        0x0001 => true, // Binding Request
        0x0101 => true, // Binding Success Response
        0x0111 => true, // Binding Error Response
        0x0002 => true, // Binding Indication (consent freshness)
        _ => false
    };

    /// <summary>
    /// True when the UDP payload is a STUN address-discovery message.
    ///
    /// Exposed as an internal seam so it is unit-testable without a live
    /// capture handle, and so the drop decision in the ferry has exactly one
    /// authoritative implementation.
    /// </summary>
    /// <param name="payload">The UDP payload (IP and UDP headers already removed).</param>
    public static bool IsStun(ReadOnlySpan<byte> payload)
    {
        // A STUN header is 20 bytes minimum (RFC 5389 §6): type(2) length(2)
        // cookie(4) transaction-id(12) [attributes]. Anything shorter cannot be
        // STUN, and must not be treated as such — dropping short UDP payloads
        // by mistake would break DNS (which can be as small as a 17-byte query)
        // and unrelated traffic.
        if (payload.Length < 20)
            return false;

        // The two most significant bits of the message type MUST be zero
        // (RFC 5389 §6). This is what makes the magic-cookie test safe on
        // arbitrary UDP: without it, ~1 in 65,536 random 8-byte prefixes would
        // collide with the cookie.
        if ((payload[0] & 0xC0) != 0)
            return false;

        var messageType = (ushort)((payload[0] << 8) | payload[1]);
        if (!IsAddressDiscoveryType(messageType))
            return false;

        // The cookie is the actual discriminator.
        return payload[4] == Cookie0 && payload[5] == Cookie1 &&
               payload[6] == Cookie2 && payload[7] == Cookie3;
    }
}