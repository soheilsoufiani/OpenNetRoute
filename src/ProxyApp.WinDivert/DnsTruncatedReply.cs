namespace ProxyApp.WinDivert;

/// <summary>
/// Builds TRUNCATED (TC=1) DNS replies for the ferry's DNS-over-TCP fallback.
///
/// WHY THIS EXISTS: some SOCKS5 proxies support TCP CONNECT but reject UDP
/// ASSOCIATE with reply code 0x07 ("command not supported") — a full-VPN
/// backend is the common case. On such a proxy the ferry's UDP relay can never
/// work, and the fail-closed drop rule would take down ALL system DNS while the
/// relay is on: no leak, but no resolution either.
///
/// The fallback turns that dead end into working DNS without any new proxy
/// transport: the captured UDP query is answered with a synthetic response
/// whose TRUNCATION (TC) bit is set. A compliant resolver (the Windows
/// resolver, browsers) re-issues the SAME query over TCP/53 on its own — and
/// TCP/53 is a forced-proxy port on the <see cref="TcpFerry"/> (see
/// ProxyEngine.DnsRelayTcpPorts), so the retry travels through the proxy over
/// CONNECT, which such proxies do support. Nothing is released to the direct
/// path; the fail-closed invariant is preserved.
///
/// The reply is deliberately MINIMAL: header + the query's question section,
/// zero answer/authority/additional records. Per RFC 1035 §4.1.4 a truncated
/// response may omit RRs entirely; the TC bit alone is what drives the retry.
/// EDNS0 (an OPT in the query's additional section) is NOT echoed — a truncated
/// response carrying more data than the caller's advertised buffer would be
/// self-defeating, and the retry over TCP makes the buffer irrelevant.
///
/// Conservative by construction: every input that cannot be interpreted as a
/// well-formed single-question standard query returns <c>null</c>, and the
/// caller MUST keep its fail-closed drop for that case. A reply that looks
/// valid to us but foreign to the client (wrong shape, wrong transaction ID)
/// would be discarded by the client while the query stays intercepted — safe —
/// but silently prolonging the blackout is worse than an honest drop trace.
/// </summary>
internal static class DnsTruncatedReply
{
    internal const int HeaderLength = 12;

    /// <summary>QR (query/response) flag.</summary>
    private const ushort FlagQr = 0x8000;

    /// <summary>TrunCation flag — the whole point of this reply.</summary>
    private const ushort FlagTc = 0x0200;

    /// <summary>Recursion Desired (copied from the query).</summary>
    private const ushort FlagRd = 0x0100;

    /// <summary>
    /// Builds a truncated (TC=1) reply for one standard query, or null when the
    /// payload is not a well-formed single-question standard query (the caller
    /// then keeps its fail-closed drop).
    /// </summary>
    /// <remarks>
    /// The reply preserves, by design: the transaction ID (so the client
    /// correlates it), the OPCODE (a reverse/status query must not come back
    /// looking like a standard one), the RD bit, and the question section verbatim.
    /// It zeroises ANCOUNT/NSCOUNT/ARCOUNT, sends NOERROR, and never sets AA/RA —
    /// this is a relay shim's "re-ask over TCP" nudge, not an authoritative server.
    /// </remarks>
    public static byte[]? BuildTruncatedReply(ReadOnlySpan<byte> query)
    {
        // A DNS header is 12 bytes; anything shorter is not a message we can
        // safely answer (and per the fail-closed contract must not be released).
        if (query.Length < HeaderLength)
            return null;

        var id = (ushort)((query[0] << 8) | query[1]);
        var queryFlags = (ushort)((query[2] << 8) | query[3]);

        // Only QUERIES are answered with TC. A captured QR=1 "response" (because
        // it was sent OUTBOUND UDP/53 — some resolvers do respond on the same
        // port the query left) cannot be truncated into another response.
        if ((queryFlags & FlagQr) != 0)
            return null;

        // Exactly ONE question is supported — the universal shape (the Windows
        // resolver, browsers, virtually every client sends one question per
        // query). A multi-question query is a legacy curiosity; a reply that
        // echoes fewer questions than the query contains is malformed against
        // the client's own view of the transaction, so such a query stays
        // fail-closed dropped rather than answered with something dubious.
        var qdCount = (ushort)((query[4] << 8) | query[5]);
        if (qdCount != 1)
            return null;

        // Walk EXACTLY ONE question: labels until the root, then QTYPE/QCLASS.
        // A compression pointer (top two bits 11) is legal in RRs but never sent
        // by a client's question section (there is nothing earlier to point at);
        // treating it as unparsable keeps the parser honest rather than clever —
        // the query is dropped fail-closed and the client retries.
        if (!TryParseSingleQuestion(query, out var questionLength))
            return null;

        var response = new byte[HeaderLength + questionLength];

        // ID echoed big-endian, exactly as the client sent it.
        response[0] = query[0];
        response[1] = query[1];

        // Flags: QR + the query's OPCODE (bits 3-0 of the high byte) + TC + RD.
        // Everything else is zeroised: NO RCODE beyond NOERROR, no RA (we are
        // not a resolver), no Z bits.
        var responseFlags = (ushort)(FlagQr | (queryFlags & 0x7800) | FlagTc | (queryFlags & FlagRd));
        response[2] = (byte)(responseFlags >> 8);
        response[3] = (byte)responseFlags;

        // QDCOUNT = 1 (the echoed question), all other counts zero.
        response[4] = 0;
        response[5] = 1;

        // The question section, verbatim (name + type + class).
        query.Slice(HeaderLength, questionLength).CopyTo(response.AsSpan(HeaderLength));

        return response;
    }

    /// <summary>
    /// Reads one question section (a root-terminated label sequence plus
    /// QTYPE/QCLASS) and reports its length in bytes, never reading past the
    /// end of <paramref name="query"/>.
    /// </summary>
    private static bool TryParseSingleQuestion(ReadOnlySpan<byte> query, out int questionLength)
    {
        questionLength = 0;
        var offset = HeaderLength;

        while (true)
        {
            // Ran past the end mid-name — truncated packet, unparsable.
            if (offset >= query.Length)
                return false;

            var length = query[offset];

            if (length == 0)
            {
                // Root label terminates the name. A question needs QTYPE and
                // QCLASS after it; both must be within the packet.
                if (offset + 4 >= query.Length)
                    return false;

                questionLength = offset + 4 + 1 - HeaderLength; // header + name + type + class
                return true;
            }

            // 0xxxxxxx = label (0-63). All other patterns (0b11 compression
            // pointer, 0b01/0b10 extended labels) are not produced by a client
            // question section and are rejected rather than guessed at.
            if ((length & 0xC0) != 0 || length > 63)
                return false;

            var labelEnd = offset + 1 + length;
            if (labelEnd > query.Length)
                return false;

            offset = labelEnd;
        }
    }
}
