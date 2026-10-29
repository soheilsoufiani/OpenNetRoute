using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the DNS ferry's DNS-over-TCP fallback reply builder
/// (<see cref="DnsTruncatedReply"/>) — the piece that turns a proxy WITHOUT UDP
/// ASSOCIATE from "all system DNS dead" into "DNS resolves over TCP/53".
///
/// The mechanism under test: on a proxy whose SOCKS5 answers UDP ASSOCIATE with
/// reply 0x07 ("command not supported" — full-VPN backends are the classic
/// case), the ferry cannot relay a single UDP query. Instead of dropping them
/// fail-closed forever (no leak, but no name resolution either), the ferry
/// answers each captured query with a TRUNCATED (TC=1) reply. A compliant
/// resolver (the Windows resolver, browsers) then re-issues the SAME query over
/// TCP/53 — a forced-proxy port on the TCP ferry — so the query still travels
/// through the proxy. Nothing is ever released to the direct path.
///
/// These tests pin the reply's wire format, because every field has a job:
/// the transaction ID correlates the reply with the query, the echoed OPCODE
/// keeps non-standard queries recognisable, the TC bit triggers the TCP retry,
/// and zero ANCOUNT/NSCOUNT/ARCOUNT makes the reply minimal and honest (no
/// fabricated records, no echoed EDNS OPT).
/// </summary>
public class DnsTruncatedReplyTests
{
    // ── Test construction helpers ──
    // RFC 1035 wire format, all 16-bit fields big-endian. Built by hand from
    // numbers so a mistake in the EXPECTED bytes cannot hide behind a shared
    // encoder used for both the input and the assertion.

    /// <summary>A DNS header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.</summary>
    private static byte[] Header(ushort id, ushort flags, ushort qd, ushort an, ushort ns, ushort ar)
    {
        var header = new byte[12];
        WriteWord(header, 0, id);
        WriteWord(header, 2, flags);
        WriteWord(header, 4, qd);
        WriteWord(header, 6, an);
        WriteWord(header, 8, ns);
        WriteWord(header, 10, ar);
        return header;
    }

    /// <summary>A domain name as an uncompressed label sequence, root-terminated.</summary>
    private static byte[] Name(params string[] labels)
    {
        var name = new List<byte>();
        foreach (var label in labels)
        {
            name.Add((byte)label.Length);
            foreach (var character in label)
                name.Add((byte)character);
        }

        name.Add(0); // root
        return name.ToArray();
    }

    private static byte[] Bytes(params byte[] bytes) => bytes;

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var combined = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(combined, offset);
            offset += part.Length;
        }

        return combined;
    }

    private static ushort Word(byte[] packet, int offset) =>
        (ushort)((packet[offset] << 8) | packet[offset + 1]);

    private static void WriteWord(byte[] packet, int offset, ushort word)
    {
        packet[offset] = (byte)(word >> 8);
        packet[offset + 1] = (byte)word;
    }

    /// <summary>The question section for <c>www.example.com A IN</c> — 21 bytes.</summary>
    private static byte[] ExampleComAQuestion() =>
        Concat(
            Name("www", "example", "com"),
            Bytes(0x00, 0x01), // QTYPE = A
            Bytes(0x00, 0x01)); // QCLASS = IN

    // ── The happy path: a plain query becomes exactly one TC=1 reply ──

    [Fact]
    public void PlainQuery_IsAnsweredWithATruncatedReply()
    {
        // A realistic recursive query by the Windows resolver: RD set, one
        // question. ID 0xABCD on purpose — its big-endian byte order is part
        // of the contract (an echoed-swapped ID would fail to correlate).
        var query = Concat(Header(0xABCD, 0x0100, 1, 0, 0, 0), ExampleComAQuestion());

        var reply = DnsTruncatedReply.BuildTruncatedReply(query);

        Assert.NotNull(reply);
        Assert.Equal(12 + 21, reply!.Length); // header + the question, nothing else

        // Transaction ID echoed big-endian, byte-for-byte: the client uses it
        // to decide whether the reply belongs to its outstanding query.
        Assert.Equal(0xAB, reply[0]);
        Assert.Equal(0xCD, reply[1]);

        // FLAGS = 0x8300: QR (0x8000) | TC (0x0200) | RD (0x0100, copied).
        // OPCODE is 0, and deliberately NOT set: AA (0x0400), RA (0x0080), the
        // Z bits, and RCODE — this is a relay shim's re-ask-over-TCP nudge,
        // not an authoritative resolver's answer.
        Assert.Equal(0x8300, Word(reply, 2));

        Assert.Equal(1, Word(reply, 4));  // QDCOUNT = the echoed question
        Assert.Equal(0, Word(reply, 6));  // ANCOUNT = zero
        Assert.Equal(0, Word(reply, 8));  // NSCOUNT = zero
        Assert.Equal(0, Word(reply, 10)); // ARCOUNT = zero

        // The question section is verbatim — same name encoding, QTYPE, QCLASS.
        Assert.Equal(ExampleComAQuestion(), reply.Skip(12).ToArray());
    }

    [Fact]
    public void Opcode_IsPreservedFromTheQuery()
    {
        // An INVERSE-query-style flags value (opcode 1 = 0x0800 set, RD kept):
        // the reply must still announce the SAME opcode — an inverse query
        // answered as a standard query would be discarded by the client, and
        // "discarded replies" here is precisely the silent-failure mode this
        // fallback exists to avoid.
        var query = Concat(Header(0x0001, 0x0900, 1, 0, 0, 0), ExampleComAQuestion());

        var reply = DnsTruncatedReply.BuildTruncatedReply(query);

        Assert.NotNull(reply);
        // QR | opcode 1 | TC | RD = 0x8000 | 0x0800 | 0x0200 | 0x0100 = 0x8B00.
        Assert.Equal(0x8B00, Word(reply!, 2));
    }

    [Fact]
    public void EdnsQuery_AnswersTheQuestionOnly_WithoutEchoingTheOpt()
    {
        // EDNS0 (RFC 6891): the OPT record lives in the additional section —
        // root name, TYPE=0x0029, CLASS=4096 (the UDP payload size), TTL, and
        // an empty RDATA. The TC reply deliberately omits it: a truncated
        // response advertising more data than the resolver's UDP buffer would
        // be self-defeating, and over TCP the buffer does not matter. The
        // ANCOUNT/NSCOUNT/ARCOUNT fields must all read zero.
        var question = ExampleComAQuestion();
        var optRecord = Concat(
            Bytes(0x00),             // root name
            Bytes(0x00, 0x29),       // TYPE = OPT (41)
            Bytes(0x10, 0x00),       // CLASS = UDP payload size 4096
            Bytes(0x00, 0x00, 0x00, 0x00), // TTL (extended RCODE + flags)
            Bytes(0x00, 0x00));      // RDLENGTH = 0
        var query = Concat(Header(0x4242, 0x0100, 1, 0, 0, 1), question, optRecord);

        var reply = DnsTruncatedReply.BuildTruncatedReply(query);

        Assert.NotNull(reply);
        Assert.Equal(12 + question.Length, reply!.Length); // no OPT bytes copied
        Assert.Equal(0, Word(reply, 6));  // ANCOUNT
        Assert.Equal(0, Word(reply, 8));  // NSCOUNT
        Assert.Equal(0, Word(reply, 10)); // ARCOUNT zeroised despite ARCOUNT=1 in the query
        Assert.Equal(question, reply.Skip(12).ToArray());
    }

    // ── The fail-closed cases: NOT answered, so the ferry keeps its drop ──

    [Fact]
    public void CapturedResponse_IsNeverAnsweredWithAnotherResponse()
    {
        // Some resolvers reply from a port-53 OUTBOUND socket, so the ferry
        // captures QR=1 datagrams too. "Truncating" a response into another
        // response is meaningless (and dangerous: a fabricated RCODE would be
        // treated as real), so the builder refuses — the datagram is dropped
        // by the ferry's fail-closed rule instead.
        var query = Concat(Header(0x1111, 0x8180, 1, 2, 0, 0), ExampleComAQuestion());

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    [Fact]
    public void TruncatedHeader_IsNotAnswered()
    {
        // 11 bytes cannot even carry a DNS header; the ferry's captures are
        // dropped fail-closed before this, but the builder also refuses on its
        // own terms so the two layers cannot disagree.
        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(new byte[11]));
    }

    [Fact]
    public void TwoQuestionQuery_StaysFailClosedInsteadOfAMalformedReply()
    {
        // Multi-question queries are a legacy curiosity; echoing ONE question
        // for a TWO-question query would byte-count against the client's view
        // of the transaction. The fallback answers nothing — the client keeps
        // retrying UDP (and the worst case is a dropped legacy query, never a
        // leak: the packet is never released to the direct path).
        var question = ExampleComAQuestion();
        var query = Concat(Header(0x0001, 0x0100, 2, 0, 0, 0), question, question);

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    [Fact]
    public void ZeroQuestionQuery_IsNotAnswered()
    {
        var query = Header(0x0001, 0x0100, 0, 0, 0, 0);

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    [Fact]
    public void CompressionPointerInTheQuestion_FailsClosed()
    {
        // A compression pointer (top two bits = 11) never starts a client's
        // question section — there is nothing earlier in the message to point
        // at. Refusing beats guessing at what it might mean; the query is
        // dropped fail-closed and the client retries.
        var query = Concat(
            Header(0x00FF, 0x0100, 1, 0, 0, 0),
            Bytes(0xC0, 0x0C),              // pointer to offset 12 (the message start)
            Bytes(0x00, 0x01),
            Bytes(0x00, 0x01));

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    [Fact]
    public void LabelRunawayName_IsNotAnswered()
    {
        // A label claiming 5 characters with only 2 in the packet: parsing
        // would read past the end. Malformed on its face — not answered.
        var query = Concat(Header(0x00FF, 0x0100, 1, 0, 0, 0), Bytes(0x05, 0x61, 0x62));

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    [Fact]
    public void QuestionWithoutQtypeQclass_IsNotAnswered()
    {
        // Name present, then the packet ends before QTYPE (2) and QCLASS (2):
        // a truncated one-question reply needs the full question to make the
        // client's TCP retry carry the same meaning.
        var query = Concat(
            Header(0x00FF, 0x0100, 1, 0, 0, 0),
            Name("a"),
            Bytes(0x00, 0x01)); // QTYPE only — no QCLASS

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }

    // ── Extended-label types (0b01 / 0b10) are refused like pointers ──

    [Fact]
    public void ExtendedLabelInQuestion_FailsClosed()
    {
        // Non-standard label types (0x41 EDNS label scheme etc.) have no place
        // in a client query's question section; by the same rule the builder
        // must not interpret them as ordinary labels.
        var query = Concat(
            Header(0x00FF, 0x0100, 1, 0, 0, 0),
            Bytes(0x40, 0x08, 0x61),        // 0b01xxxxxx = extended label
            Bytes(0x00, 0x01),
            Bytes(0x00, 0x01));

        Assert.Null(DnsTruncatedReply.BuildTruncatedReply(query));
    }
}
