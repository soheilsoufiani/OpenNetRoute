using System.Net;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the encrypted-DNS SNI observer's parsing and classification.
///
/// Two properties matter most and are pinned here:
/// <list type="number">
/// <item>The ClientHello SNI parser reads the hostname correctly and rejects
/// malformed input instead of throwing — it runs on the capture path, so an
/// exception would kill the observe loop.</item>
/// <item>Only EXACT resolver hostnames are flagged. A substring or suffix match
/// would flag ordinary sites, and for a user whose proxy egress is Cloudflare
/// or Google it would report "everything is leaking".</item>
/// </list>
/// </summary>
public class DnsSniInspectorTests
{
    /// <summary>
    /// Builds a minimal but structurally valid TLS ClientHello carrying one SNI
    /// extension. The layout follows RFC 5246 §7.4.1.2 and RFC 6066 §3, which is
    /// exactly what the parser walks.
    /// </summary>
    private static byte[] BuildClientHello(string? host)
    {
        // Extensions block: optional SNI (type 0).
        var extensions = new List<byte>();
        if (host is not null)
        {
            var name = Encoding.ASCII.GetBytes(host);
            var serverName = new List<byte>
            {
                0x00,                          // name_type = host_name
                (byte)(name.Length >> 8),
                (byte)name.Length,
            };
            serverName.AddRange(name);

            var listLength = serverName.Count;
            extensions.AddRange(new byte[] { 0x00, 0x00 });                 // type = server_name
            extensions.Add((byte)((serverName.Count) >> 8));
            extensions.Add((byte)(serverName.Count));
            extensions.AddRange(new List<byte> { (byte)(listLength >> 8), (byte)listLength });
            extensions.AddRange(serverName);
        }

        var body = new List<byte>
        {
            0x03, 0x03,                        // client_version TLS 1.2
        };
        body.AddRange(Enumerable.Repeat((byte)0xAB, 32));                  // random
        body.Add(0x00);                                                     // session_id_len = 0
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 });              // cipher suites (TLS_AES_128_GCM_SHA256)
        body.Add(0x01);                                                     // compression_methods_len = 1
        body.Add(0x00);                                                     // null compression
        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)extensions.Count);
        body.AddRange(extensions);

        var handshake = new List<byte> { 0x01 };                            // ClientHello
        handshake.Add((byte)(body.Count >> 16));
        handshake.Add((byte)(body.Count >> 8));
        handshake.Add((byte)body.Count);
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };                   // Handshake, TLS 1.0 record ver
        record.Add((byte)(handshake.Count >> 8));
        record.Add((byte)handshake.Count);
        record.AddRange(handshake);
        return record.ToArray();
    }

    /// <summary>Wraps a TCP payload in an IPv4/TCP header for Inspect().</summary>
    private static byte[] WrapInTcpPacket(ReadOnlySpan<byte> payload, ushort dstPort = 443)
    {
        const int ipLen = 20, tcpLen = 20;
        var packet = new byte[ipLen + tcpLen + payload.Length];
        packet[0] = 0x45;                              // IPv4, IHL 5
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        packet[8] = 64;                                // TTL
        packet[9] = 6;                                 // TCP
        new IPAddress(new byte[] { 192, 168, 1, 10 }).GetAddressBytes().CopyTo(packet, 12);
        new IPAddress(new byte[] { 104, 16, 0, 1 }).GetAddressBytes().CopyTo(packet, 16);
        // Not `const`: a constant 51234 cannot be narrowed to byte without
        // `unchecked`, and the truncating cast is exactly what we want here.
        ushort srcPort = 51234;
        packet[20] = (byte)(srcPort >> 8);
        packet[21] = (byte)srcPort;
        packet[22] = (byte)(dstPort >> 8);
        packet[23] = (byte)dstPort;
        packet[32] = 0x50;                             // data offset 5 (no options)
        packet[33] = 0x18;                             // PSH|ACK
        payload.CopyTo(packet.AsSpan(ipLen + tcpLen));
        return packet;
    }

    [Fact]
    public void TryReadClientHelloHost_ReadsTheSniHostname()
    {
        var hello = BuildClientHello("dns.google");
        Assert.True(DnsSniInspector.TryReadClientHelloHost(hello, out var host));
        Assert.Equal("dns.google", host);
    }

    [Fact]
    public void TryReadClientHelloHost_RejectsNonHandshakeRecord()
    {
        // 0x17 = application_data. Not a ClientHello.
        var payload = new byte[] { 0x17, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04 };
        Assert.False(DnsSniInspector.TryReadClientHelloHost(payload, out _));
    }

    [Fact]
    public void TryReadClientHelloHost_RejectsTruncatedInput()
    {
        // A real capture can hand us a short segment; the parser must return
        // false rather than read past the end (it runs on the capture path, so
        // an exception would kill the observe loop).
        var hello = BuildClientHello("dns.quad9.net");
        for (var cut = 5; cut < hello.Length; cut++)
            Assert.False(DnsSniInspector.TryReadClientHelloHost(hello.AsSpan(0, cut), out _));
    }

    [Fact]
    public void TryReadClientHelloHost_ReturnsFalseWhenSniAbsent()
    {
        var hello = BuildClientHello(null);
        Assert.False(DnsSniInspector.TryReadClientHelloHost(hello, out _));
    }

    [Theory]
    [InlineData("dns.google", true)]
    [InlineData("DNS.GOOGLE", true)]              // case-insensitive
    [InlineData("dns.google.", true)]              // trailing root dot
    [InlineData("chrome.cloudflare-dns.com", true)]
    [InlineData("dns.adguard-dns.com", true)]
    [InlineData("dns.quad9.net", true)]
    [InlineData("doh.opendns.com", true)]
    // NOT resolver endpoints. A substring, suffix or "strip www." match would
    // fail these — and each one is real web traffic, so a false positive here
    // would report normal browsing as encrypted DNS.
    [InlineData("www.dns.google", false)]
    [InlineData("example.com", false)]
    [InlineData("notdns.google", false)]           // prefix must not match
    [InlineData("google.com", false)]
    [InlineData("dns.google.evil.com", false)]     // suffix must not match
    [InlineData("cloudflare.com.evil.test", false)]
    [InlineData("", false)]
    public void IsKnownEncryptedDnsHost_MatchesOnlyExactResolverEndpoints(
        string host, bool expected)
    {
        Assert.Equal(expected, DnsSniInspector.IsKnownEncryptedDnsHost(host));
    }

    [Fact]
    public void IsKnownEncryptedDnsHost_DoesNotFlagOrdinaryWebTraffic()
    {
        // Every one of these is a real, commonly-visited hostname. For a user
        // whose proxy egress is Cloudflare, flagging CDN or vendor hostnames
        // would report every page load as a leak and make the whole
        // diagnostic untrustworthy.
        Assert.False(DnsSniInspector.IsKnownEncryptedDnsHost("cdnjs.cloudflare.com"));
        Assert.False(DnsSniInspector.IsKnownEncryptedDnsHost("www.cloudflare.com"));
        Assert.False(DnsSniInspector.IsKnownEncryptedDnsHost("cloudflare.com"));
        Assert.False(DnsSniInspector.IsKnownEncryptedDnsHost("www.google.com"));
        Assert.False(DnsSniInspector.IsKnownEncryptedDnsHost("github.com"));
    }

    [Fact]
    public void Inspect_ReportsKnownEncryptedResolverWithProcessName()
    {
        var hits = new List<string>();
        var inspector = new DnsSniInspector(
            new DnsSettings { Enabled = true },
            hit: hits.Add,
            processResolver: new StubResolver("chrome.exe", 4321));

        var packet = WrapInTcpPacket(BuildClientHello("dns.google"));
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Equal(1, inspector.EncryptedDnsHits);
        Assert.Equal(1, inspector.HostnamesParsed);
        var hit = Assert.Single(hits);
        Assert.Contains("chrome.exe", hit);
        Assert.Contains("dns.google", hit);
        Assert.Contains("not relayed", hit, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Inspect_IgnoresOrdinaryHttpsAndCountsItAsInspected()
    {
        var hits = new List<string>();
        var inspector = new DnsSniInspector(
            new DnsSettings { Enabled = true },
            hit: hits.Add,
            processResolver: new StubResolver("chrome.exe", 1));

        var packet = WrapInTcpPacket(BuildClientHello("www.example.com"));
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Empty(hits);
        Assert.Equal(0, inspector.EncryptedDnsHits);
        Assert.Equal(1, inspector.HostnamesParsed);
    }

    [Fact]
    public void Inspect_IgnoresNon443Destinations()
    {
        var hits = new List<string>();
        var inspector = new DnsSniInspector(
            new DnsSettings { Enabled = true }, hit: hits.Add);

        var packet = WrapInTcpPacket(BuildClientHello("dns.google"), dstPort: 8443);
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Empty(hits);
    }

    [Fact]
    public void Inspect_CountsUnreadableSniAsBlindSpot()
    {
        // An Encrypted ClientHello is a genuine blind spot. It must be SURFACED,
        // not silently ignored — otherwise a leak test result cannot be trusted.
        var inspector = new DnsSniInspector(new DnsSettings { Enabled = true });

        // Well-formed TLS handshake carrying a ClientHello but no SNI extension.
        var packet = WrapInTcpPacket(BuildClientHello(null));
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Equal(1, inspector.NoSniConnections);
        Assert.Equal(1, inspector.ConnectionsObserved);
        Assert.Equal(0, inspector.EncryptedDnsHits);
    }

    [Fact]
    public void Inspect_IgnoresOrdinaryDataTrafficOnPort443()
    {
        // The capture filter matches EVERY outbound TCP/443 packet — uploads,
        // ACKs, retransmits. Classifying "not a readable ClientHello" as a blind
        // spot without first confirming a handshake would count every uploaded
        // byte in the session and report thousands of unreadable connections.
        var inspector = new DnsSniInspector(new DnsSettings { Enabled = true });

        // An application_data record (0x17): a normal upload / request body.
        var body = new byte[512];
        body[0] = 0x17;
        var packet = WrapInTcpPacket(body);
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Equal(0, inspector.NoSniConnections);
        Assert.Equal(0, inspector.ConnectionsObserved);
    }

    [Fact]
    public void Inspect_IgnoresHandshakeRecordsThatAreNotAClientHello()
    {
        // A post-handshake handshake record (e.g. NewSessionTicket, or an
        // encrypted Finished) is not a ClientHello and carries no SNI. Counting
        // it as a blind spot would be noise, not evidence.
        var inspector = new DnsSniInspector(new DnsSettings { Enabled = true });

        var payload = new byte[64];
        payload[0] = 0x16; // Handshake record
        payload[1] = 0x03;
        payload[2] = 0x03;
        payload[5] = 0x04; // NewSessionTicket, not ClientHello

        var packet = WrapInTcpPacket(payload);
        inspector.Inspect(packet, (uint)packet.Length);

        Assert.Equal(0, inspector.NoSniConnections);
        Assert.Equal(0, inspector.ConnectionsObserved);
    }

    [Fact]
    public void CaptureFilter_IsPassiveAndTargetsTlsPortOnly()
    {
        var filter = DnsSniInspector.CaptureFilter;

        Assert.Contains("outbound", filter);
        Assert.Contains("tcp.DstPort == 443", filter);
        Assert.Contains("not loopback", filter);
        // The observer must NOT be able to consume traffic: it is opened with
        // SNIFF | RECEIVE_ONLY (asserted in the engine's Start path), and the
        // filter itself must never claim inbound or non-TLS traffic.
        Assert.DoesNotContain("inbound", filter);
        Assert.DoesNotContain("udp", filter);
    }

    /// <summary>A process resolver that always reports the same process.</summary>
    private sealed class StubResolver : IConnectionProcessResolver
    {
        private readonly string _name;
        private readonly int _pid;

        public StubResolver(string name, int pid)
        {
            _name = name;
            _pid = pid;
        }

        public ConnectionProcessInfo? ResolveOwner(
            IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
            => new(_pid, _name, $@"C:\Program Files\{_name}");
    }
}