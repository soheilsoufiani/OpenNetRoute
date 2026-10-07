namespace ProxyApp.Core.Configuration;

/// <summary>
/// DNS behavior settings.
///
/// When <see cref="Enabled"/> is true, the engine intercepts ALL PLAINTEXT DNS
/// SYSTEM-WIDE and relays it through the active SOCKS5 proxy:
///
/// <list type="bullet">
/// <item>UDP port 53 over IPv4 AND IPv6 (two WinDivert handles) — relayed via
/// the proxy's UDP ASSOCIATE leg.</item>
/// <item>TCP port 53 over IPv4 AND IPv6 — the fallback transport for truncated
/// answers, ferried through the proxy's TCP CONNECT leg regardless of the App
/// Rules. The IPv6 leg needs a second handle because a filter expression cannot
/// mix ip and ipv6.</item>
/// <item>Unparsable captured packets are dropped fail-closed, never re-injected
/// onto the direct path.</item>
/// <item>The Windows resolver cache is flushed at START and STOP, so no
/// pre-START answer can be served from cache without being relayed.</item>
/// <item>Encrypted DNS on TCP/443 is OBSERVED while this is on: a passive
/// sniff-mode observer reads the hostname from the TLS ClientHello and names
/// the process and resolver performing encrypted DNS. Diagnostic only —
/// nothing is blocked, and a copy-only handle cannot affect routing.</item>
/// </list>
///
/// This means plaintext DNS cannot leave directly while the relay is running.
///
/// Known limitations, always to be stated honestly:
/// <list type="bullet">
/// <item>Applications using DoH/DoT/DoQ (encrypted DNS, usually on 443/853) are
/// not relayed: their queries are inside TLS. Encrypted DNS cannot be
/// distinguished from ordinary HTTPS without TLS interception.</item>
/// <item>The observer cannot see DoH over QUIC/HTTP3 (no TLS-over-TCP
/// ClientHello) nor Encrypted ClientHello (the hostname is genuinely
/// unreadable). Those are counted as blind spots rather than missed silently,
/// and only known resolver hostnames are classified — so a zero count means
/// "nothing known was seen", not "nothing is leaking".</item>
/// <item>Applications that ship their own resolver protocol on a non-standard
/// port are outside the port-53 capture scope.</item>
/// <item>The proxy must support SOCKS5 UDP ASSOCIATE (RFC 1928 §7) for the UDP
/// leg, and TCP CONNECT for the TCP leg.</item>
/// <item>If the relay cannot serve a query the query FAILS (fail-closed) — the
/// app retries, and DNS is not sent directly as a fallback.</item>
/// </list>
/// </summary>
public sealed class DnsSettings
{
    /// <summary>
    /// Whether DNS queries are relayed through the active proxy. Default false —
    /// opt in.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Which DNS server relayed queries are sent to through the proxy:
    /// a public resolver address (e.g. "1.1.1.1" or "2606:4700:4700::1111")
    /// keeps the user's configured (typically ISP) resolver OUT of the path —
    /// the proxy exit queries the public resolver, so leak tests show that
    /// resolver instead of the user's ISP. IPv4 and IPv6 literals are both
    /// accepted; a query is sent to the override of its OWN address family
    /// (an IPv6 query to a v6 override, an IPv4 query to a v4 override).
    /// Empty = transparent: each query is relayed to the DNS server the client
    /// originally addressed. Default "1.1.1.1" (Cloudflare) — leak-free is the
    /// point of the feature.
    ///
    /// Applies to DNS ONLY. STUN datagrams keep their original destination:
    /// redirecting STUN to the resolver guarantees no reply, which would leave
    /// WebRTC quietly falling back to its direct STUN — i.e. the real IP.
    /// </summary>
    public string ResolverOverride { get; set; } = "1.1.1.1";

    /// <summary>
    /// Whether STUN traffic (UDP 3478, used by WebRTC to discover the public
    /// IP) is ALSO relayed through the proxy — WebRTC then reports the proxy's
    /// IP instead of the real one. Default false.
    ///
    /// Covers 3478/3479, 5348/5349 and Google's 19302–19309 (browsers hard-code
    /// stun.l.google.com:19302, so a port list without that range never touches
    /// the traffic a WebRTC leak test generates), on IPv4 AND IPv6.
    ///
    /// It does NOT cover TURN or non-listed ICE ports. And a relay that FAILS is
    /// itself a leak: the request is dropped and WebRTC falls back to a direct
    /// candidate. Use <see cref="BlockWebRtc"/> when relaying cannot be relied
    /// on.
    ///
    /// Independent of <see cref="Enabled"/>: this works with the DNS relay off.
    /// </summary>
    public bool RelayStun { get; set; }

    /// <summary>
    /// Whether STUN/ICE is BLOCKED outright (dropped, not relayed) so WebRTC
    /// cannot discover the real public address. Default false.
    ///
    /// This is the reliable option, and the honest ceiling for WebRTC
    /// protection here: relaying depends on the proxy supporting UDP ASSOCIATE
    /// and on the STUN port being in the list, whereas blocking those ports
    /// simply removes the only mechanism WebRTC has for learning your public IP.
    ///
    /// The cost is real and stated plainly: <b>in-browser video calls stop
    /// working</b>. With no reachable STUN server WebRTC has no server-reflexive
    /// candidate, so peer-to-peer calls cannot connect — sites do not silently
    /// fall back to some safer transport.
    ///
    /// Only the common ports are covered (see <see cref="RelayStun"/>), so this
    /// is a strong default rather than a proof. When both this and
    /// <see cref="RelayStun"/> are set, blocking wins.
    /// </summary>
    public bool BlockWebRtc { get; set; }
}