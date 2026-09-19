namespace ProxyApp.Core.Configuration;

/// <summary>
/// DNS behavior settings (Phase 8).
///
/// When <see cref="Enabled"/> is true, the engine additionally intercepts
/// outbound DNS queries (UDP port 53) of processes that the App Rules select
/// for proxying, relays each query through the active SOCKS5 proxy's UDP
/// ASSOCIATE relay to the query's original DNS server, and re-injects the
/// reply so the application cannot tell the difference. This closes the DNS
/// leak for locally-resolving apps (see docs/DNS-DESIGN.md).
///
/// Known limitations, always to be stated honestly:
/// <list type="bullet">
/// <item>Applications using DoH/DoT (DNS over HTTPS/TLS on 443) bypass packet
/// interception entirely — their DNS still leaks.</item>
/// <item>DNS carried over IPv6 transport (UDP 53 on the v6 stack) is not
/// intercepted yet (Phase 9).</item>
/// <item>The proxy must support SOCKS5 UDP ASSOCIATE (RFC 1928 §7).</item>
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
    /// a public resolver IPv4 (e.g. "1.1.1.1") keeps the user's configured
    /// (typically ISP) resolver OUT of the path — the proxy exit queries the
    /// public resolver, so leak tests show that resolver instead of the
    /// user's ISP. Empty = transparent: each query is relayed to the DNS
    /// server the client originally addressed. Default "1.1.1.1" (Cloudflare) —
    /// leak-free is the point of the feature.
    /// </summary>
    public string ResolverOverride { get; set; } = "1.1.1.1";

    /// <summary>
    /// Whether STUN traffic (UDP 3478, used by WebRTC to discover the public
    /// IP) is ALSO relayed through the proxy — WebRTC then reports the proxy's
    /// IP instead of the real one. Default false.
    /// </summary>
    public bool RelayStun { get; set; }
}
