namespace ProxyApp.Core.Services;

/// <summary>
/// A read-only snapshot of the DNS relay's health and of the encrypted-DNS
/// observer, for the UI's diagnostics line. Everything is a COUNTER or a flag —
/// no verdict is implied, and nothing here can fail the engine. Cheap enough to
/// poll once per second alongside the usage sampler.
///
/// Interpretation guidance for the UI:
/// <list type="bullet">
/// <item><c>QueriesRelayed</c> close to <c>QueriesCaptured</c> = the plaintext
/// relay is working.</item>
/// <item><c>EncryptedDnsDetected</c> &gt; 0 = at least one app resolved names
/// through an ENCRYPTED channel that this app cannot relay. That is the
/// remaining leak path, named explicitly. It is not automatically a plaintext
/// leak: the resolver may itself be Cloudflare/Google and exit via the proxy.</item>
/// <item><c>SniBlindSpots</c> &gt; 0 = some connections could not be classified
/// (Encrypted ClientHello). Reported so the blind spot is visible rather than
/// silently missing — a zero here does not prove there is no DoH.</item>
/// <item><c>Ipv6CaptureActive</c> = false means DNS over IPv6 transport could
/// not be captured on this system (a v4-only host), which is benign; on a
/// dual-stack host it means the v6 handle failed and IPv6 DNS/53 is a real
/// exposure.</item>
/// </list>
/// </summary>
public sealed record DnsDiagnostics(
    /// <summary>True while the plaintext DNS relay is capturing.</summary>
    bool RelayEnabled,

    /// <summary>The relay's human-readable state ("Active", "FAILED: …", "Not started").</summary>
    string RelayStatus,

    /// <summary>Plaintext DNS queries captured (UDP 53, IPv4 + IPv6).</summary>
    long QueriesCaptured,

    /// <summary>Captured queries successfully relayed through the proxy.</summary>
    long QueriesRelayed,

    /// <summary>Replies re-injected toward the client.</summary>
    long RepliesInjected,

    /// <summary>Relay failures (fail-closed drops; the client retries).</summary>
    long RelayFailures,

    /// <summary>Captured datagrams dropped because they could not be parsed.</summary>
    long QueriesDroppedUnparsable,

    /// <summary>True when the IPv6 UDP capture handle is open.</summary>
    bool Ipv6CaptureActive,

    /// <summary>True while the passive SNI observer is running.</summary>
    bool SniInspectionActive,

    /// <summary>
    /// True when the STUN blocking handle is OPEN — not merely when the setting
    /// is ticked. A handle that failed to open must never be reported as
    /// protection, because that is precisely how the previous port-matched
    /// implementation stayed invisible while leaking: the checkbox said "on",
    /// nothing matched, and the leak test still showed the real address.
    /// </summary>
    bool WebRtcBlockingEnabled,

    /// <summary>STUN/ICE datagrams dropped by the WebRTC block.</summary>
    long WebRtcBlocked,

    /// <summary>
    /// True when the blocker's IPv6 handle is open. False on an IPv6-capable
    /// machine is a REAL exposure, not cosmetic: browsers prefer IPv6, so STUN
    /// would leave unblocked over IPv6 while the setting showed "on".
    /// </summary>
    bool WebRtcBlockingIpv6Active,

    /// <summary>
    /// True when STUN/ICE relaying is enabled in the current settings. Reported
    /// separately from the counters below so the UI can distinguish "STUN
    /// relaying is off" from "STUN relaying is on but captured nothing" — the
    /// two look identical in a leak test but mean completely different things.
    /// </summary>
    bool StunRelayEnabled,

    /// <summary>STUN/ICE datagrams captured (UDP).</summary>
    long StunCaptured,

    /// <summary>STUN datagrams relayed through the proxy.</summary>
    long StunRelayed,

    /// <summary>STUN replies re-injected toward the client.</summary>
    long StunInjected,

    /// <summary>
    /// STUN relay failures (fail-closed drops). Non-zero here is the most
    /// likely reason a WebRTC leak test still shows the real address: a dropped
    /// STUN request makes WebRTC fall back to a direct candidate.
    /// </summary>
    long StunFailures,

    /// <summary>TLS connections whose ClientHello was inspected.</summary>
    long TlsConnectionsObserved,

    /// <summary>Connections to a KNOWN encrypted-DNS resolver (the leak path).</summary>
    long EncryptedDnsDetected,

    /// <summary>Connections where a hostname was read from the ClientHello.</summary>
    long EncryptedDnsHostnamesParsed,

    /// <summary>Connections with no readable SNI (Encrypted ClientHello / non-TLS).</summary>
    long SniBlindSpots)
{
    /// <summary>
    /// The all-zero snapshot: the relay off, nothing observed. Lets the UI
    /// render unconditionally instead of null-checking.
    /// </summary>
    public static DnsDiagnostics Empty { get; } = new(
        RelayEnabled: false,
        RelayStatus: "Not started",
        QueriesCaptured: 0,
        QueriesRelayed: 0,
        RepliesInjected: 0,
        RelayFailures: 0,
        QueriesDroppedUnparsable: 0,
        Ipv6CaptureActive: false,
        SniInspectionActive: false,
        WebRtcBlockingEnabled: false,
        WebRtcBlockingIpv6Active: false,
        WebRtcBlocked: 0,
        StunRelayEnabled: false,
        StunCaptured: 0,
        StunRelayed: 0,
        StunInjected: 0,
        StunFailures: 0,
        TlsConnectionsObserved: 0,
        EncryptedDnsDetected: 0,
        EncryptedDnsHostnamesParsed: 0,
        SniBlindSpots: 0);
}