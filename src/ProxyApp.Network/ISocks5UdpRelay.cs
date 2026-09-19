using System.Net;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Network;

/// <summary>
/// The relay surface the DNS ferry uses — the testable seam over
/// <see cref="Socks5UdpAssociateClient"/> (the ferry never constructs sockets
/// directly, so the relay leg is unit-testable with a fake).
/// </summary>
public interface ISocks5UdpRelay : IDisposable
{
    /// <summary>True once the association (control + relay endpoint) is established.</summary>
    bool IsAssociated { get; }

    /// <summary>
    /// Establishes the association with the proxy (TCP control + UDP ASSOCIATE).
    /// </summary>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Relays one UDP payload to the given server through the proxy and
    /// returns the reply payload.
    /// </summary>
    /// <param name="correlationBytes">
    /// How many leading payload bytes identify the transaction: 2 for DNS
    /// (transaction ID; the reply's flags/counters differ, so only the first
    /// two correlate) or 12 for STUN (the full transaction ID is echoed).
    /// </param>
    Task<UdpRelayResult> RelayAsync(
        byte[] dnsPayload,
        IPAddress dnsServer,
        int dnsPort,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default,
        int correlationBytes = 2);
}
