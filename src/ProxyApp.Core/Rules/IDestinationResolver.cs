using System.Net;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Resolves a domain name to IPv4 addresses for destination-rule matching.
///
/// The routing engine (Core) depends on this abstraction only — the caching,
/// timeout, and negative-caching policies live in the implementation
/// (ProxyApp.Network.<c>DnsDestinationResolver</c>), so the pure rule engine
/// stays testable with a fake resolver.
/// </summary>
public interface IDestinationResolver
{
    /// <summary>
    /// Resolves <paramref name="host"/> to its IPv4 addresses.
    /// </summary>
    /// <returns>
    /// The resolved IPv4 addresses; an empty list when the name resolved but
    /// has no IPv4 addresses; null when resolution failed (or was not
    /// possible). Both empty and null mean "the rule cannot match".
    /// </returns>
    Task<IReadOnlyList<IPAddress>?> ResolveAsync(string host, CancellationToken ct);
}
