namespace ProxyApp.Core.Configuration;

/// <summary>
/// A destination-based routing rule: matches traffic by destination IPv4
/// address or domain name (with an optional port) instead of by process.
///
/// Matching semantics (see <c>ProxyApp.Core.Rules.DestinationMatch</c>):
/// <list type="bullet">
/// <item><see cref="Host"/> is either a literal IPv4 address (e.g.
/// <c>142.250.0.14</c>) or a domain name (e.g. <c>example.com</c>). IPv6 is
/// deliberately not supported for destination rules.</item>
/// <item><see cref="Port"/> optionally restricts the rule to one destination
/// port; null matches any port.</item>
/// <item>A domain rule matches a connection whose destination IPv4 address is
/// one of the addresses the domain resolves to (resolved via DNS at connection
/// time, with caching). Applications that resolve DNS themselves over DoH/DoT
/// bypass this correlation.</item>
/// </list>
///
/// A POCO with get/set properties so it can be round-tripped through JSON
/// serialization. Validation is performed by
/// <see cref="ProxyApp.Core.Validation.ConfigurationValidator.Validate(IpDomainRule)"/>.
/// </summary>
public sealed class IpDomainRule
{
    /// <summary>
    /// The destination to match: a literal IPv4 address or a domain name,
    /// optionally written with a port suffix (<c>host:port</c>) in the UI.
    /// Stored WITHOUT the port — the port lives in <see cref="Port"/>.
    /// Required.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    /// Optional destination port (1–65535). Null matches any port.
    /// </summary>
    public int? Port { get; set; }

    /// <summary>
    /// Whether this rule is currently active. A disabled rule is ignored when
    /// the routing engine evaluates traffic.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether matching traffic goes through the proxy or stays direct.
    /// </summary>
    public ProxyMode Mode { get; set; }

    /// <summary>
    /// Optional name of the saved proxy profile (<see cref="ApplicationSettings.Proxies"/>)
    /// this rule routes through when <see cref="Mode"/> is
    /// <see cref="ProxyMode.Proxy"/>. Null/empty means "Default" — the
    /// currently selected (active) proxy. Same fallback behavior as
    /// <see cref="ApplicationRule.ProxyName"/>.
    /// </summary>
    public string? ProxyName { get; set; }
}
