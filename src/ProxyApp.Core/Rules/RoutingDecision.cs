using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Rules;

/// <summary>
/// The routing decision for one connection: whether the traffic is ferried
/// through a SOCKS5 proxy (<see cref="ProxyMode.Proxy"/>) or passed through
/// untouched (<see cref="ProxyMode.Direct"/>), and — for proxied traffic —
/// which saved proxy profile to dial.
/// </summary>
/// <param name="Mode">The routing mode (Proxy or Direct).</param>
/// <param name="ProxyName">
/// The saved profile name to route through, or null/empty for "Default" (the
/// active, selected proxy). Only meaningful when <see cref="Mode"/> is
/// <see cref="ProxyMode.Proxy"/>.
/// </param>
public readonly record struct RoutingDecision(ProxyMode Mode, string? ProxyName)
{
    /// <summary>Pass-through decision (no matching rule, or a Direct rule).</summary>
    public static readonly RoutingDecision Direct = new(ProxyMode.Direct, null);
}