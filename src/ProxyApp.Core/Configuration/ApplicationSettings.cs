namespace ProxyApp.Core.Configuration;

/// <summary>
/// The complete application configuration: the SOCKS5 proxy, the ordered list of
/// application rules, and general application settings.
///
/// A POCO with get/set properties so it can be round-tripped through JSON
/// serialization and later persisted by the host application. Validation is
/// performed by
/// <see cref="ProxyApp.Core.Validation.ConfigurationValidator.Validate(ApplicationSettings)"/>.
/// </summary>
public sealed class ApplicationSettings
{
    /// <summary>
    /// The SOCKS5 proxy server configuration used by the routing engine
    /// (the currently ACTIVE proxy). Required for Start.
    /// </summary>
    public ProxyConfiguration? Proxy { get; set; }

    /// <summary>
    /// Saved proxy profiles. The active <see cref="Proxy"/> is a copy of the
    /// selected entry; editing the active fields updates the selected profile.
    /// </summary>
    public List<ProxyConfiguration> Proxies { get; set; } = new();

    /// <summary>
    /// The <see cref="ProxyConfiguration.Name"/> of the currently selected
    /// saved profile. Null/empty when nothing (yet) matches a saved profile.
    /// </summary>
    public string? SelectedProxyName { get; set; }

    /// <summary>
    /// Application rules evaluated in order: the first rule matching a process
    /// wins. Duplicate or conflicting rules for the same executable are reported
    /// by validation.
    /// </summary>
    public List<ApplicationRule> Rules { get; set; } = new();

    /// <summary>
    /// Destination-based rules (IP/domain, IPv4 only) evaluated BEFORE the
    /// process <see cref="Rules"/>: the first enabled rule matching the
    /// connection's destination (address, optional port, or a domain the
    /// address resolves to) wins. Evaluated first so per-destination intent
    /// (e.g. "this site stays direct") can override an app-wide pin.
    /// </summary>
    public List<IpDomainRule> IpDomainRules { get; set; } = new();

    /// <summary>
    /// DNS behavior: whether all plaintext DNS (UDP/TCP 53, IPv4 and IPv6) is
    /// relayed system-wide through the active proxy, failing closed rather than
    /// falling back to a direct query. See <see cref="DnsSettings"/>.
    /// </summary>
    public DnsSettings Dns { get; set; } = new();

    /// <summary>
    /// Tunnel-optimization toggles: automatic MSS/MTU adaptation and Game
    /// Mode packet tuning.
    /// </summary>
    public OptimizationSettings Optimization { get; set; } = new();

    /// <summary>
    /// The application-wide log level.
    /// </summary>
    public LogLevelConfiguration LogLevel { get; set; } = LogLevelConfiguration.Information;

    /// <summary>Theme, accent color, and connection-test preferences.</summary>
    public UiPreferences Preferences { get; set; } = new();
}