namespace ProxyApp.Core.Configuration;

/// <summary>
/// The SOCKS5 proxy server configuration.
///
/// A POCO with get/set properties so it can be round-tripped through JSON
/// serialization (System.Text.Json) without custom converters. Validation is
/// performed by <see cref="ProxyApp.Core.Validation.ConfigurationValidator.Validate(ProxyConfiguration)"/>.
/// </summary>
public sealed class ProxyConfiguration
{
    /// <summary>
    /// The user-facing profile name (e.g. "Home VPS"). Optional — the UI falls
    /// back to "host:port" when blank.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>The proxy protocol. Only <see cref="ProxyProtocol.Socks5"/> exists today.</summary>
    public ProxyProtocol Protocol { get; set; } = ProxyProtocol.Socks5;

    /// <summary>
    /// The proxy server host. An IPv4 address, an IPv6 address, or a host name.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    /// The proxy server TCP port. Must be in the range 1–65535.
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Optional username for <see cref="ProxyAuthenticationType.UsernamePassword"/>.
    /// Ignored when <see cref="AuthenticationType"/> is <see cref="ProxyAuthenticationType.None"/>.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Optional password for <see cref="ProxyAuthenticationType.UsernamePassword"/>.
    /// The SOCKS5 username/password method (RFC 1929) permits an empty password,
    /// so this may be empty even when authentication is enabled.
    /// Ignored when <see cref="AuthenticationType"/> is <see cref="ProxyAuthenticationType.None"/>.
    /// Persisted DPAPI-protected at rest (only this property is protected — a
    /// global converter would also encrypt innocuous fields like the name/host).
    /// </summary>
    [System.Text.Json.Serialization.JsonConverter(
        typeof(Persistence.ProtectedStringJsonConverter))]
    public string? Password { get; set; }

    /// <summary>
    /// The authentication method to negotiate with the proxy server.
    /// </summary>
    public ProxyAuthenticationType AuthenticationType { get; set; }

    /// <summary>
    /// Whether the routing engine should use this proxy. A disabled proxy is
    /// never dialed, but it is still validated as a configuration value.
    /// </summary>
    public bool Enabled { get; set; }
}