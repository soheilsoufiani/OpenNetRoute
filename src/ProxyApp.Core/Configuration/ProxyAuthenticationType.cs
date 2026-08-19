namespace ProxyApp.Core.Configuration;

/// <summary>
/// The authentication method used when connecting to a SOCKS5 proxy server.
/// </summary>
public enum ProxyAuthenticationType
{
    /// <summary>No authentication. The SOCKS5 greeting offers method 0x00 only.</summary>
    None = 0,

    /// <summary>
    /// Username/password authentication (RFC 1929). The SOCKS5 greeting offers
    /// method 0x02 and the <see cref="ProxyConfiguration.Username"/> /
    /// <see cref="ProxyConfiguration.Password"/> values are sent during negotiation.
    /// </summary>
    UsernamePassword = 1
}