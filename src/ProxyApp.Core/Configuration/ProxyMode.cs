namespace ProxyApp.Core.Configuration;

/// <summary>
/// How traffic matching an <see cref="ApplicationRule"/> should be routed.
/// </summary>
public enum ProxyMode
{
    /// <summary>Route matching traffic through the configured SOCKS5 proxy.</summary>
    Proxy = 0,

    /// <summary>Let matching traffic use the normal (direct) network path.</summary>
    Direct = 1
}