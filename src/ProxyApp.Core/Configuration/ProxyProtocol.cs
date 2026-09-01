namespace ProxyApp.Core.Configuration;

/// <summary>
/// The proxy protocol implemented by a saved proxy profile. Only SOCKS5 is
/// supported today; the enum exists so persisted profiles can name their
/// protocol explicitly and future protocols can be added without a schema
/// migration.
/// </summary>
public enum ProxyProtocol
{
    /// <summary>SOCKS5 (RFC 1928), optionally with RFC 1929 authentication.</summary>
    Socks5 = 0
}
