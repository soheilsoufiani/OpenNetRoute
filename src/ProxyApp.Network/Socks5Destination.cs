namespace ProxyApp.Network;

/// <summary>
/// The destination host and port a SOCKS5 CONNECT request will be issued for.
/// This is the target address the SOCKS5 server must connect to on our behalf.
/// </summary>
/// <param name="Host">
/// The destination. May be an IPv4 address, an IPv6 address, or a domain name.
/// </param>
/// <param name="Port">The destination TCP port (1–65535).</param>
public readonly record struct Socks5Destination(string Host, int Port)
{
    /// <summary>Validates the destination independently of the client.</summary>
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(Host) && Port is >= 1 and <= 65535;
}