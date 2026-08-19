namespace ProxyApp.Network;

/// <summary>
/// The RFC 1928 reply codes a SOCKS5 server can return for a CONNECT request.
/// </summary>
public enum Socks5ReplyCode : byte
{
    /// <summary>0x00 — request granted.</summary>
    Succeeded = 0x00,

    /// <summary>0x01 — general SOCKS server failure.</summary>
    GeneralFailure = 0x01,

    /// <summary>0x02 — connection not allowed by ruleset.</summary>
    ConnectionNotAllowed = 0x02,

    /// <summary>0x03 — network unreachable.</summary>
    NetworkUnreachable = 0x03,

    /// <summary>0x04 — host unreachable.</summary>
    HostUnreachable = 0x04,

    /// <summary>0x05 — connection refused by the destination.</summary>
    ConnectionRefused = 0x05,

    /// <summary>0x06 — TTL expired.</summary>
    TtlExpired = 0x06,

    /// <summary>0x07 — command not supported.</summary>
    CommandNotSupported = 0x07,

    /// <summary>0x08 — address type not supported.</summary>
    AddressTypeNotSupported = 0x08
}