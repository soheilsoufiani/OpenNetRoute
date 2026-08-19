namespace ProxyApp.Network;

/// <summary>
/// A protocol-level SOCKS5 failure: the proxy rejected the connection or returned
/// an unexpected response during negotiation. Distinct from ordinary network
/// failures (which surface as <see cref="System.IO.IOException"/> /
/// <see cref="System.Net.Sockets.SocketException"/>).
/// </summary>
public sealed class Socks5Exception : Exception
{
    /// <summary>
    /// Creates an exception for a SOCKS5 reply code returned by the server.
    /// </summary>
    public Socks5Exception(Socks5ReplyCode replyCode)
        : base($"SOCKS5 server rejected the request: {Describe(replyCode)}.")
    {
        ReplyCode = replyCode;
        IsReplyError = true;
    }

    /// <summary>
    /// Creates an exception for a malformed or unexpected server response during
    /// negotiation (a protocol violation, not a reply error).
    /// </summary>
    public Socks5Exception(string message)
        : base(message)
    {
        ReplyCode = null;
        IsReplyError = false;
    }

    /// <summary>
    /// The RFC 1928 reply code when the server rejected the request, or null when
    /// the failure was a malformed response rather than a rejection.
    /// </summary>
    public Socks5ReplyCode? ReplyCode { get; }

    /// <summary>
    /// True when the server sent an explicit RFC 1928 reply code. When false, the
    /// failure was a protocol violation (unexpected version, truncated response, …).
    /// </summary>
    public bool IsReplyError { get; }

    private static string Describe(Socks5ReplyCode code) => code switch
    {
        Socks5ReplyCode.GeneralFailure => "general SOCKS server failure",
        Socks5ReplyCode.ConnectionNotAllowed => "connection not allowed by ruleset",
        Socks5ReplyCode.NetworkUnreachable => "network unreachable",
        Socks5ReplyCode.HostUnreachable => "host unreachable",
        Socks5ReplyCode.ConnectionRefused => "connection refused by the destination",
        Socks5ReplyCode.TtlExpired => "TTL expired",
        Socks5ReplyCode.CommandNotSupported => "command not supported",
        Socks5ReplyCode.AddressTypeNotSupported => "address type not supported",
        _ => $"reply code 0x{(byte)code:X2}"
    };
}