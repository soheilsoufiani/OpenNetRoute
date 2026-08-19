using ProxyApp.Core.Configuration;

namespace ProxyApp.Network;

/// <summary>
/// A client that negotiates a SOCKS5 connection to a remote proxy server and,
/// on success, returns the established TCP stream to the requested destination.
///
/// Implementations are stateless between calls: each <see cref="ConnectAsync"/>
/// establishes its own TCP connection and the returned
/// <see cref="Socks5Connection"/> owns that connection's socket. The client
/// itself does not need disposal.
/// </summary>
public interface ISocks5Client
{
    /// <summary>
    /// Establishes a TCP connection to the SOCKS5 proxy, performs the version
    /// negotiation and (when configured) RFC 1929 authentication, then issues a
    /// CONNECT request for <paramref name="destination"/>.
    ///
    /// On success the returned <see cref="Socks5Connection"/> carries the live,
    /// usable TCP stream to <paramref name="destination"/>. On any failure the
    /// method throws — including <see cref="Socks5Exception"/> for protocol-level
    /// rejections and <see cref="OperationCanceledException"/> when
    /// <paramref name="cancellationToken"/> is cancelled.
    /// </summary>
    /// <param name="destination">The remote destination to connect to via the proxy.</param>
    /// <param name="cancellationToken">Cancellation for the whole operation.</param>
    ValueTask<Socks5Connection> ConnectAsync(
        Socks5Destination destination,
        CancellationToken cancellationToken = default);
}