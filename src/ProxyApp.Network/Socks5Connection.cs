namespace ProxyApp.Network;

/// <summary>
/// A successfully established SOCKS5 connection: the usable TCP stream between
/// the local process and the requested destination, relayed by the SOCKS5 proxy.
///
/// The caller owns the <see cref="Stream"/> and must dispose it when done
/// (<see cref="IDisposable.Dispose"/>, or rely on the associated
/// <see cref="Socket"/> being closed). The returned <c>BndAddress</c>/<c>BndPort</c>
/// are the proxy's view of the bound endpoint (RFC 1928 reply), which clients
/// generally ignore but are surfaced for completeness and diagnostics.
/// </summary>
public sealed class Socks5Connection : IDisposable
{
    /// <param name="stream">The live, usable stream to the destination.</param>
    /// <param name="bndAddress">The proxy-reported bound address (may be a domain or IP).</param>
    /// <param name="bndPort">The proxy-reported bound port.</param>
    public Socks5Connection(Stream stream, string bndAddress, int bndPort)
    {
        Stream = stream ?? throw new ArgumentNullException(nameof(stream));
        BndAddress = bndAddress;
        BndPort = bndPort;
    }

    /// <summary>The live TCP stream to the requested destination via the proxy.</summary>
    public Stream Stream { get; }

    /// <summary>The proxy-reported bound address from the RFC 1928 success reply.</summary>
    public string BndAddress { get; }

    /// <summary>The proxy-reported bound port from the RFC 1928 success reply.</summary>
    public int BndPort { get; }

    /// <summary>Disposes the underlying stream.</summary>
    public void Dispose() => Stream.Dispose();
}