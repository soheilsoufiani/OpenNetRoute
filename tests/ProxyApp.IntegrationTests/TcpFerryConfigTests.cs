using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Pins the ferry's configuration defaults that affect perceived latency.
///
/// The SYN hold timeout was the delay between capturing a client's SYN and
/// injecting the crafted SYN-ACK. A browser opens many concurrent
/// connections; the original 600ms (later 100ms) added that delay to EVERY
/// connection before the SYN-ACK, dominating perceived latency. Parallel
/// connection establishment (SYN-ACK injected immediately, SOCKS5 CONNECT
/// in flight) removed the hold entirely — the default is pinned to 0 so a
/// stale caller cannot reintroduce a per-connection delay.
/// </summary>
public class TcpFerryConfigTests
{
    [Fact]
    public void DefaultHoldMs_IsZero_NoHandshakeDelay()
    {
        // Regression: the default SYN hold must be 0 — parallel establishment
        // injects the crafted SYN-ACK immediately on SYN capture and the
        // SOCKS5 CONNECT runs in flight, so there is no hold at all. A nonzero
        // default would re-add a per-connection delay for every new browser
        // connection.
        Assert.Equal(0, TcpFerry.DefaultHoldMs);
    }

    [Fact]
    public void Constructor_WithoutHold_UsesZeroDefault()
    {
        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = 1080,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }));

        Assert.Equal(0, TcpFerry.DefaultHoldMs);
    }
}
