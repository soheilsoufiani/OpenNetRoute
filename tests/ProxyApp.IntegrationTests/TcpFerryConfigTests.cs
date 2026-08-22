using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Pins the ferry's configuration defaults that affect perceived latency.
///
/// The SYN hold timeout is the delay between capturing a client's SYN and
/// injecting the crafted SYN-ACK. A browser opens many concurrent
/// connections; a long default (the original 600ms) added that delay to
/// EVERY connection before the SYN-ACK, dominating perceived latency. The
/// default is pinned to the browser-friendly 100ms value validated by the
/// elevated E2E tests (which already used holdTimeoutMs: 100).
/// </summary>
public class TcpFerryConfigTests
{
    [Fact]
    public void DefaultHoldMs_IsBrowserFriendly()
    {
        // Regression: the default SYN hold must stay at the validated 100ms —
        // not the original 600ms that made every browser connection pay
        // ~600ms of pure delay before the SYN-ACK was injected.
        Assert.Equal(100, TcpFerry.DefaultHoldMs);
    }

    [Fact]
    public void Constructor_WithoutHold_UsesBrowserFriendlyDefault()
    {
        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = 1080,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }));

        Assert.Equal(TcpFerry.DefaultHoldMs, 100);
    }
}
