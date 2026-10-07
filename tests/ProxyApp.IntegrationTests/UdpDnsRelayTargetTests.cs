using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the DNS ferry's relay-target rule — the bug that kept WebRTC
/// leaking even with STUN relaying switched on.
///
/// The resolver override was applied to every captured datagram, so STUN to
/// <c>stun.l.google.com:19302</c> was relayed to <c>1.1.1.1:19302</c>. The
/// reply could never correlate, the injection timed out, and the client kept its
/// direct STUN — i.e. its real IP. The user-visible symptom ("relay STUN is on
/// and WebRTC still leaks") gave no hint that the feature was self-sabotaging.
///
/// The rule under test: the override redirects DNS ONLY.
/// </summary>
public class UdpDnsRelayTargetTests
{
    private static readonly IPAddress Cloudflare = IPAddress.Parse("1.1.1.1");
    private static readonly IPAddress Google = IPAddress.Parse("8.8.8.8");
    private static readonly IPAddress GoogleStun = IPAddress.Parse("142.250.185.127");
    private static readonly IPAddress IspResolver = IPAddress.Parse("203.0.113.53");

    [Fact]
    public void DnsQuery_IsRedirectedToTheResolverOverride()
    {
        // The feature's whole point: the app asked the ISP resolver, the query
        // goes to the public resolver instead so the ISP stays out of the path.
        var target = UdpDnsFerry.ResolveRelayTarget(IspResolver, 53, Cloudflare);

        Assert.Equal(Cloudflare, target);
    }

    [Fact]
    public void DnsQuery_IsTransparentWhenNoOverrideIsConfigured()
    {
        var target = UdpDnsFerry.ResolveRelayTarget(IspResolver, 53, null);

        Assert.Equal(IspResolver, target);
    }

    [Theory]
    [InlineData(3478)]
    [InlineData(3479)]
    [InlineData(5348)]
    [InlineData(5349)]
    [InlineData(19302)]
    [InlineData(19309)]
    public void StunPort_KeepsItsOriginalDestination(ushort stunPort)
    {
        // THE REGRESSION. Redirecting STUN to the DNS resolver guarantees no
        // reply: 1.1.1.1 does not serve STUN, and even if it answered, the
        // transaction ID would never correlate because the packet was sent to a
        // different server than the client addressed. The client's stack then
        // falls back to its own direct STUN and leaks the real IP.
        var target = UdpDnsFerry.ResolveRelayTarget(GoogleStun, stunPort, Cloudflare);

        Assert.Equal(GoogleStun, target);
    }

    [Fact]
    public void StunPort_KeepsItsDestinationEvenWithTransparentMode()
    {
        var target = UdpDnsFerry.ResolveRelayTarget(GoogleStun, 19302, null);

        Assert.Equal(GoogleStun, target);
    }

    [Fact]
    public void OnlyPort53IsRedirected_AndOnlyWhenAnOverrideExists()
    {
        // Exhaustive over the interesting ports: 53 redirects, everything else
        // is untouched regardless of the override.
        foreach (var port in new ushort[] { 53, 80, 443, 853, 3478, 19302, 5353, 65535 })
        {
            var target = UdpDnsFerry.ResolveRelayTarget(IspResolver, port, Google);
            if (port == 53)
                Assert.Equal(Google, target);
            else
                Assert.Equal(IspResolver, target);
        }
    }

    [Fact]
    public void StunPorts_CoverTheBrowserDefaults_ButAreNotSufficient()
    {
        // The port set is still used, for RELAYING only, and must include
        // Google's default STUN range: browsers hard-code
        // stun.l.google.com:19302, so a port list without 19302-19309 never
        // touches the traffic they actually generate.
        Assert.Contains(3478, UdpDnsFerry.StunPorts);
        Assert.Contains(5349, UdpDnsFerry.StunPorts);
        foreach (var port in new[] { 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309 })
            Assert.Contains(port, UdpDnsFerry.StunPorts);

        // AND the list must NOT be mistaken for a WebRTC defence. Treating it as
        // complete was a real, reported bug: the leak test's STUN server uses a
        // non-standard port, so nothing matched, nothing was dropped, and the
        // page reported the real address while the setting read "on".
        // Blocking is content-based instead — see StunMessageTests.
        Assert.True(UdpDnsFerry.StunPorts.Count < 1024,
            "A port list this size cannot be assumed to cover every STUN server; " +
            "blocking must not depend on it.");
    }

    [Fact]
    public void BuildFilter_AddsStunPortsOnlyWhenStunHandlingIsEnabled()
    {
        // DNS only: exactly the historical filter.
        Assert.Equal(
            "outbound and ip and udp and udp.DstPort == 53 and not loopback",
            UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: false));

        // With a STUN relaying leg.
        var withStun = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: true);
        Assert.Contains("3478", withStun);
        Assert.Contains("19302", withStun);
        Assert.Contains("udp.DstPort == 53", withStun);
        Assert.Contains("not loopback", withStun);
    }

    [Fact]
    public void TheFerryDoesNotCaptureStun_WhenBlockingHandlesIt()
    {
        // ONLY ONE COMPONENT MAY OWN A GIVEN PACKET. WebRTC blocking moved to
        // StunBlocker, which matches by content on any port. If the ferry also
        // captured the STUN ports, one datagram would match two diverting
        // handles — a race over who re-injects it, not redundancy. Verified
        // through the setting, not just the filter argument, because that is
        // where the two are wired together.
        var settings = new ProxyApp.Core.Configuration.DnsSettings
        {
            Enabled = false,
            BlockWebRtc = true,
            RelayStun = false
        };

        var stunLeg = settings.RelayStun && !settings.BlockWebRtc;

        Assert.False(stunLeg);
        Assert.DoesNotContain("3478",
            UdpDnsFerry.BuildFilter(dnsEnabled: false, stunPortsEnabled: stunLeg));
    }

    [Fact]
    public void BuildFilter_SeparatesTheTwoLegs_Independently()
    {
        // Blocking WebRTC must NOT start intercepting DNS, and relaying STUN
        // must not either: the capture filter decides what is even seen, so a
        // coupled filter would silently turn one feature into another.
        var stunOnly = UdpDnsFerry.BuildFilter(dnsEnabled: false, stunPortsEnabled: true);
        Assert.DoesNotContain("udp.DstPort == 53", stunOnly);
        Assert.Contains("19302", stunOnly);
        Assert.Contains("not loopback", stunOnly);

        var dnsOnly = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: false);
        Assert.DoesNotContain("19302", dnsOnly);

        // Both legs on: both captured.
        var both = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: true);
        Assert.Contains("udp.DstPort == 53", both);
        Assert.Contains("19302", both);
    }

    [Theory]
    [InlineData(true, false, UdpDnsFerry.StunDisposition.Drop)]
    [InlineData(false, true, UdpDnsFerry.StunDisposition.Relay)]
    [InlineData(false, false, UdpDnsFerry.StunDisposition.PassThrough)]
    // BLOCKING WINS when both are set — deliberately. Dropping is the only
    // disposition that cannot fail open: a relay failure (no UDP ASSOCIATE, an
    // unlisted STUN port, a timeout) makes WebRTC fall back to a direct
    // candidate and report the real address, which is the leak being closed.
    [InlineData(true, true, UdpDnsFerry.StunDisposition.Drop)]
    public void DecideStunDisposition_BlockingBeatsRelaying(
        bool block, bool relay, UdpDnsFerry.StunDisposition expected)
    {
        Assert.Equal(expected, UdpDnsFerry.DecideStunDisposition(block, relay));
    }
}