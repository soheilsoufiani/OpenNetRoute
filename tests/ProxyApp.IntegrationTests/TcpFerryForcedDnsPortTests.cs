using ProxyApp.Core.Configuration;
using ProxyApp.Core.Rules;
using ProxyApp.Network;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Pins the TCP ferry's forced-proxy-port contract: when the DNS relay is on,
/// plaintext DNS over TCP (port 53) is ferried through the active proxy
/// SYSTEM-WIDE, regardless of the App Rules.
///
/// Why it matters: Windows falls back to TCP/53 for truncated DNS answers.
/// The UDP relay leg cannot see that traffic, so without the forced-port
/// override those queries went out directly — a real plaintext DNS leak that
/// no amount of UDP coverage could close.
/// </summary>
public class TcpFerryForcedDnsPortTests
{
    private static TcpFerry CreateFerry(IReadOnlySet<ushort>? forcedPorts) =>
        new(new Socks5Client(new ProxyConfiguration
        {
            Host = "127.0.0.1",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        }), forcedProxyPorts: forcedPorts);

    [Fact]
    public void ForcedPorts_DefaultToEmpty_RulesDecideEverything()
    {
        // With no forced ports (the DNS relay off), the ferry must behave
        // exactly as before: no port is proxied by fiat.
        using var ferry = CreateFerry(null);

        Assert.False(IsForced(ferry, 53));
        Assert.False(IsForced(ferry, 443));
    }

    [Fact]
    public void ForcedPorts_IncludePort53_WhenDnsRelayIsOn()
    {
        using var ferry = CreateFerry(new HashSet<ushort> { 53 });

        Assert.True(IsForced(ferry, 53));
        Assert.False(IsForced(ferry, 443));
    }

    [Fact]
    public void ForcedPorts_DoNotAffectOtherDestinations()
    {
        using var ferry = CreateFerry(new HashSet<ushort> { 53 });

        // Ordinary web traffic must still be decided by the app rules.
        Assert.False(IsForced(ferry, 80));
        Assert.False(IsForced(ferry, 443));
        Assert.False(IsForced(ferry, 853));
    }

    [Fact]
    public void DnsRelayTcpPorts_ContainOnlyPlaintextDns()
    {
        // The set the engine installs must stay minimal: 53 only. Adding a
        // non-DNS port would silently proxy traffic no rule asked for.
        var ports = (System.Collections.Generic.IReadOnlySet<ushort>)
            typeof(ProxyEngine)
                .GetField("DnsRelayTcpPorts",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                .GetValue(null)!;

        Assert.True(ports.Contains(53));
        Assert.Equal(1, ports.Count);
    }

    /// <summary>
    /// Reads the ferry's private forced-port set — the decision input the SYN
    /// handler consults before applying the app rules.
    /// </summary>
    private static bool IsForced(TcpFerry ferry, int port) =>
        ((System.Collections.Generic.IReadOnlySet<ushort>)typeof(TcpFerry)
            .GetField("_forcedProxyPorts",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(ferry)!).Contains((ushort)port);
}
