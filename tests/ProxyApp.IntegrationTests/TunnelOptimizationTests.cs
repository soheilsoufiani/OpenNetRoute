using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Pure-logic tests for <see cref="MssTuner"/> (automatic MTU / Game Mode):
/// candidate building, MSS math, Game-Mode composition, and the NIC fallback.
/// The live DF-ping probe is not tested here (needs a real network) — the
/// spike methodology covers it.
/// </summary>
public class MssTunerTests
{
    [Fact]
    public void BuildProbeCandidates_DescendsBy20_UpToFiveSteps()
    {
        var candidates = MssTuner.BuildProbeCandidates(1500);

        Assert.Equal(new[] { 1500, 1480, 1460, 1440, 1420 }, candidates);
    }

    [Fact]
    public void BuildProbeCandidates_StopsAtMinimum()
    {
        // A tiny base MTU: candidates never go below MSS 536 + 40 header bytes.
        var candidates = MssTuner.BuildProbeCandidates(600);

        Assert.All(candidates, mtu => Assert.True(mtu >= 536 + 40));
    }

    [Theory]
    [InlineData(1500, 1460)]
    [InlineData(1400, 1360)]
    [InlineData(1300, 1260)]
    public void MssFromMtu_Subtracts40ByteHeaders(int mtu, ushort expectedMss)
    {
        Assert.Equal(expectedMss, MssTuner.MssFromMtu(mtu));
    }

    [Fact]
    public void MssFromMtu_ClampsToRange()
    {
        Assert.Equal(MssTuner.MaxMss, MssTuner.MssFromMtu(9000)); // jumbo → clamped
        Assert.Equal(MssTuner.MinMss, MssTuner.MssFromMtu(100));  // tiny → clamped
    }

    [Fact]
    public void CombineWithGameMode_TightensTheCap()
    {
        Assert.Equal(MssTuner.GameModeMss, MssTuner.CombineWithGameMode(1460, gameMode: true));
        Assert.Equal(1300, MssTuner.CombineWithGameMode(1300, gameMode: true)); // tuned lower → kept
        Assert.Equal(1460, MssTuner.CombineWithGameMode(1460, gameMode: false));
    }

    [Fact]
    public void GetPrimaryInterfaceMtu_ReturnsSaneValue()
    {
        var mtu = MssTuner.GetPrimaryInterfaceMtu();

        Assert.InRange(mtu, 1300, 9000);
    }

    [Fact]
    public async Task TuneAsync_WithoutProbeHost_UsesInterfaceMtu()
    {
        var mss = await MssTuner.TuneAsync(null);

        Assert.Equal(MssTuner.MssFromMtu(MssTuner.GetPrimaryInterfaceMtu()), mss);
    }
}

/// <summary>
/// Filter construction for the DNS ferry: the STUN/ICE port set is included
/// only when the STUN relay is on.
/// </summary>
public class UdpDnsFerryFilterTests
{
    [Fact]
    public void Filter_WithoutStun_CoversOnlyUdp53()
    {
        var filter = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: false);

        Assert.Contains("udp.DstPort == 53", filter);
        Assert.DoesNotContain("3478", filter);
        Assert.DoesNotContain("19302", filter);
    }

    [Fact]
    public void Filter_WithStun_CoversIcePorts()
    {
        var filter = UdpDnsFerry.BuildFilter(dnsEnabled: true, stunPortsEnabled: true);

        Assert.Contains("udp.DstPort == 53", filter);
        Assert.Contains("3478", filter);   // standard STUN
        Assert.Contains("5349", filter);   // STUN over DTLS port family
        Assert.Contains("19302", filter);  // Google STUN (browsers' default)
        Assert.Contains("19309", filter);  // Google STUN range end
    }
}
