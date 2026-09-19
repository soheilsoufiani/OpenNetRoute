using System.Net;
using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the ferry's per-configuration usage accounting (Data Usage tab):
/// bucket resolution (pinned profile vs active proxy) and the snapshot shape.
/// Pure accounting — no WinDivert handle required.
/// </summary>
public class TcpFerryUsageTests
{
    private static ProxyConfiguration Proxy(int port) => new()
    {
        Host = "127.0.0.1",
        Port = port,
        AuthenticationType = ProxyAuthenticationType.None,
        Enabled = true
    };

    private static FlowState NewFlow() =>
        new(FlowTable.KeyFrom(
            IPAddress.Parse("10.0.0.1"), 12345,
            IPAddress.Parse("10.0.0.2"), 80),
            clientIsn: 1000, serverIsn: 2000, new WinDivertAddress());

    [Fact]
    public void Snapshot_EmptyFerry_ReportsZeroes()
    {
        var ferry = new TcpFerry(new Socks5Client(Proxy(1)), activeProxyName: "Home");
        var snapshot = ferry.GetUsageSnapshot();

        Assert.Equal(0, snapshot.UpBytes);
        Assert.Equal(0, snapshot.DownBytes);
        Assert.Empty(snapshot.ByProfile);
    }

    [Fact]
    public void UpAndDownBytes_BucketUnderActiveProxyName()
    {
        var ferry = new TcpFerry(new Socks5Client(Proxy(1)), activeProxyName: "Home");
        var flow = NewFlow();
        flow.ProxyName = "Home"; // resolved at flow creation — active bucket

        ferry.GetType()
            .GetMethod("AddUpstreamBytes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .Invoke(ferry, [flow, 300L]);
        ferry.GetType()
            .GetMethod("AddDownstreamBytes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .Invoke(ferry, [flow, 700L]);

        var snapshot = ferry.GetUsageSnapshot();
        Assert.Equal(300, snapshot.UpBytes);
        Assert.Equal(700, snapshot.DownBytes);
        Assert.Equal(new Core.Services.ProfileUsage(300, 700), snapshot.ByProfile["Home"]);
    }

    [Fact]
    public void Buckets_StaySeparatedPerProfile()
    {
        var ferry = new TcpFerry(new Socks5Client(Proxy(1)), activeProxyName: "Home");

        var pinnedFlow = NewFlow();
        pinnedFlow.ProxyName = "Work"; // a rule pinned this profile
        var activeFlow = NewFlow();
        activeFlow.ProxyName = "Home";

        var addUp = ferry.GetType()
            .GetMethod("AddUpstreamBytes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        addUp.Invoke(ferry, [pinnedFlow, 500L]);
        addUp.Invoke(ferry, [activeFlow, 100L]);

        var snapshot = ferry.GetUsageSnapshot();
        Assert.Equal(600, snapshot.UpBytes); // overall = both
        Assert.Equal(500, snapshot.ByProfile["Work"].UpBytes);
        Assert.Equal(100, snapshot.ByProfile["Home"].UpBytes);
    }
}
