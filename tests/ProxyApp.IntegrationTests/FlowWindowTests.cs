using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the flow-level window arithmetic: the advertised upload window
/// field and the downstream flow-control budget that keeps injected data
/// inside the client's receive window.
/// </summary>
public class FlowWindowTests
{
    private static FlowState NewFlow(
        uint clientIsn = 1000,
        uint serverIsn = 0x12345678,
        byte serverShift = TcpPacketBuilder.FerryWindowScaleShift,
        byte clientShift = 8)
        => new(new FlowKey(IPAddress.Loopback, 5000, IPAddress.Parse("8.8.8.8"), 443),
               clientIsn, serverIsn, default)
        {
            ServerWindowShift = serverShift,
            ClientWindowShift = clientShift
        };

    [Fact]
    public void AdvertisedWindowField_FitsSixteenBits()
    {
        var flow = NewFlow(serverShift: 0);
        Assert.Equal((ushort)Math.Min(ushort.MaxValue, FlowState.FerryReceiveWindowBytes),
                     flow.ServerAdvertisedWindowField);

        var scaled = NewFlow(serverShift: TcpPacketBuilder.FerryWindowScaleShift);
        // 1 MiB >> 8 = 4096 — the effective window is still FerryReceiveWindowBytes.
        Assert.Equal(FlowState.FerryReceiveWindowBytes >> 8, scaled.ServerAdvertisedWindowField);
    }

    [Fact]
    public void ClientReceiveWindow_IsScaledByTheClientsOffer()
    {
        var flow = NewFlow(clientShift: 8);
        flow.ClientAdvertisedWindow = 0x2000; // 8192
        Assert.Equal(8192L << 8, flow.ClientReceiveWindowBytes);
    }

    [Fact]
    public void AllowedBytes_StartsAtTheFullSynWindow()
    {
        var flow = NewFlow();
        flow.ClientAckedUpTo = flow.ServerIsn + 1; // handshake ACK only
        flow.ClientBytesRecv = 0;
        flow.ClientAdvertisedWindow = 64;
        Assert.Equal(64L << 8, flow.AllowedUnackedBytesToClient);
    }

    [Fact]
    public void AllowedBytes_ShinksWithUnackedInFlight_AndNeverGoesNegative()
    {
        var flow = NewFlow();
        const uint isnPlusOne = 0x12345679u;
        flow.ClientWindowShift = 0; // unscaled arithmetic for readability
        flow.ClientAdvertisedWindow = 10_000;

        flow.ClientBytesRecv = 4_000;
        flow.ClientAckedUpTo = isnPlusOne + 1_000; // 1 KiB accepted → 3 KiB in flight
        Assert.Equal(7_000, flow.AllowedUnackedBytesToClient);

        // More injected than accepted AND more than the window: clamps at zero.
        flow.ClientBytesRecv = 50_000;
        flow.ClientAckedUpTo = isnPlusOne + 1_000;
        Assert.Equal(0, flow.AllowedUnackedBytesToClient);
    }
}
