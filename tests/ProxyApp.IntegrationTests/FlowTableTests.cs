using System.Net;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the flow table and flow state.
/// </summary>
public class FlowTableTests
{
    private static readonly IPAddress ClientIp = IPAddress.Parse("192.168.100.10");
    private static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");

    private static FlowState MakeFlow(ushort clientPort, ushort serverPort, uint clientIsn)
    {
        var key = FlowTable.KeyFrom(ClientIp, clientPort, ServerIp, serverPort);
        return new FlowState(key, clientIsn, TcpFerry.DefaultServerIsn, default);
    }

    [Fact]
    public void TryAdd_And_Get_ReturnsFlow()
    {
        var table = new FlowTable();
        var flow = MakeFlow(12345, 80, 100);
        Assert.True(table.TryAdd(flow.Key, flow));
        Assert.Same(flow, table.Get(flow.Key));
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void DuplicateKey_IsNotAddedTwice()
    {
        var table = new FlowTable();
        var flow = MakeFlow(12345, 80, 100);
        Assert.True(table.TryAdd(flow.Key, flow));
        var dup = MakeFlow(12345, 80, 999);
        Assert.False(table.TryAdd(flow.Key, dup));
        Assert.Equal(1, table.Count);
        Assert.Same(flow, table.Get(flow.Key));
    }

    [Fact]
    public void TryRemove_ReturnsFlowAndRemoves()
    {
        var table = new FlowTable();
        var flow = MakeFlow(12345, 80, 100);
        table.TryAdd(flow.Key, flow);
        Assert.True(table.TryRemove(flow.Key, out var removed));
        Assert.Same(flow, removed);
        Assert.Null(table.Get(flow.Key));
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void KeyFrom_BuildsCorrectKey()
    {
        var key = FlowTable.KeyFrom(ClientIp, 12345, ServerIp, 80);
        Assert.Equal(ClientIp, key.LocalIp);
        Assert.Equal(12345, key.LocalPort);
        Assert.Equal(ServerIp, key.RemoteIp);
        Assert.Equal(80, key.RemotePort);
    }

    [Fact]
    public void FlowKey_Equality_IsTupleBased()
    {
        var a = FlowTable.KeyFrom(ClientIp, 12345, ServerIp, 80);
        var b = FlowTable.KeyFrom(ClientIp, 12345, ServerIp, 80);
        var c = FlowTable.KeyFrom(ClientIp, 12346, ServerIp, 80);
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void RemoveExpired_RemovesOnlyIdleFlows()
    {
        var table = new FlowTable();
        var idle = MakeFlow(1000, 80, 1);
        var active = MakeFlow(2000, 80, 2);
        table.TryAdd(idle.Key, idle);
        table.TryAdd(active.Key, active);

        // Make `idle` old, keep `active` fresh.
        idle.LastActivityUtc = DateTime.UtcNow.AddMinutes(-5);
        active.Touch();

        var expired = table.RemoveExpired(TimeSpan.FromMinutes(2));
        Assert.Single(expired);
        Assert.Same(idle, expired[0]);
        Assert.Equal(1, table.Count);
        Assert.Same(active, table.Get(active.Key));
    }

    [Fact]
    public void RemoveAll_ReturnsEveryFlow()
    {
        var table = new FlowTable();
        var a = MakeFlow(1000, 80, 1);
        var b = MakeFlow(2000, 80, 2);
        table.TryAdd(a.Key, a);
        table.TryAdd(b.Key, b);

        var all = table.RemoveAll();
        Assert.Equal(2, all.Count);
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void FlowState_StartsWithServerIsnAndResolvingStatus()
    {
        var flow = MakeFlow(12345, 80, 100u);
        Assert.Equal(100u, flow.ClientIsn);
        Assert.Equal(TcpFerry.DefaultServerIsn, flow.ServerIsn);
        Assert.Equal(FlowStatus.Resolving, flow.Status);
    }

    [Fact]
    public void FlowState_Status_Transitions()
    {
        var flow = MakeFlow(12345, 80, 100u);
        flow.Status = FlowStatus.Connecting;
        Assert.Equal(FlowStatus.Connecting, flow.Status);
        flow.Status = FlowStatus.Established;
        Assert.Equal(FlowStatus.Established, flow.Status);
    }

    [Fact]
    public void FlowState_Touch_UpdatesActivity()
    {
        var flow = MakeFlow(12345, 80, 100u);
        flow.LastActivityUtc = DateTime.UtcNow.AddMinutes(-10);
        flow.Touch();
        Assert.True(flow.LastActivityUtc > DateTime.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public void FlowState_NextServerSeq_StartsAtServerIsnPlusOne()
    {
        var flow = MakeFlow(12345, 80, 100u);
        // First data byte after the SYN-ACK (which consumed ServerIsn).
        Assert.Equal((uint)(TcpFerry.DefaultServerIsn + 1), flow.NextServerSeq);
    }

    [Fact]
    public void FlowState_NextServerSeq_AdvancesByClientBytesRecv()
    {
        var flow = MakeFlow(12345, 80, 100u);
        flow.ClientBytesRecv = 10;
        Assert.Equal((uint)(TcpFerry.DefaultServerIsn + 1 + 10), flow.NextServerSeq);
    }

    [Fact]
    public void FlowState_NextClientAck_StartsAtClientIsnPlusOne()
    {
        var flow = MakeFlow(12345, 80, 100u);
        Assert.Equal(101u, flow.NextClientAck);
    }

    [Fact]
    public void FlowState_NextClientAck_AdvancesByClientBytesSent()
    {
        var flow = MakeFlow(12345, 80, 100u);
        flow.ClientBytesSent = 71;
        Assert.Equal(100u + 1 + 71, flow.NextClientAck);
    }

    [Fact]
    public void DataPacket_UsesValidatedSeqAckTranslation()
    {
        var flow = MakeFlow(12345, 80, 100u);
        flow.ClientBytesSent = 71;
        flow.ClientBytesRecv = 0;

        // Build a server→client data packet with the flow's current seq/ack.
        // BuildDataPacket(serverIp, clientIp, serverPort, clientPort, seq, ack, payload).
        var packet = TcpPacketBuilder.BuildDataPacket(
            ServerIp, ClientIp, 80, 12345,
            flow.NextServerSeq, flow.NextClientAck, "OK"u8.ToArray());

        Assert.True(TcpPacketParser.TryParse(packet, (uint)packet.Length, out var tuple));
        // Server→client: src = server, dst = client.
        Assert.Equal(ServerIp, tuple.SrcIp);
        Assert.Equal(80, tuple.SrcPort);
        Assert.Equal(ClientIp, tuple.DstIp);
        Assert.Equal(12345, tuple.DstPort);
        // seq = S1 + 1 + clientBytesRecv; ack = C + 1 + clientBytesSent.
        Assert.Equal((uint)(TcpFerry.DefaultServerIsn + 1 + 0), tuple.Seq);
        Assert.Equal((uint)(100 + 1 + 71), tuple.Ack);
    }
}
