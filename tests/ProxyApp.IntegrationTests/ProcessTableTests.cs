using System.Net;
using System.Net.Sockets;
using ProxyApp.Processes;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for <see cref="ProcessTable"/>, which maps a TCP 4-tuple to its owning
/// process via GetExtendedTcpTable. These exercise the real Windows API against
/// sockets owned by the current process.
/// </summary>
public class ProcessTableTests
{
    /// <summary>
    /// Opens a real loopback TCP connection owned by the current process and
    /// resolves its owner. The owning process must be the test host itself.
    /// </summary>
    [Fact]
    public async Task ResolveOwner_FindsCurrentProcess()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var client = new TcpClient();
        var connectTask = client.ConnectAsync(IPAddress.Loopback, port);
        using (var server = await listener.AcceptTcpClientAsync())
        {
            await connectTask;

            var localIp = IPAddress.Loopback;
            var localEndpoint = (IPEndPoint?)client.Client.LocalEndPoint;
            Assert.NotNull(localEndpoint);
            var localPort = (ushort)localEndpoint!.Port;
            var remoteIp = IPAddress.Loopback;
            var remotePort = (ushort)port;

            var resolver = new ProcessTable();
            var info = resolver.ResolveOwner(localIp, localPort, remoteIp, remotePort);

            Assert.NotNull(info);
            Assert.Equal(Environment.ProcessId, info.Value.ProcessId);
            Assert.False(string.IsNullOrWhiteSpace(info.Value.ExecutableName));
        }
    }

    /// <summary>A tuple with no matching connection resolves to null.</summary>
    [Fact]
    public void ResolveOwner_UnknownTuple_ReturnsNull()
    {
        // Use a port that nothing is listening on; no TCP row should match.
        var resolver = new ProcessTable();
        var info = resolver.ResolveOwner(
            IPAddress.Loopback, 1,
            IPAddress.Loopback, 2);

        Assert.Null(info);
    }
}
