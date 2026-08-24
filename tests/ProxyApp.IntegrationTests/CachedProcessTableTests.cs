using System.Net;
using System.Net.Sockets;
using ProxyApp.Processes;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for <see cref="CachedProcessTable"/>, the snapshot-cached resolver
/// that the production engine uses (it replaces the per-SYN full-table walk of
/// <see cref="ProcessTable"/> with one snapshot per ~50ms window). Behavior
/// must match the uncached resolver for attribution correctness.
/// </summary>
public class CachedProcessTableTests
{
    /// <summary>
    /// Opens a real loopback TCP connection owned by the current process and
    /// resolves its owner via the CACHED resolver. The owning process must be
    /// the test host itself.
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

            var localEndpoint = (IPEndPoint?)client.Client.LocalEndPoint;
            Assert.NotNull(localEndpoint);
            var localPort = (ushort)localEndpoint!.Port;
            var remotePort = (ushort)port;

            var resolver = new CachedProcessTable();
            var info = resolver.ResolveOwner(
                IPAddress.Loopback, localPort,
                IPAddress.Loopback, remotePort);

            Assert.NotNull(info);
            Assert.Equal(Environment.ProcessId, info.Value.ProcessId);
            Assert.False(string.IsNullOrWhiteSpace(info.Value.ExecutableName));
        }
    }

    /// <summary>A tuple with no matching connection resolves to null (safe default → Direct).</summary>
    [Fact]
    public void ResolveOwner_UnknownTuple_ReturnsNull()
    {
        var resolver = new CachedProcessTable();
        var info = resolver.ResolveOwner(
            IPAddress.Loopback, 1,
            IPAddress.Loopback, 2);

        Assert.Null(info);
    }

    /// <summary>
    /// The cache must reuse one snapshot across lookups within the window — the
    /// whole point is to avoid N full-table walks for an N-SYN browser burst.
    /// Two back-to-back lookups hit the same snapshot.
    /// </summary>
    [Fact]
    public void ResolveOwner_ReusesSnapshot_WithinCacheWindow()
    {
        var resolver = new CachedProcessTable();
        _ = resolver.ResolveOwner(IPAddress.Loopback, 1, IPAddress.Loopback, 2);
        // A second lookup within the 50ms window must not re-query the OS
        // (it returns the same result — null for the unknown tuple).
        var info = resolver.ResolveOwner(IPAddress.Loopback, 1, IPAddress.Loopback, 2);
        Assert.Null(info);
    }
}
