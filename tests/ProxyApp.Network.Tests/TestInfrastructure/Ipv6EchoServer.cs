using System.Net;
using System.Net.Sockets;

namespace ProxyApp.Network.Tests.TestInfrastructure;

/// <summary>
/// A loopback TCP server bound to <c>::1</c> that echoes every byte it receives.
/// Used as the "destination" for tests that need an IPv6 endpoint.
/// </summary>
public sealed class Ipv6EchoServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly List<Task> _connections = new();

    public Ipv6EchoServer()
    {
        if (!Socket.OSSupportsIPv6)
            throw new PlatformNotSupportedException("This environment has no IPv6 support.");

        _listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        _listener.Start();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    /// <summary>The IPv6 loopback port the echo server is listening on.</summary>
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>
    /// Verifies the OS can actually COMPLETE TCP connections on the IPv6
    /// loopback interface within a short budget. <see cref="Socket.OSSupportsIPv6"/>
    /// only proves the protocol stack is loaded: some environments report true
    /// yet silently DROP connects to ::1 (security software / VPN virtual
    /// adapters), which previously surfaced downstream as an opaque
    /// "server closed the connection" instead of a clean environmental skip.
    /// </summary>
    public static async Task<bool> CanConnectToLoopbackAsync(CancellationToken ct = default)
    {
        if (!Socket.OSSupportsIPv6)
            return false;

        try
        {
            using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();

            using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            probeCts.CancelAfter(TimeSpan.FromSeconds(3));

            using var client = new TcpClient(AddressFamily.InterNetworkV6);
            await client.ConnectAsync(
                IPAddress.IPv6Loopback,
                ((IPEndPoint)listener.LocalEndpoint).Port,
                probeCts.Token);
            return true;
        }
        catch (Exception)
        {
            // IPv6 stack present but ::1 is not reachable in practice.
            return false;
        }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                _connections.Add(Task.Run(() => EchoLoopAsync(client, ct), ct));
            }
        }
        catch (Exception)
        {
            // Teardown.
        }
    }

    private static async Task EchoLoopAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            using (var stream = client.GetStream())
            {
                var buffer = new byte[4096];
                while (!ct.IsCancellationRequested)
                {
                    var n = await stream.ReadAsync(buffer, ct);
                    if (n <= 0)
                        break;
                    await stream.WriteAsync(buffer.AsMemory(0, n), ct);
                }
            }
        }
        catch (Exception)
        {
            // Client closed or test cancelled.
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _acceptLoop.GetAwaiter().GetResult(); } catch { }
        try { Task.WaitAll(_connections.ToArray(), TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}