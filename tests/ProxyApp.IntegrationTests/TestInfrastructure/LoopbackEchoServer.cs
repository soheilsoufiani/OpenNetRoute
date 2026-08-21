using System.Net;
using System.Net.Sockets;

namespace ProxyApp.Network.Tests.TestInfrastructure;

/// <summary>
/// A loopback TCP server that echoes back every byte it receives. Used as the
/// "destination" behind the SOCKS5 test proxy so tests can verify end-to-end data
/// flow over real sockets.
/// </summary>
public sealed class LoopbackEchoServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly List<Task> _connections = new();

    public LoopbackEchoServer()
    {
        // Bind IPv4 loopback. On Windows a single DualMode IPv6 socket does not
        // reliably accept IPv4 connections, so tests that need IPv6 use their own
        // IPv6 echo listener rather than sharing this one.
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    /// <summary>The loopback port the echo server is listening on.</summary>
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

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