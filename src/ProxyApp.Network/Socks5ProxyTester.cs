using System.Diagnostics;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Services;

namespace ProxyApp.Network;

/// <summary>
/// Connectivity test for a saved proxy profile: performs a full SOCKS5
/// handshake (method negotiation + optional username/password auth + CONNECT)
/// against a small reference endpoint, then disposes the connection. No user
/// payload is sent; the result reports success, latency, and a human-readable
/// outcome (never including credentials).
/// Each test creates its own <see cref="Socks5Client"/> from the candidate
/// proxy — no shared client state leaks between tests.
///
/// Reference target: 1.1.1.1:53 (Cloudflare DNS over TCP) — a stable, tiny,
/// content-neutral endpoint that exercises the complete proxy path.
/// </summary>
public sealed class Socks5ProxyTester : IProxyTester
{
    /// <summary>The reference CONNECT destination used by tests.</summary>
    internal const string TestHost = "1.1.1.1";
    internal const int TestPort = 53;

    private readonly TimeSpan _defaultTimeout;

    public Socks5ProxyTester(TimeSpan? defaultTimeout = null)
    {
        _defaultTimeout = defaultTimeout ?? TimeSpan.FromSeconds(5);
    }

    /// <inheritdoc />
    public async Task<ProxyTestResult> TestAsync(
        ProxyConfiguration proxy,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        var stopwatch = Stopwatch.StartNew();
        try
        {
            var destination = new Socks5Destination(TestHost, TestPort);
            var client = new Socks5Client(proxy, _defaultTimeout);
            using var connection = await client.ConnectAsync(destination, cts.Token);
            stopwatch.Stop();
            return ProxyTestResult.Ok(
                (int)stopwatch.Elapsed.TotalMilliseconds,
                $"SOCKS5 handshake + CONNECT {TestHost}:{TestPort} succeeded " +
                $"in {stopwatch.Elapsed.TotalMilliseconds:F0} ms.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ProxyTestResult.Fail(
                $"Test timed out after {timeout.TotalSeconds:F0} s (proxy unreachable or too slow).");
        }
        catch (Socks5Exception ex)
        {
            return ProxyTestResult.Fail(ex.Message);
        }
        catch (Exception ex)
        {
            return ProxyTestResult.Fail($"{ex.GetType().Name}: {ex.Message}");
        }
    }
}