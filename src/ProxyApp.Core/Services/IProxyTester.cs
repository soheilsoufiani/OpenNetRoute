namespace ProxyApp.Core.Services;

/// <summary>The outcome of a proxy connectivity test.</summary>
public readonly record struct ProxyTestResult(bool Success, int LatencyMs, string Message)
{
    public static ProxyTestResult Ok(int latencyMs, string message) => new(true, latencyMs, message);
    public static ProxyTestResult Fail(string message) => new(false, 0, message);
}

/// <summary>
/// Tests whether a configured proxy can complete a SOCKS5 CONNECT to a
/// reference destination. Implemented by the networking layer; consumed by
/// the UI for the connection-test preference.
/// </summary>
public interface IProxyTester
{
    /// <summary>Runs the test with the given timeout.</summary>
    Task<ProxyTestResult> TestAsync(
        Configuration.ProxyConfiguration proxy,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}
