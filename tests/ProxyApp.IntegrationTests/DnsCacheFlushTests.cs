using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// The resolver-cache flush is a freshness nicety, NOT a guarantee — but when
/// it fails, the failure used to be a bare <c>false</c> and the WHY was
/// discarded, which made a real user report ("flush failed" in the log,
/// mysteriously) undiagnosable. The contract now: <see cref="DnsCache.FlushWithDiagnostics"/>
/// always returns a complete trace line — success, the ipconfig fallback's
/// rescue (with the original Win32 error), or both failures honestly stated —
/// and never throws, because the ferry must START on DNS regardless.
/// </summary>
public class DnsCacheFlushTests
{
    [Fact]
    public void FlushWithDiagnostics_NeverThrows_AndAlwaysReturnsAnActionableLine()
    {
        var line = DnsCache.FlushWithDiagnostics();

        Assert.False(string.IsNullOrWhiteSpace(line));
        // Either the native flush succeeded (possibly via the ipconfig
        // fallback), or the line says the cache could not be flushed. The old
        // bool-only shape had exactly two stances and neither said WHY; every
        // outcome here must be readable in the Debug log without follow-up.
        Assert.True(
            line.Contains("Windows DNS cache flushed", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("Could not flush the Windows DNS cache", StringComparison.Ordinal),
            $"Unexpected flush diagnostics wording: {line}");
    }
}
