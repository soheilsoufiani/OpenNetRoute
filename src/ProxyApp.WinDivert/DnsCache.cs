using System.Runtime.InteropServices;

namespace ProxyApp.WinDivert;

/// <summary>
/// Flushes the Windows DNS Client cache (<c>dnscache</c>). Called when the DNS
/// ferry starts so no name resolved BEFORE interception can be served from the
/// local cache — otherwise an app could keep using a pre-START answer and a
/// leak test run immediately after START would see stale, un-relayed results.
///
/// The cache is flushed again when the ferry stops, so the system returns to
/// normal resolution instead of re-resolving everything through the proxy.
/// </summary>
internal static class DnsCache
{
    /// <summary>
    /// <c>DnsFlushResolverCache</c> (dnsapi.dll). Returns 0 on success.
    /// Best-effort by contract: a failure is traced, never fatal — the relay
    /// works with a warm cache, it is only a freshness nicety.
    /// </summary>
    [DllImport("dnsapi.dll", SetLastError = true)]
    private static extern int DnsFlushResolverCache();

    /// <summary>Flushes the resolver cache; returns true when Windows accepted it.</summary>
    public static bool Flush() => DnsFlushResolverCache() == 0;
}
