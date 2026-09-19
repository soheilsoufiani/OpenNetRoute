using System.Net;
using ProxyApp.Network;

namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for <see cref="DnsDestinationResolver"/>: IPv4-only filtering,
/// session caching, and graceful failure on unresolvable names. Uses only
/// names that resolve without external network access ("localhost"), or
/// accepts either failure shape (null or empty) for genuinely external
/// lookups so the suite is robust on offline machines.
/// </summary>
public class DnsDestinationResolverTests
{
    [Fact]
    public async Task LocalHost_ResolvesToIpv4()
    {
        var resolver = new DnsDestinationResolver();

        var result = await resolver.ResolveAsync("localhost", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!, a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
    }

    [Fact]
    public async Task CachedAnswer_IsReusedWithoutSecondLookup()
    {
        var resolver = new DnsDestinationResolver();

        var first = await resolver.ResolveAsync("localhost", CancellationToken.None);
        var second = await resolver.ResolveAsync("localhost", CancellationToken.None);

        // Same list instance = served from the session cache.
        Assert.Same(first, second);
    }

    [Fact]
    public async Task UnresolvableName_FailsGracefully()
    {
        var resolver = new DnsDestinationResolver();

        // RFC 2606/6761: ".invalid" is guaranteed not to resolve. Offline
        // machines time out instead — both null and empty are "no match".
        var result = await resolver.ResolveAsync("definitely-not-a-host.invalid", CancellationToken.None);

        Assert.True(result is null or []);
    }

    [Fact]
    public async Task BlankHost_ReturnsNull()
    {
        var resolver = new DnsDestinationResolver();

        Assert.Null(await resolver.ResolveAsync("", CancellationToken.None));
        Assert.Null(await resolver.ResolveAsync("   ", CancellationToken.None));
    }
}
