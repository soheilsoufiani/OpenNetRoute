using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ProxyApp.Core.Rules;

namespace ProxyApp.Network;

/// <summary>
/// <see cref="IDestinationResolver"/> backed by the system DNS — the "DNS
/// optimizer + cache" (port of TunnelX's DnsResolverCache to the SOCKS5-ferry
/// architecture):
///
/// <list type="bullet">
/// <item><b>Single-flight</b> — concurrent SYNs for the same domain share one
/// in-flight lookup.</item>
/// <item><b>TTL</b> — positive answers cached 2 minutes, negative answers 20
/// seconds (record-level DNS TTLs are deliberately not parsed — fixed TTLs are
/// what TunnelX uses too).</item>
/// <item><b>Stale serving</b> — when a fresh lookup FAILS and an expired
/// entry exists, its addresses are served for another 45 s instead of failing
/// (graceful degradation during resolver outages).</item>
/// <item><b>IPv4 only</b> — a name with no IPv4 address resolves to an empty
/// list (negative result).</item>
/// <item><b>Bounded</b> — at most <see cref="MaxEntries"/> entries; the
/// soonest-expiring entry is evicted when full.</item>
/// <item><b>Per-lookup timeout</b> — one SYN never waits on a dead DNS server
/// for long; timeouts are NOT cached (transient).</item>
/// </list>
///
/// A new instance is created per engine Start; nothing survives Stop.
/// </summary>
public sealed class DnsDestinationResolver : IDestinationResolver
{
    /// <summary>TTL for successful answers.</summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(2);

    /// <summary>TTL for negative answers (no IPv4 records / unknown host).</summary>
    public static readonly TimeSpan NegativeTtl = TimeSpan.FromSeconds(20);

    /// <summary>How long an EXPIRED entry may still be served after a failed fresh lookup.</summary>
    public static readonly TimeSpan StaleWindow = TimeSpan.FromSeconds(45);

    /// <summary>Hard cap on cached hosts — keeps the dictionary bounded for long sessions.</summary>
    public const int MaxEntries = 1024;

    private static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(1);

    private sealed class CacheEntry
    {
        public required Task<IReadOnlyList<IPAddress>?> Lookup;
        public DateTimeOffset CreatedAtUtc;
        public TimeSpan? ForcedTtl;

        private int _expirySealed;
        private DateTimeOffset _expiresAtUtc;

        /// <summary>
        /// The entry's expiry — positive vs negative TTL decided from the
        /// lookup's actual result, sealed once. Default (MinValue) means "still
        /// in flight" and counts as valid.
        /// </summary>
        public DateTimeOffset ExpiresAtUtc
        {
            get => _expiresAtUtc;
            private set => _expiresAtUtc = value;
        }

        public bool IsExpired(DateTimeOffset now) =>
            _expirySealed == 1 && now >= _expiresAtUtc;

        public void SealExpiry(IReadOnlyList<IPAddress>? result)
        {
            if (Interlocked.Exchange(ref _expirySealed, 1) == 1)
                return;
            var ttl = ForcedTtl ?? (result is { Count: > 0 } ? DefaultTtl : NegativeTtl);
            ExpiresAtUtc = CreatedAtUtc + ttl;
        }
    }

    private readonly ConcurrentDictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public async Task<IReadOnlyList<IPAddress>?> ResolveAsync(string host, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host))
            return null;

        // Single flight: concurrent callers share the same lookup task. A
        // refreshed lookup replaces the entry atomically; racing callers just
        // await the winner's task.
        var entry = _cache.GetOrAdd(host, CreateEntry);

        IReadOnlyList<IPAddress>? stale = null;
        if (entry.IsExpired(DateTimeOffset.UtcNow))
        {
            // Expired — refresh in place. Keep the old addresses for
            // stale-serving if the fresh lookup fails.
            stale = await SafeResultAsync(entry.Lookup).ConfigureAwait(false);

            var fresh = CreateEntry(host);
            var winner = _cache.TryUpdate(host, fresh, entry) ? fresh : entry;
            if (winner == fresh && _cache.Count > MaxEntries)
                EvictOldest();
            entry = winner;
        }

        try
        {
            var result = await entry.Lookup.WaitAsync(ResolveTimeout, ct).ConfigureAwait(false);
            entry.SealExpiry(result);
            return result;
        }
        catch (TimeoutException)
        {
            return ServeStaleOrNull(host, stale); // do not cache a timeout
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // engine shutting down — propagate
        }
        catch (OperationCanceledException)
        {
            return ServeStaleOrNull(host, stale);
        }
    }

    /// <summary>Creates a cache entry wrapping a fresh single-flight lookup.</summary>
    private CacheEntry CreateEntry(string host)
    {
        var entry = new CacheEntry
        {
            Lookup = ResolveOnceAsync(host),
            CreatedAtUtc = DateTimeOffset.UtcNow
        };
        // Seal the TTL once the lookup lands (ResolveOnceAsync never throws).
        _ = entry.Lookup.ContinueWith(
            t => entry.SealExpiry(t.Status == TaskStatus.RanToCompletion ? t.Result : []),
            TaskScheduler.Default);
        return entry;
    }

    /// <summary>
    /// Stale-serving: when a fresh lookup failed and an expired-but-nonempty
    /// answer exists, serve it for another <see cref="StaleWindow"/> instead of
    /// failing (TunnelX behavior). Otherwise null = "cannot match".
    /// </summary>
    private IReadOnlyList<IPAddress>? ServeStaleOrNull(string host, IReadOnlyList<IPAddress>? staleAddresses)
    {
        if (staleAddresses is not { Count: > 0 })
            return null;

        // Re-side the entry so the stale answer is served (and retried) only
        // for the stale window.
        var staleEntry = new CacheEntry
        {
            Lookup = Task.FromResult(staleAddresses),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            ForcedTtl = StaleWindow
        };
        staleEntry.SealExpiry(staleAddresses);
        _cache.TryUpdate(host, staleEntry, _cache[host]);
        return staleAddresses;
    }

    /// <summary>Awaits a lookup task, mapping failures to an empty answer (negative result).</summary>
    private static async Task<IReadOnlyList<IPAddress>?> SafeResultAsync(Task<IReadOnlyList<IPAddress>?> lookup)
    {
        try
        {
            return await lookup.ConfigureAwait(false);
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Evicts the soonest-expiring entry when the cache is over capacity.</summary>
    private void EvictOldest()
    {
        string? oldestKey = null;
        var oldest = DateTimeOffset.MaxValue;
        foreach (var kvp in _cache)
        {
            if (kvp.Value.ExpiresAtUtc < oldest)
            {
                oldest = kvp.Value.ExpiresAtUtc;
                oldestKey = kvp.Key;
            }
        }
        if (oldestKey is not null)
            _cache.TryRemove(oldestKey, out _);
    }

    /// <summary>
    /// Performs the actual DNS query (never throws to the caller): failures
    /// and IPv4-less answers resolve to an empty list.
    /// </summary>
    private static async Task<IReadOnlyList<IPAddress>?> ResolveOnceAsync(string host)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            return addresses
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .ToList();
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            // Unknown host, no records, or invalid name — a stable negative
            // answer for the TTL window.
            return [];
        }
    }
}
