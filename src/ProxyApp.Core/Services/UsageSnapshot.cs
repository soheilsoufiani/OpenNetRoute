namespace ProxyApp.Core.Services;

/// <summary>Cumulative byte counters for one proxy configuration.</summary>
/// <param name="UpBytes">Total uploaded bytes (client → proxy).</param>
/// <param name="DownBytes">Total downloaded bytes (proxy → client).</param>
public readonly record struct ProfileUsage(long UpBytes, long DownBytes)
{
    /// <summary>Up + down combined.</summary>
    public long TotalBytes => UpBytes + DownBytes;

    public static ProfileUsage operator +(ProfileUsage a, ProfileUsage b) =>
        new(a.UpBytes + b.UpBytes, a.DownBytes + b.DownBytes);
}

/// <summary>
/// A point-in-time snapshot of the engine's traffic accounting: the overall
/// session totals plus a per-configuration breakdown (pinned-profile buckets
/// + the active proxy's bucket). All values are bytes for the CURRENT session
/// (since START) — persisted history is the store's job.
/// </summary>
/// <param name="UpBytes">Total uploaded this session.</param>
/// <param name="DownBytes">Total downloaded this session.</param>
/// <param name="ByProfile">Per-configuration usage; keys are profile names
/// (the active proxy's flows bucket under ITS name; a pinned rule's flows
/// under the pinned name).</param>
public sealed record UsageSnapshot(
    long UpBytes,
    long DownBytes,
    IReadOnlyDictionary<string, ProfileUsage> ByProfile)
{
    /// <summary>An empty snapshot (engine stopped / no traffic yet).</summary>
    public static UsageSnapshot Empty { get; } =
        new(0, 0, new Dictionary<string, ProfileUsage>());

    /// <summary>Overall = up + down.</summary>
    public long TotalBytes => UpBytes + DownBytes;
}
