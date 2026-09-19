using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// Pure merge logic for the usage history: folds a session
/// <see cref="UsageSnapshot"/>'s per-configuration deltas into the persisted
/// record list. The UI host owns the store and flushes DELTAS (never full
/// snapshots) so periodic flushes + a final flush can never double-count.
/// </summary>
public static class UsageStatsMerger
{
    /// <summary>
    /// Merges <paramref name="delta"/> into <paramref name="existing"/> and
    /// returns the new record list (ordered by name). Existing records are
    /// mutated in place (the caller persists the result).
    /// </summary>
    public static IReadOnlyList<UsageStatsEntry> Merge(
        IReadOnlyList<UsageStatsEntry> existing, Services.UsageSnapshot delta)
    {
        var byName = existing.ToDictionary(e => e.Name ?? "", StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in delta.ByProfile)
        {
            if (!byName.TryGetValue(kvp.Key, out var entry))
            {
                entry = new UsageStatsEntry { Name = kvp.Key };
                byName[entry.Name] = entry;
            }

            entry.UpBytes += kvp.Value.UpBytes;
            entry.DownBytes += kvp.Value.DownBytes;
            entry.UpdatedAtUtc = DateTimeOffset.UtcNow;
        }

        return byName.Values
            .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
