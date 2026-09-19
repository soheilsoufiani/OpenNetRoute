using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// Persisted cumulative per-configuration traffic history (the Data Usage
/// tab's History section). Implementations keep the counters OUT of
/// <see cref="ApplicationSettings"/> so frequent flushes never rewrite the
/// main settings file.
/// </summary>
public interface IUsageStatsStore
{
    /// <summary>Loads all persisted per-configuration records (empty when none).</summary>
    IReadOnlyList<UsageStatsEntry> Load();

    /// <summary>
    /// Persists the complete record set (replaces the stored list). Cheap
    /// enough for periodic flushes; implementers write atomically.
    /// </summary>
    void Save(IReadOnlyList<UsageStatsEntry> entries);
}
