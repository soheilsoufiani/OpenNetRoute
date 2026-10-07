using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Services;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for the merge that folds a session's per-configuration deltas into the
/// persisted history.
///
/// This is the accounting path the Data Usage tab's "Reset Usage" button
/// depends on: after a reset the stored history is empty and the UI rebases
/// its flush baselines onto the engine's cumulative counters, so the first
/// flush after a reset must record ONLY the traffic moved since the reset — not
/// the whole session. Double-counting there would resurrect the history the
/// user just deleted.
/// </summary>
public class UsageResetTests
{
    private static UsageSnapshot Snapshot(long up, long down, params (string Name, long Up, long Down)[] byProfile) =>
        new(up, down, byProfile.ToDictionary(
            p => p.Name, p => new ProfileUsage(p.Up, p.Down), StringComparer.OrdinalIgnoreCase));

    [Fact]
    public void Merge_IntoEmptyHistory_RecordsOnlyThePostResetDelta()
    {
        // The engine counted 5000 up / 9000 down this session; the UI rebased
        // its baselines onto that, so the delta reaching the merger is only the
        // traffic moved after the reset.
        var postReset = Snapshot(500, 900, ("Home", 500, 900));

        var merged = UsageStatsMerger.Merge([], postReset);

        var entry = Assert.Single(merged);
        Assert.Equal("Home", entry.Name);
        Assert.Equal(500, entry.UpBytes);
        Assert.Equal(900, entry.DownBytes);
        Assert.Equal(1400, entry.TotalBytes);
    }

    [Fact]
    public void Merge_AfterReset_DoesNotResurrectPreviousTotals()
    {
        // Pre-reset history existed and was deleted. Replaying the pre-reset
        // portion must not bring it back.
        var history = new List<UsageStatsEntry>();
        var postReset = Snapshot(10, 20, ("Home", 10, 20));

        var merged = UsageStatsMerger.Merge(history, postReset);

        Assert.Equal(30, Assert.Single(merged).TotalBytes);
    }

    [Fact]
    public void Merge_IsAdditiveAcrossMultipleFlushes()
    {
        var history = new List<UsageStatsEntry>();

        var first = UsageStatsMerger.Merge(history, Snapshot(100, 200, ("Home", 100, 200)));
        var second = UsageStatsMerger.Merge(first.ToList(), Snapshot(50, 60, ("Home", 50, 60)));

        var entry = Assert.Single(second);
        Assert.Equal(150, entry.UpBytes);
        Assert.Equal(260, entry.DownBytes);
    }

    [Fact]
    public void Merge_KeepsSeparateRecordsPerConfiguration()
    {
        var merged = UsageStatsMerger.Merge([], Snapshot(100, 200,
            ("Home", 40, 60),
            ("Work", 60, 140)));

        Assert.Equal(2, merged.Count);
        Assert.Equal(100, merged.Sum(e => e.UpBytes));
        Assert.Equal(200, merged.Sum(e => e.DownBytes));
    }

    [Fact]
    public void Merge_ZeroDelta_LeavesHistoryEmpty()
    {
        // A reset with no traffic since is a no-op: nothing must be written, or
        // the Data Usage tab would show a zero row instead of its empty hint.
        var merged = UsageStatsMerger.Merge([], UsageSnapshot.Empty);

        Assert.Empty(merged);
    }
}
