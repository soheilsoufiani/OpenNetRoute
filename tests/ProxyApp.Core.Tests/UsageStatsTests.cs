using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Services;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for the Data Usage pipeline: <see cref="ByteFormatter"/> display,
/// <see cref="UsageStatsMerger"/> delta merging, and the
/// <see cref="JsonUsageStatsStore"/> round trip (atomic save, corrupt-file
/// quarantine, missing-file default).
/// </summary>
public class UsageStatsTests : IDisposable
{
    private readonly string _dir;
    private readonly JsonUsageStatsStore _store;

    public UsageStatsTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"usage-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _store = new JsonUsageStatsStore(Path.Combine(_dir, "usage.json"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // ── ByteFormatter ──

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(512, "512 B")]
    [InlineData(1024, "1.0 KB")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(1048576, "1.0 MB")]
    [InlineData(1073741824, "1.0 GB")]
    [InlineData(-5, "0 B")]
    public void ByteFormatter_ScalesWithBinaryUnits(long bytes, string expected)
    {
        Assert.Equal(expected, ByteFormatter.Format(bytes));
    }

    [Fact]
    public void ByteFormatter_Rate_AppendsPerSecond()
    {
        Assert.Equal("0 B/s", ByteFormatter.FormatRate(0));
        Assert.Equal("1.5 KB/s", ByteFormatter.FormatRate(1536));
    }

    // ── UsageStatsMerger ──

    [Fact]
    public void Merge_AddsDeltasPerProfile()
    {
        var existing = new List<UsageStatsEntry> { new() { Name = "Home", UpBytes = 100, DownBytes = 200 } };
        var session = new UsageSnapshot(50, 75, new Dictionary<string, ProfileUsage>
        {
            ["Home"] = new(50, 75),
            ["Work"] = new(10, 20)
        });

        var merged = UsageStatsMerger.Merge(existing, session);

        Assert.Equal(2, merged.Count);
        Assert.Equal(150, merged.First(e => e.Name == "Home").UpBytes);
        Assert.Equal(275, merged.First(e => e.Name == "Home").DownBytes);
        Assert.Equal(10, merged.First(e => e.Name == "Work").UpBytes);
        Assert.Equal(20, merged.First(e => e.Name == "Work").DownBytes);
    }

    [Fact]
    public void Merge_EmptyDelta_KeepsHistoryUnchanged()
    {
        var existing = new List<UsageStatsEntry> { new() { Name = "Home", UpBytes = 1, DownBytes = 2 } };

        var merged = UsageStatsMerger.Merge(existing, UsageSnapshot.Empty);

        Assert.Single(merged);
        Assert.Equal(1, merged[0].UpBytes);
    }

    [Fact]
    public void Merge_SequentialDeltas_SumExactly()
    {
        // delta-flush simulation: repeated small deltas must sum to the total
        // (this is what makes delta flushing double-count-proof).
        IReadOnlyList<UsageStatsEntry> history = [];
        var total = 0L;
        for (var i = 1; i <= 10; i++)
        {
            var delta = new UsageSnapshot(i * 10, 0, new Dictionary<string, ProfileUsage>
            {
                ["Home"] = new(10, 0) // each delta is 10 bytes up
            });
            history = UsageStatsMerger.Merge(history, delta);
            total += 10;
        }

        Assert.Equal(total, history.Single(e => e.Name == "Home").UpBytes);
    }

    // ── JsonUsageStatsStore ──

    [Fact]
    public void Store_MissingFile_LoadsEmpty()
    {
        Assert.Empty(_store.Load());
    }

    [Fact]
    public void Store_RoundTrips()
    {
        var entries = new List<UsageStatsEntry>
        {
            new() { Name = "Home", UpBytes = 111, DownBytes = 222 },
            new() { Name = "Work", UpBytes = 5, DownBytes = 7 }
        };

        _store.Save(entries);
        var loaded = _store.Load();

        Assert.Equal(2, loaded.Count);
        Assert.Equal(111, loaded.First(e => e.Name == "Home").UpBytes);
        Assert.Equal(222, loaded.First(e => e.Name == "Home").DownBytes);
        Assert.Equal(5, loaded.First(e => e.Name == "Work").UpBytes);
    }

    [Fact]
    public void Store_CorruptFile_IsQuarantinedAndLoadReturnsEmpty()
    {
        File.WriteAllText(_store.FilePath, "{ this is not json");

        var loaded = _store.Load();

        Assert.Empty(loaded);
        Assert.False(File.Exists(_store.FilePath)); // moved away, not deleted silently
        Assert.Single(Directory.GetFiles(_dir, "usage.json.corrupt-*"));
    }

    [Fact]
    public void Store_SaveThenLoad_PreservesAcrossInstances()
    {
        _store.Save(new List<UsageStatsEntry> { new() { Name = "Home", UpBytes = 9, DownBytes = 8 } });

        var secondInstance = new JsonUsageStatsStore(_store.FilePath);
        Assert.Equal(9, secondInstance.Load().First(e => e.Name == "Home").UpBytes);
    }
}
