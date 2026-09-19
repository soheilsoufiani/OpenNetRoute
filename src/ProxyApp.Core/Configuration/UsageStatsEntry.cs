using System.Text.Json.Serialization;

namespace ProxyApp.Core.Configuration;

/// <summary>
/// One persisted per-configuration usage record (Phase 12-era feature: Data
/// Usage history): cumulative uploaded/downloaded bytes for one proxy
/// configuration across ALL sessions, keyed by profile name. A POCO for JSON
/// round-trip in the usage store.
/// </summary>
public sealed class UsageStatsEntry
{
    /// <summary>The proxy configuration (profile) name this record belongs to.</summary>
    public string Name { get; set; } = "";

    /// <summary>Cumulative uploaded bytes (client → proxy).</summary>
    public long UpBytes { get; set; }

    /// <summary>Cumulative downloaded bytes (proxy → client).</summary>
    public long DownBytes { get; set; }

    /// <summary>When the counters were last updated (diagnostics).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public DateTimeOffset UpdatedAtUtc { get; set; }

    public long TotalBytes => UpBytes + DownBytes;
}
