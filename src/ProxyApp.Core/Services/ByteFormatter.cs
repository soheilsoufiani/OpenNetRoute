namespace ProxyApp.Core.Services;

/// <summary>Human-readable byte-count formatting for the Data Usage UI.</summary>
public static class ByteFormatter
{
    /// <summary>
    /// Formats a byte count with binary units (B, KB, MB, GB, TB — 1024-based)
    /// and one decimal above 1 KB: 0 B, 512 B, 1.5 KB, 20.0 MB, 1.2 GB.
    /// Negative values (never expected) format as 0 B.
    /// </summary>
    public static string Format(long bytes)
    {
        if (bytes <= 0)
            return "0 B";

        const long Scale = 1024;
        if (bytes < Scale)
            return $"{bytes} B";

        return ((double)bytes / Scale) switch
        {
            < 1024 => $"{bytes / (double)Scale:F1} KB",
            < 1024 * 1024 => $"{bytes / (double)(Scale * 1024):F1} MB",
            < 1024L * 1024 * 1024 => $"{bytes / (double)(Scale * 1024 * 1024):F1} GB",
            _ => $"{bytes / (double)(Scale * 1024 * 1024 * 1024):F1} TB"
        };
    }

    /// <summary>Formats a transfer RATE: bytes/s scaled with units (e.g. "1.5 MB/s", "0 B/s").</summary>
    public static string FormatRate(long bytesPerSecond) =>
        bytesPerSecond <= 0 ? "0 B/s" : Format(bytesPerSecond) + "/s";
}
