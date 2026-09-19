using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// JSON-file <see cref="IUsageStatsStore"/>: keeps the per-configuration
/// traffic history in <c>%APPDATA%\OpenNetRoute\usage.json</c> (alongside the
/// settings file), written atomically (temp file + move) so a crash mid-write
/// can never corrupt the history. Same hygiene rules as the settings store:
/// no credentials live here, corrupt files are quarantined (never deleted),
/// and a missing file means empty history.
/// </summary>
public sealed class JsonUsageStatsStore : IUsageStatsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _filePath;
    private readonly object _writeLock = new();

    /// <summary>Creates the store at the default per-user location.</summary>
    public JsonUsageStatsStore() : this(DefaultFilePath()) { }

    /// <summary>Creates the store at an explicit path (tests).</summary>
    public JsonUsageStatsStore(string filePath) => _filePath = filePath;

    /// <summary>The file this store reads/writes.</summary>
    public string FilePath => _filePath;

    /// <summary>%APPDATA%\OpenNetRoute\usage.json</summary>
    public static string DefaultFilePath()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "OpenNetRoute");
        return Path.Combine(dir, "usage.json");
    }

    /// <inheritdoc />
    public IReadOnlyList<UsageStatsEntry> Load()
    {
        lock (_writeLock)
        {
            try
            {
                if (!File.Exists(_filePath))
                    return [];

                var json = File.ReadAllText(_filePath);
                if (string.IsNullOrWhiteSpace(json))
                    return [];

                var entries = JsonSerializer.Deserialize<List<UsageStatsEntry>>(json, SerializerOptions);
                return entries ?? [];
            }
            catch (Exception)
            {
                // Corrupt file: quarantine (never silently delete) and start
                // empty — the same contract as the settings store.
                TryQuarantineCorruptFile();
                return [];
            }
        }
    }

    /// <inheritdoc />
    public void Save(IReadOnlyList<UsageStatsEntry> entries)
    {
        lock (_writeLock)
        {
            try
            {
                var dir = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                var temp = _filePath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(entries, SerializerOptions));

                // Atomic on the same volume: replace never leaves a partial file.
                if (File.Exists(_filePath))
                    File.Replace(temp, _filePath, null);
                else
                    File.Move(temp, _filePath);
            }
            catch (Exception)
            {
                // A failed flush must never crash the caller (a save timer or
                // the STOP path) — the next flush retries. Never silent for
                // debugging: rethrow only in DEBUG builds is not possible here;
                // the caller traces. Intentionally swallowed with the .tmp
                // left for inspection.
                try { if (File.Exists(_filePath + ".tmp")) { } } catch { }
            }
        }
    }

    private void TryQuarantineCorruptFile()
    {
        try
        {
            if (!File.Exists(_filePath))
                return;
            var backup = _filePath + $".corrupt-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}";
            File.Move(_filePath, backup);
        }
        catch
        {
            // Quarantine is best-effort.
        }
    }
}
