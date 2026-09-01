using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// JSON-file implementation of <see cref="IApplicationSettingsStore"/>.
///
///  - Location: %APPDATA%\MyProxy\settings.json (overridable for tests).
///  - Writes are ATOMIC: serialize to a temp file in the same directory,
///    then File.Replace → a crash mid-save can never truncate the real file.
///  - A corrupt settings file is moved aside (never deleted) and defaults are
///    returned — the app always starts, user data is recoverable by hand.
///  - Passwords are protected at rest via <see cref="SecretProtector"/>
///    (DPAPI CurrentUser) through <see cref="ProtectedStringJsonConverter"/>.
/// </summary>
public sealed class JsonApplicationSettingsStore : IApplicationSettingsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        // NOTE: ProtectedStringJsonConverter is NOT registered globally — a
        // JsonConverter<string?> in Converters would protect EVERY string in
        // the document (names, hosts, folders...). It is attached to the
        // Password property only via [JsonConverter].
    };

    private readonly string _path;
    private readonly string _directory;

    /// <summary>Creates a store persisting to %APPDATA%\MyProxy\settings.json.</summary>
    public JsonApplicationSettingsStore()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "MyProxy", "settings.json"))
    {
    }

    /// <summary>Creates a store with an explicit file path (tests, portable mode).</summary>
    public JsonApplicationSettingsStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Settings path must not be empty.", nameof(path));
        _path = path;
        _directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
    }

    /// <inheritdoc />
    public string Location => _path;

    /// <inheritdoc />
    public ApplicationSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
                return new ApplicationSettings();

            using var stream = File.OpenRead(_path);
            var settings = JsonSerializer.Deserialize<ApplicationSettings>(stream, SerializerOptions);
            return settings ?? new ApplicationSettings();
        }
        catch (Exception ex) when (
            ex is IOException or JsonException or UnauthorizedAccessException
            or CryptographicException or FormatException)
        {
            // Never crash startup on a corrupt/locked file: move it aside so the
            // user's data is recoverable, and continue with defaults.
            Debug.WriteLine($"[SettingsStore] Load failed ({ex.GetType().Name}: {ex.Message}) — quarantining file.");
            TryQuarantineCorruptFile();
            return new ApplicationSettings();
        }
    }

    /// <inheritdoc />
    public void Save(ApplicationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        Directory.CreateDirectory(_directory);

        var tempPath = $"{_path}.tmp";
        try
        {
            using (var stream = File.Create(tempPath))
            {
                JsonSerializer.Serialize(stream, settings, SerializerOptions);
            }

            // Atomic replace: readers see either the old or the new file, never a
            // partial write. File.Replace preserves the destination on failure.
            if (File.Exists(_path))
                File.Replace(tempPath, _path, destinationBackupFileName: null);
            else
                File.Move(tempPath, _path);
        }
        catch
        {
            // Clean up the temp file on any serialization or replace failure.
            try { File.Delete(tempPath); }
            catch (IOException) { }
            throw;
        }
    }

    private void TryQuarantineCorruptFile()
    {
        try
        {
            if (!File.Exists(_path))
                return;
            var backup = $"{_path}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}";
            File.Move(_path, backup);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Debug.WriteLine($"[SettingsStore] Could not quarantine corrupt settings: {ex.Message}");
        }
    }
}
