using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// Loads and saves the complete <see cref="ApplicationSettings"/> document.
/// Implementations must be safe to call from the UI thread for small
/// documents and must never throw for recoverable conditions (missing or
/// corrupt files degrade to defaults).
/// </summary>
public interface IApplicationSettingsStore
{
    /// <summary>
    /// The file (or equivalent location) the store persists to — exposed for
    /// diagnostics and tests.
    /// </summary>
    string Location { get; }

    /// <summary>Loads settings, returning defaults when nothing is persisted.</summary>
    ApplicationSettings Load();

    /// <summary>Persists the full settings document atomically.</summary>
    void Save(ApplicationSettings settings);
}
