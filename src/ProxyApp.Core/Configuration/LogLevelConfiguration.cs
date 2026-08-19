namespace ProxyApp.Core.Configuration;

/// <summary>
/// Application-wide structured logging level. Independent of any logging library
/// so this project has no external dependency; the host maps these values to its
/// logging framework (e.g. Microsoft.Extensions.Logging) at startup.
/// </summary>
public enum LogLevelConfiguration
{
    /// <summary>Most verbose. Diagnostic detail, packet-level noise.</summary>
    Trace = 0,

    /// <summary>Detailed debugging information.</summary>
    Debug = 1,

    /// <summary>Normal operational messages.</summary>
    Information = 2,

    /// <summary>Unexpected but non-fatal conditions.</summary>
    Warning = 3,

    /// <summary>Errors that do not stop the application.</summary>
    Error = 4,

    /// <summary>Fatal errors that prevent continued operation.</summary>
    Critical = 5,

    /// <summary>Logging disabled entirely.</summary>
    None = 6
}