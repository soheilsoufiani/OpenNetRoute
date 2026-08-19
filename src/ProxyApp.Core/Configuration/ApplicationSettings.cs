namespace ProxyApp.Core.Configuration;

/// <summary>
/// The complete application configuration: the SOCKS5 proxy, the ordered list of
/// application rules, and general application settings.
///
/// A POCO with get/set properties so it can be round-tripped through JSON
/// serialization and later persisted by the host application. Validation is
/// performed by
/// <see cref="ProxyApp.Core.Validation.ConfigurationValidator.Validate(ApplicationSettings)"/>.
/// </summary>
public sealed class ApplicationSettings
{
    /// <summary>
    /// The SOCKS5 proxy server configuration. Required.
    /// </summary>
    public ProxyConfiguration? Proxy { get; set; }

    /// <summary>
    /// Application rules evaluated in order: the first rule matching a process
    /// wins. Duplicate or conflicting rules for the same executable are reported
    /// by validation.
    /// </summary>
    public List<ApplicationRule> Rules { get; set; } = new();

    /// <summary>
    /// The application-wide log level.
    /// </summary>
    public LogLevelConfiguration LogLevel { get; set; } = LogLevelConfiguration.Information;
}