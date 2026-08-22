using System.Net;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Validation;

/// <summary>
/// Validation rules for the configuration models.
///
/// All methods are pure functions of their input: they never mutate the model,
/// never throw for user input, and return a <see cref="ValidationResult"/> with
/// useful, ordered error messages. Validation is deliberately independent of the
/// model's <c>Enabled</c> flag — an invalid configuration is invalid data whether
/// or not it is currently in use, and the routing engine will only consume enabled
/// configuration.
/// </summary>
public static class ConfigurationValidator
{
    /// <summary>Valid TCP/UDP port numbers.</summary>
    public const int MinPort = 1;
    public const int MaxPort = 65535;

    /// <summary>
    /// Maximum length of a host string accepted by validation. Hosts longer than
    /// this are rejected as invalid rather than accepted and later truncated.
    /// </summary>
    public const int MaxHostLength = 255;

    /// <summary>Maximum length of a username accepted by validation.</summary>
    public const int MaxUsernameLength = 255;

    /// <summary>Maximum length of a password accepted by validation.</summary>
    public const int MaxPasswordLength = 255;

    /// <summary>Maximum length of an executable name accepted by validation.</summary>
    public const int MaxExecutableNameLength = 255;

    /// <summary>Maximum length of an executable path accepted by validation.</summary>
    public const int MaxExecutablePathLength = 1024;

    private static readonly HashSet<string> ForbiddenHostValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "0.0.0.0",
        "::",
        "::0",
        "localhost"
    };

    /// <summary>
    /// Validates a <see cref="ProxyConfiguration"/>.
    /// </summary>
    public static ValidationResult Validate(ProxyConfiguration proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var errors = new List<string>();
        var hostErrors = ValidateHost(proxy.Host);
        if (hostErrors is not null)
            errors.Add(hostErrors);

        var portErrors = ValidatePort(proxy.Port);
        if (portErrors is not null)
            errors.Add(portErrors);

        switch (proxy.AuthenticationType)
        {
            case ProxyAuthenticationType.None:
                break;

            case ProxyAuthenticationType.UsernamePassword:
                errors.AddRange(ValidateUsernamePassword(proxy.Username, proxy.Password));
                break;

            default:
                errors.Add($"Authentication type '{proxy.AuthenticationType}' is not supported.");
                break;
        }

        return errors.Count == 0
            ? ValidationResult.Success
            : ValidationResult.Fail(errors.ToArray());
    }

    /// <summary>
    /// Validates an <see cref="ApplicationRule"/>.
    /// </summary>
    public static ValidationResult Validate(ApplicationRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var errors = new List<string>();

        // A folder/bundle rule may have no executable name (it matches by
        // FolderPath prefix); a name/path rule must have one.
        if (string.IsNullOrWhiteSpace(rule.FolderPath))
        {
            var nameErrors = ValidateExecutableName(rule.ExecutableName);
            if (nameErrors is not null)
                errors.Add(nameErrors);
        }

        var pathErrors = ValidateExecutablePath(rule.ExecutablePath);
        if (pathErrors is not null)
            errors.Add(pathErrors);

        var folderErrors = ValidateFolderPath(rule.FolderPath);
        if (folderErrors is not null)
            errors.Add(folderErrors);

        if (!Enum.IsDefined(rule.Mode))
            errors.Add($"Rule mode '{rule.Mode}' is not supported.");

        return errors.Count == 0
            ? ValidationResult.Success
            : ValidationResult.Fail(errors.ToArray());
    }

    /// <summary>
    /// Validates an <see cref="ApplicationSettings"/> collection.
    /// </summary>
    public static ValidationResult Validate(ApplicationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var errors = new List<string>();

        if (settings.Proxy is not null)
        {
            var proxyErrors = Validate(settings.Proxy);
            if (!proxyErrors.IsValid)
                errors.AddRange(proxyErrors.Errors);
        }
        else
        {
            errors.Add("SOCKS5 proxy configuration is required.");
        }

        var ruleErrors = ValidateRules(settings.Rules);
        errors.AddRange(ruleErrors.Errors);

        if (!Enum.IsDefined(settings.LogLevel))
            errors.Add($"Log level '{settings.LogLevel}' is not supported.");

        return errors.Count == 0
            ? ValidationResult.Success
            : ValidationResult.Fail(errors.ToArray());
    }

    /// <summary>
    /// Validates an ordered collection of application rules. Duplicate rules and
    /// conflicting rules for the same executable are reported because rule
    /// precedence is evaluated in order and duplicates are ambiguous.
    /// </summary>
    public static ValidationResult ValidateRules(IReadOnlyList<ApplicationRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var errors = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var modes = new Dictionary<string, ProxyMode>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rules.Count; i++)
        {
            var rule = rules[i];
            if (rule is null)
            {
                errors.Add($"Rule at index {i} is null.");
                continue;
            }

            var ruleErrors = Validate(rule);
            errors.AddRange(ruleErrors.Errors);

            // Only check for duplicates when the rule's identity is itself valid;
            // otherwise the duplicate check on a blank name would add noise.
            if (ruleErrors.IsValid)
            {
                // A valid rule is guaranteed to have a non-blank identity: its
                // executable name (name/path rule) or its folder path (bundle
                // rule). Two folder rules on the SAME folder conflict; a name
                // rule and a folder rule never conflict (different identities).
                var identity = rule.FolderPath ?? rule.ExecutableName!;

                if (!seen.Add(identity))
                {
                    errors.Add($"Duplicate rule for '{identity}' at index {i}.");
                }
                else
                {
                    if (modes.TryGetValue(identity, out var existingMode) &&
                        existingMode != rule.Mode)
                    {
                        errors.Add(
                            $"Conflicting rules for '{identity}': index {modes[identity]} is " +
                            $"'{existingMode}' and index {i} is '{rule.Mode}'.");
                    }
                    else
                    {
                        modes[identity] = rule.Mode;
                    }
                }
            }
        }

        return errors.Count == 0
            ? ValidationResult.Success
            : ValidationResult.Fail(errors.ToArray());
    }

    private static string? ValidateHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return "Proxy host must not be empty.";

        if (host.Length > MaxHostLength)
            return $"Proxy host must not exceed {MaxHostLength} characters.";

        if (ForbiddenHostValues.Contains(host))
            return $"'{host}' is not a valid proxy host.";

        if (IPAddress.TryParse(host, out var address))
        {
            if (address.AddressFamily is not (System.Net.Sockets.AddressFamily.InterNetwork or
                                              System.Net.Sockets.AddressFamily.InterNetworkV6))
                return $"'{host}' is not a valid IP address.";

            return null;
        }

        if (Uri.CheckHostName(host) is UriHostNameType.Unknown or UriHostNameType.Basic)
            return $"'{host}' is not a valid proxy host.";

        return null;
    }

    private static string? ValidatePort(int port)
    {
        if (port < MinPort || port > MaxPort)
            return $"Proxy port must be between {MinPort} and {MaxPort}. Got {port}.";
        return null;
    }

    private static IEnumerable<string> ValidateUsernamePassword(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            yield return "A username is required when username/password authentication is enabled.";
        }
        else if (username.Length > MaxUsernameLength)
        {
            yield return $"Username must not exceed {MaxUsernameLength} characters.";
        }

        if (password is not null && password.Length > MaxPasswordLength)
            yield return $"Password must not exceed {MaxPasswordLength} characters.";
    }

    private static string? ValidateExecutableName(string? executableName)
    {
        if (string.IsNullOrWhiteSpace(executableName))
            return "Executable name must not be empty.";

        if (executableName.Length > MaxExecutableNameLength)
            return $"Executable name must not exceed {MaxExecutableNameLength} characters.";

        if (executableName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return $"'{executableName}' is not a valid executable name.";

        return null;
    }

    private static string? ValidateExecutablePath(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return null;

        if (executablePath.Length > MaxExecutablePathLength)
            return $"Executable path must not exceed {MaxExecutablePathLength} characters.";

        if (executablePath.IndexOf('\0') >= 0)
            return "Executable path must not contain a null character.";

        return null;
    }

    private static string? ValidateFolderPath(string? folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath))
            return null;

        if (folderPath.Length > MaxExecutablePathLength)
            return $"Folder path must not exceed {MaxExecutablePathLength} characters.";

        if (folderPath.IndexOf('\0') >= 0)
            return "Folder path must not contain a null character.";

        if (!Path.IsPathRooted(folderPath))
            return $"Folder path '{folderPath}' is not a rooted path.";

        return null;
    }
}